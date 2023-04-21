use anyhow::{bail, Result};
use mutator_set_tf::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use mutator_set_tf::util_types::mutator_set::mutator_set_trait::MutatorSet;
use num_traits::{CheckedSub, Zero};
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};
use twenty_first::util_types::storage_vec::StorageVec;

use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::shared_math::rescue_prime_digest::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

use self::blockchain_state::BlockchainState;
use self::mempool::Mempool;
use self::networking_state::NetworkingState;
use self::wallet::wallet_state::WalletState;
use super::blockchain::transaction::devnet_input::DevNetInput;
use super::blockchain::transaction::utxo::Utxo;
use super::blockchain::transaction::{amount::Amount, Transaction};
use crate::config_models::cli_args;
use crate::database::leveldb::LevelDB;
use crate::database::rusty::RustyLevelDBIterator;
use crate::models::peer::{HandshakeData, PeerStanding};
use crate::{Hash, VERSION};

pub mod archival_state;
pub mod blockchain_state;
pub mod light_state;
pub mod mempool;
pub mod networking_state;
pub mod shared;
pub mod wallet;

/// `GlobalState` handles all state of a Neptune node that is shared across its threads.
///
/// Some fields are only written to by certain threads.
#[derive(Debug, Clone)]
pub struct GlobalState {
    /// The `WalletState` may be updated by the main thread and the RPC server.
    pub wallet_state: WalletState,

    /// The `BlockchainState` may only be updated by the main thread.
    pub chain: BlockchainState,

    /// The `NetworkingState` may be updated by both the main thread and peer threads.
    pub net: NetworkingState,

    /// The `cli_args::Args` are read-only and accessible by all threads.
    pub cli: cli_args::Args,

    /// The `Mempool` may only be updated by the main thread.
    pub mempool: Mempool,
}

impl GlobalState {
    /// Create a transaction that sends coins to the given
    /// `recipient_utxos` from some selection of owned UTXOs.
    /// A change UTXO will be added if needed; the caller
    /// does not need to supply this. The caller must supply
    /// the fee that they are willing to spend to have this
    /// transaction mined.
    pub async fn create_transaction(
        &self,
        recipient_utxos: Vec<Utxo>,
        fee: Amount,
    ) -> Result<Transaction> {
        // acquire a lock on `WalletState` to prevent it from being updated
        let mut wallet_db_lock = self.wallet_state.wallet_db.lock().await;

        // Get the block tip as the transaction is made relative to it
        let bc_tip = self.chain.light_state.latest_block.lock().await.to_owned();

        // Get the UTXOs required for this transaction
        let total_spend: Amount = recipient_utxos.iter().map(|x| x.amount).sum::<Amount>() + fee;
        let spendable_utxos_and_mps: Vec<(Utxo, MsMembershipProof<Hash>)> = self
            .wallet_state
            .allocate_sufficient_input_funds_from_lock(&mut wallet_db_lock, total_spend, &bc_tip)?;

        // Create all removal records. These must be relative to the block tip.
        let mut msa_tip = bc_tip.body.next_mutator_set_accumulator;
        let mut inputs: Vec<DevNetInput> = vec![];
        let mut input_amount: Amount = Amount::zero();
        for (spendable_utxo, mp) in spendable_utxos_and_mps {
            let removal_record = msa_tip.kernel.drop(&Hash::hash(&spendable_utxo), &mp);
            input_amount = input_amount + spendable_utxo.amount;
            inputs.push(DevNetInput {
                utxo: spendable_utxo,
                membership_proof: mp.into(),
                removal_record,
                signature: None,
            });
        }

        let mut outputs: Vec<(Utxo, Digest)> = vec![];
        for output_utxo in recipient_utxos {
            let output_randomness = self
                .wallet_state
                .next_output_randomness_from_lock(&mut wallet_db_lock);
            outputs.push((output_utxo, output_randomness));
        }

        // Send remaining amount back to self
        let change_amount = match input_amount.checked_sub(&total_spend) {
            Some(amt) => amt,
            None => {
                bail!("Cannot create change UTXO with negative amount.");
            }
        };
        if input_amount > total_spend {
            let change_utxo = Utxo {
                amount: change_amount,
                public_key: self.wallet_state.wallet_secret.get_public_key(),
            };
            outputs.push((
                change_utxo,
                self.wallet_state
                    .next_output_randomness_from_lock(&mut wallet_db_lock),
            ));
        }

        let mut transaction = Transaction {
            inputs,
            outputs,
            public_scripts: vec![],
            fee,
            timestamp: BFieldElement::new(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
            authority_proof: None,
        };
        transaction.sign(&self.wallet_state.wallet_secret);

        Ok(transaction)
    }

    // Storing IP addresses is, according to this answer, not a violation of GDPR:
    // https://law.stackexchange.com/a/28609/45846
    // Wayback machine: https://web.archive.org/web/20220708143841/https://law.stackexchange.com/questions/28603/how-to-satisfy-gdprs-consent-requirement-for-ip-logging/28609
    pub async fn write_peer_standing_on_increase(&self, ip: IpAddr, standing: PeerStanding) {
        let mut peer_databases = self.net.peer_databases.lock().await;
        let old_standing = peer_databases.peer_standings.get(ip);

        if old_standing.is_none() || old_standing.unwrap().standing < standing.standing {
            peer_databases.peer_standings.put(ip, standing)
        }
    }

    pub async fn get_peer_standing_from_database(&self, ip: IpAddr) -> Option<PeerStanding> {
        let mut peer_databases = self.net.peer_databases.lock().await;
        peer_databases.peer_standings.get(ip)
    }

    pub async fn get_handshakedata(&self) -> HandshakeData {
        let listen_addr_socket = SocketAddr::new(self.cli.listen_addr, self.cli.peer_port);
        let latest_block_header = self.chain.light_state.get_latest_block_header().await;

        HandshakeData {
            tip_header: latest_block_header,
            listen_address: Some(listen_addr_socket),
            network: self.cli.network,
            instance_id: self.net.instance_id,
            version: VERSION.to_string(),
            // For now, all nodes are archival nodes
            is_archival_node: true,
        }
    }

    pub async fn clear_ip_standing_in_database(&self, ip: IpAddr) {
        let mut peer_databases = self.net.peer_databases.lock().await;

        let old_standing = peer_databases.peer_standings.get(ip);

        if old_standing.is_some() {
            peer_databases
                .peer_standings
                .put(ip, PeerStanding::default())
        }
    }

    pub async fn clear_all_standings_in_database(&self) {
        let mut peer_databases = self.net.peer_databases.lock().await;

        let mut dbiterator: RustyLevelDBIterator<IpAddr, PeerStanding> =
            peer_databases.peer_standings.new_iter();

        for (ip, _v) in dbiterator.by_ref() {
            let old_standing = peer_databases.peer_standings.get(ip);

            if old_standing.is_some() {
                peer_databases
                    .peer_standings
                    .put(ip, PeerStanding::default())
            }
        }
    }

    pub async fn resync_membership_proofs_to_tip(&self, tip_hash: Digest) -> Result<()> {
        // loop over all monitored utxos
        let mut monitored_utxos = self
            .wallet_state
            .wallet_db
            .lock()
            .await
            .monitored_utxos
            .clone();
        let num_monitored_utxos = monitored_utxos.len();
        'outer: for i in 0..num_monitored_utxos {
            let mut monitored_utxo = monitored_utxos.get(i).clone();

            // ignore synced ones
            if monitored_utxo.is_synced_to(&tip_hash) {
                continue;
            }

            // If the UTXO was not confirmed yet, there is no
            // point in synchronizing its membership proof.
            let confirming_block = match monitored_utxo.confirmed_in_block {
                Some((confirmed_block_hash, _timestamp)) => confirmed_block_hash,
                None => {
                    continue;
                }
            };

            // try latest (block hash, membership proof) entry
            let (block_hash, mut membership_proof) = monitored_utxo
                .get_latest_membership_proof_entry()
                .expect("Database not in consistent state. Monitored UTXO must have at least one membership proof.");

            // request path-to-tip
            let (backwards, _luca, forwards) = self
                .chain
                .archival_state
                .as_ref()
                .unwrap()
                .find_path(&block_hash, &tip_hash)
                .await;

            // walk backwards, reverting
            for revert_block_hash in backwards.into_iter() {
                // Was the UTXO confirmed in this block? If so, there
                // is nothing we can do except orphan the UTXO: that
                // is, leave it without a synced membership proof.
                // Whenever current owned UTXOs are queried, one
                // should take care to filter for UTXOs that have a
                // membership proof synced to the current block tip.
                if confirming_block == revert_block_hash {
                    break 'outer;
                }

                let revert_block = self
                    .chain
                    .archival_state
                    .as_ref()
                    .unwrap()
                    .get_block(revert_block_hash)
                    .await?
                    .unwrap();

                // revert removals
                let removal_records = revert_block.body.mutator_set_update.removals;
                for removal_record in removal_records.iter().rev() {
                    // membership_proof.revert_update_from_removal(&removal);
                    membership_proof
                        .revert_update_from_remove(removal_record)
                        .expect("Could not revert membership proof from removal record.");
                }

                // revert additions
                let previous_mutator_set = revert_block.body.previous_mutator_set_accumulator;
                membership_proof.revert_update_from_batch_addition(&previous_mutator_set);

                // assert valid
                assert!(previous_mutator_set
                    .verify(&Hash::hash(&monitored_utxo.utxo), &membership_proof));
            }

            // walk forwards, applying
            for apply_block_hash in forwards.into_iter() {
                // Was the UTXO confirmed in this block?
                // This can occur in some edge cases of forward-only
                // resynchronization. In this case, assume the
                // membership proof is already synced to this block.
                if confirming_block == apply_block_hash {
                    continue;
                }

                let apply_block = self
                    .chain
                    .archival_state
                    .as_ref()
                    .unwrap()
                    .get_block(apply_block_hash)
                    .await?
                    .unwrap();
                let addition_records = apply_block.body.mutator_set_update.additions;
                let removal_records = apply_block.body.mutator_set_update.removals;
                let mut block_msa = apply_block.body.previous_mutator_set_accumulator.clone();

                // apply additions
                for addition_record in addition_records.iter() {
                    membership_proof
                        .update_from_addition(
                            &Hash::hash(&monitored_utxo.utxo),
                            &block_msa,
                            addition_record,
                        )
                        .expect("Could not update membership proof with addition record.");
                    block_msa.add(addition_record);
                }

                // apply removals
                for removal_record in removal_records.iter() {
                    membership_proof
                        .update_from_remove(removal_record)
                        .expect("Could not update membership proof from removal record.");
                    block_msa.remove(removal_record);
                }

                assert_eq!(block_msa, apply_block.body.next_mutator_set_accumulator);
            }

            // store updated membership proof
            monitored_utxo.add_membership_proof_for_tip(tip_hash, membership_proof);
            monitored_utxos.set(i, monitored_utxo);
        }

        // mark as synced
        self.wallet_state
            .wallet_db
            .lock()
            .await
            .set_sync_label(tip_hash);

        Ok(())
    }
}

#[cfg(test)]
mod global_state_tests {
    use crate::{
        config_models::network::Network,
        tests::shared::{get_mock_global_state, make_mock_block},
    };
    use rand::thread_rng;
    use secp256k1::Secp256k1;
    use tracing_test::traced_test;

    use super::{wallet::WalletSecret, *};

    #[traced_test]
    #[tokio::test]
    async fn premine_recipient_can_spend_genesis_block_output() {
        let other_wallet = WalletSecret::new(wallet::generate_secret_key());
        let global_state = get_mock_global_state(Network::Main, 2, None).await;
        let output_utxo = Utxo {
            amount: 20.into(),
            public_key: other_wallet.get_public_key(),
        };
        let tx: Transaction = global_state
            .create_transaction(vec![output_utxo], 1.into())
            .await
            .unwrap();

        assert!(tx.is_valid_for_devnet(None));
        assert_eq!(
            2,
            tx.outputs.len(),
            "tx must have a send output and a change output"
        );
        assert_eq!(
            1,
            tx.inputs.len(),
            "tx must have exactly one input, a genesis UTXO"
        );

        // Test with a transaction with three outputs and one (premine) input
        let mut output_utxos: Vec<Utxo> = vec![];
        for i in 2..5 {
            let utxo = Utxo {
                amount: i.into(),
                public_key: other_wallet.get_public_key(),
            };
            output_utxos.push(utxo);
        }

        let new_tx: Transaction = global_state
            .create_transaction(output_utxos, 1.into())
            .await
            .unwrap();
        assert!(new_tx.is_valid_for_devnet(None));
        assert_eq!(
            4,
            new_tx.outputs.len(),
            "tx must have three send outputs and a change output"
        );
        assert_eq!(
            1,
            new_tx.inputs.len(),
            "tx must have exactly one input, a genesis UTXO"
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn resync_ms_membership_proofs_test() -> Result<()> {
        let global_state = get_mock_global_state(Network::Main, 2, None).await;

        let (_secret_key, public_key): (secp256k1::SecretKey, secp256k1::PublicKey) =
            Secp256k1::new().generate_keypair(&mut thread_rng());

        // 1. Create new block 1 and store it to the DB
        let genesis_block = global_state
            .chain
            .archival_state
            .as_ref()
            .unwrap()
            .get_latest_block()
            .await;
        let mock_block_1a = make_mock_block(&genesis_block, None, public_key);
        {
            let mut block_db_lock = global_state
                .chain
                .archival_state
                .as_ref()
                .unwrap()
                .block_index_db
                .lock()
                .await;
            global_state
                .chain
                .archival_state
                .as_ref()
                .unwrap()
                .write_block(
                    Box::new(mock_block_1a.clone()),
                    &mut block_db_lock,
                    Some(mock_block_1a.header.proof_of_work_family),
                )?;
        }

        // Verify that wallet has a monitored UTXO (from genesis)
        assert!(!global_state.wallet_state.get_balance().await.is_zero());

        // Verify that this is unsynced with mock_block_1a
        assert!(
            global_state
                .wallet_state
                .is_synced_to(genesis_block.hash)
                .await
        );
        assert!(
            !global_state
                .wallet_state
                .is_synced_to(mock_block_1a.hash)
                .await
        );

        // Call resync
        global_state
            .resync_membership_proofs_to_tip(mock_block_1a.hash)
            .await
            .unwrap();

        // Verify that it is synced
        assert!(
            global_state
                .wallet_state
                .is_synced_to(mock_block_1a.hash)
                .await
        );

        Ok(())
    }
}
