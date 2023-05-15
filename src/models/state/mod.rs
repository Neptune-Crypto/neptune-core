use anyhow::{bail, Result};
use itertools::Itertools;
use mutator_set_tf::util_types::mutator_set::addition_record::AdditionRecord;
use mutator_set_tf::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use mutator_set_tf::util_types::mutator_set::mutator_set_trait::{commit, MutatorSet};
use mutator_set_tf::util_types::mutator_set::removal_record::RemovalRecord;
use num_traits::{CheckedSub, Zero};
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;
use twenty_first::util_types::storage_schema::StorageWriter;
use twenty_first::util_types::storage_vec::StorageVec;

use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::shared_math::digest::Digest;
use twenty_first::util_types::algebraic_hasher::{AlgebraicHasher, Hashable};

use self::blockchain_state::BlockchainState;
use self::mempool::Mempool;
use self::networking_state::NetworkingState;
use self::wallet::utxo_notification_pool::UtxoNotifier;
use self::wallet::wallet_state::WalletState;
use super::blockchain::transaction::transaction_kernel::TransactionKernel;
use super::blockchain::transaction::utxo::Utxo;
use super::blockchain::transaction::{amount::Amount, Transaction};
use super::blockchain::transaction::{PrimitiveWitness, PubScript, Witness};
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

#[derive(Debug, Clone)]
pub struct UtxoReceiverData {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
    pub receiver_privacy_digest: Digest,
    pub pubscript: PubScript,
    pub pubscript_input: Vec<BFieldElement>,
}

impl GlobalState {
    /// Create a transaction that sends coins to the given
    /// `recipient_utxos` from some selection of owned UTXOs.
    /// A change UTXO will be added if needed; the caller
    /// does not need to supply this. The caller must supply
    /// the fee that they are willing to spend to have this
    /// transaction mined.
    ///
    /// Returns the transaction and a vector containing the sender
    /// randomness for each output UTXO.
    pub async fn create_transaction(
        &self,
        receiver_data: Vec<UtxoReceiverData>,
        fee: Amount,
    ) -> Result<Transaction> {
        // TODO: Spending key should probably be input to this function
        // acquire a lock on `WalletState` to prevent it from being updated
        let mut wallet_db_lock = self.wallet_state.wallet_db.lock().await;

        // Get the block tip as the transaction is made relative to it
        let bc_tip = self.chain.light_state.latest_block.lock().await.to_owned();

        // Get the UTXOs required for this transaction
        let total_spend: Amount = receiver_data
            .iter()
            .map(|x| x.utxo.get_native_coin_amount())
            .sum::<Amount>()
            + fee;
        let spendable_utxos_and_mps: Vec<(Utxo, MsMembershipProof<Hash>)> = self
            .wallet_state
            .allocate_sufficient_input_funds_from_lock(&mut wallet_db_lock, total_spend, &bc_tip)?;

        // Create all removal records. These must be relative to the block tip.
        let msa_tip = bc_tip.body.next_mutator_set_accumulator;
        let mut inputs: Vec<RemovalRecord<Hash>> = vec![];
        let mut input_amount: Amount = Amount::zero();
        for (spendable_utxo, mp) in spendable_utxos_and_mps.iter() {
            let removal_record = msa_tip.kernel.drop(&Hash::hash(spendable_utxo), mp);
            inputs.push(removal_record);

            input_amount = input_amount + spendable_utxo.get_native_coin_amount();
        }

        let mut transaction_outputs: Vec<AdditionRecord> = vec![];
        let mut output_utxos: Vec<Utxo> = vec![];
        for rd in receiver_data.iter() {
            let addition_record = commit::<Hash>(
                &Hash::hash(&rd.utxo),
                &rd.sender_randomness,
                &rd.receiver_privacy_digest,
            );
            transaction_outputs.push(addition_record);
            output_utxos.push(rd.utxo.to_owned());
        }

        // Send remaining amount back to self
        let change_amount = match input_amount.checked_sub(&total_spend) {
            Some(amt) => amt,
            None => {
                bail!("Cannot create change UTXO with negative amount.");
            }
        };

        // add change UTXO if necessary
        if input_amount > total_spend {
            let own_spending_key_for_change = self
                .wallet_state
                .wallet_secret
                .nth_generation_spending_key(0);
            let own_receiving_address = own_spending_key_for_change.to_address();
            let lock_script = own_receiving_address.lock_script();
            let change_utxo = Utxo {
                coins: change_amount.to_native_coins(),
                lock_script,
            };
            let receiver_digest = own_receiving_address.privacy_digest;
            let change_sender_randomness = self.wallet_state.get_sender_randomness(
                &change_utxo,
                &receiver_digest,
                bc_tip.header.height,
            );
            let change_addition_record = commit::<Hash>(
                &Hash::hash(&change_utxo),
                &change_sender_randomness,
                &receiver_digest,
            );
            transaction_outputs.push(change_addition_record);
            output_utxos.push(change_utxo.clone());

            // Add change UTXO to pool of expected incoming UTXOs
            let receiver_preimage = own_spending_key_for_change.privacy_preimage;
            let _change_addition_record = self
                .wallet_state
                .expected_utxos
                .write()
                .unwrap()
                .add_expected_utxo(
                    change_utxo,
                    change_sender_randomness,
                    receiver_preimage,
                    UtxoNotifier::Myself,
                )
                .expect("Adding change UTXO to UTXO notification pool must succeed");
        }

        let pubscript_hashes_and_inputs = receiver_data
            .iter()
            .map(|x| (Hash::hash(&x.pubscript), x.pubscript_input.clone()))
            .collect_vec();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        let kernel = TransactionKernel {
            inputs,
            outputs: transaction_outputs,
            pubscript_hashes_and_inputs,
            fee,
            timestamp: BFieldElement::new(timestamp.try_into().unwrap()),
        };

        // TODO: This needs to be fetched from monitored UTXOs. Can be different for each
        // input UTXO for this transaction
        let spending_key = self
            .wallet_state
            .wallet_secret
            .nth_generation_spending_key(0);
        let input_utxos = spendable_utxos_and_mps
            .iter()
            .map(|(utxo, _mp)| utxo)
            .cloned()
            .collect_vec();
        let input_membership_proofs = spendable_utxos_and_mps
            .iter()
            .map(|(_utxo, mp)| mp)
            .cloned()
            .collect_vec();
        let pubscripts = receiver_data
            .iter()
            .map(|rd| rd.pubscript.clone())
            .collect_vec();

        let witness = PrimitiveWitness {
            input_utxos: input_utxos.clone(),
            lock_script_witnesses: vec![
                spending_key.unlock_key.to_sequence();
                spendable_utxos_and_mps.len()
            ],
            input_membership_proofs,
            output_utxos: output_utxos.clone(),
            pubscripts,
        };

        let transaction = Transaction {
            kernel,
            witness: Witness::Primitive(witness),
        };

        Ok(transaction)
    }

    // Storing IP addresses is, according to this answer, not a violation of GDPR:
    // https://law.stackexchange.com/a/28609/45846
    // Wayback machine: https://web.archive.org/web/20220708143841/https://law.stackexchange.com/questions/28603/how-to-satisfy-gdprs-consent-requirement-for-ip-logging/28609
    pub async fn write_peer_standing_on_decrease(
        &self,
        ip: IpAddr,
        current_standing: PeerStanding,
    ) {
        let mut peer_databases = self.net.peer_databases.lock().await;
        let old_standing = peer_databases.peer_standings.get(ip);

        if old_standing.is_none() || old_standing.unwrap().standing > current_standing.standing {
            peer_databases.peer_standings.put(ip, current_standing)
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

            debug!(
                "Resyncing monitored UTXO number {i}, with hash {}",
                Hash::hash(&monitored_utxo.utxo)
            );

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
                let removal_records = revert_block.body.transaction.kernel.inputs.clone();
                for removal_record in removal_records.iter().rev() {
                    // membership_proof.revert_update_from_removal(&removal);
                    membership_proof
                        .revert_update_from_remove(removal_record)
                        .expect("Could not revert membership proof from removal record.");
                }

                // revert additions
                let previous_mutator_set =
                    revert_block.body.previous_mutator_set_accumulator.clone();
                membership_proof.revert_update_from_batch_addition(&previous_mutator_set);

                // assert valid
                assert!(previous_mutator_set
                    .verify(&Hash::hash(&monitored_utxo.utxo), &membership_proof), "Failed to verify monitored UTXO {monitored_utxo:?}\n against previous MSA in block {revert_block:?}");
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
                let addition_records = apply_block.body.transaction.kernel.outputs;
                let removal_records = apply_block.body.transaction.kernel.inputs;
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

        // Update sync label and persist
        self.wallet_state
            .wallet_db
            .lock()
            .await
            .set_sync_label(tip_hash);
        self.wallet_state.wallet_db.lock().await.persist();

        Ok(())
    }
}

#[cfg(test)]
mod global_state_tests {
    use crate::{
        config_models::network::Network,
        models::{blockchain::block::Block, state::wallet::utxo_notification_pool::UtxoNotifier},
        tests::shared::{get_mock_global_state, make_mock_block},
    };
    use rand::{random, thread_rng};
    use secp256k1::Secp256k1;
    use tracing_test::traced_test;

    use super::{wallet::WalletSecret, *};

    async fn wallet_state_has_all_valid_mps_for(
        wallet_state: &WalletState,
        tip_block: &Block,
    ) -> bool {
        let wallet_db_lock = wallet_state.wallet_db.lock().await;
        let monitored_utxos = &wallet_db_lock.monitored_utxos;
        for i in 0..monitored_utxos.len() {
            let monitored_utxo = monitored_utxos.get(i);
            let current_mp = monitored_utxo.get_membership_proof_for_block(&tip_block.hash);

            match current_mp {
                Some(mp) => {
                    if !tip_block
                        .body
                        .next_mutator_set_accumulator
                        .verify(&Hash::hash(&monitored_utxo.utxo), &mp)
                    {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }

    #[traced_test]
    #[tokio::test]
    async fn premine_recipient_can_spend_genesis_block_output() {
        let other_wallet = WalletSecret::new(wallet::generate_secret_key());
        let global_state = get_mock_global_state(Network::Main, 2, None).await;
        let twenty_amount: Amount = 20.into();
        let twenty_coins = twenty_amount.to_native_coins();
        let recipient_address = other_wallet.nth_generation_spending_key(0).to_address();
        let main_lock_script = recipient_address.lock_script();
        let output_utxo = Utxo {
            coins: twenty_coins,
            lock_script: main_lock_script,
        };
        let sender_randomness = Digest::default();
        let receiver_privacy_digest = recipient_address.privacy_digest;
        let (pubscript, pubscript_input) = recipient_address
            .generate_pubscript_and_input(&output_utxo, sender_randomness)
            .unwrap();
        let receiver_data = vec![UtxoReceiverData {
            utxo: output_utxo.clone(),
            sender_randomness,
            receiver_privacy_digest,
            pubscript,
            pubscript_input,
        }];
        let tx: Transaction = global_state
            .create_transaction(receiver_data, 1.into())
            .await
            .unwrap();

        assert!(tx.is_valid(None));
        assert_eq!(
            2,
            tx.kernel.outputs.len(),
            "tx must have a send output and a change output"
        );
        assert_eq!(
            1,
            tx.kernel.inputs.len(),
            "tx must have exactly one input, a genesis UTXO"
        );

        // Test with a transaction with three outputs and one (premine) input
        let mut other_receiver_data = vec![];
        let mut output_utxos: Vec<Utxo> = vec![];
        for i in 2..5 {
            let amount: Amount = i.into();
            let that_many_coins = amount.to_native_coins();
            let receiving_address = other_wallet.nth_generation_spending_key(0).to_address();
            let lock_script = receiving_address.lock_script();
            let utxo = Utxo {
                coins: that_many_coins,
                lock_script,
            };
            let other_sender_randomness = Digest::default();
            let other_receiver_digest = receiving_address.privacy_digest;
            let (other_pubscript, other_pubscript_input) = receiving_address
                .generate_pubscript_and_input(&utxo, other_sender_randomness)
                .unwrap();
            output_utxos.push(utxo.clone());
            other_receiver_data.push(UtxoReceiverData {
                utxo,
                sender_randomness: other_sender_randomness,
                receiver_privacy_digest: other_receiver_digest,
                pubscript: other_pubscript,
                pubscript_input: other_pubscript_input,
            });
        }

        let new_tx: Transaction = global_state
            .create_transaction(other_receiver_data, 1.into())
            .await
            .unwrap();
        assert!(new_tx.is_valid(None));
        assert_eq!(
            4,
            new_tx.kernel.outputs.len(),
            "tx must have three send outputs and a change output"
        );
        assert_eq!(
            1,
            new_tx.kernel.inputs.len(),
            "tx must have exactly one input, a genesis UTXO"
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn resync_ms_membership_proofs_simple_test() -> Result<()> {
        let global_state = get_mock_global_state(Network::Main, 2, None).await;

        let other_receiver_wallet_secret = WalletSecret::new(random());
        let other_receiver_address = other_receiver_wallet_secret
            .nth_generation_spending_key(0)
            .to_address();

        // 1. Create new block 1 and store it to the DB
        let genesis_block = global_state
            .chain
            .archival_state
            .as_ref()
            .unwrap()
            .get_latest_block()
            .await;
        let (mock_block_1a, _, _) = make_mock_block(&genesis_block, None, other_receiver_address);
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

        // Verify that MPs are valid
        assert!(
            wallet_state_has_all_valid_mps_for(&global_state.wallet_state, &mock_block_1a).await
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn resync_ms_membership_proofs_fork_test() -> Result<()> {
        let global_state = get_mock_global_state(Network::Main, 2, None).await;
        let own_spending_key = global_state
            .wallet_state
            .wallet_secret
            .nth_generation_spending_key(0);
        let own_receiving_address = own_spending_key.to_address();

        // 1. Create new block 1a where we receive a coinbase UTXO, store it
        let genesis_block = global_state
            .chain
            .archival_state
            .as_ref()
            .unwrap()
            .get_latest_block()
            .await;
        let (mock_block_1a, coinbase_utxo, coinbase_output_randomness) =
            make_mock_block(&genesis_block, None, own_receiving_address.clone());
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
            let mut wallet_db_lock = global_state.wallet_state.wallet_db.lock().await;
            global_state
                .wallet_state
                .expected_utxos
                .write()
                .unwrap()
                .add_expected_utxo(
                    coinbase_utxo,
                    coinbase_output_randomness,
                    own_spending_key.privacy_preimage,
                    UtxoNotifier::OwnMiner,
                )
                .unwrap();
            global_state
                .wallet_state
                .update_wallet_state_with_new_block(&mock_block_1a, &mut wallet_db_lock)
                .unwrap();
        }

        // Verify that wallet has monitored UTXOs, from genesis and from block_1a
        let wallet_status = global_state.wallet_state.get_wallet_status_from_lock(
            &mut global_state.wallet_state.wallet_db.lock().await,
            &mock_block_1a,
        );
        assert_eq!(2, wallet_status.synced_unspent.len());

        // Make a new fork from genesis that makes us lose the coinbase UTXO of block 1a
        let other_wallet_secret = WalletSecret::new(random());
        let other_receiving_address = other_wallet_secret
            .nth_generation_spending_key(0)
            .to_address();
        let mut parent_block = genesis_block;
        for _ in 0..5 {
            let (next_block, _, _) =
                make_mock_block(&parent_block, None, other_receiving_address.clone());
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
                    Box::new(next_block.clone()),
                    &mut block_db_lock,
                    Some(next_block.header.proof_of_work_family),
                )?;
            let mut wallet_db_lock = global_state.wallet_state.wallet_db.lock().await;
            global_state
                .wallet_state
                .update_wallet_state_with_new_block(&next_block, &mut wallet_db_lock)
                .unwrap();
            parent_block = next_block;
        }

        // Call resync which fails to sync the UTXO that was abandoned when block 1a was abandoned
        global_state
            .resync_membership_proofs_to_tip(parent_block.hash)
            .await
            .unwrap();

        // Verify that one MUTXO is unsynced, and that 1 (from genesis) is synced
        let wallet_status_after_forking = global_state.wallet_state.get_wallet_status_from_lock(
            &mut global_state.wallet_state.wallet_db.lock().await,
            &parent_block,
        );
        assert_eq!(1, wallet_status_after_forking.synced_unspent.len());
        assert_eq!(1, wallet_status_after_forking.unsynced_unspent.len());

        // Verify that the MUTXO from block 1a is considered abandoned, and that the one from
        // genesis block is not.
        let wallet_db_lock = global_state.wallet_state.wallet_db.lock().await;
        let monitored_utxos = &wallet_db_lock.monitored_utxos;
        assert!(
            !monitored_utxos
                .get(0)
                .was_abandoned(
                    &parent_block.hash,
                    global_state.chain.archival_state.as_ref().unwrap()
                )
                .await
        );
        assert!(
            monitored_utxos
                .get(1)
                .was_abandoned(
                    &parent_block.hash,
                    global_state.chain.archival_state.as_ref().unwrap()
                )
                .await
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn resync_ms_membership_proofs_across_stale_fork() -> Result<()> {
        let global_state = get_mock_global_state(Network::Main, 2, None).await;
        let wallet_secret = global_state.wallet_state.wallet_secret.clone();
        let own_spending_key = wallet_secret.nth_generation_spending_key(0);
        let own_receiving_address = own_spending_key.to_address();
        let other_wallet_secret = WalletSecret::new(random());
        let other_receiving_address = other_wallet_secret
            .nth_generation_spending_key(0)
            .to_address();

        // 1. Create new block 1a where we receive a coinbase UTXO, store it
        let genesis_block = global_state
            .chain
            .archival_state
            .as_ref()
            .unwrap()
            .get_latest_block()
            .await;
        assert!(genesis_block.header.height.is_genesis());
        let (mock_block_1a, coinbase_utxo_1a, cb_utxo_output_randomness_1a) =
            make_mock_block(&genesis_block, None, own_receiving_address);
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
            global_state
                .wallet_state
                .expected_utxos
                .write()
                .unwrap()
                .add_expected_utxo(
                    coinbase_utxo_1a,
                    cb_utxo_output_randomness_1a,
                    own_spending_key.privacy_preimage,
                    UtxoNotifier::OwnMiner,
                )
                .unwrap();
            let mut wallet_db_lock = global_state.wallet_state.wallet_db.lock().await;
            global_state
                .wallet_state
                .update_wallet_state_with_new_block(&mock_block_1a, &mut wallet_db_lock)
                .unwrap();

            // Verify that UTXO was recorded
            let wallet_status_after_1a = global_state
                .wallet_state
                .get_wallet_status_from_lock(&mut wallet_db_lock, &mock_block_1a);
            assert_eq!(2, wallet_status_after_1a.synced_unspent.len());
        }

        // Add 5 blocks on top of 1a
        let mut fork_a_block = mock_block_1a.clone();
        for _ in 0..100 {
            let (next_a_block, _, _) =
                make_mock_block(&fork_a_block, None, other_receiving_address.clone());
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
                    Box::new(next_a_block.clone()),
                    &mut block_db_lock,
                    Some(next_a_block.header.proof_of_work_family),
                )?;
            let mut wallet_db_lock = global_state.wallet_state.wallet_db.lock().await;
            global_state
                .wallet_state
                .update_wallet_state_with_new_block(&next_a_block, &mut wallet_db_lock)
                .unwrap();
            fork_a_block = next_a_block;
        }

        // Verify that all both MUTXOs have synced MPs
        let wallet_status_on_a_fork = global_state.wallet_state.get_wallet_status_from_lock(
            &mut global_state.wallet_state.wallet_db.lock().await,
            &fork_a_block,
        );

        assert_eq!(2, wallet_status_on_a_fork.synced_unspent.len());

        // Fork away from the "a" chain to the "b" chain, with block 1a as LUCA
        let mut fork_b_block = mock_block_1a.clone();
        for _ in 0..100 {
            let (next_b_block, _, _) =
                make_mock_block(&fork_b_block, None, other_receiving_address.clone());
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
                    Box::new(next_b_block.clone()),
                    &mut block_db_lock,
                    Some(next_b_block.header.proof_of_work_family),
                )?;
            let mut wallet_db_lock = global_state.wallet_state.wallet_db.lock().await;
            global_state
                .wallet_state
                .update_wallet_state_with_new_block(&next_b_block, &mut wallet_db_lock)
                .unwrap();
            fork_b_block = next_b_block;
        }

        // Verify that there are zero MUTXOs with synced MPs
        let wallet_status_on_b_fork_before_resync =
            global_state.wallet_state.get_wallet_status_from_lock(
                &mut global_state.wallet_state.wallet_db.lock().await,
                &fork_b_block,
            );
        assert_eq!(
            0,
            wallet_status_on_b_fork_before_resync.synced_unspent.len()
        );
        assert_eq!(
            2,
            wallet_status_on_b_fork_before_resync.unsynced_unspent.len()
        );

        // Run the resync and verify that MPs are synced
        global_state
            .resync_membership_proofs_to_tip(fork_b_block.hash)
            .await
            .unwrap();
        let wallet_status_on_b_fork_after_resync =
            global_state.wallet_state.get_wallet_status_from_lock(
                &mut global_state.wallet_state.wallet_db.lock().await,
                &fork_b_block,
            );
        assert_eq!(2, wallet_status_on_b_fork_after_resync.synced_unspent.len());
        assert_eq!(
            0,
            wallet_status_on_b_fork_after_resync.unsynced_unspent.len()
        );

        // `wallet_state_has_all_valid_mps_for`
        // Make a new chain c with genesis block as LUCA. Verify that the genesis UTXO can be synced
        // to this new chain
        let mut fork_c_block = genesis_block.clone();
        for _ in 0..100 {
            let (next_c_block, _, _) =
                make_mock_block(&fork_c_block, None, other_receiving_address.clone());
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
                    Box::new(next_c_block.clone()),
                    &mut block_db_lock,
                    Some(next_c_block.header.proof_of_work_family),
                )?;
            let mut wallet_db_lock = global_state.wallet_state.wallet_db.lock().await;
            global_state
                .wallet_state
                .update_wallet_state_with_new_block(&next_c_block, &mut wallet_db_lock)
                .unwrap();
            fork_c_block = next_c_block;
        }

        // Verify that there are zero MUTXOs with synced MPs
        let wallet_status_on_c_fork_before_resync =
            global_state.wallet_state.get_wallet_status_from_lock(
                &mut global_state.wallet_state.wallet_db.lock().await,
                &fork_c_block,
            );
        assert_eq!(
            0,
            wallet_status_on_c_fork_before_resync.synced_unspent.len()
        );
        assert_eq!(
            2,
            wallet_status_on_c_fork_before_resync.unsynced_unspent.len()
        );

        // Run the resync and verify that UTXO from genesis is synced, but that
        // UTXO from 1a is not synced.
        global_state
            .resync_membership_proofs_to_tip(fork_c_block.hash)
            .await
            .unwrap();
        let wallet_status_on_c_fork_after_resync =
            global_state.wallet_state.get_wallet_status_from_lock(
                &mut global_state.wallet_state.wallet_db.lock().await,
                &fork_c_block,
            );
        assert_eq!(1, wallet_status_on_c_fork_after_resync.synced_unspent.len());
        assert_eq!(
            1,
            wallet_status_on_c_fork_after_resync.unsynced_unspent.len()
        );

        // Also check that UTXO from 1a is considered abandoned
        let wallet_db_lock = global_state.wallet_state.wallet_db.lock().await;
        let monitored_utxos = &wallet_db_lock.monitored_utxos;
        assert!(
            !monitored_utxos
                .get(0)
                .was_abandoned(
                    &fork_c_block.hash,
                    global_state.chain.archival_state.as_ref().unwrap()
                )
                .await
        );
        assert!(
            monitored_utxos
                .get(1)
                .was_abandoned(
                    &fork_c_block.hash,
                    global_state.chain.archival_state.as_ref().unwrap()
                )
                .await
        );

        Ok(())
    }
}
