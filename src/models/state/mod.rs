use anyhow::Result;
use mutator_set_tf::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use num_traits::{One, Zero};
use std::{
    net::{IpAddr, SocketAddr},
    time::{SystemTime, UNIX_EPOCH},
};
use twenty_first::shared_math::b_field_element::BFieldElement;

use self::{
    blockchain_state::BlockchainState, mempool::Mempool, networking_state::NetworkingState,
    wallet::WalletState,
};
use super::blockchain::{
    digest::{Digest, Hashable2},
    transaction::{devnet_input::DevNetInput, utxo::Utxo, Amount, Transaction},
};
use crate::{
    config_models::cli_args,
    database::{leveldb::LevelDB, rusty::RustyLevelDBIterator},
    models::peer::{HandshakeData, PeerStanding},
    Hash, VERSION,
};

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
    /// Create a transaction from own UTXOs. A change UTXO will be added if needed, the caller
    /// does not need to supply this.
    pub async fn create_transaction(&self, output_utxos: Vec<Utxo>) -> Result<Transaction> {
        // acquire a lock on `WalletState` to prevent it from being updated
        let mut wallet_db_lock = self.wallet_state.wallet_db.lock().await;

        // Acquire a lock on `LightState` to prevent it from being updated
        let light_state_lock = self.chain.light_state.latest_block.lock().await;

        // Get the UTXOs required for this transaction
        let fee = Amount::one(); // TODO: Set this to something more sane
        let total_spend: Amount = output_utxos.iter().map(|x| x.amount).sum::<Amount>() + fee;
        let spendable_utxos_and_mps: Vec<(Utxo, MsMembershipProof<Hash>)> = self
            .wallet_state
            .allocate_sufficient_input_funds_with_lock(&mut wallet_db_lock, total_spend)?;

        // Create all removal records. These must be relative to the block tip.
        let mut msa_tip = light_state_lock.body.next_mutator_set_accumulator.clone();
        let mut inputs: Vec<DevNetInput> = vec![];
        let mut input_amount: Amount = Amount::zero();
        for (spendable_utxo, mp) in spendable_utxos_and_mps {
            let removal_record = msa_tip
                .set_commitment
                .drop(&spendable_utxo.neptune_hash().values(), &mp);
            input_amount = input_amount + spendable_utxo.amount;
            inputs.push(DevNetInput {
                utxo: spendable_utxo,
                membership_proof: mp.into(),
                removal_record,
                signature: None,
            });
        }

        let mut outputs: Vec<(Utxo, Digest)> = vec![];
        for output_utxo in output_utxos {
            let output_randomness = self.wallet_state.next_output_randomness().await;
            outputs.push((output_utxo, output_randomness));
        }

        // Send remaining amount back to self
        if input_amount > total_spend {
            let change_utxo = Utxo {
                amount: input_amount - total_spend,
                public_key: self.wallet_state.wallet.get_public_key(),
            };
            outputs.push((
                change_utxo,
                self.wallet_state.next_output_randomness().await,
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
        transaction.sign(&self.wallet_state.wallet);

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
}

#[cfg(test)]
mod global_state_tests {
    use crate::{config_models::network::Network, tests::shared::get_mock_global_state};
    use tracing_test::traced_test;

    use super::{wallet::Wallet, *};

    #[traced_test]
    #[tokio::test]
    async fn premine_recipient_can_spend_genesis_block_output() {
        let other_wallet = Wallet::new(wallet::generate_secret_key());
        let global_state = get_mock_global_state(Network::Main, 2, None).await;
        let output_utxo = Utxo {
            amount: 20.into(),
            public_key: other_wallet.get_public_key(),
        };
        let tx: Transaction = global_state
            .create_transaction(vec![output_utxo])
            .await
            .unwrap();

        assert!(tx.devnet_is_valid(None));
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

        let new_tx: Transaction = global_state.create_transaction(output_utxos).await.unwrap();
        assert!(new_tx.devnet_is_valid(None));
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
}
