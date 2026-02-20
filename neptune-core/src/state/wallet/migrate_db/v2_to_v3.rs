use std::collections::VecDeque;

use futures::pin_mut;
use tracing::debug;

use crate::application::database::storage::storage_schema::SimpleRustyStorage;
use crate::application::database::storage::storage_vec::traits::*;
use crate::state::wallet::monitored_utxo::MonitoredUtxo;
use crate::state::wallet::monitored_utxo::MonitoredUtxoSpentStatus;
use crate::state::wallet::wallet_db_tables::WalletDbTables;

pub(super) async fn migrate(storage: &mut SimpleRustyStorage) -> anyhow::Result<()> {
    // reset the schema, so we start with table_count = 0.
    storage.reset_schema();

    // add a DbtVec<MonitoredUtxoV1> to the schema at the correct position
    // so the correct key-prefix is used. This allows for the reading of
    // v2-monitored UTXOs.
    storage.schema.table_count = WalletDbTables::monitored_utxos_table_count();
    let mutxos_v2 = storage
        .schema
        .new_vec::<migration::schema_v2::MonitoredUtxo>("mutxo_v2")
        .await;

    debug!(
        "Preparing to convert {} monitored UTXOs to v3.",
        mutxos_v2.len().await
    );

    // reset the schema again, to prepare for loading v3 schema.
    storage.reset_schema();

    // load v3 schema tables
    let mut tables = WalletDbTables::load_schema_in_order(storage).await;
    let mutxos_v3 = &mut tables.monitored_utxos;

    /* Migrate monitored UTXOs */
    let mutxos_v2s = mutxos_v2.stream().await;
    pin_mut!(mutxos_v2s); // needed for iteration

    while let Some((list_index, mutxo_v2)) = mutxos_v2s.next().await {
        // Conversion implies three changes:
        // 1. The spent status is now an enum, rather than an Option. This
        //    allows for the status that a UTXO is spent without knowing the
        //    block in which it was spent.
        // 2. The blockhash_to_membership_proof is now empty, as we no longer
        // maintain membership proofs for UTXOs, as we can generate them on
        // demand since all nodes, at the time of the writing, are archival.
        let mutxo_v3 = MonitoredUtxo {
            utxo: mutxo_v2.utxo,
            aocl_leaf_index: mutxo_v2.aocl_leaf_index,
            sender_randomness: mutxo_v2.sender_randomness,
            receiver_preimage: mutxo_v2.receiver_preimage,
            blockhash_to_membership_proof: VecDeque::new(),
            number_of_mps_per_utxo: 0,
            spent: match mutxo_v2.spent_in_block {
                None => MonitoredUtxoSpentStatus::Unspent,
                Some((block_hash, block_timestamp, block_height)) => {
                    MonitoredUtxoSpentStatus::SpentIn {
                        block_hash,
                        block_height,
                        block_timestamp,
                    }
                }
            },
            confirmed_in_block: mutxo_v2.confirmed_in_block,
            abandoned_at: mutxo_v2.abandoned_at,
        };

        // Overwrite the v2 monitored UTXO with a v3.
        debug!("Inserting monitored UTXO number {list_index}");
        mutxos_v3.set(list_index, mutxo_v3).await;
    }

    // set schema version to v3 since migration is complete
    tables.schema_version.set(3).await;

    // success!
    Ok(())
}

pub(super) mod migration {
    // Wallet database definitions relating to v2.
    pub(in crate::state::wallet::migrate_db) mod schema_v2 {
        use std::collections::VecDeque;

        use serde::Deserialize;
        use serde::Serialize;
        use tasm_lib::prelude::Digest;
        use tasm_lib::prelude::Tip5;

        use crate::api::export::AdditionRecord;
        use crate::api::export::BlockHeight;
        use crate::application::database::storage::storage_schema::DbtMap;
        use crate::application::database::storage::storage_schema::DbtSingleton;
        use crate::application::database::storage::storage_schema::DbtVec;
        use crate::application::database::storage::storage_schema::SimpleRustyStorage;
        use crate::application::database::storage::storage_vec::Index;
        use crate::protocol::consensus::transaction::utxo::Utxo;
        use crate::state::wallet::expected_utxo::ExpectedUtxo;
        use crate::state::wallet::sent_transaction::SentTransaction;
        use crate::state::wallet::wallet_db_tables::StrongUtxoKey;
        use crate::state::Timestamp;
        use crate::util_types::mutator_set::commit;
        use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
        use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;

        // this is a copy of MonitoredUtxo as it was in v2 schema.
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
        pub(in crate::state::wallet::migrate_db) struct MonitoredUtxo {
            pub utxo: Utxo,
            pub aocl_leaf_index: u64,
            pub sender_randomness: Digest,
            pub receiver_preimage: Digest,
            pub blockhash_to_membership_proof: VecDeque<(Digest, MsMembershipProof)>,
            pub number_of_mps_per_utxo: usize,
            pub spent_in_block: Option<(Digest, Timestamp, BlockHeight)>,
            pub confirmed_in_block: (Digest, Timestamp, BlockHeight),
            pub abandoned_at: Option<(Digest, Timestamp, BlockHeight)>,
        }

        impl MonitoredUtxo {
            /// Return the absolute index set associated with this mined UTXO.
            pub(in crate::state::wallet::migrate_db) fn absolute_indices(
                &self,
            ) -> AbsoluteIndexSet {
                let item = Tip5::hash(&self.utxo);

                AbsoluteIndexSet::compute(
                    item,
                    self.sender_randomness,
                    self.receiver_preimage,
                    self.aocl_leaf_index,
                )
            }

            /// Return the addition record associated with this UTXO.
            pub(in crate::state::wallet::migrate_db) fn addition_record(&self) -> AdditionRecord {
                let item = Tip5::hash(&self.utxo);
                commit(item, self.sender_randomness, self.receiver_preimage.hash())
            }
        }

        /// Load fields in order, as defined in v2.
        pub(in crate::state::wallet::migrate_db) async fn load_v2_schema_in_order(
            storage: &mut SimpleRustyStorage,
        ) -> V2WalletDbTables {
            let monitored_utxos = storage
                .schema
                .new_vec::<MonitoredUtxo>("monitored_utxos")
                .await;

            let expected_utxos = storage
                .schema
                .new_vec::<ExpectedUtxo>("expected_utxos")
                .await;

            let sent_transactions = storage
                .schema
                .new_vec::<SentTransaction>("sent_transactions")
                .await;

            let sync_label = storage.schema.new_singleton::<Digest>("sync_label").await;

            let counter = storage.schema.new_singleton::<u64>("counter").await;

            let generation_key_counter = storage
                .schema
                .new_singleton::<u64>("generation_key_counter")
                .await;
            let symmetric_key_counter = storage
                .schema
                .new_singleton::<u64>("symmetric_key_counter")
                .await;

            let schema_version = storage.schema.new_singleton::<u16>("schema_version").await;

            let strong_key_to_mutxo = storage.schema.new_map("strong_key_to_mutxo").await;

            let index_set_to_mutxo = storage.schema.new_map("absolute_index_set_to_mutxo").await;

            let addition_record_to_expected_utxo = storage
                .schema
                .new_map("addition_record_to_expected_utxo")
                .await;

            V2WalletDbTables {
                sync_label,
                monitored_utxos,
                expected_utxos,
                sent_transactions,
                counter,
                generation_key_counter,
                symmetric_key_counter,
                schema_version,
                strong_key_to_mutxo,
                index_set_to_mutxo,
                addition_record_to_expected_utxo,
            }
        }

        /// Wallet database tables as they looked in v2.
        #[expect(dead_code)]
        #[derive(Debug)]
        pub(in crate::state::wallet::migrate_db) struct V2WalletDbTables {
            pub monitored_utxos: DbtVec<MonitoredUtxo>,
            pub expected_utxos: DbtVec<ExpectedUtxo>,
            pub sent_transactions: DbtVec<SentTransaction>,
            pub sync_label: DbtSingleton<Digest>,
            pub counter: DbtSingleton<u64>,
            pub generation_key_counter: DbtSingleton<u64>,
            pub symmetric_key_counter: DbtSingleton<u64>,
            pub schema_version: DbtSingleton<u16>,
            pub strong_key_to_mutxo: DbtMap<StrongUtxoKey, Index>,
            pub index_set_to_mutxo: DbtMap<Digest, Index>,
            pub addition_record_to_expected_utxo: DbtMap<AdditionRecord, Index>,
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use macro_rules_attr::apply;

    use super::*;
    use crate::api::export::Network;
    use crate::application::database::NeptuneLevelDb;
    use crate::state::wallet::migrate_db::worker;
    use crate::state::wallet::rusty_wallet_database::RustyWalletDatabase;
    use crate::tests::shared::files::unit_test_data_directory;
    use crate::tests::shared_tokio_runtime;

    #[tracing_test::traced_test]
    #[apply(shared_tokio_runtime)]
    async fn migrate_real_v2_db_to_current_version() -> anyhow::Result<()> {
        // obtain source db path and target path
        let data_dir = unit_test_data_directory(Network::Testnet(0))?;
        let test_data_wallet_db_dir = worker::crate_root()
            .join("test_data/migrations/wallet_db/v2_to_v3/wallet_db.v2-with-mutxos");
        let wallet_database_path = data_dir.wallet_database_dir_path();

        // copy DB in test_data to wallet_database_path
        crate::copy_dir_recursive(&test_data_wallet_db_dir, &wallet_database_path)?;

        // Sleep to ensure data copying is completed on CI machines.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // open v2 DB file
        let db_v2 =
            NeptuneLevelDb::new(&wallet_database_path, &leveldb::options::Options::new()).await?;

        // connect to v2 Db with v3 RustyWalletDatabase.  This is where the
        // migration occurs.
        let wallet_db_v3 = RustyWalletDatabase::try_connect_and_migrate(db_v2).await?;

        let monitored_utxos = wallet_db_v3.monitored_utxos();
        assert_eq!(monitored_utxos.len().await, 2);

        let stream = monitored_utxos.stream().await;
        pin_mut!(stream);
        while let Some((_, mutxo)) = stream.next().await {
            assert_eq!(MonitoredUtxoSpentStatus::Unspent, mutxo.spent);
        }

        Ok(())
    }
}
