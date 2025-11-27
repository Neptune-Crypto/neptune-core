use futures::pin_mut;

use crate::application::database::storage::storage_schema::SimpleRustyStorage;
use crate::application::database::storage::storage_vec::traits::*;
use crate::state::wallet::wallet_db_tables::WalletDbTables;

/// migrates wallet db with schema-version v1 to v2
///
/// The only thing that changed in v2 is that a new mapping was added, a mapping
/// from AOCL leaf index to a list of indices into the monitored UTXOs list.
///
/// Older databases are migrated simply by iterating over all monitored UTXOs,
/// finding their AOCL leaf index from their respective mutator set membership
/// proofs and then inserting the key-value pair AOCL leaf index/monitored UTXO
/// index into the new mapping.
pub(super) async fn migrate(storage: &mut SimpleRustyStorage) -> anyhow::Result<()> {
    // obtain stream (iterator) of all monitored UTXOs

    // Reload all tables to get access to the two tables needed: monitored
    // UTXOs and aocl_to_mutxo.
    storage.reset_schema();
    let mut tables = WalletDbTables::load_schema_in_order(storage).await;

    let monitored_utxos = tables.monitored_utxos;
    let aocl_to_mutxo_v2 = &mut tables.aocl_to_mutxo;

    let stream = monitored_utxos.stream().await;
    pin_mut!(stream); // needed for iteration

    let mut reorganized_duplicates: u64 = 0;
    while let Some((mutxo_index, mutxo)) = stream.next().await {
        let aocl_leaf_index = mutxo
            .get_latest_membership_proof_entry()
            .map(|msmp| msmp.1.aocl_leaf_index);

        if let Some(aocl_leaf_index) = aocl_leaf_index {
            let mut mutxo_indices: Vec<u64> = aocl_to_mutxo_v2
                .get(&aocl_leaf_index)
                .await
                .unwrap_or_default();
            let num_reorgs: u64 = mutxo_indices
                .len()
                .try_into()
                .expect("Can always convert usize to u64");
            reorganized_duplicates += num_reorgs;

            mutxo_indices.push(mutxo_index);
            aocl_to_mutxo_v2
                .insert(aocl_leaf_index, mutxo_indices)
                .await;
        }
    }

    // ensure we have the same number of entries in both tables
    assert_eq!(
        monitored_utxos.len().await,
        aocl_to_mutxo_v2.len().await + reorganized_duplicates
    );

    // set schema version to v2
    tables.schema_version.set(2).await;

    // success!
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use macro_rules_attr::apply;
    use tasm_lib::prelude::Digest;
    use tasm_lib::twenty_first::prelude::MmrMembershipProof;

    use super::*;
    use crate::api::export::NativeCurrencyAmount;
    use crate::api::export::Utxo;
    use crate::application::config::network::Network;
    use crate::application::database::storage::storage_schema::traits::StorageWriter;
    use crate::application::database::storage::storage_schema::DbtSingleton;
    use crate::application::database::storage::storage_schema::DbtVec;
    use crate::application::database::storage::storage_schema::RustyKey;
    use crate::application::database::storage::storage_schema::RustyValue;
    use crate::application::database::NeptuneLevelDb;
    use crate::protocol::consensus::transaction::lock_script::LockScript;
    use crate::state::wallet::migrate_db::worker;
    use crate::state::wallet::monitored_utxo::MonitoredUtxo;
    use crate::state::wallet::rusty_wallet_database::RustyWalletDatabase;
    use crate::tests::shared::files::unit_test_data_directory;
    use crate::tests::shared_tokio_runtime;
    use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
    use crate::util_types::mutator_set::removal_record::chunk_dictionary::ChunkDictionary;

    /// tests migrating a simulated v1 wallet db to v2.
    ///
    /// This test uses mock types from v1 wallet to create a v2
    /// database and then migrates it.
    #[tracing_test::traced_test]
    #[apply(shared_tokio_runtime)]
    async fn migrate() -> anyhow::Result<()> {
        fn fake_mutxo(aocl_leaf_index: u64, num_coins: u32) -> MonitoredUtxo {
            let utxo = Utxo::new_native_currency(
                LockScript::anyone_can_spend().hash(),
                NativeCurrencyAmount::coins(num_coins),
            );
            let mut mutxo = MonitoredUtxo::new(utxo, 2);
            let msmp = MsMembershipProof {
                sender_randomness: Digest::default(),
                receiver_preimage: Digest::default(),
                auth_path_aocl: MmrMembershipProof {
                    authentication_path: vec![],
                },
                aocl_leaf_index,
                target_chunks: ChunkDictionary::default(),
            };
            mutxo.add_membership_proof_for_tip(Digest::default(), msmp);

            mutxo
        }

        // basics
        let network = Network::Main;
        let data_dir = unit_test_data_directory(network)?;

        // create a schema-v1 database and store the monitored UTXOs
        let v1_mutxos = {
            tracing::info!("creating v1 DB");
            let db_v1 = worker::open_db(&data_dir).await?;

            // connect to DB with v1 simulated RustyWalletDatabase
            let mut wallet_db_v1 = test_schema_v1::RustyWalletDatabase::connect(db_v1).await;

            wallet_db_v1.schema_version.set(1).await;

            // sync-label is required, else db is considered "new" on next open.
            wallet_db_v1.sync_label.set(rand::random()).await;

            let mutxos = vec![fake_mutxo(14, 1), fake_mutxo(14, 2), fake_mutxo(22, 1)];
            for mutxo in mutxos.iter() {
                wallet_db_v1.monitored_utxos.push(mutxo.clone()).await;
            }
            assert_eq!(wallet_db_v1.monitored_utxos.len().await, 3);

            wallet_db_v1.storage.persist().await;

            println!("dump of v1 database");
            wallet_db_v1.storage.db().dump_database().await;

            mutxos
        }; // <--- db drops, and closed.

        // open v1 DB file
        tracing::info!("opening existing v1 DB for migration to v2");
        let db_v1 = worker::open_db(&data_dir).await?;

        // connect to v1 Db with v2 RustyWalletDatabase.  This is where the
        // migration occurs.
        let wallet_db_v2 = RustyWalletDatabase::try_connect_and_migrate(db_v1).await?;

        println!("dump of v2 (upgraded) database");
        wallet_db_v2.storage().db().dump_database().await;

        let aocl_to_mutxo = wallet_db_v2.aocl_to_mutxo();
        assert_eq!(aocl_to_mutxo.len().await, 2);
        assert_eq!(wallet_db_v2.monitored_utxos().len().await, 3);

        // verify that AOCL leaf index points to right entries into MUTXO list
        assert_eq!(Some(vec![0, 1]), aocl_to_mutxo.get(&14).await);
        assert!(aocl_to_mutxo.get(&15).await.is_none());
        assert_eq!(Some(vec![2]), aocl_to_mutxo.get(&22).await);
        assert!(aocl_to_mutxo.get(&23).await.is_none());

        assert_eq!(
            v1_mutxos,
            wallet_db_v2.monitored_utxos().get_all().await,
            "Monitored UTXOs must be unchanged by upgrade"
        );

        Ok(())
    }

    // contains schema version 1 types for test(s)
    mod test_schema_v1 {
        use super::*;
        use crate::state::wallet::monitored_utxo::MonitoredUtxo;

        // represents a subset of RustyWalletDatabase as it was in v1
        pub(super) struct RustyWalletDatabase {
            pub storage: SimpleRustyStorage,
            pub monitored_utxos: DbtVec<MonitoredUtxo>,
            pub sync_label: DbtSingleton<Digest>,
            pub schema_version: DbtSingleton<u16>,
        }
        impl RustyWalletDatabase {
            // simulates connecting to DB with v0 schema
            // only impls requirements for SentTransactions
            pub async fn connect(db: NeptuneLevelDb<RustyKey, RustyValue>) -> Self {
                let mut storage = SimpleRustyStorage::new_with_callback(
                    db,
                    "RustyWalletDatabase-Schema",
                    crate::LOG_TOKIO_LOCK_EVENT_CB,
                );
                storage.schema.table_count = WalletDbTables::monitored_utxos_table_count();
                let monitored_utxos = storage
                    .schema
                    .new_vec::<MonitoredUtxo>("monitored_utxos")
                    .await;
                storage.schema.table_count = WalletDbTables::sync_label_table_count();
                let sync_label = storage.schema.new_singleton::<Digest>("sync_label").await;

                storage.schema.table_count = WalletDbTables::schema_version_table_count();
                let schema_version = storage.schema.new_singleton::<u16>("schema_version").await;

                Self {
                    storage,
                    monitored_utxos,
                    sync_label,
                    schema_version,
                }
            }
        }
    }
}
