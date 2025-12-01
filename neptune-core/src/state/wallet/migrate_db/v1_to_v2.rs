use futures::pin_mut;
use tasm_lib::prelude::Tip5;
use tracing::debug;

use crate::application::database::storage::storage_schema::SimpleRustyStorage;
use crate::application::database::storage::storage_vec::traits::*;
use crate::state::wallet::monitored_utxo::MonitoredUtxo;
use crate::state::wallet::wallet_db_tables::WalletDbTables;

/// migrates wallet db with schema-version v1 to v2
///
/// Changes between v1 and v2:
/// - Add mapping from AOCL leaf index to a list of indices into the monitored
///   UTXOs list.
/// - Add mapping from hash(absolute index set) to index into the list of
///   monitored UTXOs.
/// - Change monitored UTXO field `confirmed_in_block` from Option<T> to T since
///   [`MonitoredUtxo`] always represents a mined UTXO.
/// - Add fields to monitored UTXOs:
///   - aocl_leaf_index: u64 (was always read from MSMP previously)
///   - sender_randomness: Digest (as above)
///   - receiver_preimage: Digest (as above)
///
/// Older databases are migrated simply by iterating over all monitored UTXOs,
/// finding their AOCL leaf index and the two required digests from their
/// respective mutator set membership proofs and then inserting the key-value
/// pairs into the new mappings.
pub(super) async fn migrate(storage: &mut SimpleRustyStorage) -> anyhow::Result<()> {
    // reset the schema, so we start with table_count = 0.
    storage.reset_schema();

    // add a DbtVec<MonitoredUtxoV1> to the schema at the correct position
    // so the correct key-prefix is used
    storage.schema.table_count = WalletDbTables::monitored_utxos_table_count();
    let mutxos_v1 = storage
        .schema
        .new_vec::<migration::schema_v1::MonitoredUtxo>("mutxo_v1")
        .await;

    debug!(
        "Preparing to convert {} monitored UTXOs to v2.",
        mutxos_v1.len().await
    );

    // reset the schema again, to prepare for loading v2 schema.
    storage.reset_schema();

    // load v2 schema tables
    let mut tables = WalletDbTables::load_schema_in_order(storage).await;
    let mutxos_v2 = &mut tables.monitored_utxos;
    let aocl_to_mutxo = &mut tables.aocl_to_mutxo;
    let index_set_to_mutxo = &mut tables.index_set_to_mutxo;

    let stream = mutxos_v1.stream().await;
    pin_mut!(stream); // needed for iteration

    let mut reorganized_duplicates: u64 = 0;
    while let Some((list_index, mutxo_v1)) = stream.next().await {
        let msmp = mutxo_v1
            .blockhash_to_membership_proof
            .iter()
            .next()
            .cloned();
        let Some((_, msmp)) = msmp else {
            // Cannot happen as all monitored UTXOs always had a membership
            // proof.
            panic!(
                "Found monitored UTXO without membership proof. This \
             monitored UTXO might be recovered from your incoming_randomness file."
            );
        };

        let Some(confirmed_in_block) = mutxo_v1.confirmed_in_block else {
            // Cannot happen as the `confirmed_in_block` was always populated.
            panic!(
                "Found monitored UTXO without reference to block in which it was confirmed. \
            This monitored UTXO might be recovered from your \
            incoming_randomness file."
            );
        };

        let aocl_leaf_index = msmp.aocl_leaf_index;
        let utxo = mutxo_v1.utxo;
        let mutxo_v2 = MonitoredUtxo {
            utxo: utxo.clone(),
            aocl_leaf_index,
            sender_randomness: msmp.sender_randomness,
            receiver_preimage: msmp.receiver_preimage,
            blockhash_to_membership_proof: mutxo_v1.blockhash_to_membership_proof,
            number_of_mps_per_utxo: mutxo_v1.number_of_mps_per_utxo,
            spent_in_block: mutxo_v1.spent_in_block,
            confirmed_in_block,
            abandoned_at: mutxo_v1.abandoned_at,
        };

        // Populate lookup table for index set.
        let index_set_digest = Tip5::hash(&mutxo_v2.absolute_indices());
        index_set_to_mutxo
            .insert(index_set_digest, list_index)
            .await;

        // Overwrite the v1 monitored UTXO with a v2.
        debug!("Inserting monitored UTXO number {list_index}");
        mutxos_v2.set(list_index, mutxo_v2.clone()).await;

        let mut mutxo_indices: Vec<u64> = aocl_to_mutxo
            .get(&aocl_leaf_index)
            .await
            .unwrap_or_default();
        let num_reorgs: u64 = mutxo_indices
            .len()
            .try_into()
            .expect("Can always convert usize to u64");
        reorganized_duplicates += (num_reorgs != 0) as u64;

        if num_reorgs != 0 {
            debug!("num_reorgs: {num_reorgs}; aocl_leaf_index: {aocl_leaf_index}");
            let item = Tip5::hash(&utxo);
            debug!("This item: {item:x}");

            for mutxo_index in &mutxo_indices {
                let duplicate_mutxo = mutxos_v2.get(*mutxo_index).await;
                let item_of_duplicate = Tip5::hash(&duplicate_mutxo.utxo);
                debug!("Reorganized duplicate: {item_of_duplicate:x}");
            }
        }

        mutxo_indices.push(list_index);
        aocl_to_mutxo.insert(aocl_leaf_index, mutxo_indices).await;
    }

    // ensure entries in tables are consistent
    let num_mutxos_v2 = mutxos_v2.len().await;
    let num_aocl_entries = aocl_to_mutxo.len().await;
    assert_eq!(
        num_mutxos_v2,
        num_aocl_entries + reorganized_duplicates,
        "Mismatch:\nnum_mutxos_v2: {num_mutxos_v2}\nnum_aocl_entries: {num_aocl_entries}\nreorganized_duplicates: {reorganized_duplicates}"
    );

    let num_index_set_entries = index_set_to_mutxo.len().await;
    assert_eq!(
        num_mutxos_v2, num_index_set_entries,
        "Mismatch:\nnum_mutxos_v2: {num_mutxos_v2}\nnum_index_set_entries: {num_index_set_entries}"
    );

    // set schema version to v2 since migration is complete
    tables.schema_version.set(2).await;

    // success!
    Ok(())
}

mod migration {
    pub(super) mod schema_v1 {
        use std::collections::VecDeque;

        use serde::Deserialize;
        use serde::Serialize;
        use tasm_lib::prelude::Digest;

        use crate::api::export::BlockHeight;
        use crate::protocol::consensus::transaction::utxo::Utxo;
        use crate::state::Timestamp;
        use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;

        // this is a copy of MonitoredUtxo as it was in v1 schema.
        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub(in super::super) struct MonitoredUtxo {
            pub utxo: Utxo,
            pub blockhash_to_membership_proof: VecDeque<(Digest, MsMembershipProof)>,
            pub number_of_mps_per_utxo: usize,
            pub spent_in_block: Option<(Digest, Timestamp, BlockHeight)>,
            pub confirmed_in_block: Option<(Digest, Timestamp, BlockHeight)>,
            pub abandoned_at: Option<(Digest, Timestamp, BlockHeight)>,
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::VecDeque;

    use itertools::Itertools;
    use macro_rules_attr::apply;
    use tasm_lib::prelude::Digest;
    use tasm_lib::twenty_first::prelude::MmrMembershipProof;

    use super::*;
    use crate::api::export::NativeCurrencyAmount;
    use crate::api::export::Timestamp;
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
    use crate::state::wallet::rusty_wallet_database::RustyWalletDatabase;
    use crate::state::BlockHeight;
    use crate::tests::shared::files::unit_test_data_directory;
    use crate::tests::shared_tokio_runtime;
    use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
    use crate::util_types::mutator_set::removal_record::chunk_dictionary::ChunkDictionary;

    impl migration::schema_v1::MonitoredUtxo {
        pub(in super::super) fn new(utxo: Utxo, number_of_mps_per_utxo: usize) -> Self {
            Self {
                utxo,
                blockhash_to_membership_proof: VecDeque::default(),
                number_of_mps_per_utxo,
                spent_in_block: None,
                confirmed_in_block: None,
                abandoned_at: None,
            }
        }
    }

    /// tests migrating a simulated v1 wallet db to v2.
    ///
    /// This test uses mock types from v1 wallet to create a v2
    /// database and then migrates it.
    #[tracing_test::traced_test]
    #[apply(shared_tokio_runtime)]
    async fn migrate() -> anyhow::Result<()> {
        fn fake_v1_mutxo(
            aocl_leaf_index: u64,
            num_coins: u32,
        ) -> migration::schema_v1::MonitoredUtxo {
            let utxo = Utxo::new_native_currency(
                LockScript::anyone_can_spend().hash(),
                NativeCurrencyAmount::coins(num_coins),
            );
            let mut mutxo = migration::schema_v1::MonitoredUtxo::new(utxo, 2);

            let msmp = MsMembershipProof {
                sender_randomness: Digest::default(),
                receiver_preimage: Digest::default(),
                auth_path_aocl: MmrMembershipProof {
                    authentication_path: vec![],
                },
                aocl_leaf_index,
                target_chunks: ChunkDictionary::default(),
            };
            mutxo
                .blockhash_to_membership_proof
                .push_back((Digest::default(), msmp));
            mutxo.confirmed_in_block = Some((
                Digest::default(),
                Timestamp::now(),
                BlockHeight::genesis().next(),
            ));

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

            let mutxos = vec![
                fake_v1_mutxo(14, 1),
                fake_v1_mutxo(14, 2),
                // Four instances of same AOCL leaf index
                fake_v1_mutxo(22, 1),
                fake_v1_mutxo(22, 2),
                fake_v1_mutxo(22, 3),
                fake_v1_mutxo(22, 5),
                fake_v1_mutxo(49, 88),
            ];
            for mutxo in mutxos.iter() {
                wallet_db_v1.monitored_utxos.push(mutxo.clone()).await;
            }
            assert_eq!(wallet_db_v1.monitored_utxos.len().await, 7);

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
        assert_eq!(aocl_to_mutxo.len().await, 3);
        assert_eq!(wallet_db_v2.monitored_utxos().len().await, 7);

        // verify that AOCL leaf index points to right entries into MUTXO list
        assert_eq!(Some(vec![0, 1]), aocl_to_mutxo.get(&14).await);
        assert!(aocl_to_mutxo.get(&15).await.is_none());
        assert_eq!(Some(vec![2, 3, 4, 5]), aocl_to_mutxo.get(&22).await);
        assert!(aocl_to_mutxo.get(&23).await.is_none());
        assert_eq!(Some(vec![6]), aocl_to_mutxo.get(&49).await);

        let utxos_from_v1 = v1_mutxos.into_iter().map(|x| x.utxo).collect_vec();
        let all_v2_mutxos = wallet_db_v2.monitored_utxos().get_all().await;
        let utxos_from_v2 = all_v2_mutxos
            .clone()
            .into_iter()
            .map(|x| x.utxo)
            .collect_vec();
        assert_eq!(
            utxos_from_v1, utxos_from_v2,
            "Monitored UTXOs must be unchanged by upgrade"
        );

        // Verify that lookup data for absolute index sets looks correct
        for v2_mutxo in all_v2_mutxos {
            let index_set = v2_mutxo.absolute_indices();
            let (mutxo, list_index) = wallet_db_v2
                .monitored_utxo_by_index_set(&index_set)
                .await
                .expect("Must have this lookup entry");
            assert_eq!(v2_mutxo, mutxo);
            let by_list_index = wallet_db_v2.monitored_utxos().get(list_index).await;
            assert_eq!(v2_mutxo, by_list_index);
        }

        wallet_db_v2.assert_mutxo_lookup_integrity().await;

        Ok(())
    }

    // contains schema version 1 types for test(s)
    mod test_schema_v1 {
        use super::*;

        // represents a subset of RustyWalletDatabase as it was in v1
        pub(super) struct RustyWalletDatabase {
            pub storage: SimpleRustyStorage,
            pub monitored_utxos: DbtVec<migration::schema_v1::MonitoredUtxo>,
            pub sync_label: DbtSingleton<Digest>,
            pub schema_version: DbtSingleton<u16>,
        }
        impl RustyWalletDatabase {
            // simulates connecting to DB with v1 schema
            // only impls requirements for MonitoredUtxo
            pub async fn connect(db: NeptuneLevelDb<RustyKey, RustyValue>) -> Self {
                let mut storage = SimpleRustyStorage::new_with_callback(
                    db,
                    "RustyWalletDatabase-Schema",
                    crate::LOG_TOKIO_LOCK_EVENT_CB,
                );
                storage.schema.table_count = WalletDbTables::monitored_utxos_table_count();
                let monitored_utxos = storage
                    .schema
                    .new_vec::<migration::schema_v1::MonitoredUtxo>("monitored_utxos")
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
