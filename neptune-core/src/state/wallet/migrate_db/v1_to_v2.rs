use std::collections::HashSet;

use futures::pin_mut;
use tasm_lib::prelude::Tip5;
use tracing::debug;
use tracing::trace;

use crate::application::database::storage::storage_schema::SimpleRustyStorage;
use crate::application::database::storage::storage_vec::traits::*;
use crate::state::wallet::monitored_utxo::MonitoredUtxo;
use crate::state::wallet::wallet_db_tables::StrongUtxoKey;
use crate::state::wallet::wallet_db_tables::WalletDbTables;

/// migrates wallet db with schema-version v1 to v2
///
/// Changes between v1 and v2:
/// - Add mapping from addition record to list index into list of expected
///   UTXOS.
/// - Add mapping from (addition_record, aocl_leaf_index) pair to list index
///   into the list of monitored UTXOs.
/// - Add mapping from hash(absolute index set) to index into the list of
///   monitored UTXOs.
/// - Change monitored UTXO field `confirmed_in_block` from `Option<T>` to `T`
///   since [`MonitoredUtxo`] always represents a mined UTXO.
/// - Add fields to monitored UTXOs:
///   - aocl_leaf_index: u64 (was always read from MSMP previously)
///   - sender_randomness: Digest (as above)
///   - receiver_preimage: Digest (as above)
///
/// Older databases are migrated simply by iterating over all monitored UTXOs,
/// finding their AOCL leaf index and the two required digests from their
/// respective mutator set membership proofs and then inserting the key-value
/// pairs into the new mappings. And by iterating over all expected UTXOs and
/// adding an index value for it, removing duplicates based on addition records.
pub(super) async fn migrate(storage: &mut SimpleRustyStorage) -> anyhow::Result<()> {
    // reset the schema, so we start with table_count = 0.
    storage.reset_schema();

    // add a DbtVec<MonitoredUtxoV1> to the schema at the correct position
    // so the correct key-prefix is used. This allows for the reading of
    // v1-monitored UTXOs.
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
    let strong_key_to_mutxo = &mut tables.strong_key_to_mutxo;
    let index_set_to_mutxo = &mut tables.index_set_to_mutxo;

    /* Migrate monitored UTXOs */
    let mutxo_stream = mutxos_v1.stream().await;
    pin_mut!(mutxo_stream); // needed for iteration

    while let Some((list_index, mutxo_v1)) = mutxo_stream.next().await {
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

        // Populate lookup table for strong key
        let strong_key = StrongUtxoKey::new(mutxo_v2.addition_record(), aocl_leaf_index);
        let existing = strong_key_to_mutxo.insert(strong_key, list_index).await;

        // I don't think there is a way to recover from this problem in this migration logic
        // because it requires deleting entries in the list of monitored UTXOs which means that
        // their indices change. It's probably best to regenerate wallet database from the
        // incoming randomnesss file.
        assert!(existing.is_none(), "Wallet database contains duplicated entries. Try restoring wallet database from incoming_randomness file");
    }

    // ensure entries in tables are consistent
    let num_mutxos_v2 = mutxos_v2.len().await;
    let num_strong_key_entries = strong_key_to_mutxo.len().await;
    assert_eq!(
        num_mutxos_v2, num_strong_key_entries,
        "Mismatch:\nnum_mutxos_v2: {num_mutxos_v2}\nnum_aocl_entries: {num_strong_key_entries}"
    );

    let num_index_set_entries = index_set_to_mutxo.len().await;
    assert_eq!(
        num_mutxos_v2, num_index_set_entries,
        "Mismatch:\nnum_mutxos_v2: {num_mutxos_v2}\nnum_index_set_entries: {num_index_set_entries}"
    );

    /* Create index for expected UTXOs, ensuring no duplicates */

    // I don't have a reasonable expectation that expected UTXOs are *not*
    // duplicated in many real databases out there. So to create the index,
    // we must clear the expected UTXO list and build it again.
    let all_eutxos = tables.expected_utxos.get_all().await;
    debug!("Found {} expected UTXOs for migration", all_eutxos.len());
    tables.expected_utxos.clear().await;
    tables.addition_record_to_expected_utxo.clear().await;

    let mut seen = HashSet::new();
    for eutxo in all_eutxos {
        let addition_record = eutxo.addition_record;
        if !seen.contains(&addition_record) {
            let list_index = tables.expected_utxos.len().await;
            tables
                .addition_record_to_expected_utxo
                .insert(addition_record, list_index)
                .await;

            tables.expected_utxos.push(eutxo).await;

            seen.insert(addition_record);

            trace!("Migrated expected UTXO to index {list_index}",);
        }
    }
    trace!(
        "Length after deduplication (expected_utxos): {}",
        tables.expected_utxos.len().await
    );
    trace!(
        "Length after deduplication (addition_record_to_expected_utxo): {}",
        tables.addition_record_to_expected_utxo.len().await
    );

    let num_eutxos = tables.expected_utxos.len().await;
    let num_eutxo_indices = tables.addition_record_to_expected_utxo.len().await;
    let num_seen: u64 = seen.len().try_into().unwrap();
    assert_eq!(
        num_eutxos, num_eutxo_indices,
        "Mismatch:\nnum_eutxos: {num_eutxos}\nnum_eutxo_indices: {num_eutxo_indices}"
    );
    assert_eq!(
        num_seen, num_eutxo_indices,
        "Mismatch:\nnum_seen: {num_seen}\nnum_eutxo_indices: {num_eutxo_indices}"
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
    use crate::state::wallet::expected_utxo::ExpectedUtxo;
    use crate::state::wallet::expected_utxo::UtxoNotifier;
    use crate::state::wallet::migrate_db::worker;
    use crate::state::wallet::rusty_wallet_database::RustyWalletDatabase;
    use crate::state::BlockHeight;
    use crate::tests::shared::files::unit_test_data_directory;
    use crate::tests::shared_tokio_runtime;
    use crate::util_types::mutator_set::commit;
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
        todo!("Reimplement");
    }

    #[cfg_attr(
        target_os = "windows",
        ignore = "Test disabled on Windows due to LevelDB cross-platform issues"
    )]
    #[tracing_test::traced_test]
    #[apply(shared_tokio_runtime)]
    async fn migrate_real_v1_db() -> anyhow::Result<()> {
        // obtain source db path and target path
        let data_dir = unit_test_data_directory(Network::Testnet(0))?;
        let test_data_wallet_db_dir = worker::crate_root()
            .join("test_data/migrations/wallet_db/v1_to_v2/wallet_db.v1-with-mutxos");
        let wallet_database_path = data_dir.wallet_database_dir_path();

        println!(
            "Reading v1 database from: {}",
            test_data_wallet_db_dir.to_string_lossy()
        );
        println!(
            "Contents of v1 source path: {:?}",
            std::fs::read_dir(&test_data_wallet_db_dir)?.collect::<Vec<_>>()
        );
        println!(
            "Copying v1 database to: {}",
            wallet_database_path.to_string_lossy()
        );

        // copy DB in test_data to wallet_database_path
        crate::copy_dir_recursive(&test_data_wallet_db_dir, &wallet_database_path)?;

        // Sleep to ensure data copying is completed on CI machines.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        println!(
            "Contents of v1 dest path: {:?}",
            std::fs::read_dir(&wallet_database_path)?.collect::<Vec<_>>()
        );

        todo!("Reimplement");

        Ok(())
    }

    // contains schema version 1 types for test(s)
    mod test_schema_v1 {
        use super::*;

        // represents a subset of RustyWalletDatabase as it was in v1
        pub(super) struct RustyWalletDatabase {
            pub storage: SimpleRustyStorage,
            pub monitored_utxos: DbtVec<migration::schema_v1::MonitoredUtxo>,
            pub expected_utxos: DbtVec<ExpectedUtxo>,
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
                storage.schema.table_count = WalletDbTables::expected_utxo_table_count();
                let expected_utxos = storage
                    .schema
                    .new_vec::<ExpectedUtxo>("expected_utxos")
                    .await;

                storage.schema.table_count = WalletDbTables::sync_label_table_count();
                let sync_label = storage.schema.new_singleton::<Digest>("sync_label").await;

                storage.schema.table_count = WalletDbTables::schema_version_table_count();
                let schema_version = storage.schema.new_singleton::<u16>("schema_version").await;

                Self {
                    storage,
                    monitored_utxos,
                    expected_utxos,
                    sync_label,
                    schema_version,
                }
            }
        }
    }
}
