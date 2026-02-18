use std::cmp::Ordering;

use futures::Stream;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::tip5::digest::Digest;

use super::expected_utxo::ExpectedUtxo;
use super::migrate_db;
use super::monitored_utxo::MonitoredUtxo;
use super::sent_transaction::SentTransaction;
use super::wallet_db_tables::WalletDbTables;
use super::wallet_db_tables::WALLET_DB_SCHEMA_VERSION;
use crate::api::export::AdditionRecord;
use crate::api::export::BlockHeight;
use crate::api::export::Timestamp;
use crate::application::database::storage::storage_schema::traits::*;
use crate::application::database::storage::storage_schema::DbtMap;
use crate::application::database::storage::storage_schema::DbtVec;
use crate::application::database::storage::storage_schema::RustyKey;
use crate::application::database::storage::storage_schema::RustyValue;
use crate::application::database::storage::storage_schema::SimpleRustyStorage;
use crate::application::database::storage::storage_vec::traits::StorageVecBase;
use crate::application::database::storage::storage_vec::traits::StorageVecStream;
use crate::application::database::storage::storage_vec::Index;
use crate::application::database::NeptuneLevelDb;
use crate::state::wallet::wallet_db_tables::StrongUtxoKey;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;

#[derive(Debug)]
pub struct RustyWalletDatabase {
    storage: SimpleRustyStorage,
    tables: WalletDbTables,
}

/// Communicates whether the monitored UTXO inserted was already known to the database, or whether
/// it was new.
#[derive(Debug, Clone, Copy)]
pub(crate) enum MonitoredUtxoInsertResult {
    /// Indicates that the inserted monitored UTXO was new; not previously known to the wallet
    /// database. The returned index is the list index at which the monitored UTXO was inserted.
    New(Index),

    /// The monitored UTXO was already tracked by the wallet database. The returned index is the
    /// list index into the list of monitored UTXOs.
    Existing(Index),
}

impl RustyWalletDatabase {
    /// try to connect to db and fail if schema requires migration
    pub async fn try_connect(
        db: NeptuneLevelDb<RustyKey, RustyValue>,
    ) -> Result<Self, WalletDbConnectError> {
        Self::try_connect_internal(db, false).await
    }

    /// try to connect to db and migrate schema if required
    pub async fn try_connect_and_migrate(
        db: NeptuneLevelDb<RustyKey, RustyValue>,
    ) -> Result<Self, WalletDbConnectError> {
        Self::try_connect_internal(db, true).await
    }

    async fn try_connect_internal(
        db: NeptuneLevelDb<RustyKey, RustyValue>,
        migrate: bool,
    ) -> Result<Self, WalletDbConnectError> {
        let mut storage = SimpleRustyStorage::new_with_callback(
            db,
            "RustyWalletDatabase-Schema",
            crate::LOG_TOKIO_LOCK_EVENT_CB,
        );
        let mut tables = WalletDbTables::load_schema_in_order(&mut storage).await;
        let schema_version = tables.schema_version.get();

        let current_sync_label = tables.sync_label.get();
        tracing::trace!("Read wallet database schema version: {schema_version}");
        tracing::trace!("Read sync_label: {current_sync_label:x}");

        // if the DB is brand-new then we set the schema version to the most
        // recent value, since there's nothing to migrate. The wallet database
        // only considered new if schema_version *and* sync_label have default
        // values since some wallet-DBs might have been populated without the
        // sync label being set, because of recovery functions' past behavior.
        let is_new_db = schema_version == 0 && current_sync_label == Digest::default();
        if is_new_db {
            tables.schema_version.set(WALLET_DB_SCHEMA_VERSION).await;
            storage.persist().await;
            tracing::info!(
                "set new wallet database to schema version: v{}",
                WALLET_DB_SCHEMA_VERSION
            );
        } else {
            tracing::debug!("Wallet DB schema version is {}", schema_version);

            match schema_version.cmp(&WALLET_DB_SCHEMA_VERSION) {
                // happy path. db schema version matches code schema version.
                Ordering::Equal => {
                    tracing::info!(
                        "Wallet DB schema version {} is correct.  proceeding",
                        schema_version
                    );
                }

                // database has old schema version and needs to be migrated.
                Ordering::Less => {
                    if migrate {
                        migrate_db::migrate_range(
                            &mut storage,
                            schema_version,
                            WALLET_DB_SCHEMA_VERSION,
                        )
                        .await?;

                        // Reload table data after migration to get rid of
                        // potential ephemeral (non-persisted) data such as
                        // vector length, in case the migration changed any
                        // vector lengths, e.g. due to deduplication.
                        storage.reset_schema();
                        tables = WalletDbTables::load_schema_in_order(&mut storage).await;
                    } else {
                        return Err(WalletDbConnectError::SchemaVersionTooLow {
                            found: schema_version,
                            expected: WALLET_DB_SCHEMA_VERSION,
                        });
                    }
                }

                // database is too new, probably from a newer neptune-core binary.
                Ordering::Greater => {
                    return Err(WalletDbConnectError::SchemaVersionTooHigh {
                        found: schema_version,
                        expected: WALLET_DB_SCHEMA_VERSION,
                    });
                }
            }
        }

        Ok(RustyWalletDatabase { storage, tables })
    }

    /// get monitored_utxos.
    pub fn monitored_utxos(&self) -> &DbtVec<MonitoredUtxo> {
        &self.tables.monitored_utxos
    }

    /// Mapping from index set digest to monitored UTXO list index.
    pub(crate) fn index_set_to_mutxo(&self) -> &DbtMap<Digest, Index> {
        &self.tables.index_set_to_mutxo
    }

    /// Return existing monitored UTXO by list index in the list of all
    /// monitored UTXOs.
    ///
    /// # Panics
    ///
    /// - If index for monitored UTXO is out of range.
    pub(crate) async fn monitored_utxo_by_list_index(&self, index: Index) -> MonitoredUtxo {
        self.tables.monitored_utxos.get(index).await
    }

    /// Return the UTXO of a monitored UTXO and the monitored UTXOs list index
    /// matching the specified absolute index set, if any.
    ///
    /// # Panics
    ///
    /// - If index for monitored UTXO is out of range, which requires the
    ///   database to be malformed, to be missing a monitored UTXO element
    ///   although the lookup table points to it.
    pub(crate) async fn monitored_utxo_by_index_set(
        &self,
        index_set: &AbsoluteIndexSet,
    ) -> Option<(MonitoredUtxo, Index)> {
        let index_set_digest = Tip5::hash(index_set);
        let list_index: Option<Index> = self.tables.index_set_to_mutxo.get(&index_set_digest).await;

        match list_index {
            Some(list_index) => {
                let mutxo = (
                    self.tables.monitored_utxos.get(list_index).await,
                    list_index,
                );
                Some(mutxo)
            }
            None => None,
        }
    }

    /// Mark a monitored UTXO as abandoned
    ///
    /// # Panics
    ///
    /// - If index for monitored UTXO is out of range.
    pub(crate) async fn abandon_monitored_utxo(
        &mut self,
        mutxo_list_index: Index,
        abandoned_at: (Digest, Timestamp, BlockHeight),
    ) {
        let mut existing_mutxo = self.tables.monitored_utxos.get(mutxo_list_index).await;
        existing_mutxo.abandoned_at = Some(abandoned_at);
        self.tables
            .monitored_utxos
            .set(mutxo_list_index, existing_mutxo)
            .await;
    }

    /// Mark existing monitored UTXO as received in a specified block.
    ///
    /// # Panics
    ///
    /// - If the [`StrongUtxoKey`] is not known by the wallet.
    pub(crate) async fn update_mutxo_confirmation_block(
        &mut self,
        strong_utxo_key: &StrongUtxoKey,
        block_info: (Digest, Timestamp, BlockHeight),
    ) {
        let list_index = self
            .tables
            .strong_key_to_mutxo
            .get(strong_utxo_key)
            .await
            .expect("Expected UTXO key must be present in database");
        let mut existing_mutxo = self.tables.monitored_utxos.get(list_index).await;
        existing_mutxo.confirmed_in_block = block_info;
        self.tables
            .monitored_utxos
            .set(list_index, existing_mutxo)
            .await;
    }

    /// Mark a [`MonitoredUtxo`] as spent in a specified block.
    ///
    /// # Panics
    ///
    /// - If index for monitored UTXO is out of range.
    pub(crate) async fn mark_mutxo_as_spent(
        &mut self,
        mutxo_list_index: Index,
        block_hash: Digest,
        block_timestamp: Timestamp,
        block_height: BlockHeight,
    ) {
        let mut spent_mutxo = self.tables.monitored_utxos.get(mutxo_list_index).await;
        spent_mutxo.mark_as_spent(block_hash, block_timestamp, block_height);
        self.tables
            .monitored_utxos
            .set(mutxo_list_index, spent_mutxo)
            .await;
    }

    /// Add a new [`MsMembershipProof`] to a [`MonitoredUtxo`].
    ///
    /// # Panics
    ///
    /// - If index for monitored UTXO is out of range.
    pub(crate) async fn add_msmp_to_monitored_utxo(
        &mut self,
        mutxo_list_index: Index,
        block_hash: Digest,
        msmp: MsMembershipProof,
    ) {
        let mut mutxo = self.tables.monitored_utxos.get(mutxo_list_index).await;
        mutxo.add_membership_proof_for_tip(block_hash, msmp);
        self.tables
            .monitored_utxos
            .set(mutxo_list_index, mutxo)
            .await;
    }

    /// Check if the wallet database contains a [`MonitoredUtxo`] with the
    /// specified [`StrongUtxoKey`].
    pub(crate) async fn has_mutxo(&self, strong_utxo_key: &StrongUtxoKey) -> bool {
        self.tables
            .strong_key_to_mutxo
            .contains_key(strong_utxo_key)
            .await
    }

    /// Insert a new [`MonitoredUtxo`] into the wallet's database and return the
    /// index of the inserted element, if this monitored UTXO is new. If the
    /// monitored UTXO is already known to the wallet database, the index of the
    /// duplicate (already existing entry) is returned. If the entry already
    /// existed in the database, this call does not write to the database.
    ///
    /// The list of [`MonitoredUtxo`] is only allowed to grow through this
    /// function, since this function handles the lookup tables and the
    /// duplication checks. If the list of [`MonitoredUtxo`] grows in other ways
    /// than through this function, these tables might get out of sync.
    pub(crate) async fn insert_mutxo(
        &mut self,
        monitored_utxo: MonitoredUtxo,
    ) -> MonitoredUtxoInsertResult {
        // Check for duplicated entries
        let strong_key = monitored_utxo.strong_utxo_key();
        if let Some(existing_list_index) = self.tables.strong_key_to_mutxo.get(&strong_key).await {
            return MonitoredUtxoInsertResult::Existing(existing_list_index);
        }

        let list_index = self.tables.monitored_utxos.len().await;

        // populate lookup table for addition record/AOCL leaf index pair
        self.tables
            .strong_key_to_mutxo
            .insert(strong_key, list_index)
            .await;

        // Populate lookup table for index set.
        let index_set_digest = Tip5::hash(&monitored_utxo.absolute_indices());
        self.tables
            .index_set_to_mutxo
            .insert(index_set_digest, list_index)
            .await;

        // Add monitored UTXO to list
        self.tables.monitored_utxos.push(monitored_utxo).await;

        MonitoredUtxoInsertResult::New(list_index)
    }

    /// Return an [`ExpectedUtxo`] if any with a matching addition record exists.
    pub(crate) async fn expected_utxo_by_addition_record(
        &self,
        addition_record: &AdditionRecord,
    ) -> Option<ExpectedUtxo> {
        debug_assert_eq!(
            self.tables.addition_record_to_expected_utxo.len().await,
            self.tables.expected_utxos.len().await,
            "Index for expected UTXOs must match list of expected UTXOs"
        );

        let list_index = self
            .tables
            .addition_record_to_expected_utxo
            .get(addition_record)
            .await;

        match list_index {
            Some(i) => Some(self.tables.expected_utxos.get(i).await),
            None => None,
        }
    }

    /// Return all expected UTXOs
    pub(crate) async fn stream_expected_utxos(
        &self,
    ) -> impl Stream<Item = (Index, ExpectedUtxo)> + '_ {
        self.tables.expected_utxos.stream().await
    }

    /// Mark the expected UTXO matching the addition record as received. Does
    /// nothing if an expected UTXO with this addition record does not exist
    /// in the database.
    pub(crate) async fn mark_expected_utxo_as_received(
        &mut self,
        addition_record: &AdditionRecord,
        block_hash: Digest,
        block_timestamp: Timestamp,
    ) {
        debug_assert_eq!(
            self.tables.addition_record_to_expected_utxo.len().await,
            self.tables.expected_utxos.len().await,
            "Index for expected UTXOs must match list of expected UTXOs"
        );

        let list_index = self
            .tables
            .addition_record_to_expected_utxo
            .get(addition_record)
            .await;

        let Some(list_index) = list_index else {
            return;
        };

        let mut entry = self.tables.expected_utxos.get(list_index).await;

        entry.mined_in_block = Some((block_hash, block_timestamp));

        self.tables.expected_utxos.set(list_index, entry).await;
    }

    /// Insert an expected UTXO into the wallet database. The insertion of a
    /// duplicate is guaranteed to not modify the database. Duplicates are
    /// identified by their addition records. So two expected UTXOs with the
    /// same addition record cannot be added to the wallet database.
    ///
    /// All insertions of [`ExpectedUtxo`]s into the database must go through
    /// this method to ensure indexing consistency.
    pub(crate) async fn insert_expected_utxo(&mut self, expected_utxo: ExpectedUtxo) {
        // Check for duplicated entries
        if self
            .tables
            .addition_record_to_expected_utxo
            .contains_key(&expected_utxo.addition_record)
            .await
        {
            return;
        }

        let list_index = self.tables.expected_utxos.len().await;
        self.tables
            .addition_record_to_expected_utxo
            .insert(expected_utxo.addition_record, list_index)
            .await;

        self.tables.expected_utxos.push(expected_utxo).await;

        debug_assert_eq!(
            self.tables.addition_record_to_expected_utxo.len().await,
            self.tables.expected_utxos.len().await,
            "Index for expected UTXOs must match list of expected UTXOs"
        );
    }

    /// Convenience method for loading all expected UTXOs into memory.
    pub(crate) async fn all_expected_utxos(&self) -> Vec<ExpectedUtxo> {
        self.tables.expected_utxos.get_all().await
    }

    /// Return the number of expected UTXOs in the database.
    pub(crate) async fn num_expected_utxos(&self) -> u64 {
        self.tables.expected_utxos.len().await
    }

    /// Delete all expected UTXOs and associated indexing data from the
    /// database.
    pub(crate) async fn clear_expected_utxos(&mut self) {
        self.tables.expected_utxos.clear().await;
        self.tables.addition_record_to_expected_utxo.clear().await;
    }

    /// get sent transactions
    pub fn sent_transactions(&self) -> &DbtVec<SentTransaction> {
        &self.tables.sent_transactions
    }

    /// get mutable sent transactions
    pub fn sent_transactions_mut(&mut self) -> &mut DbtVec<SentTransaction> {
        &mut self.tables.sent_transactions
    }

    /// Get the hash of the block to which this database is synced.
    pub fn get_sync_label(&self) -> Digest {
        self.tables.sync_label.get()
    }

    pub async fn set_sync_label(&mut self, sync_label: Digest) {
        self.tables.sync_label.set(sync_label).await;
    }

    pub fn get_counter(&self) -> u64 {
        self.tables.counter.get()
    }

    pub async fn set_counter(&mut self, counter: u64) {
        self.tables.counter.set(counter).await;
    }

    pub fn get_generation_key_counter(&self) -> u64 {
        self.tables.generation_key_counter.get()
    }

    pub async fn set_generation_key_counter(&mut self, counter: u64) {
        self.tables.generation_key_counter.set(counter).await;
    }

    pub fn get_symmetric_key_counter(&self) -> u64 {
        self.tables.symmetric_key_counter.get()
    }

    pub async fn set_symmetric_key_counter(&mut self, counter: u64) {
        self.tables.symmetric_key_counter.set(counter).await;
    }

    /// retrieve the database schema version
    pub fn schema_version(&self) -> u16 {
        self.tables.schema_version.get()
    }

    #[doc(hidden)]
    /// Delete all monitored UTXOs and associated lookup tables.
    /// This function is required for benchmarks, but is not part of the public
    /// API.
    pub async fn clear_mutxos(&mut self) {
        self.tables.monitored_utxos.clear().await;
        self.tables.strong_key_to_mutxo.clear().await;
        self.tables.index_set_to_mutxo.clear().await;
    }
}

impl StorageWriter for RustyWalletDatabase {
    async fn persist(&mut self) {
        self.storage.persist().await
    }

    async fn drop_unpersisted(&mut self) {
        unimplemented!("wallet does not need it")
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum WalletDbConnectError {
    #[error("Wallet database schema version is lower than expected.  expected schema version: {}, found: {}", expected, found)]
    SchemaVersionTooLow { found: u16, expected: u16 },
    #[error("Wallet database schema version is higher than expected.  It appears to come from a newer release of neptune-core.  expected schema version: {}, found: {}", expected, found)]
    SchemaVersionTooHigh { found: u16, expected: u16 },
    #[error("wallet db connect failed: {0}")]
    Failed(String),
}

// convert anyhow::Error to WalletDbConnectError::Failed.
// note that anyhow Error is not serializable.
impl From<anyhow::Error> for WalletDbConnectError {
    fn from(e: anyhow::Error) -> Self {
        Self::Failed(e.to_string())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashSet;

    use num_traits::Zero;

    use super::*;
    use crate::application::database::storage::storage_schema::DbtMap;

    impl RustyWalletDatabase {
        pub fn storage(&self) -> &SimpleRustyStorage {
            &self.storage
        }

        pub(crate) fn expected_utxos(&self) -> &DbtVec<ExpectedUtxo> {
            &self.tables.expected_utxos
        }

        pub(crate) fn strong_keys(&self) -> &DbtMap<StrongUtxoKey, u64> {
            &self.tables.strong_key_to_mutxo
        }

        pub(crate) async fn assert_expected_utxo_integrity(&self) {
            let num_eutxos = self.tables.expected_utxos.len().await;
            assert_eq!(
                num_eutxos,
                self.tables.addition_record_to_expected_utxo.len().await
            );

            for i in 0..num_eutxos {
                let elem = self.tables.expected_utxos.get(i).await;
                assert_eq!(
                    i,
                    self.tables
                        .addition_record_to_expected_utxo
                        .get(&elem.addition_record)
                        .await
                        .unwrap()
                );
            }
        }

        pub(crate) async fn assert_mutxo_lookup_integrity(&self) {
            // What has to be true for a well-formed database?
            // Checks that the correct lookup values exist for all monitored
            // UTXOs in the database.
            let num_mutxos = self.tables.monitored_utxos.len().await;
            assert_eq!(num_mutxos, self.tables.index_set_to_mutxo.len().await);

            let all_strong_keys = self.tables.strong_key_to_mutxo.all_keys().await;
            let num_strong_keys = all_strong_keys.len();
            let unique_strong_keys: HashSet<_> = all_strong_keys.into_iter().collect();
            assert_eq!(
                num_strong_keys,
                unique_strong_keys.len(),
                "All strong keys must be unique"
            );

            let mut reported_list_indices = HashSet::new();
            for strong_key in &unique_strong_keys {
                let list_index = self
                    .tables
                    .strong_key_to_mutxo
                    .get(strong_key)
                    .await
                    .expect("Must have reported strong key");
                reported_list_indices.insert(list_index);
            }

            assert!(
                reported_list_indices
                    .iter()
                    .copied()
                    .min()
                    .unwrap_or_default()
                    .is_zero(),
                "Min value of list indices must be zero, or list must be empty"
            );
            assert_eq!(
                num_mutxos,
                reported_list_indices
                    .iter()
                    .copied()
                    .max()
                    .map(|x| x + 1)
                    .unwrap_or_default(),
                "Max value of list indices must be len - 1, or list must be empty"
            );

            for i in 0..num_mutxos {
                let mutxo = self.tables.monitored_utxos.get(i).await;
                let index_set = mutxo.absolute_indices();
                let list_index_from_index_set = self
                    .tables
                    .index_set_to_mutxo
                    .get(&Tip5::hash(&index_set))
                    .await
                    .expect("Must have lookup entry for index set");
                assert_eq!(i, list_index_from_index_set);

                let list_index_from_strong_key = self
                    .tables
                    .strong_key_to_mutxo
                    .get(&mutxo.strong_utxo_key())
                    .await
                    .unwrap();
                assert_eq!(
                    list_index_from_strong_key, i,
                    "Strong key lookup must match probed monitored UTXO"
                );
            }
        }
    }
}
