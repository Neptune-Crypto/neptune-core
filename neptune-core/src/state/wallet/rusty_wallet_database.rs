use std::cmp::Ordering;

use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::tip5::digest::Digest;

use super::expected_utxo::ExpectedUtxo;
use super::migrate_db;
use super::monitored_utxo::MonitoredUtxo;
use super::sent_transaction::SentTransaction;
use super::wallet_db_tables::WalletDbTables;
use super::wallet_db_tables::WALLET_DB_SCHEMA_VERSION;
use crate::api::export::BlockHeight;
use crate::api::export::Timestamp;
use crate::application::database::storage::storage_schema::traits::*;
use crate::application::database::storage::storage_schema::DbtMap;
use crate::application::database::storage::storage_schema::DbtVec;
use crate::application::database::storage::storage_schema::RustyKey;
use crate::application::database::storage::storage_schema::RustyValue;
use crate::application::database::storage::storage_schema::SimpleRustyStorage;
use crate::application::database::storage::storage_vec::traits::StorageVecBase;
use crate::application::database::storage::storage_vec::Index;
use crate::application::database::NeptuneLevelDb;
use crate::protocol::consensus::block::Block;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;

#[derive(Debug)]
pub struct RustyWalletDatabase {
    storage: SimpleRustyStorage,
    tables: WalletDbTables,
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

        // if the DB is brand-new then we set the schema version to the most
        // recent value, since there's nothing to migrate.
        let is_new_db = tables.sync_label.get() == Digest::default();
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
    /// - If index for monitored UTXO is out of range.
    pub(crate) async fn update_mutxo_confirmation_block(
        &mut self,
        mutxo_list_index: Index,
        block: &Block,
    ) {
        let mut existing_mutxo = self.tables.monitored_utxos.get(mutxo_list_index).await;
        existing_mutxo.confirmed_in_block = (
            block.hash(),
            block.kernel.header.timestamp,
            block.kernel.header.height,
        );
        self.tables
            .monitored_utxos
            .set(mutxo_list_index, existing_mutxo)
            .await;
    }

    /// Mark a [`MonitoredUtxo`] as spent in a specified block.
    ///
    /// # Panics
    ///
    /// - If index for monitored UTXO is out of range.
    pub(crate) async fn mark_mutxo_as_spent(&mut self, mutxo_list_index: Index, block: &Block) {
        let mut spent_mutxo = self.tables.monitored_utxos.get(mutxo_list_index).await;
        spent_mutxo.mark_as_spent(block);
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

    /// Insert a new [`MonitoredUtxo`] into the wallet's database and return the
    /// index of the inserted element.
    ///
    /// The list of [`MonitoredUtxo`] is only allowed to grow through this
    /// function, since this function handles the lookup tables that allows for
    /// fast lookup from an AOCL leaf index and from an absolute index set to a
    /// monitored UTXO. If the list of [`MonitoredUtxo`] grows in other ways
    /// than through this function, these tables might get out of sync.
    pub(crate) async fn insert_mutxo(&mut self, monitored_utxo: MonitoredUtxo) -> Index {
        let index_new_mutxo = self.tables.monitored_utxos.len().await;
        let aocl_leaf_index = monitored_utxo.aocl_leaf_index;

        // Populate lookup table for index set.
        let index_set_digest = Tip5::hash(&monitored_utxo.absolute_indices());
        self.tables
            .index_set_to_mutxo
            .insert(index_set_digest, index_new_mutxo)
            .await;

        self.tables.monitored_utxos.push(monitored_utxo).await;

        // Handle AOCL to mutxo lookup
        // In the common case (no reorgs), this is the empty vector, so it will
        // only contain one element after insertion.
        let mut all_mutxo_indices: Vec<u64> = self
            .tables
            .aocl_to_mutxo
            .get(&aocl_leaf_index)
            .await
            .unwrap_or_default();
        all_mutxo_indices.push(index_new_mutxo);

        self.tables
            .aocl_to_mutxo
            .insert(aocl_leaf_index, all_mutxo_indices)
            .await;

        index_new_mutxo
    }

    /// get expected_utxos.
    pub fn expected_utxos(&self) -> &DbtVec<ExpectedUtxo> {
        &self.tables.expected_utxos
    }

    /// get mutable expected_utxos.
    pub fn expected_utxos_mut(&mut self) -> &mut DbtVec<ExpectedUtxo> {
        &mut self.tables.expected_utxos
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

    /// retrieve wallet derivation counter for generation keys
    pub fn get_generation_key_counter(&self) -> u64 {
        self.tables.generation_key_counter.get()
    }

    /// set wallet derivation counter for generation keys
    pub async fn set_generation_key_counter(&mut self, counter: u64) {
        self.tables.generation_key_counter.set(counter).await;
    }

    /// retrieve wallet derivation counter for symmetric keys
    pub fn get_symmetric_key_counter(&self) -> u64 {
        self.tables.symmetric_key_counter.get()
    }

    /// set wallet derivation counter for symmetric keys
    pub async fn set_symmetric_key_counter(&mut self, counter: u64) {
        self.tables.symmetric_key_counter.set(counter).await;
    }

    /// retrieve the database schema version
    pub fn schema_version(&self) -> u16 {
        self.tables.schema_version.get()
    }

    pub fn aocl_to_mutxo(&self) -> &DbtMap<u64, Vec<u64>> {
        &self.tables.aocl_to_mutxo
    }

    #[cfg(test)]
    pub fn storage(&self) -> &SimpleRustyStorage {
        &self.storage
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
    use super::*;

    impl RustyWalletDatabase {
        pub(crate) async fn clear_mutxos(&mut self) {
            self.tables.monitored_utxos.clear().await;
        }

        pub(crate) async fn clear_expected_utxos(&mut self) {
            self.tables.expected_utxos.clear().await;
        }

        pub(crate) async fn assert_mutxo_lookup_integrity(&self) {
            // What has to be true for a well-formed database?
            // Checks that the correct lookup values exist for all monitored
            // UTXOs in the database.
            let num_mutxos = self.tables.monitored_utxos.len().await;
            assert_eq!(num_mutxos, self.tables.index_set_to_mutxo.len().await);

            let all_aocl_keys = self.tables.aocl_to_mutxo.all_keys().await;
            let mut num_aocl_lookup_values = 0;
            for aocl_key in all_aocl_keys {
                let count = self
                    .tables
                    .aocl_to_mutxo
                    .get(&aocl_key)
                    .await
                    .unwrap()
                    .len() as u64;
                num_aocl_lookup_values += count;
            }

            assert_eq!(num_mutxos, num_aocl_lookup_values);

            for i in 0..num_mutxos {
                let mutxo = self.tables.monitored_utxos.get(i).await;
                let index_set = mutxo.absolute_indices();
                let list_index_from_index_set = self
                    .tables
                    .index_set_to_mutxo
                    .get(&Tip5::hash(&index_set))
                    .await
                    .expect("Must have lookup entry");
                assert_eq!(i, list_index_from_index_set);

                let list_indices_from_aocl = self
                    .tables
                    .aocl_to_mutxo
                    .get(&mutxo.aocl_leaf_index)
                    .await
                    .unwrap();
                assert!(
                    list_indices_from_aocl.contains(&i),
                    "One of the AOCL leaf index lookup values must match probed monitored UTXO"
                );
            }
        }
    }
}
