use std::cmp::Ordering;

use twenty_first::math::tip5::Digest;

use super::expected_utxo::ExpectedUtxo;
use super::migrate_db;
use super::monitored_utxo::MonitoredUtxo;
use super::sent_transaction::SentTransaction;
use super::wallet_db_tables::WalletDbTables;
use super::wallet_db_tables::WALLET_DB_SCHEMA_VERSION;
use crate::database::storage::storage_schema::traits::*;
use crate::database::storage::storage_schema::DbtVec;
use crate::database::storage::storage_schema::RustyKey;
use crate::database::storage::storage_schema::RustyValue;
use crate::database::storage::storage_schema::SimpleRustyStorage;
use crate::database::NeptuneLevelDb;
use crate::prelude::twenty_first;

#[derive(Debug)]
pub struct RustyWalletDatabase {
    storage: SimpleRustyStorage,
    tables: WalletDbTables,
}

impl RustyWalletDatabase {
    pub async fn connect(db: NeptuneLevelDb<RustyKey, RustyValue>) -> Self {
        let mut storage = SimpleRustyStorage::new_with_callback(
            db,
            "RustyWalletDatabase-Schema",
            crate::LOG_TOKIO_LOCK_EVENT_CB,
        );

        let mut tables = WalletDbTables::load_schema_in_order(&mut storage).await;
        let schema_version = &mut tables.schema_version;

        // if the DB is brand-new then we set the schema version.
        // note that schema-version was not present in DB until version 1.

        let is_new_db = schema_version.get() == 0 && tables.sync_label.get() == Digest::default();
        if is_new_db {
            schema_version.set(WALLET_DB_SCHEMA_VERSION).await;
            tracing::info!(
                "set new wallet database to schema version: v{}",
                WALLET_DB_SCHEMA_VERSION
            );
        } else {
            match schema_version.get().cmp(&WALLET_DB_SCHEMA_VERSION) {
                // happy path. db schema version matches code schema version.
                Ordering::Equal => {}

                // database has old schema version and needs to be migrated.
                Ordering::Less => {
                    migrate_db::migrate_range(
                        &mut storage,
                        schema_version.get(),
                        WALLET_DB_SCHEMA_VERSION,
                    )
                    .await
                    .unwrap();
                    schema_version.set(WALLET_DB_SCHEMA_VERSION).await;
                }

                // database is too new, probably from a newer neptune-core binary.
                Ordering::Greater =>
                    panic!("Wallet database schema version is higher than expected.  It appears to come from a newer release of neptune-core.  expected schema version: {}, found: {}", WALLET_DB_SCHEMA_VERSION, schema_version.get())
            }
        }

        RustyWalletDatabase { storage, tables }
    }

    /// get monitored_utxos.
    pub fn monitored_utxos(&self) -> &DbtVec<MonitoredUtxo> {
        &self.tables.monitored_utxos
    }

    /// get mutable monitored_utxos.
    pub fn monitored_utxos_mut(&mut self) -> &mut DbtVec<MonitoredUtxo> {
        &mut self.tables.monitored_utxos
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

    pub fn guesser_preimages(&self) -> &DbtVec<Digest> {
        &self.tables.guesser_preimages
    }

    pub fn guesser_preimages_mut(&mut self) -> &mut DbtVec<Digest> {
        &mut self.tables.guesser_preimages
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
