use std::cmp::Ordering;

use tasm_lib::twenty_first::tip5::digest::Digest;

use super::expected_utxo::ExpectedUtxo;
use super::migrate_db;
use super::monitored_utxo::MonitoredUtxo;
use super::sent_transaction::SentTransaction;
use super::wallet_db_tables::WalletDbTables;
use super::wallet_db_tables::WALLET_DB_SCHEMA_VERSION;
use crate::application::database::storage::storage_schema::traits::*;
use crate::application::database::storage::storage_schema::DbtVec;
use crate::application::database::storage::storage_schema::RustyKey;
use crate::application::database::storage::storage_schema::RustyValue;
use crate::application::database::storage::storage_schema::SimpleRustyStorage;
use crate::application::database::NeptuneLevelDb;

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

        // if the DB is brand-new then we set the schema version.
        // note that schema-version was not present in DB until version 1.

        let is_new_db = schema_version == 0 && tables.sync_label.get() == Digest::default();
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
