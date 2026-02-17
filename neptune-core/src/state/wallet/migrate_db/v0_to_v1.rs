use futures::pin_mut;
use itertools::Itertools;

use crate::application::database::storage::storage_schema::SimpleRustyStorage;
use crate::application::database::storage::storage_vec::traits::*;
use crate::state::wallet::sent_transaction::SentTransaction;
use crate::state::wallet::transaction_output::TxOutput;
use crate::state::wallet::transaction_output::TxOutputList;
use crate::state::wallet::wallet_db_tables::WalletDbTables;

// migrates wallet db with schema-version v0 to v1.
//
// The only thing that changed in v1 is that `TxOuput` added boolean field
// 'is_change'.
//
// We migrate older databases using the heuristic that any owned TxOutput
// represents a change output.  This is not necessarily true, but should be true
// most of the time.
//
// This fn implements the SQL equivalent of:
//  ALTER TABLE sent_transactions ADD COLUMN is_change BOOLEAN DEFAULT owned;
pub(super) async fn migrate(storage: &mut SimpleRustyStorage) -> anyhow::Result<()> {
    // first, it's important to understant that keys in the DB are prefixed with
    // a key-prefix which is an integer that increases (in
    // storage.schema.table_count) with each call to new_vec() or
    // new_singleton().

    // reset the schema, so we start with table_count = 0.
    storage.reset_schema();

    // add a DbtVec<SentTransactionV0> to the schema at the correct position
    // so the correct key-prefix is used
    storage.schema.table_count = WalletDbTables::sent_transactions_table_count();
    let sent_transactions_v0 = storage
        .schema
        .new_vec::<migration::schema_v0::SentTransaction>("st")
        .await;

    // reset the schema again, to prepare for loading v1 schema.
    storage.reset_schema();

    // load v1 schema tables and reference sent_transactions.
    let mut tables = WalletDbTables::load_schema_in_order(storage).await;
    let sent_transactions_v1 = &mut tables.sent_transactions;

    // ensure we see same # of sent transactions for both schemas.
    assert_eq!(
        sent_transactions_v1.len().await,
        sent_transactions_v0.len().await
    );

    // obtain stream (iterator) of all v0 sent-transactions
    let stream = sent_transactions_v0.stream().await;
    pin_mut!(stream); // needed for iteration

    // iterate all v0 sent-tx and migrate each to v1.
    // tx_v0.into() migrates, and the set() updates the DB record.
    while let Some((index, tx_v0)) = stream.next().await {
        sent_transactions_v1.set(index, tx_v0.into()).await;
    }

    // set schema version to v1
    tables.schema_version.set(1).await;

    // success!
    Ok(())
}

mod migration {
    use super::*;

    pub mod schema_v0 {
        use serde::Deserialize;
        use serde::Serialize;
        use tasm_lib::prelude::Digest;

        use crate::protocol::consensus::transaction::utxo::Utxo;
        use crate::state::wallet::sent_transaction::AoclLeafIndex;
        use crate::state::wallet::utxo_notification::UtxoNotificationMethod;
        use crate::state::NativeCurrencyAmount;
        use crate::state::Timestamp;

        // this is a copy of TxOutput as it was in v0 schema.
        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct TxOutput {
            pub utxo: Utxo,
            pub sender_randomness: Digest,
            pub receiver_digest: Digest,
            pub(crate) notification_method: UtxoNotificationMethod,
            pub owned: bool,
        }

        // this is a copy of SentTransaction as it was in v0 schema.
        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct SentTransaction {
            pub tx_inputs: Vec<(AoclLeafIndex, Utxo)>,
            pub tx_outputs: Vec<TxOutput>,
            pub fee: NativeCurrencyAmount,
            pub timestamp: Timestamp,
            pub tip_when_sent: Digest,
        }
    }

    // for migrating v0 to v1.
    // in particular, the is_change field is new, and defaults to owned.
    impl From<schema_v0::TxOutput> for TxOutput {
        fn from(v0: schema_v0::TxOutput) -> Self {
            Self::new(
                v0.utxo,
                v0.sender_randomness,
                v0.receiver_digest,
                v0.notification_method,
                v0.owned,
                v0.owned, // is_change.  default to owned (v0)
            )
        }
    }

    // for migrating v0 to v1.
    // in particular, the tx_outputs field.
    impl From<schema_v0::SentTransaction> for SentTransaction {
        fn from(v0: schema_v0::SentTransaction) -> Self {
            let tx_outputs: TxOutputList = v0
                .tx_outputs
                .into_iter()
                .map(TxOutput::from)
                .collect_vec()
                .into();
            Self {
                tx_inputs: v0.tx_inputs,
                tx_outputs,
                fee: v0.fee,
                timestamp: v0.timestamp,
                tip_when_sent: v0.tip_when_sent,
            }
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use macro_rules_attr::apply;
    use num_traits::Zero;
    use tasm_lib::prelude::Digest;

    use super::*;
    use crate::api::export::NativeCurrencyAmount;
    use crate::application::config::network::Network;
    use crate::application::database::storage::storage_schema::traits::StorageWriter;
    use crate::application::database::storage::storage_schema::DbtSingleton;
    use crate::application::database::storage::storage_schema::DbtVec;
    use crate::application::database::storage::storage_schema::RustyKey;
    use crate::application::database::storage::storage_schema::RustyValue;
    use crate::application::database::NeptuneLevelDb;
    use crate::state::wallet::migrate_db::worker;
    use crate::state::wallet::rusty_wallet_database::RustyWalletDatabase;
    use crate::state::wallet::utxo_notification::UtxoNotificationMethod;
    use crate::state::Timestamp;
    use crate::tests::shared::files::unit_test_data_directory;
    use crate::tests::shared_tokio_runtime;

    /// tests migrating a simulated v0 wallet db to v1.
    ///
    /// This test uses mock types from v0 wallet to create a v0
    /// database and then migrates it.
    #[tracing_test::traced_test]
    #[apply(shared_tokio_runtime)]
    async fn migrate() -> anyhow::Result<()> {
        todo!("Reimplement");

        // success!
        Ok(())
    }

    /// tests migrating a "real" v0 wallet db to current version.
    ///
    /// This test uses a copy of a small v0 testnet database that is stored
    /// inside the test_data directory.
    ///
    /// The DB was created by running v0.2.2 of neptune-core in testnet mode and
    /// sending a transaction to a peer.  Thus the DB contains a single
    /// SentTransaction.
    ///
    /// Windows:
    ///
    /// When the test is run on windows an error occurs opening the DB due to
    /// path issues.  Presumably because the DB was created on Linux.  For
    /// now, the simplest path is just to ignore (but still compile) the test
    /// on windows.
    #[cfg_attr(
        target_os = "windows",
        ignore = "Test disabled on Windows due to LevelDB cross-platform issues"
    )]
    #[tracing_test::traced_test]
    #[apply(shared_tokio_runtime)]
    async fn migrate_real_v0_db() -> anyhow::Result<()> {
        todo!("Reimplement");
    }

    // contains schema version 0 types for test(s)
    mod test_schema_v0 {
        use super::*;

        // represents a subset of RustyWalletDatabase as it was in v0
        pub(super) struct RustyWalletDatabase {
            pub storage: SimpleRustyStorage,
            pub sent_transactions: DbtVec<migration::schema_v0::SentTransaction>, // table 2
            pub sync_label: DbtSingleton<Digest>,                                 // table 3
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
                storage.schema.table_count = WalletDbTables::sent_transactions_table_count();
                let sent_transactions = storage
                    .schema
                    .new_vec::<migration::schema_v0::SentTransaction>("sent_transactions")
                    .await;
                let sync_label = storage.schema.new_singleton::<Digest>("sync_label").await;

                Self {
                    storage,
                    sent_transactions,
                    sync_label,
                }
            }
        }
    }
}
