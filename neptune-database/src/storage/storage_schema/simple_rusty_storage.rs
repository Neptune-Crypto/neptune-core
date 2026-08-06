use neptune_locks::tokio::LockCallbackFn;

use super::super::super::neptune_leveldb::NeptuneLevelDb;
use super::traits::StorageWriter;
use super::DbtSchema;
use super::RustyKey;
use super::RustyValue;
use super::SimpleRustyReader;
use super::WriteOperation;
use crate::neptune_leveldb::WriteBatchAsync;

/// Database schema and tables logic for RustyLevelDB.
///
/// You probably want to implement your own storage class after this example so
/// that you can hardcode the schema in new(). But it is nevertheless possible
/// to use this struct and add to the schema.
#[derive(Debug)]
pub struct SimpleRustyStorage {
    /// dynamic DB Schema.  (new tables may be added)
    pub schema: DbtSchema,
    db: NeptuneLevelDb<RustyKey, RustyValue>,
}

impl StorageWriter for SimpleRustyStorage {
    #[inline]
    async fn persist(&mut self) {
        // Hold the lock across the entire operation, so that no interleaved
        // write can land between building the batch and clearing the queue.
        let mut pending_writes = self.schema.pending_writes.lock_guard_mut().await;

        let mut write_ops = WriteBatchAsync::new();
        for op in &pending_writes.write_ops {
            match op.clone() {
                WriteOperation::Write(key, value) => write_ops.op_write(key, value),
                WriteOperation::Delete(key) => write_ops.op_delete(key),
            }
        }

        self.db.batch_write(write_ops).await;

        // Only clear the queue once the batch write has completed. If this
        // future is dropped mid-write, the operations stay queued and the next
        // persist retries them. Redoing an operation is harmless: writes and
        // deletes are both idempotent.
        pending_writes.write_ops.clear();
        pending_writes.persist_count += 1;
    }

    async fn drop_unpersisted(&mut self) {
        self.schema
            .pending_writes
            .lock_guard_mut()
            .await
            .write_ops
            .clear();
    }
}

impl SimpleRustyStorage {
    /// Create a new SimpleRustyStorage
    #[inline]
    pub fn new(db: NeptuneLevelDb<RustyKey, RustyValue>) -> Self {
        let schema = DbtSchema::new(SimpleRustyReader { db: db.clone() }, None, None);
        Self { schema, db }
    }

    /// Create a new SimpleRustyStorage and provide a
    /// name and lock acquisition callback for tracing
    pub fn new_with_callback(
        db: NeptuneLevelDb<RustyKey, RustyValue>,
        storage_name: &str,
        lock_callback_fn: LockCallbackFn,
    ) -> Self {
        let schema = DbtSchema::new(
            SimpleRustyReader { db: db.clone() },
            Some(storage_name),
            Some(lock_callback_fn),
        );
        Self { schema, db }
    }

    /// Reset the schema to a new, empty schema.
    ///
    /// This causes the schema to forget about any logical tables
    /// that were created with `new_vec()` or `new_singleton()` and
    /// resets the table_count to 0.
    ///
    /// This fn should not be used in normal operation, but is
    /// useful for migrating between different schema versions
    /// where the newer version has an altered datatype.
    pub fn reset_schema(&mut self) {
        self.schema = DbtSchema::new(
            SimpleRustyReader {
                db: self.db.clone(),
            },
            None,
            None,
        );
    }

    /// Obtain a reference to the underlying db. For tests only.
    ///
    /// Exposed cross-crate (e.g. neptune-core's migration tests) via the
    /// `test-helpers` feature; not part of the normal public API.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn db(&self) -> &NeptuneLevelDb<RustyKey, RustyValue> {
        &self.db
    }
}
