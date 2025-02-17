use super::super::super::neptune_leveldb::NeptuneLevelDb;
use super::traits::StorageWriter;
use super::DbtSchema;
use super::RustyKey;
use super::RustyValue;
use super::SimpleRustyReader;
use super::WriteOperation;
use crate::database::neptune_leveldb::WriteBatchAsync;
use crate::locks::tokio::LockCallbackFn;

/// Database schema and tables logic for RustyLevelDB.
///
/// You probably want to implement your own storage class after this example so
/// that you can hardcode the schema in new(). But it is nevertheless possible
/// to use this struct and add to the schema.
pub struct SimpleRustyStorage {
    /// dynamic DB Schema.  (new tables may be added)
    pub schema: DbtSchema,
    db: NeptuneLevelDb<RustyKey, RustyValue>,
}

impl StorageWriter for SimpleRustyStorage {
    #[inline]
    async fn persist(&mut self) {
        let mut write_ops = WriteBatchAsync::new();

        // note: we read all pending ops and perform mutations
        // in a single atomic operation.
        {
            let mut pending_writes = self.schema.pending_writes.lock_guard_mut().await;
            for op in pending_writes.write_ops.iter() {
                match op.clone() {
                    WriteOperation::Write(key, value) => write_ops.op_write(key, value),
                    WriteOperation::Delete(key) => write_ops.op_delete(key),
                }
            }
            pending_writes.write_ops.clear();
            pending_writes.persist_count += 1;
        }

        self.db.batch_write(write_ops).await
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
}
