use super::super::level_db::DB;
use super::enums::WriteOperation;
use super::{traits::StorageWriter, DbtSchema, SimpleRustyReader};
use crate::sync::LockCallbackFn;
use leveldb::batch::WriteBatch;
use std::sync::Arc;

/// Database schema and tables logic for RustyLevelDB. You probably
/// want to implement your own storage class after this example so
/// that you can hardcode the schema in new(). But it is nevertheless
/// possible to use this struct and add to the schema.
pub struct SimpleRustyStorage {
    /// dynamic DB Schema.  (new tables may be added)
    pub schema: DbtSchema<SimpleRustyReader>,
    db: DB,
}

impl StorageWriter for SimpleRustyStorage {
    #[inline]
    fn persist(&mut self) {
        let write_batch = WriteBatch::new();
        for table in self.schema.tables.lock_guard_mut().iter_mut() {
            let operations = table.pull_queue();
            for op in operations {
                match op {
                    WriteOperation::Write(key, value) => write_batch.put(&key.0, &value.0),
                    WriteOperation::Delete(key) => write_batch.delete(&key.0),
                }
            }
        }

        self.db
            .write(&write_batch, true)
            .expect("Could not persist to database.");
    }

    #[inline]
    fn restore_or_new(&mut self) {
        for table in self.schema.tables.lock_guard_mut().iter_mut() {
            table.restore_or_new();
        }
    }
}

impl SimpleRustyStorage {
    /// Create a new SimpleRustyStorage
    #[inline]
    pub fn new(db: DB) -> Self {
        let schema = DbtSchema::<SimpleRustyReader>::new(
            Arc::new(SimpleRustyReader { db: db.clone() }),
            None,
            None,
        );
        Self { schema, db }
    }

    /// Create a new SimpleRustyStorage and provide a
    /// name and lock acquisition callback for tracing
    pub fn new_with_callback(db: DB, storage_name: &str, lock_callback_fn: LockCallbackFn) -> Self {
        let schema = DbtSchema::<SimpleRustyReader>::new(
            Arc::new(SimpleRustyReader { db: db.clone() }),
            Some(storage_name),
            Some(lock_callback_fn),
        );
        Self { schema, db }
    }
}
