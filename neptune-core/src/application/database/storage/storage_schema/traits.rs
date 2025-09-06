//! Traits that define the StorageSchema interface
//!
//! It is recommended to wildcard import these with
//! `use crate::application::database::storage::storage_vec::traits::*`

pub use leveldb::database::key::IntoLevelDBKey;

use super::RustyKey;
use super::RustyValue;

/// Defines table interface for types used by [`super::DbtSchema`]
#[async_trait::async_trait]
pub trait DbTable {
    // Retrieve all unwritten operations and empty write-queue
    // async fn pull_queue(&mut self) -> Vec<WriteOperation>;
    /// Restore existing table if present, else create a new one
    async fn restore_or_new(&mut self);
}

/// Defines storage reader interface
#[expect(async_fn_in_trait)]
pub trait StorageReader {
    /// Return multiple values from storage, in the same order as the input keys
    async fn get_many(&self, keys: impl IntoIterator<Item = RustyKey>) -> Vec<Option<RustyValue>>;

    /// Return a single value from storage
    async fn get(&self, key: RustyKey) -> Option<RustyValue>;
}

/// Defines storage writer interface
#[expect(async_fn_in_trait)]
pub trait StorageWriter {
    /// Write data to storage
    async fn persist(&mut self);

    /// Delete all changes that were not persisted.
    async fn drop_unpersisted(&mut self);
}
