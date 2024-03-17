//! Traits that define the StorageSchema interface
//!
//! It is recommended to wildcard import these with
//! `use twenty_first::storage::storage_vec::traits::*`

use super::{RustyKey, RustyValue, WriteOperation};
pub use crate::leveldb::database::key::IntoLevelDBKey;

/// Defines table interface for types used by [`super::DbtSchema`]
pub trait DbTable {
    /// Retrieve all unwritten operations and empty write-queue
    fn pull_queue(&mut self) -> Vec<WriteOperation>;
    /// Restore existing table if present, else create a new one
    fn restore_or_new(&mut self);
}

/// Defines storage singleton for types created by [`super::DbtSchema`]
pub trait StorageSingleton<T>
where
    T: Clone,
{
    /// Retrieve value
    fn get(&self) -> T;

    /// Set value
    fn set(&mut self, t: T);
}

/// Defines storage reader interface
pub trait StorageReader {
    /// Return multiple values from storage, in the same order as the input keys
    fn get_many(&self, keys: &[RustyKey]) -> Vec<Option<RustyValue>>;

    /// Return a single value from storage
    fn get(&self, key: RustyKey) -> Option<RustyValue>;
}

/// Defines storage writer interface
pub trait StorageWriter {
    /// Write data to storage
    fn persist(&mut self);
    /// restore, or new
    fn restore_or_new(&mut self);
}
