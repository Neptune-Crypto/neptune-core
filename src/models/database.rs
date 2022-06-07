use std::fmt;

use crate::models::blockchain::{BlockHeight, RescuePrimeDigest};
use db_key::Key;
use leveldb::database::Database;

pub struct Databases {
    pub block_height_to_hash: Database<BlockHeight>,
    pub block_hash_to_block: Database<RescuePrimeDigest>,
    pub latest_block: Database<DatabaseUnit>,
}

// We have to implement `Debug` for `Databases` as the `State` struct
// contains a database object, and `State` is used as input argument
// to multiple functions where logging is enabled with the `instrument`
// attributes from the `tracing` crate, and this requires all input
// arguments to the function to implement the `Debug` trait as this
// info is written on all logging events.
impl fmt::Debug for Databases {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("").finish()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DatabaseUnit();
impl Key for DatabaseUnit {
    fn from_u8(_key: &[u8]) -> Self {
        DatabaseUnit()
    }

    fn as_slice<T, F: Fn(&[u8]) -> T>(&self, f: F) -> T {
        f(&[])
    }
}
