#![warn(missing_docs)]
#![warn(rustdoc::unescaped_backticks)]
#![warn(rustdoc::broken_intra_doc_links)]

//! Collection types backed by LevelDB.
//!
//! In particular:
//!  - [`OrdinaryVec`](storage_vec::OrdinaryVec) provides a standard (in-memory)
//!    Vec that implements the StorageVec trait.  It is mainly useful for tests
//!    and doctests.
//!  - [`SimpleRustyStorage`](storage_schema::SimpleRustyStorage) provides
//!    atomic NeptuneLevelDb writes across any number of
//!    [`DbtVec`](storage_schema::DbtVec) or
//!    [`DbtSingleton`](storage_schema::DbtSingleton) "tables".
//!  - [`NeptuneLevelDb`](crate::application::database::NeptuneLevelDb) provides
//!    a convenient wrapper for the LevelDB API.

// For anyone reading this code and trying to understand the StorageVec trait and the DbSchema
// in particular may help speed understanding.
//
//  0. DbSchema::pending_writes holds an AtomicRw<PendingWrites> (Arc<RwLock<..>).
//     PendingWrites is a list of pending DB operations that are waiting to
//     persisted to the database.
//  1. Each logical table (DbtVec or DbtSingleton) created by a given DbSchema holds
//     an Arc clone of the PendingWrites.  Thus the list is shared between tables
//     and DbSchema has a view of all pending writes, across all tables.
//  2. SimpleStorageReader provides DB access for the tables to read data as needed.
//     It does not provide any API for them to write, so they can only write by adding
//     an operation to PendingWrites.
//  3. SimpleStorageWriter::persist() reads all the PendingWrites in DbSchema and
//     writes them to the DB, and then clears the list.
//  4. Table types such as DbtVec keep an internal cache of pending written data that
//     must at all times match the logical state of the DB, as if it had already been
//     written to.  This cache is cleared when data is actually persisted.

pub mod storage_schema;
pub mod storage_vec;
