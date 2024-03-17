#![warn(missing_docs)]
#![warn(rustdoc::unescaped_backticks)]
#![warn(rustdoc::broken_intra_doc_links)]

//! Thread-safe collection types backed by levelDB.
//!
//! In particular:
//!  - [`OrdinaryVec`](storage_vec::OrdinaryVec) provides a standard (in-memory) Vec
//!    that implements the StorageVec trait.  It is mainly useful for tests and doctests.
//!  - [`SimpleRustyStorage`](storage_schema::SimpleRustyStorage) provides atomic DB writes across
//!    any number of [`DbtVec`](storage_schema::DbtVec) or [`DbtSingleton`](storage_schema::DbtSingleton) "tables".
//!  - [`DB`](level_db::DB) provides a convenient wrapper for the LevelDB API.

// For anyone reading this code and trying to understand the StorageVec trait and the DbSchema
// in particular, especially with regards to locks, mutability, and concurrency, the following
// may help speed understanding.  This explains the "Why" of present design.
//
//  0. DbtSchema::tables holds an Arc::clone() reference to each instance of a `DbTable`
//     implementor such as DbtVec.  This is done so that DbtSchema can iterate over these
//     tables, collect pending Write operations into a database WriteBatch, then send
//     all writes to DB at once, atomically.
//  1. To have a reference in DbtSchema::tables, a `DBTable` implementor such as DbtVec
//     must include Arc, to impl cheap reference clone.
//  2. For mutability of its contents, Arc must include either RwLock or Mutex.
//  3. Without Arc<Mutex<..>> wrapper around DbtVecPrivate, DbtVec cannot modify
//     anything, unless it's methods are &mut self.
//  4. StorageVec methods are presently &self, not &mut self.
//  5. StorageVec methods are &self because that allows eg DbtVec to be shared between
//     threads directly.  Rust does not allow mutable method calls on an item that
//     is shared between threads.
//  6. An alternative could be to make StorageVec methods take &mut self, remove Arc<RwLock<..>>
//     from within DbtVec, and then wrap DbtVec with Arc<Mutex<..>> and clone before returning
//     from `DbtSchema::new_vec()`.  This requires callers to see and deal with locks, rather than
//     keeping them encapsulated inside DbtVec.
//  7. For multi-table read/write atomicity, it is also necessary to have locks over all related
//     `dyn DbTable` items created by `DbtSchema`. Given this, the locks over individual tables,
//     such as DbtVec are redundant, and it would be desirable to eliminate them.  However, then
//     refer back to point 1 above.  If we wish to continue with this DbtSchema model of references,
//     the individual tables must have locks around them, somehow.
//  8. There is also a consideration about iterators for StorageVec implementors.  These iterators
//     could be impl'd to operate atomically or not, over items in the Vec.  In order to operate atomically
//     they must store a lock guard, which must be dropped by the application to prevent deadlock.
//     As of this writing, the iterators do operate atomically.  Deadlock is not considered a problem
//     since the lock is dropped when the iterator is dropped, and if it does occur, it is quite
//     obvious, with just a hang and no CPU usage.  Anyway, if we removed inner locks from DbtVec,
//     these iterators would be forced to use the non-atomic mode.
//  9. So with these points in mind, we have settled on the present design/impl, for now.
// 10. An alternative design might get rid of the DbtSchema::tables entirely and just create a
//     collection/struct of `dyn DbTable` types.  There would be a lock around the collection
//     but no inner lock for each table, and no Arc reference for each.  When it is time to write
//     to database, the collection would be iterated to obtain the Write operations, instead of
//     iterating over DbtSchema::tables.  The primary advantage here is getting rid of the inner
//     locks, which may not be any performance issue anyway, as there is only one lock acquisition
//     per operation.  The disadvantage is that caller must keep track of the created tables
//     and pass them to StorageWriter::persist() as Vec<&type as &dyn DbTable>, which is ugly.

pub mod level_db;
pub mod storage_schema;
pub mod storage_vec;
