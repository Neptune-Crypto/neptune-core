//! [`DB`] wraps [`Database`] and provides
//! functionality for reading the database on-disk path
//! as well as destroying the on-disk database manually
//! or automatically upon drop.
//!
//! auto-destroy-on-drop is needed for unit tests that use the DB.

use std::path::Path;
use std::sync::Arc;

use leveldb::batch::Batch;
use leveldb::batch::WriteBatch;
use leveldb::compaction::Compaction;
use leveldb::database::comparator::Comparator;
use leveldb::database::Database;
use leveldb::error::Error as DbError;
use leveldb::iterator::Iterable;
use leveldb::iterator::Iterator;
use leveldb::iterator::KeyIterator;
use leveldb::iterator::ValueIterator;
use leveldb::key::IntoLevelDBKey;
use leveldb::options::Options;
use leveldb::options::ReadOptions;
use leveldb::options::WriteOptions;
use leveldb::snapshots::Snapshot;
use leveldb::snapshots::Snapshots;
use rand::distr::Alphanumeric;
use rand::distr::SampleString;

/// `DbIntMut` provides thread-safe access to LevelDB API with `&self` setters
///
/// Interior mutability is available without rust locks because the underlying
/// C++ levelDB API is internally thread-safe.
///
/// If `&self` setters are not needed, prefer [`DB`] instead.
//
//  This also provides an abstraction layer which enables
//  us to provide an API that is somewhat backwards compatible
//  with rusty-leveldb.  For example, our get() and put()
//  do not require ReadOptions and WriteOptions param.
//
//  Do not add any public (mutable) fields to this struct.
#[derive(Debug, Clone)]
pub struct DbIntMut {
    // note: these must be private and unchanged after creation.

    // This Option is needed for the Drop impl.  See comments there.
    // All other methods can call unwrap() because constructors always
    // set Some(..)
    db: Option<Arc<Database>>, // Send + Sync.  Arc is so we can derive Clone.
    path: std::path::PathBuf,
    destroy_db_on_drop: bool,
    read_options: ReadOptions,
    write_options: WriteOptions,
}

impl DbIntMut {
    /// Open a new database
    ///
    /// If the database is missing, the behaviour depends on `options.create_if_missing`.
    /// The database will be created using the settings given in `options`.
    #[inline]
    pub fn open(name: &Path, options: &Options) -> Result<Self, DbError> {
        let db = Database::open(name, options)?;
        Ok(Self {
            db: Some(Arc::new(db)),
            path: name.into(),
            destroy_db_on_drop: false,
            read_options: ReadOptions::new(),
            write_options: WriteOptions::new(),
        })
    }

    /// Open a new database
    ///
    /// If the database is missing, the behaviour depends on `options.create_if_missing`.
    /// The database will be created using the settings given in `options`.
    #[inline]
    pub fn open_with_options(
        name: &Path,
        options: &Options,
        read_options: ReadOptions,
        write_options: WriteOptions,
    ) -> Result<Self, DbError> {
        let db = Database::open(name, options)?;
        Ok(Self {
            db: Some(Arc::new(db)),
            path: name.into(),
            destroy_db_on_drop: false,
            read_options,
            write_options,
        })
    }

    /// Open a new database with a custom comparator
    ///
    /// If the database is missing, the behaviour depends on `options.create_if_missing`.
    /// The database will be created using the settings given in `options`.
    ///
    /// The comparator must implement a total ordering over the keyspace.
    ///
    /// For keys that implement Ord, consider the `OrdComparator`.
    #[inline]
    pub fn open_with_comparator<C: Comparator>(
        name: &Path,
        options: &Options,
        comparator: C,
    ) -> Result<Self, DbError> {
        let db = Database::open_with_comparator(name, options, comparator)?;
        Ok(Self {
            db: Some(Arc::new(db)),
            path: name.into(),
            destroy_db_on_drop: false,
            read_options: ReadOptions::new(),
            write_options: WriteOptions::new(),
        })
    }

    /// Creates and opens a test database
    ///
    /// The database will be created in the system
    /// temp directory with prefix "test-db-" followed
    /// by a random string.
    ///
    /// if destroy_db_on_drop is true, the database on-disk
    /// files will be wiped when the DB struct is dropped.
    pub fn open_new_test_database(
        destroy_db_on_drop: bool,
        options: Option<Options>,
        read_options: Option<ReadOptions>,
        write_options: Option<WriteOptions>,
    ) -> Result<Self, DbError> {
        let path = std::env::temp_dir().join(format!(
            "test-db-{}",
            Alphanumeric.sample_string(&mut rand::rng(), 10)
        ));
        Self::open_test_database(
            &path,
            destroy_db_on_drop,
            options,
            read_options,
            write_options,
        )
    }

    /// Opens an existing (test?) database, with auto-destroy option.
    ///
    /// if destroy_db_on_drop is true, the database on-disk
    /// files will be wiped when the DB struct is dropped.
    /// This is usually useful only for unit-test purposes.
    pub fn open_test_database(
        path: &std::path::Path,
        destroy_db_on_drop: bool,
        options: Option<Options>,
        read_options: Option<ReadOptions>,
        write_options: Option<WriteOptions>,
    ) -> Result<Self, DbError> {
        let mut opt = options.unwrap_or_else(Options::new);
        let read_opt = read_options.unwrap_or_else(ReadOptions::new);
        let write_opt = write_options.unwrap_or_else(WriteOptions::new);

        opt.create_if_missing = true;
        opt.error_if_exists = false;

        let mut db = Self::open_with_options(path, &opt, read_opt, write_opt)?;
        db.destroy_db_on_drop = destroy_db_on_drop;
        Ok(db)
    }

    /// Set a key/val in the database
    #[inline]
    pub fn put(&self, key: &dyn IntoLevelDBKey, value: &[u8]) -> Result<(), DbError> {
        self.db
            .as_ref()
            .unwrap()
            .put(&self.write_options, key, value)
    }

    /// Set a key/val in the database, with key as bytes.
    #[inline]
    pub fn put_u8(&self, key: &[u8], value: &[u8]) -> Result<(), DbError> {
        self.db
            .as_ref()
            .unwrap()
            .put_u8(&self.write_options, key, value)
    }

    /// Get a value matching key from the database
    #[inline]
    pub fn get(&self, key: &dyn IntoLevelDBKey) -> Result<Option<Vec<u8>>, DbError> {
        self.db.as_ref().unwrap().get(&self.read_options, key)
    }

    /// Get a value matching key from the database, with key as bytes
    #[inline]
    pub fn get_u8(&self, key: &[u8]) -> Result<Option<Vec<u8>>, DbError> {
        self.db.as_ref().unwrap().get_u8(&self.read_options, key)
    }

    /// Delete an entry matching key from the database
    #[inline]
    pub fn delete(&self, key: &dyn IntoLevelDBKey) -> Result<(), DbError> {
        self.db.as_ref().unwrap().delete(&self.write_options, key)
    }

    /// Delete an entry matching key from the database, with key as bytes
    #[inline]
    pub fn delete_u8(&self, key: &[u8]) -> Result<(), DbError> {
        self.db
            .as_ref()
            .unwrap()
            .delete_u8(&self.write_options, key)
    }

    /// Write the WriteBatch to database atomically
    ///
    /// The sync flag forces filesystem sync operation eg fsync
    /// which will be slower than async writes, which are not
    /// guaranteed to complete. See leveldb Docs.
    pub fn write(&self, batch: &WriteBatch, sync: bool) -> Result<(), DbError> {
        const WO_SYNC: WriteOptions = WriteOptions { sync: true };
        const WO_NOSYNC: WriteOptions = WriteOptions { sync: false };

        self.db
            .as_ref()
            .unwrap()
            .write(if sync { &WO_SYNC } else { &WO_NOSYNC }, batch)
    }

    /// Write [`WriteBatch`] to database atomically
    ///
    /// Sync behavior will be determined by the WriteOptions
    /// supplied at `DB` creation.
    pub fn write_auto(&self, batch: &WriteBatch) -> Result<(), DbError> {
        self.db.as_ref().unwrap().write(&self.write_options, batch)
    }

    /// returns the directory path of the database files on disk.
    #[inline]
    pub fn path(&self) -> &std::path::PathBuf {
        &self.path
    }

    /// returns `destroy_db_on_drop` setting
    #[inline]
    pub fn destroy_db_on_drop(&self) -> bool {
        self.destroy_db_on_drop
    }

    /// Wipe the database files, if existing.
    fn destroy_db(&self) -> Result<(), std::io::Error> {
        match self.path.exists() {
            true => std::fs::remove_dir_all(&self.path),
            false => Ok(()),
        }
    }
}

impl Drop for DbIntMut {
    #[inline]
    fn drop(&mut self) {
        if self.destroy_db_on_drop {
            {
                // note: this block is only needed on windows, though it works
                // on other platforms.  Windows won't allow deletion of the
                // underlying DB file while it remains open.  The file doesn't
                // get closed until the the `rs_leveldb::DB` is dropped, which calls
                // the C API leveldb_close().
                //
                // So we must drop the `DB` held by `self`, but to do that we must
                // obtain ownership of the `Arc<DB>`.
                //
                // `Self::db` is an `Option` because `Option::take()` allows extracting
                // an owned value with an `&mut` reference.  Whereas `Cell`, `Refcell`
                // require a `self` (for `into_inner()`), but `impl Drop` provides us
                // only an `&mut self` reference.
                //
                // `mem::replace()` is another way to do it, but then we must replace
                // the `DB` with another `DB` which also opens a file, so we would
                // just create the problem again.

                // get `Arc<DB>` out of the `Option`, and replace with `None`.
                let db_opt = self.db.take();

                // now we own the `Arc`, so we can drop it, and `DB` with it.
                if let Some(db_arc) = db_opt {
                    drop(db_arc);
                }
            }

            // note: we do not panic if the database directory
            // cannot be removed.  Perhaps revisit later.
            let _ = self.destroy_db();
        }
    }
}

impl Batch for DbIntMut {
    #[inline]
    fn write(&self, options: &WriteOptions, batch: &WriteBatch) -> Result<(), DbError> {
        self.db.as_ref().unwrap().write(options, batch)
    }
}

impl<'a> Compaction<'a> for DbIntMut {
    #[inline]
    fn compact(&self, start: &'a [u8], limit: &'a [u8]) {
        self.db.as_ref().unwrap().compact(start, limit)
    }
}

impl<'a> Iterable<'a> for DbIntMut {
    #[inline]
    fn iter(&'a self, options: &ReadOptions) -> Iterator<'a> {
        self.db.as_ref().unwrap().iter(options)
    }

    #[inline]
    fn keys_iter(&'a self, options: &ReadOptions) -> KeyIterator<'a> {
        self.db.as_ref().unwrap().keys_iter(options)
    }

    #[inline]
    fn value_iter(&'a self, options: &ReadOptions) -> ValueIterator<'a> {
        self.db.as_ref().unwrap().value_iter(options)
    }
}

impl Snapshots for DbIntMut {
    fn snapshot(&self) -> Snapshot<'_> {
        self.db.as_ref().unwrap().snapshot()
    }
}

/// `DB` provides thread-safe access to LevelDB API with `&mut self` setters.
///
/// `DB` is a newtype wrapper for [`DbIntMut`] that hides the interior mutability
/// of the underlying C++ levelDB API, which is internally thread-safe.
///
/// If interior mutability is needed, use [`DbIntMut`] instead.
//
//  This also provides an abstraction layer which enables
//  us to provide an API that is somewhat backwards compatible
//  with rusty-leveldb.  For example, our get() and put()
//  do not require ReadOptions and WriteOptions param.
#[derive(Debug, Clone)]
pub struct DB(DbIntMut);

impl DB {
    /// Open a new database
    ///
    /// If the database is missing, the behaviour depends on `options.create_if_missing`.
    /// The database will be created using the settings given in `options`.
    #[inline]
    pub fn open(name: &Path, options: &Options) -> Result<Self, DbError> {
        Ok(Self(DbIntMut::open(name, options)?))
    }

    /// Open a new database
    ///
    /// If the database is missing, the behaviour depends on `options.create_if_missing`.
    /// The database will be created using the settings given in `options`.
    #[inline]
    pub fn open_with_options(
        name: &Path,
        options: &Options,
        read_options: ReadOptions,
        write_options: WriteOptions,
    ) -> Result<Self, DbError> {
        Ok(Self(DbIntMut::open_with_options(
            name,
            options,
            read_options,
            write_options,
        )?))
    }

    /// Open a new database with a custom comparator
    ///
    /// If the database is missing, the behaviour depends on `options.create_if_missing`.
    /// The database will be created using the settings given in `options`.
    ///
    /// The comparator must implement a total ordering over the keyspace.
    ///
    /// For keys that implement Ord, consider the `OrdComparator`.
    #[inline]
    pub fn open_with_comparator<C: Comparator>(
        name: &Path,
        options: &Options,
        comparator: C,
    ) -> Result<Self, DbError> {
        Ok(Self(DbIntMut::open_with_comparator(
            name, options, comparator,
        )?))
    }

    /// Creates and opens a test database
    ///
    /// The database will be created in the system
    /// temp directory with prefix "test-db-" followed
    /// by a random string.
    ///
    /// if destroy_db_on_drop is true, the database on-disk
    /// files will be wiped when the DB struct is dropped.
    pub fn open_new_test_database(
        destroy_db_on_drop: bool,
        options: Option<Options>,
        read_options: Option<ReadOptions>,
        write_options: Option<WriteOptions>,
    ) -> Result<Self, DbError> {
        Ok(Self(DbIntMut::open_new_test_database(
            destroy_db_on_drop,
            options,
            read_options,
            write_options,
        )?))
    }

    /// Opens an existing (test?) database, with auto-destroy option.
    ///
    /// if destroy_db_on_drop is true, the database on-disk
    /// files will be wiped when the DB struct is dropped.
    /// This is usually useful only for unit-test purposes.
    pub fn open_test_database(
        path: &std::path::Path,
        destroy_db_on_drop: bool,
        options: Option<Options>,
        read_options: Option<ReadOptions>,
        write_options: Option<WriteOptions>,
    ) -> Result<Self, DbError> {
        Ok(Self(DbIntMut::open_test_database(
            path,
            destroy_db_on_drop,
            options,
            read_options,
            write_options,
        )?))
    }

    /// Set a key/val in the database
    #[inline]
    pub fn put(&mut self, key: &dyn IntoLevelDBKey, value: &[u8]) -> Result<(), DbError> {
        self.0.put(key, value)
    }

    /// Set a key/val in the database, with key as bytes.
    #[inline]
    pub fn put_u8(&mut self, key: &[u8], value: &[u8]) -> Result<(), DbError> {
        self.0.put_u8(key, value)
    }

    /// Get a value matching key from the database
    #[inline]
    pub fn get(&self, key: &dyn IntoLevelDBKey) -> Result<Option<Vec<u8>>, DbError> {
        self.0.get(key)
    }

    /// Get a value matching key from the database, with key as bytes
    #[inline]
    pub fn get_u8(&self, key: &[u8]) -> Result<Option<Vec<u8>>, DbError> {
        self.0.get_u8(key)
    }

    /// Delete an entry matching key from the database
    #[inline]
    pub fn delete(&mut self, key: &dyn IntoLevelDBKey) -> Result<(), DbError> {
        self.0.delete(key)
    }

    /// Delete an entry matching key from the database, with key as bytes
    #[inline]
    pub fn delete_u8(&mut self, key: &[u8]) -> Result<(), DbError> {
        self.0.delete_u8(key)
    }

    /// Write the WriteBatch to database atomically
    ///
    /// The sync flag forces filesystem sync operation eg fsync
    /// which will be slower than async writes, which are not
    /// guaranteed to complete. See leveldb Docs.
    pub fn write(&mut self, batch: &WriteBatch, sync: bool) -> Result<(), DbError> {
        self.0.write(batch, sync)
    }

    /// Write the WriteBatch to database atomically
    ///
    /// The sync flag forces filesystem sync operation eg fsync
    /// which will be slower than async writes, which are not
    /// guaranteed to complete. See leveldb Docs.
    pub fn write_batch_iter(
        &mut self,
        batch: impl IntoIterator<Item = (&'static [u8], &'static [u8])>,
        sync: bool,
    ) -> Result<(), DbError> {
        let write_batch = WriteBatch::new();
        for (key, value) in batch {
            write_batch.put(&key, value);
        }

        self.0.write(&write_batch, sync)
    }

    /// Write [`WriteBatch`] to database atomically
    ///
    /// Sync behavior will be determined by the WriteOptions
    /// supplied at `DB` creation.
    pub fn write_auto(&mut self, batch: &WriteBatch) -> Result<(), DbError> {
        self.0.write_auto(batch)
    }

    /// Write the WriteBatch to database atomically
    ///
    /// The sync flag forces filesystem sync operation eg fsync
    /// which will be slower than async writes, which are not
    /// guaranteed to complete. See leveldb Docs.
    pub fn write_batch_iter_auto(
        &mut self,
        batch: impl IntoIterator<Item = (&'static [u8], &'static [u8])>,
    ) -> Result<(), DbError> {
        let write_batch = WriteBatch::new();
        for (key, value) in batch {
            write_batch.put(&key, value);
        }

        self.0.write_auto(&write_batch)
    }

    /// returns the directory path of the database files on disk.
    #[inline]
    pub fn path(&self) -> &std::path::PathBuf {
        self.0.path()
    }

    /// returns `destroy_db_on_drop` setting
    #[inline]
    pub fn destroy_db_on_drop(&self) -> bool {
        self.0.destroy_db_on_drop()
    }

    /// compacts the database file.  should be called periodically.
    #[inline]
    pub fn compact<'a>(&mut self, start: &'a [u8], limit: &'a [u8]) {
        self.0.compact(start, limit)
    }

    /// Wipe the database files, if existing.
    pub fn destroy_db(&mut self) -> Result<(), std::io::Error> {
        self.0.destroy_db()
    }
}

impl<'a> Iterable<'a> for DB {
    #[inline]
    fn iter(&'a self, options: &ReadOptions) -> Iterator<'a> {
        self.0.iter(options)
    }

    #[inline]
    fn keys_iter(&'a self, options: &ReadOptions) -> KeyIterator<'a> {
        self.0.keys_iter(options)
    }

    #[inline]
    fn value_iter(&'a self, options: &ReadOptions) -> ValueIterator<'a> {
        self.0.value_iter(options)
    }
}

impl Snapshots for DB {
    fn snapshot(&self) -> Snapshot<'_> {
        self.0.snapshot()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn level_db_close_and_reload() {
        // open new test database that will not be destroyed on close.
        let mut db = DB::open_new_test_database(false, None, None, None).unwrap();
        let db_path = db.path().clone();

        let key = "answer-to-everything";
        let val = vec![42];

        let _ = db.put(&key, &val);

        drop(db); // close the DB.

        assert!(db_path.exists());

        // open existing database that will be destroyed on close.
        let db2 = DbIntMut::open_test_database(&db_path, true, None, None, None).unwrap();

        let val2 = db2.get(&key).unwrap().unwrap();
        assert_eq!(val, val2);

        drop(db2); // close the DB.  db_path dir is auto removed.

        assert!(!db_path.exists());
    }
}
