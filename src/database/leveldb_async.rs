use leveldb::{
    compaction::Compaction,
    error::Error as DbError,
    iterator::{Iterable, Iterator, KeyIterator, ValueIterator},
    options::{Options, ReadOptions, WriteOptions},
    key::IntoLevelDBKey,
};
use leveldb_sys::Compression;
use super::leveldb::DB;
use tokio::task;
use std::path::Path;

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
pub struct LevelDbAsync(DB);

impl LevelDbAsync {
    /// Open a new database
    ///
    /// If the database is missing, the behaviour depends on `options.create_if_missing`.
    /// The database will be created using the settings given in `options`.
    #[inline]
    pub async fn open(name: &Path, options: &Options) -> Result<Self, DbError> {

        // let options_async: OptionsAsync = options.into();

        // let db =
        //     task::spawn_blocking(move || DB::open(name, &options_async.into()))
        //         .await??;

        Self::open_with_options(name, options, ReadOptions::new(), WriteOptions::new()).await
    }

    /// Open a new database
    ///
    /// If the database is missing, the behaviour depends on `options.create_if_missing`.
    /// The database will be created using the settings given in `options`.
    #[inline]
    pub async fn open_with_options(
        path: &Path,
        options: &Options,
        read_options: ReadOptions,
        write_options: WriteOptions,
    ) -> Result<Self, DbError> {

        let path_buf = path.to_path_buf();

        let options_async: OptionsAsync = options.into();

        let db =
            task::spawn_blocking(move || DB::open_with_options(path_buf.as_path(), &options_async.into(), read_options, write_options))
                .await.unwrap()?;

        Ok(Self(db))
    }

    /// Creates and opens a test database
    ///
    /// The database will be created in the system
    /// temp directory with prefix "test-db-" followed
    /// by a random string.
    ///
    /// if destroy_db_on_drop is true, the database on-disk
    /// files will be wiped when the DB struct is dropped.
    pub async fn open_new_test_database(
        destroy_db_on_drop: bool,
        options: Option<Options>,
        read_options: Option<ReadOptions>,
        write_options: Option<WriteOptions>,
    ) -> Result<Self, DbError> {

        let options_async: Option<OptionsAsync> = options.map(|o| o.into());

        let db =
            task::spawn_blocking(move || NeptuneLevelDb::open_new_test_database(destroy_db_on_drop, options_async.map(|o| o.into()), read_options, write_options))
                .await.unwrap()?;

        Ok(Self(db))
    }

    /// Opens an existing (test?) database, with auto-destroy option.
    ///
    /// if destroy_db_on_drop is true, the database on-disk
    /// files will be wiped when the DB struct is dropped.
    /// This is usually useful only for unit-test purposes.
    pub async fn open_test_database(
        path: &std::path::Path,
        destroy_db_on_drop: bool,
        options: Option<Options>,
        read_options: Option<ReadOptions>,
        write_options: Option<WriteOptions>,
    ) -> Result<Self, DbError> {
        let path_buf = path.to_path_buf();

        let options_async: Option<OptionsAsync> = options.map(|o| o.into());

        let db =
            task::spawn_blocking(move || NeptuneLevelDb::open_test_database(path_buf.as_path(), destroy_db_on_drop, options_async.map(|o| o.into()), read_options, write_options))
                .await.unwrap()?;

        Ok(Self(db))
    }

    /// Set a key/val in the database
    #[inline]
    pub async fn put(&mut self, key: &'static dyn IntoLevelDBKey, value: &'static [u8]) -> Result<(), DbError> {

        let mut inner = self.0.clone();
        task::spawn_blocking(move || inner.put(key, value))
            .await
            .unwrap()
    }

    /// Set a key/val in the database, with key as bytes.
    #[inline]
    pub async fn put_u8(&mut self, key: &'static [u8], value: &'static [u8]) -> Result<(), DbError> {

        let mut inner = self.0.clone();
        task::spawn_blocking(move || inner.put_u8(key, value))
            .await
            .unwrap()
    }

    /// Get a value matching key from the database
    #[inline]
    pub async fn get(&self, key: &'static [u8]) -> Result<Option<Vec<u8>>, DbError> {
        let inner = self.0.clone();
        task::spawn_blocking(move || inner.get(key))
            .await
            .unwrap()
    }

    /// Get a value matching key from the database, with key as bytes
    #[inline]
    pub async fn get_u8(&self, key: &'static [u8]) -> Result<Option<Vec<u8>>, DbError> {

        let inner = self.0.clone();
        task::spawn_blocking(move || inner.get_u8(key))
            .await
            .unwrap()
    }

    /// Delete an entry matching key from the database
    #[inline]
    pub async fn delete(&mut self, key: &'static [u8]) -> Result<(), DbError> {
        let mut inner = self.0.clone();
        task::spawn_blocking(move || inner.delete(key))
            .await
            .unwrap()
    }

    /// Delete an entry matching key from the database, with key as bytes
    #[inline]
    pub async fn delete_u8(&mut self, key: &'static [u8]) -> Result<(), DbError> {
        let mut inner = self.0.clone();
        task::spawn_blocking(move || inner.delete_u8(key))
            .await
            .unwrap()
    }

    /// Write the WriteBatch to database atomically
    ///
    /// The sync flag forces filesystem sync operation eg fsync
    /// which will be slower than async writes, which are not
    /// guaranteed to complete. See leveldb Docs.
    pub async fn write_batch_iter(&mut self,
        batch: Vec<(&'static [u8], &'static [u8])>,
        sync: bool) -> Result<(), DbError> {
        let mut inner = self.0.clone();
        task::spawn_blocking(move || inner.write_batch_iter(batch, sync))
            .await
            .unwrap()
    }

    /// Write [`WriteBatch`] to database atomically
    ///
    /// Sync behavior will be determined by the WriteOptions
    /// supplied at `DB` creation.
    pub async fn write_auto(&mut self,
        batch: Vec<(&'static [u8], &'static [u8])>,
    ) -> Result<(), DbError> {
        let mut inner = self.0.clone();
        task::spawn_blocking(move || inner.write_batch_iter_auto(batch))
            .await
            .unwrap()
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
    pub async fn compact(&mut self, start: &'static [u8], limit: &'static [u8]) {
        let mut inner = self.0.clone();
        task::spawn_blocking(move || inner.compact(start, limit))
            .await.unwrap()
    }

    /// Wipe the database files, if existing.
    pub async fn destroy_db(&mut self) -> Result<(), std::io::Error> {
        let mut inner = self.0.clone();
        task::spawn_blocking(move || inner.destroy_db())
            .await
            .unwrap()
    }
}

impl<'a> Iterable<'a> for LevelDbAsync {
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


// We made this OptionsAsync struct because leveldb::options::Options cannot be
// passed between threads because it contains the `cache: Option<Cache>` field
// and Cache is not `Send`.  We can't do anything about that, so instead we
// send this OptionsAsync between threads, which does not have a Cache field.
//
// todo:  add a cache_size option specified in bytes.
pub(super) struct OptionsAsync {
    pub create_if_missing: bool,
    pub error_if_exists: bool,
    pub paranoid_checks: bool,
    pub write_buffer_size: Option<usize>,
    pub max_open_files: Option<i32>,
    pub block_size: Option<usize>,
    pub block_restart_interval: Option<i32>,
    pub compression: Compression,
}
impl From<&Options> for OptionsAsync {
    fn from(o: &Options) -> Self {
        if o.cache.is_some() {
            panic!("cache option not supported for NeptuneLevelDb");
        }

        Self {
            create_if_missing: o.create_if_missing,
            error_if_exists: o.error_if_exists,
            paranoid_checks: o.paranoid_checks,
            write_buffer_size: o.write_buffer_size,
            max_open_files: o.max_open_files,
            block_size: o.block_size,
            block_restart_interval: o.block_restart_interval,
            compression: o.compression,
        }
    }
}
impl From<Options> for OptionsAsync {
    fn from(o: Options) -> Self {
        Self::from(&o)
    }
}

impl From<&OptionsAsync> for Options {
    fn from(o: &OptionsAsync) -> Self {
        Self {
            create_if_missing: o.create_if_missing,
            error_if_exists: o.error_if_exists,
            paranoid_checks: o.paranoid_checks,
            write_buffer_size: o.write_buffer_size,
            max_open_files: o.max_open_files,
            block_size: o.block_size,
            block_restart_interval: o.block_restart_interval,
            compression: o.compression,
            cache: None,
        }
    }
}
impl From<OptionsAsync> for Options {
    fn from(o: OptionsAsync) -> Self {
        Self::from(&o)
    }
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn level_db_close_and_reload() {
        // open new test database that will not be destroyed on close.
        let mut db = NeptuneLevelDb::open_new_test_database(false, None, None, None).unwrap();
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
