use std::marker::PhantomData;
use std::path::Path;

use anyhow::Result;
use leveldb::batch::WriteBatch;
use leveldb::iterator::Iterable;
use leveldb::options::Options;
use leveldb::options::ReadOptions;
use leveldb::options::WriteOptions;
use leveldb_sys::Compression;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::task;

use super::leveldb::DB;

struct NeptuneLevelDbInternal<Key, Value>
where
    Key: Serialize + DeserializeOwned,
    Value: Serialize + DeserializeOwned,
{
    database: DB,
    _key: PhantomData<Key>,
    _value: PhantomData<Value>,
}

impl<Key, Value> From<DB> for NeptuneLevelDbInternal<Key, Value>
where
    Key: Serialize + DeserializeOwned,
    Value: Serialize + DeserializeOwned,
{
    fn from(database: DB) -> Self {
        Self {
            database,
            _key: Default::default(),
            _value: Default::default(),
        }
    }
}

impl<Key, Value> Clone for NeptuneLevelDbInternal<Key, Value>
where
    Key: Serialize + DeserializeOwned,
    Value: Serialize + DeserializeOwned,
{
    fn clone(&self) -> Self {
        Self {
            database: self.database.clone(),
            _key: Default::default(),
            _value: Default::default(),
        }
    }
}

// We have to implement `Debug` for `NeptuneLevelDbInternal` as the `State` struct
// contains a database object, and `State` is used as input argument
// to multiple functions where logging is enabled with the `instrument`
// attributes from the `tracing` crate, and this requires all input
// arguments to the function to implement the `Debug` trait as this
// info is written on all logging events.
impl<Key, Value> core::fmt::Debug for NeptuneLevelDbInternal<Key, Value>
where
    Key: Serialize + DeserializeOwned,
    Value: Serialize + DeserializeOwned,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("").finish()
    }
}

pub fn create_db_if_missing() -> Options {
    let mut opts = Options::new();
    opts.create_if_missing = true;
    opts
}

impl<Key, Value> NeptuneLevelDbInternal<Key, Value>
where
    Key: Serialize + DeserializeOwned,
    Value: Serialize + DeserializeOwned,
{
    /// Open or create a new or existing database
    fn new(db_path: &Path, options: &Options) -> Result<Self> {
        let mut write_options = WriteOptions::new();
        write_options.sync = true;

        let mut read_options = ReadOptions::new();
        read_options.verify_checksums = true;
        read_options.fill_cache = true;

        let database = DB::open_with_options(db_path, options, read_options, write_options)?;
        let database = Self {
            database,
            _key: PhantomData,
            _value: PhantomData,
        };
        Ok(database)
    }

    fn get(&self, key: Key) -> Option<Value> {
        let key_bytes: Vec<u8> = bincode::serialize(&key).unwrap();
        let value_bytes: Option<Vec<u8>> = self.database.get(&key_bytes).unwrap();
        value_bytes.map(|bytes| bincode::deserialize(&bytes).unwrap())
    }

    fn get_u8(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        self.database.get_u8(key).unwrap()
    }

    fn put(&mut self, key: Key, value: Value) {
        let key_bytes: Vec<u8> = bincode::serialize(&key).unwrap();
        let value_bytes: Vec<u8> = bincode::serialize(&value).unwrap();
        self.database.put(&key_bytes, &value_bytes).unwrap();
    }

    fn put_u8(&mut self, key: &[u8], value: &[u8]) {
        self.database.put_u8(key, value).unwrap()
    }

    fn batch_write(&mut self, entries: WriteBatchAsync<Key, Value>) {
        let batch = WriteBatch::new();
        for op in entries.0 {
            match op {
                WriteBatchOpAsync::Write(key, value) => {
                    let key_bytes: Vec<u8> = bincode::serialize(&key).unwrap();
                    let value_bytes: Vec<u8> = bincode::serialize(&value).unwrap();
                    batch.put(&key_bytes, &value_bytes);
                }
                WriteBatchOpAsync::Delete(key) => {
                    let key_bytes: Vec<u8> = bincode::serialize(&key).unwrap();
                    batch.delete(&key_bytes);
                }
            }
        }

        self.database.write(&batch, true).unwrap();
    }

    fn delete(&mut self, key: Key) -> Option<Value> {
        let key_bytes: Vec<u8> = bincode::serialize(&key).unwrap(); // add safety
        let value_bytes: Option<Vec<u8>> = self.database.get(&key_bytes).unwrap();
        let value_object = value_bytes.map(|bytes| bincode::deserialize(&bytes).unwrap());
        let status = self.database.delete(&key_bytes);

        match status {
            Ok(_) => value_object, // could be None, if record is not present
            Err(err) => panic!("database failure: {}", err),
        }
    }

    fn flush(&mut self) {
        self.database
            .write(&WriteBatch::new(), true)
            .expect("Database flushing to disk must succeed");
    }

    // dumps entire database to stdout, with keys and values in hex.
    fn dump_database(&self) {
        use std::io::Write;
        for (key, val) in self.database.iter(&ReadOptions::new()) {
            print!("Key (hex): ");
            for byte in &key {
                print!("{:02x} ", byte);
            }
            println!(); // Newline after key

            print!("Value (hex): ");
            for byte in &val {
                print!("{:02x} ", byte);
            }
            println!(); // Newline after value

            println!(); // Extra newline between value and the next key
            std::io::stdout().flush().unwrap(); // Force immediate output
        }
    }
}

/// `NeptuneLevelDb` provides an async-friendly and clone-friendly wrapper
/// around `NeptuneLevelDbInternal`.
///
/// Methods in the underlying struct `LevelDB` from `rs-leveldb` crate are all sync
/// and they sometimes perform blocking file IO.  It is discouraged to
/// call blocking IO from async code as it can lead to concurrency problems,
/// usually hidden until a certain level of load is reached.
///
/// The tokio page for spawn_blocking says:
///     In general, issuing a blocking call or performing a lot of compute in a
///     future without yielding is problematic, as it may prevent the executor from
///     driving other futures forward.
///
/// See:
///  * <https://github.com/Neptune-Crypto/neptune-core/issues/74>
///  * <https://internals.rust-lang.org/t/warning-when-calling-a-blocking-function-in-an-async-context/11440/5>
///  * <https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html>
///
/// Therefore `NeptuneLevelDb` wraps the sync methods with `spawn_blocking()`
/// so that the tokio runtime can run the blocking IO on a thread where blocking
/// is acceptable
#[derive(Clone)]
pub struct NeptuneLevelDb<Key, Value>(NeptuneLevelDbInternal<Key, Value>)
where
    Key: Serialize + DeserializeOwned,
    Value: Serialize + DeserializeOwned;

impl<Key, Value> core::fmt::Debug for NeptuneLevelDb<Key, Value>
where
    Key: Serialize + DeserializeOwned,
    Value: Serialize + DeserializeOwned,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NeptuneLevelDb").finish()
    }
}

impl<Key, Value> NeptuneLevelDb<Key, Value>
where
    Key: Serialize + DeserializeOwned + Send + Sync + 'static,
    Value: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    /// IMPORTANT:  the returned iterator is NOT async.  The database is queried
    /// synchrously so the caller will block.  Consider using
    /// `spawn_blocking()` task when using this iterator in async code.
    ///
    /// ALSO: this calls allocates all DB keys.  For large databases
    /// this could be problematic and is best to avoid.
    ///
    // todo: can we avoid allocating keys with collect()?
    // todo: can we create a true async iterator?
    // todo: perhaps refactor neptune, so it does not need/use a level-db iterator.
    pub fn iter(&self) -> Box<dyn Iterator<Item = (Key, Value)> + '_> {
        let inner = self.0.clone();
        let keys: Vec<_> = inner.database.keys_iter(&ReadOptions::new()).collect();

        Box::new(keys.into_iter().map(move |k| {
            let v = inner.database.get_u8(&k).unwrap().unwrap();

            (
                bincode::deserialize(&k).unwrap(),
                bincode::deserialize(&v).unwrap(),
            )
        }))
    }

    /// Open or create a new or existing database asynchronously
    pub async fn new(db_path: &Path, options: &Options) -> Result<Self> {
        let options_async = OptionsAsync::from(options);
        let path = db_path.to_path_buf();

        let db =
            task::spawn_blocking(move || NeptuneLevelDbInternal::new(&path, &options_async.into()))
                .await??;

        Ok(Self(db))
    }

    /// Get database value asynchronously
    pub async fn get(&self, key: Key) -> Option<Value> {
        let inner = self.0.clone();
        task::spawn_blocking(move || inner.get(key)).await.unwrap()
    }

    pub async fn get_u8(&self, key: Vec<u8>) -> Option<Vec<u8>> {
        let mut inner = self.0.clone();
        task::spawn_blocking(move || inner.get_u8(&key))
            .await
            .unwrap()
    }

    /// Set database value asynchronously
    pub async fn put(&mut self, key: Key, value: Value) {
        let mut inner = self.0.clone();
        task::spawn_blocking(move || inner.put(key, value))
            .await
            .unwrap()
    }

    pub async fn put_u8(&mut self, key: Vec<u8>, value: Vec<u8>) {
        let mut inner = self.0.clone();
        task::spawn_blocking(move || inner.put_u8(&key, &value))
            .await
            .unwrap()
    }

    /// Write database values as a batch asynchronously
    pub async fn batch_write(&mut self, entries: WriteBatchAsync<Key, Value>) {
        let mut inner = self.0.clone();
        task::spawn_blocking(move || inner.batch_write(entries))
            .await
            .unwrap()
    }

    /// Delete database value asynchronously
    pub async fn delete(&mut self, key: Key) -> Option<Value> {
        let mut inner = self.0.clone();
        task::spawn_blocking(move || inner.delete(key))
            .await
            .unwrap()
    }

    /// Delete database value asynchronously
    pub async fn flush(&mut self) {
        let mut inner = self.0.clone();
        task::spawn_blocking(move || inner.flush()).await.unwrap()
    }

    /// returns the directory path of the database files on disk.
    #[inline]
    pub fn path(&self) -> &std::path::PathBuf {
        self.0.database.path()
    }
}

impl<Key, Value> NeptuneLevelDb<Key, Value>
where
    Key: Serialize + DeserializeOwned + Send + Sync + 'static,
    Value: Serialize + DeserializeOwned + Send + Sync + 'static,
{
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
    ) -> Result<Self> {
        let options_async = options.map(OptionsAsync::from);

        let db = task::spawn_blocking(move || {
            DB::open_new_test_database(
                destroy_db_on_drop,
                options_async.map(|o| o.into()),
                read_options,
                write_options,
            )
        })
        .await??;

        Ok(Self(NeptuneLevelDbInternal::from(db)))
    }

    /// Opens an existing (test?) database, with auto-destroy option.
    ///
    /// if destroy_db_on_drop is true, the database on-disk
    /// files will be wiped when the DB struct is dropped.
    /// This is usually useful only for unit-test purposes.
    pub async fn open_test_database(
        db_path: &std::path::Path,
        destroy_db_on_drop: bool,
        options: Option<Options>,
        read_options: Option<ReadOptions>,
        write_options: Option<WriteOptions>,
    ) -> Result<Self> {
        let path = db_path.to_path_buf();
        let options_async = options.map(OptionsAsync::from);

        let db = task::spawn_blocking(move || {
            DB::open_test_database(
                &path,
                destroy_db_on_drop,
                options_async.map(|o| o.into()),
                read_options,
                write_options,
            )
        })
        .await??;

        Ok(Self(NeptuneLevelDbInternal::from(db)))
    }

    /// dumps entire database to stdout, with keys and values in hex.
    pub async fn dump_database(&self) {
        let inner = self.0.clone();
        task::spawn_blocking(move || inner.dump_database())
            .await
            .unwrap()
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
        assert!(
            o.cache.is_none(),
            "cache option not supported for NeptuneLevelDb"
        );

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

#[derive(Debug, Clone)]
enum WriteBatchOpAsync<K, V> {
    // args: key, val
    Write(K, V),

    // args: key
    Delete(K),
}

#[derive(Debug, Clone)]
pub struct WriteBatchAsync<K, V>(Vec<WriteBatchOpAsync<K, V>>);

impl<K, V> WriteBatchAsync<K, V> {
    pub fn new() -> Self {
        Self(vec![])
    }

    pub fn op_write(&mut self, key: K, value: V) {
        self.0.push(WriteBatchOpAsync::Write(key, value));
    }

    pub fn op_delete(&mut self, key: K) {
        self.0.push(WriteBatchOpAsync::Delete(key));
    }
}

impl<K, V> Default for WriteBatchAsync<K, V> {
    fn default() -> Self {
        Self::new()
    }
}
