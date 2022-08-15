use super::leveldb::LevelDB;
use anyhow::Result;
use rusty_leveldb::{DBIterator, LdbIterator, DB};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    marker::PhantomData,
    path::{Path, PathBuf},
};

pub struct RustyLevelDB<Key: Serialize + DeserializeOwned, Value: Serialize + DeserializeOwned> {
    database: DB,
    _key: PhantomData<Key>,
    _value: PhantomData<Value>,
}
// We have to implement `Debug` for `RustyLevelDB` as the `State` struct
// contains a database object, and `State` is used as input argument
// to multiple functions where logging is enabled with the `instrument`
// attributes from the `tracing` crate, and this requires all input
// arguments to the function to implement the `Debug` trait as this
// info is written on all logging events.
impl<Key: Serialize + DeserializeOwned, Value: Serialize + DeserializeOwned> core::fmt::Debug
    for RustyLevelDB<Key, Value>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("").finish()
    }
}

// pub trait RustyDatabaseTable<Key: Serialize + DeserializeOwned, Value: Serialize + DeserializeOwned>:
// DatabaseTable<Key, Value>
impl<Key: Serialize + DeserializeOwned, Value: Serialize + DeserializeOwned> LevelDB<Key, Value>
    for RustyLevelDB<Key, Value>
{
    fn new<P: AsRef<Path>>(db_path: P, db_name: &str) -> Result<Self> {
        let mut path = PathBuf::new();
        path.push(db_path);
        path.push(db_name);
        let options = rusty_leveldb::Options::default();
        let db = DB::open(path, options)?;

        Ok(Self {
            database: db,
            _key: PhantomData,
            _value: PhantomData,
        })
    }

    fn get(&mut self, key: Key) -> Option<Value> {
        let key_bytes: Vec<u8> = bincode::serialize(&key).unwrap();
        let value_bytes: Option<Vec<u8>> = self.database.get(&key_bytes);
        value_bytes.map(|bytes| bincode::deserialize(&bytes).unwrap())
    }

    fn put(&mut self, key: Key, value: Value) {
        let key_bytes: Vec<u8> = bincode::serialize(&key).unwrap();
        let value_bytes: Vec<u8> = bincode::serialize(&value).unwrap();
        self.database.put(&key_bytes, &value_bytes).unwrap();

        // TODO: We probably don't have to flush after each writing mutation. But then we would have
        // to flush on shutdown.
        self.database
            .flush()
            .expect("Database flushing to disk must succeed");
    }

    fn delete(&mut self, key: Key) -> Option<Value> {
        let key_bytes: Vec<u8> = bincode::serialize(&key).unwrap(); // add safety
        let value_bytes: Option<Vec<u8>> = self.database.get(&key_bytes);
        let value_object = value_bytes.map(|bytes| bincode::deserialize(&bytes).unwrap());
        let status = self.database.delete(&key_bytes);

        // TODO: We probably don't have to flush after each mutation. But then we would have
        // to flush on shutdown.
        self.database
            .flush()
            .expect("Database flushing to disk must succeed");
        match status {
            Ok(_) => value_object, // could be None, if record is not present
            Err(err) => panic!("database failure: {}", err),
        }
    }
}

impl<Key: Serialize + DeserializeOwned, Value: Serialize + DeserializeOwned>
    RustyLevelDB<Key, Value>
{
    pub fn new_iter(&mut self) -> RustyLevelDBIterator<Key, Value> {
        RustyLevelDBIterator::new(self)
    }
}

pub struct RustyLevelDBIterator<
    Key: Serialize + DeserializeOwned,
    Value: Serialize + DeserializeOwned,
> {
    iterator: DBIterator,
    _key: PhantomData<Key>,
    _value: PhantomData<Value>,
}

impl<Key: Serialize + DeserializeOwned, Value: Serialize + DeserializeOwned> Iterator
    for RustyLevelDBIterator<Key, Value>
{
    type Item = (Key, Value);

    fn next(&mut self) -> Option<Self::Item> {
        self.iterator.next().map(|(sk, sv)| {
            (
                bincode::deserialize(&sk).unwrap(),
                bincode::deserialize(&sv).unwrap(),
            )
        })
    }
}

impl<Key: Serialize + DeserializeOwned, Value: Serialize + DeserializeOwned>
    RustyLevelDBIterator<Key, Value>
{
    fn new(database: &mut RustyLevelDB<Key, Value>) -> Self {
        let iterator = database
            .database
            .new_iter()
            .expect("Iterator should be constructed.");
        Self {
            iterator,
            _key: PhantomData,
            _value: PhantomData,
        }
    }
}
