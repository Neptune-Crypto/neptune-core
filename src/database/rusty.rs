use super::leveldb::LevelDB;
use anyhow::Result;
use rusty_leveldb::DB;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    marker::PhantomData,
    path::{Path, PathBuf},
};

pub struct RustyLevelDB<Key: Serialize + DeserializeOwned, Value: Serialize + DeserializeOwned> {
    database: DB,
    _name: String, // helper field for debugging purposes
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
            _name: db_name.to_string(),
        })
    }

    fn get(&mut self, key: Key) -> Option<Value> {
        let key_bytes: Vec<u8> = bincode::serialize(&key).unwrap();
        let value_bytes: Option<Vec<u8>> = self.database.get(&key_bytes);
        match value_bytes {
            Some(bytes) => {
                let options = bincode::DefaultOptions::new();
                let mut deserializer = bincode::Deserializer::from_slice(&bytes, options);
                let deserializer = serde_stacker::Deserializer::new(&mut deserializer);
                let a = Value::deserialize(deserializer);
                match a {
                    Ok(res) => Some(res),
                    Err(err) => panic!("Failed to deserialize: {}", err),
                }
            }
            None => None,
        }
    }

    fn put(&mut self, key: Key, value: Value) {
        let key_bytes: Vec<u8> = bincode::serialize(&key).unwrap();
        let mut value_bytes: Vec<u8> = vec![];
        let options = bincode::DefaultOptions::new();
        let mut serializer = bincode::Serializer::new(&mut value_bytes, options);
        let serializer = serde_stacker::Serializer::new(&mut serializer);
        let _result = value.serialize(serializer);
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
