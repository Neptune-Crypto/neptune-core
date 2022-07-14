use anyhow::Result;
use serde::{de::DeserializeOwned, Serialize};
use std::path::Path;

/// The interface we want for any LevelDB crate we may use.
pub trait LevelDB<Key: Serialize + DeserializeOwned, Value: Serialize + DeserializeOwned> {
    fn new<P>(path: P, db_name: &str) -> Result<Self>
    where
        P: AsRef<Path> + Clone,
        Self: Sized;
    fn get(&mut self, key: Key) -> Option<Value>;
    fn put(&mut self, key: Key, value: Value);
    fn delete(&mut self, key: Key) -> Option<Value>;
}
