use anyhow::Result;
use serde::{de::DeserializeOwned, Serialize};
use std::path::Path;
use twenty_first::leveldb::options::Options;

/// The interface we want for any LevelDB crate we may use.
pub trait LevelDB<Key, Value>
where
    Key: Serialize + DeserializeOwned,
    Value: Serialize + DeserializeOwned,
{
    fn new(db_path: &Path, options: &Options) -> Result<Self>
    where
        Self: Sized;
    fn batch_write(&self, entries: impl IntoIterator<Item = (Key, Value)>);
    fn get(&self, key: Key) -> Option<Value>;
    fn put(&self, key: Key, value: Value);
    fn delete(&self, key: Key) -> Option<Value>;
    fn flush(&self);
}
