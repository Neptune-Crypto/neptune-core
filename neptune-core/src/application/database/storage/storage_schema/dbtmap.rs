use std::fmt::Debug;
use std::hash::Hash;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::Serialize;

use super::super::storage_vec::Index;
use super::traits::*;
use super::PendingWrites;
use super::SimpleRustyReader;
use crate::application::database::storage::storage_schema::dbtmap_private::DbtMapPrivate;
use crate::application::locks::tokio::AtomicRw;

/// A LevelDb-backed insert-only mapping from keys to values for use with
/// DbSchema. Notably, this mapping does not support removal of records. Once
/// a key/value pair is inserted, it cannot be removed again. However, existing
/// values can be overwritten. If some notion of deletion is required, the
/// value entries must be declared such that they can be marked as deleted by
/// the caller. As an alternative to deleting individual elements, the entire
/// mapping can be cleared.
#[derive(Debug)]
pub struct DbtMap<K, V> {
    inner: DbtMapPrivate<K, V>,
}

impl<K, V> DbtMap<K, V>
where
    K: Clone + Debug + Serialize + DeserializeOwned + Eq + Hash + Send + Sync,
    V: Clone + Debug + Serialize + DeserializeOwned,
{
    // DbtMap cannot be instantiated directly outside of storage_schema module
    // use [Schema::new_map()]
    #[inline]
    pub(super) async fn new(
        pending_writes: AtomicRw<PendingWrites>,
        reader: Arc<SimpleRustyReader>,
        key_prefixes: [u8; 2],
        name: &str,
    ) -> Self {
        let map = DbtMapPrivate::new(pending_writes, reader, key_prefixes, name).await;

        Self { inner: map }
    }

    /// Returns true iff the map contains no elements.
    #[inline]
    pub async fn is_empty(&self) -> bool {
        self.inner.is_empty().await
    }

    /// Get collection length, the number of entries in the map.
    #[inline]
    pub async fn len(&self) -> Index {
        self.inner.len().await
    }

    /// Returns the value corresponding to the key.
    pub async fn get(&self, key: &K) -> Option<V> {
        self.inner.get(key).await
    }

    /// Returns true if the map contains a value for the specified key.
    pub async fn contains_key(&self, key: &K) -> bool {
        self.inner.contains_key(key).await
    }

    /// Inserts a key-value pair into the map.
    ///
    /// If the map did not have this key present, [`None`] is returned.
    ///
    /// If the map did have this key present, the value is updated, and the old
    /// value is returned.
    pub async fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.inner.insert(key, value).await
    }

    /// Return all keys in the mapping, ordered by insertion order.
    pub async fn all_keys(&self) -> Vec<K> {
        self.inner.all_keys().await
    }

    /// Delete all entries in the map.
    pub async fn clear(&mut self) {
        self.inner.clear().await
    }
}

#[async_trait::async_trait]
impl<K, V> DbTable for DbtMap<K, V>
where
    K: Clone + Debug + Serialize + DeserializeOwned + Eq + Hash + Send + Sync,
    V: Clone + Serialize + DeserializeOwned + Send + Sync,
{
    #[inline]
    // No preprocessing needed for this table type
    async fn restore_or_new(&mut self) {}
}
