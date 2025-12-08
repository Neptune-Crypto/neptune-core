use std::collections::HashMap;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::hash::Hash;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::Serialize;

use super::traits::StorageReader;
use super::PendingWrites;
use super::RustyKey;
use super::RustyValue;
use super::SimpleRustyReader;
use super::WriteOperation;
use crate::application::database::storage::storage_schema::DbtVec;
use crate::application::database::storage::storage_vec::traits::StorageVecBase;
use crate::application::database::storage::storage_vec::Index;
use crate::application::locks::tokio::AtomicRw;

/// A level-DB backed insertion-only mapping from keys to values.
///
/// The reason that remove functionality is not supported is that the
/// underlying [`DbtVec`] does not support removal of an arbitrary element, it
/// only supports push and pop operations, so there would be no efficient way
/// of removing a key from the maps list of keys by index.
pub(super) struct DbtMapPrivate<K, V> {
    pub(super) name: String,
    pub(super) reader: Arc<SimpleRustyReader>,
    pub(super) prefix_map_key: u8,
    pub(super) cache: HashMap<K, (V, Index)>,
    pub(super) pending_writes: AtomicRw<PendingWrites>,

    /// A list of all keys in the mapping, sorted by insertion order.
    keys_by_index: AtomicRw<DbtVec<K>>,
    persist_count: usize,
}

impl<K, V> Debug for DbtMapPrivate<K, V>
where
    K: Debug,
    V: Debug,
{
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("DbtMapPrivate")
            .field("name", &self.name)
            .field("key_prefix", &self.prefix_map_key)
            .field("cache", &self.cache)
            .finish()
    }
}

impl<K, V> DbtMapPrivate<K, V>
where
    K: Clone + Debug + Serialize + DeserializeOwned + Eq + Hash + Send + Sync,
    V: Clone + Serialize + DeserializeOwned,
{
    pub(super) async fn new(
        pending_writes: AtomicRw<PendingWrites>,
        reader: Arc<SimpleRustyReader>,
        key_prefixes: [u8; 2],
        name: &str,
    ) -> Self {
        let cache = HashMap::new();
        let [prefix_map_keys, prefix_keys_by_index] = key_prefixes;
        let keys_name = format!("{name}_keys_by_index");
        let keys_by_index = AtomicRw::from(
            DbtVec::new(
                pending_writes.clone(),
                reader.clone(),
                prefix_keys_by_index,
                &keys_name,
            )
            .await,
        );

        let persist_count = pending_writes.lock_guard().await.persist_count;

        Self {
            name: name.into(),
            reader,
            prefix_map_key: prefix_map_keys,
            cache,
            pending_writes,
            keys_by_index,
            persist_count,
        }
    }

    fn process_persist_count(&mut self, pending_writes_persist_count: usize) {
        if pending_writes_persist_count > self.persist_count {
            self.cache.clear();
        }
        self.persist_count = pending_writes_persist_count;
    }

    /// Return the RustyKey associated with a specific key into the map. The
    /// RustyKey where the value is stored.
    #[inline]
    fn map_key_rusty_key(&self, key: &K) -> RustyKey {
        let prefix = vec![self.prefix_map_key];
        let sub_key = RustyKey::from_any(key);

        RustyKey([prefix, sub_key.0].concat())
    }

    #[inline]
    pub(super) async fn contains_key(&self, key: &K) -> bool {
        // First check cache.
        if self.cache.contains_key(key) {
            return true;
        }

        // Then check persisted storage
        let rkey = self.map_key_rusty_key(key);
        self.reader.get(rkey).await.is_some()
    }

    /// Returns the value and the key index referenced by the key.
    #[inline]
    async fn inner_get(&self, key: &K) -> Option<(V, Index)> {
        // First check cache
        if let Some(v) = self.cache.get(key) {
            return Some(v.to_owned());
        }

        // Then check persisted storage
        let rkey = self.map_key_rusty_key(key);
        self.reader.get(rkey).await.map(|val| val.into_any())
    }

    /// Returns the value referenced by the key.
    pub(super) async fn get(&self, key: &K) -> Option<V> {
        self.inner_get(key).await.map(|(v, _)| v)
    }

    /// Inserts a key-value pair into the map.
    ///
    /// If the map did not have this key present, [`None`] is returned.
    ///
    /// If the map did have this key present, the value is updated, and the old
    /// value is returned.
    pub(super) async fn insert(&mut self, key: K, value: V) -> Option<V> {
        let previous_val = self.inner_get(&key).await.map(|x| x.to_owned());

        // Add key to key list iff key is new
        let key_index = match previous_val {
            Some((_, key_index)) => key_index,
            None => {
                // Hold lock to ensure consistent length reading/index pair
                let mut keys_by_index = self.keys_by_index.lock_guard_mut().await;
                let key_index = keys_by_index.len().await;
                keys_by_index.push(key.clone()).await;
                key_index
            }
        };

        // Add to write list
        let key_as_rusty_key = self.map_key_rusty_key(&key);
        let persist_count = {
            let mut pending_writes = self.pending_writes.lock_guard_mut().await;

            pending_writes.write_ops.push(WriteOperation::Write(
                key_as_rusty_key,
                RustyValue::from_any(&(value.clone(), key_index)),
            ));
            pending_writes.persist_count
        };
        self.process_persist_count(persist_count);

        // Update cache
        let prev_cache_value = self.cache.insert(key, (value, key_index));
        if let Some((_, prev_key_index)) = prev_cache_value {
            debug_assert_eq!(prev_key_index, key_index, "Key index cannot change");
        }

        previous_val.map(|(v, _)| v)
    }

    #[inline]
    pub(super) async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Get collection length, the number of entries in the map.
    #[inline]
    pub(super) async fn len(&self) -> u64 {
        self.keys_by_index.lock_guard().await.len().await
    }

    /// Return all keys in the mapping, ordered by insertion order.
    ///
    /// ### Warning: This function puts all keys into memory, so the caller
    /// should ensure that this does not take up excessive space.
    pub(super) async fn all_keys(&self) -> Vec<K> {
        self.keys_by_index.lock_guard().await.get_all().await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use futures::FutureExt;
    use itertools::Itertools;

    use super::*;

    impl<K, V> DbtMapPrivate<K, V>
    where
        K: Clone + Debug + Serialize + DeserializeOwned + Eq + Hash + Send + Sync,
        V: Clone + Serialize + DeserializeOwned,
    {
        /// Delete all entries in the mapping.
        ///
        /// # Warning
        ///
        /// Do not pull this function out from under the test flag before you make sure that the
        /// cache is handled correctly.
        pub(in super::super) async fn clear_test(&mut self) {
            let all_keys = self.all_keys().await;
            self.keys_by_index
                .lock_mut_async(|lock| async { lock.clear().await }.boxed())
                .await;

            let all_keys = all_keys
                .into_iter()
                .map(|k| self.map_key_rusty_key(&k))
                .collect_vec();

            let persist_count = {
                let mut pending_writes = self.pending_writes.lock_guard_mut().await;
                for key in all_keys {
                    pending_writes.write_ops.push(WriteOperation::Delete(key));
                }

                pending_writes.persist_count
            };

            self.process_persist_count(persist_count);

            // Is this the correct way of handling cache?
            self.cache.clear();
        }
    }
}
