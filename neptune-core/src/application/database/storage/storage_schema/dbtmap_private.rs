use std::collections::HashMap;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::hash::Hash;
use std::sync::Arc;

use futures::FutureExt;
use itertools::Itertools;
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
use crate::application::locks::tokio::AtomicRw;

pub(super) struct DbtMapPrivate<K, V> {
    pub(super) name: String,
    pub(super) reader: Arc<SimpleRustyReader>,
    pub(super) prefix_map_keys: u8,
    pub(super) cache: HashMap<K, V>,
    pub(super) pending_writes: AtomicRw<PendingWrites>,
    keys_by_index: DbtVec<Option<K>>,
}

impl<K, V> Debug for DbtMapPrivate<K, V>
where
    K: Debug,
    V: Debug,
{
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("DbtMapPrivate")
            .field("name", &self.name)
            .field("key_prefix", &self.prefix_map_keys)
            .field("cache", &self.cache)
            .finish()
    }
}

impl<K, V> DbtMapPrivate<K, V>
where
    K: Clone + Debug + Serialize + DeserializeOwned + Eq + Hash + Send + Sync,
    V: Clone + Serialize + DeserializeOwned,
{
    pub(crate) async fn new(
        pending_writes: AtomicRw<PendingWrites>,
        reader: Arc<SimpleRustyReader>,
        key_prefixes: [u8; 2],
        name: &str,
    ) -> Self {
        let cache = HashMap::new();
        let [prefix_map_keys, prefix_keys_by_index] = key_prefixes;
        let keys_name = format!("{name}_keys_by_index");
        let keys_by_index = DbtVec::new(
            pending_writes.clone(),
            reader.clone(),
            prefix_keys_by_index,
            &keys_name,
        )
        .await;

        Self {
            name: name.into(),
            reader,
            prefix_map_keys,
            cache,
            pending_writes,
            keys_by_index,
        }
    }

    /// Return the RustyKey associated with a specific key into the map. The
    /// RustyKey where the value is stored.
    #[inline]
    pub(super) fn map_key_rusty_key(&self, key: &K) -> RustyKey {
        let prefix = vec![self.prefix_map_keys];
        let sub_key = RustyKey::from_any(key);

        RustyKey([prefix, sub_key.0].concat())
    }

    #[inline]
    pub async fn contains_key(&self, key: &K) -> bool {
        // First check cache.
        if self.cache.contains_key(key) {
            return true;
        }

        // Then check persisted storage
        let rkey = self.map_key_rusty_key(key);
        self.reader.get(rkey).await.is_some()
    }

    #[inline]
    pub async fn get(&self, key: &K) -> Option<V> {
        // First check cache
        if let Some(v) = self.cache.get(key) {
            return Some(v.to_owned());
        }

        // Then check persisted storage
        let rkey = self.map_key_rusty_key(key);
        self.reader.get(rkey).await.map(|val| val.into_any())
    }

    /// Inserts a key-value pair into the map.
    ///
    /// If the map did not have this key present, [`None`] is returned.
    ///
    /// If the map did have this key present, the value is updated, and the old
    /// value is returned.
    pub async fn insert(&mut self, key: K, value: V) -> Option<V> {
        let previous_val = self.get(&key).await.map(|x| x.to_owned());

        // Update cache
        self.cache.insert(key.clone(), value.clone());

        // Add to write list
        let key_as_rusty_key = self.map_key_rusty_key(&key);
        let mut pending_writes = self.pending_writes.lock_guard_mut().await;
        pending_writes.write_ops.push(WriteOperation::Write(
            key_as_rusty_key,
            RustyValue::from_any(&value),
        ));

        // Add key to key list iff key is new
        if previous_val.is_none() {
            self.keys_by_index.push(Some(key)).await;
        }

        previous_val
    }

    /// This will remove the entry if it exists.
    pub async fn remove(&mut self, key: &K) -> Option<V> {
        // let previous_val = self.get(&key).await.map(|x| x.to_owned());

        // // Update cache (nop if not present)
        // self.cache.remove(&key);

        // let keys = self.keys_by_index.get_all();

        todo!()
        // self.cache.remo
        // no-op if key not found.
        // if !self.keys_by_index.remove(k) {
        //     return false;
        // }

        // self.write_queue.push(WriteOperation::Write(
        //     self.keylist_db_key(),
        //     RustyValue::from_any(&self.keys_by_index),
        // ));

        // self.write_cache.remove(k);

        // // add to write queue
        // self.write_queue
        //     .push(WriteOperation::Delete(self.db_key(k)));

        // true
    }

    // Return the key used to store the length of the vector
    #[inline]
    pub(super) fn keylist_db_key(&self) -> RustyKey {
        let prefix_rk: RustyKey = self.prefix_map_keys.into();
        let keylist_rk = RustyKey::from(b"_kl".as_ref());

        // This concatenates prefix + "_kl" to form the
        // real Key as used in LevelDB
        (prefix_rk, keylist_rk).into()
    }

    pub(super) fn persisted_keys(&self) -> Option<HashSet<K>> {
        self.reader.get(self.keylist_db_key()).map(|v| v.into_any())
    }

    /// Return the key of K type used to store the element at a given usize of usize type
    #[inline]
    pub(super) fn db_key(&self, k: &K) -> RustyKey {
        let prefix_rk: RustyKey = self.prefix_map_keys.into();
        let k_rk = RustyKey::from_any(&k);

        // This concatenates prefix + "_kl" to form the
        // real Key as used in LevelDB
        (prefix_rk, k_rk).into()
    }

    #[inline]
    pub(super) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub(super) async fn len(&self) -> u64 {
        self.keys_by_index.len().await
    }

    #[inline]
    pub(super) fn clear(&mut self) {
        for k in self.keys_by_index.clone().iter() {
            self.remove(k);
        }
        self.keys_by_index.clear()
    }

    pub(super) fn iter_keys(&self) -> impl Iterator<Item = &K> {
        self.keys_by_index.iter()
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = (&K, Cow<'_, V>)> {
        self.keys_by_index.iter().map(|k| (k, self.get(k).unwrap()))
    }

    pub(super) fn iter_values(&self) -> impl Iterator<Item = Cow<'_, V>> {
        self.keys_by_index.iter().map(|k| self.get(k).unwrap())
    }
}
