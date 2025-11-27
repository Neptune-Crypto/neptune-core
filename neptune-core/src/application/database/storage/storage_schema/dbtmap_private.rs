use std::collections::HashMap;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::hash::Hash;
use std::sync::Arc;

use itertools::Itertools;
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::super::storage_vec::Index;
use super::traits::StorageReader;
use super::PendingWrites;
use super::RustyKey;
use super::RustyValue;
use super::SimpleRustyReader;
use super::WriteOperation;
use crate::application::database::storage::storage_schema::DbtVec;
use crate::application::locks::tokio::AtomicRw;

const LENGTH_KEY_PREFIX: u8 = 0;
const KEYS_BY_INDEX_PREFIX: u8 = 1;
const MAP_KEY_PREFIX: u8 = 2;

pub(super) struct DbtMapPrivate<K, V> {
    pub(super) name: String,
    pub(super) reader: Arc<SimpleRustyReader>,
    pub(super) current_length: Option<Index>,
    pub(super) key_prefix: u8,
    pub(super) cache: HashMap<K, V>,
    pub(super) pending_writes: AtomicRw<PendingWrites>,
    keys: DbtVec<K>,
}

impl<K, V> Debug for DbtMapPrivate<K, V>
where
    K: Debug,
    V: Debug,
{
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("DbtMapPrivate")
            .field("name", &self.name)
            .field("key_prefix", &self.key_prefix)
            .field("cache", &self.cache)
            .finish()
    }
}

impl<K, V> DbtMapPrivate<K, V>
where
    K: Clone + Serialize + Eq + Hash,
    V: Clone + Serialize + DeserializeOwned,
{
    /// Return the RustyKey where the length of the map is stored.
    #[inline]
    pub(super) fn length_rusty_key(&self) -> RustyKey {
        RustyKey(vec![self.key_prefix, LENGTH_KEY_PREFIX])
    }

    /// Return the RustyKey for the value of a key into the map, where the key
    /// is specified by index. The RustyKey where the map's key is stored.
    #[inline]
    pub(super) fn key_by_index_rusty_key(&self, key_index: u64) -> RustyKey {
        let prefix = vec![self.key_prefix, KEYS_BY_INDEX_PREFIX];
        let sub_key = key_index.to_be_bytes().to_vec();
        RustyKey([prefix, sub_key].concat())
    }

    /// Return the RustyKey associated with a specific key into the map. The
    /// RustyKey where the value is stored.
    #[inline]
    pub(super) fn map_key_rusty_key(&self, key: &K) -> RustyKey {
        let prefix = vec![self.key_prefix, MAP_KEY_PREFIX];
        let sub_key = RustyKey::from_any(key);

        RustyKey([prefix, sub_key.0].concat())
    }

    pub(crate) fn new(
        pending_writes: AtomicRw<PendingWrites>,
        reader: Arc<SimpleRustyReader>,
        key_prefix: u8,
        name: &str,
    ) -> Self {
        let length = None;
        let cache = HashMap::new();
        Self {
            name: name.into(),
            key_prefix,
            reader,
            current_length: length,
            cache,
            pending_writes,
        }
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
    pub fn insert(&mut self, key: K, v: V) -> bool {
        let new = self.cache.insert(key, v);

        todo!()
        // let new = self.keys.insert(k.clone());
        // if new {
        //     // key list grew by 1.  Set entire key-list
        //     self.write_queue.push(WriteOperation::Write(
        //         self.keylist_db_key(),
        //         RustyValue::from_any(&self.keys),
        //     ));
        // }

        // self.write_queue.push(WriteOperation::Write(
        //     self.db_key(&k),
        //     RustyValue::from_any(&v),
        // ));

        // let _ = self.write_cache.insert(k, v);

        // new
    }

    /// This will remove the entry identified by `k` if it
    /// exists.
    pub fn remove(&mut self, k: &K) -> bool {
        // no-op if key not found.
        if !self.keys.remove(k) {
            return false;
        }

        self.write_queue.push(WriteOperation::Write(
            self.keylist_db_key(),
            RustyValue::from_any(&self.keys),
        ));

        self.write_cache.remove(k);

        // add to write queue
        self.write_queue
            .push(WriteOperation::Delete(self.db_key(k)));

        true
    }

    // Return the key used to store the length of the vector
    #[inline]
    pub(super) fn keylist_db_key(&self) -> RustyKey {
        let prefix_rk: RustyKey = self.key_prefix.into();
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
        let prefix_rk: RustyKey = self.key_prefix.into();
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
    pub(super) fn len(&self) -> usize {
        self.keys.len()
    }

    #[inline]
    pub(super) fn clear(&mut self) {
        for k in self.keys.clone().iter() {
            self.remove(k);
        }
        self.keys.clear()
    }

    pub(super) fn iter_keys(&self) -> impl Iterator<Item = &K> {
        self.keys.iter()
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = (&K, Cow<'_, V>)> {
        self.keys.iter().map(|k| (k, self.get(k).unwrap()))
    }

    pub(super) fn iter_values(&self) -> impl Iterator<Item = Cow<'_, V>> {
        self.keys.iter().map(|k| self.get(k).unwrap())
    }
}
