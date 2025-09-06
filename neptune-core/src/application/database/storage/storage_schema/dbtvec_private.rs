use std::collections::HashMap;
use std::fmt::Debug;
use std::fmt::Formatter;
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
use crate::application::locks::tokio::AtomicRw;

pub(super) struct DbtVecPrivate<V> {
    pub(super) pending_writes: AtomicRw<PendingWrites>,
    pub(super) reader: Arc<SimpleRustyReader>,
    pub(super) current_length: Option<Index>,
    pub(super) key_prefix: u8,
    pub(super) cache: HashMap<Index, V>,
    persist_count: usize,
    pub(super) name: String,
    phantom: std::marker::PhantomData<V>,
}

impl<V> Debug for DbtVecPrivate<V>
where
    V: Debug,
{
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("DbtVecPrivate")
            .field("reader", &"Arc<SimpleRustyReader + Send + Sync>")
            .field("current_length", &self.current_length)
            .field("key_prefix", &self.key_prefix)
            .field("cache", &self.cache)
            .field("name", &self.name)
            .finish()
    }
}

impl<V: Clone + Serialize + DeserializeOwned> DbtVecPrivate<V> {
    #[inline]
    pub(super) async fn get(&self, index: Index) -> V {
        // Disallow getting values out-of-bounds

        assert!(
            index < self.len().await,
            "Out-of-bounds. Got {index} but length was {}. persisted vector name: {}",
            self.len().await,
            self.name
        );

        // try cache first
        if self.cache.contains_key(&index) {
            return self
                .cache
                .get(&index)
                .expect("there should be some value")
                .clone();
        }

        // then try persistent storage
        let key: RustyKey = self.get_index_key(index);
        let val = self.reader.get(key).await.unwrap_or_else(|| {
            panic!(
                "Element with index {index} does not exist in {}. This should not happen",
                self.name
            )
        });
        val.into_any()
    }

    #[inline]
    pub(super) async fn set(&mut self, index: Index, value: V) {
        // Disallow setting values out-of-bounds

        assert!(
            index < self.len().await,
            "Out-of-bounds. Got {index} but length was {}. persisted vector name: {}",
            self.len().await,
            self.name
        );

        self.write_op_overwrite(index, value).await;
    }
}

impl<V> DbtVecPrivate<V>
where
    V: Clone + Serialize,
{
    // Return the key used to store the length of the vector
    #[inline]
    pub(super) fn get_length_key(key_prefix: u8) -> RustyKey {
        let const_length_key: RustyKey = 0u8.into();
        let key_prefix_key: RustyKey = key_prefix.into();

        // This concatenates prefix + length (0u8) to form the
        // real Key as used in LevelDB
        (key_prefix_key, const_length_key).into()
    }

    /// Return the length at the last write to disk
    #[inline]
    pub(super) async fn persisted_length(&self) -> Option<Index> {
        self.reader
            .get(Self::get_length_key(self.key_prefix))
            .await
            .map(|v| v.into_any())
    }

    /// Return the key of K type used to store the element at a given index of Index type
    #[inline]
    pub(super) fn get_index_key(&self, index: Index) -> RustyKey {
        let key_prefix_key: RustyKey = self.key_prefix.into();
        let index_key: RustyKey = index.into();

        // This concatenates prefix + index to form the
        // real Key as used in LevelDB
        (key_prefix_key, index_key).into()
    }

    #[inline]
    pub(crate) async fn new(
        pending_writes: AtomicRw<PendingWrites>,
        reader: Arc<SimpleRustyReader>,
        key_prefix: u8,
        name: &str,
    ) -> Self {
        let length = None;
        let cache = HashMap::new();
        let persist_count = pending_writes.lock_guard().await.persist_count;

        Self {
            pending_writes,
            key_prefix,
            reader,
            current_length: length,
            cache,
            persist_count,
            name: name.to_string(),
            phantom: Default::default(),
        }
    }

    #[inline]
    async fn write_op_overwrite(&mut self, index: Index, value: V) {
        let index_key = self.get_index_key(index);

        let persist_count = {
            let mut pending_writes = self.pending_writes.lock_guard_mut().await;

            pending_writes.write_ops.push(WriteOperation::Write(
                index_key,
                RustyValue::from_any(&value),
            ));
            pending_writes.persist_count
        };
        self.process_persist_count(persist_count);

        self.cache.insert(index, value.clone());
    }

    fn process_persist_count(&mut self, pending_writes_persist_count: usize) {
        if pending_writes_persist_count > self.persist_count {
            self.cache.clear();
        }
        self.persist_count = pending_writes_persist_count;
    }
}

impl<V> DbtVecPrivate<V>
where
    V: Clone + Serialize + DeserializeOwned,
{
    #[inline]
    pub(super) async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    #[inline]
    pub(super) async fn len(&self) -> Index {
        match self.current_length {
            Some(l) => l,
            None => self.persisted_length().await.unwrap_or(0),
        }
    }

    /// Fetch multiple elements from a `DbtVec` and return the elements matching the order
    /// of the input indices.
    pub(super) async fn get_many(&self, indices: &[Index]) -> Vec<V> {
        fn sort_to_match_requested_index_order<V>(indexed_elements: HashMap<usize, V>) -> Vec<V> {
            let mut elements = indexed_elements.into_iter().collect_vec();
            elements.sort_unstable_by_key(|&(index_position, _)| index_position);
            elements.into_iter().map(|(_, element)| element).collect()
        }

        let Some(max_index) = indices.iter().max() else {
            return vec![];
        };

        assert!(
            *max_index < self.len().await,
            "Out-of-bounds. Got index {max_index} but length was {}. persisted vector name: {}",
            self.len().await,
            self.name
        );

        let (indices_of_elements_in_cache, indices_of_elements_not_in_cache): (Vec<_>, Vec<_>) =
            indices
                .iter()
                .copied()
                .enumerate()
                .partition(|&(_, index)| self.cache.contains_key(&index));

        let mut fetched_elements = HashMap::with_capacity(indices.len());
        for (index_position, index) in indices_of_elements_in_cache {
            let value = self
                .cache
                .get(&index)
                .expect("there should be some value")
                .clone();
            fetched_elements.insert(index_position, value);
        }

        let no_need_to_lock_database = indices_of_elements_not_in_cache.is_empty();
        if no_need_to_lock_database {
            return sort_to_match_requested_index_order(fetched_elements);
        }

        let keys_for_indices_not_in_cache = indices_of_elements_not_in_cache
            .iter()
            .map(|&(_, index)| self.get_index_key(index))
            .collect_vec();
        let elements_fetched_from_db = self
            .reader
            .get_many(keys_for_indices_not_in_cache)
            .await
            .into_iter()
            .map(|x| x.expect("there should be some value").into_any());

        let indexed_fetched_elements_from_db = indices_of_elements_not_in_cache
            .iter()
            .map(|&(index_position, _)| index_position)
            .zip_eq(elements_fetched_from_db);
        fetched_elements.extend(indexed_fetched_elements_from_db);

        sort_to_match_requested_index_order(fetched_elements)
    }

    /// Return all stored elements in a vector, whose index matches the StorageVec's.
    /// It's the caller's responsibility that there is enough memory to store all elements.
    pub(super) async fn get_all(&self) -> Vec<V> {
        let (indices_of_elements_in_cache, indices_of_elements_not_in_cache): (Vec<_>, Vec<_>) =
            (0..self.len().await).partition(|index| self.cache.contains_key(index));

        let mut fetched_elements: Vec<Option<V>> = vec![None; self.len().await as usize];
        for index in indices_of_elements_in_cache {
            let element = self.cache[&index].clone();
            fetched_elements[index as usize] = Some(element);
        }

        let no_need_to_lock_database = indices_of_elements_not_in_cache.is_empty();
        if no_need_to_lock_database {
            return fetched_elements
                .into_iter()
                .map(|x| x.expect("there should be some value"))
                .collect_vec();
        }

        let keys = indices_of_elements_not_in_cache
            .iter()
            .map(|x| self.get_index_key(*x))
            .collect_vec();
        let elements_fetched_from_db = self
            .reader
            .get_many(keys)
            .await
            .into_iter()
            .map(|x| x.expect("there should be some value").into_any());
        let indexed_fetched_elements_from_db = indices_of_elements_not_in_cache
            .into_iter()
            .zip_eq(elements_fetched_from_db);
        for (index, element) in indexed_fetched_elements_from_db {
            fetched_elements[index as usize] = Some(element);
        }

        fetched_elements
            .into_iter()
            .map(|x| x.expect("there should be some value"))
            .collect_vec()
    }

    /// set multiple elements.
    ///
    /// panics if key_vals contains an index not in the collection
    ///
    /// It is the caller's responsibility to ensure that index values are
    /// unique.  If not, the last value with the same index will win.
    /// For unordered collections such as HashMap, the behavior is undefined.
    pub(super) async fn set_many(&mut self, key_vals: impl IntoIterator<Item = (Index, V)> + Send) {
        let self_len = self.len().await;

        for (index, value) in key_vals {
            assert!(
                index < self_len,
                "Out-of-bounds. Got {index} but length was {}. persisted vector name: {}",
                self_len,
                self.name
            );

            self.write_op_overwrite(index, value).await;
        }
    }

    /// Delete the non-persisted values, without persisting to disk.
    pub(super) async fn delete_cache(&mut self) {
        self.cache.clear();
        self.current_length = self.persisted_length().await;
    }

    #[inline]
    pub(super) async fn pop(&mut self) -> Option<V> {
        // If vector is empty, return None
        if self.is_empty().await {
            return None;
        }

        // Update length
        let current_length = self
            .current_length
            .as_mut()
            .expect("there should be some value");

        *current_length -= 1;

        let new_length = *current_length;
        let index_key = self.get_index_key(new_length);

        let persist_count = {
            let mut pending_writes = self.pending_writes.lock_guard_mut().await;

            pending_writes
                .write_ops
                .push(WriteOperation::Delete(index_key));
            pending_writes.write_ops.push(WriteOperation::Write(
                Self::get_length_key(self.key_prefix),
                RustyValue::from_any(&new_length),
            ));
            pending_writes.persist_count
        };

        self.process_persist_count(persist_count);

        // try cache first
        if self.cache.contains_key(&new_length) {
            self.cache.remove(&new_length)
        } else {
            // then try persistent storage
            let key = self.get_index_key(new_length);
            self.reader.get(key).await.map(|value| value.into_any())
        }
    }

    #[inline]
    pub(super) async fn push(&mut self, value: V) {
        // record in cache
        let current_length = self.len().await;
        let new_length = current_length + 1;
        let index_key = self.get_index_key(current_length);

        let persist_count = {
            let mut pending_writes = self.pending_writes.lock_guard_mut().await;

            pending_writes.write_ops.push(WriteOperation::Write(
                index_key,
                RustyValue::from_any(&value),
            ));
            pending_writes.write_ops.push(WriteOperation::Write(
                Self::get_length_key(self.key_prefix),
                RustyValue::from_any(&new_length),
            ));
            pending_writes.persist_count
        };
        self.process_persist_count(persist_count);

        let _old_val = self.cache.insert(current_length, value.clone());

        // update length
        self.current_length = Some(new_length);
    }

    #[inline]
    pub(super) async fn clear(&mut self) {
        while !self.is_empty().await {
            self.pop().await;
        }
    }
}
