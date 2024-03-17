use super::super::storage_vec::traits::*;
use super::super::storage_vec::Index;
use super::dbtvec_private::DbtVecPrivate;
use super::{traits::*, RustyValue, VecWriteOperation, WriteOperation};
use crate::sync::{AtomicRw, AtomicRwReadGuard, AtomicRwWriteGuard, LockCallbackFn};
use serde::{de::DeserializeOwned, Serialize};
use std::{fmt::Debug, sync::Arc};

/// A DB-backed Vec for use with DBSchema
///
/// This type is concurrency-safe.  A single RwLock is employed
/// for all read and write ops.  Callers do not need to perform
/// any additional locking.
///
/// Also because the locking is fully encapsulated within DbtVec
/// there is no possibility of a caller holding a lock too long
/// by accident or encountering ordering deadlock issues.
///
/// `DbtVec` is a NewType around Arc<RwLock<..>>.  Thus it
/// can be cheaply cloned to create a reference as if it were an
/// Arc.
#[derive(Debug)]
pub struct DbtVec<V> {
    inner: AtomicRw<DbtVecPrivate<V>>,
}

impl<V> Clone for DbtVec<V> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<V> DbtVec<V>
where
    V: Clone,
{
    // DbtVec cannot be instantiated directly outside of this crate.
    #[inline]
    pub(crate) fn new(
        reader: Arc<dyn StorageReader + Send + Sync>,
        key_prefix: u8,
        name: &str,
        lock_name: String,
        lock_callback_fn: Option<LockCallbackFn>,
    ) -> Self {
        let vec = DbtVecPrivate::<V>::new(reader, key_prefix, name);

        Self {
            inner: AtomicRw::from((vec, Some(lock_name), lock_callback_fn)),
        }
    }
}

impl<T> DbtVec<T> {
    #[inline]
    pub(crate) fn write_lock(&mut self) -> AtomicRwWriteGuard<'_, DbtVecPrivate<T>> {
        self.inner.lock_guard_mut()
    }

    #[inline]
    pub(crate) fn read_lock(&self) -> AtomicRwReadGuard<'_, DbtVecPrivate<T>> {
        self.inner.lock_guard()
    }
}

impl<T> StorageVecRwLock<T> for DbtVec<T> {
    type LockedData = DbtVecPrivate<T>;

    #[inline]
    fn try_write_lock(&mut self) -> Option<AtomicRwWriteGuard<'_, Self::LockedData>> {
        Some(self.write_lock())
    }

    #[inline]
    fn try_read_lock(&self) -> Option<AtomicRwReadGuard<'_, Self::LockedData>> {
        Some(self.read_lock())
    }
}

impl<V> StorageVec<V> for DbtVec<V>
where
    V: Clone + Debug,
    V: DeserializeOwned,
{
    #[inline]
    fn is_empty(&self) -> bool {
        self.inner.lock(|inner| inner.is_empty())
    }

    #[inline]
    fn len(&self) -> Index {
        self.inner.lock(|inner| inner.len())
    }

    #[inline]
    fn get(&self, index: Index) -> V {
        self.inner.lock(|inner| inner.get(index))
    }

    #[inline]
    fn many_iter<'a>(
        &'a self,
        indices: impl IntoIterator<Item = Index> + 'a,
    ) -> Box<dyn Iterator<Item = (Index, V)> + '_> {
        let inner = self.inner.lock_guard();
        Box::new(indices.into_iter().map(move |i| {
            assert!(
                i < inner.len(),
                "Out-of-bounds. Got index {} but length was {}. persisted vector name: {}",
                i,
                inner.len(),
                inner.name
            );

            if inner.cache.contains_key(&i) {
                (i, inner.cache[&i].clone())
            } else {
                let key = inner.get_index_key(i);
                let db_element = inner.reader.get(key).unwrap();
                (i, db_element.into_any())
            }
        }))
    }

    #[inline]
    fn many_iter_values<'a>(
        &'a self,
        indices: impl IntoIterator<Item = Index> + 'a,
    ) -> Box<dyn Iterator<Item = V> + '_> {
        let inner = self.inner.lock_guard();
        Box::new(indices.into_iter().map(move |i| {
            assert!(
                i < inner.len(),
                "Out-of-bounds. Got index {} but length was {}. persisted vector name: {}",
                i,
                inner.len(),
                inner.name
            );

            if inner.cache.contains_key(&i) {
                inner.cache[&i].clone()
            } else {
                let key = inner.get_index_key(i);
                let db_element = inner.reader.get(key).unwrap();
                db_element.into_any()
            }
        }))
    }

    #[inline]
    fn get_many(&self, indices: &[Index]) -> Vec<V> {
        self.inner.lock(|inner| inner.get_many(indices))
    }

    #[inline]
    fn get_all(&self) -> Vec<V> {
        self.inner.lock(|inner| inner.get_all())
    }

    #[inline]
    fn set(&mut self, index: Index, value: V) {
        self.inner.lock_mut(|inner| inner.set(index, value));
    }

    #[inline]
    fn set_many(&mut self, key_vals: impl IntoIterator<Item = (Index, V)>) {
        self.inner.lock_mut(|inner| inner.set_many(key_vals));
    }

    #[inline]
    fn pop(&mut self) -> Option<V> {
        self.inner.lock_mut(|inner| inner.pop())
    }

    #[inline]
    fn push(&mut self, value: V) {
        self.inner.lock_mut(|inner| inner.push(value));
    }

    #[inline]
    fn clear(&mut self) {
        self.inner.lock_mut(|inner| inner.clear());
    }
}

impl<V> DbTable for DbtVec<V>
where
    V: Clone,
    V: Serialize + DeserializeOwned,
{
    /// Collect all added elements that have not yet been persisted
    ///
    /// note: this clears the internal cache.  Thus the cache does
    /// not grow unbounded, so long as `pull_queue()` is called
    /// regularly.  It also means the cache must be rebuilt after
    /// each call (batch write)
    fn pull_queue(&mut self) -> Vec<WriteOperation> {
        self.inner.lock_mut(|inner| {
            let maybe_original_length = inner.persisted_length();
            // necessary because we need maybe_original_length.is_none() later
            let original_length = maybe_original_length.unwrap_or(0);
            let mut length = original_length;
            let mut queue = vec![];
            while let Some(write_element) = inner.write_queue.pop_front() {
                match write_element {
                    VecWriteOperation::OverWrite((i, t)) => {
                        let key = inner.get_index_key(i);
                        queue.push(WriteOperation::Write(key, RustyValue::from_any(&t)));
                    }
                    VecWriteOperation::Push(t) => {
                        let key = inner.get_index_key(length);
                        length += 1;
                        queue.push(WriteOperation::Write(key, RustyValue::from_any(&t)));
                    }
                    VecWriteOperation::Pop => {
                        let key = inner.get_index_key(length - 1);
                        length -= 1;
                        queue.push(WriteOperation::Delete(key));
                    }
                };
            }

            if original_length != length || maybe_original_length.is_none() {
                let key = DbtVecPrivate::<V>::get_length_key(inner.key_prefix);
                queue.push(WriteOperation::Write(key, RustyValue::from_any(&length)));
            }

            inner.cache.clear();

            queue
        })
    }

    #[inline]
    fn restore_or_new(&mut self) {
        self.inner.lock_mut(|inner| {
            if let Some(length) = inner
                .reader
                .get(DbtVecPrivate::<V>::get_length_key(inner.key_prefix))
            {
                inner.current_length = Some(length.into_any());
            } else {
                inner.current_length = Some(0);
            }
            inner.cache.clear();
            inner.write_queue.clear();
        });
    }
}
