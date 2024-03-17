use super::super::level_db::DB;
use super::rusty_leveldb_vec_private::RustyLevelDbVecPrivate;
use super::{traits::*, Index};
use crate::sync::{AtomicRw, AtomicRwReadGuard, AtomicRwWriteGuard};
use leveldb::batch::WriteBatch;
use serde::{de::DeserializeOwned, Serialize};

/// A concurrency safe database-backed Vec with in memory read/write caching for all operations.
#[derive(Debug, Clone)]
pub struct RustyLevelDbVec<T: Serialize + DeserializeOwned> {
    inner: AtomicRw<RustyLevelDbVecPrivate<T>>,
}

impl<T: Serialize + DeserializeOwned + Clone> StorageVec<T> for RustyLevelDbVec<T> {
    #[inline]
    fn is_empty(&self) -> bool {
        self.read_lock().is_empty()
    }

    #[inline]
    fn len(&self) -> Index {
        self.read_lock().len()
    }

    #[inline]
    fn get(&self, index: Index) -> T {
        self.read_lock().get(index)
    }

    fn many_iter<'a>(
        &'a self,
        indices: impl IntoIterator<Item = Index> + 'a,
    ) -> Box<dyn Iterator<Item = (Index, T)> + '_> {
        // note: this lock is moved into the iterator closure and is not
        //       released until caller drops the returned iterator
        let inner = self.read_lock();

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
                (i, inner.get_u8(&key))
            }
        }))
    }

    fn many_iter_values<'a>(
        &'a self,
        indices: impl IntoIterator<Item = Index> + 'a,
    ) -> Box<dyn Iterator<Item = T> + '_> {
        // note: this lock is moved into the iterator closure and is not
        //       released until caller drops the returned iterator
        let inner = self.read_lock();

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
                inner.get_u8(&key)
            }
        }))
    }

    #[inline]
    fn get_many(&self, indices: &[Index]) -> Vec<T> {
        self.read_lock().get_many(indices)
    }

    /// Return all stored elements in a vector, whose index matches the StorageVec's.
    /// It's the caller's responsibility that there is enough memory to store all elements.
    #[inline]
    fn get_all(&self) -> Vec<T> {
        self.read_lock().get_all()
    }

    #[inline]
    fn set(&mut self, index: Index, value: T) {
        self.write_lock().set(index, value)
    }

    /// set multiple elements.
    ///
    /// panics if key_vals contains an index not in the collection
    ///
    /// It is the caller's responsibility to ensure that index values are
    /// unique.  If not, the last value with the same index will win.
    /// For unordered collections such as HashMap, the behavior is undefined.
    #[inline]
    fn set_many(&mut self, key_vals: impl IntoIterator<Item = (Index, T)>) {
        self.write_lock().set_many(key_vals)
    }

    #[inline]
    fn pop(&mut self) -> Option<T> {
        self.write_lock().pop()
    }

    #[inline]
    fn push(&mut self, value: T) {
        self.write_lock().push(value)
    }

    #[inline]
    fn clear(&mut self) {
        self.write_lock().clear();
    }
}

impl<T: Serialize + DeserializeOwned> RustyLevelDbVec<T> {
    #[inline]
    pub(crate) fn write_lock(&mut self) -> AtomicRwWriteGuard<'_, RustyLevelDbVecPrivate<T>> {
        self.inner.lock_guard_mut()
    }

    #[inline]
    pub(crate) fn read_lock(&self) -> AtomicRwReadGuard<'_, RustyLevelDbVecPrivate<T>> {
        self.inner.lock_guard()
    }
}

impl<T: Serialize + DeserializeOwned> StorageVecRwLock<T> for RustyLevelDbVec<T> {
    type LockedData = RustyLevelDbVecPrivate<T>;

    #[inline]
    fn try_write_lock(&mut self) -> Option<AtomicRwWriteGuard<'_, Self::LockedData>> {
        Some(self.write_lock())
    }

    #[inline]
    fn try_read_lock(&self) -> Option<AtomicRwReadGuard<'_, Self::LockedData>> {
        Some(self.read_lock())
    }
}

impl<T: Serialize + DeserializeOwned + Clone> RustyLevelDbVec<T> {
    // Return the key used to store the length of the persisted vector
    #[inline]
    pub fn get_length_key(key_prefix: u8) -> [u8; 2] {
        RustyLevelDbVecPrivate::<T>::get_length_key(key_prefix)
    }

    /// Return the length at the last write to disk
    #[inline]
    pub fn persisted_length(&self) -> Index {
        self.read_lock().persisted_length()
    }

    /// Return the level-DB key used to store the element at an index
    #[inline]
    pub fn get_index_key(&self, index: Index) -> [u8; 9] {
        self.read_lock().get_index_key(index)
    }

    #[inline]
    pub fn new(db: DB, key_prefix: u8, name: &str) -> Self {
        Self {
            inner: AtomicRw::from(RustyLevelDbVecPrivate::<T>::new(db, key_prefix, name)),
        }
    }

    /// Collect all added elements that have not yet bit persisted
    #[inline]
    pub fn pull_queue(&mut self, write_batch: &WriteBatch) {
        self.write_lock().pull_queue(write_batch)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::get_test_db;
    use super::super::traits::tests as traits_tests;
    use super::*;

    mod concurrency {
        use super::*;

        fn gen_concurrency_test_vec() -> RustyLevelDbVec<u64> {
            let db = get_test_db(true);
            RustyLevelDbVec::new(db, 0, "test-vec")
        }

        #[test]
        #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: Any { .. }")]
        fn non_atomic_set_and_get() {
            traits_tests::concurrency::non_atomic_set_and_get(&mut gen_concurrency_test_vec());
        }

        #[test]
        #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: Any { .. }")]
        fn non_atomic_set_and_get_wrapped_atomic_rw() {
            traits_tests::concurrency::non_atomic_set_and_get_wrapped_atomic_rw(
                &mut gen_concurrency_test_vec(),
            );
        }

        #[test]
        fn atomic_set_and_get_wrapped_atomic_rw() {
            traits_tests::concurrency::atomic_set_and_get_wrapped_atomic_rw(
                &mut gen_concurrency_test_vec(),
            );
        }

        #[test]
        fn atomic_setmany_and_getmany() {
            traits_tests::concurrency::atomic_setmany_and_getmany(&mut gen_concurrency_test_vec());
        }

        #[test]
        fn atomic_setall_and_getall() {
            traits_tests::concurrency::atomic_setall_and_getall(&mut gen_concurrency_test_vec());
        }

        #[test]
        fn atomic_iter_mut_and_iter() {
            traits_tests::concurrency::atomic_iter_mut_and_iter(&mut gen_concurrency_test_vec());
        }
    }
}
