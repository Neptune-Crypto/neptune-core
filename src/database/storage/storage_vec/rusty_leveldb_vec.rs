use super::super::super::neptune_leveldb::NeptuneLevelDb;
use super::rusty_leveldb_vec_private::RustyLevelDbVecPrivate;
use super::{traits::*, Index};
// use crate::locks::tokio::{AtomicRw, AtomicRwReadGuard, AtomicRwWriteGuard};
use leveldb::batch::WriteBatch;
use serde::{de::DeserializeOwned, Serialize};

// for Stream (async Iterator equiv)
// use async_stream::stream;
// use futures::stream::Stream;

/// A concurrency safe database-backed Vec with in memory read/write caching for all operations.
#[derive(Debug, Clone)]
pub struct RustyLevelDbVec<T: Serialize + DeserializeOwned> {
    inner: RustyLevelDbVecPrivate<T>,
}

#[async_trait::async_trait]
impl<T: Serialize + DeserializeOwned + Clone + Send + Sync + 'static> StorageVec<T> for RustyLevelDbVec<T> {
    #[inline]
    async fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[inline]
    async fn len(&self) -> Index {
        self.inner.len()
    }

    #[inline]
    async fn get(&self, index: Index) -> T {
        self.inner.get(index).await
    }

    // fn many_iter<'a>(
    //     &'a self,
    //     indices: impl IntoIterator<Item = Index> + 'a,
    // ) -> Box<dyn Iterator<Item = (Index, T)> + '_> {
    //     // note: this lock is moved into the iterator closure and is not
    //     //       released until caller drops the returned iterator
    //     let inner = self.read_lock();

    //     Box::new(indices.into_iter().map(move |i| {
    //         assert!(
    //             i < inner.len(),
    //             "Out-of-bounds. Got index {} but length was {}. persisted vector name: {}",
    //             i,
    //             inner.len(),
    //             inner.name
    //         );

    //         if inner.cache.contains_key(&i) {
    //             (i, inner.cache[&i].clone())
    //         } else {
    //             let key = inner.get_index_key(i);
    //             (i, inner.get_u8(&key))
    //         }
    //     }))
    // }

    // fn many_iter_values<'a>(
    //     &'a self,
    //     indices: impl IntoIterator<Item = Index> + 'a,
    // ) -> Box<dyn Iterator<Item = T> + '_> {
    //     // note: this lock is moved into the iterator closure and is not
    //     //       released until caller drops the returned iterator
    //     let inner = self.read_lock();

    //     Box::new(indices.into_iter().map(move |i| {
    //         assert!(
    //             i < inner.len(),
    //             "Out-of-bounds. Got index {} but length was {}. persisted vector name: {}",
    //             i,
    //             inner.len(),
    //             inner.name
    //         );

    //         if inner.cache.contains_key(&i) {
    //             inner.cache[&i].clone()
    //         } else {
    //             let key = inner.get_index_key(i);
    //             inner.get_u8(&key)
    //         }
    //     }))
    // }


    #[inline]
    async fn get_many(&self, indices: &[Index]) -> Vec<T> {
        self.inner.get_many(indices).await
    }

    /// Return all stored elements in a vector, whose index matches the StorageVec's.
    /// It's the caller's responsibility that there is enough memory to store all elements.
    #[inline]
    async fn get_all(&self) -> Vec<T> {
        self.inner.get_all().await
    }

    #[inline]
    async fn set(&mut self, index: Index, value: T) {
        self.inner.set(index, value).await
    }

    /// set multiple elements.
    ///
    /// panics if key_vals contains an index not in the collection
    ///
    /// It is the caller's responsibility to ensure that index values are
    /// unique.  If not, the last value with the same index will win.
    /// For unordered collections such as HashMap, the behavior is undefined.
    #[inline]
    async fn set_many(&mut self, key_vals: impl IntoIterator<Item = (Index, T)> + Send) {
        self.inner.set_many(key_vals.into_iter().collect::<Vec<_>>()).await
    }

    #[inline]
    async fn pop(&mut self) -> Option<T> {
        self.inner.pop().await
    }

    #[inline]
    async fn push(&mut self, value: T) {
        self.inner.push(value).await
    }

    #[inline]
    async fn clear(&mut self) {
        self.inner.clear().await;
    }
}

// impl<T: Serialize + DeserializeOwned + Clone + Send + Sync + 'static> RustyLevelDbVec<T> {

//     #[inline]
//     pub(crate) async fn write_lock(&mut self) -> AtomicRwWriteGuard<'_, RustyLevelDbVecPrivate<T>> {
//         self.inner.lock_guard_mut().await
//     }

//     #[inline]
//     pub(crate) async fn read_lock(&self) -> AtomicRwReadGuard<'_, RustyLevelDbVecPrivate<T>> {
//         self.inner.lock_guard().await
//     }
// }

// #[async_trait::async_trait]
// impl<T: Serialize + DeserializeOwned + Clone + Send + Sync + 'static> StorageVecRwLock<T> for RustyLevelDbVec<T> {
//     type LockedData = RustyLevelDbVecPrivate<T>;

//     #[inline]
//     async fn try_write_lock(&mut self) -> Option<AtomicRwWriteGuard<'_, Self::LockedData>>
//     {
//         Some(self.write_lock().await)
//     }

//     #[inline]
//     async fn try_read_lock(&self) -> Option<AtomicRwReadGuard<'_, Self::LockedData>>
//     {
//         Some(self.read_lock().await)
//     }
// }

impl<T: Serialize + DeserializeOwned + Clone + Send + Sync + 'static> RustyLevelDbVec<T> {
    // Return the key used to store the length of the persisted vector
    #[inline]
    pub fn get_length_key(key_prefix: u8) -> [u8; 2] {
        RustyLevelDbVecPrivate::<T>::get_length_key(key_prefix)
    }

    /// Return the length at the last write to disk
    #[inline]
    pub async fn persisted_length(&self) -> Index {
        self.inner.persisted_length().await
    }

    /// Return the level-NeptuneLevelDb key used to store the element at an index
    #[inline]
    pub async fn get_index_key(&self, index: Index) -> [u8; 9] {
        self.inner.get_index_key(index)
    }

    #[inline]
    pub async fn new(db: NeptuneLevelDb<Index, T>, key_prefix: u8, name: &str) -> Self {
        Self {
            inner: RustyLevelDbVecPrivate::<T>::new(db, key_prefix, name).await,
        }
    }

    /// Collect all added elements that have not yet bit persisted
    #[inline]
    pub async fn pull_queue(&mut self, write_ops: &WriteBatch) {
        self.inner.pull_queue(write_ops).await
    }
}

/// Async Streams (ie async iterators)
impl<T: Serialize + DeserializeOwned + Clone + Send + Sync + 'static> StorageVecStream<T> for RustyLevelDbVec<T> {}

#[cfg(test)]
mod tests {
    use super::super::tests::get_test_db;
    use super::super::traits::tests as traits_tests;
    use super::*;

    async fn gen_test_vec() -> RustyLevelDbVec<u64> {
        let db = get_test_db(true).await;
        RustyLevelDbVec::new(db, 0, "test-vec").await
    }

    mod streams {
        use super::*;

        #[tokio::test]
        async fn stream() {
            traits_tests::streams::stream(gen_test_vec().await).await
        }

        #[tokio::test]
        async fn stream_many() {
            traits_tests::streams::stream_many(gen_test_vec().await).await
        }
    }

    mod concurrency {
        use super::*;

        #[tokio::test(flavor = "multi_thread")]
        #[should_panic]
        async fn non_atomic_set_and_get() {
            traits_tests::concurrency::non_atomic_set_and_get(&mut gen_test_vec().await).await;
        }

        #[tokio::test(flavor = "multi_thread")]
        #[should_panic]
        async fn non_atomic_set_and_get_wrapped_atomic_rw() {
            traits_tests::concurrency::non_atomic_set_and_get_wrapped_atomic_rw(
                &mut gen_test_vec().await,
            ).await;
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn atomic_set_and_get_wrapped_atomic_rw() {
            traits_tests::concurrency::atomic_set_and_get_wrapped_atomic_rw(
                &mut gen_test_vec().await,
            ).await;
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn atomic_setmany_and_getmany() {
            traits_tests::concurrency::atomic_setmany_and_getmany(&mut gen_test_vec().await).await;
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn atomic_setall_and_getall() {
            traits_tests::concurrency::atomic_setall_and_getall(&mut gen_test_vec().await).await;
        }

        // #[tokio::test]
        // async fn atomic_iter_mut_and_iter() {
        //     traits_tests::concurrency::atomic_iter_mut_and_iter(&mut gen_test_vec());
        // }
    }
}
