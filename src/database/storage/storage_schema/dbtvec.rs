// use super::super::storage_vec::traits::*;
use super::super::storage_vec::{traits::*, Index};
use super::dbtvec_private::DbtVecPrivate;
use super::{traits::*, PendingWrites, SimpleRustyReader};
use crate::locks::tokio::AtomicRw;
use serde::{de::DeserializeOwned, Serialize};
use std::{fmt::Debug, sync::Arc};

use async_stream::stream;
use futures::Stream;

/// A NeptuneLevelDb-backed Vec for use with NeptuneLevelDbSchema
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
    inner: DbtVecPrivate<V>,
}

// impl<V> Clone for DbtVec<V> {
//     fn clone(&self) -> Self {
//         Self {
//             inner: self.inner.clone(),
//         }
//     }
// }

impl<V> DbtVec<V>
where
    V: Clone + Serialize,
{
    // DbtVec cannot be instantiated directly outside of storage_schema module
    // use [Schema::new_vec()]
    #[inline]
    pub(super) async fn new(
        pending_writes: AtomicRw<PendingWrites>,
        reader: Arc<SimpleRustyReader>,
        key_prefix: u8,
        name: &str,
    ) -> Self {
        let vec = DbtVecPrivate::<V>::new(pending_writes, reader, key_prefix, name).await;

        Self { inner: vec }
    }
}

// impl<T> DbtVec<T> {
//     #[inline]
//     pub(crate) async fn write_lock(&mut self) -> AtomicRwWriteGuard<'_, DbtVecPrivate<T>> {
//         self.inner.lock_guard_mut().await
//     }

//     #[inline]
//     pub(crate) async fn read_lock(&self) -> AtomicRwReadGuard<'_, DbtVecPrivate<T>> {
//         self.inner.lock_guard().await
//     }
// }

// #[async_trait::async_trait]
// impl<T: Send + Sync> StorageVecRwLock<T> for DbtVec<T> {
//     type LockedData = DbtVecPrivate<T>;

//     #[inline]
//     async fn try_write_lock(&mut self) -> Option<AtomicRwWriteGuard<'_, Self::LockedData>> {
//         Some(self.write_lock().await)
//     }

//     #[inline]
//     async fn try_read_lock(&self) -> Option<AtomicRwReadGuard<'_, Self::LockedData>> {
//         Some(self.read_lock().await)
//     }
// }

#[async_trait::async_trait]
impl<V> StorageVecBase<V> for DbtVec<V>
// impl<V> DbtVec<V>
where
    V: Clone + Debug,
    V: Serialize + DeserializeOwned + Send + Sync,
{
    /// todo: doc
    #[inline]
    async fn is_empty(&self) -> bool {
        self.inner.is_empty().await
    }

    /// todo: doc
    #[inline]
    async fn len(&self) -> Index {
        self.inner.len().await
    }

    /// todo: doc
    #[inline]
    async fn get(&self, index: Index) -> V {
        self.inner.get(index).await
    }

    // #[inline]
    // async fn many_iter<'a>(
    //     &'a self,
    //     indices: impl IntoIterator<Item = Index> + 'a,
    // ) -> Box<dyn Iterator<Item = (Index, V)> + '_> {
    //     let inner = self.inner.lock_guard().await;
    //     Box::new(
    //         futures::future::join_all(
    //             indices.into_iter().map(move |i| async {
    //             assert!(
    //                 i < inner.len(),
    //                 "Out-of-bounds. Got index {} but length was {}. persisted vector name: {}",
    //                 i,
    //                 inner.len(),
    //                 inner.name
    //             );

    //             // if inner.cache.contains_key(&i) {
    //             //     (i, inner.cache[&i].clone())
    //             // } else {
    //                 let key = inner.get_index_key(i);
    //                 let db_element = inner.reader.get(key).await.unwrap();
    //                 (i, db_element.into_any())
    //             // }
    //         })).await.into_iter()
    //     )
    // }

    // #[inline]
    // async fn many_iter_values<'a>(
    //     &'a self,
    //     indices: impl IntoIterator<Item = Index> + 'a,
    // ) -> Box<dyn Iterator<Item = V> + '_> {
    //     let inner = self.inner.lock_guard().await;
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
    //             let db_element = inner.reader.get(key).unwrap();
    //             db_element.into_any()
    //         }
    //     }))
    // }

    /// todo: doc
    #[inline]
    async fn get_many(&self, indices: &[Index]) -> Vec<V> {
        self.inner.get_many(indices).await
    }

    /// todo: doc
    #[inline]
    async fn get_all(&self) -> Vec<V> {
        self.inner.get_all().await
    }

    /// todo: doc
    #[inline]
    async fn set(&mut self, index: Index, value: V) {
        self.inner.set(index, value).await;
    }

    /// todo: doc
    #[inline]
    async fn set_many(&mut self, key_vals: impl IntoIterator<Item = (Index, V)> + Send) {
        self.inner
            .set_many(key_vals.into_iter().collect::<Vec<_>>())
            .await;
    }

    /// todo: doc
    #[inline]
    async fn pop(&mut self) -> Option<V> {
        self.inner.pop().await
    }

    /// todo: doc
    #[inline]
    async fn push(&mut self, value: V) {
        self.inner.push(value).await;
    }

    /// todo: doc
    #[inline]
    async fn clear(&mut self) {
        self.inner.clear().await;
    }
}

#[async_trait::async_trait]
impl<V> DbTable for DbtVec<V>
where
    V: Clone,
    V: Serialize + DeserializeOwned + Send + Sync,
{
    /// Collect all added elements that have not yet been persisted
    ///
    /// note: this clears the internal cache.  Thus the cache does
    /// not grow unbounded, so long as `pull_queue()` is called
    /// regularly.  It also means the cache must be rebuilt after
    /// each call (batch write)
    // async fn pull_queue(&mut self) -> Vec<WriteOperation> {
    //     let mut inner = self.inner.lock_guard_mut().await;

    //     let maybe_original_length = inner.persisted_length();
    //     // necessary because we need maybe_original_length.is_none() later
    //     let original_length = maybe_original_length.unwrap_or(0);
    //     let mut length = original_length;
    //     let mut queue = vec![];
    //     while let Some(write_element) = inner.write_queue.pop_front() {
    //         match write_element {
    //             VecWriteOperation::OverWrite((i, t)) => {
    //                 let key = inner.get_index_key(i);
    //                 queue.push(WriteOperation::Write(key, RustyValue::from_any(&t)));
    //             }
    //             VecWriteOperation::Push(t) => {
    //                 let key = inner.get_index_key(length);
    //                 length += 1;
    //                 queue.push(WriteOperation::Write(key, RustyValue::from_any(&t)));
    //             }
    //             VecWriteOperation::Pop => {
    //                 let key = inner.get_index_key(length - 1);
    //                 length -= 1;
    //                 queue.push(WriteOperation::Delete(key));
    //             }
    //         };
    //     }

    //     if original_length != length || maybe_original_length.is_none() {
    //         let key = DbtVecPrivate::<V>::get_length_key(inner.key_prefix);
    //         queue.push(WriteOperation::Write(key, RustyValue::from_any(&length)));
    //     }

    //     inner.cache.clear();

    //     queue
    // }

    #[inline]
    async fn restore_or_new(&mut self) {
        // let mut inner = self.inner.lock_guard_mut().await;

        if let Some(length) = self
            .inner
            .reader
            .get(DbtVecPrivate::<V>::get_length_key(self.inner.key_prefix))
            .await
        {
            self.inner.current_length = Some(length.into_any());
        } else {
            self.inner.current_length = Some(0);
        }
        // inner.cache.clear();
        // inner.write_queue.clear();
    }
}

/// Async Streams (ie async iterators)
// impl<T: Debug + Serialize + DeserializeOwned + Clone + Send + Sync + 'static> DbtVec<T> {
impl<T: Debug + Serialize + DeserializeOwned + Clone + Send + Sync + 'static> StorageVecStream<T> for DbtVec<T> {

    /// todo: doc
    async fn stream<'a>(&'a self) -> impl Stream<Item = (Index, T)> + 'a
    where
        T: 'a,
    {
        self.stream_many(0..self.len().await).await
    }

    /// todo: doc
    async fn stream_values<'a>(&'a self) -> impl Stream<Item = T> + 'a
    where
        T: 'a,
    {
        self.stream_many_values(0..self.len().await).await
    }

    /// we override trait default impl to provide a locked stream
    /// that provides consistent reads until the stream is dropped.
    ///
    /// note: if this behavior is not desired, use the default impl instead.
    async fn stream_many<'a>(
        &'a self,
        indices: impl IntoIterator<Item = Index> + 'a,
    ) -> impl Stream<Item = (Index, T)> + 'a {
        // note: this lock is not released until caller drops
        // the returned iterator
        // let inner = self.read_lock().await;

        stream! {
            for i in indices.into_iter() {
                yield (i, self.inner.get(i).await)
            }
        }
    }

    /// we override trait default impl to provide a locked stream
    /// that provides consistent reads until the stream is dropped.
    ///
    /// note: if this behavior is not desired, use the default impl instead.
    async fn stream_many_values<'a>(
        &'a self,
        indices: impl IntoIterator<Item = Index> + 'a,
    ) -> impl Stream<Item = T> + 'a {
        // note: this lock is not released until caller drops
        // the returned iterator
        // let inner = self.read_lock().await;

        stream! {
            for i in indices.into_iter() {
                yield self.inner.get(i).await
            }
        }
    }
}

impl<T: Debug + Serialize + DeserializeOwned + Clone + Send + Sync + 'static> StorageVec<T> for DbtVec<T> {}