use std::fmt::Debug;
use std::sync::Arc;

use futures::Stream;
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::super::storage_vec::traits::*;
use super::super::storage_vec::Index;
use super::dbtvec_private::DbtVecPrivate;
use super::traits::*;
use super::PendingWrites;
use super::SimpleRustyReader;
use crate::application::locks::tokio::AtomicRw;

/// A LevelDb-backed Vec for use with DbSchema
///
/// Data stored in a DbtVec gets persisted to a levelDb database.
#[derive(Debug)]
pub struct DbtVec<V> {
    // todo: merge DbtVecPrivate into DbtVec
    inner: DbtVecPrivate<V>,
}

impl<V> DbtVec<V>
where
    V: Clone + Serialize + DeserializeOwned,
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

    #[inline]
    pub(crate) async fn delete_cache(&mut self) {
        self.inner.delete_cache().await;
    }
}

#[async_trait::async_trait]
impl<V> StorageVecBase<V> for DbtVec<V>
// impl<V> DbtVec<V>
where
    V: Clone + Debug,
    V: Serialize + DeserializeOwned + Send + Sync,
{
    #[inline]
    async fn is_empty(&self) -> bool {
        self.inner.is_empty().await
    }

    #[inline]
    async fn len(&self) -> Index {
        self.inner.len().await
    }

    #[inline]
    async fn get(&self, index: Index) -> V {
        self.inner.get(index).await
    }

    #[inline]
    async fn get_many(&self, indices: &[Index]) -> Vec<V> {
        self.inner.get_many(indices).await
    }

    #[inline]
    async fn get_all(&self) -> Vec<V> {
        self.inner.get_all().await
    }

    #[inline]
    async fn set(&mut self, index: Index, value: V) {
        self.inner.set(index, value).await;
    }

    #[inline]
    async fn set_many(&mut self, key_vals: impl IntoIterator<Item = (Index, V)> + Send) {
        self.inner
            .set_many(key_vals.into_iter().collect::<Vec<_>>())
            .await;
    }

    #[inline]
    async fn pop(&mut self) -> Option<V> {
        self.inner.pop().await
    }

    #[inline]
    async fn push(&mut self, value: V) {
        self.inner.push(value).await;
    }

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
    #[inline]
    async fn restore_or_new(&mut self) {
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
    }
}

/// Async Streams (ie async iterators)
impl<T: Debug + Serialize + DeserializeOwned + Clone + Send + Sync + 'static> StorageVecStream<T>
    for DbtVec<T>
{
    async fn stream<'a>(&'a self) -> impl Stream<Item = (Index, T)> + 'a
    where
        T: 'a,
    {
        self.stream_many(0..self.len().await)
    }

    async fn stream_values<'a>(&'a self) -> impl Stream<Item = T> + 'a
    where
        T: 'a,
    {
        self.stream_many_values(0..self.len().await)
    }
}

impl<T: Debug + Serialize + DeserializeOwned + Clone + Send + Sync + 'static> StorageVec<T>
    for DbtVec<T>
{
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::super::SimpleRustyStorage;
    use super::*;
    use crate::application::database::NeptuneLevelDb;

    pub async fn mk_test_vec_u64() -> DbtVec<u64> {
        // open new DB that will be closed on drop.
        let db = NeptuneLevelDb::open_new_test_database(true, None, None, None)
            .await
            .unwrap();
        let mut rusty_storage = SimpleRustyStorage::new(db);
        rusty_storage.schema.new_vec::<u64>("test-vector").await
    }

    pub mod streams {
        use macro_rules_attr::apply;

        use super::super::super::super::storage_vec::traits::tests::streams as stream_tests;
        use super::*;
        use crate::tests::shared_tokio_runtime;

        #[apply(shared_tokio_runtime)]
        pub async fn stream() {
            stream_tests::stream(mk_test_vec_u64().await).await
        }

        #[apply(shared_tokio_runtime)]
        pub async fn stream_many() {
            stream_tests::stream_many(mk_test_vec_u64().await).await
        }
    }
}
