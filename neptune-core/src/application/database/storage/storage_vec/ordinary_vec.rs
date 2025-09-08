use serde::de::DeserializeOwned;
use serde::Serialize;

use super::ordinary_vec_private::OrdinaryVecPrivate;
use super::traits::*;
use super::Index;

/// Implements [`StorageVec`] trait for an ordinary (in memory) `Vec`
#[derive(Debug, Clone, Default)]
pub struct OrdinaryVec<T>(OrdinaryVecPrivate<T>);

impl<T> From<Vec<T>> for OrdinaryVec<T> {
    fn from(v: Vec<T>) -> Self {
        Self(OrdinaryVecPrivate(v))
    }
}

#[async_trait::async_trait]
impl<T: Serialize + DeserializeOwned + Clone + Send + Sync + 'static> StorageVecBase<T>
    for OrdinaryVec<T>
{
    #[inline]
    async fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline]
    async fn len(&self) -> Index {
        self.0.len()
    }

    #[inline]
    async fn get(&self, index: Index) -> T {
        self.0.get(index)
    }

    #[inline]
    async fn get_many(&self, indices: &[Index]) -> Vec<T> {
        self.0.get_many(indices)
    }

    /// Return all stored elements in a vector, whose index matches the StorageVec's.
    /// It's the caller's responsibility that there is enough memory to store all elements.
    #[inline]
    async fn get_all(&self) -> Vec<T> {
        self.0.get_all()
    }

    #[inline]
    async fn set(&mut self, index: Index, value: T) {
        // note: on 32 bit systems, this could panic.
        self.0.set(index, value);
    }

    #[inline]
    async fn set_many(&mut self, key_vals: impl IntoIterator<Item = (Index, T)> + Send) {
        self.0.set_many(key_vals)
    }

    #[inline]
    async fn pop(&mut self) -> Option<T> {
        self.0.pop()
    }

    #[inline]
    async fn push(&mut self, value: T) {
        self.0.push(value);
    }

    #[inline]
    async fn clear(&mut self) {
        self.0.clear();
    }
}

// Async Streams (ie async iterators)
impl<T: Serialize + DeserializeOwned + Clone + Send + Sync + 'static> StorageVecStream<T>
    for OrdinaryVec<T>
{
}

impl<T: Serialize + DeserializeOwned + Clone + Send + Sync + 'static> StorageVec<T>
    for OrdinaryVec<T>
{
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::super::traits::tests as trait_tests;
    use super::*;

    pub fn mk_test_vec_u64() -> OrdinaryVec<u64> {
        OrdinaryVec::from(vec![])
    }

    pub mod streams {
        use macro_rules_attr::apply;
        use trait_tests::streams as stream_tests;

        use super::*;
        use crate::tests::shared_tokio_runtime;

        #[apply(shared_tokio_runtime)]
        pub async fn stream() {
            stream_tests::stream(mk_test_vec_u64()).await
        }

        #[apply(shared_tokio_runtime)]
        pub async fn stream_many() {
            stream_tests::stream_many(mk_test_vec_u64()).await
        }
    }
}
