//! Traits that define the StorageVec interface
//!
//! It is recommended to wildcard import these with
//! `use crate::application::database::storage::storage_vec::traits::*`

// for Stream (async Iterator equiv)
use async_stream::stream;
use futures::stream::Stream;
// re-export to make life easier for users of our API.
pub use futures::{pin_mut, StreamExt};

use super::Index;

// #[expect(async_fn_in_trait)]
#[async_trait::async_trait]
pub trait StorageVecBase<T: Send> {
    /// check if collection is empty
    async fn is_empty(&self) -> bool;

    /// get collection length
    async fn len(&self) -> Index;
    // fn len(&self) -> impl Future<Output = Index > + Send;

    /// get single element at index
    async fn get(&self, index: Index) -> T;

    /// get multiple elements matching indices
    ///
    /// This is a convenience method. For large collections
    /// it may be more efficient to use a Stream or for-loop
    /// and avoid allocating a Vec
    async fn get_many(&self, indices: &[Index]) -> Vec<T>;
    // #[inline]
    // async fn get_many(&self, indices: &[Index]) -> Vec<T> {
    //     self.many_iter(indices.to_vec()).map(|(_i, v)| v).collect()
    // }

    /// get all elements
    ///
    /// This is a convenience method. For large collections
    /// it may be more efficient to use an iterator or for-loop
    /// and avoid allocating a Vec
    #[inline]
    async fn get_all(&self) -> Vec<T> {
        let all_indices = (0..self.len().await).collect::<Vec<_>>();
        self.get_many(&all_indices).await
    }

    /// set a single element.
    ///
    /// note: The update is performed as a single atomic operation.
    async fn set(&mut self, index: Index, value: T);

    /// set multiple elements.
    ///
    /// It is the caller's responsibility to ensure that index values are
    /// unique.  If not, the last value with the same index will win.
    /// For unordered collections such as HashMap, the behavior is undefined.
    ///
    /// note: all updates are performed as a single atomic operation.
    ///       readers will see either the before or after state,
    ///       never an intermediate state.
    async fn set_many(&mut self, key_vals: impl IntoIterator<Item = (Index, T)> + Send);

    /// set elements from start to vals.count()
    ///
    /// note: all updates are performed as a single atomic operation.
    ///       readers will see either the before or after state,
    ///       never an intermediate state.
    #[inline]
    async fn set_first_n(&mut self, vals: impl IntoIterator<Item = T> + Send) {
        self.set_many((0..).zip(vals).collect::<Vec<_>>()).await;
    }

    /// set all elements with a simple list of values in an array or Vec
    /// and validates that input length matches target length.
    ///
    /// panics if input length does not match target length.
    ///
    /// note: all updates are performed as a single atomic operation.
    ///       readers will see either the before or after state,
    ///       never an intermediate state.
    ///
    /// note: casts the input value's length from usize to Index
    ///       so will panic if vals contains more than 2^32 items
    #[inline]
    async fn set_all(
        &mut self,
        vals: impl IntoIterator<IntoIter = impl ExactSizeIterator<Item = T> + Send> + Send,
    ) {
        let iter = vals.into_iter();

        assert!(
            iter.len() as Index == self.len().await,
            "size-mismatch.  input has {} elements and target has {} elements.",
            iter.len(),
            self.len().await,
        );

        self.set_first_n(iter).await;
    }

    /// pop an element from end of collection
    ///
    /// note: The update is performed as a single atomic operation.
    async fn pop(&mut self) -> Option<T>;

    /// push an element to end of collection
    ///
    /// note: The update is performed as a single atomic operation.
    async fn push(&mut self, value: T);

    /// Removes all elements from the collection
    ///
    /// note: The update is performed as a single atomic operation.
    async fn clear(&mut self);
}

#[expect(async_fn_in_trait)]
pub trait StorageVecStream<T: Send>: StorageVecBase<T> {
    /// get an async Stream for iterating over all elements by key/val
    ///
    /// # Example:
    /// ```
    /// # tokio_test::block_on(async {
    /// # use neptune_cash::application::database::storage::storage_vec::{OrdinaryVec, traits::*};
    /// # let mut vec = OrdinaryVec::<u32>::from(vec![1,2,3,4,5,6,7,8,9]);
    ///
    /// let stream = vec.stream().await;
    /// pin_mut!(stream);  // needed for iteration
    ///
    /// while let Some((key, val)) = stream.next().await {
    ///     println!("{key}: {val}")
    /// }
    /// # })
    /// ```
    #[inline]
    async fn stream<'a>(&'a self) -> impl Stream<Item = (Index, T)> + 'a
    where
        T: 'a,
    {
        self.stream_many(0..self.len().await)
    }

    /// get an async Stream for iterating over all elements by value
    ///
    /// # Example:
    /// ```
    /// # tokio_test::block_on(async {
    /// # use neptune_cash::application::database::storage::storage_vec::{OrdinaryVec, traits::*};
    /// # let mut vec = OrdinaryVec::<u32>::from(vec![1,2,3,4,5,6,7,8,9]);
    ///
    /// let stream = vec.stream_values().await;
    /// pin_mut!(stream);  // needed for iteration
    ///
    /// while let Some(val) = stream.next().await {
    ///     println!("{val}")
    /// }
    /// # })
    /// ```
    #[inline]
    async fn stream_values<'a>(&'a self) -> impl Stream<Item = T> + 'a
    where
        T: 'a,
    {
        self.stream_many_values(0..self.len().await)
    }

    /// get an async Stream for iterating over elements matching indices by key/value
    ///
    /// # Example:
    /// ```
    /// # tokio_test::block_on(async {
    /// # use neptune_cash::application::database::storage::storage_vec::{OrdinaryVec, traits::*};
    /// # let mut vec = OrdinaryVec::<u32>::from(vec![1,2,3,4,5,6,7,8,9]);
    ///
    /// let stream = vec.stream_many([2,3,7]);
    /// pin_mut!(stream);  // needed for iteration
    ///
    /// while let Some((key, val)) = stream.next().await {
    ///     println!("{key}: {val}")
    /// }
    /// # })
    /// ```
    fn stream_many<'a>(
        &'a self,
        indices: impl IntoIterator<Item = Index> + 'a,
    ) -> impl Stream<Item = (Index, T)> + 'a
    where
        T: 'a,
    {
        stream! {
            for i in indices {
                yield (i, self.get(i).await)
            }
        }
    }

    /// get an async Stream for iterating over elements matching indices by value
    ///
    /// # Example:
    /// ```
    /// # tokio_test::block_on(async {
    /// # use neptune_cash::application::database::storage::storage_vec::{OrdinaryVec, traits::*};
    /// # let mut vec = OrdinaryVec::<u32>::from(vec![1,2,3,4,5,6,7,8,9]);
    ///
    /// let stream = vec.stream_many_values([2,3,7]);
    /// pin_mut!(stream);  // needed for iteration
    ///
    /// while let Some(val) = stream.next().await {
    ///     println!("{val}")
    /// }
    /// # })
    /// ```
    fn stream_many_values<'a>(
        &'a self,
        indices: impl IntoIterator<Item = Index> + 'a,
    ) -> impl Stream<Item = T> + 'a
    where
        T: 'a,
    {
        stream! {
            for i in indices {
                yield self.get(i).await
            }
        }
    }
}

pub trait StorageVec<T: Send>: StorageVecBase<T> + StorageVecStream<T> {}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(in super::super) mod tests {
    use super::*;

    pub mod streams {
        use futures::pin_mut;
        use futures::StreamExt;

        use super::*;

        pub async fn prepare_streams_test_vec(vec: &mut impl StorageVecBase<u64>) {
            vec.clear().await;
            for i in 0..4 {
                vec.push(i * 10).await;
            }
        }

        pub async fn stream(mut vec: impl StorageVecStream<u64>) {
            prepare_streams_test_vec(&mut vec).await;

            {
                let mut vals = vec![];
                let stream = vec.stream().await;
                pin_mut!(stream); // needed for iteration
                while let Some(value) = stream.next().await {
                    vals.push(value);
                }
                assert_eq!(vals, vec![(0, 0), (1, 10), (2, 20), (3, 30)]);
            }

            vec.clear().await;

            {
                let mut vals = vec![];
                let stream = vec.stream().await;
                pin_mut!(stream); // needed for iteration
                while let Some(value) = stream.next().await {
                    vals.push(value);
                }
                assert_eq!(vals, vec![]);
            }
        }

        pub async fn stream_many(mut vec: impl StorageVecStream<u64>) {
            prepare_streams_test_vec(&mut vec).await;

            {
                let mut vals = vec![];
                let stream = vec.stream_many([0, 1, 2, 3]);
                pin_mut!(stream); // needed for iteration
                while let Some(value) = stream.next().await {
                    vals.push(value);
                }
                assert_eq!(vals, vec![(0, 0), (1, 10), (2, 20), (3, 30)]);
            }

            {
                let mut vals = vec![];
                let stream = vec.stream_many([1, 2]);
                pin_mut!(stream); // needed for iteration
                while let Some(value) = stream.next().await {
                    vals.push(value);
                }
                assert_eq!(vals, vec![(1, 10), (2, 20)]);
            }
        }
    }
}
