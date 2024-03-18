//! Traits that define the StorageVec interface
//!
//! It is recommended to wildcard import these with
//! `use crate::database::storage::storage_vec::traits::*`

use super::Index;

// for Stream (async Iterator equiv)
use async_stream::stream;
use futures::stream::Stream;

// re-export to make life easier for users of our API.
pub use futures::{pin_mut, StreamExt};

// #[allow(async_fn_in_trait)]
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

    /*
    /// get a mutable iterator over all elements
    ///
    /// note: all updates are performed as a single atomic operation.
    ///       readers will see either the before or after state,
    ///       never an intermediate state.
    ///
    /// note: the returned (lending) iterator cannot be used in a for loop.  Use a
    ///       while loop instead.  See example below.
    ///
    /// Note: The returned iterator holds a write lock over `StorageVecRwLock::LockedData`.
    /// This write lock must be dropped before performing any read operation.
    /// This is enforced by the borrow-checker, which also prevents deadlocks.
    ///
    /// # Example:
    /// ```
    /// # use crate::database::storage::storage_vec::{OrdinaryVec, traits::*};
    /// # let mut vec = OrdinaryVec::<u32>::from(vec![1,2,3,4,5,6,7,8,9]);
    ///
    /// {
    ///     let mut iter = vec.iter_mut();
    ///         while let Some(mut setter) = iter.next() {
    ///         setter.set(50);
    ///     }
    /// } // <----- iter is dropped here.  write lock is released.
    ///
    /// // read can proceed
    /// let val = vec.get(2);
    /// ```
    // #[allow(private_bounds)]
    // #[inline]
    // fn iter_mut(&mut self) -> ManyIterMut<Self, T>
    // where
    //     Self: Sized + StorageVecRwLock<T>,
    // {
    //     ManyIterMut::new(0..self.len(), self)
    // }

    /// get a mutable iterator over elements matching indices
    ///
    /// note: all updates are performed as a single atomic operation.
    ///       readers will see either the before or after state,
    ///       never an intermediate state.
    ///
    /// note: the returned (lending) iterator cannot be used in a for loop.  Use a
    ///       while loop instead.  See example below.
    ///
    /// Note: The returned iterator holds a write lock over `StorageVecRwLock::LockedData`.
    /// This write lock must be dropped before performing any read operation.
    /// This is enforced by the borrow-checker, which also prevents deadlocks.
    ///
    /// # Example:
    /// ```
    /// # use crate::database::storage::storage_vec::{OrdinaryVec, traits::*};
    /// # let mut vec = OrdinaryVec::<&str>::from(vec!["1","2","3","4","5","6","7","8","9"]);
    ///
    /// {
    ///     let mut iter = vec.many_iter_mut([2, 4, 6]);
    ///         while let Some(mut setter) = iter.next() {
    ///         setter.set("50");
    ///     }
    /// } // <----- iter is dropped here.  write lock is released.
    ///
    /// // read can proceed
    /// let val = vec.get(2);
    /// ```
    // #[allow(private_bounds)]
    // #[inline]
    // fn many_iter_mut<'a>(
    //     &'a mut self,
    //     indices: impl IntoIterator<Item = Index> + 'a,
    // ) -> ManyIterMut<Self, T>
    // where
    //     Self: Sized + StorageVecRwLock<T>,
    // {
    //     ManyIterMut::new(indices, self)
    // }
    */
}

// We keep this trait private for now as impl detail.
// #[allow(async_fn_in_trait)]
// pub(in super::super) trait StorageVecLockedData<T> {
//     /// get single element at index
//     async fn get(&self, index: Index) -> T;

//     /// set a single element.
//     async fn set(&mut self, index: Index, value: T);
// }

// We keep this trait private so that the locks remain encapsulated inside our API.
// #[allow(async_fn_in_trait)]
// #[async_trait::async_trait]
// pub(in super::super) trait StorageVecRwLock<T> {
//     type LockedData;

//     /// obtain write lock over mutable data.
//     async fn try_write_lock(&mut self) -> Option<AtomicRwWriteGuard<'_, Self::LockedData>>;
//     // where <Self as StorageVecRwLock<T>>::LockedData: 'a;

//     /// obtain read lock over mutable data.
//     async fn try_read_lock(&self) -> Option<AtomicRwReadGuard<'_, Self::LockedData>>;
//     // where <Self as StorageVecRwLock<T>>::LockedData: 'a;
// }

#[allow(async_fn_in_trait)]
pub trait StorageVecStream<T: Send>: StorageVecBase<T> {
    /// get an iterator over all elements
    ///
    /// The returned iterator holds a read-lock over the collection contents.
    /// This enables consistent (snapshot) reads because any writer must
    /// wait until the lock is released.
    ///
    /// The lock is not released until the iterator is dropped, so it is
    /// important to drop the iterator immediately after use.  Typical
    /// for-loop usage does this automatically.
    ///
    /// # Example:
    /// ```
    /// # use crate::database::storage::storage_vec::{OrdinaryVec, traits::*};
    /// # let mut vec = OrdinaryVec::<u32>::from(vec![1,2,3,4,5,6,7,8,9]);
    ///
    /// for (key, val) in vec.iter() {
    ///     println!("{key}: {val}")
    /// } // <--- iterator is dropped here.
    ///
    /// // write can proceed
    /// vec.set(5, 2);
    /// ```
    // #[inline]
    // async fn iter(&self) -> Box<dyn Iterator<Item = (Index, T)> + '_> {
    //     self.many_iter(0..self.len())
    // }
    async fn stream<'a>(&'a self) -> impl Stream<Item = (Index, T)> + 'a
    where
        T: 'a,
    {
        self.stream_many(0..self.len().await).await
    }

    /// The returned iterator holds a read-lock over the collection contents.
    /// This enables consistent (snapshot) reads because any writer must
    /// wait until the lock is released.
    ///
    /// The lock is not released until the iterator is dropped, so it is
    /// important to drop the iterator immediately after use.  Typical
    /// for-loop usage does this automatically.
    ///
    /// # Example:
    /// ```
    /// # use crate::database::storage::storage_vec::{OrdinaryVec, traits::*};
    /// # let mut vec = OrdinaryVec::<u32>::from(vec![1,2,3,4,5,6,7,8,9]);
    ///
    /// for (val) in vec.iter_values() {
    ///     println!("{val}")
    /// } // <--- iterator is dropped here.
    ///
    /// // write can proceed
    /// let val = vec.push(2);
    /// ```
    // #[inline]
    // fn iter_values(&self) -> Box<dyn Iterator<Item = T> + '_> {
    //     self.many_iter_values(0..self.len())
    // }
    async fn stream_values<'a>(&'a self) -> impl Stream<Item = T> + 'a
    where
        T: 'a,
    {
        self.stream_many_values(0..self.len().await).await
    }

    /// get an iterator over elements matching indices
    ///
    /// The returned iterator holds a read-lock over the collection contents.
    /// This enables consistent (snapshot) reads because any writer must
    /// wait until the lock is released.
    ///
    /// The lock is not released until the iterator is dropped, so it is
    /// important to drop the iterator immediately after use.  Typical
    /// for-loop usage does this automatically.
    ///
    /// # Example:
    /// ```
    /// # use crate::database::storage::storage_vec::{OrdinaryVec, traits::*};
    /// # let mut vec = OrdinaryVec::<u32>::from(vec![1,2,3,4,5,6,7,8,9]);
    ///
    /// for (key, val) in vec.many_iter([3, 5, 7]) {
    ///     println!("{key}: {val}")
    /// } // <--- iterator is dropped here.
    ///
    /// // write can proceed
    /// vec.set(5, 2);
    /// ```
    // fn many_iter<'a>(
    //     &'a self,
    //     indices: impl IntoIterator<Item = Index> + 'a,
    // ) -> Box<dyn Iterator<Item = (Index, T)> + '_>;
    async fn stream_many<'a>(
        &'a self,
        indices: impl IntoIterator<Item = Index> + 'a,
    ) -> impl Stream<Item = (Index, T)> + 'a
    where
        T: 'a,
    {
        stream! {
            for i in indices.into_iter() {
                yield (i, self.get(i).await)
            }
        }
    }

    /// get an iterator over elements matching indices
    ///
    /// The returned iterator holds a read-lock over the collection contents.
    /// This enables consistent (snapshot) reads because any writer must
    /// wait until the lock is released.
    ///
    /// The lock is not released until the iterator is dropped, so it is
    /// important to drop the iterator immediately after use.  Typical
    /// for-loop usage does this automatically.
    ///
    /// # Example:
    /// ```
    /// # use crate::database::storage::storage_vec::{OrdinaryVec, traits::*};
    /// # let mut vec = OrdinaryVec::<u32>::from(vec![1,2,3,4,5,6,7,8,9]);
    ///
    /// for (val) in vec.many_iter_values([2, 5, 8]) {
    ///     println!("{val}")
    /// } // <--- iterator is dropped here.
    ///
    /// // write can proceed
    /// vec.set(5, 2);
    /// ```
    // fn many_iter_values<'a>(
    //     &'a self,
    //     indices: impl IntoIterator<Item = Index> + 'a,
    // ) -> Box<dyn Iterator<Item = T> + '_>;
    async fn stream_many_values<'a>(
        &'a self,
        indices: impl IntoIterator<Item = Index> + 'a,
    ) -> impl Stream<Item = T> + 'a
    where
        T: 'a,
    {
        stream! {
            for i in indices.into_iter() {
                yield self.get(i).await
            }
        }
    }
}

pub trait StorageVec<T: Send>: StorageVecBase<T> + StorageVecStream<T> {}

pub(in super::super) trait StorageVecIterMut<T: Send>: StorageVec<T> {}

#[cfg(test)]
pub(in super::super) mod tests {
    use super::*;
    // use itertools::Itertools;

    pub mod streams {
        use super::*;
        use futures::{pin_mut, StreamExt};

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
                let stream = vec.stream_many([0, 1, 2, 3]).await;
                pin_mut!(stream); // needed for iteration
                while let Some(value) = stream.next().await {
                    vals.push(value);
                }
                assert_eq!(vals, vec![(0, 0), (1, 10), (2, 20), (3, 30)]);
            }

            {
                let mut vals = vec![];
                let stream = vec.stream_many([1, 2]).await;
                pin_mut!(stream); // needed for iteration
                while let Some(value) = stream.next().await {
                    vals.push(value);
                }
                assert_eq!(vals, vec![(1, 10), (2, 20)]);
            }
        }
    }
}
