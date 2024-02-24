//! Traits that define the StorageVec interface
//!
//! It is recommended to wildcard import these with
//! `use crate::database::storage::storage_vec::traits::*`

// use super::iterators::{ManyIterMut, StorageSetter};
use super::Index; //, ManyIterMut};
                  // use crate::locks::tokio::{AtomicRwReadGuard, AtomicRwWriteGuard};

// for Stream (async Iterator equiv)
use async_stream::stream;
use futures::stream::Stream;

// re-export to make life easier for users of our API.
// pub use lending_iterator::LendingIterator;

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
    /// it may be more efficient to use an iterator or for-loop
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

    pub mod concurrency {
        use super::*;
        use futures::FutureExt;
        use std::thread;

        pub async fn prepare_concurrency_test_vec(vec: &mut impl StorageVec<u64>) {
            vec.clear().await;
            for i in 0..400 {
                vec.push(i).await;
            }
        }

        // This test demonstrates/verifies that multiple calls to set() and get() are not atomic
        // for a type that impl's StorageVec.
        //
        // note: this test is expected to panic and calling test fn should be annotated with:
        // #[should_panic]
        pub async fn non_atomic_set_and_get(
            vec: &mut (impl StorageVec<u64> + Send + Sync + Clone),
        ) {
            prepare_concurrency_test_vec(vec).await;
            let orig = vec.get_all().await;
            let modified: Vec<u64> = orig.iter().map(|_| 50).collect();

            // note: this non-deterministic test is expected to fail/assert
            //       within 10000 iterations though that can depend on
            //       machine load, etc.
            for _i in 0..10000 {
                thread::scope(|s| {
                    s.spawn(|| {
                        let rt = tokio::runtime::Runtime::new().unwrap();
                        tokio_scoped::scoped(rt.handle()).scope(|ts| {
                            ts.block_on(async {
                                // read values one by one.
                                let mut copy = vec![];
                                for z in 0..vec.len().await {
                                    copy.push(vec.get(z).await);
                                }
                                // seems to help find inconsistencies sooner
                                tokio::time::sleep(std::time::Duration::from_millis(1)).await;

                                assert!(
                                    copy == orig || copy == modified,
                                    "encountered inconsistent read: {:?}",
                                    copy
                                );
                            });
                        });
                    });

                    s.spawn(|| {
                        let rt = tokio::runtime::Runtime::new().unwrap();
                        tokio_scoped::scoped(rt.handle()).scope(|ts| {
                            ts.block_on(async {
                                // set values one by one, in reverse order than the reader.
                                for j in (0..vec.len().await).rev() {
                                    vec.clone().set(j, 50).await;
                                }
                            });
                        });
                    });
                });
                vec.clone().set_all(orig.clone()).await;
            }
        }

        // This test demonstrates/verifies that wrapping an impl StorageVec in an AtomicRw
        // (Arc<RwLock<..>>) is not atomic if the lock is re-acquired for each read/write op.
        //
        // note: this test is expected to panic and calling test fn should be annotated with:
        // #[should_panic]
        pub async fn non_atomic_set_and_get_wrapped_atomic_rw(
            vec: &mut (impl StorageVec<u64> + Send + Sync + Clone),
        ) {
            prepare_concurrency_test_vec(vec).await;
            let orig = vec.get_all().await;
            let modified: Vec<u64> = orig.iter().map(|_| 50).collect();

            let atomic_vec = crate::locks::tokio::AtomicRw::from(vec);

            // note: this test is non-deterministic.  It is expected to fail/assert
            // within 10000 iterations though that can depend on machine load, etc.
            for i in 0..10000 {
                println!("i: {}", i);
                thread::scope(|s| {
                    s.spawn(|| {
                        let rt = tokio::runtime::Runtime::new().unwrap();
                        tokio_scoped::scoped(rt.handle()).scope(|ts| {
                            ts.block_on(async {
                                // read values one by one.
                                let mut copy = vec![];
                                let len = atomic_vec.lock_guard().await.len().await;
                                for z in 0..len {
                                    // acquire read lock
                                    copy.push(atomic_vec.lock_guard().await.get(z).await);
                                }
                                // seems to help find inconsistencies sooner
                                tokio::time::sleep(std::time::Duration::from_millis(1)).await;

                                assert!(
                                    copy == orig || copy == modified,
                                    "encountered inconsistent read: {:?}",
                                    copy
                                );
                            });
                        });
                    });

                    s.spawn(|| {
                        let rt = tokio::runtime::Runtime::new().unwrap();
                        tokio_scoped::scoped(rt.handle()).scope(|ts| {
                            ts.block_on(async {
                                // set values one by one.
                                let len = atomic_vec.lock_guard().await.len().await;
                                for j in 0..len {
                                    // acquire write lock
                                    atomic_vec.clone().lock_guard_mut().await.set(j, 50).await;
                                }
                            });
                        });
                    });
                });
                atomic_vec
                    .clone()
                    .lock_guard_mut()
                    .await
                    .set_all(orig.clone())
                    .await;
            }
        }

        // This test demonstrates/verifies that wrapping an impl StorageVec in an AtomicRw
        // (Arc<RwLock<..>>) is atomic if the lock is held across all write/read operations
        pub async fn atomic_set_and_get_wrapped_atomic_rw(
            vec: &mut (impl StorageVec<u64> + Send + Sync),
        ) {
            prepare_concurrency_test_vec(vec).await;
            let orig = vec.get_all().await;
            let modified: Vec<u64> = orig.iter().map(|_| 50).collect();

            let atomic_vec = crate::locks::tokio::AtomicRw::from(vec);

            // note: this test is expected to fail/assert within 1000 iterations
            //       though that can depend on machine load, etc.
            for _i in 0..1000 {
                thread::scope(|s| {
                    s.spawn(|| {
                        let rt = tokio::runtime::Runtime::new().unwrap();
                        tokio_scoped::scoped(rt.handle()).scope(|ts| {
                            ts.block_on(async {
                                // acquire read lock
                                atomic_vec
                                    .lock_async(|v| {
                                        async {
                                            // read values one by one.
                                            let mut copy = vec![];
                                            for z in 0..v.len().await {
                                                copy.push(v.get(z).await);
                                            }

                                            assert!(
                                                copy == orig || copy == modified,
                                                "encountered inconsistent read: {:?}",
                                                copy
                                            );
                                        }
                                        .boxed()
                                    })
                                    .await; // release read lock
                            });
                        });
                    });

                    s.spawn(|| {
                        let rt = tokio::runtime::Runtime::new().unwrap();
                        tokio_scoped::scoped(rt.handle()).scope(|ts| {
                            ts.block_on(async {
                                atomic_vec
                                    .clone()
                                    .lock_mut_async(|v| {
                                        async {
                                            // acquire write lock
                                            for j in 0..v.len().await {
                                                // set values one by one.
                                                v.set(j, 50).await;
                                            }
                                        }
                                        .boxed()
                                    })
                                    .await; // release write lock.
                            });
                        });
                    });
                });
                atomic_vec
                    .clone()
                    .lock_guard_mut()
                    .await
                    .set_all(orig.clone())
                    .await;
            }
        }

        pub async fn atomic_setmany_and_getmany(
            vec: &mut (impl StorageVec<u64> + Send + Sync + Clone),
        ) {
            prepare_concurrency_test_vec(vec).await;
            let orig = vec.get_all().await;
            let modified: Vec<u64> = orig.iter().map(|_| 50).collect();

            let indices: Vec<_> = (0..orig.len() as u64).collect();

            // this test should never fail.  we only loop 100 times to keep
            // the test fast.  Bump it up to 10000+ temporarily to be extra certain.
            for _i in 0..100 {
                thread::scope(|s| {
                    s.spawn(|| {
                        let rt = tokio::runtime::Runtime::new().unwrap();
                        tokio_scoped::scoped(rt.handle()).scope(|ts| {
                            ts.block_on(async {
                                let copy = vec.get_many(&indices).await;

                                assert!(
                                    copy == orig || copy == modified,
                                    "encountered inconsistent read: {:?}",
                                    copy
                                );
                            });
                        });
                    });

                    s.spawn(|| {
                        let rt = tokio::runtime::Runtime::new().unwrap();
                        tokio_scoped::scoped(rt.handle()).scope(|ts| {
                            ts.block_on(async {
                                vec.clone()
                                    .set_many(
                                        orig.iter().enumerate().map(|(k, _v)| (k as u64, 50u64)),
                                    )
                                    .await;
                            });
                        });
                    });
                });
                vec.clone().set_all(orig.clone()).await;
            }
        }

        pub async fn atomic_setall_and_getall(
            vec: &mut (impl StorageVec<u64> + Send + Sync + Clone),
        ) {
            prepare_concurrency_test_vec(vec).await;
            let orig = vec.get_all().await;
            let modified: Vec<u64> = orig.iter().map(|_| 50).collect();

            // this test should never fail.  we only loop 100 times to keep
            // the test fast.  Bump it up to 10000+ temporarily to be extra certain.
            for _i in 0..100 {
                thread::scope(|s| {
                    s.spawn(|| {
                        let rt = tokio::runtime::Runtime::new().unwrap();
                        tokio_scoped::scoped(rt.handle()).scope(|ts| {
                            ts.block_on(async {
                                let copy = vec.get_all().await;

                                assert!(
                                    copy == orig || copy == modified,
                                    "encountered inconsistent read: {:?}",
                                    copy
                                );
                            });
                        });
                    });

                    s.spawn(|| {
                        let rt = tokio::runtime::Runtime::new().unwrap();
                        tokio_scoped::scoped(rt.handle()).scope(|ts| {
                            ts.block_on(async {
                                vec.clone().set_all(orig.iter().map(|_| 50)).await;
                            });
                        });
                    });
                });
                vec.clone().set_all(orig.clone()).await;
            }
        }

        // pub async fn atomic_iter_mut_and_iter<T>(vec: &mut T)
        // where
        //     T: StorageVec<u64> + StorageVecRwLock<u64> + Send + Sync + Clone,
        //     T::LockedData: StorageVecLockedData<u64>,
        // {
        //     prepare_concurrency_test_vec(vec).await;
        //     let orig = vec.get_all().await;
        //     let modified: Vec<u64> = orig.iter().map(|_| 50).collect();

        //     // this test should never fail.  we only loop 100 times to keep
        //     // the test fast.  Bump it up to 10000+ temporarily to be extra certain.
        //     thread::scope(|s| {
        //         for _i in 0..100 {
        //             let gets = s.spawn(|| {
        //                 let copy = vec.iter_values().collect_vec();
        //                 assert!(
        //                     copy == orig || copy == modified,
        //                     "encountered inconsistent read: {:?}",
        //                     copy
        //                 );
        //             });

        //             let sets = s.spawn(|| {
        //                 let mut vec_mut = vec.clone();
        //                 let mut iter = vec_mut.iter_mut();
        //                 while let Some(mut setter) = iter.next() {
        //                     setter.set(50);
        //                 }
        //             });
        //             gets.join().unwrap();
        //             sets.join().unwrap();

        //             vec.clone().set_all(orig.clone());
        //         }
        //     });
        // }
    }
}
