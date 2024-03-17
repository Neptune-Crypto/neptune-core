//! Traits that define the StorageVec interface
//!
//! It is recommended to wildcard import these with
//! `use twenty_first::storage::storage_vec::traits::*`

// use super::iterators::{ManyIterMut, StorageSetter};
use super::{Index, ManyIterMut};
use crate::sync::{AtomicRwReadGuard, AtomicRwWriteGuard};

// re-export to make life easier for users of our API.
pub use lending_iterator::LendingIterator;

pub trait StorageVec<T> {
    /// check if collection is empty
    fn is_empty(&self) -> bool;

    /// get collection length
    fn len(&self) -> Index;

    /// get single element at index
    fn get(&self, index: Index) -> T;

    /// get multiple elements matching indices
    ///
    /// This is a convenience method. For large collections
    /// it may be more efficient to use an iterator or for-loop
    /// and avoid allocating a Vec
    #[inline]
    fn get_many(&self, indices: &[Index]) -> Vec<T> {
        self.many_iter(indices.to_vec()).map(|(_i, v)| v).collect()
    }

    /// get all elements
    ///
    /// This is a convenience method. For large collections
    /// it may be more efficient to use an iterator or for-loop
    /// and avoid allocating a Vec
    #[inline]
    fn get_all(&self) -> Vec<T> {
        self.iter().map(|(_i, v)| v).collect()
    }

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
    /// # use twenty_first::storage::storage_vec::{OrdinaryVec, traits::*};
    /// # let mut vec = OrdinaryVec::<u32>::from(vec![1,2,3,4,5,6,7,8,9]);
    ///
    /// for (key, val) in vec.iter() {
    ///     println!("{key}: {val}")
    /// } // <--- iterator is dropped here.
    ///
    /// // write can proceed
    /// vec.set(5, 2);
    /// ```
    #[inline]
    fn iter(&self) -> Box<dyn Iterator<Item = (Index, T)> + '_> {
        self.many_iter(0..self.len())
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
    /// # use twenty_first::storage::storage_vec::{OrdinaryVec, traits::*};
    /// # let mut vec = OrdinaryVec::<u32>::from(vec![1,2,3,4,5,6,7,8,9]);
    ///
    /// for (val) in vec.iter_values() {
    ///     println!("{val}")
    /// } // <--- iterator is dropped here.
    ///
    /// // write can proceed
    /// let val = vec.push(2);
    /// ```
    #[inline]
    fn iter_values(&self) -> Box<dyn Iterator<Item = T> + '_> {
        self.many_iter_values(0..self.len())
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
    /// # use twenty_first::storage::storage_vec::{OrdinaryVec, traits::*};
    /// # let mut vec = OrdinaryVec::<u32>::from(vec![1,2,3,4,5,6,7,8,9]);
    ///
    /// for (key, val) in vec.many_iter([3, 5, 7]) {
    ///     println!("{key}: {val}")
    /// } // <--- iterator is dropped here.
    ///
    /// // write can proceed
    /// vec.set(5, 2);
    /// ```
    fn many_iter<'a>(
        &'a self,
        indices: impl IntoIterator<Item = Index> + 'a,
    ) -> Box<dyn Iterator<Item = (Index, T)> + '_>;

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
    /// # use twenty_first::storage::storage_vec::{OrdinaryVec, traits::*};
    /// # let mut vec = OrdinaryVec::<u32>::from(vec![1,2,3,4,5,6,7,8,9]);
    ///
    /// for (val) in vec.many_iter_values([2, 5, 8]) {
    ///     println!("{val}")
    /// } // <--- iterator is dropped here.
    ///
    /// // write can proceed
    /// vec.set(5, 2);
    /// ```
    fn many_iter_values<'a>(
        &'a self,
        indices: impl IntoIterator<Item = Index> + 'a,
    ) -> Box<dyn Iterator<Item = T> + '_>;

    /// set a single element.
    ///
    /// note: The update is performed as a single atomic operation.
    fn set(&mut self, index: Index, value: T);

    /// set multiple elements.
    ///
    /// It is the caller's responsibility to ensure that index values are
    /// unique.  If not, the last value with the same index will win.
    /// For unordered collections such as HashMap, the behavior is undefined.
    ///
    /// note: all updates are performed as a single atomic operation.
    ///       readers will see either the before or after state,
    ///       never an intermediate state.
    fn set_many(&mut self, key_vals: impl IntoIterator<Item = (Index, T)>);

    /// set elements from start to vals.count()
    ///
    /// note: all updates are performed as a single atomic operation.
    ///       readers will see either the before or after state,
    ///       never an intermediate state.
    #[inline]
    fn set_first_n(&mut self, vals: impl IntoIterator<Item = T>) {
        self.set_many((0..).zip(vals));
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
    fn set_all(&mut self, vals: impl IntoIterator<IntoIter = impl ExactSizeIterator<Item = T>>) {
        let iter = vals.into_iter();

        assert!(
            iter.len() as Index == self.len(),
            "size-mismatch.  input has {} elements and target has {} elements.",
            iter.len(),
            self.len(),
        );

        self.set_first_n(iter);
    }

    /// pop an element from end of collection
    ///
    /// note: The update is performed as a single atomic operation.
    fn pop(&mut self) -> Option<T>;

    /// push an element to end of collection
    ///
    /// note: The update is performed as a single atomic operation.
    fn push(&mut self, value: T);

    /// Removes all elements from the collection
    ///
    /// note: The update is performed as a single atomic operation.
    fn clear(&mut self);

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
    /// # use twenty_first::storage::storage_vec::{OrdinaryVec, traits::*};
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
    #[allow(private_bounds)]
    #[inline]
    fn iter_mut(&mut self) -> ManyIterMut<Self, T>
    where
        Self: Sized + StorageVecRwLock<T>,
    {
        ManyIterMut::new(0..self.len(), self)
    }

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
    /// # use twenty_first::storage::storage_vec::{OrdinaryVec, traits::*};
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
    #[allow(private_bounds)]
    #[inline]
    fn many_iter_mut<'a>(
        &'a mut self,
        indices: impl IntoIterator<Item = Index> + 'a,
    ) -> ManyIterMut<Self, T>
    where
        Self: Sized + StorageVecRwLock<T>,
    {
        ManyIterMut::new(indices, self)
    }
}

// We keep this trait private for now as impl detail.
pub(in super::super) trait StorageVecLockedData<T> {
    /// get single element at index
    fn get(&self, index: Index) -> T;

    /// set a single element.
    fn set(&mut self, index: Index, value: T);
}

// We keep this trait private so that the locks remain encapsulated inside our API.
pub(in super::super) trait StorageVecRwLock<T> {
    type LockedData;

    /// obtain write lock over mutable data.
    fn try_write_lock(&mut self) -> Option<AtomicRwWriteGuard<Self::LockedData>>;

    /// obtain read lock over mutable data.
    fn try_read_lock(&self) -> Option<AtomicRwReadGuard<Self::LockedData>>;
}

pub(in super::super) trait StorageVecIterMut<T>: StorageVec<T> {}

#[cfg(test)]
pub(in crate::storage) mod tests {
    use super::*;
    use itertools::Itertools;

    pub mod concurrency {
        use super::*;
        use std::thread;

        pub fn prepare_concurrency_test_vec(vec: &mut impl StorageVec<u64>) {
            vec.clear();
            for i in 0..400 {
                vec.push(i);
            }
        }

        // This test demonstrates/verifies that multiple calls to set() and get() are not atomic
        // for a type that impl's StorageVec.
        //
        // note: this test is expected to panic and calling test fn should be annotated with:
        #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: Any { .. }")]
        pub fn non_atomic_set_and_get(vec: &mut (impl StorageVec<u64> + Send + Sync + Clone)) {
            prepare_concurrency_test_vec(vec);
            let orig = vec.get_all();
            let modified: Vec<u64> = orig.iter().map(|_| 50).collect();

            // note: this non-deterministic test is expected to fail/assert
            //       within 10000 iterations though that can depend on
            //       machine load, etc.
            thread::scope(|s| {
                for _i in 0..10000 {
                    let gets = s.spawn(|| {
                        // read values one by one.
                        let mut copy = vec![];
                        for z in 0..vec.len() {
                            copy.push(vec.get(z));
                        }
                        // seems to help find inconsistencies sooner
                        thread::sleep(std::time::Duration::from_millis(1));

                        assert!(
                            copy == orig || copy == modified,
                            "encountered inconsistent read: {:?}",
                            copy
                        );
                    });

                    let sets = s.spawn(|| {
                        // set values one by one, in reverse order than the reader.
                        for j in (0..vec.len()).rev() {
                            vec.clone().set(j, 50);
                        }
                    });
                    gets.join().unwrap();
                    sets.join().unwrap();

                    vec.clone().set_all(orig.clone());
                }
            });
        }

        // This test demonstrates/verifies that wrapping an impl StorageVec in an AtomicRw
        // (Arc<RwLock<..>>) is atomic if the lock is held across all write/read operations
        //
        // note: this test is expected to panic and calling test fn should be annotated with:
        #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: Any { .. }")]
        pub fn non_atomic_set_and_get_wrapped_atomic_rw(
            vec: &mut (impl StorageVec<u64> + Send + Sync + Clone),
        ) {
            prepare_concurrency_test_vec(vec);
            let orig = vec.get_all();
            let modified: Vec<u64> = orig.iter().map(|_| 50).collect();

            let atomic_vec = crate::sync::AtomicRw::from(vec);

            // note: this test is non-deterministic.  It is expected to fail/assert
            // within 10000 iterations though that can depend on machine load, etc.
            thread::scope(|s| {
                for _i in 0..10000 {
                    let gets = s.spawn(|| {
                        // read values one by one.
                        let mut copy = vec![];
                        for z in 0..atomic_vec.lock(|v| v.len()) {
                            // acquire write lock
                            atomic_vec.lock(|v| {
                                copy.push(v.get(z));
                            }); // release read lock
                        }
                        // seems to help find inconsistencies sooner
                        thread::sleep(std::time::Duration::from_millis(1));

                        assert!(
                            copy == orig || copy == modified,
                            "encountered inconsistent read: {:?}",
                            copy
                        );
                    });

                    let sets = s.spawn(|| {
                        // set values one by one.
                        for j in 0..atomic_vec.lock(|v| v.len()) {
                            // acquire write lock
                            atomic_vec.clone().lock_guard_mut().set(j, 50);
                        }
                    });
                    gets.join().unwrap();
                    sets.join().unwrap();

                    atomic_vec.clone().lock_mut(|v| v.set_all(orig.clone()));
                }
            });
        }

        // This test demonstrates/verifies that wrapping an impl StorageVec in an AtomicRw
        // (Arc<RwLock<..>>) is atomic if the lock is held across all write/read operations
        pub fn atomic_set_and_get_wrapped_atomic_rw(
            vec: &mut (impl StorageVec<u64> + Send + Sync),
        ) {
            prepare_concurrency_test_vec(vec);
            let orig = vec.get_all();
            let modified: Vec<u64> = orig.iter().map(|_| 50).collect();

            let atomic_vec = crate::sync::AtomicRw::from(vec);

            // note: this test is expected to fail/assert within 1000 iterations
            //       though that can depend on machine load, etc.
            thread::scope(|s| {
                for _i in 0..1000 {
                    let gets = s.spawn(|| {
                        // acquire read lock
                        atomic_vec.lock(|v| {
                            // read values one by one.
                            let mut copy = vec![];
                            for z in 0..v.len() {
                                copy.push(v.get(z));
                            }

                            assert!(
                                copy == orig || copy == modified,
                                "encountered inconsistent read: {:?}",
                                copy
                            );
                        }); // release read lock
                    });

                    let sets = s.spawn(|| {
                        atomic_vec.clone().lock_mut(|v| {
                            // acquire write lock
                            for j in 0..v.len() {
                                // set values one by one.
                                v.set(j, 50);
                            }
                        }); // release write lock.
                    });
                    gets.join().unwrap();
                    sets.join().unwrap();

                    atomic_vec.clone().lock_mut(|v| v.set_all(orig.clone()));
                }
            });
        }

        pub fn atomic_setmany_and_getmany(vec: &mut (impl StorageVec<u64> + Send + Sync + Clone)) {
            prepare_concurrency_test_vec(vec);
            let orig = vec.get_all();
            let modified: Vec<u64> = orig.iter().map(|_| 50).collect();

            let indices: Vec<_> = (0..orig.len() as u64).collect();

            // this test should never fail.  we only loop 100 times to keep
            // the test fast.  Bump it up to 10000+ temporarily to be extra certain.
            thread::scope(|s| {
                for _i in 0..100 {
                    let gets = s.spawn(|| {
                        let copy = vec.get_many(&indices);

                        assert!(
                            copy == orig || copy == modified,
                            "encountered inconsistent read: {:?}",
                            copy
                        );
                    });

                    let sets = s.spawn(|| {
                        vec.clone()
                            .set_many(orig.iter().enumerate().map(|(k, _v)| (k as u64, 50u64)));
                    });
                    gets.join().unwrap();
                    sets.join().unwrap();

                    vec.clone().set_all(orig.clone());
                }
            });
        }

        pub fn atomic_setall_and_getall(vec: &mut (impl StorageVec<u64> + Send + Sync + Clone)) {
            prepare_concurrency_test_vec(vec);
            let orig = vec.get_all();
            let modified: Vec<u64> = orig.iter().map(|_| 50).collect();

            // this test should never fail.  we only loop 100 times to keep
            // the test fast.  Bump it up to 10000+ temporarily to be extra certain.
            thread::scope(|s| {
                for _i in 0..100 {
                    let gets = s.spawn(|| {
                        let copy = vec.get_all();

                        assert!(
                            copy == orig || copy == modified,
                            "encountered inconsistent read: {:?}",
                            copy
                        );
                    });

                    let sets = s.spawn(|| {
                        vec.clone().set_all(orig.iter().map(|_| 50));
                    });
                    gets.join().unwrap();
                    sets.join().unwrap();

                    vec.clone().set_all(orig.clone());
                }
            });
        }

        pub fn atomic_iter_mut_and_iter<T>(vec: &mut T)
        where
            T: StorageVec<u64> + StorageVecRwLock<u64> + Send + Sync + Clone,
            T::LockedData: StorageVecLockedData<u64>,
        {
            prepare_concurrency_test_vec(vec);
            let orig = vec.get_all();
            let modified: Vec<u64> = orig.iter().map(|_| 50).collect();

            // this test should never fail.  we only loop 100 times to keep
            // the test fast.  Bump it up to 10000+ temporarily to be extra certain.
            thread::scope(|s| {
                for _i in 0..100 {
                    let gets = s.spawn(|| {
                        let copy = vec.iter_values().collect_vec();
                        assert!(
                            copy == orig || copy == modified,
                            "encountered inconsistent read: {:?}",
                            copy
                        );
                    });

                    let sets = s.spawn(|| {
                        let mut vec_mut = vec.clone();
                        let mut iter = vec_mut.iter_mut();
                        while let Some(mut setter) = iter.next() {
                            setter.set(50);
                        }
                    });
                    gets.join().unwrap();
                    sets.join().unwrap();

                    vec.clone().set_all(orig.clone());
                }
            });
        }
    }
}
