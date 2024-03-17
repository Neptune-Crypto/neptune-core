use super::ordinary_vec_private::OrdinaryVecPrivate;
use super::{traits::*, Index};
use crate::sync::{AtomicRw, AtomicRwReadGuard, AtomicRwWriteGuard};

/// A wrapper that adds [`RwLock`](std::sync::RwLock) and atomic snapshot
/// guarantees around all accesses to an ordinary [`Vec`]
#[derive(Debug, Clone, Default)]
pub struct OrdinaryVec<T>(AtomicRw<OrdinaryVecPrivate<T>>);

impl<T> From<Vec<T>> for OrdinaryVec<T> {
    fn from(v: Vec<T>) -> Self {
        Self(AtomicRw::from(OrdinaryVecPrivate(v)))
    }
}

impl<T> OrdinaryVec<T> {
    #[inline]
    pub(crate) fn write_lock(&mut self) -> AtomicRwWriteGuard<'_, OrdinaryVecPrivate<T>> {
        self.0.lock_guard_mut()
    }

    #[inline]
    pub(crate) fn read_lock(&self) -> AtomicRwReadGuard<'_, OrdinaryVecPrivate<T>> {
        self.0.lock_guard()
    }
}

impl<T> StorageVecRwLock<T> for OrdinaryVec<T> {
    type LockedData = OrdinaryVecPrivate<T>;

    #[inline]
    fn try_write_lock(&mut self) -> Option<AtomicRwWriteGuard<'_, Self::LockedData>> {
        Some(self.write_lock())
    }

    #[inline]
    fn try_read_lock(&self) -> Option<AtomicRwReadGuard<'_, Self::LockedData>> {
        Some(self.read_lock())
    }
}

impl<T: Clone> StorageVec<T> for OrdinaryVec<T> {
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
                "Out-of-bounds. Got index {} but length was {}.",
                i,
                inner.len(),
            );
            (i, inner.get(i))
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
                "Out-of-bounds. Got index {} but length was {}.",
                i,
                inner.len(),
            );
            inner.get(i)
        }))
    }

    #[inline]
    fn set(&mut self, index: Index, value: T) {
        // note: on 32 bit systems, this could panic.
        self.write_lock().set(index, value);
    }

    #[inline]
    fn set_many(&mut self, key_vals: impl IntoIterator<Item = (Index, T)>) {
        self.write_lock().set_many(key_vals);
    }

    #[inline]
    fn pop(&mut self) -> Option<T> {
        self.write_lock().pop()
    }

    #[inline]
    fn push(&mut self, value: T) {
        self.write_lock().push(value);
    }

    #[inline]
    fn clear(&mut self) {
        self.write_lock().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::super::traits::tests as traits_tests;
    use super::*;

    mod concurrency {
        use super::*;

        fn gen_concurrency_test_vec() -> OrdinaryVec<u64> {
            Default::default()
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
