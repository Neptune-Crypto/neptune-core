use super::{traits::*, Index};
use crate::sync::AtomicRwWriteGuard;
use lending_iterator::prelude::*;
use lending_iterator::{gat, LendingIterator};
use std::iter::Iterator;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};

/// A mutating iterator for [`StorageVec`] trait
///
/// Important: This iterator holds a reference to the
/// [`StorageVec`] implementor which will not be released
/// until the iterator is dropped.
///
/// See examples for [`StorageVec::iter_mut()`].
#[allow(private_bounds)]
pub struct ManyIterMut<'a, V, T>
where
    V: StorageVec<T> + StorageVecRwLock<T> + ?Sized,
{
    indices: Box<dyn Iterator<Item = Index> + 'a>,

    data_ref: DataRefMut<'a, V, T>,
    phantom_t: PhantomData<T>,
    phantom_d: PhantomData<V>,
}

#[allow(private_bounds)]
impl<'a, V, T> ManyIterMut<'a, V, T>
where
    V: StorageVec<T> + StorageVecRwLock<T> + ?Sized,
{
    pub(super) fn new<I>(indices: I, data: &'a mut V) -> Self
    where
        I: IntoIterator<Item = Index> + 'a,
    {
        // note: this is a bit awkward due to borrow-checker constraints.
        // So we can't just `match data.try_write_lock() { .. }`

        if data.try_write_lock().is_none() {
            return Self {
                indices: Box::new(indices.into_iter()),
                data_ref: DataRefMut::RefMut(data),
                phantom_t: Default::default(),
                phantom_d: Default::default(),
            };
        }

        let g = data.try_write_lock().unwrap();
        Self {
            indices: Box::new(indices.into_iter()),
            data_ref: DataRefMut::RwWriteGuard(g),
            phantom_t: Default::default(),
            phantom_d: Default::default(),
        }
    }
}

// LendingIterator trait gives us all the nice iterator type functions.
// We only have to impl next()
#[allow(private_bounds)]
#[gat]
impl<'a, V, T: 'a> LendingIterator for ManyIterMut<'a, V, T>
where
    V: StorageVec<T> + StorageVecRwLock<T> + ?Sized,
    V::LockedData: StorageVecLockedData<T>,
{
    type Item<'b> = StorageSetter<'a, 'b, V, T>
    where
        Self: 'b;

    fn next(&mut self) -> Option<Self::Item<'_>> {
        if let Some(i) = Iterator::next(&mut self.indices) {
            let value = self.data_ref.get(i);
            Some(StorageSetter {
                phantom: Default::default(),
                data_ref: &mut self.data_ref,
                index: i,
                value,
            })
        } else {
            None
        }
    }
}

/// used for accessing and setting values returned from StorageVec::get_mut() and mutable iterators
#[allow(private_bounds)]
pub struct StorageSetter<'a, 'b, V, T>
where
    V: StorageVec<T> + StorageVecRwLock<T> + ?Sized,
{
    phantom: PhantomData<V>,
    data_ref: &'b mut DataRefMut<'a, V, T>,
    index: Index,
    value: T,
}

#[allow(private_bounds)]
impl<'a, 'b, V, T> StorageSetter<'a, 'b, V, T>
where
    V: StorageVec<T> + StorageVecRwLock<T> + ?Sized,
    V::LockedData: StorageVecLockedData<T>,
{
    pub fn set(&mut self, value: T) {
        self.data_ref.deref_mut().set(self.index, value)
    }

    pub fn index(&self) -> Index {
        self.index
    }

    pub fn value(&self) -> &T {
        &self.value
    }
}

/// represents a reference to data held in an impl StorageVec.
///
/// abstracts over types with an RwLock or no lock.
///
/// For types with an RwLock, this enables ManyIterMut
/// to hold the lock-write-guard for duration of the
/// iteration.
enum DataRefMut<'a, V, T>
where
    V: StorageVec<T> + StorageVecRwLock<T> + ?Sized,
{
    RwWriteGuard(AtomicRwWriteGuard<'a, V::LockedData>),
    RefMut(&'a mut V),
}

impl<'a, V, T> DataRefMut<'a, V, T>
where
    V: StorageVec<T> + StorageVecRwLock<T> + ?Sized,
    V::LockedData: StorageVecLockedData<T>,
{
    fn get(&self, i: Index) -> T {
        match self {
            Self::RwWriteGuard(g) => g.deref().get(i),
            Self::RefMut(r) => r.get(i),
        }
    }

    fn set(&mut self, i: Index, value: T) {
        match self {
            Self::RwWriteGuard(g) => g.deref_mut().set(i, value),
            Self::RefMut(r) => r.set(i, value),
        }
    }
}
