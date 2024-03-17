use super::{traits::*, Index};

#[derive(Debug, Clone, Default)]
pub(crate) struct OrdinaryVecPrivate<T>(pub(super) Vec<T>);

impl<T: Clone> StorageVecLockedData<T> for OrdinaryVecPrivate<T> {
    #[inline]
    fn get(&self, index: Index) -> T {
        self.0.get(index as usize).unwrap().clone()
    }

    #[inline]
    fn set(&mut self, index: Index, value: T) {
        self.0[index as usize] = value;
    }
}

impl<T: Clone> OrdinaryVecPrivate<T> {
    #[inline]
    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline]
    pub(super) fn len(&self) -> Index {
        self.0.len() as Index
    }

    #[inline]
    pub(super) fn set_many(&mut self, key_vals: impl IntoIterator<Item = (Index, T)>) {
        for (key, val) in key_vals.into_iter() {
            self.set(key, val);
        }
    }

    #[inline]
    pub(super) fn pop(&mut self) -> Option<T> {
        self.0.pop()
    }

    #[inline]
    pub(super) fn push(&mut self, value: T) {
        self.0.push(value);
    }

    #[inline]
    pub(super) fn clear(&mut self) {
        self.0.clear();
    }
}
