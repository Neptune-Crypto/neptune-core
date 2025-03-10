use serde::de::DeserializeOwned;
use serde::Serialize;

use super::Index;

#[derive(Debug, Clone, Default)]
pub(crate) struct OrdinaryVecPrivate<T>(pub(super) Vec<T>);

impl<T: Serialize + DeserializeOwned + Clone + Send + Sync + 'static> OrdinaryVecPrivate<T> {
    #[inline]
    pub(super) fn get(&self, index: Index) -> T {
        self.0
            .get(index as usize)
            .unwrap_or_else(|| {
                panic!(
                    "Out-of-bounds. Got index {} but length was {}.",
                    index,
                    self.0.len(),
                )
            })
            .clone()
    }

    pub(super) fn get_many(&self, indices: &[Index]) -> Vec<T> {
        indices.iter().map(|i| self.get(*i)).collect()
    }

    pub(super) fn get_all(&self) -> Vec<T> {
        self.0.clone()
    }

    #[inline]
    pub(super) fn set(&mut self, index: Index, value: T) {
        self.0[index as usize] = value;
    }

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
        for (key, val) in key_vals {
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
