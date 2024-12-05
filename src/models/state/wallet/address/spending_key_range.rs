use rayon::prelude::IntoParallelIterator;
use serde::Deserialize;
use serde::Serialize;

use super::par_iter::SpendingKeyParallelIter;
use super::DerivationIndex;
use super::SpendingKey;
use super::SpendingKeyIter;

/// Represents a range of spending keys.
///
/// The range starts with `first` child-key of parent_key and ends with `last`
/// child-key of parent_key.
///
/// child keys can be derived via `parent_key.derive_child(n)`.
///
/// Alternatively, an iterator can be used via iter(), par_iter(), into_iter(),
/// into_par_iter().  note that iterators are limited to usize::MAX.
///
/// note: first and last fields are used rather than a RangeInclusive<T> because
/// this type is intended for usage in the RPC API, and distinct integer fields
/// should be more portable across languages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendingKeyRange {
    pub parent_key: SpendingKey,
    pub first: DerivationIndex,
    pub last: DerivationIndex,
}
impl IntoIterator for SpendingKeyRange {
    type Item = SpendingKey;
    type IntoIter = SpendingKeyIter;

    // panics if the range > usize::MAX
    fn into_iter(self) -> Self::IntoIter {
        self.parent_key.into_range_iter(0..=self.last)
    }
}
impl IntoParallelIterator for SpendingKeyRange {
    type Item = SpendingKey;
    type Iter = SpendingKeyParallelIter;

    // panics if the range > usize::MAX
    fn into_par_iter(self) -> Self::Iter {
        self.parent_key.into_par_range_iter(0..=self.last)
    }
}
impl SpendingKeyRange {
    /// instantiate a new `SpendingKeyRange`
    pub fn new(parent_key: SpendingKey, first: DerivationIndex, last: DerivationIndex) -> Self {
        Self {
            parent_key,
            first,
            last,
        }
    }

    /// create a [SpendingKeyIter]
    ///
    /// panics if the range > usize::MAX
    pub fn iter(&self) -> SpendingKeyIter {
        self.parent_key.into_range_iter(self.first..=self.last)
    }

    /// create a [SpendingKeyParallelIter]
    ///
    /// panics if the range > usize::MAX
    pub fn par_iter(&self) -> SpendingKeyParallelIter {
        self.parent_key.into_par_range_iter(self.first..=self.last)
    }
}
