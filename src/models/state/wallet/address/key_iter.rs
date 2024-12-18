use serde::Deserialize;
use serde::Serialize;

use super::DerivationIndex;
use super::SpendingKey;

// an endless iterator over spending keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingKeyIter {
    curr: SpendingKey,
}
impl SpendingKeyIter {
    pub fn new(curr: SpendingKey) -> Self {
        Self { curr }
    }
}

impl Iterator for SpendingKeyIter {
    type Item = SpendingKey;

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.curr;
        self.curr = key.derive_child(0);
        Some(key)
    }
}

// an iterator over a range of spending keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingKeyRangeIter {
    first: SpendingKey,
    curr: DerivationIndex,
    last: DerivationIndex,
}

impl SpendingKeyRangeIter {
    pub fn new(first: SpendingKey, curr: DerivationIndex, last: DerivationIndex) -> Self {
        Self { first, curr, last }
    }

    pub fn nth(&self, index: DerivationIndex) -> SpendingKey {
        self.first.derive_child(index)
    }
}
impl Iterator for SpendingKeyRangeIter {
    type Item = SpendingKey;

    fn next(&mut self) -> Option<Self::Item> {
        if self.curr <= self.last {
            let key = self.first.derive_child(self.curr);
            self.curr += 1;
            Some(key)
        } else {
            None
        }
    }
}
