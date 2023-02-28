use std::ops::Range;

use itertools::Itertools;
use serde::{Deserialize, Serialize};

/// SparseBloomFilter
///
/// A sparse Bloom filter of static length N (number of possible
/// distinct indices) is a
/// list of indices, counting duplicates. The indices
/// live in the range [0; N) and are stored sorted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparseBloomFilter<const N: u128> {
    pub indices: Vec<u128>,
}

#[allow(clippy::new_without_default)]
impl<const N: u128> SparseBloomFilter<N> {
    pub fn new() -> Self {
        SparseBloomFilter {
            indices: Vec::new(),
        }
    }

    pub fn from_multiset(mset: Vec<u128>) -> Self {
        let mut sbf = Self::new();
        for l in mset {
            sbf.increment(l);
        }
        sbf
    }

    /// Grab a slice from the sparse Bloom filter by supplying an
    /// interval. Given how the
    /// sparse Bloom filter is represented (i.e., as a list of
    /// indices), this operation boils down to copying all indices
    /// that live in the range and subtracting the lower bound from
    /// them.
    /// The word "slice" is used in the denotation of submatrices not
    /// rust's contiguous memory structures.
    pub fn slice<const M: u128>(&self, interval: Range<u128>) -> SparseBloomFilter<M> {
        let indices = self
            .indices
            .iter()
            .filter(|l| interval.contains(*l))
            .map(|l| *l - interval.start)
            .collect_vec();
        SparseBloomFilter { indices }
    }

    /// Set range to zero.
    pub fn zerofy(&mut self, lower: u128, upper: u128) {
        // locate
        let mut drops = Vec::new();
        for (location_index, location) in self.indices.iter().enumerate() {
            if lower <= *location && *location < upper {
                drops.push(location_index);
            }
        }

        // drop
        for d in drops.iter().rev() {
            self.indices.remove(*d);
        }
    }

    /// Return true iff there is a set integer in the given range.
    pub fn hasset(&self, lower: u128, upper: u128) -> bool {
        for location in self.indices.iter() {
            if lower <= *location && *location < upper {
                return true;
            }
        }
        false
    }

    pub fn to_vec_u32(&self) -> Vec<u32> {
        let mut vector = vec![];
        for i in self.indices.iter() {
            vector.push(((i >> 96) & 0xffffffff) as u32);
            vector.push(((i >> 64) & 0xffffffff) as u32);
            vector.push(((i >> 32) & 0xffffffff) as u32);
            vector.push((i & 0xffffffff) as u32);
        }
        vector.to_vec()
    }

    pub fn from_vec_u32(vector: &[u32]) -> SparseBloomFilter<N> {
        let mut indices = Vec::<u128>::new();
        for chunk in vector.chunks(4) {
            let mut acc = 0;
            for c in chunk {
                acc = (acc << 32) | *c as u128;
            }
            indices.push(acc);
        }
        SparseBloomFilter { indices }
    }
}

pub trait InvertibleBloomFilter {
    fn increment(&mut self, location: u128);
    fn decrement(&mut self, location: u128);
    fn isset(&self, location: u128) -> bool;
}

impl<const N: u128> InvertibleBloomFilter for SparseBloomFilter<N> {
    fn increment(&mut self, location: u128) {
        // locate
        let mut found = false;
        let mut insert_index = 0;
        for (index, loc) in self.indices.iter().enumerate() {
            if *loc == location {
                found = true;
                insert_index = index;
            }
        }

        if found {
            self.indices.insert(insert_index, location);
        } else {
            self.indices.push(location);
            self.indices.sort();
        }
    }

    fn decrement(&mut self, location: u128) {
        // locate
        let mut found = false;
        let mut drop_index = 0;
        for (index, loc) in self.indices.iter().enumerate() {
            if *loc == location {
                found = true;
                drop_index = index;
            }
        }

        // if found, drop
        if found {
            self.indices.remove(drop_index);
        }

        // if not found, the indicated integer is zero
        if !found {
            panic!("Decremented integer is already zero.");
        }
    }

    fn isset(&self, location: u128) -> bool {
        for loc in self.indices.iter() {
            if *loc == location {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod ibf_tests {
    use rand::{thread_rng, RngCore};

    use super::*;

    #[test]
    fn test_populate_depopulate() {
        let num_actions = 1 << 14;
        const N: u128 = 1024;
        let mut ibf = SparseBloomFilter::<N>::new();
        let mut index_set = vec![];
        let mut rng = thread_rng();
        for _ in 0..num_actions {
            if index_set.is_empty() || rng.next_u32() % 2 == 1 {
                let location = rng.next_u32() as u128 % N;
                ibf.increment(location);
                index_set.push(location);
            } else {
                let idx = rng.next_u32() as u128 % index_set.len() as u128;
                let location = index_set[idx as usize];
                ibf.decrement(location);
                index_set.remove(idx as usize);
            }

            for idx in index_set.iter() {
                assert!(ibf.isset(*idx));
            }
            let test_index = rng.next_u32() as u128 % N;
            if !index_set.contains(&test_index) {
                assert!(!ibf.isset(test_index));
            }
        }
    }

    #[test]
    fn test_vectorize() {
        let num_actions = 1 << 14;
        const N: u128 = 1024;
        let mut ibf = SparseBloomFilter::<N>::new();
        let mut index_set = vec![];
        let mut rng = thread_rng();
        for _ in 0..num_actions {
            if index_set.is_empty() || rng.next_u32() % 2 == 1 {
                let location = rng.next_u32() as u128 % N;
                ibf.increment(location);
                index_set.push(location);
            } else {
                let idx = rng.next_u32() as u128 % index_set.len() as u128;
                let location = index_set[idx as usize];
                ibf.decrement(location);
                index_set.remove(idx as usize);
            }
        }

        let vectorized = ibf.to_vec_u32();
        let unvectorized = SparseBloomFilter::from_vec_u32(&vectorized);
        assert_eq!(unvectorized, ibf);
    }
}
