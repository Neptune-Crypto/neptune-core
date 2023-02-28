use itertools::Itertools;
use serde_derive::{Deserialize, Serialize};
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::util_types::algebraic_hasher::Hashable;

use super::ibf::InvertibleBloomFilter;
use super::shared::CHUNK_SIZE;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chunk {
    pub bits: Vec<u32>,
}

impl Chunk {
    pub fn empty_chunk() -> Self {
        let bits = vec![];
        Chunk { bits }
    }

    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }

    pub fn insert(&mut self, index: u32) {
        assert!(
            index < CHUNK_SIZE as u32,
            "index cannot exceed chunk size in `set_bit`. CHUNK_SIZE = {}, got index = {}",
            CHUNK_SIZE,
            index
        );
        self.bits.push(index);
        self.bits.sort();
    }

    pub fn remove(&mut self, index: u32) {
        assert!(
            index < CHUNK_SIZE as u32,
            "index cannot exceed chunk size in `unset_bit`. CHUNK_SIZE = {}, got index = {}",
            CHUNK_SIZE,
            index
        );
        let mut drops = vec![];
        for i in 0..self.bits.len() {
            if self.bits[i] == index {
                drops.push(i);
            }
        }

        for d in drops.iter().rev() {
            self.bits.remove(*d);
        }
    }

    pub fn contains(&self, index: u32) -> bool {
        assert!(
            index < CHUNK_SIZE as u32,
            "index cannot exceed chunk size in `get_bit`. CHUNK_SIZE = {}, got index = {}",
            CHUNK_SIZE,
            index
        );

        self.bits.contains(&index)
    }

    /// Return a chunk with indices which are the concatenation and sorting of indices in two input chunks
    pub fn combine(self, other: Self) -> Self {
        let mut ret = Self::empty_chunk();
        for idx in self.bits {
            ret.bits.push(idx);
        }
        for idx in other.bits {
            ret.bits.push(idx);
        }
        ret.bits.sort();
        ret
    }

    pub fn subtract(&mut self, other: Self) {
        for remove_index in other.bits {
            match self.bits.iter().find_position(|x| **x == remove_index) {
                Some((i, _)) => self.bits.remove(i),
                None => panic!("Attempted to remove bit index that was not set in chunk"),
            };
        }
    }

    pub fn to_indices(&self) -> Vec<u128> {
        self.bits.iter().map(|i| *i as u128).collect()
    }

    pub fn from_indices(indices: &[u128]) -> Self {
        let bits = indices.iter().map(|i| *i as u32).collect();
        Chunk { bits }
    }

    pub fn from_slice(sl: &[u32]) -> Chunk {
        Chunk { bits: sl.to_vec() }
    }
}

impl Hashable for Chunk {
    fn to_sequence(&self) -> Vec<BFieldElement> {
        self.bits
            .iter()
            .flat_map(|&val| val.to_sequence())
            .collect()
    }
}

impl InvertibleBloomFilter for Chunk {
    fn increment(&mut self, location: u128) {
        self.bits.push(location as u32);
        self.bits.sort();
    }

    fn decrement(&mut self, location: u128) {
        let mut drop_index = 0;
        let mut found = false;
        for (i, b) in self.bits.iter().enumerate() {
            if *b == location as u32 {
                drop_index = i;
                found = true;
            }
        }
        if found {
            self.bits.remove(drop_index);
        } else {
            panic!("Cannot decrement integer that is already zero.");
        }
    }

    fn isset(&self, location: u128) -> bool {
        self.bits.contains(&(location as u32))
    }
}

#[cfg(test)]
mod chunk_tests {
    use num_traits::Zero;
    use rand::{thread_rng, RngCore};
    use std::collections::HashSet;

    use twenty_first::shared_math::b_field_element::BFieldElement;

    use super::*;

    #[test]
    fn constant_sanity_check_test() {
        // This test assumes that the bits in the chunks window are represented as `u32`s. If they are,
        // then the chunk size should be a multiple of 32.
        assert_eq!(0, CHUNK_SIZE % 32);
    }

    #[test]
    fn get_set_unset_bits_pbt() {
        let mut aw = Chunk::empty_chunk();
        for i in 0..CHUNK_SIZE {
            assert!(!aw.contains(i as u32));
        }

        let mut prng = thread_rng();
        for _ in 0..CHUNK_SIZE {
            let index = prng.next_u32() % CHUNK_SIZE as u32;
            let set = prng.next_u32() % 2 == 0;
            if set {
                aw.insert(index);
            } else {
                aw.remove(index);
            }

            assert_eq!(set, aw.contains(index));
        }

        // Set all bits, then check that they are set
        for i in 0..CHUNK_SIZE {
            aw.insert(i as u32);
        }

        for i in 0..CHUNK_SIZE {
            assert!(aw.contains(i as u32));
        }
    }

    #[test]
    fn chunk_hashpreimage_test() {
        let zero_chunk = Chunk::empty_chunk();
        let zero_chunk_preimage = zero_chunk.to_sequence();
        assert!(zero_chunk_preimage.iter().all(|elem| elem.is_zero()));

        let mut one_chunk = Chunk::empty_chunk();
        one_chunk.insert(32);
        let one_chunk_preimage = one_chunk.to_sequence();

        assert_ne!(zero_chunk_preimage, one_chunk_preimage);

        let mut two_ones_chunk = Chunk::empty_chunk();
        two_ones_chunk.insert(32);
        two_ones_chunk.insert(33);
        let two_ones_preimage = two_ones_chunk.to_sequence();

        assert_ne!(two_ones_preimage, one_chunk_preimage);
        assert_ne!(two_ones_preimage, zero_chunk_preimage);

        // Verify that setting any bit produces a unique hash-preimage value
        let mut previous_values: HashSet<Vec<BFieldElement>> = HashSet::new();
        for i in 0..CHUNK_SIZE {
            let mut chunk = Chunk::empty_chunk();
            chunk.insert(i as u32);
            assert!(previous_values.insert(chunk.to_sequence()));
        }
    }

    #[test]
    fn subtract_and_combine_and_is_empty_test() {
        let mut chunk_a = Chunk::empty_chunk();
        chunk_a.insert(12);
        chunk_a.insert(13);
        chunk_a.insert(48);

        let mut chunk_b = Chunk::empty_chunk();
        chunk_b.insert(48);
        chunk_b.insert(13);

        let mut expected_sub = Chunk::empty_chunk();
        expected_sub.insert(12);

        let mut chunk_c = chunk_a.clone();
        chunk_c.subtract(chunk_b.clone());

        assert_eq!(
            expected_sub, chunk_c,
            "subtract on chunks must behave as expected"
        );

        let mut expected_combine = Chunk::empty_chunk();
        expected_combine.insert(12);
        expected_combine.insert(13);
        expected_combine.insert(13);
        expected_combine.insert(48);
        expected_combine.insert(48);

        chunk_c = chunk_a.clone().combine(chunk_b.clone());
        assert_eq!(
            expected_combine, chunk_c,
            "combine on chunks must behave as expected"
        );

        // Verify that `is_empty` behaves as expected
        assert!(!chunk_a.is_empty());
        assert!(!chunk_b.is_empty());
        assert!(!chunk_c.is_empty());
        assert!(Chunk::empty_chunk().is_empty());
    }

    #[test]
    fn serialization_test() {
        // TODO: You could argue that this test doesn't belong here, as it tests the behavior of
        // an imported library. I included it here, though, because the setup seems a bit clumsy
        // to me so far.
        let chunk = Chunk::empty_chunk();
        let json = serde_json::to_string(&chunk).unwrap();
        let s_back = serde_json::from_str::<Chunk>(&json).unwrap();
        assert!(s_back.bits.iter().all(|&x| x == 0u32));
    }

    #[test]
    fn test_indices() {
        let mut chunk = Chunk::empty_chunk();
        let mut rng = thread_rng();
        let num_insertions = 100;
        for _ in 0..num_insertions {
            let index = rng.next_u32() % (CHUNK_SIZE as u32);
            chunk.insert(index);
        }

        let indices = chunk.to_indices();

        let reconstructed_chunk = Chunk::from_indices(&indices);

        assert_eq!(chunk, reconstructed_chunk);
    }
}
