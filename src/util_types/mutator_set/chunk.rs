use itertools::Itertools;
use num_traits::Zero;
use serde_big_array;
use serde_big_array::BigArray;
use serde_derive::{Deserialize, Serialize};
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::util_types::algebraic_hasher::Hashable;

use super::shared::{BITS_PER_U32, CHUNK_SIZE};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chunk {
    #[serde(with = "BigArray")]
    pub bits: [u32; CHUNK_SIZE as usize / BITS_PER_U32 as usize],
}

impl Chunk {
    pub fn empty_chunk() -> Self {
        let bits = [0; CHUNK_SIZE as usize / BITS_PER_U32 as usize];
        Chunk { bits }
    }

    pub fn set_bit(&mut self, index: usize) {
        assert!(
            index < CHUNK_SIZE as usize,
            "index cannot exceed chunk size in `set_bit`. CHUNK_SIZE = {}, got index = {}",
            CHUNK_SIZE,
            index
        );
        self.bits[index / BITS_PER_U32 as usize] |= 1u32 << (index % BITS_PER_U32 as usize);
    }

    pub fn unset_bit(&mut self, index: usize) {
        assert!(
            index < CHUNK_SIZE as usize,
            "index cannot exceed chunk size in `unset_bit`. CHUNK_SIZE = {}, got index = {}",
            CHUNK_SIZE,
            index
        );
        self.bits[index / BITS_PER_U32 as usize] &=
            0xFFFFFFFFu32 ^ (1u32 << (index % BITS_PER_U32 as usize));
    }

    pub fn get_bit(&self, index: usize) -> bool {
        assert!(
            index < CHUNK_SIZE as usize,
            "index cannot exceed chunk size in `get_bit`. CHUNK_SIZE = {}, got index = {}",
            CHUNK_SIZE,
            index
        );

        self.bits[index / BITS_PER_U32 as usize] & (1u32 << (index % BITS_PER_U32 as usize)) != 0
    }

    pub fn or(self, other: Self) -> Self {
        let mut ret = Self::empty_chunk();
        for ((ret_elem, self_element), other_element) in ret
            .bits
            .iter_mut()
            .zip_eq(self.bits.into_iter())
            .zip_eq(other.bits.into_iter())
        {
            *ret_elem = self_element | other_element;
        }

        ret
    }

    pub fn xor(&mut self, other: Self) {
        for (self_element, other_element) in self.bits.iter_mut().zip_eq(other.bits.into_iter()) {
            *self_element ^= other_element;
        }
    }

    pub fn and(self, other: Self) -> Self {
        let mut ret = Self::empty_chunk();
        for ((ret_elem, self_element), other_element) in ret
            .bits
            .iter_mut()
            .zip_eq(self.bits.into_iter())
            .zip_eq(other.bits.into_iter())
        {
            *ret_elem = self_element & other_element;
        }

        ret
    }

    pub fn is_unset(&self) -> bool {
        self.bits.iter().all(|x| x.is_zero())
    }

    /// Return the length of the Vec<u128>-representation of the active window
    const fn get_u128s_length() -> usize {
        if CHUNK_SIZE % (8 * 16) == 0 {
            CHUNK_SIZE as usize / (8 * 16)
        } else {
            CHUNK_SIZE as usize / (8 * 16) + 1
        }
    }

    /// Return the Vec<u128> representation of the bits in ActiveWindow.
    /// todo: improve comment or drop function
    fn get_u128s(&self) -> Vec<u128> {
        let mut u128s: Vec<u128> = vec![0u128; Self::get_u128s_length()];
        for i in 0..(CHUNK_SIZE / BITS_PER_U32) as usize {
            let shift = 32 * (i % 4) as u128;
            u128s[i / 4] += (self.bits[i] as u128 * (1 << shift)) as u128;
        }

        u128s
    }

    pub fn to_indices(&self) -> Vec<u128> {
        let mut vector = vec![];
        for (i, int) in self.bits.iter().enumerate() {
            for sh in (0..32).rev() {
                if int & (1 << sh) != 0 {
                    vector.push((i as u128) << 5 | sh);
                }
            }
        }
        vector
    }

    pub fn from_indices(indices: &[u128]) -> Self {
        let bits = [0u32; (CHUNK_SIZE / BITS_PER_U32) as usize];
        let mut chunk = Chunk { bits };
        for index in indices.iter() {
            chunk.set_bit(*index as usize);
        }
        chunk
    }

    pub fn from_slice(sl: &[u32]) -> Chunk {
        assert!(sl.len() <= (CHUNK_SIZE / BITS_PER_U32) as usize);
        let mut bits = [0u32; (CHUNK_SIZE / BITS_PER_U32) as usize];
        for (i, int) in sl.iter().enumerate() {
            bits[i] = *int;
        }
        Chunk { bits }
    }
}

impl Hashable for Chunk {
    fn to_sequence(&self) -> Vec<BFieldElement> {
        self.get_u128s()
            .iter()
            .flat_map(|&val| val.to_sequence())
            .collect()
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
            assert!(!aw.get_bit(i as usize));
        }

        let mut prng = thread_rng();
        for _ in 0..CHUNK_SIZE {
            let index = prng.next_u32() as usize % CHUNK_SIZE as usize;
            let set = prng.next_u32() % 2 == 0;
            if set {
                aw.set_bit(index);
            } else {
                aw.unset_bit(index);
            }

            assert!(set == aw.get_bit(index));
        }

        // Set all bits, then check that they are set
        for i in 0..CHUNK_SIZE {
            aw.set_bit(i as usize);
        }

        for i in 0..CHUNK_SIZE / BITS_PER_U32 {
            assert_eq!(0xFFFFFFFFu32, aw.bits[i as usize]);
        }

        for i in 0..CHUNK_SIZE {
            assert!(aw.get_bit(i as usize));
        }
    }

    #[test]
    fn chunk_hashpreimage_test() {
        let zero_chunk = Chunk::empty_chunk();
        let zero_chunk_preimage = zero_chunk.to_sequence();
        assert!(zero_chunk_preimage.iter().all(|elem| elem.is_zero()));

        let mut one_chunk = Chunk::empty_chunk();
        one_chunk.set_bit(32);
        let one_chunk_preimage = one_chunk.to_sequence();

        assert_ne!(zero_chunk_preimage, one_chunk_preimage);

        let mut two_ones_chunk = Chunk::empty_chunk();
        two_ones_chunk.set_bit(32);
        two_ones_chunk.set_bit(33);
        let two_ones_preimage = two_ones_chunk.to_sequence();

        assert_ne!(two_ones_preimage, one_chunk_preimage);
        assert_ne!(two_ones_preimage, zero_chunk_preimage);

        // Verify that setting any bit produces a unique hash-preimage value
        let mut previous_values: HashSet<Vec<BFieldElement>> = HashSet::new();
        for i in 0..CHUNK_SIZE {
            let mut chunk = Chunk::empty_chunk();
            chunk.set_bit(i as usize);
            assert!(previous_values.insert(chunk.to_sequence()));
        }
    }

    #[test]
    fn xor_and_and_and_is_unset_test() {
        let mut chunk_a = Chunk::empty_chunk();
        chunk_a.set_bit(12);
        chunk_a.set_bit(13);

        let mut chunk_b = Chunk::empty_chunk();
        chunk_b.set_bit(48);
        chunk_b.set_bit(13);

        let mut expected_xor = Chunk::empty_chunk();
        expected_xor.set_bit(12);
        expected_xor.set_bit(48);

        let mut chunk_c = chunk_a;
        chunk_c.xor(chunk_b);

        assert_eq!(
            expected_xor, chunk_c,
            "XOR on chunks must behave as expected"
        );

        let mut expected_and = Chunk::empty_chunk();
        expected_and.set_bit(13);

        chunk_c = chunk_a.and(chunk_b);
        assert_eq!(
            expected_and, chunk_c,
            "AND on chunks must behave as expected"
        );

        // Verify that `is_unset` behaves as expected
        assert!(!chunk_a.is_unset());
        assert!(!chunk_b.is_unset());
        assert!(!chunk_c.is_unset());
        assert!(Chunk::empty_chunk().is_unset());
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
            let index = (rng.next_u32() as usize) % (CHUNK_SIZE as usize);
            chunk.set_bit(index);
        }

        let indices = chunk.to_indices();

        let reconstructed_chunk = Chunk::from_indices(&indices);

        assert_eq!(chunk, reconstructed_chunk);
    }
}
