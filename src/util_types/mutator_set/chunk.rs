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
    pub bits: [u32; CHUNK_SIZE / BITS_PER_U32],
}

impl Default for Chunk {
    fn default() -> Self {
        Self {
            bits: [0u32; CHUNK_SIZE / BITS_PER_U32],
        }
    }
}

impl Chunk {
    pub fn empty_chunk() -> Self {
        let bits = [0; CHUNK_SIZE / BITS_PER_U32];
        Chunk { bits }
    }

    pub fn set_bit(&mut self, index: usize) {
        assert!(
            index < CHUNK_SIZE,
            "index cannot exceed chunk size in `set_bit`. CHUNK_SIZE = {}, got index = {}",
            CHUNK_SIZE,
            index
        );
        self.bits[index / BITS_PER_U32] |= 1u32 << (index % BITS_PER_U32);
    }

    pub fn unset_bit(&mut self, index: usize) {
        assert!(
            index < CHUNK_SIZE,
            "index cannot exceed chunk size in `unset_bit`. CHUNK_SIZE = {}, got index = {}",
            CHUNK_SIZE,
            index
        );
        self.bits[index / BITS_PER_U32] &= 0xFFFFFFFFu32 ^ (1u32 << (index % BITS_PER_U32));
    }

    pub fn get_bit(&self, index: usize) -> bool {
        assert!(
            index < CHUNK_SIZE,
            "index cannot exceed chunk size in `get_bit`. CHUNK_SIZE = {}, got index = {}",
            CHUNK_SIZE,
            index
        );

        self.bits[index / BITS_PER_U32] & (1u32 << (index % BITS_PER_U32)) != 0
    }

    pub fn or(self, other: Self) -> Self {
        let mut ret = Self::default();
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
        let mut ret = Self::default();
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
            CHUNK_SIZE / (8 * 16)
        } else {
            CHUNK_SIZE / (8 * 16) + 1
        }
    }

    /// Return the Vec<u128> representation of the bits in ActiveWindow.
    fn get_u128s(&self) -> Vec<u128> {
        let mut u128s: Vec<u128> = vec![0u128; Self::get_u128s_length()];
        for i in 0..(CHUNK_SIZE / BITS_PER_U32) {
            let shift = 32 * (i % 4) as u128;
            u128s[i / 4] += (self.bits[i] as u128 * (1 << shift)) as u128;
        }

        u128s
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

    #[inline]
    const fn get_hashpreimage_length() -> usize {
        // This assumes that CHUNK_SIZE is not a multiple of 128
        CHUNK_SIZE / BITS_PER_U32 / 4 * 5 + 5
    }

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
            assert!(!aw.get_bit(i));
        }

        let mut prng = thread_rng();
        for _ in 0..CHUNK_SIZE {
            let index = prng.next_u32() as usize % CHUNK_SIZE;
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
            aw.set_bit(i);
        }

        for i in 0..CHUNK_SIZE / BITS_PER_U32 {
            assert_eq!(0xFFFFFFFFu32, aw.bits[i]);
        }

        for i in 0..CHUNK_SIZE {
            assert!(aw.get_bit(i));
        }
    }

    #[test]
    fn chunk_hashpreimage_test() {
        let zero_chunk = Chunk::empty_chunk();
        let zero_chunk_preimage = zero_chunk.to_sequence();
        assert_eq!(get_hashpreimage_length(), zero_chunk_preimage.len());
        assert!(zero_chunk_preimage.iter().all(|elem| elem.is_zero()));

        let mut one_chunk = Chunk::empty_chunk();
        one_chunk.set_bit(32);
        let one_chunk_preimage = one_chunk.to_sequence();

        assert_ne!(zero_chunk_preimage, one_chunk_preimage);
        assert_eq!(get_hashpreimage_length(), one_chunk_preimage.len());

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
            chunk.set_bit(i);
            assert!(previous_values.insert(chunk.to_sequence()));
        }
    }

    #[test]
    fn xor_and_and_and_is_unset_test() {
        let mut chunk_a = Chunk::default();
        chunk_a.set_bit(12);
        chunk_a.set_bit(13);

        let mut chunk_b = Chunk::default();
        chunk_b.set_bit(48);
        chunk_b.set_bit(13);

        let mut expected_xor = Chunk::default();
        expected_xor.set_bit(12);
        expected_xor.set_bit(48);

        let mut chunk_c = chunk_a;
        chunk_c.xor(chunk_b);

        assert_eq!(
            expected_xor, chunk_c,
            "XOR on chunks must behave as expected"
        );

        let mut expected_and = Chunk::default();
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
        assert!(Chunk::default().is_unset());
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
}
