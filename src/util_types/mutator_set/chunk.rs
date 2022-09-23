use serde_big_array;
use serde_big_array::BigArray;
use serde_derive::{Deserialize, Serialize};

use twenty_first::util_types::simple_hasher::{Hashable, Hasher};

use super::shared::{BITS_PER_U32, CHUNK_SIZE};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chunk {
    #[serde(with = "BigArray")]
    pub bits: [u32; CHUNK_SIZE / BITS_PER_U32],
}

impl Chunk {
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

    #[inline]
    fn hash_preimage<H: Hasher>(&self) -> Vec<H::T>
    where
        u128: Hashable<<H as Hasher>::T>,
    {
        self.get_u128s()
            .iter()
            .flat_map(|&val| val.to_sequence())
            .collect()
    }

    pub fn hash<H: Hasher>(&self, hasher: &H) -> H::Digest
    where
        u128: Hashable<<H as Hasher>::T>,
    {
        let seq: Vec<H::T> = self.hash_preimage::<H>();

        hasher.hash_sequence(&seq)
    }
}

#[cfg(test)]
mod chunk_tests {
    use std::collections::HashSet;

    use super::*;
    use num_traits::Zero;
    use rand::{thread_rng, RngCore};
    use twenty_first::shared_math::b_field_element::BFieldElement;
    use twenty_first::shared_math::rescue_prime_regular::RescuePrimeRegular;

    impl Chunk {
        fn default() -> Self {
            Self {
                bits: [0u32; CHUNK_SIZE / BITS_PER_U32],
            }
        }
    }

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
        let mut aw = Chunk::default();
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
        type H = RescuePrimeRegular;

        let zero_chunk = Chunk {
            bits: [0u32; CHUNK_SIZE / BITS_PER_U32],
        };
        let zero_chunk_hash_preimage = zero_chunk.hash_preimage::<H>();
        assert_eq!(get_hashpreimage_length(), zero_chunk_hash_preimage.len());
        for elem in zero_chunk_hash_preimage.iter() {
            assert!(elem.is_zero());
        }

        let mut one_one = Chunk {
            bits: [0u32; CHUNK_SIZE / BITS_PER_U32],
        };
        one_one.set_bit(32);
        let one_one_preimage = one_one.hash_preimage::<H>();

        assert_ne!(zero_chunk_hash_preimage, one_one_preimage);
        assert_eq!(get_hashpreimage_length(), one_one_preimage.len());

        let mut two_ones = Chunk {
            bits: [0u32; CHUNK_SIZE / BITS_PER_U32],
        };
        two_ones.set_bit(32);
        two_ones.set_bit(33);
        let two_ones_preimage = two_ones.hash_preimage::<H>();

        assert_ne!(two_ones_preimage, one_one_preimage);
        assert_ne!(two_ones_preimage, zero_chunk_hash_preimage);

        // Verify that setting any bit produces a unique hash-preimage value
        let mut previous_values: HashSet<Vec<BFieldElement>> = HashSet::new();
        for i in 0..CHUNK_SIZE {
            let mut chunk = Chunk {
                bits: [0u32; CHUNK_SIZE / BITS_PER_U32],
            };
            chunk.set_bit(i);
            assert!(previous_values.insert(chunk.hash_preimage::<H>()));
        }
    }

    #[test]
    fn serialization_test() {
        // TODO: You could argue that this test doesn't belong here, as it tests the behavior of
        // an imported library. I included it here, though, because the setup seems a bit clumsy
        // to me so far.
        let chunk = Chunk {
            bits: [0u32; CHUNK_SIZE / BITS_PER_U32],
        };
        let json = serde_json::to_string(&chunk).unwrap();
        let s_back = serde_json::from_str::<Chunk>(&json).unwrap();
        assert!(s_back.bits.iter().all(|&x| x == 0u32));
    }
}
