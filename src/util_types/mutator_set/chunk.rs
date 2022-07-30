use serde_big_array;
use serde_big_array::BigArray;
use serde_derive::{Deserialize, Serialize};

use twenty_first::{
    shared_math::b_field_element::BFieldElement,
    util_types::simple_hasher::{self, ToDigest},
};

use super::shared::{BITS_PER_U32, CHUNK_SIZE};

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
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

    #[inline]
    fn hash_preimage(&self) -> Vec<BFieldElement> {
        self.bits.iter().map(|&val| val.into()).collect()
    }

    pub fn hash<H: simple_hasher::Hasher>(&self, hasher: &H) -> H::Digest
    where
        Vec<BFieldElement>: ToDigest<H::Digest>,
    {
        let preimage = self.hash_preimage();

        hasher.hash(&preimage.to_digest())
    }
}

#[cfg(test)]
mod chunk_tests {
    use rand::{thread_rng, RngCore};

    use twenty_first::shared_math::traits::IdentityValues;

    use super::*;

    impl Chunk {
        fn default() -> Self {
            Self {
                bits: [0u32; CHUNK_SIZE / BITS_PER_U32],
            }
        }
    }

    #[inline]
    const fn get_hashpreimage_length() -> usize {
        // This assumes that CHUNK_SIZE is a multiple of 32
        CHUNK_SIZE / BITS_PER_U32
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
        let zero_chunk = Chunk {
            bits: [0u32; CHUNK_SIZE / BITS_PER_U32],
        };
        let zero_chunk_hash_preimage = zero_chunk.hash_preimage();
        assert_eq!(get_hashpreimage_length(), zero_chunk_hash_preimage.len());
        for elem in zero_chunk_hash_preimage {
            assert!(elem.is_zero());
        }

        let mut one_one = Chunk {
            bits: [0u32; CHUNK_SIZE / BITS_PER_U32],
        };
        one_one.set_bit(32);
        let one_one_preimage = one_one.hash_preimage();
        assert_eq!(get_hashpreimage_length(), one_one_preimage.len());
        assert!(one_one_preimage[0].is_zero());
        assert!(one_one_preimage[1].is_one());
        for i in 2..get_hashpreimage_length() {
            assert!(one_one_preimage[i].is_zero());
        }

        let mut two_ones = Chunk {
            bits: [0u32; CHUNK_SIZE / BITS_PER_U32],
        };
        two_ones.set_bit(32);
        two_ones.set_bit(33);
        let two_ones_preimage = two_ones.hash_preimage();
        assert!(two_ones_preimage[0].is_zero());
        assert_eq!(3, two_ones_preimage[1].value());
        for i in 2..get_hashpreimage_length() {
            assert!(two_ones_preimage[i].is_zero());
        }
    }

    #[test]
    fn chunk_hashpreimage_big_test() {
        let mut chunk = Chunk {
            bits: [0u32; CHUNK_SIZE / BITS_PER_U32],
        };

        // Verify that the hash preimage is producted according to expectations.
        chunk.set_bit(CHUNK_SIZE - 1 - BITS_PER_U32);
        let hashpreimage = chunk.hash_preimage();
        let mut expected = [BFieldElement::ring_zero(); get_hashpreimage_length()];
        expected[get_hashpreimage_length() - 2] = BFieldElement::new(1u64 << 31);
        assert_eq!(expected.to_vec(), hashpreimage);
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
