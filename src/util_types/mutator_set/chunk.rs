use crate::{
    shared_math::b_field_element::BFieldElement,
    util_types::simple_hasher::{self, ToDigest},
};

use super::set_commitment::CHUNK_SIZE;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Chunk {
    pub bits: [bool; CHUNK_SIZE],
}

impl Chunk {
    const BIT_CAPACITY_PER_BFIELD_ELEMENT: usize = 63;

    #[inline]
    const fn get_hashpreimage_length() -> usize {
        CHUNK_SIZE / Self::BIT_CAPACITY_PER_BFIELD_ELEMENT
            + if CHUNK_SIZE % Self::BIT_CAPACITY_PER_BFIELD_ELEMENT == 0 {
                0
            } else {
                1
            }
    }

    #[inline]
    fn hash_preimage(&self) -> Vec<BFieldElement> {
        let num_iterations = CHUNK_SIZE / Self::BIT_CAPACITY_PER_BFIELD_ELEMENT;
        let mut ret: Vec<BFieldElement> = Vec::with_capacity(Self::get_hashpreimage_length());
        let mut acc: u64;
        for i in 0..num_iterations {
            acc = 0;
            for j in 0..Self::BIT_CAPACITY_PER_BFIELD_ELEMENT {
                acc += if self.bits[i * Self::BIT_CAPACITY_PER_BFIELD_ELEMENT + j] {
                    1 << j
                } else {
                    0
                };
            }
            ret.push(BFieldElement::new(acc));
        }
        if CHUNK_SIZE % Self::BIT_CAPACITY_PER_BFIELD_ELEMENT != 0 {
            acc = 0;
            for j in 0..CHUNK_SIZE % Self::BIT_CAPACITY_PER_BFIELD_ELEMENT {
                acc += if self.bits[num_iterations * Self::BIT_CAPACITY_PER_BFIELD_ELEMENT + j] {
                    1 << j
                } else {
                    0
                };
            }
            ret.push(BFieldElement::new(acc));
        }

        ret
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
    use crate::shared_math::traits::IdentityValues;

    use super::*;

    #[test]
    fn chunk_hashpreimage_test() {
        let zero_chunk = Chunk {
            bits: [false; CHUNK_SIZE],
        };
        let zero_chunk_hash_preimage = zero_chunk.hash_preimage();
        assert_eq!(
            Chunk::get_hashpreimage_length(),
            zero_chunk_hash_preimage.len()
        );
        for elem in zero_chunk_hash_preimage {
            assert!(elem.is_zero());
        }

        let mut one_one = Chunk {
            bits: [false; CHUNK_SIZE],
        };
        one_one.bits[63] = true;
        let one_one_preimage = one_one.hash_preimage();
        assert_eq!(Chunk::get_hashpreimage_length(), one_one_preimage.len());
        assert!(one_one_preimage[0].is_zero());
        assert!(one_one_preimage[1].is_one());
        for i in 2..Chunk::get_hashpreimage_length() {
            assert!(one_one_preimage[i].is_zero());
        }

        let mut two_ones = Chunk {
            bits: [false; CHUNK_SIZE],
        };
        two_ones.bits[63] = true;
        two_ones.bits[64] = true;
        let two_ones_preimage = two_ones.hash_preimage();
        assert!(two_ones_preimage[0].is_zero());
        assert_eq!(3, two_ones_preimage[1].value());
        for i in 2..Chunk::get_hashpreimage_length() {
            assert!(two_ones_preimage[i].is_zero());
        }
    }
}
