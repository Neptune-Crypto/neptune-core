pub mod keyable_digest;
pub mod ordered_digest;

use serde::{Deserialize, Serialize};
use twenty_first::shared_math::{b_field_element::BFieldElement, traits::FromVecu8};

use self::keyable_digest::KeyableDigest;

pub const BYTES_PER_BFE: usize = 8;
pub const RESCUE_PRIME_OUTPUT_SIZE_IN_BFES: usize = 6;
pub const DEVNET_SIGNATURE_SIZE_IN_BYTES: usize = 32;
pub const RESCUE_PRIME_DIGEST_SIZE_IN_BYTES: usize =
    RESCUE_PRIME_OUTPUT_SIZE_IN_BFES * BYTES_PER_BFE;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub struct Digest([BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES]);

pub trait Hashable {
    fn hash(&self) -> Digest;
}

impl Digest {
    pub fn values(&self) -> [BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES] {
        self.0
    }

    pub const fn new(digest: [BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES]) -> Self {
        Self(digest)
    }

    pub const fn default() -> Self {
        Self([BFieldElement::ring_zero(); RESCUE_PRIME_OUTPUT_SIZE_IN_BFES])
    }
}

impl From<Vec<BFieldElement>> for Digest {
    fn from(vals: Vec<BFieldElement>) -> Self {
        Self(
            vals.try_into()
                .expect("Hash function returned bad number of B field elements"),
        )
    }
}

impl From<Digest> for Vec<BFieldElement> {
    fn from(val: Digest) -> Self {
        val.0.to_vec()
    }
}

impl From<Digest> for KeyableDigest {
    fn from(digest: Digest) -> Self {
        Self::new(digest.values())
    }
}

impl From<Digest> for [u8; RESCUE_PRIME_DIGEST_SIZE_IN_BYTES] {
    fn from(item: Digest) -> Self {
        let u64s = item.0.iter().map(|x| x.value());
        u64s.map(|x| x.to_ne_bytes())
            .collect::<Vec<_>>()
            .concat()
            .try_into()
            .unwrap()
    }
}

impl From<[u8; RESCUE_PRIME_DIGEST_SIZE_IN_BYTES]> for Digest {
    fn from(item: [u8; RESCUE_PRIME_DIGEST_SIZE_IN_BYTES]) -> Self {
        let mut bfes: [BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES] =
            [BFieldElement::ring_zero(); RESCUE_PRIME_OUTPUT_SIZE_IN_BFES];
        for (i, bfe) in bfes.iter_mut().enumerate() {
            let start_index = i * BYTES_PER_BFE;
            let end_index = (i + 1) * BYTES_PER_BFE;
            *bfe = BFieldElement::ring_zero().from_vecu8(item[start_index..end_index].to_vec())
        }

        Self(bfes)
    }
}
