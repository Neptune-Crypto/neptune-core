use db_key::Key;
use serde::Serialize;
use twenty_first::shared_math::{b_field_element::BFieldElement, traits::FromVecu8};

pub const BYTES_PER_BFE: usize = 8;
pub const RESCUE_PRIME_OUTPUT_SIZE_IN_BFES: usize = 6;
pub const RESCUE_PRIME_DIGEST_SIZE_IN_BYTES: usize =
    RESCUE_PRIME_OUTPUT_SIZE_IN_BFES * BYTES_PER_BFE;

#[derive(Clone, Copy, Debug, Serialize, serde::Deserialize, PartialEq)]
pub struct RescuePrimeDigest([BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES]);

impl RescuePrimeDigest {
    pub fn values(&self) -> [BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES] {
        self.0
    }

    pub fn new(digest: [BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES]) -> Self {
        Self(digest)
    }
}

impl From<[u8; RESCUE_PRIME_DIGEST_SIZE_IN_BYTES]> for RescuePrimeDigest {
    fn from(item: [u8; RESCUE_PRIME_DIGEST_SIZE_IN_BYTES]) -> Self {
        let bfes: [BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES] =
            [BFieldElement::ring_zero(); RESCUE_PRIME_OUTPUT_SIZE_IN_BFES];
        for i in 0..RESCUE_PRIME_OUTPUT_SIZE_IN_BFES {
            let start_index = i * RESCUE_PRIME_DIGEST_SIZE_IN_BYTES;
            let end_index = (i + 1) * RESCUE_PRIME_DIGEST_SIZE_IN_BYTES;
            bfes[i] = BFieldElement::ring_zero().from_vecu8(item[start_index..end_index].to_vec())
        }

        Self(bfes)
    }
}

impl Key for RescuePrimeDigest {
    fn from_u8(key: &[u8]) -> Self {
        let converted_key: [u8; RESCUE_PRIME_DIGEST_SIZE_IN_BYTES] = key
            .to_owned()
            .try_into()
            .expect("slice with incorrect length used as block hash");
        converted_key.into()
    }

    fn as_slice<T, F: Fn(&[u8]) -> T>(&self, f: F) -> T {
        let u8s: [u8; RESCUE_PRIME_DIGEST_SIZE_IN_BYTES] = self.to_owned().into();
        f(&u8s)
    }
}

impl From<RescuePrimeDigest> for [u8; RESCUE_PRIME_DIGEST_SIZE_IN_BYTES] {
    fn from(item: RescuePrimeDigest) -> Self {
        let u64s = item.0.iter().map(|x| x.value());
        u64s.map(|x| x.to_ne_bytes())
            .collect::<Vec<_>>()
            .concat()
            .try_into()
            .unwrap()
    }
}
