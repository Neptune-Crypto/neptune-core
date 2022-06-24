use db_key::Key;
use serde::Serialize;
use twenty_first::shared_math::{b_field_element::BFieldElement, traits::FromVecu8};

use super::{BYTES_PER_BFE, RESCUE_PRIME_DIGEST_SIZE_IN_BYTES, RESCUE_PRIME_OUTPUT_SIZE_IN_BFES};

// The data structure `RescuePrimeDigest` is primarily needed, so we can make
// database keys out of rescue prime digests.
#[derive(Clone, Copy, Debug, Serialize, serde::Deserialize, PartialEq)]
pub struct KeyableDigest([BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES]);

impl KeyableDigest {
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

impl From<[u8; RESCUE_PRIME_DIGEST_SIZE_IN_BYTES]> for KeyableDigest {
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

impl From<[BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES]> for KeyableDigest {
    fn from(array: [BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES]) -> Self {
        KeyableDigest(array)
    }
}

impl From<KeyableDigest> for [BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES] {
    fn from(val: KeyableDigest) -> Self {
        val.0
    }
}

impl From<Vec<BFieldElement>> for KeyableDigest {
    fn from(elems: Vec<BFieldElement>) -> Self {
        let argument_length = elems.len();
        let array: [BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES] =
            elems.try_into().unwrap_or_else(|_| {
                panic!(
                    "Digest must have length {}. Got: {}",
                    RESCUE_PRIME_OUTPUT_SIZE_IN_BFES, argument_length
                )
            });

        array.into()
    }
}

impl From<KeyableDigest> for Vec<BFieldElement> {
    fn from(val: KeyableDigest) -> Self {
        val.0.to_vec()
    }
}

impl Key for KeyableDigest {
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

impl From<KeyableDigest> for [u8; RESCUE_PRIME_DIGEST_SIZE_IN_BYTES] {
    fn from(item: KeyableDigest) -> Self {
        let u64s = item.0.iter().map(|x| x.value());
        u64s.map(|x| x.to_ne_bytes())
            .collect::<Vec<_>>()
            .concat()
            .try_into()
            .unwrap()
    }
}

#[cfg(test)]
mod digest_tests {
    use super::*;

    #[test]
    fn digest_conversion_bytes_test() {
        let bytes: [u8; 48] = [
            233u8, 98, 63, 126, 235, 100, 36, 0, 180, 31, 210, 220, 41, 70, 233, 224, 138, 178, 41,
            219, 14, 203, 155, 214, 203, 227, 78, 111, 164, 128, 128, 236, 166, 4, 248, 213, 253,
            7, 230, 222, 16, 130, 56, 160, 127, 32, 132, 196,
        ];
        let rescue_prime_digest_type: KeyableDigest = bytes.into();
        let back_to_bytes: [u8; 48] = rescue_prime_digest_type.into();
        assert_eq!(bytes, back_to_bytes);
    }

    #[test]
    fn digest_conversion_bfes_test() {
        // Conversion with array
        let bfe_array = [
            BFieldElement::new(12),
            BFieldElement::new(24),
            BFieldElement::new(36),
            BFieldElement::new(48),
            BFieldElement::new(60),
            BFieldElement::new(70),
        ];
        let rescue_prime_digest_type_from_array: KeyableDigest = bfe_array.into();
        let back_to_bfes_from_array: [BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES] =
            rescue_prime_digest_type_from_array.into();
        assert_eq!(
            bfe_array, back_to_bfes_from_array,
            "Converting to and from a BFE array must be the identity operator"
        );

        // Same but for a vector
        let bfe_vec = vec![
            BFieldElement::new(12),
            BFieldElement::new(24),
            BFieldElement::new(36),
            BFieldElement::new(48),
            BFieldElement::new(60),
            BFieldElement::new(70),
        ];
        let rescue_prime_digest_type_from_vec: KeyableDigest = bfe_vec.clone().into();
        let back_to_bfes_from_vec: Vec<BFieldElement> = rescue_prime_digest_type_from_vec.into();
        assert_eq!(
            bfe_vec, back_to_bfes_from_vec,
            "Converting to and from a BFE vector must be the identity operator"
        );

        // Sanity check that both conversions agree
        assert_eq!(
            rescue_prime_digest_type_from_array, rescue_prime_digest_type_from_vec,
            "Conversion from vector and array must agree"
        );
    }
}
