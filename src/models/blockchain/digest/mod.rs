pub mod ordered_digest;

use get_size::GetSize;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use twenty_first::shared_math::{b_field_element::BFieldElement, traits::FromVecu8};

pub const BYTES_PER_BFE: usize = 8;
pub const RESCUE_PRIME_OUTPUT_SIZE_IN_BFES: usize = 6;
pub const DEVNET_MSG_DIGEST_SIZE_IN_BYTES: usize = 32;
pub const DEVNET_SECRET_KEY_SIZE_IN_BYTES: usize = 32;
pub const RESCUE_PRIME_DIGEST_SIZE_IN_BYTES: usize =
    RESCUE_PRIME_OUTPUT_SIZE_IN_BFES * BYTES_PER_BFE;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Digest([BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES]);

impl GetSize for Digest {
    fn get_stack_size() -> usize {
        std::mem::size_of::<Self>()
    }

    fn get_heap_size(&self) -> usize {
        // This seems to be the case, see test `get_size`.
        0
    }

    fn get_size(&self) -> usize {
        Self::get_stack_size() + GetSize::get_heap_size(self)
    }
}

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

const DIGEST_SEPARATOR: &str = ",";

//TODO: Use emojihash
impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let string = self.0.map(|elem| elem.to_string()).join(DIGEST_SEPARATOR);
        write!(f, "{}", string)
    }
}

impl FromStr for Digest {
    type Err = String;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let parsed_u64s: Vec<Result<u64, _>> = string
            .split(DIGEST_SEPARATOR)
            .map(|substring| substring.parse::<u64>())
            .collect();
        if parsed_u64s.len() != RESCUE_PRIME_OUTPUT_SIZE_IN_BFES {
            Err("Given invalid number of BFieldElements in string.".to_owned())
        } else {
            let mut bf_elms: Vec<BFieldElement> =
                Vec::with_capacity(RESCUE_PRIME_OUTPUT_SIZE_IN_BFES);
            for parse_result in parsed_u64s {
                if let Ok(content) = parse_result {
                    bf_elms.push(BFieldElement::new(content));
                } else {
                    return Err("Given invalid BFieldElement in string.".to_owned());
                }
            }
            let digest = Digest::from(bf_elms);
            Ok(digest)
        }
    }
}

impl From<Vec<BFieldElement>> for Digest {
    fn from(vals: Vec<BFieldElement>) -> Self {
        Self(
            vals.try_into()
                .expect("Hash function returned bad number of B field elements."),
        )
    }
}

impl From<Digest> for Vec<BFieldElement> {
    fn from(val: Digest) -> Self {
        val.0.to_vec()
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

// The implementations for dev net byte arrays are not to be used on main net
impl From<Digest> for [u8; DEVNET_MSG_DIGEST_SIZE_IN_BYTES] {
    fn from(input: Digest) -> Self {
        let whole: [u8; RESCUE_PRIME_DIGEST_SIZE_IN_BYTES] = input.into();
        whole[0..DEVNET_MSG_DIGEST_SIZE_IN_BYTES]
            .to_vec()
            .try_into()
            .unwrap()
    }
}

#[cfg(test)]
mod digest_tests {
    use super::*;

    #[test]
    fn devnet_signature_digest_conversion_test() {
        let bfe_vec = vec![
            BFieldElement::new(12),
            BFieldElement::new(24),
            BFieldElement::new(36),
            BFieldElement::new(48),
            BFieldElement::new(60),
            BFieldElement::new(70),
        ];
        let rescue_prime_digest_type_from_array: Digest = bfe_vec.into();
        let _shorter: [u8; DEVNET_MSG_DIGEST_SIZE_IN_BYTES] =
            rescue_prime_digest_type_from_array.into();
    }

    #[test]
    pub fn get_size() {
        let stack = crate::models::blockchain::digest::Digest::get_stack_size();

        let bfe_vec = vec![
            BFieldElement::new(12),
            BFieldElement::new(24),
            BFieldElement::new(36),
            BFieldElement::new(48),
            BFieldElement::new(60),
            BFieldElement::new(70),
        ];
        let rescue_prime_digest_type_from_array: crate::models::blockchain::digest::Digest =
            bfe_vec.into();

        let heap = rescue_prime_digest_type_from_array.get_heap_size();

        let total = rescue_prime_digest_type_from_array.get_size();

        println!("stack: {stack} + heap: {heap} = {total}");

        assert_eq!(stack + heap, total)
    }

    #[test]
    pub fn digest_from_str() {
        // This tests a valid digest. It will fail when we change RESCUE_PRIME_OUTPUT_SIZE_IN_BFES.
        let valid_digest_string = "00059361073062755064,05168490802189810700,02524349865623165603,04907779149954626615,01487912569022462807,00000104867047771348";
        let valid_digest = Digest::from_str(valid_digest_string);
        assert!(valid_digest.is_ok());

        // This ensures that it can fail when given a wrong number of BFieldElements.
        let invalid_digest_string = "00059361073062755064,05168490802189810700";
        let invalid_digest = Digest::from_str(invalid_digest_string);
        assert!(invalid_digest.is_err());

        // This ensures that it can fail if given something that isn't a valid string of a BFieldElement.
        let second_invalid_digest_string = "this_is_not_a_bfield_element,05168490802189810700";
        let second_invalid_digest = Digest::from_str(second_invalid_digest_string);
        assert!(second_invalid_digest.is_err());
    }
}
