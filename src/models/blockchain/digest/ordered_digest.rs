use num_bigint::BigUint;
use num_traits::Zero;
use serde::Serialize;
use twenty_first::shared_math::b_field_element::BFieldElement;

use super::{Digest, RESCUE_PRIME_OUTPUT_SIZE_IN_BFES};

// The data structure `RescuePrimeDigest` is primarily needed, so we can make
// database keys out of rescue prime digests.
/// Type for ordered digests. The digest is considered a big-endian unsigned integer
/// written in base BFieldElement::QUOTIENT.
#[derive(Clone, Copy, Debug, Serialize, serde::Deserialize, PartialEq)]
pub struct OrderedDigest([BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES]);

// Digest needs a partial ordering for the mining/PoW process, to check if
// a digest is below the difficulty threshold.
impl PartialOrd for OrderedDigest {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        for i in (0..RESCUE_PRIME_OUTPUT_SIZE_IN_BFES).rev() {
            if self.0[i].value() != other.0[i].value() {
                return self.0[i].value().partial_cmp(&other.0[i].value());
            }
        }

        None
    }
}

impl OrderedDigest {
    pub const fn default() -> Self {
        Self([BFieldElement::ring_zero(); RESCUE_PRIME_OUTPUT_SIZE_IN_BFES])
    }

    pub const fn new(digest: [BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES]) -> Self {
        Self(digest)
    }
}

impl From<BigUint> for OrderedDigest {
    fn from(biguint: BigUint) -> Self {
        let mut remaining = biguint;
        let mut ret = OrderedDigest::default();
        let modulus: BigUint = BFieldElement::QUOTIENT.into();
        for i in 0..RESCUE_PRIME_OUTPUT_SIZE_IN_BFES {
            let resulting_u64: u64 = (remaining.clone() % modulus.clone()).try_into().unwrap();
            ret.0[i] = BFieldElement::new(resulting_u64);
            remaining /= modulus.clone();
        }

        assert!(
            remaining.is_zero(),
            "Overflow when converting from BigUint to OrderedDigest"
        );

        ret
    }
}

impl From<Digest> for OrderedDigest {
    fn from(digest: Digest) -> Self {
        Self(digest.values())
    }
}

#[cfg(test)]
mod digest_tests {
    use super::*;

    #[test]
    #[should_panic(expected = "Overflow when converting from BigUint to OrderedDigest")]
    fn digest_biguint_overflow_test() {
        let mut two_pow_384: BigUint = (1u128 << 96).into();
        two_pow_384 = two_pow_384.pow(4);
        let _failing_conversion: OrderedDigest = two_pow_384.into();
    }

    #[test]
    fn digest_biguint_conversion_simple_test() {
        let fourteen: BigUint = 14u128.into();
        let bfe_max: BigUint = BFieldElement::MAX.into();
        let bfe_max_plus_one: BigUint = BFieldElement::QUOTIENT.into();
        let two_pow_64: BigUint = (1u128 << 64).into();
        let two_pow_123: BigUint = (1u128 << 123).into();
        let mut two_pow_351: BigUint = (1u128 << 70).into();
        two_pow_351 = two_pow_351.pow(5);
        two_pow_351 = two_pow_351 * 2u32;
        assert_eq!(
            OrderedDigest([
                BFieldElement::new(14),
                BFieldElement::ring_zero(),
                BFieldElement::ring_zero(),
                BFieldElement::ring_zero(),
                BFieldElement::ring_zero(),
                BFieldElement::ring_zero()
            ]),
            fourteen.into()
        );
        assert_eq!(
            OrderedDigest([
                BFieldElement::new(BFieldElement::MAX),
                BFieldElement::ring_zero(),
                BFieldElement::ring_zero(),
                BFieldElement::ring_zero(),
                BFieldElement::ring_zero(),
                BFieldElement::ring_zero()
            ]),
            bfe_max.into()
        );
        assert_eq!(
            OrderedDigest([
                BFieldElement::ring_zero(),
                BFieldElement::ring_one(),
                BFieldElement::ring_zero(),
                BFieldElement::ring_zero(),
                BFieldElement::ring_zero(),
                BFieldElement::ring_zero()
            ]),
            bfe_max_plus_one.into()
        );
        assert_eq!(
            OrderedDigest([
                BFieldElement::new((1u64 << 32) - 1),
                BFieldElement::ring_one(),
                BFieldElement::ring_zero(),
                BFieldElement::ring_zero(),
                BFieldElement::ring_zero(),
                BFieldElement::ring_zero()
            ]),
            two_pow_64.into()
        );
        assert_eq!(
            OrderedDigest([
                BFieldElement::new(18446744069280366593),
                BFieldElement::new(576460752437641215),
                BFieldElement::ring_zero(),
                BFieldElement::ring_zero(),
                BFieldElement::ring_zero(),
                BFieldElement::ring_zero()
            ]),
            two_pow_123.into()
        );
        // Result calculated on Wolfram alpha
        assert_eq!(
            OrderedDigest([
                BFieldElement::new(9223372032559808513),
                BFieldElement::new(6442450940),
                BFieldElement::new(9223372041149743112),
                BFieldElement::new(18446744037202329596),
                BFieldElement::new(9223372056182128637),
                BFieldElement::new(2147483650),
            ]),
            two_pow_351.into()
        );
    }

    #[test]
    fn digest_ordering() {
        let val0 = OrderedDigest::new([BFieldElement::new(0); RESCUE_PRIME_OUTPUT_SIZE_IN_BFES]);
        let val1 = OrderedDigest::new([
            BFieldElement::new(14),
            BFieldElement::new(0),
            BFieldElement::new(0),
            BFieldElement::new(0),
            BFieldElement::new(0),
            BFieldElement::new(0),
        ]);
        assert!(val0 < val1);

        let val2 = OrderedDigest::new([BFieldElement::new(14); RESCUE_PRIME_OUTPUT_SIZE_IN_BFES]);
        assert!(val2 > val1);
        assert!(val2 > val0);

        let val3 = OrderedDigest::new([
            BFieldElement::new(15),
            BFieldElement::new(14),
            BFieldElement::new(14),
            BFieldElement::new(14),
            BFieldElement::new(14),
            BFieldElement::new(14),
        ]);
        assert!(val3 > val2);
        assert!(val3 > val1);
        assert!(val3 > val0);

        let val4 = OrderedDigest::new([
            BFieldElement::new(14),
            BFieldElement::new(15),
            BFieldElement::new(14),
            BFieldElement::new(14),
            BFieldElement::new(14),
            BFieldElement::new(14),
        ]);
        assert!(val4 > val3);
        assert!(val4 > val2);
        assert!(val4 > val1);
        assert!(val4 > val0);
    }
}
