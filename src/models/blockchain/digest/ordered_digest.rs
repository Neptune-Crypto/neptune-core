use num_bigint::BigUint;
use num_traits::Zero;
use serde::Serialize;
use twenty_first::{amount::u32s::U32s, shared_math::b_field_element::BFieldElement};

use super::{Digest, RESCUE_PRIME_OUTPUT_SIZE_IN_BFES};

// The data structure `RescuePrimeDigest` is primarily needed, so we can make
// database keys out of rescue prime digests.
/// Type for ordered digests. The digest is considered a big-endian unsigned integer
/// written in base BFieldElement::QUOTIENT.
#[derive(Clone, Copy, Debug, Serialize, serde::Deserialize, PartialEq, Eq)]
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
    pub const fn max() -> Self {
        Self([BFieldElement::new(BFieldElement::MAX); RESCUE_PRIME_OUTPUT_SIZE_IN_BFES])
    }

    pub const fn default() -> Self {
        Self([BFieldElement::zero(); RESCUE_PRIME_OUTPUT_SIZE_IN_BFES])
    }

    pub const fn new(digest: [BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES]) -> Self {
        Self(digest)
    }

    pub fn to_digest_threshold(target_difficulty: U32s<5>) -> Self {
        assert!(
            !target_difficulty.is_zero(),
            "Difficulty cannot be less than 1"
        );

        let difficulty_as_bui: BigUint = target_difficulty.into();
        let max_threshold_as_bui: BigUint = Self::max().into();
        let threshold_as_bui: BigUint = max_threshold_as_bui / difficulty_as_bui;

        threshold_as_bui.into()
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

impl From<OrderedDigest> for BigUint {
    fn from(digest: OrderedDigest) -> Self {
        let mut ret = BigUint::zero();
        let modulus: BigUint = BFieldElement::QUOTIENT.into();
        for i in (0..RESCUE_PRIME_OUTPUT_SIZE_IN_BFES).rev() {
            ret *= modulus.clone();
            let digest_element: BigUint = digest.0[i].value().into();
            ret += digest_element;
        }

        ret
    }
}

impl From<Digest> for OrderedDigest {
    fn from(digest: Digest) -> Self {
        Self(digest.values())
    }
}

#[cfg(test)]
mod ordered_digest_tests {
    use num_traits::One;
    use rand::{thread_rng, RngCore};

    use super::*;

    #[test]
    fn difficulty_to_threshold_test() {
        // Verify that a difficulty of 2 accepts half of the digests
        let two = U32s::<5>::one() + U32s::<5>::one();
        let threshold_for_difficulty_two: OrderedDigest = OrderedDigest::to_digest_threshold(two);
        assert_eq!(
            BFieldElement::MAX / 2,
            threshold_for_difficulty_two.0[5].value()
        );

        // Verify that a difficulty of BFieldElement::MAX accepts all digests where the last BFieldElement is zero
        let bfe_max = U32s::<5>::new([1, u32::MAX, 0, 0, 0]);
        let threshold_for_bfe_max: OrderedDigest = OrderedDigest::to_digest_threshold(bfe_max);
        assert_eq!(0u64, threshold_for_bfe_max.0[5].value());
        assert_eq!(BFieldElement::MAX, threshold_for_bfe_max.0[4].value());
    }

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
        let fourteen_converted_expected: OrderedDigest = OrderedDigest([
            BFieldElement::new(14),
            BFieldElement::zero(),
            BFieldElement::zero(),
            BFieldElement::zero(),
            BFieldElement::zero(),
            BFieldElement::zero(),
        ]);

        let bfe_max: BigUint = BFieldElement::MAX.into();
        let bfe_max_converted_expected = OrderedDigest([
            BFieldElement::new(BFieldElement::MAX),
            BFieldElement::zero(),
            BFieldElement::zero(),
            BFieldElement::zero(),
            BFieldElement::zero(),
            BFieldElement::zero(),
        ]);

        let bfe_max_plus_one: BigUint = BFieldElement::QUOTIENT.into();
        let bfe_max_plus_one_converted_expected = OrderedDigest([
            BFieldElement::zero(),
            BFieldElement::one(),
            BFieldElement::zero(),
            BFieldElement::zero(),
            BFieldElement::zero(),
            BFieldElement::zero(),
        ]);

        let two_pow_64: BigUint = (1u128 << 64).into();
        let two_pow_64_converted_expected = OrderedDigest([
            BFieldElement::new((1u64 << 32) - 1),
            BFieldElement::one(),
            BFieldElement::zero(),
            BFieldElement::zero(),
            BFieldElement::zero(),
            BFieldElement::zero(),
        ]);

        let two_pow_123: BigUint = (1u128 << 123).into();
        let two_pow_123_converted_expected = OrderedDigest([
            BFieldElement::new(18446744069280366593),
            BFieldElement::new(576460752437641215),
            BFieldElement::zero(),
            BFieldElement::zero(),
            BFieldElement::zero(),
            BFieldElement::zero(),
        ]);

        let mut two_pow_351: BigUint = (1u128 << 70).into();
        two_pow_351 = two_pow_351.pow(5);
        two_pow_351 *= 2u32;
        // Result calculated on Wolfram alpha
        let two_pow_351_converted_expected = OrderedDigest([
            BFieldElement::new(9223372032559808513),
            BFieldElement::new(6442450940),
            BFieldElement::new(9223372041149743112),
            BFieldElement::new(18446744037202329596),
            BFieldElement::new(9223372056182128637),
            BFieldElement::new(2147483650),
        ]);

        // Verify conversion from BigUint to OrderedDigest
        assert_eq!(fourteen_converted_expected, fourteen.clone().into());
        assert_eq!(bfe_max_converted_expected, bfe_max.clone().into());
        assert_eq!(
            bfe_max_plus_one_converted_expected,
            bfe_max_plus_one.clone().into()
        );
        assert_eq!(two_pow_64_converted_expected, two_pow_64.clone().into());
        assert_eq!(two_pow_123_converted_expected, two_pow_123.clone().into());
        assert_eq!(two_pow_351_converted_expected, two_pow_351.clone().into());

        // Verify conversion from OrderedDigest to BigUint
        assert_eq!(fourteen, fourteen_converted_expected.into());
        assert_eq!(bfe_max, bfe_max_converted_expected.into());
        assert_eq!(bfe_max_plus_one, bfe_max_plus_one_converted_expected.into());
        assert_eq!(two_pow_64, two_pow_64_converted_expected.into());
        assert_eq!(two_pow_123, two_pow_123_converted_expected.into());
        assert_eq!(two_pow_351, two_pow_351_converted_expected.into());
    }

    #[test]
    fn digest_biguint_conversion_pbt() {
        let count = 100;
        let mut prng = thread_rng();
        for _ in 0..count {
            // Generate a random BigUint that will fit into an ordered digest
            let mut biguint: BigUint = BigUint::one();
            for _ in 0..5 {
                biguint *= prng.next_u64();
            }
            biguint *= prng.next_u32();

            // Verify that conversion back and forth is the identity operator
            let as_digest: OrderedDigest = biguint.clone().into();
            let converted_back: BigUint = as_digest.into();
            assert_eq!(biguint, converted_back);
        }
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
