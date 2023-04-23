use num_bigint::{BigUint, TryFromBigIntError};
use num_traits::Zero;
use serde::Serialize;

use twenty_first::amount::u32s::U32s;
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::shared_math::rescue_prime_digest::Digest;
use twenty_first::shared_math::rescue_prime_digest::DIGEST_LENGTH;

// The data structure `RescuePrimeDigest` is primarily needed, so we can make
// database keys out of rescue prime digests.
/// Type for ordered digests. The digest is considered a big-endian unsigned integer
/// written in base BFieldElement::QUOTIENT.
#[derive(Clone, Copy, Debug, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct OrderedDigest([BFieldElement; DIGEST_LENGTH]);

// Digest needs a partial ordering for the mining/PoW process, to check if
// a digest is below the difficulty threshold.
impl PartialOrd for OrderedDigest {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        for i in (0..DIGEST_LENGTH).rev() {
            if self.0[i].value() != other.0[i].value() {
                return self.0[i].value().partial_cmp(&other.0[i].value());
            }
        }

        None
    }
}

impl Default for OrderedDigest {
    fn default() -> Self {
        Self([BFieldElement::zero(); DIGEST_LENGTH])
    }
}

impl OrderedDigest {
    pub fn max() -> Self {
        Self([BFieldElement::new(BFieldElement::MAX); DIGEST_LENGTH])
    }

    pub fn new(digest: [BFieldElement; DIGEST_LENGTH]) -> Self {
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

        threshold_as_bui.try_into().unwrap()
    }
}

impl TryFrom<BigUint> for OrderedDigest {
    type Error = String;

    fn try_from(value: BigUint) -> Result<Self, Self::Error> {
        let mut remaining = value;
        let mut ret = OrderedDigest::default();
        let modulus: BigUint = BFieldElement::P.into();
        for i in 0..DIGEST_LENGTH {
            let resulting_u64: u64 = (remaining.clone() % modulus.clone()).try_into().map_err(
                |err: TryFromBigIntError<BigUint>| {
                    format!("Could not convert remainder back to u64: {:?}", err)
                },
            )?;
            ret.0[i] = BFieldElement::new(resulting_u64);
            remaining /= modulus.clone();
        }

        if !remaining.is_zero() {
            return Err("Overflow when converting from BigUint to OrderedDigest".to_string());
        }

        Ok(ret)
    }
}

impl From<OrderedDigest> for BigUint {
    fn from(digest: OrderedDigest) -> Self {
        let mut ret = BigUint::zero();
        let modulus: BigUint = BFieldElement::P.into();
        for i in (0..DIGEST_LENGTH).rev() {
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
    fn conversion_test() {
        let u32_max_difficulty_actual = U32s::<5>::from(u32::MAX);
        let u32_max_difficulty_expected = U32s::<5>::new([u32::MAX, 0, 0, 0, 0]);
        assert_eq!(u32_max_difficulty_actual, u32_max_difficulty_expected);
    }

    #[test]
    fn difficulty_to_threshold_test() {
        // Verify that a difficulty of 2 accepts half of the digests
        let difficulty: u32 = 2;
        let difficulty_u32s = U32s::<5>::from(difficulty);
        let threshold_for_difficulty_two: OrderedDigest =
            OrderedDigest::to_digest_threshold(difficulty_u32s);

        for elem in threshold_for_difficulty_two.0 {
            assert_eq!(BFieldElement::MAX / u64::from(difficulty), elem.value());
        }

        // Verify that a difficulty of BFieldElement::MAX accepts all digests where the last BFieldElement is zero
        let some_difficulty = U32s::<5>::new([1, u32::MAX, 0, 0, 0]);
        let some_threshold_actual: OrderedDigest =
            OrderedDigest::to_digest_threshold(some_difficulty);

        let bfe_max_elem = BFieldElement::new(BFieldElement::MAX);
        let some_threshold_expected = OrderedDigest::new([
            bfe_max_elem,
            bfe_max_elem,
            bfe_max_elem,
            bfe_max_elem,
            BFieldElement::zero(),
        ]);

        assert_eq!(0u64, some_threshold_actual.0[4].value());
        assert_eq!(some_threshold_actual, some_threshold_expected);
        assert_eq!(bfe_max_elem, some_threshold_actual.0[3]);
    }

    #[test]
    #[should_panic(expected = "Overflow when converting from BigUint to OrderedDigest")]
    fn digest_biguint_overflow_test() {
        let mut two_pow_384: BigUint = (1u128 << 96).into();
        two_pow_384 = two_pow_384.pow(4);
        let _failing_conversion: OrderedDigest = two_pow_384.try_into().unwrap();
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
        ]);

        let bfe_max: BigUint = BFieldElement::MAX.into();
        let bfe_max_converted_expected = OrderedDigest([
            BFieldElement::new(BFieldElement::MAX),
            BFieldElement::zero(),
            BFieldElement::zero(),
            BFieldElement::zero(),
            BFieldElement::zero(),
        ]);

        let bfe_max_plus_one: BigUint = BFieldElement::P.into();
        let bfe_max_plus_one_converted_expected = OrderedDigest([
            BFieldElement::zero(),
            BFieldElement::one(),
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
        ]);

        let two_pow_123: BigUint = (1u128 << 123).into();
        let two_pow_123_converted_expected = OrderedDigest([
            BFieldElement::new(18446744069280366593),
            BFieldElement::new(576460752437641215),
            BFieldElement::zero(),
            BFieldElement::zero(),
            BFieldElement::zero(),
        ]);

        let two_pow_315: BigUint = BigUint::from(2u128).pow(315);

        // Result calculated on Wolfram alpha
        let two_pow_315_converted_expected = OrderedDigest([
            BFieldElement::new(18446744069280366593),
            BFieldElement::new(1729382257312923647),
            BFieldElement::new(13258597298683772929),
            BFieldElement::new(3458764513015234559),
            BFieldElement::new(576460752840294400),
        ]);

        // Verify conversion from BigUint to OrderedDigest
        assert_eq!(
            fourteen_converted_expected,
            fourteen.clone().try_into().unwrap()
        );
        assert_eq!(
            bfe_max_converted_expected,
            bfe_max.clone().try_into().unwrap()
        );
        assert_eq!(
            bfe_max_plus_one_converted_expected,
            bfe_max_plus_one.clone().try_into().unwrap()
        );
        assert_eq!(
            two_pow_64_converted_expected,
            two_pow_64.clone().try_into().unwrap()
        );
        assert_eq!(
            two_pow_123_converted_expected,
            two_pow_123.clone().try_into().unwrap()
        );
        assert_eq!(
            two_pow_315_converted_expected,
            two_pow_315.clone().try_into().unwrap()
        );

        // Verify conversion from OrderedDigest to BigUint
        assert_eq!(fourteen, fourteen_converted_expected.try_into().unwrap());
        assert_eq!(bfe_max, bfe_max_converted_expected.try_into().unwrap());
        assert_eq!(
            bfe_max_plus_one,
            bfe_max_plus_one_converted_expected.try_into().unwrap()
        );
        assert_eq!(
            two_pow_64,
            two_pow_64_converted_expected.try_into().unwrap()
        );
        assert_eq!(
            two_pow_123,
            two_pow_123_converted_expected.try_into().unwrap()
        );
        assert_eq!(
            two_pow_315,
            two_pow_315_converted_expected.try_into().unwrap()
        );
    }

    #[test]
    fn digest_biguint_conversion_pbt() {
        let count = 100;
        let mut rng = thread_rng();
        for _ in 0..count {
            // Generate a random BigUint that will fit into an ordered digest
            let mut biguint: BigUint = BigUint::one();
            for _ in 0..4 {
                biguint *= rng.next_u64();
            }
            biguint *= rng.next_u32();

            // Verify that conversion back and forth is the identity operator
            let as_digest: OrderedDigest = biguint.clone().try_into().unwrap();
            let converted_back: BigUint = as_digest.into();
            assert_eq!(biguint, converted_back);
        }
    }

    #[test]
    fn digest_ordering() {
        let val0 = OrderedDigest::new([BFieldElement::new(0); DIGEST_LENGTH]);
        let val1 = OrderedDigest::new([
            BFieldElement::new(14),
            BFieldElement::new(0),
            BFieldElement::new(0),
            BFieldElement::new(0),
            BFieldElement::new(0),
        ]);
        assert!(val0 < val1);

        let val2 = OrderedDigest::new([BFieldElement::new(14); DIGEST_LENGTH]);
        assert!(val2 > val1);
        assert!(val2 > val0);

        let val3 = OrderedDigest::new([
            BFieldElement::new(15),
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
        ]);
        assert!(val4 > val3);
        assert!(val4 > val2);
        assert!(val4 > val1);
        assert!(val4 > val0);
    }
}
