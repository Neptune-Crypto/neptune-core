use num_bigint::BigUint;
use num_traits::Zero;

use twenty_first::amount::u32s::U32s;
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::shared_math::digest::Digest;
use twenty_first::shared_math::digest::DIGEST_LENGTH;

/// `target_difficulty` is a number that counts the expected number of digests you need to compute in order to find a valid block.
pub fn to_digest_threshold(target_difficulty: U32s<5>) -> Digest {
    assert!(
        !target_difficulty.is_zero(),
        "Difficulty cannot be less than 1"
    );

    let difficulty_as_bui: BigUint = target_difficulty.into();
    let max_threshold_as_bui: BigUint =
        Digest([BFieldElement::new(BFieldElement::MAX); DIGEST_LENGTH]).into();
    let threshold_as_bui: BigUint = max_threshold_as_bui / difficulty_as_bui;

    threshold_as_bui.try_into().unwrap()
}

#[cfg(test)]
mod ordered_digest_tests {

    use super::*;

    #[test]
    fn difficulty_to_threshold_test() {
        // Verify that a difficulty of 2 accepts half of the digests
        let difficulty: u32 = 2;
        let difficulty_u32s = U32s::<5>::from(difficulty);
        let threshold_for_difficulty_two: Digest = Digest::to_digest_threshold(difficulty_u32s);

        for elem in threshold_for_difficulty_two.values() {
            assert_eq!(BFieldElement::MAX / u64::from(difficulty), elem.value());
        }

        // Verify that a difficulty of BFieldElement::MAX accepts all digests where the last BFieldElement is zero
        let some_difficulty = U32s::<5>::new([1, u32::MAX, 0, 0, 0]);
        let some_threshold_actual: Digest = Digest::to_digest_threshold(some_difficulty);

        let bfe_max_elem = BFieldElement::new(BFieldElement::MAX);
        let some_threshold_expected = Digest::new([
            bfe_max_elem,
            bfe_max_elem,
            bfe_max_elem,
            bfe_max_elem,
            BFieldElement::zero(),
        ]);

        assert_eq!(0u64, some_threshold_actual.values()[4].value());
        assert_eq!(some_threshold_actual, some_threshold_expected);
        assert_eq!(bfe_max_elem, some_threshold_actual.values()[3]);
    }
}
