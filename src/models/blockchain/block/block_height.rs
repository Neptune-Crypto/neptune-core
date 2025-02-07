use std::cmp::Ordering;
use std::fmt::Display;
use std::ops::Add;
use std::ops::Sub;

#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use get_size2::GetSize;
use num_traits::ConstZero;
use num_traits::One;
use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::math::bfield_codec::BFieldCodec;

use crate::prelude::twenty_first;

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Hash, BFieldCodec, GetSize,
)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(Arbitrary))]
pub struct BlockHeight(BFieldElement);

// Assuming a block time of 588 seconds, and a halving every three years,
// the number of blocks per halving cycle is 160815.
pub const BLOCKS_PER_GENERATION: u64 = 160815;

impl BlockHeight {
    pub fn get_generation(&self) -> u64 {
        self.0.value() / BLOCKS_PER_GENERATION
    }

    pub fn next(&self) -> Self {
        Self(self.0 + BFieldElement::one())
    }

    pub fn previous(&self) -> Option<Self> {
        if self.is_genesis() {
            None
        } else {
            Some(Self(self.0 - BFieldElement::one()))
        }
    }

    pub const fn genesis() -> Self {
        Self(BFieldElement::ZERO)
    }

    pub fn is_genesis(&self) -> bool {
        self.0.is_zero()
    }

    pub(crate) fn arithmetic_mean(left: Self, right: Self) -> Self {
        // Calculate arithmetic mean, without risk of overflow.
        let left = left.0.value();
        let right = right.0.value();
        let ret = (left / 2) + (right / 2) + (left % 2 + right % 2) / 2;

        Self(BFieldElement::new(ret))
    }

    /// Subtract a number from a block height.
    //
    // *NOT* implemented as trait `CheckedSub` because of type mismatch.
    pub(crate) fn checked_sub(&self, v: u64) -> Option<Self> {
        self.0.value().checked_sub(v).map(|x| x.into())
    }
}

impl From<BFieldElement> for BlockHeight {
    fn from(item: BFieldElement) -> Self {
        BlockHeight(item)
    }
}

impl From<BlockHeight> for BFieldElement {
    fn from(item: BlockHeight) -> BFieldElement {
        item.0
    }
}

impl From<u64> for BlockHeight {
    fn from(val: u64) -> Self {
        BlockHeight(BFieldElement::new(val))
    }
}

impl From<BlockHeight> for u64 {
    fn from(bh: BlockHeight) -> Self {
        bh.0.value()
    }
}

impl Ord for BlockHeight {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.0.value()).cmp(&(other.0.value()))
    }
}

impl Add<usize> for BlockHeight {
    type Output = BlockHeight;

    fn add(self, rhs: usize) -> Self::Output {
        Self(BFieldElement::new(self.0.value() + rhs as u64))
    }
}

impl Sub for BlockHeight {
    type Output = i128;

    fn sub(self, rhs: Self) -> Self::Output {
        self.0.value() as i128 - rhs.0.value() as i128
    }
}

impl PartialOrd for BlockHeight {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for BlockHeight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", u64::from(self.0))
    }
}

#[cfg(test)]
mod test {
    use num_traits::CheckedAdd;
    use num_traits::CheckedSub;
    use tracing_test::traced_test;

    use super::*;
    use crate::models::blockchain::block::block_tests::PREMINE_MAX_SIZE;
    use crate::models::blockchain::block::Block;
    use crate::models::blockchain::block::TARGET_BLOCK_INTERVAL;
    use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use crate::models::proof_abstractions::timestamp::Timestamp;

    #[traced_test]
    #[tokio::test]
    async fn genesis_test() {
        assert!(BlockHeight::genesis().is_genesis());
        assert!(!BlockHeight::genesis().next().is_genesis());
    }

    #[test]
    fn block_interval_times_generation_count_is_three_years() {
        let calculated_halving_time = TARGET_BLOCK_INTERVAL * (BLOCKS_PER_GENERATION as usize);
        let calculated_halving_time = calculated_halving_time.to_millis();
        let three_years = Timestamp::years(3);
        let three_years = three_years.to_millis();
        assert!(
            (calculated_halving_time as f64) * 1.01 > three_years as f64
                && (calculated_halving_time as f64) * 0.99 < three_years as f64,
            "target halving time must be within 1 % of 3 years. Got:\n\
            three years = {three_years}ms\n calculated_halving_time = {calculated_halving_time}ms"
        );
    }

    #[test]
    fn asymptotic_limit_is_42_million() {
        let generation_0_subsidy = Block::block_subsidy(BlockHeight::genesis().next());

        // Genesis block does not contain block subsidy so it must be subtracted
        // from total number.
        let mineable_amount = generation_0_subsidy
            .scalar_mul(BLOCKS_PER_GENERATION as u32)
            .scalar_mul(2)
            .checked_sub(&generation_0_subsidy)
            .unwrap();

        println!("mineable_amount: {mineable_amount}");
        let designated_premine = PREMINE_MAX_SIZE;
        let asymptotic_limit = mineable_amount.checked_add(&designated_premine).unwrap();

        let expected_limit = NativeCurrencyAmount::coins(42_000_000);
        assert_eq!(expected_limit, asymptotic_limit);

        // Premine is less than promise of 1.98 %
        let relative_premine = designated_premine.to_nau_f64() / expected_limit.to_nau_f64();
        println!("relative_premine: {relative_premine}");
        println!("absolute premine: {designated_premine} coins");
        assert!(relative_premine < 0.0198, "Premine may not exceed promise");

        // Designated premine is less than or equal to allocation
        let actual_premine = Block::premine_distribution()
            .iter()
            .map(|(_receiving_address, amount)| *amount)
            .sum::<NativeCurrencyAmount>();
        assert!(
            actual_premine <= designated_premine,
            "Distributed premine may not exceed designated value"
        );
    }
}
