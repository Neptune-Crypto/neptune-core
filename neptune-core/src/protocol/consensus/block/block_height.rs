use std::cmp::min;
use std::cmp::Ordering;
use std::fmt::Display;
use std::ops::Add;
use std::ops::Sub;

use crate::api::export::Network;
use crate::protocol::consensus::consensus_rule_set::{
    ConsensusRuleSet, BLOCK_HEIGHT_HARDFORK_BETA_MAIN_NET, BLOCK_HEIGHT_HARDFORK_BETA_TESTNET,
};
#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use get_size2::GetSize;
use num_traits::ConstZero;
use num_traits::One;
use num_traits::Zero;
use rand::distr::Distribution;
use rand::distr::StandardUniform;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::TasmObject;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

/// The distance, in number of blocks, to the genesis block.
///
/// This struct wraps around a [`BFieldElement`], so the maximum block height
/// is P-1 = 2^64 - 2^32. With an average block time of 588 seconds, this
/// maximum will be reached roughly 344 trillion years after launch. Not urgent.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Hash,
    BFieldCodec,
    TasmObject,
    GetSize,
)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(Arbitrary))]
pub struct BlockHeight(BFieldElement);

// Assuming a block time of 588 seconds, and a halving every three years,
// the number of blocks per halving cycle is 160815.
pub const BLOCKS_PER_GENERATION_BEFORE_BETA: u64 = 160815;

// Assuming a block time of 900 seconds, and a halving every three years,
// the number of blocks per halving cycle is 105066.
pub const BLOCKS_PER_GENERATION_FROM_BETA: u64 = 105066;
pub const NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT: u64 = 21310;

impl BlockHeight {
    pub const MAX: u64 = BFieldElement::MAX;

    pub const fn new(value: BFieldElement) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u64 {
        self.0.value()
    }

    pub fn get_generation(&self, network: Network) -> u64 {
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, *self);

        match consensus_rule_set {
            ConsensusRuleSet::Reboot | ConsensusRuleSet::HardforkAlpha => {
                self.0
                    .value()
                    .saturating_add(NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT)
                    / BLOCKS_PER_GENERATION_BEFORE_BETA
            }
            ConsensusRuleSet::HardforkBeta => {
                let hard_fork_block = match network {
                    Network::Testnet(_) => BLOCK_HEIGHT_HARDFORK_BETA_TESTNET,
                    Network::Main => BLOCK_HEIGHT_HARDFORK_BETA_MAIN_NET,
                    _ => BlockHeight::from(1)
                }
                .value()
                    - 1;
                let before_beta_gen =
                    (hard_fork_block.saturating_add(NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT) as f64)
                        / (BLOCKS_PER_GENERATION_BEFORE_BETA as f64);
                let from_beta_gen = (self.0.value().saturating_sub(hard_fork_block) as f64)
                    / (BLOCKS_PER_GENERATION_FROM_BETA as f64);

                (before_beta_gen + from_beta_gen) as u64
            }
        }
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
        BlockHeight(BFieldElement::new(min(BFieldElement::MAX, val)))
    }
}

impl From<BlockHeight> for u64 {
    fn from(bh: BlockHeight) -> Self {
        bh.0.value()
    }
}

impl Ord for BlockHeight {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.value().cmp(&(other.0.value()))
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
        i128::from(self.0.value()) - i128::from(rhs.0.value())
    }
}

impl PartialOrd for BlockHeight {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for BlockHeight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", u64::from(self.0))
    }
}

impl Distribution<BlockHeight> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BlockHeight {
        let height = rng.random::<BFieldElement>();
        BlockHeight::new(height)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use macro_rules_attr::apply;
    use num_traits::CheckedAdd;
    use num_traits::CheckedSub;
    use tracing_test::traced_test;

    use super::*;
    use crate::protocol::consensus::block::Block;
    use crate::protocol::consensus::block::Network;
    use crate::protocol::consensus::block::PREMINE_MAX_SIZE;
    use crate::protocol::consensus::consensus_rule_set::BLOCK_HEIGHT_HARDFORK_ALPHA_MAIN_NET;
    use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use crate::protocol::proof_abstractions::timestamp::Timestamp;
    use crate::tests::shared_tokio_runtime;

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn genesis_test() {
        assert!(BlockHeight::genesis().is_genesis());
        assert!(!BlockHeight::genesis().next().is_genesis());
    }

    #[test]
    fn block_interval_times_generation_count_is_three_years() {
        let network = Network::Main;

        let check = |block_per_generation: u64, block_height: BlockHeight| {
            let calculated_halving_time = network
                .target_block_interval(block_height)
                * (block_per_generation as usize);
            let calculated_halving_time = calculated_halving_time.to_millis();
            let three_years = Timestamp::years(3);
            let three_years = three_years.to_millis();
            assert!(
                (calculated_halving_time as f64) * 1.01 > three_years as f64
                    && (calculated_halving_time as f64) * 0.99 < three_years as f64,
                "target halving time must be within 1 % of 3 years. Got:\n\
            three years = {three_years}ms\n calculated_halving_time = {calculated_halving_time}ms"
            );
        };
        
        check(BLOCKS_PER_GENERATION_BEFORE_BETA, BLOCK_HEIGHT_HARDFORK_ALPHA_MAIN_NET);
        check(BLOCKS_PER_GENERATION_FROM_BETA, BLOCK_HEIGHT_HARDFORK_BETA_MAIN_NET);
    }

    #[test]
    fn asymptotic_limit_is_42_million() {
        let generation_0_subsidy =
            Block::block_subsidy(BlockHeight::genesis().next(), Network::Main);

        // Genesis block does not contain block subsidy so it must be subtracted
        // from total number.
        let total_skipped_subsidies_generation_0 = generation_0_subsidy
            .scalar_mul(u32::try_from(NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT).unwrap());
        let mineable_amount = generation_0_subsidy
            .scalar_mul(BLOCKS_PER_GENERATION_BEFORE_BETA as u32)
            .scalar_mul(2)
            .checked_sub(&generation_0_subsidy)
            .unwrap()
            .checked_sub(&total_skipped_subsidies_generation_0)
            .unwrap();

        println!("mineable_amount: {mineable_amount}");
        let original_premine = PREMINE_MAX_SIZE;
        let claims_pool = total_skipped_subsidies_generation_0;
        let asymptotic_limit = mineable_amount
            .checked_add(&original_premine)
            .unwrap()
            .checked_add(&claims_pool)
            .unwrap();

        assert_eq!(NativeCurrencyAmount::coins(42_000_000), asymptotic_limit);

        // Premine is less than promise of 1.98 %
        let relative_premine = original_premine.to_nau_f64() / asymptotic_limit.to_nau_f64();
        println!("asymptotic_limit: {asymptotic_limit}");
        println!("claims pool: {claims_pool}");
        println!("relative_premine: {relative_premine}");
        println!("absolute premine: {original_premine} coins");
        assert!(relative_premine < 0.0198, "Premine may not exceed promise");

        // Designated premine is less than or equal to allocation. Note that
        // the allocation for reboot-claims is not considered part of the
        // premine.
        let reboot_premine_including_claims_pool = Block::premine_distribution()
            .iter()
            .map(|(_receiving_address, amount)| *amount)
            .sum::<NativeCurrencyAmount>();
        let of_which_is_claims_pool = Block::utxo_redemption_fund_and_claims()
            .iter()
            .map(|(_receiving_address, amount)| *amount)
            .sum::<NativeCurrencyAmount>();
        let individual_claims = Block::redemption_claims()
            .iter()
            .map(|(_receiving_address, amount)| *amount)
            .sum::<NativeCurrencyAmount>();
        let actual_premine = reboot_premine_including_claims_pool
            .checked_sub(&of_which_is_claims_pool)
            .unwrap();
        println!("reboot_premine: {reboot_premine_including_claims_pool}");
        println!("of_which_is_claims_pool: {of_which_is_claims_pool}");
        println!("of which is individual claims: {individual_claims}");
        println!("actual_premine: {actual_premine}");
        assert_eq!(
            actual_premine, original_premine,
            "Distributed premine may not exceed designated value"
        );

        assert_eq!(
            actual_premine + total_skipped_subsidies_generation_0,
            reboot_premine_including_claims_pool
        );
        assert_eq!(
            total_skipped_subsidies_generation_0,
            of_which_is_claims_pool
        );
    }
}
