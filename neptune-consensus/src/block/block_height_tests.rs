//! Tests for [`BlockHeight`](neptune_primitives::block_height::BlockHeight).
//!
//! `BlockHeight` itself lives in `neptune-primitives`; these tests remain in
//! `neptune-consensus` because they exercise consensus-level types (`Block`,
//! premine distribution, etc.).

use macro_rules_attr::apply;
use neptune_primitives::block_height::BlockHeight;
use neptune_primitives::block_height::BLOCKS_PER_GENERATION;
use neptune_primitives::block_height::NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT;
use neptune_primitives::network::Network;
use neptune_primitives::timestamp::Timestamp;
use num_traits::CheckedAdd;
use num_traits::CheckedSub;
use proptest::prop_assert;
use proptest::prop_assume;
use test_strategy::proptest;
use tracing_test::traced_test;

use crate::block::Block;
use crate::block::PREMINE_MAX_SIZE;
use crate::proof_abstractions::test_runtime::shared_tokio_runtime;
use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

#[traced_test]
#[apply(shared_tokio_runtime)]
async fn genesis_test() {
    assert!(BlockHeight::genesis().is_genesis());
    assert!(!BlockHeight::genesis().next().is_genesis());
}

#[test]
fn default_height_is_genesis() {
    assert!(BlockHeight::default().is_genesis());
}

#[test]
fn block_interval_times_generation_count_is_three_years() {
    let network = Network::Main;
    let calculated_halving_time =
        network.target_block_interval() * (BLOCKS_PER_GENERATION as usize);
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
    let total_skipped_subsidies_generation_0 =
        generation_0_subsidy.scalar_mul(u32::try_from(NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT).unwrap());
    let mineable_amount = generation_0_subsidy
        .scalar_mul(BLOCKS_PER_GENERATION as u32)
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

#[proptest]
fn arithmetic_mean_of_block_heights_is_always_in_between_arguments(low: u64, up: u64) {
    prop_assume!(low <= up);
    let lower = BlockHeight::from(low);
    let upper = BlockHeight::from(up);
    let mean = BlockHeight::arithmetic_mean(lower, upper);
    prop_assert!(low <= mean.value());
    prop_assert!(mean.value() <= up);
}
