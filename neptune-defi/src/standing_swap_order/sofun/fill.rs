//! The coinbase transaction that fills a SOFuN order.

use std::fmt;

use neptune_consensus::block::pow::LustrationStatus;
use neptune_consensus::block::Block;
use neptune_consensus::block::MINING_REWARD_TIME_LOCK_PERIOD;
use neptune_consensus::transaction::announcement::Announcement;
use neptune_consensus::transaction::primitive_witness::PrimitiveWitness;
use neptune_consensus::transaction::transparent_input::TransparentInput;
use neptune_consensus::transaction::utxo::Utxo;
use neptune_consensus::transaction::utxo_triple::UtxoTriple;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_mutator_set::ms_membership_proof::MsMembershipProof;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_primitives::block_height::BlockHeight;
use neptune_primitives::network::Network;
use neptune_primitives::timestamp::Timestamp;
use neptune_wallet::address::ReceivingAddress;
use neptune_wallet::transaction_details::TransactionDetails;
use neptune_wallet::transaction_output::TxOutput;
use neptune_wallet::unlocked_utxo::UnlockedUtxo;
use neptune_wallet::utxo_notification::UtxoNotificationMethod;
use num_traits::CheckedSub;
use num_traits::Zero;
use tasm_lib::prelude::Digest;

use super::super::order_book::Order;
use super::Sofun;
use super::GRID_STEP;
use super::NUM_GRID_POINTS;

/// Everything a fill depends on besides the order.
#[derive(Debug, Clone)]
pub struct FillTerms {
    /// The height of the block the fill is for.
    pub height: BlockHeight,

    /// The fill's timestamp.
    pub timestamp: Timestamp,

    /// The mutator set after the block's parent.
    pub mutator_set: MutatorSetAccumulator,

    /// The order UTXO's membership proof against `mutator_set`.
    pub membership_proof: MsMembershipProof,

    /// The parent's lustration status, if lustration is in force at the
    /// block's height.
    pub lustration_status: Option<LustrationStatus>,

    /// Where the composer's own outputs go, with on-chain notifications.
    pub composer: ReceivingAddress,

    pub network: Network,
}

/// Why an order cannot be filled on the given terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FillError {
    /// The order demands an amount other than half the block's subsidy.
    WrongAmount,

    /// No point of the order's grid is time-locked for three years from the
    /// fill's timestamp.
    GridRunOut,
}

impl fmt::Display for FillError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongAmount => write!(f, "the order demands other than half the subsidy"),
            Self::GridRunOut => write!(f, "the order's grid ends too early"),
        }
    }
}

impl std::error::Error for FillError {}

/// The primitive witness of the coinbase transaction that fills `order` in
/// the block `terms` describe.
///
/// The transaction claims the whole block subsidy `C` and pays no fee, so the
/// composer keeps what a guesser would otherwise get; a fill pays the composer
/// only when they guess their own blocks. It spends the order UTXO, worth `X`,
/// through the fill path of its lock script, and pays:
///
///  - the reward, `⌊C/2⌋`, at the first point of the order's grid that is time
///    locked for three years and one grid step from the timestamp, or for
///    three years if none is, the step being headroom against a later
///    timestamp;
///  - `⌈X/2⌉` to the composer, time-locked for three years, which the rule
///    that at least half of the total output `C + X` be time-locked asks for
///    on top of the reward;
///  - the rest, `⌈C/2⌉ + ⌊X/2⌋`, to the composer, liquid.
///
/// It lustrates the order UTXO if the lustration status says it must.
pub fn fill_witness(
    order: &Order<Sofun>,
    terms: &FillTerms,
) -> Result<PrimitiveWitness, FillError> {
    let subsidy = Block::block_subsidy(terms.height);
    let demanded = order.order.demanded_amount();
    if demanded != subsidy.half() {
        return Err(FillError::WrongAmount);
    }

    let locked_until = terms.timestamp + MINING_REWARD_TIME_LOCK_PERIOD;
    let rewards = (0..NUM_GRID_POINTS).filter_map(|k| order.order.reward(k));
    let released_by = |reward: &UtxoTriple, date| {
        reward
            .utxo
            .release_date()
            .is_some_and(|release| release >= date)
    };
    let reward = rewards
        .clone()
        .find(|reward| released_by(reward, locked_until + GRID_STEP))
        .or_else(|| {
            rewards
                .clone()
                .find(|reward| released_by(reward, locked_until))
        })
        .ok_or(FillError::GridRunOut)?;

    let offered = order.order.offered_amount();
    let own_locked = offered
        .checked_sub(&offered.half())
        .expect("half an amount is at most the amount");
    let own_liquid = (subsidy + offered)
        .checked_sub(&(demanded + own_locked))
        .expect("the reward and the locked part are at most the total");
    let composer_output = |amount, release_date: Option<Timestamp>| {
        let utxo = Utxo::new_native_currency(terms.composer.lock_script_hash(), amount);
        let utxo = match release_date {
            Some(release_date) => utxo.with_time_lock(release_date),
            None => utxo,
        };
        TxOutput::onchain_utxo(utxo, rand::random(), terms.composer.clone(), true)
    };

    let order_utxo = order.order.order_utxo();
    let lustrations = terms
        .lustration_status
        .map(|status| {
            Announcement::lustration_announcements(
                status,
                &[TransparentInput {
                    utxo: order_utxo.utxo.clone(),
                    aocl_leaf_index: order.id.0,
                    sender_randomness: order.order.offered_sender_randomness(),
                    receiver_preimage: order.order.offered_receiver_preimage(),
                }],
            )
        })
        .unwrap_or_default();

    // The fill witness points into the kernel's outputs, so it is computed
    // from the kernel. The kernel does not depend on any lock script witness,
    // so the cancel witness stands in until then.
    let lock_script = order.order.lock_script();
    let details = TransactionDetails::new(
        UnlockedUtxo::unlock(
            order_utxo.utxo,
            lock_script.cancel(Digest::default()),
            terms.membership_proof.clone(),
        ),
        vec![
            TxOutput::new(
                reward.utxo.clone(),
                reward.sender_randomness,
                reward.receiver_digest,
                UtxoNotificationMethod::None,
                false,
                false,
            ),
            composer_output(own_locked, Some(locked_until)),
            composer_output(own_liquid, None),
        ],
        NativeCurrencyAmount::zero(),
        Some(subsidy),
        terms.timestamp,
        terms.mutator_set.clone(),
        terms.network,
    )
    .with_announcements(lustrations);

    let mut witness = details.primitive_witness();
    witness.lock_scripts_and_witnesses[0] = lock_script
        .fill(&witness.kernel)
        .expect("the kernel pays the reward");

    Ok(witness)
}

#[cfg(test)]
mod tests {
    use neptune_consensus::block::Block;
    use neptune_primitives::block_height::BLOCKS_PER_GENERATION;
    use neptune_wallet::address::generation_address::GenerationReceivingAddress;
    use tasm_lib::prelude::Tip5;

    use super::*;
    use crate::chain::BlockId;
    use crate::standing_swap_order::order_book::OrderId;
    use crate::standing_swap_order::sofun::SofunParams;
    use crate::standing_swap_order::StandingSwapOrder;

    const NOW: Timestamp = Timestamp::millis(1_800_000_000_000);

    /// An order offering `offered`, whose grid starts three years and a day
    /// after [`NOW`], confirmed as the only UTXO of a mutator set; and the
    /// terms for filling it at [`NOW`] in a block of generation 0.
    fn order_and_terms(offered: NativeCurrencyAmount) -> (Order<Sofun>, FillTerms) {
        let order = StandingSwapOrder::<Sofun>::new(
            offered,
            SofunParams {
                d_zero: NOW + MINING_REWARD_TIME_LOCK_PERIOD + Timestamp::days(1),
                epoch: 0,
            },
            rand::random(),
            rand::random(),
            rand::random(),
            rand::random(),
        )
        .unwrap();

        let order_utxo = order.order_utxo();
        let mut mutator_set = MutatorSetAccumulator::default();
        let membership_proof = mutator_set.prove(
            Tip5::hash(&order_utxo.utxo),
            order.offered_sender_randomness(),
            order.offered_receiver_preimage(),
        );
        mutator_set.add(&order_utxo.addition_record());

        let order = Order {
            id: OrderId(0),
            opened_in: BlockId {
                height: BlockHeight::genesis(),
                hash: Digest::default(),
            },
            closed_in: None,
            order,
        };
        let terms = FillTerms {
            height: BlockHeight::genesis().next(),
            timestamp: NOW,
            mutator_set,
            membership_proof,
            lustration_status: None,
            composer: GenerationReceivingAddress::derive_from_seed(rand::random()).into(),
            network: Network::RegTest,
        };
        (order, terms)
    }

    /// The fill is valid, claims the whole subsidy without a fee, and pays the
    /// reward at the first grid point a step clear of three years.
    #[tokio::test]
    async fn the_fill_is_valid_and_pays_the_reward_with_headroom() {
        let (order, terms) = order_and_terms(NativeCurrencyAmount::coins(10));
        let witness = fill_witness(&order, &terms).unwrap();
        witness.validate().await.unwrap();

        assert_eq!(
            Some(Block::block_subsidy(terms.height)),
            witness.kernel.coinbase
        );
        assert!(witness.kernel.fee.is_zero());
        let reward = order.order.reward(1).unwrap().addition_record();
        assert!(witness.kernel.outputs.contains(&reward));
        assert!(!witness
            .kernel
            .outputs
            .contains(&order.order.reward(0).unwrap().addition_record()));
    }

    /// An odd offered amount is valid too: the composer locks the larger half
    /// of it, which keeps the time-locked part at half of the total.
    #[tokio::test]
    async fn an_odd_offered_amount_gives_a_valid_fill() {
        let offered = NativeCurrencyAmount::coins(10) + NativeCurrencyAmount::from_nau(1);
        let (order, terms) = order_and_terms(offered);
        fill_witness(&order, &terms)
            .unwrap()
            .validate()
            .await
            .unwrap();
    }

    /// Without a step of headroom on the grid, the fill takes the tightest
    /// point that clears three years.
    #[tokio::test]
    async fn the_tightest_point_serves_when_no_point_has_headroom() {
        let (order, mut terms) = order_and_terms(NativeCurrencyAmount::coins(10));
        let last = order.order.reward(NUM_GRID_POINTS - 1).unwrap();
        terms.timestamp = last.utxo.release_date().unwrap() - MINING_REWARD_TIME_LOCK_PERIOD;

        let witness = fill_witness(&order, &terms).unwrap();
        witness.validate().await.unwrap();
        assert!(witness.kernel.outputs.contains(&last.addition_record()));
    }

    #[test]
    fn an_order_past_its_grid_or_for_another_generation_is_refused() {
        let (order, mut terms) = order_and_terms(NativeCurrencyAmount::coins(10));
        let last = order.order.reward(NUM_GRID_POINTS - 1).unwrap();
        terms.timestamp = last.utxo.release_date().unwrap() - MINING_REWARD_TIME_LOCK_PERIOD
            + Timestamp::millis(1);
        assert_eq!(
            Err(FillError::GridRunOut),
            fill_witness(&order, &terms).map(|_| ())
        );

        let (order, mut terms) = order_and_terms(NativeCurrencyAmount::coins(10));
        terms.height = BlockHeight::new((BLOCKS_PER_GENERATION + 1).into());
        assert_eq!(
            Err(FillError::WrongAmount),
            fill_witness(&order, &terms).map(|_| ())
        );
    }

    /// The order UTXO is lustrated if and only if a lustration status asks
    /// for it.
    #[test]
    fn the_order_is_lustrated_when_the_status_asks() {
        let (order, mut terms) = order_and_terms(NativeCurrencyAmount::coins(10));
        let announcements = |terms: &FillTerms| {
            fill_witness(&order, terms)
                .unwrap()
                .kernel
                .announcements
                .iter()
                .filter(|announcement| announcement.looks_like_lustration())
                .count()
        };
        assert_eq!(0, announcements(&terms));

        terms.lustration_status = Some(LustrationStatus {
            counter: NativeCurrencyAmount::coins(1_000_000),
            max_lustrating_aocl_leaf_index: 0,
        });
        assert_eq!(1, announcements(&terms));
    }

    /// The fill is valid whatever the order offers: nothing, one nau, an odd
    /// amount, or more than the block subsidy.
    #[tokio::test]
    async fn the_fill_is_valid_for_any_offered_amount() {
        for offered in [
            NativeCurrencyAmount::from_nau(0),
            NativeCurrencyAmount::from_nau(1),
            NativeCurrencyAmount::coins(13) + NativeCurrencyAmount::from_nau(1),
            NativeCurrencyAmount::coins(1_000_000),
        ] {
            let (order, terms) = order_and_terms(offered);
            let witness = fill_witness(&order, &terms).unwrap();
            assert!(witness.validate().await.is_ok(), "{offered}");
        }
    }
}
