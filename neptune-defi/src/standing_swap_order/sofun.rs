pub mod fill;
pub mod plugin;

use std::collections::HashSet;

use neptune_consensus::block::Block;
use neptune_consensus::block::MINING_REWARD_TIME_LOCK_PERIOD;
use neptune_consensus::proof_abstractions::tasm::program::TritonProgram;
use neptune_consensus::transaction::utxo::Utxo;
use neptune_consensus::transaction::utxo_triple::UtxoTriple;
use neptune_consensus::type_scripts::native_currency::NativeCurrency;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_consensus::type_scripts::time_lock::TimeLock;
use neptune_primitives::timestamp::Timestamp;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldCodec;

use super::order_book::Order;
use super::order_book::OrderBook;
use super::sso_lock_script::SsoLockScript;
use super::AssetPair;
use super::StandingSwapOrder;
use super::Swappable;

/// `G`: the spacing of an order's grid of release dates.
///
/// Fixed, so it is not on the wire.
pub const GRID_STEP: Timestamp = Timestamp::days(7);

/// `K`: how many release dates an order's grid holds.
///
/// It sets the shelf life of an order, because the grid is anchored at
/// creation: the order is fillable only while its last grid point still clears
/// three years out, which is `(K - 1) * G` from placement.
pub const NUM_GRID_POINTS: u32 = 26;

/// A timestamp for unlock dates beyond which a SOFuN order is invalid.
///
/// No release date on an order's grid is allowed to reach this bound, so
/// `D_0 + k * G` is the same number in `u64` as it is in the field, and a
/// release date is never a wrapped-around one.
const RELEASE_DATE_BOUND: u64 = 1 << 63;

/// Why a [`SofunBody`] is not a valid SOFuN order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SofunError {
    /// `padding` is nonzero
    NonzeroPadding,

    /// The offered amount is negative, which no UTXO can hold.
    NegativeOffer,

    /// `D_0 + (K - 1) * G` reaches `2^63` milliseconds, past which a release
    /// date would wrap the field.
    GridOutOfRange,
}

/// The encoding format of a [`super::StandingSwapOrder`] for Future Neptune
/// coins.
///
/// Agrees with [`super::v1::StandingSwapOrderV1`], except for `demanded_amount`
/// which here becomes
///  - d_zero: Timestamp -- when the timestamp grid starts
///  - epoch: u32 -- which epoch the order is valid for
///  - padding: u64 -- must be zero
#[derive(Debug, Clone, Copy, BFieldCodec, PartialEq, Eq)]
pub struct SofunBody {
    offered_amount: NativeCurrencyAmount,
    d_zero: Timestamp,
    epoch: u32,
    padding: u64,
    seed: Digest,
    cancel_post_image: Digest,
    reward_lock_script_hash: Digest,
    reward_receiver_digest: Digest,
}

/// The SOFuN configuration of a standing swap order: orders for Future Neptune
/// coins, paid into a grid of release dates.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(arbitrary::Arbitrary))]
pub struct Sofun;

impl SofunParams {
    /// `D_max`, the last point of the grid, or [`SofunError::GridOutOfRange`]
    /// if that point reaches [`RELEASE_DATE_BOUND`].
    ///
    /// The whole grid lies between `d_zero` and this, so a grid fits if and
    /// only if its last point does.
    fn last_release_date(&self) -> Result<Timestamp, SofunError> {
        let span = u64::from(NUM_GRID_POINTS - 1) * GRID_STEP.to_millis();
        let d_max = self
            .d_zero
            .to_millis()
            .checked_add(span)
            .ok_or(SofunError::GridOutOfRange)?;
        if d_max >= RELEASE_DATE_BOUND {
            return Err(SofunError::GridOutOfRange);
        }

        Ok(Timestamp::millis(d_max))
    }
}

impl StandingSwapOrder<Sofun> {
    /// A SOFuN order, whose demanded amount is half the block subsidy of
    /// generation `params.epoch`, or an error if the offered amount is
    /// negative or the grid reaches `RELEASE_DATE_BOUND`.
    pub fn new(
        offered_amount: NativeCurrencyAmount,
        params: SofunParams,
        seed: Digest,
        cancel_post_image: Digest,
        reward_lock_script_hash: Digest,
        reward_receiver_digest: Digest,
    ) -> Result<Self, SofunError> {
        if offered_amount.is_negative() {
            return Err(SofunError::NegativeOffer);
        }
        // check the grid
        params.last_release_date()?;

        let demanded_amount = Block::generation_subsidy(u64::from(params.epoch)).half();
        Ok(Self {
            offered_amount,
            demanded_amount,
            seed,
            cancel_post_image,
            reward_lock_script_hash,
            reward_receiver_digest,
            params,
        })
    }

    /// The reward this order would generate at the given release date.
    ///
    /// Accepts release dates off the grid, so it may result in an invalid
    /// reward if not used with care.
    fn reward_released_at(&self, release_date: Timestamp) -> UtxoTriple {
        UtxoTriple {
            utxo: Utxo::new_native_currency(self.reward_lock_script_hash, self.demanded_amount)
                .with_time_lock(release_date),
            sender_randomness: self.reward_sender_randomness(),
            receiver_digest: self.reward_receiver_digest,
        }
    }

    /// The reward that fills this order at grid point `k`, released at
    /// `D_0 + k * G`. `None` for `k >= K`, which is not a point of the grid.
    pub fn reward(&self, k: u32) -> Option<UtxoTriple> {
        if k >= NUM_GRID_POINTS {
            return None;
        }

        let release_date = Timestamp::millis(
            self.params.d_zero.to_millis() + u64::from(k) * GRID_STEP.to_millis(),
        );

        Some(self.reward_released_at(release_date))
    }

    /// Every reward this order admits, one per grid point, in grid order.
    ///
    /// This is the wallet's watch set: `K` candidate payments, of which at most
    /// one is ever made.
    pub fn rewards(&self) -> Vec<UtxoTriple> {
        (0..NUM_GRID_POINTS)
            .map(|k| self.reward(k).expect("k < K"))
            .collect()
    }

    /// The order's lock script: cancelled by the proposer's preimage, filled by
    /// any transaction paying one of [`Self::rewards`].
    ///
    /// The grid is a rule for constructing the admissible set, and this is
    /// where the rule is applied. Everything below this point is the general
    /// standing swap order, which knows nothing about release dates.
    pub fn lock_script(&self) -> SsoLockScript {
        SsoLockScript {
            cancel_post_image: self.cancel_post_image,
            admissible_outputs: self
                .rewards()
                .iter()
                .map(UtxoTriple::addition_record)
                .collect(),
        }
    }
}

impl From<StandingSwapOrder<Sofun>> for SofunBody {
    fn from(order: StandingSwapOrder<Sofun>) -> Self {
        SofunBody {
            offered_amount: order.offered_amount,
            d_zero: order.params.d_zero,
            epoch: order.params.epoch,
            padding: 0,
            seed: order.seed,
            cancel_post_image: order.cancel_post_image,
            reward_lock_script_hash: order.reward_lock_script_hash,
            reward_receiver_digest: order.reward_receiver_digest,
        }
    }
}

impl TryFrom<SofunBody> for StandingSwapOrder<Sofun> {
    type Error = SofunError;

    fn try_from(body: SofunBody) -> Result<Self, Self::Error> {
        if body.padding != 0 {
            return Err(SofunError::NonzeroPadding);
        }
        let params = SofunParams {
            d_zero: body.d_zero,
            epoch: body.epoch,
        };
        Self::new(
            body.offered_amount,
            params,
            body.seed,
            body.cancel_post_image,
            body.reward_lock_script_hash,
            body.reward_receiver_digest,
        )
    }
}

impl Sofun {
    /// SOFuN's market: native currency offered for native currency that is
    /// time-locked.
    ///
    /// This is what `pair_id` names. A consumer builds the pair itself, from
    /// the type scripts this schema fixes, and never recovers it from an
    /// announcement, since `pair_id` is a one-way hash of a single element.
    pub fn asset_pair() -> AssetPair {
        AssetPair {
            offered: HashSet::from([NativeCurrency.hash()]),
            demanded: HashSet::from([NativeCurrency.hash(), TimeLock.hash()]),
        }
    }
}

impl Swappable for Sofun {
    fn version() -> u64 {
        0
    }

    type Params = SofunParams;

    type EncodingFormat = SofunBody;

    fn order_utxo(order: &StandingSwapOrder<Self>) -> UtxoTriple {
        UtxoTriple {
            utxo: Utxo::new_native_currency(
                order.lock_script().lock_script().hash(),
                order.offered_amount,
            ),
            sender_randomness: order.offered_sender_randomness(),
            receiver_digest: order.offered_receiver_preimage().hash(),
        }
    }
}

/// The parameters a SOFuN order carries beyond its standing swap terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SofunParams {
    /// The first point of the order's grid of release dates.
    pub d_zero: Timestamp,

    /// The generation, as [`BlockHeight::get_generation`] counts it, whose
    /// block subsidy the demanded amount is half of.
    ///
    /// [`BlockHeight::get_generation`]: neptune_primitives::block_height::BlockHeight::get_generation
    pub epoch: u32,
}

impl OrderBook<Sofun> {
    /// Open orders asking exactly `demanded`, richest offer first.
    ///
    /// The filter comes before the ranking because a composer cannot fill an
    /// order demanding anything other than half of its own block's subsidy.
    /// There is no best order in general, only a best order for a given block,
    /// which is why the amount is an argument. Every order that survives the
    /// filter demands the same amount, so ranking by the offered amount is
    /// ranking by price.
    ///
    /// Callers still skip orders that are not
    /// [fillable](StandingSwapOrder::is_fillable_at) at their timestamp.
    //
    // ponytail: scan and sort per query, O(n log n) in the whole book. Replace
    // with a priority queue on the offered amount, bucketed by demanded amount,
    // when a composer's template build measurably notices.
    pub fn demanding(&self, demanded: NativeCurrencyAmount) -> Vec<&Order<Sofun>> {
        let mut matching = self
            .open_orders()
            .filter(|order| order.order.demanded_amount() == demanded)
            .collect::<Vec<_>>();
        matching.sort_unstable_by_key(|order| std::cmp::Reverse(order.order.offered_amount()));

        matching
    }

    /// The order to fill in a transaction with timestamp `timestamp` that
    /// redirects `demanded`: of the open orders demanding exactly `demanded`
    /// and fillable at `timestamp`, the one that offers the most. `None` if no
    /// open order qualifies.
    pub fn best_fill(
        &self,
        demanded: NativeCurrencyAmount,
        timestamp: Timestamp,
    ) -> Option<&Order<Sofun>> {
        self.demanding(demanded)
            .into_iter()
            .find(|order| order.order.is_fillable_at(timestamp))
    }
}

impl StandingSwapOrder<Sofun> {
    /// Whether a fill in a transaction with timestamp `timestamp` can release
    /// the reward at a point of this order's grid that counts toward the
    /// composer's time-locked half, which is true if and only if the grid's
    /// last point is at least `timestamp + 3 years`.
    pub fn is_fillable_at(&self, timestamp: Timestamp) -> bool {
        self.params
            .last_release_date()
            .is_ok_and(|d_max| d_max >= timestamp + MINING_REWARD_TIME_LOCK_PERIOD)
    }
}

// A derived implementation would draw a `d_zero` whose grid runs off the end of
// the field, which the constructor rejects.
#[cfg(any(test, feature = "arbitrary-impls"))]
impl<'a> arbitrary::Arbitrary<'a> for SofunParams {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let span = u64::from(NUM_GRID_POINTS - 1) * GRID_STEP.to_millis();
        Ok(Self {
            d_zero: Timestamp::millis(u.int_in_range(0..=RELEASE_DATE_BOUND - span - 1)?),
            epoch: u.arbitrary()?,
        })
    }
}

// A derived implementation would set `padding` to nonzero values, which
// decoding rejects.
#[cfg(any(test, feature = "arbitrary-impls"))]
impl<'a> arbitrary::Arbitrary<'a> for SofunBody {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(u.arbitrary::<StandingSwapOrder<Sofun>>()?.into())
    }
}

// The demanded amount is not arbitrary, so the constructor must compute it.
#[cfg(any(test, feature = "arbitrary-impls"))]
impl<'a> arbitrary::Arbitrary<'a> for StandingSwapOrder<Sofun> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // `SofunParams` draws a grid that fits, and the offer is made
        // non-negative, so the constructor cannot fail here.
        let offered: NativeCurrencyAmount = u.arbitrary()?;
        let offered = if offered.is_negative() {
            -offered
        } else {
            offered
        };
        Ok(Self::new(
            offered,
            u.arbitrary()?,
            u.arbitrary()?,
            u.arbitrary()?,
            u.arbitrary()?,
            u.arbitrary()?,
        )
        .expect("an arbitrary order is valid"))
    }
}

#[cfg(test)]
mod tests {
    use tasm_lib::triton_vm::prelude::BFieldElement;

    use std::collections::HashMap;
    use std::collections::HashSet;

    use neptune_consensus::transaction::transaction_kernel::TransactionKernel;
    use neptune_mutator_set::addition_record::AdditionRecord;
    use neptune_primitives::block_height::BlockHeight;
    use neptune_primitives::block_height::BLOCKS_PER_GENERATION;
    use neptune_primitives::block_height::NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT;
    use proptest::collection::hash_map;
    use proptest::collection::hash_set;
    use proptest::collection::vec;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest::prop_assume;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;
    use crate::chain::BlockId;
    use crate::standing_swap_order::order_book::BlockUpdate;
    use crate::standing_swap_order::order_book::OrderId;
    use crate::standing_swap_order::sso_lock_script::tests::public_input;
    use crate::standing_swap_order::sso_lock_script::tests::with_outputs;
    use crate::standing_swap_order::v1::StandingSwapOrderV1;
    use crate::standing_swap_order::AssetPair;
    use crate::standing_swap_order::UnrecognizedOrder;
    use crate::standing_swap_order::STANDING_SWAP_ORDER_FLAG;

    /// The window where `StandingSwapOrderV1` and `SofunBody` are allowed to
    /// disagree.
    /// `StandingSwapOrderV1` spends it on `demanded_amount` and
    /// [`SofunBody`] spends it on `padding`, `epoch` and `d_zero`.
    const OVERLOADED_ELEMENTS: std::ops::Range<usize> = 20..24;

    #[proptest]
    fn sofun_matches_the_v1_layout(
        #[strategy(arb())] body: SofunBody,
        #[strategy(arb())] demanded_amount: NativeCurrencyAmount,
    ) {
        let generic = StandingSwapOrderV1 {
            offered_amount: body.offered_amount,
            demanded_amount,
            seed: body.seed,
            cancel_post_image: body.cancel_post_image,
            reward_lock_script_hash: body.reward_lock_script_hash,
            reward_receiver_digest: body.reward_receiver_digest,
        };

        let sofun = body.encode();
        let generic = generic.encode();
        assert_eq!(28, sofun.len());
        assert_eq!(28, generic.len());

        // Every field the two schemas share sits at the same offset, so the
        // encodings agree everywhere outside the overloaded window.
        assert_eq!(
            sofun[..OVERLOADED_ELEMENTS.start],
            generic[..OVERLOADED_ELEMENTS.start]
        );
        assert_eq!(
            sofun[OVERLOADED_ELEMENTS.end..],
            generic[OVERLOADED_ELEMENTS.end..]
        );

        // The windows agree only if the four limbs of `demanded_amount` equal the
        // elements of `d_zero`, `epoch` and `padding`, which arbitrary inputs make
        // negligibly likely. The inequality shows that the fields the schemas
        // disagree on lie inside the window.
        assert_ne!(sofun[OVERLOADED_ELEMENTS], generic[OVERLOADED_ELEMENTS]);
    }

    /// Decoding success is not a schema test, and the failure is one-directional.
    ///
    /// `demanded_amount` is an `i128` written as four 32-bit limbs, so every
    /// element in the overloaded window is below `u32::MAX` by construction.
    /// That is exactly what `SofunBody`'s `epoch` and `padding` require, and
    /// its `d_zero` accepts any element at all. So a generic body always
    /// decodes as a SOFuN order, with a meaningless release date. Only
    /// `pair_id` separates the two.
    #[proptest]
    fn v1_always_decodes_as_sofun(#[strategy(arb())] v1: StandingSwapOrderV1, demanded_nau: i128) {
        // Use a uniform u128 for `demanded_amount`
        let v1 = StandingSwapOrderV1 {
            demanded_amount: NativeCurrencyAmount::from_nau(demanded_nau),
            ..v1
        };
        assert!(SofunBody::decode(&v1.encode()).is_ok());
    }

    #[proptest]
    fn sofun_body_does_not_decode_as_v1(
        #[strategy(arb())]
        #[filter(u64::from(u32::MAX) < #body.d_zero.0.value())]
        body: SofunBody,
    ) {
        // A timestamp in milliseconds exceeds `u32::MAX`, and the amount codec
        // rejects any limb above that bound, so the wrong decoder fails loudly
        // rather than reporting a nonsense price. That follows from real
        // timestamps, not from the layout: a `d_zero` small enough to pass
        // would be a date before 1970-02-19, which no order can carry.
        assert!(StandingSwapOrderV1::decode(&body.encode()).is_err());
    }

    /// Decoding and re-encoding a valid body reproduces it element for element.
    #[proptest]
    fn sofun_body_survives_a_round_trip(#[strategy(arb())] body: SofunBody) {
        let order = StandingSwapOrder::<Sofun>::try_from(body).unwrap();
        assert_eq!(body, SofunBody::from(order));
    }

    #[proptest]
    fn recognize_checks_envelope_before_body(
        #[strategy(arb())] pair_id: BFieldElement,
        #[strategy(arb())] body: SofunBody,
        #[strategy(arb())]
        #[filter(#other_flag != STANDING_SWAP_ORDER_FLAG)]
        other_flag: BFieldElement,
        #[strategy(arb())]
        #[filter(#other_pair != #pair_id)]
        other_pair: BFieldElement,
        #[strategy(arb())]
        #[filter(#other_version != BFieldElement::new(Sofun::version()))]
        other_version: BFieldElement,
        #[filter(#padding != 0)] padding: u64,
        #[strategy(1..VALID_LENGTH)] prefix_len: usize,
        #[strategy(vec(arb::<BFieldElement>(),1..10))] suffix: Vec<BFieldElement>,
    ) {
        let version = BFieldElement::new(Sofun::version());
        let message =
            |flag, id, version, body: SofunBody| [vec![flag, id, version], body.encode()].concat();
        let recognize = |message: Vec<BFieldElement>| Sofun::recognize(pair_id, &message);

        let valid = message(STANDING_SWAP_ORDER_FLAG, pair_id, version, body);
        assert_eq!(VALID_LENGTH, valid.len());
        let order = recognize(valid.clone()).unwrap();
        assert_eq!(body.encode(), SofunBody::from(order).encode());

        let padded = SofunBody { padding, ..body };
        for (message, reason) in [
            (
                message(other_flag, pair_id, version, body),
                UnrecognizedOrder::NotAnOrder,
            ),
            (
                message(STANDING_SWAP_ORDER_FLAG, other_pair, version, body),
                UnrecognizedOrder::NotThisPair,
            ),
            (
                message(STANDING_SWAP_ORDER_FLAG, pair_id, other_version, body),
                UnrecognizedOrder::UnknownVersion(other_version),
            ),
            (
                message(STANDING_SWAP_ORDER_FLAG, pair_id, version, padded),
                UnrecognizedOrder::Malformed,
            ),
            (valid[..prefix_len].to_vec(), UnrecognizedOrder::Malformed),
            ([valid, suffix].concat(), UnrecognizedOrder::Malformed),
        ] {
            assert_eq!(Err(reason), recognize(message).map(|_| ()));
        }
    }

    /// An announcement is what `recognize` reads, so the two are tested as
    /// one: generate, then read back under the pair's own id.
    #[proptest]
    fn an_announced_order_is_recognized(#[strategy(arb())] body: SofunBody) {
        let order = StandingSwapOrder::<Sofun>::try_from(body).unwrap();
        let pair = Sofun::asset_pair();
        let message = order.announce(&pair).message;

        assert_eq!(VALID_LENGTH, message.len());
        assert_eq!(STANDING_SWAP_ORDER_FLAG, message[0]);
        assert_eq!(pair.pair_id(), message[1]);
        assert_eq!(BFieldElement::new(Sofun::version()), message[2]);

        let recognized = Sofun::recognize(pair.pair_id(), &message).unwrap();
        assert_eq!(body, SofunBody::from(recognized));
    }

    /// The length of a message: three envelope elements and a 28-element body.
    const VALID_LENGTH: usize = 3 + 28;

    #[proptest]
    fn sofun_body_with_nonzero_padding_is_rejected(
        #[strategy(arb())] body: SofunBody,
        #[filter(#padding != 0)] padding: u64,
    ) {
        let body = SofunBody { padding, ..body };
        assert!(StandingSwapOrder::<Sofun>::try_from(body).is_err());
    }

    #[proptest]
    fn sofun_reward_expected_features(
        #[strategy(arb())] order: StandingSwapOrder<Sofun>,
        #[strategy(0..NUM_GRID_POINTS)] k: u32,
    ) {
        let reward = order.reward(k).unwrap();
        let expected_release_date = Timestamp::millis(
            order.params.d_zero.to_millis() + u64::from(k) * GRID_STEP.to_millis(),
        );

        prop_assert_eq!(
            order.reward_lock_script_hash,
            reward.utxo.lock_script_hash()
        );
        prop_assert_eq!(2, reward.utxo.coins().len());
        prop_assert_eq!(
            order.demanded_amount,
            reward.utxo.get_native_currency_amount()
        );
        prop_assert_eq!(Some(expected_release_date), reward.utxo.release_date());
        prop_assert_eq!(order.reward_receiver_digest, reward.receiver_digest);
        prop_assert_eq!(order.reward_sender_randomness(), reward.sender_randomness);
    }

    /// A transaction fills the order if and only if it pays the
    /// reward at some point of the grid. Any point of the grid works.
    #[proptest(cases = 2)]
    fn order_is_filled_at_every_grid_point_and_nowhere_else(
        #[strategy(arb())] order: StandingSwapOrder<Sofun>,
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(vec(arb::<AdditionRecord>(), 0..3))] other_outputs: Vec<AdditionRecord>,
    ) {
        let lock_script = order.lock_script();
        prop_assert_eq!(
            NUM_GRID_POINTS as usize,
            lock_script.admissible_outputs.len()
        );

        let unpaid = with_outputs(&kernel, other_outputs.clone());
        prop_assert!(lock_script.fill(&unpaid).is_none());

        for k in 0..NUM_GRID_POINTS {
            let reward = order.reward(k).unwrap().addition_record();
            let paid = with_outputs(&kernel, [other_outputs.clone(), vec![reward]].concat());
            prop_assert!(lock_script
                .fill(&paid)
                .unwrap()
                .halts_gracefully(public_input(&paid)));
        }
    }

    /// The grid stops at `K`. A release date one step past the last is a date
    /// like any other, and the order does not admit its reward.
    #[proptest(cases = 4)]
    fn no_release_date_past_the_grid_fills_the_order(
        #[strategy(arb())] order: StandingSwapOrder<Sofun>,
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(NUM_GRID_POINTS..NUM_GRID_POINTS + 4)] k: u32,
    ) {
        prop_assert!(order.reward(k).is_none());

        let past_the_grid = Timestamp::millis(
            order.params.d_zero.to_millis() + u64::from(k) * GRID_STEP.to_millis(),
        );
        let reward = order.reward_released_at(past_the_grid).addition_record();
        let paid = with_outputs(&kernel, vec![reward]);
        prop_assert!(order.lock_script().fill(&paid).is_none());
    }

    #[proptest(cases = 2)]
    fn malformed_reward_does_not_fill(
        #[strategy(arb())] order: StandingSwapOrder<Sofun>,
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(0_u32..8)] epoch: u32,
        #[strategy(0_u32..8)] other_epoch: u32,
        #[strategy(arb())] other_lock_script_hash: Digest,
        #[strategy(arb())] other_receiver_digest: Digest,
        #[strategy(0..NUM_GRID_POINTS)] k: u32,
    ) {
        prop_assume!(epoch != other_epoch);
        prop_assume!(order.reward_lock_script_hash != other_lock_script_hash);
        prop_assume!(order.reward_receiver_digest != other_receiver_digest);

        let variant = |epoch, reward_lock_script_hash, reward_receiver_digest| {
            StandingSwapOrder::<Sofun>::new(
                order.offered_amount,
                SofunParams {
                    epoch,
                    ..order.params
                },
                order.seed,
                order.cancel_post_image,
                reward_lock_script_hash,
                reward_receiver_digest,
            )
            .unwrap()
        };

        let lsh = order.reward_lock_script_hash;
        let rd = order.reward_receiver_digest;
        let order = variant(epoch, lsh, rd);
        let lock_script = order.lock_script();

        // The right reward at the same grid point does fill, so each failure
        // below is the one term that was changed and nothing else.
        let successful_fill =
            with_outputs(&kernel, vec![order.reward(k).unwrap().addition_record()]);
        prop_assert!(lock_script
            .fill(&successful_fill)
            .unwrap()
            .halts_gracefully(public_input(&successful_fill)));

        for wrong in [
            variant(other_epoch, lsh, rd),
            variant(epoch, other_lock_script_hash, rd),
            variant(epoch, lsh, other_receiver_digest),
        ] {
            let failed_fill =
                with_outputs(&kernel, vec![wrong.reward(k).unwrap().addition_record()]);
            prop_assert!(lock_script.fill(&failed_fill).is_none());
        }
    }

    /// Two orders
    /// agreeing on every reward parameter but the seed share no admissible
    /// output, at any grid point, so no one output spends both.
    #[proptest(cases = 2)]
    fn distinct_seeds_make_two_orders_disjoint(
        #[strategy(arb())] order: StandingSwapOrder<Sofun>,
        #[strategy(arb())] other_seed: Digest,
    ) {
        prop_assume!(order.seed != other_seed);
        let other = StandingSwapOrder::<Sofun> {
            seed: other_seed,
            ..order
        };

        let admissible = order.lock_script().admissible_outputs;
        prop_assert!(other
            .lock_script()
            .admissible_outputs
            .iter()
            .all(|output| !admissible.contains(output)));
    }

    /// The last grid point stays below the bound, so no release date is a
    /// wrapped-around one. The constructor is the only place that check lives,
    /// so an order with such a grid cannot be built, and an announcement
    /// carrying one is malformed rather than an order nobody can fill.
    #[proptest]
    fn out_of_bounds_grid_is_rejected(
        #[strategy(arb())] body: SofunBody,
        #[strategy(arb())] pair_id: BFieldElement,
        #[strategy(0_u64..1000)] overshoot: u64,
    ) {
        let span = u64::from(NUM_GRID_POINTS - 1) * GRID_STEP.to_millis();
        let build = |d_zero| StandingSwapOrder::<Sofun>::try_from(SofunBody { d_zero, ..body });

        // The bound is on the last grid point, so the two `d_zero` that
        // straddle it are `RELEASE_DATE_BOUND - span` and one millisecond
        // below. Both are asserted outright rather than drawn, because a
        // strategy that merely contains the boundary usually misses it: 256
        // uniform draws from a thousand values hit any one of them only about
        // a quarter of the time, and it is the boundary that tells `>=` from
        // `>`.
        prop_assert!(build(Timestamp::millis(RELEASE_DATE_BOUND - span - 1)).is_ok());
        prop_assert_eq!(
            Err(SofunError::GridOutOfRange),
            build(Timestamp::millis(RELEASE_DATE_BOUND - span)).map(|_| ())
        );

        // reject out-of-bounds grids on announcements too
        let d_zero = Timestamp::millis(RELEASE_DATE_BOUND - span + overshoot);
        prop_assert_eq!(Err(SofunError::GridOutOfRange), build(d_zero).map(|_| ()));

        let message = [
            vec![
                STANDING_SWAP_ORDER_FLAG,
                pair_id,
                BFieldElement::new(Sofun::version()),
            ],
            SofunBody { d_zero, ..body }.encode(),
        ]
        .concat();
        prop_assert_eq!(
            Err(UnrecognizedOrder::Malformed),
            Sofun::recognize(pair_id, &message).map(|_| ())
        );
    }

    /// `demanding` returns the open orders whose demanded amount is `demanded`,
    /// and no others, in order of non-increasing offered amount.
    ///
    /// Epochs are drawn from a range small enough that orders share them, so
    /// the filter both keeps and drops orders. Keying the terms on the order ID
    /// makes the IDs distinct.
    #[proptest]
    fn demanding_filters_by_demanded_amount_then_ranks_by_offered_amount(
        #[strategy(hash_map(arb::<OrderId>(), (arb::<SofunBody>(), 0_u32..4), 0..20))]
        terms: HashMap<OrderId, (SofunBody, u32)>,
        #[strategy(0_u32..4)] epoch: u32,
        #[strategy(arb())] block: BlockId,
        #[strategy(arb())] parent: Digest,
        #[strategy(hash_set(arb::<Digest>(), 0..4))] offered: HashSet<Digest>,
        #[strategy(hash_set(arb::<Digest>(), 0..4))] demanded: HashSet<Digest>,
    ) {
        let orders = terms
            .into_iter()
            .map(|(id, (body, epoch))| Order::<Sofun> {
                id,
                opened_in: block,
                closed_in: None,
                order: StandingSwapOrder::<Sofun>::try_from(SofunBody { epoch, ..body }).unwrap(),
            })
            .collect::<Vec<_>>();

        let mut book = OrderBook::<Sofun>::new(AssetPair { offered, demanded }, u64::MAX);
        book.apply(BlockUpdate::<Sofun> {
            block,
            parent,
            opened: orders.clone(),
            closed: vec![],
        })
        .unwrap();

        let demanded = Block::generation_subsidy(u64::from(epoch)).half();
        let found = book.demanding(demanded);

        let matching = orders
            .iter()
            .filter(|order| order.order.demanded_amount() == demanded)
            .count();
        assert_eq!(matching, found.len());
        assert!(found
            .iter()
            .all(|order| order.order.demanded_amount() == demanded));
        assert!(found
            .windows(2)
            .all(|pair| pair[0].order.offered_amount() >= pair[1].order.offered_amount()));
    }

    #[proptest]
    fn sofun_order_is_found(
        #[strategy(arb())] body: SofunBody,
        #[strategy(1_u64..8)] generation: u64,
        #[strategy(0..BLOCKS_PER_GENERATION)] index: u64,
    ) {
        // Generation `generation` starts `NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT`
        // heights before `generation * BLOCKS_PER_GENERATION`. An epoch derived
        // without the reboot offset is off by one on those first heights of
        // every generation, and fails this test there.
        let height = BlockHeight::from(
            generation * BLOCKS_PER_GENERATION - NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT + index,
        );
        assert_eq!(generation, height.get_generation());

        let body = SofunBody {
            epoch: u32::try_from(height.get_generation()).unwrap(),
            ..body
        };
        let decoded = *SofunBody::decode(&body.encode()).unwrap();
        let order = StandingSwapOrder::<Sofun>::try_from(decoded).unwrap();

        let block = BlockId {
            height,
            hash: Digest::default(),
        };
        let mut book = OrderBook::<Sofun>::new(
            AssetPair {
                offered: HashSet::new(),
                demanded: HashSet::new(),
            },
            u64::MAX,
        );
        book.apply(BlockUpdate::<Sofun> {
            block,
            parent: Digest::default(),
            opened: vec![Order {
                id: OrderId(0),
                opened_in: block,
                closed_in: None,
                order,
            }],
            closed: vec![],
        })
        .unwrap();

        let ids = book
            .demanding(Block::block_subsidy(height).half())
            .iter()
            .map(|order| order.id)
            .collect::<Vec<_>>();
        assert_eq!(vec![OrderId(0)], ids);
    }

    /// An order is fillable at `t` if and only if its last grid point is at
    /// least `t + 3 years`, so the last fillable timestamp is exactly three
    /// years before that point.
    #[proptest]
    fn fillable_until_three_years_before_the_last_grid_point(
        #[strategy(arb())] order: StandingSwapOrder<Sofun>,
    ) {
        let d_max = order.params.last_release_date().unwrap();
        prop_assume!(d_max >= MINING_REWARD_TIME_LOCK_PERIOD + Timestamp::millis(1));
        let last =
            Timestamp::millis(d_max.to_millis() - MINING_REWARD_TIME_LOCK_PERIOD.to_millis());

        prop_assert!(order.is_fillable_at(last));
        prop_assert!(!order.is_fillable_at(last + Timestamp::millis(1)));
    }

    /// The best fill is the richest order that is still fillable, skipping a
    /// richer one whose grid has run out.
    #[proptest]
    fn best_fill_is_the_richest_fillable_order(
        #[strategy(arb())] block: BlockId,
        #[strategy(arb())] parent: Digest,
    ) {
        let t = Timestamp::years(10);
        let order = |id, coins, d_zero| Order::<Sofun> {
            id: OrderId(id),
            opened_in: block,
            closed_in: None,
            order: StandingSwapOrder::<Sofun>::new(
                NativeCurrencyAmount::coins(coins),
                SofunParams { d_zero, epoch: 0 },
                Digest::default(),
                Digest::default(),
                Digest::default(),
                Digest::default(),
            )
            .unwrap(),
        };
        let expired = order(0, 3, Timestamp::years(1));
        let fillable = order(1, 2, t + MINING_REWARD_TIME_LOCK_PERIOD);
        let poorer = order(2, 1, t + MINING_REWARD_TIME_LOCK_PERIOD);
        let demanded = expired.order.demanded_amount();

        let mut book = OrderBook::<Sofun>::new(Sofun::asset_pair(), u64::MAX);
        book.apply(BlockUpdate::<Sofun> {
            block,
            parent,
            opened: vec![expired, fillable, poorer],
            closed: vec![],
        })
        .unwrap();

        let best = book.best_fill(demanded, t);
        prop_assert_eq!(Some(OrderId(1)), best.map(|order| order.id));
    }

    /// No UTXO can hold a negative amount, so no order can offer one. An
    /// announcement claiming one is not an order, whether or not a book would
    /// ever find its UTXO.
    #[proptest(cases = 10)]
    fn an_order_offering_a_negative_amount_is_refused(
        #[strategy(arb())] order: StandingSwapOrder<Sofun>,
        #[strategy(1..i64::MAX)] nau: i64,
    ) {
        let negative = NativeCurrencyAmount::from_nau(-i128::from(nau));
        let refused = StandingSwapOrder::<Sofun>::new(
            negative,
            order.params,
            order.seed,
            order.cancel_post_image,
            order.reward_lock_script_hash,
            order.reward_receiver_digest,
        );
        prop_assert_eq!(Some(SofunError::NegativeOffer), refused.err());
    }
}
