use neptune_consensus::block::Block;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_primitives::timestamp::Timestamp;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldCodec;

use super::order_book::Order;
use super::order_book::OrderBook;
use super::StandingSwapOrder;
use super::Swappable;

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

impl StandingSwapOrder<Sofun> {
    /// A SOFuN order, whose demanded amount is half the block subsidy of
    /// generation `params.epoch`.
    ///
    /// The demanded amount is computed rather than passed in.
    pub fn new(
        offered_amount: NativeCurrencyAmount,
        params: SofunParams,
        seed: Digest,
        cancel_post_image: Digest,
        reward_lock_script_hash: Digest,
        reward_receiver_digest: Digest,
    ) -> Self {
        Self {
            offered_amount,
            demanded_amount: Block::generation_subsidy(u64::from(params.epoch)).half(),
            seed,
            cancel_post_image,
            reward_lock_script_hash,
            reward_receiver_digest,
            params,
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
    type Error = ();

    fn try_from(body: SofunBody) -> Result<Self, Self::Error> {
        if body.padding != 0 {
            return Err(());
        }
        let params = SofunParams {
            d_zero: body.d_zero,
            epoch: body.epoch,
        };
        Ok(Self::new(
            body.offered_amount,
            params,
            body.seed,
            body.cancel_post_image,
            body.reward_lock_script_hash,
            body.reward_receiver_digest,
        ))
    }
}

impl Swappable for Sofun {
    fn version() -> u64 {
        0
    }

    type Params = SofunParams;

    type EncodingFormat = SofunBody;
}

/// The parameters a SOFuN order carries beyond its standing swap terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(arbitrary::Arbitrary))]
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
    /// Callers still skip orders whose grid no longer clears `t + 3 years`,
    /// reading [`StandingSwapOrder::params`].
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
        Ok(Self::new(
            u.arbitrary()?,
            u.arbitrary()?,
            u.arbitrary()?,
            u.arbitrary()?,
            u.arbitrary()?,
            u.arbitrary()?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use tasm_lib::triton_vm::prelude::BFieldElement;

    use std::collections::HashMap;
    use std::collections::HashSet;

    use neptune_primitives::block_height::BlockHeight;
    use neptune_primitives::block_height::BLOCKS_PER_GENERATION;
    use neptune_primitives::block_height::NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT;
    use proptest::collection::hash_map;
    use proptest::collection::hash_set;
    use proptest::collection::vec;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;
    use crate::standing_swap_order::order_book::BlockId;
    use crate::standing_swap_order::order_book::BlockUpdate;
    use crate::standing_swap_order::order_book::OrderId;
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

        let mut book = OrderBook::<Sofun>::new(AssetPair { offered, demanded });
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
        let mut book = OrderBook::<Sofun>::new(AssetPair {
            offered: HashSet::new(),
            demanded: HashSet::new(),
        });
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
}
