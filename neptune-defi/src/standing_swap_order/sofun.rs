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
#[derive(Debug, Clone, Copy, BFieldCodec)]
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

#[cfg(test)]
mod tests {
    use tasm_lib::triton_vm::prelude::BFieldElement;

    use std::collections::HashSet;

    use neptune_primitives::block_height::BlockHeight;
    use neptune_primitives::block_height::BLOCKS_PER_GENERATION;
    use neptune_primitives::block_height::NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT;

    use super::*;
    use crate::standing_swap_order::order_book::BlockId;
    use crate::standing_swap_order::order_book::BlockUpdate;
    use crate::standing_swap_order::order_book::OrderId;
    use crate::standing_swap_order::v1::StandingSwapOrderV1;
    use crate::standing_swap_order::AssetPair;
    use crate::standing_swap_order::UnrecognizedOrder;
    use crate::standing_swap_order::STANDING_SWAP_ORDER_FLAG;

    /// The window of disagreement between `StandingSwapOrderV1` and `SofunBody`.
    /// `StandingSwapOrderV1` spends it on `demanded_amount` and
    /// [`SofunBody`] spends it on `padding`, `epoch` and `d_zero`.
    const OVERLOADED_ELEMENTS: std::ops::Range<usize> = 20..24;

    fn digest(seed: u64) -> Digest {
        Digest::new([1, 2, 3, 4, 5].map(|i| BFieldElement::new(seed * 100 + i)))
    }

    fn sofun() -> SofunBody {
        SofunBody {
            offered_amount: NativeCurrencyAmount::coins(7),
            d_zero: Timestamp::millis(1_757_000_000_000),
            epoch: 3,
            padding: 0,
            seed: digest(1),
            cancel_post_image: digest(2),
            reward_lock_script_hash: digest(3),
            reward_receiver_digest: digest(4),
        }
    }

    #[test]
    fn sofun_matches_the_v1_layout() {
        let generic = StandingSwapOrderV1 {
            offered_amount: sofun().offered_amount,
            demanded_amount: NativeCurrencyAmount::coins(11),
            seed: sofun().seed,
            cancel_post_image: sofun().cancel_post_image,
            reward_lock_script_hash: sofun().reward_lock_script_hash,
            reward_receiver_digest: sofun().reward_receiver_digest,
        };

        let sofun = sofun().encode();
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
        assert_ne!(sofun[OVERLOADED_ELEMENTS], generic[OVERLOADED_ELEMENTS]);
    }

    /// Decoding success is not a schema test, and the failure is one-directional.
    ///
    /// `demanded_amount` is an `i128` written as four 32-bit limbs, so every
    /// element in the overloaded window is below `u32::MAX` by construction.
    /// That is exactly what `SofunBody`'s `epoch` and `padding` require, and its
    /// `d_zero` accepts any element at all. So a generic body always decodes as
    /// a SOFuN order, with a meaningless release date. Only `pair_id` separates
    /// the two.
    #[test]
    fn a_generic_body_always_decodes_as_sofun() {
        for demanded_amount in [
            NativeCurrencyAmount::coins(11),
            NativeCurrencyAmount::from_nau(0),
            NativeCurrencyAmount::from_nau(i128::MAX),
            NativeCurrencyAmount::from_nau(-1),
        ] {
            let generic = StandingSwapOrderV1 {
                offered_amount: sofun().offered_amount,
                demanded_amount,
                seed: sofun().seed,
                cancel_post_image: sofun().cancel_post_image,
                reward_lock_script_hash: sofun().reward_lock_script_hash,
                reward_receiver_digest: sofun().reward_receiver_digest,
            };
            assert!(SofunBody::decode(&generic.encode()).is_ok());
        }
    }

    #[test]
    fn a_sofun_body_does_not_decode_as_a_generic_order() {
        // A timestamp in milliseconds exceeds `u32::MAX`, and the amount codec
        // rejects any limb above that bound, so the wrong decoder fails loudly
        // rather than reporting a nonsense price. That follows from real
        // timestamps, not from the layout: a `d_zero` small enough to pass
        // would be a date before 1970-02-19, which no order can carry.
        assert!(u64::from(u32::MAX) < sofun().d_zero.0.value());
        assert!(StandingSwapOrderV1::decode(&sofun().encode()).is_err());
    }

    /// Decoding and re-encoding a valid body reproduces it element for element.
    #[test]
    fn a_sofun_body_survives_a_round_trip() {
        let order = StandingSwapOrder::<Sofun>::try_from(sofun()).unwrap();
        assert_eq!(sofun().encode(), SofunBody::from(order).encode());
    }

    #[test]
    fn recognize_checks_the_envelope_before_the_body() {
        let pair_id = BFieldElement::new(77);
        let message = |flag, id, version, body: SofunBody| {
            [vec![flag, id, BFieldElement::new(version)], body.encode()].concat()
        };
        let recognize = |message: Vec<BFieldElement>| Sofun::recognize(pair_id, &message);

        let valid = message(STANDING_SWAP_ORDER_FLAG, pair_id, 0, sofun());
        let order = recognize(valid.clone()).unwrap();
        assert_eq!(sofun().encode(), SofunBody::from(order).encode());

        let other_flag = BFieldElement::new(999);
        let other_pair = BFieldElement::new(78);
        let padded = SofunBody {
            padding: 1,
            ..sofun()
        };
        for (message, reason) in [
            (
                message(other_flag, pair_id, 0, sofun()),
                UnrecognizedOrder::NotAnOrder,
            ),
            (
                message(STANDING_SWAP_ORDER_FLAG, other_pair, 0, sofun()),
                UnrecognizedOrder::NotThisPair,
            ),
            (
                message(STANDING_SWAP_ORDER_FLAG, pair_id, 1, sofun()),
                UnrecognizedOrder::UnknownVersion(BFieldElement::new(1)),
            ),
            (
                message(STANDING_SWAP_ORDER_FLAG, pair_id, 0, padded),
                UnrecognizedOrder::Malformed,
            ),
            (
                valid[..valid.len() - 1].to_vec(),
                UnrecognizedOrder::Malformed,
            ),
            (valid[..2].to_vec(), UnrecognizedOrder::Malformed),
        ] {
            assert_eq!(Err(reason), recognize(message).map(|_| ()));
        }
    }

    #[test]
    fn a_sofun_body_with_nonzero_padding_is_rejected() {
        let body = SofunBody {
            padding: 1,
            ..sofun()
        };
        assert!(StandingSwapOrder::<Sofun>::try_from(body).is_err());
    }

    #[test]
    fn demanding_filters_by_demanded_amount_then_ranks_by_offered_amount() {
        let block = BlockId {
            height: BlockHeight::from(1_u64),
            hash: Digest::default(),
        };
        let order = |id, offered, epoch| Order::<Sofun> {
            id: OrderId(id),
            opened_in: block,
            closed_in: None,
            order: StandingSwapOrder::<Sofun>::new(
                NativeCurrencyAmount::coins(offered),
                SofunParams {
                    d_zero: Timestamp::default(),
                    epoch,
                },
                Digest::default(),
                Digest::default(),
                Digest::default(),
                Digest::default(),
            ),
        };

        let mut book = OrderBook::<Sofun>::new(AssetPair {
            offered: HashSet::new(),
            demanded: HashSet::new(),
        });
        book.apply(BlockUpdate::<Sofun> {
            block,
            parent: Digest::default(),
            opened: vec![order(1, 5, 0), order(2, 9, 0), order(3, 99, 1)],
            closed: vec![],
        })
        .unwrap();

        let ids = book
            .demanding(Block::generation_subsidy(0).half())
            .iter()
            .map(|order| order.id)
            .collect::<Vec<_>>();
        assert_eq!(vec![OrderId(2), OrderId(1)], ids);
    }

    #[test]
    fn a_decoded_order_is_found_by_half_the_subsidy_of_its_block() {
        // The first height of generation 1. Without the reboot offset it would
        // count as generation 0, whose subsidy is twice as large, so an epoch
        // derived without the offset fails this test.
        let height = BlockHeight::from(BLOCKS_PER_GENERATION - NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT);
        assert_eq!(1, height.get_generation());

        let body = SofunBody {
            epoch: u32::try_from(height.get_generation()).unwrap(),
            ..sofun()
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
