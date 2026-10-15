use neptune_consensus::transaction::utxo_triple::UtxoTriple;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldCodec;

use super::StandingSwapOrder;
use super::Swappable;

/// The encoding format of a version 1 [`super::StandingSwapOrder`].
#[derive(Debug, Clone, Copy, BFieldCodec, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(arbitrary::Arbitrary))]
pub struct StandingSwapOrderV1 {
    pub offered_amount: NativeCurrencyAmount,
    pub demanded_amount: NativeCurrencyAmount,
    pub seed: Digest,
    pub cancel_post_image: Digest,
    pub reward_lock_script_hash: Digest,
    pub reward_receiver_digest: Digest,
}

/// The configuration of a standing swap order in which both amounts are chosen
/// by the order's creator, and orders carry no parameters.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(arbitrary::Arbitrary))]
pub struct V1Swap;

impl Swappable for V1Swap {
    fn version() -> u64 {
        1
    }

    type Params = ();

    type EncodingFormat = StandingSwapOrderV1;

    fn order_utxo(_order: &StandingSwapOrder<Self>) -> UtxoTriple {
        unimplemented!("what the demanded UTXO's coins look like is not settled")
    }
}

/// Why a version 1 body is not a valid order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V1Error {
    /// The offered amount is negative, which no UTXO can hold.
    NegativeOffer,
}

impl StandingSwapOrder<V1Swap> {
    /// A version 1 order, or an error if the offered amount is negative. No
    /// other relation binds its terms, so every field is an argument.
    pub fn new(
        offered_amount: NativeCurrencyAmount,
        demanded_amount: NativeCurrencyAmount,
        seed: Digest,
        cancel_post_image: Digest,
        reward_lock_script_hash: Digest,
        reward_receiver_digest: Digest,
    ) -> Result<Self, V1Error> {
        if offered_amount.is_negative() {
            return Err(V1Error::NegativeOffer);
        }

        Ok(Self {
            offered_amount,
            demanded_amount,
            seed,
            cancel_post_image,
            reward_lock_script_hash,
            reward_receiver_digest,
            params: (),
        })
    }
}

impl From<StandingSwapOrder<V1Swap>> for StandingSwapOrderV1 {
    fn from(order: StandingSwapOrder<V1Swap>) -> Self {
        StandingSwapOrderV1 {
            offered_amount: order.offered_amount,
            demanded_amount: order.demanded_amount,
            seed: order.seed,
            cancel_post_image: order.cancel_post_image,
            reward_lock_script_hash: order.reward_lock_script_hash,
            reward_receiver_digest: order.reward_receiver_digest,
        }
    }
}

impl TryFrom<StandingSwapOrderV1> for StandingSwapOrder<V1Swap> {
    type Error = V1Error;

    fn try_from(body: StandingSwapOrderV1) -> Result<Self, Self::Error> {
        Self::new(
            body.offered_amount,
            body.demanded_amount,
            body.seed,
            body.cancel_post_image,
            body.reward_lock_script_hash,
            body.reward_receiver_digest,
        )
    }
}

#[cfg(any(test, feature = "arbitrary-impls"))]
impl<'a> arbitrary::Arbitrary<'a> for StandingSwapOrder<V1Swap> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
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
        .expect("a non-negative offer is valid"))
    }
}

#[cfg(test)]
mod tests {
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;

    /// A body decodes to an order if and only if its offered amount is not
    /// negative, and the order encodes back to the body.
    #[proptest]
    fn v1swap_round_trip(#[strategy(arb())] body: StandingSwapOrderV1) {
        match StandingSwapOrder::<V1Swap>::try_from(body) {
            Ok(order) => assert_eq!(body, StandingSwapOrderV1::from(order)),
            Err(error) => {
                assert!(body.offered_amount.is_negative());
                assert_eq!(V1Error::NegativeOffer, error);
            }
        }
    }

    #[proptest(cases = 10)]
    fn an_order_offering_a_negative_amount_is_refused(
        #[strategy(arb())] order: StandingSwapOrder<V1Swap>,
        #[strategy(1..i64::MAX)] nau: i64,
    ) {
        let negative = NativeCurrencyAmount::from_nau(-i128::from(nau));
        let refused = StandingSwapOrder::<V1Swap>::new(
            negative,
            order.demanded_amount,
            order.seed,
            order.cancel_post_image,
            order.reward_lock_script_hash,
            order.reward_receiver_digest,
        );
        assert_eq!(Some(V1Error::NegativeOffer), refused.err());
    }
}
