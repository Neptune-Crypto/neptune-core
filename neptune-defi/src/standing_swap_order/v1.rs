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
}

impl StandingSwapOrder<V1Swap> {
    /// A version 1 order. No relation binds its terms, so every field is an
    /// argument.
    pub fn new(
        offered_amount: NativeCurrencyAmount,
        demanded_amount: NativeCurrencyAmount,
        seed: Digest,
        cancel_post_image: Digest,
        reward_lock_script_hash: Digest,
        reward_receiver_digest: Digest,
    ) -> Self {
        Self {
            offered_amount,
            demanded_amount,
            seed,
            cancel_post_image,
            reward_lock_script_hash,
            reward_receiver_digest,
            params: (),
        }
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

impl From<StandingSwapOrderV1> for StandingSwapOrder<V1Swap> {
    fn from(body: StandingSwapOrderV1) -> Self {
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
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;

    #[proptest]
    fn v1swap_round_trip(#[strategy(arb())] body: StandingSwapOrderV1) {
        let order = StandingSwapOrder::<V1Swap>::from(body);
        assert_eq!(body, StandingSwapOrderV1::from(order));
    }
}
