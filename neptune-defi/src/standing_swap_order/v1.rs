use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldCodec;

use super::StandingSwapOrder;
use super::Swappable;

/// The encoding format of a version 1 [`super::StandingSwapOrder`].
#[derive(Debug, Clone, Copy, BFieldCodec)]
pub struct StandingSwapOrderV1 {
    pub offered_amount: NativeCurrencyAmount,
    pub demanded_amount: NativeCurrencyAmount,
    pub seed: Digest,
    pub cancel_post_image: Digest,
    pub reward_lock_script_hash: Digest,
    pub reward_receiver_digest: Digest,
}

/// The generic configuration of a standing swap order: both amounts are free,
/// and orders carry no parameters.
#[derive(Debug, Clone, Copy)]
pub struct Generic;

impl Swappable for Generic {
    fn version() -> u64 {
        1
    }

    type Params = ();

    type EncodingFormat = StandingSwapOrderV1;
}

impl StandingSwapOrder<Generic> {
    /// A generic order. No relation binds its terms, so every field is an
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

impl From<StandingSwapOrder<Generic>> for StandingSwapOrderV1 {
    fn from(order: StandingSwapOrder<Generic>) -> Self {
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

impl From<StandingSwapOrderV1> for StandingSwapOrder<Generic> {
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
