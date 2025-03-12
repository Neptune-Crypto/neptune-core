use tasm_lib::prelude::Digest;

use crate::models::state::wallet::address::ReceivingAddress;

#[derive(Debug, Clone)]
pub(crate) struct ComposerParameters {
    reward_address: ReceivingAddress,
    sender_randomness: Digest,
    guesser_fee_fraction: f64,
}

impl ComposerParameters {
    pub(crate) fn new(
        reward_address: ReceivingAddress,
        sender_randomness: Digest,
        guesser_fee_fraction: f64,
    ) -> Self {
        let is_fraction = (0_f64..=1.0).contains(&guesser_fee_fraction);
        assert!(
            is_fraction,
            "Guesser fee fraction must be a fraction. Got: {guesser_fee_fraction}"
        );
        Self {
            reward_address,
            sender_randomness,
            guesser_fee_fraction,
        }
    }

    pub(crate) fn reward_address(&self) -> ReceivingAddress {
        self.reward_address.clone()
    }

    pub(crate) fn sender_randomness(&self) -> Digest {
        self.sender_randomness
    }

    pub(crate) fn guesser_fee_fraction(&self) -> f64 {
        self.guesser_fee_fraction
    }
}
