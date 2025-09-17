use std::ops::Deref;

use anyhow::ensure;
use anyhow::Result;

use crate::api::export::ReceivingAddress;

#[derive(Debug, Clone)]
pub struct CoinbaseOutput {
    pub fraction_in_promille: u32,
    pub recipient: ReceivingAddress,
    pub timelocked: bool,
}

impl CoinbaseOutput {
    /// A coinbase output that's timelocked for three years
    pub fn timelocked(recipient: ReceivingAddress, fraction_in_promille: u32) -> Self {
        Self {
            fraction_in_promille,
            recipient,
            timelocked: true,
        }
    }

    /// A coinbase output that's immediately liquid
    pub fn liquid(recipient: ReceivingAddress, fraction_in_promille: u32) -> Self {
        Self {
            fraction_in_promille,
            recipient,
            timelocked: false,
        }
    }

    pub(super) fn fraction_in_promille(&self) -> u32 {
        self.fraction_in_promille
    }

    pub(super) fn recipient(&self) -> &ReceivingAddress {
        &self.recipient
    }

    pub(super) fn is_timelocked(&self) -> bool {
        self.timelocked
    }
}

/// A coinbase distribution describing how the output in the locally produced
/// block proposal should be distributed.
#[derive(Debug, Clone)]
pub struct CoinbaseDistribution {
    coinbase_outputs: Vec<CoinbaseOutput>,
}

impl Deref for CoinbaseDistribution {
    type Target = Vec<CoinbaseOutput>;

    fn deref(&self) -> &Self::Target {
        &self.coinbase_outputs
    }
}

impl CoinbaseDistribution {
    /// Constructor guaranteeing that
    /// a) All fractions sum to 1000 ‰
    /// b) Has at least one liquid and one timelocked output
    /// c) All timelocked outputs sum to at least 500 ‰.
    /// d) All fractions are non-negative
    ///
    /// If the above rules are followed, the distribution is guaranteed to be
    /// consensus-compatible.
    // All constructors should go through this interface to ensure consensus-
    // compatibility.
    pub fn try_new(outputs: Vec<CoinbaseOutput>) -> Result<Self> {
        ensure!(
            1000 == outputs.iter().map(|x| x.fraction_in_promille).sum::<u32>(),
            "Output fractions must sum to 1000 ‰."
        );
        ensure!(
            500 <= outputs
                .iter()
                .filter(|x| x.timelocked)
                .map(|x| x.fraction_in_promille)
                .sum::<u32>(),
            "At least half of output must be timelocked."
        );
        ensure!(
            outputs.iter().any(|x| !x.timelocked),
            "At least one output must be liquid"
        );

        Ok(Self {
            coinbase_outputs: outputs,
        })
    }

    /// The coinbase distribution for solo mining
    pub(crate) fn solo(reward_address: ReceivingAddress) -> Self {
        let liquid = CoinbaseOutput::liquid(reward_address.clone(), 500);
        let timelocked = CoinbaseOutput::timelocked(reward_address.clone(), 500);

        Self::try_new(vec![liquid, timelocked]).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use tasm_lib::prelude::Digest;

    use super::*;
    use crate::state::wallet::address::generation_address::GenerationReceivingAddress;

    #[test]
    fn solo_doesnt_crash() {
        let _ = CoinbaseDistribution::solo(
            GenerationReceivingAddress::derive_from_seed(Digest::default()).into(),
        );
    }

    #[test]
    fn try_new_behavior() {
        assert!(CoinbaseDistribution::try_new(vec![]).is_err());

        let dummy_address = GenerationReceivingAddress::derive_from_seed(Digest::default());
        let whole_liquid = CoinbaseOutput {
            fraction_in_promille: 1000,
            recipient: dummy_address.into(),
            timelocked: false,
        };
        assert!(CoinbaseDistribution::try_new(vec![whole_liquid]).is_err());

        let whole_timelocked = CoinbaseOutput {
            fraction_in_promille: 1000,
            recipient: dummy_address.into(),
            timelocked: true,
        };
        assert!(CoinbaseDistribution::try_new(vec![whole_timelocked.clone()]).is_err());

        let empty_liquid = CoinbaseOutput {
            fraction_in_promille: 0,
            recipient: dummy_address.into(),
            timelocked: false,
        };

        assert!(CoinbaseDistribution::try_new(vec![whole_timelocked, empty_liquid]).is_ok());
    }
}
