use anyhow::bail;
use regex::Regex;

use crate::state::wallet::utxo_notification::UtxoNotificationMedium;

/// How notifications for UTXOs resulting from proving jobs (*i.e.*, composing
/// or upgrading) are communicated.
//
// In the future, this enum might be expanded with an option to supply an
// address (one that is *not* linked to the client's wallet) for cold composing
// and/or upgrading.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub(crate) enum FeeNotificationPolicy {
    OffChain,
    #[default]
    OnChainSymmetric,
    OnChainGeneration,
}

impl FeeNotificationPolicy {
    pub(crate) fn parse(unparsed_policy: &str) -> Result<Self, anyhow::Error> {
        let off_chain = Regex::new(r"(?i)^off-?chain$").unwrap();
        let on_chain_symmetric = Regex::new(r"(?i)^((on-?chain-)|(onchain))?symmetric$").unwrap();
        let on_chain_generation = Regex::new(r"(?i)^((on-?chain-)|(onchain))?generation$").unwrap();

        if off_chain.is_match(unparsed_policy) {
            Ok(Self::OffChain)
        } else if on_chain_symmetric.is_match(unparsed_policy) {
            Ok(Self::OnChainSymmetric)
        } else if on_chain_generation.is_match(unparsed_policy) {
            Ok(Self::OnChainGeneration)
        } else {
            bail!("failed to parse fee notification policy")
        }
    }
}

impl From<FeeNotificationPolicy> for UtxoNotificationMedium {
    fn from(value: FeeNotificationPolicy) -> Self {
        match value {
            FeeNotificationPolicy::OffChain => UtxoNotificationMedium::OffChain,
            FeeNotificationPolicy::OnChainSymmetric => UtxoNotificationMedium::OnChain,
            FeeNotificationPolicy::OnChainGeneration => UtxoNotificationMedium::OnChain,
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::FeeNotificationPolicy;

    #[test]
    fn test_parse_fee_notification_policy() {
        let vectors_success = [
            ("off-chain", FeeNotificationPolicy::OffChain),
            ("offchain", FeeNotificationPolicy::OffChain),
            ("OffChain", FeeNotificationPolicy::OffChain),
            ("oFf-chAiN", FeeNotificationPolicy::OffChain),
            ("off-chain", FeeNotificationPolicy::OffChain),
            ("off-chain", FeeNotificationPolicy::OffChain),
            ("off-chain", FeeNotificationPolicy::OffChain),
            (
                "on-chain-symmetric",
                FeeNotificationPolicy::OnChainSymmetric,
            ),
            ("onchain-symmetric", FeeNotificationPolicy::OnChainSymmetric),
            ("onchainsymmetric", FeeNotificationPolicy::OnChainSymmetric),
            ("onChainSymmetric", FeeNotificationPolicy::OnChainSymmetric),
            ("OnChainSymmetric", FeeNotificationPolicy::OnChainSymmetric),
            (
                "on-chain-generation",
                FeeNotificationPolicy::OnChainGeneration,
            ),
            (
                "onchain-generation",
                FeeNotificationPolicy::OnChainGeneration,
            ),
            (
                "onchaingeneration",
                FeeNotificationPolicy::OnChainGeneration,
            ),
            (
                "onChainGeneration",
                FeeNotificationPolicy::OnChainGeneration,
            ),
            (
                "OnChainGeneration",
                FeeNotificationPolicy::OnChainGeneration,
            ),
        ];
        for (argument, target) in vectors_success {
            assert_eq!(
                target,
                FeeNotificationPolicy::parse(argument).unwrap(),
                "original string: {argument}"
            );
        }

        let vectors_fail = [
            "on-chainsymmetric",
            "on-chaingeneration",
            "on-chain",
            "onchain",
            "invalid",
            "error",
            "",
            " on-chain-symmetric",
            "off-chain ",
        ];
        for argument in vectors_fail {
            assert!(FeeNotificationPolicy::parse(argument).is_err());
        }
    }
}
