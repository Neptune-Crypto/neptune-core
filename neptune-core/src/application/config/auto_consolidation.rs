use neptune_primitives::network::Network;
use neptune_wallet::address::ReceivingAddress;

#[derive(Debug, Clone, Default)]
pub struct AutoConsolidationSettings {
    /// The number of inputs used in each consolidation transaction. Will never
    /// consolidate with another number of inputs than this.
    pub(crate) num_inputs: u8,

    /// Where the consolidated outputs should be sent.
    pub(crate) policy: ConsolidationTarget,

    /// Whether the lustration of the consolidated inputs is acceptable.
    pub(crate) accept_lustrations: bool,
}

#[derive(Debug, Clone, Default)]
pub enum ConsolidationTarget {
    #[default]
    Inactive,
    ActiveDynamic,
    ActiveFixed {
        address: ReceivingAddress,
    },
}

impl AutoConsolidationSettings {
    // OK to suppress this linter rule because we are parsing and the nested
    // type tells clap how to parse.
    #[expect(clippy::option_option)]
    pub(crate) fn parse(
        auto_consolidate_cli: &Option<Option<String>>,
        num_consolidation_inputs_cli: u8,
        network: Network,
        accept_lustrations: bool,
    ) -> Result<Self, String> {
        let policy = match auto_consolidate_cli {
            Some(None) => ConsolidationTarget::ActiveDynamic,
            Some(Some(address)) => {
                let address = ReceivingAddress::from_bech32m(address, network)
                    .map_err(|inner_err| inner_err.to_string())?;
                ConsolidationTarget::ActiveFixed { address }
            }
            None => ConsolidationTarget::Inactive,
        };

        Ok(AutoConsolidationSettings {
            num_inputs: num_consolidation_inputs_cli,
            policy,
            accept_lustrations,
        })
    }
}
