use crate::api::export::Network;
use crate::api::export::ReceivingAddress;

#[derive(Debug, Clone, Default)]
pub struct AutoConsolidationSettings {
    pub(crate) max_num_inpus: u8,
    pub(crate) policy: ConsolidationPolicy,
}

#[derive(Debug, Clone, Default)]
pub enum ConsolidationPolicy {
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
    ) -> Result<Self, String> {
        let policy = match auto_consolidate_cli {
            Some(None) => ConsolidationPolicy::ActiveDynamic,
            Some(Some(address)) => {
                let address = ReceivingAddress::from_bech32m(address, network)
                    .map_err(|inner_err| inner_err.to_string())?;
                ConsolidationPolicy::ActiveFixed { address }
            }
            None => ConsolidationPolicy::Inactive,
        };

        Ok(AutoConsolidationSettings {
            max_num_inpus: num_consolidation_inputs_cli,
            policy,
        })
    }
}
