use crate::api::export::Network;
use crate::api::export::ReceivingAddress;

#[derive(Debug, Clone, Default)]
pub enum AutoConsolidationSetting {
    #[default]
    Inactive,
    ActiveDynamic,
    ActiveFixed {
        address: ReceivingAddress,
    },
}

impl AutoConsolidationSetting {
    pub(crate) fn parse(
        cli_argument: &Option<Option<String>>,
        network: Network,
    ) -> Result<Self, String> {
        let auto_consolidate = match cli_argument {
            Some(None) => AutoConsolidationSetting::ActiveDynamic,
            Some(Some(address)) => {
                let address = ReceivingAddress::from_bech32m(address, network)
                    .map_err(|inner_err| inner_err.to_string())?;
                AutoConsolidationSetting::ActiveFixed { address }
            }
            None => AutoConsolidationSetting::Inactive,
        };

        Ok(auto_consolidate)
    }
}
