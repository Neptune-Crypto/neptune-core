use crate::api::export::Network;
use crate::api::export::ReceivingAddress;

#[derive(Debug, Clone, Default)]
pub enum AutoConsolidationSetting {
    #[default]
    Inactive,
    ActiveDynamic {
        accept_lustrations: bool,
    },
    ActiveFixed {
        accept_lustrations: bool,
        address: ReceivingAddress,
    },
}

impl AutoConsolidationSetting {
    // OK to suppress this linter rule because we are parsing and the nested
    // type tells clap how to parse.
    #[expect(clippy::option_option)]
    pub(crate) fn parse(
        cli_argument: &Option<Option<String>>,
        network: Network,
        accept_lustrations: bool,
    ) -> Result<Self, String> {
        let auto_consolidate = match cli_argument {
            Some(None) => AutoConsolidationSetting::ActiveDynamic { accept_lustrations },
            Some(Some(address)) => {
                let address = ReceivingAddress::from_bech32m(address, network)
                    .map_err(|inner_err| inner_err.to_string())?;
                AutoConsolidationSetting::ActiveFixed {
                    accept_lustrations,
                    address,
                }
            }
            None => AutoConsolidationSetting::Inactive,
        };

        Ok(auto_consolidate)
    }
}
