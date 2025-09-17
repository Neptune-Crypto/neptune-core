use anyhow::Ok;
use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;

use crate::api::export::Network;
use crate::api::export::ReceivingAddress;
use crate::application::loops::mine_loop::coinbase_distribution::CoinbaseOutput;

/// Data structure to avoid the default JSON encoding of addresses and instead
/// use Bech32.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoinbaseOutputReadable {
    // Addresses are represented as strings here because we cannot parse them
    // without knowing the network.
    fraction_in_promille: u32,
    recipient: String,
    timelocked: bool,
}

impl CoinbaseOutputReadable {
    pub(crate) fn into_coinbase_output(self, network: Network) -> Result<CoinbaseOutput> {
        Ok(CoinbaseOutput {
            fraction_in_promille: self.fraction_in_promille,
            recipient: ReceivingAddress::from_bech32m(&self.recipient, network)?,
            timelocked: self.timelocked,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl CoinbaseOutputReadable {
        pub(crate) fn new(fraction_in_promille: u32, recipient: String, timelocked: bool) -> Self {
            Self {
                fraction_in_promille,
                recipient,
                timelocked,
            }
        }
    }
}
