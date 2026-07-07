use anyhow::Ok;
use anyhow::Result;
use neptune_primitives::network::Network;
use neptune_wallet::address::ReceivingAddress;
use neptune_wallet::coinbase_distribution::CoinbaseOutput;
use serde::Deserialize;
use serde::Serialize;

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
    use neptune_wallet::address::KeyType;
    use neptune_wallet::wallet_entropy::WalletEntropy;

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

    #[test]
    fn print_coinbase_output_readable_as_json() {
        let recipient = WalletEntropy::devnet_wallet()
            .nth_receiving_address(0, KeyType::Generation)
            .to_display_bech32m(Network::Main)
            .unwrap();
        let timelocked = CoinbaseOutputReadable::new(540, recipient.clone(), true);
        let liquid = CoinbaseOutputReadable::new(460, recipient, false);

        let cb_outputs = vec![timelocked, liquid];
        let cb_outputs = serde_json::to_string(&cb_outputs).unwrap();
        println!("{cb_outputs}");
    }
}
