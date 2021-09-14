use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Network {
    Main,
    Testnet,
    RegTest,
}

impl ToString for Network {
    fn to_string(&self) -> String {
        match self {
            Network::Main => "main".to_string(),
            Network::Testnet => "testnet".to_string(),
            Network::RegTest => "regtest".to_string(),
        }
    }
}

impl FromStr for Network {
    type Err = ();

    fn from_str(input: &str) -> Result<Network, Self::Err> {
        match input {
            "main" => Ok(Network::Main),
            "testnet" => Ok(Network::Testnet),
            "regtest" => Ok(Network::RegTest),
            _ => Err(()),
        }
    }
}
