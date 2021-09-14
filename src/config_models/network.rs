use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum Network {
    Main,
    Testnet,
    RegTest,
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let string = match self {
            Network::Main => "main".to_string(),
            Network::Testnet => "testnet".to_string(),
            Network::RegTest => "regtest".to_string(),
        };
        write!(f, "{}", string)
    }
}

impl FromStr for Network {
    type Err = String;
    fn from_str(input: &str) -> Result<Network, Self::Err> {
        match input {
            "main" => Ok(Network::Main),
            "testnet" => Ok(Network::Testnet),
            "regtest" => Ok(Network::RegTest),
            _ => Err("Failed to parse".to_string()),
        }
    }
}
