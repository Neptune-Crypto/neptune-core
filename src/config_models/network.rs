use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use strum::EnumIter;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default, EnumIter)]
pub enum Network {
    #[default]
    Alpha,
    Testnet,
    RegTest,
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let string = match self {
            Network::Alpha => "alpha".to_string(),
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
            "alpha" => Ok(Network::Alpha),
            "testnet" => Ok(Network::Testnet),
            "regtest" => Ok(Network::RegTest),
            _ => Err(format!("Failed to parse {} as network", input)),
        }
    }
}
