use std::fmt;
use std::str::FromStr;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use serde::Deserialize;
use serde::Serialize;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;

use crate::models::consensus::timestamp::Timestamp;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Network {
    /// First iteration of testnet. Not feature-complete. Soon to be deprecated.
    #[default]
    Alpha,

    /// Upcoming iteration of testnet.
    ///
    /// Not feature-complete either but moreso than Alpha. Soon to be set as default.
    Beta,

    /// Main net. Feature-complete. Fixed launch date. Not ready yet.
    Main,

    /// Feature-complete test network (eventually).
    ///
    /// For integration tests involving multiple nodes over a network.
    Testnet,

    /// Network for development and tests.
    ///
    /// The timestamp for the RegTest genesis block is set to now, rounded down
    /// to the first block of 10 hours. As a result, there is a small
    /// probability that tests fail because they generate the genesis block
    /// twice on two opposite sides of a round timestamp.
    Regtest,
}
impl Network {
    pub(crate) fn launch_date(&self) -> Timestamp {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        const TEN_HOURS_AS_MS: u64 = 1000 * 60 * 60 * 10;
        let now_rounded = (now / TEN_HOURS_AS_MS) * TEN_HOURS_AS_MS;
        match self {
            Network::Regtest => Timestamp(BFieldElement::new(now_rounded)),
            // 1 July 2024 (might be revised though)
            Network::Alpha | Network::Testnet | Network::Beta | Network::Main => {
                Timestamp(BFieldElement::new(1719792000000u64))
            }
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let string = match self {
            Network::Alpha => "alpha".to_string(),
            Network::Testnet => "testnet".to_string(),
            Network::Regtest => "regtest".to_string(),
            Network::Beta => "beta".to_string(),
            Network::Main => "main".to_string(),
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
            "regtest" => Ok(Network::Regtest),
            "beta" => Ok(Network::Beta),
            "main" => Ok(Network::Main),
            _ => Err(format!("Failed to parse {} as network", input)),
        }
    }
}
