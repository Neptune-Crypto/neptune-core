use std::fmt;
use std::str::FromStr;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use serde::Deserialize;
use serde::Serialize;
use strum::EnumIter;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;

use crate::models::blockchain::block::block_header;
use crate::models::proof_abstractions::timestamp::Timestamp;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default, EnumIter)]
pub enum Network {
    /// Main net. Feature-complete. Fixed launch date.
    #[default]
    Main,

    /// First iteration of testnet. Not feature-complete.
    Alpha,

    /// 2nd iteration of integration testing. Not feature-complete either but
    /// more than Alpha.
    Beta,

    /// Feature-complete (or as feature-complete as possible) test network separate
    /// from whichever network is currently running. For integration tests involving
    /// multiple nodes over a network.
    Testnet,

    /// Network for individual unit and integration tests. The timestamp for the
    /// RegTest genesis block is set to now, rounded down to the first block of
    /// seven days. As a result, there is a small probability that tests fail
    /// because they generate the genesis block twice on two opposite sides of a
    /// round timestamp. You probably shouldn't use `RegTest` for unit tests, as
    /// this will invalidate the stored proofs when the rounded timestamp
    /// changes.
    RegTest,
}

impl Network {
    pub(crate) fn launch_date(&self) -> Timestamp {
        match self {
            Network::RegTest => {
                const SEVEN_DAYS: u64 = 1000 * 60 * 60 * 24 * 7;

                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                let now_rounded = (now / SEVEN_DAYS) * SEVEN_DAYS;
                Timestamp(BFieldElement::new(now_rounded))
            }
            // 11 Feb 2025, noon UTC
            Network::Alpha | Network::Testnet | Network::Beta | Network::Main => {
                Timestamp(BFieldElement::new(1739275200000u64))
            }
        }
    }

    pub(crate) fn minimum_block_time(&self) -> Timestamp {
        if self.is_regtest() {
            block_header::MINIMUM_BLOCK_TIME_REGTEST
        } else {
            block_header::MINIMUM_BLOCK_TIME
        }
    }

    pub(crate) fn target_block_interval(&self) -> Timestamp {
        if self.is_regtest() {
            block_header::TARGET_BLOCK_INTERVAL_REGTEST
        } else {
            block_header::TARGET_BLOCK_INTERVAL
        }
    }

    pub fn is_mainnet(&self) -> bool {
        matches!(self, Self::Main)
    }

    pub fn is_testnet(&self) -> bool {
        matches!(self, Self::Testnet)
    }

    pub fn is_regtest(&self) -> bool {
        matches!(self, Self::RegTest)
    }

    /// indicates if the network uses mock proofs
    ///
    /// mock proofs enable transactions and blocks to be created quickly
    /// but must only be used for testing purposes.
    ///
    /// note: for now only the RegTest network uses mock proofs, but that could
    /// change in the future so it is best use this method rather than checking
    /// for is_regtest().
    pub fn use_mock_proof(&self) -> bool {
        matches!(self, Self::RegTest)
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let string = match self {
            Network::Alpha => "alpha".to_string(),
            Network::Testnet => "testnet".to_string(),
            Network::RegTest => "regtest".to_string(),
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
            "regtest" => Ok(Network::RegTest),
            "beta" => Ok(Network::Beta),
            "main" => Ok(Network::Main),
            _ => Err(format!("Failed to parse {} as network", input)),
        }
    }
}

#[cfg(test)]
mod tests {
    use num_traits::Zero;

    use super::*;

    #[test]
    fn main_variant_is_zero() {
        assert!((Network::Main as u32).is_zero());
    }
}
