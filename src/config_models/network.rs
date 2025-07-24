use std::fmt;
use std::str::FromStr;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumIter;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;

use crate::models::blockchain::block::difficulty_control::Difficulty;
use crate::models::proof_abstractions::timestamp::Timestamp;

#[derive(
    Clone,
    Copy,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Default,
    EnumIter,
    strum::EnumIs,
    GetSize,
)]
#[non_exhaustive]
pub enum Network {
    /// Main net. Feature-complete. Fixed launch date.
    #[default]
    Main,

    /// Public test network that utilizes mock proofs and difficulty resets so
    /// that mining is possible without high-end hardware.  Intended for staging
    /// of release candidates prior to release and for the community to try out
    /// release candidates and report issues.
    TestnetMock,

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
    pub fn launch_date(&self) -> Timestamp {
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
            // 25 July 2025, 06:30:59 UTC
            Network::TestnetMock | Network::Testnet | Network::Beta | Network::Main => {
                Timestamp(BFieldElement::new(1753425059000u64))
            }
        }
    }

    /// indicates if the network uses mock proofs
    ///
    /// mock proofs enable transactions and blocks to be created quickly but
    /// must only be used for testing purposes.
    pub fn use_mock_proof(&self) -> bool {
        matches!(self, Self::RegTest | Self::TestnetMock)
    }

    /// indicates max duration between blocks before difficulty reset, if any.
    ///
    /// The difficulty is reset to genesis difficulty on testnet network(s) any
    /// time the duration between a block and the previous block is >= twice the
    /// target interval ie 19.6 minutes.
    ///
    /// - testnet, testnet-mock: Some(19.6 minutes)
    /// - mainnet, others: None
    pub fn difficulty_reset_interval(&self) -> Option<Timestamp> {
        match *self {
            Self::TestnetMock => Some(self.target_block_interval() * 2),
            _ => None,
        }
    }

    /// indicates if peer discovery should be performed by nodes on this network
    ///
    /// - regtest: false
    /// - mainnet and others: true
    pub fn performs_peer_discovery(&self) -> bool {
        // disable peer-discovery for regtest only (so far)
        !self.is_reg_test()
    }

    /// difficulty setting for the Genesis block
    pub fn genesis_difficulty(&self) -> Difficulty {
        match *self {
            Self::RegTest => Difficulty::MINIMUM,
            Self::Testnet | Self::TestnetMock => Difficulty::new([1_000_000, 0, 0, 0, 0]),
            Self::Main | Self::Beta => Difficulty::new([1_000_000_000, 0, 0, 0, 0]),
        }
    }

    /// minimum time between blocks.
    ///
    /// Blocks spaced apart by less than this amount of time are not valid.
    ///
    /// - for regtest: 1 milli
    /// - for testnet-mock: 100 milli
    /// - for mainnet and others: 60 seconds
    pub fn minimum_block_time(&self) -> Timestamp {
        match *self {
            Self::RegTest => Timestamp::millis(1),
            Self::TestnetMock => Timestamp::millis(100),
            Self::Main | Self::Beta | Self::Testnet => Timestamp::seconds(60),
        }
    }

    /// desired/average time between blocks.
    ///
    /// - for regtest: 100 milliseconds.
    /// - for mainnet and others: 588000 milliseconds equals 9.8 minutes.
    pub fn target_block_interval(&self) -> Timestamp {
        match *self {
            Self::RegTest => Timestamp::millis(100),
            Self::Main | Self::Beta | Self::Testnet | Self::TestnetMock => {
                Timestamp::millis(588000)
            }
        }
    }

    /// indicates if automated mining should be performed by this network
    ///
    /// note: we disable auto-mining in regtest mode because it generates blocks
    /// very quickly and that is not a good fit when mining is enabled for
    /// duration of the neptune-core process as blockchain grows very quickly.
    ///
    /// instead developers are encouraged to use [crate::api::regtest] module to
    /// generate any number of blocks in a controlled, deterministic fashion.
    //
    // bitcoin-core does not use cli flags, but rather RPC commands to
    // enable/disable mining in controlled fashion. We might consider moving to
    // that model before enabling automated mining for RegTest.
    pub fn performs_automated_mining(&self) -> bool {
        !self.is_reg_test()
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let string = match self {
            Network::TestnetMock => "testnet-mock".to_string(),
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
            "testnet-mock" => Ok(Network::TestnetMock),
            "testnet" => Ok(Network::Testnet),
            "regtest" => Ok(Network::RegTest),
            "beta" => Ok(Network::Beta),
            "main" => Ok(Network::Main),
            _ => Err(format!("Failed to parse {} as network", input)),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use num_traits::Zero;

    use super::*;

    #[test]
    fn main_variant_is_zero() {
        assert!((Network::Main as u32).is_zero());
    }
}
