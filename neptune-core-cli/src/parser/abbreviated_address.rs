use std::fmt::Display;
use std::str::FromStr;

use neptune_cash::api::export::{KeyType, Network};

/// Type for abbreviated addresses that clap can pase
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AbbreviatedAddress {
    pub(crate) key_type: KeyType,
    beginning: String,
    ending: String,
}

impl Display for AbbreviatedAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}...{}", self.key_type, self.beginning, self.ending)
    }
}

#[derive(Debug, Clone)]
pub enum AbbreviatedAddressParseError {
    Format,
    Hrp,
    BeginningLength,
    EndingLength,
    InvalidBeginningChar,
    InvalidEndingChar,
}

fn key_type_from_hrp(hrp: &str) -> Option<KeyType> {
    for network in [
        Network::Main,
        Network::RegTest,
        Network::TestnetMock,
        Network::Testnet(0),
    ] {
        for key_type in KeyType::all_types() {
            if hrp == key_type.get_hrp(network) {
                return Some(key_type);
            }
        }
    }

    None
}

impl FromStr for AbbreviatedAddress {
    type Err = AbbreviatedAddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        /// Allowed characters in bech32m (lowercase only)
        const BECH32M_ALPHABET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

        // Split by "...".
        let parts: Vec<&str> = s.split("...").collect();
        if parts.len() != 2 {
            return Err(Self::Err::Format);
        }
        let (start, ending) = (parts[0], parts[1]);

        // Split start string into HRP and beginning. The latter part has length
        // 12.
        if start.len() < 12 {
            return Err(Self::Err::BeginningLength);
        }

        let (hrp, beginning) = start.split_at(start.len() - 12);

        if beginning.len() != 12 {
            return Err(Self::Err::BeginningLength);
        }
        if ending.len() != 12 {
            return Err(Self::Err::EndingLength);
        }

        // Check characters in beginning and ending against bech32m alphabet
        if beginning.chars().nth(0).unwrap() != '1' {
            // separator
            return Err(Self::Err::InvalidBeginningChar);
        }
        for char in beginning.chars().skip(1) {
            if !BECH32M_ALPHABET.contains(char) {
                return Err(Self::Err::InvalidBeginningChar);
            }
        }
        if !ending.chars().all(|c| BECH32M_ALPHABET.contains(c)) {
            return Err(Self::Err::InvalidEndingChar);
        }

        // Parse key_type from HRP.
        let Some(key_type) = key_type_from_hrp(hrp) else {
            return Err(Self::Err::Hrp);
        };

        Ok(AbbreviatedAddress {
            key_type,
            beginning: beginning.to_string(),
            ending: ending.to_string(),
        })
    }
}
