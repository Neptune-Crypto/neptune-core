use std::str::FromStr;

use neptune_cash::api::export::KeyType;
use neptune_cash::api::export::Network;

/// Type for abbreviated addresses that clap can pase
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AbbreviatedAddress {
    pub(crate) key_type: KeyType,
    beginning: String,
    ending: String,
}

impl AbbreviatedAddress {
    pub(crate) fn to_string(&self, network: Network) -> String {
        format!(
            "{}1{}...{}",
            self.key_type.get_hrp(network),
            self.beginning,
            self.ending
        )
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
    NoSeparator,
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
        if start.len() < 8 {
            return Err(Self::Err::BeginningLength);
        }

        let start_parts: Vec<&str> = start.split("1").collect();
        if start_parts.len() != 2 {
            return Err(Self::Err::NoSeparator);
        }

        let (hrp, beginning) = (start_parts[0], start_parts[1]);

        if beginning.len() != 11 && beginning.len() != 7 {
            return Err(Self::Err::BeginningLength);
        }
        if ending.len() != 12 && ending.len() != 8 {
            println!("from {s} got ending: {ending} with length {}", ending.len());
            return Err(Self::Err::EndingLength);
        }

        // Check characters in beginning and ending against bech32m alphabet
        if !beginning.chars().all(|c| BECH32M_ALPHABET.contains(c)) {
            return Err(Self::Err::InvalidBeginningChar);
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

#[cfg(test)]
mod tests {
    use neptune_cash::api::export::Digest;
    use neptune_cash::state::wallet::address::generation_address::GenerationReceivingAddress;
    use neptune_cash::state::wallet::address::symmetric_key::SymmetricKey;
    use neptune_cash::state::wallet::address::ReceivingAddress;
    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;

    #[proptest]
    fn from_str_to_str_round_trip_generation_standard(#[strategy(arb::<Digest>())] digest: Digest) {
        let address = GenerationReceivingAddress::derive_from_seed(digest);
        let as_string = ReceivingAddress::from(address)
            .to_display_bech32m_abbreviated(Network::Main)
            .unwrap();
        let from_string = AbbreviatedAddress::from_str(&as_string).unwrap();
        let as_string_again = from_string.to_string(Network::Main);
        prop_assert_eq!(as_string, as_string_again);
    }

    #[proptest]
    fn from_str_to_str_round_trip_generation_direct(#[strategy(arb::<Digest>())] digest: Digest) {
        let address = GenerationReceivingAddress::derive_from_seed(digest);
        #[allow(deprecated)]
        let as_string = address.to_bech32m_abbreviated(Network::Main).unwrap();
        let from_string = AbbreviatedAddress::from_str(&as_string).unwrap();
        let as_string_again = from_string.to_string(Network::Main);
        prop_assert_eq!(as_string, as_string_again);
    }

    #[proptest]
    fn from_str_to_str_round_trip_symmetric_display(#[strategy(arb::<Digest>())] digest: Digest) {
        let address = SymmetricKey::from_seed(digest);
        let as_string = ReceivingAddress::from(address)
            .to_display_bech32m_abbreviated(Network::Main)
            .unwrap();
        let from_string = AbbreviatedAddress::from_str(&as_string).unwrap();
        let as_string_again = from_string.to_string(Network::Main);
        prop_assert_eq!(as_string, as_string_again);
    }

    #[proptest]
    fn from_str_to_str_round_trip_symmetric_leaky(#[strategy(arb::<Digest>())] digest: Digest) {
        let address = SymmetricKey::from_seed(digest);
        let as_string = ReceivingAddress::from(address)
            .to_bech32m_abbreviated(Network::Main)
            .unwrap();
        let from_string = AbbreviatedAddress::from_str(&as_string).unwrap();
        let as_string_again = from_string.to_string(Network::Main);
        prop_assert_eq!(as_string, as_string_again);
    }
}
