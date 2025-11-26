use std::str::FromStr;

use neptune_cash::api::export::KeyType;
use neptune_cash::api::export::Network;
use neptune_cash::api::export::ReceivingAddress;

use crate::parser::abbreviated_address::AbbreviatedAddress;

/// Type for abbreviated addresses that clap can pase
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FullOrAbbreviatedAddress {
    Full(ReceivingAddress),
    Abbreviated(AbbreviatedAddress),
}

impl FullOrAbbreviatedAddress {
    pub(crate) fn parse(address: &str, network: Network) -> Option<Self> {
        if let Ok(receiving_address) = ReceivingAddress::from_bech32m(address, network) {
            return Some(Self::Full(receiving_address));
        }

        if let Ok(abbreviated_address) = AbbreviatedAddress::from_str(address) {
            return Some(Self::Abbreviated(abbreviated_address));
        }

        None
    }

    pub(crate) fn key_type(&self) -> KeyType {
        match self {
            FullOrAbbreviatedAddress::Full(receiving_address) => KeyType::from(receiving_address),
            FullOrAbbreviatedAddress::Abbreviated(abbreviated_address) => {
                abbreviated_address.key_type
            }
        }
    }
}
