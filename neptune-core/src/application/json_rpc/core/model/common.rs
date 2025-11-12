use std::fmt::Display;
use std::fmt::LowerHex;
use std::str::FromStr;

use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use tasm_lib::triton_vm::prelude::BFieldElement;
use thiserror::Error;

use crate::api::export::NativeCurrencyAmount;
use crate::protocol::consensus::block::block_selector::BlockSelector;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RpcNativeCurrencyAmount(pub NativeCurrencyAmount);

impl From<NativeCurrencyAmount> for RpcNativeCurrencyAmount {
    fn from(v: NativeCurrencyAmount) -> Self {
        RpcNativeCurrencyAmount(v)
    }
}

impl Serialize for RpcNativeCurrencyAmount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_nau().to_string())
    }
}

impl<'de> Deserialize<'de> for RpcNativeCurrencyAmount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let nau = i128::from_str(&s).map_err(serde::de::Error::custom)?;
        Ok(RpcNativeCurrencyAmount(NativeCurrencyAmount::from_nau(nau)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcBFieldElements(pub Vec<BFieldElement>);

impl From<Vec<BFieldElement>> for RpcBFieldElements {
    fn from(v: Vec<BFieldElement>) -> Self {
        RpcBFieldElements(v)
    }
}

impl LowerHex for RpcBFieldElements {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for m in &self.0 {
            // big-endian (Arabic)
            write!(f, "{:016x}", m.value())?;
        }
        Ok(())
    }
}

impl Display for RpcBFieldElements {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}", self)
    }
}

#[derive(Debug, Clone, Copy, Error)]
pub enum RpcBFieldElementsParseError {
    #[error("missing '0x' prefix")]
    MissingPrefix,

    #[error("decoded byte length must be a multiple of 8, got {0}")]
    InvalidLength(usize),

    #[error("failed to decode hex: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    #[error("input too large (decoded {0} bytes, limit is {1} bytes)")]
    TooLarge(usize, usize),
}

impl FromStr for RpcBFieldElements {
    type Err = RpcBFieldElementsParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        const MAX_BYTES: usize = 4 * 1024 * 1024; // 4 MB

        let s = s.strip_prefix("0x").ok_or(Self::Err::MissingPrefix)?;
        let byte_len = s.len() / 2;

        if byte_len > MAX_BYTES {
            return Err(Self::Err::TooLarge(byte_len, MAX_BYTES));
        }
        if byte_len % 8 != 0 {
            return Err(Self::Err::InvalidLength(byte_len));
        }

        let bytes = hex::decode(s)?;
        let bfes = bytes
            .chunks_exact(8)
            .map(|chunk| {
                let array: [u8; 8] = chunk.try_into().expect("8-byte chunk expected");
                BFieldElement::new(u64::from_be_bytes(array))
            })
            .collect();

        Ok(Self(bfes))
    }
}

impl Serialize for RpcBFieldElements {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for RpcBFieldElements {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(serde::de::Error::custom)
    }
}

pub type RpcBlockSelector = BlockSelector;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use serde_json;
    use tasm_lib::twenty_first::bfe_vec;

    use super::*;

    #[test]
    fn rpc_native_currency_amount_serde_roundtrip() {
        let amount = NativeCurrencyAmount::from_nau(123i128);
        let rpc_amount: RpcNativeCurrencyAmount = amount.into();

        let json_amount = serde_json::to_string(&rpc_amount).unwrap();
        assert_eq!(json_amount, "\"123\"");

        let deserialized_amount: RpcNativeCurrencyAmount =
            serde_json::from_str(&json_amount).unwrap();
        assert_eq!(rpc_amount, deserialized_amount);
    }

    #[test]
    fn rpc_bfield_elements_serde_roundtrip() {
        let bfes = bfe_vec![0, 1, 255, 0x1234567890ABCDEFu64, u64::MAX,];
        let rpc_bfes: RpcBFieldElements = bfes.into();

        let serialized = serde_json::to_string(&rpc_bfes).expect("Serialization should succeed");
        let deserialized: RpcBFieldElements =
            serde_json::from_str(&serialized).expect("Deserialization should succeed");

        assert_eq!(rpc_bfes, deserialized);
    }

    #[test]
    fn rpc_bfield_elements_display_format() {
        let bfes = RpcBFieldElements(vec![BFieldElement::new(0x0001), BFieldElement::new(0xABCD)]);

        let hex_str = format!("{}", bfes);
        assert!(hex_str.starts_with("0x"));
        assert_eq!(hex_str.len(), 34); // 2 + 32 hex chars
    }

    #[test]
    fn rpc_bfield_elements_from_str() {
        let hex_str = "0x00000000000000010000000000000002";
        let bfes: RpcBFieldElements = hex_str.parse().expect("Parsing should succeed");

        let expected = RpcBFieldElements(vec![BFieldElement::new(1), BFieldElement::new(2)]);

        assert_eq!(bfes, expected);
    }

    #[test]
    fn rpc_bfield_elements_from_str_invalid() {
        // Missing 0x prefix
        assert!("0000000000000001".parse::<RpcBFieldElements>().is_err());
        // Wrong length (not multiple of 16)
        assert!("0x0000000000000100000000000002"
            .parse::<RpcBFieldElements>()
            .is_err());
        // Invalid hex characters
        assert!("0x0000000000000x0000000000000002"
            .parse::<RpcBFieldElements>()
            .is_err());
        // Too big hex string (over 4 MB)
        let oversized_hex = "0x".to_string() + &"00".repeat(4 * 1024 * 1024 + 1);
        assert!(oversized_hex.parse::<RpcBFieldElements>().is_err());
    }
}
