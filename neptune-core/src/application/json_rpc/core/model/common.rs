use std::str::FromStr;

use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use tasm_lib::triton_vm::prelude::BFieldElement;

use crate::api::export::NativeCurrencyAmount;
use crate::state::wallet::address::common::bfes_to_bytes;
use crate::state::wallet::address::common::bytes_to_bfes;

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

impl Serialize for RpcBFieldElements {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = bfes_to_bytes(&self.0).map_err(serde::ser::Error::custom)?;
        let hex_str = hex::encode(bytes);
        serializer.serialize_str(&hex_str)
    }
}

impl<'de> Deserialize<'de> for RpcBFieldElements {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        let bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;
        Ok(RpcBFieldElements(bytes_to_bfes(&bytes)))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use serde_json;

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
        let bytes = vec![1u8, 2, 3, 4];
        let bfes = bytes_to_bfes(&bytes);

        let rpc_bfes: RpcBFieldElements = bfes.into();
        let json_bfes = serde_json::to_string(&rpc_bfes).unwrap();
        let deserialized: RpcBFieldElements = serde_json::from_str(&json_bfes).unwrap();
        assert_eq!(rpc_bfes, deserialized);
    }
}
