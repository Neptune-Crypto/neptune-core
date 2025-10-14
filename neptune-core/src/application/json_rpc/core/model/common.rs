use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;
use tasm_lib::triton_vm::prelude::BFieldElement;

use crate::{
    api::export::NativeCurrencyAmount,
    state::wallet::address::common::{bfes_to_bytes, bytes_to_bfes},
};

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
