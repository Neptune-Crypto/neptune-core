use serde::Deserialize;
use serde::Serialize;

/// Generate Address Response
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GenerateAddressResponse {
    pub address: String,
}

/// Balance Response
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BalanceResponse {
    pub balance: String,
}

/// Validate Amount Response
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ValidateAmountResponse {
    pub amount: Option<String>,
}

