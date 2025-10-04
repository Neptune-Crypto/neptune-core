use serde::{Deserialize, Serialize};
use serde_tuple::Deserialize_tuple; // Due a problem of serde_tuple we cant use it on empty structs so we just use serialize as placeholder for now

#[derive(Clone, Copy, Debug, Serialize, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetHeightRequest {}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetHeightResponse {
    pub height: u64, // This technically could exceed JavaScript's safe int limits but practically it would take thousand(?) years.
}
