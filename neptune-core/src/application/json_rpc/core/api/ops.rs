use crate::application::json_rpc::core::api::router::RpcRouter;
use crate::application::json_rpc::core::api::rpc::RpcApi;
use crate::application::json_rpc::core::error::RpcError;
use crate::application::json_rpc::core::model::message::*;
use neptune_rpc_macros::Router;
use serde::{Deserialize, Serialize};
use strum::EnumString;

/// API version.
pub const RPC_API_VERSION: u16 = 1;

// TODO: Strum EnumString is too sensitive
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, EnumString)]
#[serde(rename_all = "camelCase")]
#[strum(serialize_all = "camelCase")]
pub enum Namespace {
    Node,
    Networking,
    Chain,
    Mining,
    Archival,
    Mempool,
    Wallet,
}

#[derive(Router, Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RpcMethods {
    #[namespace(Namespace::Chain)]
    GetHeight,
}
