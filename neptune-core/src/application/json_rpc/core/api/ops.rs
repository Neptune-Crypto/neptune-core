use neptune_rpc_macros::Router;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumString;

use crate::application::json_rpc::core::api::router::RpcRouter;
use crate::application::json_rpc::core::api::rpc::RpcApi;
use crate::application::json_rpc::core::error::RpcError;
use crate::application::json_rpc::core::model::message::*;

/// API version.
pub const RPC_API_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, EnumString)]
#[serde(rename_all = "camelCase")]
#[strum(ascii_case_insensitive)]
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
    #[namespace(Namespace::Node)]
    Network,

    #[namespace(Namespace::Chain)]
    Height,

    #[namespace(Namespace::Chain)]
    TipDigest,

    #[namespace(Namespace::Chain)]
    Tip,

    #[namespace(Namespace::Chain)]
    TipProof,

    #[namespace(Namespace::Chain)]
    TipKernel,

    #[namespace(Namespace::Chain)]
    TipHeader,

    #[namespace(Namespace::Chain)]
    TipBody,

    #[namespace(Namespace::Chain)]
    TipTransactionKernel,

    #[namespace(Namespace::Chain)]
    TipAnnouncements,

    #[namespace(Namespace::Archival)]
    GetBlockDigest,

    #[namespace(Namespace::Archival)]
    GetBlockDigests,

    #[namespace(Namespace::Archival)]
    GetBlock,

    #[namespace(Namespace::Archival)]
    GetBlockProof,

    #[namespace(Namespace::Archival)]
    GetBlockKernel,

    #[namespace(Namespace::Archival)]
    GetBlockHeader,

    #[namespace(Namespace::Archival)]
    GetBlockBody,

    #[namespace(Namespace::Archival)]
    GetBlockTransactionKernel,

    #[namespace(Namespace::Archival)]
    GetBlockAnnouncements,

    #[namespace(Namespace::Archival)]
    IsBlockCanonical,
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::application::json_rpc::core::api::ops::Namespace;

    #[test]
    fn namespace_parses_case_insensitively() {
        use std::str::FromStr;

        assert_eq!(Namespace::from_str("node").unwrap(), Namespace::Node);
        assert_eq!(Namespace::from_str("Node").unwrap(), Namespace::Node);
        assert_eq!(Namespace::from_str("NODE").unwrap(), Namespace::Node);
        assert_eq!(Namespace::from_str("NoDe").unwrap(), Namespace::Node);

        assert!(
            Namespace::from_str("nodewallet").is_err(),
            "Expected parse error for invalid namespace"
        );
    }
}
