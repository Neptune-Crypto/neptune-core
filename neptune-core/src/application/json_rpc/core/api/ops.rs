use neptune_rpc_macros::Router;
use neptune_rpc_macros::Routes;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumString;

use crate::application::json_rpc::core::api::client::transport::Transport;
use crate::application::json_rpc::core::api::rpc::RpcApi;
use crate::application::json_rpc::core::api::rpc::RpcResult;
use crate::application::json_rpc::core::api::server::router::RpcRouter;
use crate::application::json_rpc::core::model::json::JsonError;
use crate::application::json_rpc::core::model::message::*;

/// API version.
pub const RPC_API_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, EnumString)]
#[serde(rename_all = "camelCase")]
#[strum(ascii_case_insensitive)]
pub enum Namespace {
    Node,
    Network,
    Chain,
    Mining,
    Archival,

    /// Endpoints for inspecting the mempool status
    Mempool,

    /// Endpoints for serving external wallets
    Wallet,

    /// Endpoints for managing personal wallet
    Personal,

    /// Endpoints relating to and requiring a UTXO index
    Utxoindex,
}

#[derive(Router, Routes, Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

    #[namespace(Namespace::Archival)]
    GetUtxoDigest,

    #[namespace(Namespace::Archival)]
    FindUtxoOrigin,

    /// Check if indices in an absolute index set are set. Can be used to check
    /// if a UTXO is spent without having to know the mutator set membership
    /// proof.
    #[namespace(Namespace::Archival)]
    AreBloomIndicesSet,

    #[namespace(Namespace::Archival)]
    CirculatingSupply,

    #[namespace(Namespace::Archival)]
    MaxSupply,

    #[namespace(Namespace::Archival)]
    BurnedSupply,

    #[namespace(Namespace::Wallet)]
    GetBlocks,

    #[namespace(Namespace::Wallet)]
    RestoreMembershipProof,

    #[namespace(Namespace::Wallet)]
    SubmitTransaction,

    #[namespace(Namespace::Personal)]
    RescanAnnounced,

    #[namespace(Namespace::Personal)]
    RescanExpected,

    #[namespace(Namespace::Personal)]
    RescanOutgoing,

    #[namespace(Namespace::Personal)]
    RescanGuesserRewards,

    #[namespace(Namespace::Personal)]
    DerivationIndex,

    #[namespace(Namespace::Personal)]
    SetDerivationIndex,

    #[namespace(Namespace::Personal)]
    GenerateAddress,

    #[namespace(Namespace::Personal)]
    OutgoingHistory,

    #[namespace(Namespace::Mining)]
    GetBlockTemplate,

    #[namespace(Namespace::Mining)]
    SubmitBlock,

    /// Return block heights for blocks containing announcements with specified
    /// announcement flags. May return results from orphaned blocks.
    #[namespace(Namespace::Utxoindex)]
    BlockHeightsByFlags,

    /// Return block heights for blocks containing specified addition records.
    /// Returned block heights are guaranteed to reference blocks belonging to
    /// the canonical chain.
    #[namespace(Namespace::Utxoindex)]
    BlockHeightsByAdditionRecords,

    /// Return block heights for blocks containing specified absolute index
    /// sets. Returned block heights are guaranteed to reference blocks
    /// belonging to the canonical chain.
    #[namespace(Namespace::Utxoindex)]
    BlockHeightsByAbsoluteIndexSets,

    #[namespace(Namespace::Utxoindex)]
    WasMined,

    #[namespace(Namespace::Mempool)]
    Transactions,

    #[namespace(Namespace::Mempool)]
    GetTransactionKernel,

    #[namespace(Namespace::Mempool)]
    GetTransactionProof,

    #[namespace(Namespace::Mempool)]
    GetTransactionsByAdditionRecords,

    #[namespace(Namespace::Mempool)]
    GetTransactionsByAbsoluteIndexSets,

    /// Return transaction most likely to be mined in next block, based on fee
    /// density, sync status, and proof quality.
    #[namespace(Namespace::Mempool)]
    BestTransactionForNextBlock,

    #[namespace(Namespace::Network)]
    Ban,
    #[namespace(Namespace::Network)]
    Unban,
    #[namespace(Namespace::Network)]
    UnbanAll,
    #[namespace(Namespace::Network)]
    Dial,
    #[namespace(Namespace::Network)]
    ProbeNat,
    #[namespace(Namespace::Network)]
    ResetRelayReservations,
    #[namespace(Namespace::Network)]
    NetworkOverview,
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
