use libp2p::Multiaddr;
use serde::Deserialize;
use serde::Serialize;
use serde_tuple::Deserialize_tuple;
use serde_tuple::Serialize_tuple;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldElement;

use crate::api::export::KeyType;
use crate::api::export::Timestamp;
use crate::application::json_rpc::core::model::block::body::*;
use crate::application::json_rpc::core::model::block::header::*;
use crate::application::json_rpc::core::model::block::transaction_kernel::*;
use crate::application::json_rpc::core::model::block::*;
use crate::application::json_rpc::core::model::common::*;
use crate::application::json_rpc::core::model::mining::template::RpcBlockTemplate;
use crate::application::json_rpc::core::model::wallet::block::*;
use crate::application::json_rpc::core::model::wallet::mutator_set::*;
use crate::application::json_rpc::core::model::wallet::personal_history::InitiatedTransaction;
use crate::application::json_rpc::core::model::wallet::transaction::RpcTransaction;
use crate::application::json_rpc::core::model::wallet::transaction::RpcTransactionProof;
use crate::application::json_rpc::core::model::wallet::RpcAnnouncementFlag;
use crate::application::network::overview::NetworkOverview;

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct NetworkRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkResponse {
    pub network: String,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct HeightRequest {}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeightResponse {
    pub height: RpcBlockHeight,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TipDigestRequest {}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TipDigestResponse {
    pub digest: Digest,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TipRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TipResponse {
    pub block: RpcBlock,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TipProofRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TipProofResponse {
    pub proof: RpcBlockProof,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TipKernelRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TipKernelResponse {
    pub kernel: RpcBlockKernel,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TipHeaderRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TipHeaderResponse {
    pub header: RpcBlockHeader,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TipBodyRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TipBodyResponse {
    pub body: RpcBlockBody,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TipTransactionKernelRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TipTransactionKernelResponse {
    pub kernel: RpcTransactionKernel,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TipAnnouncementsRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TipAnnouncementsResponse {
    pub announcements: Vec<RpcAnnouncement>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockDigestRequest {
    pub selector: RpcBlockSelector,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockDigestResponse {
    pub digest: Option<Digest>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockDigestsRequest {
    pub height: BFieldElement,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockDigestsResponse {
    pub digests: Vec<Digest>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockRequest {
    pub selector: RpcBlockSelector,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockResponse {
    pub block: Option<RpcBlock>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockProofRequest {
    pub selector: RpcBlockSelector,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockProofResponse {
    pub proof: Option<RpcBlockProof>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockKernelRequest {
    pub selector: RpcBlockSelector,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockKernelResponse {
    pub kernel: Option<RpcBlockKernel>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockHeaderRequest {
    pub selector: RpcBlockSelector,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockHeaderResponse {
    pub header: Option<RpcBlockHeader>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockBodyRequest {
    pub selector: RpcBlockSelector,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockBodyResponse {
    pub body: Option<RpcBlockBody>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockTransactionKernelRequest {
    pub selector: RpcBlockSelector,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockTransactionKernelResponse {
    pub kernel: Option<RpcTransactionKernel>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockAnnouncementsRequest {
    pub selector: RpcBlockSelector,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockAnnouncementsResponse {
    pub announcements: Option<Vec<RpcAnnouncement>>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct IsBlockCanonicalRequest {
    pub digest: Digest,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IsBlockCanonicalResponse {
    pub canonical: bool,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetUtxoDigestRequest {
    pub leaf_index: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetUtxoDigestResponse {
    pub digest: Option<Digest>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct FindUtxoOriginRequest {
    pub addition_record: RpcAdditionRecord,

    #[serde(default)]
    pub search_depth: Option<u64>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindUtxoOriginResponse {
    pub block: Option<Digest>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct AreBloomIndicesSetRequest {
    pub absolute_index_set: RpcAbsoluteIndexSet,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AreBloomIndicesSetResponse {
    pub are_set: bool,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct CirculatingSupplyRequest {}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CirculatingSupplyResponse {
    pub amount: RpcNativeCurrencyAmount,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct MaxSupplyRequest {}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MaxSupplyResponse {
    pub amount: RpcNativeCurrencyAmount,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct BurnedSupplyRequest {}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BurnedSupplyResponse {
    pub amount: RpcNativeCurrencyAmount,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlocksRequest {
    pub from_height: RpcBlockHeight,
    pub to_height: RpcBlockHeight,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlocksResponse {
    pub blocks: Vec<RpcWalletBlock>,
}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct RestoreMembershipProofRequest {
    pub absolute_index_sets: Vec<RpcAbsoluteIndexSet>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreMembershipProofResponse {
    pub snapshot: RpcMsMembershipSnapshot,
}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct SubmitTransactionRequest {
    pub transaction: RpcTransaction,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitTransactionResponse {
    pub success: bool,
}

/* Personal */

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct RescanAnnouncedRequest {
    pub first: RpcBlockHeight,
    pub last: RpcBlockHeight,
    pub derivation_path: Option<(KeyType, u64)>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RescanAnnouncedResponse {}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct RescanExpectedRequest {
    pub first: RpcBlockHeight,
    pub last: RpcBlockHeight,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RescanExpectedResponse {}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct RescanOutgoingRequest {}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RescanOutgoingResponse {}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct RescanGuesserRewardsRequest {
    pub first: RpcBlockHeight,
    pub last: RpcBlockHeight,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RescanGuesserRewardsResponse {}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct DerivationIndexRequest {
    pub key_type: KeyType,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DerivationIndexResponse {
    pub derivation_index: u64,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct SetDerivationIndexRequest {
    pub key_type: KeyType,
    pub derivation_index: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetDerivationIndexResponse {}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GenerateAddressRequest {
    pub key_type: KeyType,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateAddressResponse {
    pub address: String,
}

/* Mining */
#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockTemplateRequest {
    pub guesser_address: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockTemplateResponse {
    pub template: Option<RpcBlockTemplate>,
}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct SubmitBlockRequest {
    pub template: RpcBlock,
    pub pow: RpcBlockPow,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitBlockResponse {
    pub success: bool,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct OutgoingHistoryRequest {
    pub sender_randomness: Option<Digest>,
    pub receiver_digest: Option<Digest>,
    pub output_lock_script_hash: Option<Digest>,
    pub output: Option<RpcAdditionRecord>,
    pub timestamp: Option<Timestamp>,

    /// Upper limit on the number of returned elements
    pub max_num_elements: Option<u64>,

    /// 0-indexed page.
    pub page: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutgoingHistoryResponse {
    pub matching_sent: Vec<InitiatedTransaction>,
}

/* Utxo Index */
#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeightsByFlagsRequest {
    pub announcement_flags: Vec<RpcAnnouncementFlag>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeightsByFlagsResponse {
    pub block_heights: Vec<RpcBlockHeight>,
}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeightsByAdditionRecordsRequest {
    pub addition_records: Vec<RpcAdditionRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeightsByAdditionRecordsResponse {
    pub block_heights: Vec<RpcBlockHeight>,
}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeightsByAbsoluteIndexSetsRequest {
    pub absolute_index_sets: Vec<RpcAbsoluteIndexSet>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeightsByAbsoluteIndexSetsResponse {
    pub block_heights: Vec<RpcBlockHeight>,
}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct WasMinedRequest {
    pub absolute_index_sets: Vec<RpcAbsoluteIndexSet>,
    pub addition_records: Vec<RpcAdditionRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WasMinedResponse {
    pub block_heights: Vec<RpcBlockHeight>,
}

/* Mempool */
#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TransactionsRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionsResponse {
    pub transactions: Vec<RpcTransactionKernelId>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactionKernelRequest {
    pub id: RpcTransactionKernelId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactionKernelResponse {
    pub kernel: Option<RpcTransactionKernel>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactionProofRequest {
    pub id: RpcTransactionKernelId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactionProofResponse {
    pub proof: Option<RpcTransactionProof>,
}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactionsByAdditionRecordsRequest {
    pub addition_records: Vec<RpcAdditionRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactionsByAdditionRecordsResponse {
    pub transactions: Vec<TransactionKernelWithPriority>,
}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactionsByAbsoluteIndexSetsRequest {
    pub absolute_index_sets: Vec<RpcAbsoluteIndexSet>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactionsByAbsoluteIndexSetsResponse {
    pub transactions: Vec<TransactionKernelWithPriority>,
}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct BestTransactionForNextBlockRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BestTransactionForNextBlockResponse {
    pub transaction: Option<RpcTransactionKernel>,
}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
pub struct BanRequest {
    pub address: Multiaddr,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BanResponse {}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct UnbanRequest {
    pub address: Multiaddr,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnbanResponse {}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct UnbanAllRequest {}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnbanAllResponse {}

#[derive(Clone, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct DialRequest {
    pub address: Multiaddr,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DialResponse {}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct ProbeNatRequest {}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeNatResponse {}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct ResetRelayReservationsRequest {}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetRelayReservationsResponse {}

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct NetworkOverviewRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkOverviewResponse {
    pub network_overview: NetworkOverview,
}
