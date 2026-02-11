use libp2p::Multiaddr;
use serde::Deserialize;
use serde::Serialize;
use serde_tuple::Deserialize_tuple;
use serde_tuple::Serialize_tuple;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldElement;

use crate::application::json_rpc::core::model::block::body::*;
use crate::application::json_rpc::core::model::block::header::*;
use crate::application::json_rpc::core::model::block::transaction_kernel::*;
use crate::application::json_rpc::core::model::block::*;
use crate::application::json_rpc::core::model::common::*;
use crate::application::json_rpc::core::model::mining::template::RpcBlockTemplate;
use crate::application::json_rpc::core::model::wallet::block::*;
use crate::application::json_rpc::core::model::wallet::mutator_set::*;
use crate::application::json_rpc::core::model::wallet::transaction::RpcTransaction;
use crate::application::json_rpc::core::model::wallet::transaction::RpcTransactionProof;
use crate::application::json_rpc::core::model::wallet::RpcAnnouncementFlag;
use crate::application::network::overview::NetworkOverview;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::difficulty_control::Difficulty;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::application::json_rpc::core::model::wallet::adapter;

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

#[derive(Clone, Copy, Debug, Serialize_tuple, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct RescanAnnouncedRequest {
    pub first: RpcBlockHeight,
    pub last: RpcBlockHeight,
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
pub struct RescanOutgoingRequest {
    pub first: RpcBlockHeight,
    pub last: RpcBlockHeight,
}

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

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockInfoRequest {
    pub selector: RpcBlockSelector,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockInfoInput {
    pub n: usize,
    pub leaf_index: u64,
    pub utxo_digest: Digest,
    pub sender_randomness: Digest,
    pub confirmed_height: BlockHeight,
    pub utxo: ApiUtxo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockInfoOutput {
    pub n: usize,
    pub leaf_index: u64,
    pub utxo_digest: Digest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_randomness: Option<Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiving_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver_digest: Option<Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver_identifier: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utxo: Option<ApiUtxo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockInfo {
    pub height: BlockHeight,
    pub digest: Digest,
    pub timestamp: Timestamp,
    pub difficulty: Difficulty,
    pub size: usize,
    pub fee: String,
    pub inputs: Vec<BlockInfoInput>,
    pub outputs: Vec<BlockInfoOutput>,
}

pub type BlockInfoResponse = Option<BlockInfo>;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateAddressRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateAddressResponse {
    #[serde(flatten)]
    pub address: adapter::GenerateAddressResponse,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBalanceRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBalanceResponse {
    #[serde(flatten)]
    pub balance: adapter::BalanceResponse,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendTxRequest {
    pub amount: String,
    pub fee: String,
    pub to_address: String,
    #[serde(default)]
    pub exclude_recent_blocks: usize,
    /// Maximum number of input UTXOs to select. `None` means no limit.
    #[serde(default)]
    pub max_inputs: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendTxUtxo {
    pub lock_script_hash: Digest,
    pub amount: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendTxInput {
    pub leaf_index: u64,
    pub utxo_digest: Digest,
    pub utxo: SendTxUtxo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendTxOutput {
    pub utxo: SendTxUtxo,
    pub utxo_digest: Digest,
    pub sender_randomness: Digest,
    pub is_owned: bool,
    pub is_change: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendTxResponse {
    pub timestamp: Timestamp,
    pub tip_when_sent: Digest,
    pub inputs: Vec<SendTxInput>,
    pub outputs: Vec<SendTxOutput>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateAddressRequest {
    pub address_string: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateAddressResponse {
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver_identifier: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_address: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateAmountRequest {
    pub amount_string: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateAmountResponse {
    #[serde(flatten)]
    pub amount: adapter::ValidateAmountResponse,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnspentUtxosRequest {
    #[serde(default)]
    pub exclude_recent_blocks: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnspentUtxo {
    pub leaf_index: u64,
    pub lock_script_hash: Digest,
    pub amount: String,
}

pub type UnspentUtxosResponse = Vec<UnspentUtxo>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryRequest {
    pub leaf_index: Option<u64>,
    pub utxo_digest: Option<Digest>,
    pub receiving_address: Option<String>,
    pub sender_randomness: Option<Digest>,
    pub confirmed_height: Option<BlockHeight>,
    pub spent_height: Option<BlockHeight>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct History {
    pub utxo_digest: Option<Digest>,
    pub leaf_index: u64,
    pub sender_randomness: Digest,
    pub digest: Digest,
    pub confirmed_height: BlockHeight,
    pub spent_height: Option<BlockHeight>,
    pub timestamp: Timestamp,
    pub receiving_address: Option<String>,
    pub utxo: ApiUtxo,
}

pub type HistoryResponse = Vec<History>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SentTxInput {
    pub leaf_index: u64,
    pub utxo_digest: Option<Digest>,
    pub utxo: ApiUtxo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SentTxOutput {
    pub utxo: ApiUtxo,
    pub utxo_digest: Digest,
    pub sender_randomness: Digest,
    pub receiver_digest: Digest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SentTxToRespResponse {
    pub tx_inputs: Vec<SentTxInput>,
    pub tx_outputs: Vec<SentTxOutput>,
    pub fee: String,
    pub timestamp: Timestamp,
    pub tip_when_sent: Digest,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SentTransactionRequest {
    pub sender_randomness: Option<Digest>,
    pub receiver_digest: Option<Digest>,
    pub lock_script_hash: Option<Digest>,
    pub utxo_digest: Option<Digest>,
    pub timestamp: Option<Timestamp>,
    pub limit: Option<u64>,
    pub page: Option<u64>,
}

pub type SentTransactionResponse = Vec<SentTxToRespResponse>;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CountSentTransactionsAtBlockRequest {
    pub block: RpcBlockSelector,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CountSentTransactionsAtBlockResponse {
    pub count: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindUtxoLeafIndexRequest {
    pub utxo_digest: Digest,

    #[serde(default)]
    pub from_leaf_index: Option<u64>,

    #[serde(default)]
    pub to_leaf_index: Option<u64>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindUtxoLeafIndexResponse {
    pub leaf_index: Option<u64>,
    pub mempool: bool,
    pub block_height: Option<BlockHeight>,
    pub block_digest: Option<Digest>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAoclLeafIndicesRequest {
    pub commitments: Vec<Digest>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAoclLeafIndicesResponse {
    pub indices: Vec<Option<u64>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiUtxo {
    pub lock_script_hash: Digest,
    pub amount: String,
    pub can_spend: bool,
    pub release_date: Option<Timestamp>,
    pub valid: bool,
}

impl ApiUtxo {
    pub fn new(utxo: &crate::protocol::consensus::transaction::utxo::Utxo) -> Self {
        Self {
            lock_script_hash: utxo.lock_script_hash(),
            amount: utxo.get_native_currency_amount().to_string(),
            can_spend: utxo.can_spend_at(Timestamp::now()),
            release_date: utxo.release_date(),
            valid: utxo.all_type_script_states_are_valid(),
        }
    }
}
