use serde::Deserialize;
use serde::Serialize;
use serde_tuple::Deserialize_tuple;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::twenty_first::tip5::digest::Digest;

use crate::application::json_rpc::core::model::block::body::*;
use crate::application::json_rpc::core::model::block::header::*;
use crate::application::json_rpc::core::model::block::transaction_kernel::*;
use crate::application::json_rpc::core::model::block::*;
use crate::application::json_rpc::core::model::common::*;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::block_info::BlockInfo;
use crate::protocol::consensus::block::block_selector::BlockSelector;

#[derive(Clone, Copy, Debug, Serialize, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct NetworkRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkResponse {
    pub network: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct HeightRequest {}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeightResponse {
    pub height: BFieldElement,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TipRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TipResponse {
    pub block: RpcBlock,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TipProofRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TipProofResponse {
    pub proof: RpcBlockProof,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TipKernelRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TipKernelResponse {
    pub kernel: RpcBlockKernel,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TipHeaderRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TipHeaderResponse {
    pub header: RpcBlockHeader,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TipBodyRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TipBodyResponse {
    pub body: RpcBlockBody,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TipTransactionKernelRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TipTransactionKernelResponse {
    pub kernel: RpcTransactionKernel,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct TipAnnouncementsRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TipAnnouncementsResponse {
    pub announcements: Vec<RpcBFieldElements>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct CookieHintRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CookieHintResponse {
    pub data_directory: String,
    pub network: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockInfoRequest {
    pub block_selector: BlockSelector,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockInfoResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_info: Option<BlockInfo>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockDigestRequest {
    pub block_selector: BlockSelector,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockDigestResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<Digest>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockDigestsByHeightRequest {
    pub height: BlockHeight,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockDigestsByHeightResponse {
    pub digests: Vec<Digest>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LatestTipDigestsRequest {
    pub n: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LatestTipDigestsResponse {
    pub digests: Vec<Digest>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmationsRequest {}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmationsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmations: Option<BlockHeight>,
}
