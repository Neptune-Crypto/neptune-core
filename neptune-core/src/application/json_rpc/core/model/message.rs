use serde::Deserialize;
use serde::Serialize;
use serde_tuple::Deserialize_tuple;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldElement;

use crate::application::json_rpc::core::model::block::body::*;
use crate::application::json_rpc::core::model::block::header::*;
use crate::application::json_rpc::core::model::block::transaction_kernel::*;
use crate::application::json_rpc::core::model::block::*;
use crate::application::json_rpc::core::model::common::*;

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
pub struct TipDigestRequest {}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TipDigestResponse {
    pub digest: Digest,
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
pub struct GetBlockDigestRequest {
    pub selector: RpcBlockSelector,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockDigestResponse {
    pub digest: Option<Digest>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockDigestsRequest {
    pub height: BFieldElement,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockDigestsResponse {
    pub digests: Vec<Digest>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockRequest {
    pub selector: RpcBlockSelector,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockResponse {
    pub block: Option<RpcBlock>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockProofRequest {
    pub selector: RpcBlockSelector,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockProofResponse {
    pub proof: Option<RpcBlockProof>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockKernelRequest {
    pub selector: RpcBlockSelector,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockKernelResponse {
    pub kernel: Option<RpcBlockKernel>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockHeaderRequest {
    pub selector: RpcBlockSelector,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockHeaderResponse {
    pub header: Option<RpcBlockHeader>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockBodyRequest {
    pub selector: RpcBlockSelector,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockBodyResponse {
    pub body: Option<RpcBlockBody>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockTransactionKernelRequest {
    pub selector: RpcBlockSelector,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockTransactionKernelResponse {
    pub kernel: Option<RpcTransactionKernel>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockAnnouncementsRequest {
    pub selector: RpcBlockSelector,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockAnnouncementsResponse {
    pub announcements: Option<Vec<RpcBFieldElements>>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize_tuple)]
#[serde(rename_all = "camelCase")]
pub struct IsBlockCanonicalRequest {
    pub digest: Digest,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IsBlockCanonicalResponse {
    pub canonical: bool,
}
