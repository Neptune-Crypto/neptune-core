use async_trait::async_trait;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldElement;

use crate::application::json_rpc::core::model::common::RpcBlockSelector;
use crate::application::json_rpc::core::model::message::*;

#[async_trait]
pub trait RpcApi: Sync + Send {
    /* Node */

    async fn network(&self) -> NetworkResponse {
        self.network_call(NetworkRequest {}).await
    }
    async fn network_call(&self, request: NetworkRequest) -> NetworkResponse;

    /* Chain */

    async fn height(&self) -> HeightResponse {
        self.height_call(HeightRequest {}).await
    }
    async fn height_call(&self, request: HeightRequest) -> HeightResponse;

    async fn tip_digest(&self) -> TipDigestResponse {
        self.tip_digest_call(TipDigestRequest {}).await
    }
    async fn tip_digest_call(&self, request: TipDigestRequest) -> TipDigestResponse;

    async fn tip(&self) -> TipResponse {
        self.tip_call(TipRequest {}).await
    }
    async fn tip_call(&self, request: TipRequest) -> TipResponse;

    async fn tip_proof(&self) -> TipProofResponse {
        self.tip_proof_call(TipProofRequest {}).await
    }
    async fn tip_proof_call(&self, request: TipProofRequest) -> TipProofResponse;

    async fn tip_kernel(&self) -> TipKernelResponse {
        self.tip_kernel_call(TipKernelRequest {}).await
    }
    async fn tip_kernel_call(&self, request: TipKernelRequest) -> TipKernelResponse;

    async fn tip_header(&self) -> TipHeaderResponse {
        self.tip_header_call(TipHeaderRequest {}).await
    }
    async fn tip_header_call(&self, request: TipHeaderRequest) -> TipHeaderResponse;

    async fn tip_body(&self) -> TipBodyResponse {
        self.tip_body_call(TipBodyRequest {}).await
    }
    async fn tip_body_call(&self, request: TipBodyRequest) -> TipBodyResponse;

    async fn tip_transaction_kernel(&self) -> TipTransactionKernelResponse {
        self.tip_transaction_kernel_call(TipTransactionKernelRequest {})
            .await
    }
    async fn tip_transaction_kernel_call(
        &self,
        request: TipTransactionKernelRequest,
    ) -> TipTransactionKernelResponse;

    async fn tip_announcements(&self) -> TipAnnouncementsResponse {
        self.tip_announcements_call(TipAnnouncementsRequest {})
            .await
    }
    async fn tip_announcements_call(
        &self,
        request: TipAnnouncementsRequest,
    ) -> TipAnnouncementsResponse;

    /* Archival */

    async fn get_block_digests(&self, height: BFieldElement) -> GetBlockDigestsResponse {
        self.get_block_digests_call(GetBlockDigestsRequest { height })
            .await
    }
    async fn get_block_digests_call(
        &self,
        request: GetBlockDigestsRequest,
    ) -> GetBlockDigestsResponse;

    async fn get_block_digest(&self, selector: RpcBlockSelector) -> GetBlockDigestResponse {
        self.get_block_digest_call(GetBlockDigestRequest { selector })
            .await
    }
    async fn get_block_digest_call(&self, request: GetBlockDigestRequest)
        -> GetBlockDigestResponse;

    async fn get_block(&self, selector: RpcBlockSelector) -> GetBlockResponse {
        self.get_block_call(GetBlockRequest { selector }).await
    }
    async fn get_block_call(&self, request: GetBlockRequest) -> GetBlockResponse;

    async fn get_block_proof(&self, selector: RpcBlockSelector) -> GetBlockProofResponse {
        self.get_block_proof_call(GetBlockProofRequest { selector })
            .await
    }
    async fn get_block_proof_call(&self, request: GetBlockProofRequest) -> GetBlockProofResponse;

    async fn get_block_kernel(&self, selector: RpcBlockSelector) -> GetBlockKernelResponse {
        self.get_block_kernel_call(GetBlockKernelRequest { selector })
            .await
    }
    async fn get_block_kernel_call(&self, request: GetBlockKernelRequest)
        -> GetBlockKernelResponse;

    async fn get_block_header(&self, selector: RpcBlockSelector) -> GetBlockHeaderResponse {
        self.get_block_header_call(GetBlockHeaderRequest { selector })
            .await
    }
    async fn get_block_header_call(&self, request: GetBlockHeaderRequest)
        -> GetBlockHeaderResponse;

    async fn get_block_body(&self, selector: RpcBlockSelector) -> GetBlockBodyResponse {
        self.get_block_body_call(GetBlockBodyRequest { selector })
            .await
    }
    async fn get_block_body_call(&self, request: GetBlockBodyRequest) -> GetBlockBodyResponse;

    async fn get_block_transaction_kernel(
        &self,
        selector: RpcBlockSelector,
    ) -> GetBlockTransactionKernelResponse {
        self.get_block_transaction_kernel_call(GetBlockTransactionKernelRequest { selector })
            .await
    }
    async fn get_block_transaction_kernel_call(
        &self,
        request: GetBlockTransactionKernelRequest,
    ) -> GetBlockTransactionKernelResponse;

    async fn get_block_announcements(
        &self,
        selector: RpcBlockSelector,
    ) -> GetBlockAnnouncementsResponse {
        self.get_block_announcements_call(GetBlockAnnouncementsRequest { selector })
            .await
    }
    async fn get_block_announcements_call(
        &self,
        request: GetBlockAnnouncementsRequest,
    ) -> GetBlockAnnouncementsResponse;

    async fn is_block_canonical(&self, digest: Digest) -> IsBlockCanonicalResponse {
        self.is_block_canonical_call(IsBlockCanonicalRequest { digest })
            .await
    }
    async fn is_block_canonical_call(
        &self,
        request: IsBlockCanonicalRequest,
    ) -> IsBlockCanonicalResponse;
}
