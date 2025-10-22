use async_trait::async_trait;

use crate::application::json_rpc::core::model::message::*;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::block_selector::BlockSelector;

#[async_trait]
pub trait RpcApi: Sync + Send {
    async fn network(&self) -> NetworkResponse {
        self.network_call(NetworkRequest {}).await
    }
    async fn network_call(&self, request: NetworkRequest) -> NetworkResponse;

    async fn height(&self) -> HeightResponse {
        self.height_call(HeightRequest {}).await
    }
    async fn height_call(&self, request: HeightRequest) -> HeightResponse;

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

    async fn cookie_hint(&self) -> CookieHintResponse {
        self.cookie_hint_call(CookieHintRequest {}).await
    }
    async fn cookie_hint_call(&self, request: CookieHintRequest) -> CookieHintResponse;

    async fn block_info(&self, block_selector: BlockSelector) -> BlockInfoResponse {
        self.block_info_call(BlockInfoRequest { block_selector })
            .await
    }
    async fn block_info_call(&self, request: BlockInfoRequest) -> BlockInfoResponse;

    async fn block_digest(&self, block_selector: BlockSelector) -> BlockDigestResponse {
        self.block_digest_call(BlockDigestRequest { block_selector })
            .await
    }
    async fn block_digest_call(&self, request: BlockDigestRequest) -> BlockDigestResponse;

    async fn block_digests_by_height(&self, height: BlockHeight) -> BlockDigestsByHeightResponse {
        self.block_digests_by_height_call(BlockDigestsByHeightRequest { height })
            .await
    }
    async fn block_digests_by_height_call(
        &self,
        request: BlockDigestsByHeightRequest,
    ) -> BlockDigestsByHeightResponse;

    async fn latest_tip_digests(&self, n: usize) -> LatestTipDigestsResponse {
        self.latest_tip_digests_call(LatestTipDigestsRequest { n })
            .await
    }
    async fn latest_tip_digests_call(
        &self,
        request: LatestTipDigestsRequest,
    ) -> LatestTipDigestsResponse;

    async fn confirmations(&self) -> ConfirmationsResponse {
        self.confirmations_call(ConfirmationsRequest {}).await
    }
    async fn confirmations_call(&self, request: ConfirmationsRequest) -> ConfirmationsResponse;
}
