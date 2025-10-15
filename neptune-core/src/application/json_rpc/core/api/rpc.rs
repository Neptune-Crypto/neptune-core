use async_trait::async_trait;

use crate::application::json_rpc::core::model::message::*;

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

    async fn block(&self) -> BlockResponse {
        self.block_call(BlockRequest {}).await
    }
    async fn block_call(&self, request: BlockRequest) -> BlockResponse;

    async fn block_proof(&self) -> BlockProofResponse {
        self.block_proof_call(BlockProofRequest {}).await
    }
    async fn block_proof_call(&self, request: BlockProofRequest) -> BlockProofResponse;

    async fn block_kernel(&self) -> BlockKernelResponse {
        self.block_kernel_call(BlockKernelRequest {}).await
    }
    async fn block_kernel_call(&self, request: BlockKernelRequest) -> BlockKernelResponse;

    async fn block_header(&self) -> BlockHeaderResponse {
        self.block_header_call(BlockHeaderRequest {}).await
    }
    async fn block_header_call(&self, request: BlockHeaderRequest) -> BlockHeaderResponse;

    async fn block_body(&self) -> BlockBodyResponse {
        self.block_body_call(BlockBodyRequest {}).await
    }
    async fn block_body_call(&self, request: BlockBodyRequest) -> BlockBodyResponse;

    async fn block_transaction_kernel(&self) -> BlockTransactionKernelResponse {
        self.block_transaction_kernel_call(BlockTransactionKernelRequest {})
            .await
    }
    async fn block_transaction_kernel_call(
        &self,
        request: BlockTransactionKernelRequest,
    ) -> BlockTransactionKernelResponse;

    async fn block_announcements(&self) -> BlockAnnouncementsResponse {
        self.block_announcements_call(BlockAnnouncementsRequest {})
            .await
    }
    async fn block_announcements_call(
        &self,
        request: BlockAnnouncementsRequest,
    ) -> BlockAnnouncementsResponse;
}
