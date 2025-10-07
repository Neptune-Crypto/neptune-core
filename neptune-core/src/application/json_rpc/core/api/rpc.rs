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
}
