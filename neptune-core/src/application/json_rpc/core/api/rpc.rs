use async_trait::async_trait;

use crate::application::json_rpc::core::model::message::*;

#[async_trait]
pub trait RpcApi: Sync + Send {
    async fn get_height(&self) -> GetHeightResponse {
        self.get_height_call(GetHeightRequest {}).await
    }
    async fn get_height_call(&self, request: GetHeightRequest) -> GetHeightResponse;
}
