use crate::application::json_rpc::{
    core::{api::rpc::RpcApi, model::message::*},
    server::http::RpcServer,
};
use async_trait::async_trait;

#[async_trait]
impl RpcApi for RpcServer {
    async fn network_call(&self, _: NetworkRequest) -> NetworkResponse {
        NetworkResponse {
            network: self.state.cli().network.to_string(),
        }
    }

    async fn height_call(&self, _: HeightRequest) -> HeightResponse {
        HeightResponse {
            height: self
                .state
                .lock_guard()
                .await
                .chain
                .light_state()
                .kernel
                .header
                .height
                .into(),
        }
    }

    async fn block_proof_call(&self, _: BlockProofRequest) -> BlockProofResponse {
        BlockProofResponse {
            proof: self
                .state
                .lock_guard()
                .await
                .chain
                .light_state()
                .proof
                .clone()
                .into(),
        }
    }

    async fn block_header_call(&self, _: BlockHeaderRequest) -> BlockHeaderResponse {
        BlockHeaderResponse {
            header: self
                .state
                .lock_guard()
                .await
                .chain
                .light_state()
                .header()
                .into(),
        }
    }

    async fn block_transaction_kernel_call(
        &self,
        _: BlockTransactionKernelRequest,
    ) -> BlockTransactionKernelResponse {
        BlockTransactionKernelResponse {
            kernel: self
                .state
                .lock_guard()
                .await
                .chain
                .light_state()
                .body()
                .transaction_kernel()
                .into(),
        }
    }

    async fn block_announcements_call(
        &self,
        _: BlockAnnouncementsRequest,
    ) -> BlockAnnouncementsResponse {
        BlockAnnouncementsResponse {
            announcements: self
                .state
                .lock_guard()
                .await
                .chain
                .light_state()
                .body()
                .transaction_kernel()
                .announcements
                .iter()
                .map(|a| a.message.clone().into())
                .collect(),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod tests {
    use crate::{
        api::export::Network,
        application::{
            config::cli_args,
            json_rpc::{core::api::rpc::RpcApi, server::http::RpcServer},
        },
        state::wallet::wallet_entropy::WalletEntropy,
        tests::{shared::globalstate::mock_genesis_global_state, shared_tokio_runtime},
    };
    use macro_rules_attr::apply;

    pub async fn test_rpc_server() -> RpcServer {
        let global_state_lock = mock_genesis_global_state(
            2,
            WalletEntropy::new_random(),
            cli_args::Args::default_with_network(Network::Main),
        )
        .await;

        RpcServer::new(global_state_lock)
    }

    #[apply(shared_tokio_runtime)]
    async fn network_is_consistent() {
        let rpc_server = test_rpc_server().await;
        assert_eq!("main", rpc_server.network().await.network);
    }

    #[apply(shared_tokio_runtime)]
    async fn height_is_correct() {
        let rpc_server = test_rpc_server().await;
        assert_eq!(0, rpc_server.height().await.height);
    }
}
