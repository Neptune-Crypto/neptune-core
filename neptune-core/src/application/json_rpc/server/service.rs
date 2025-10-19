use async_trait::async_trait;

use crate::application::json_rpc::core::api::rpc::RpcApi;
use crate::application::json_rpc::core::model::message::*;
use crate::application::json_rpc::server::http::RpcServer;

#[async_trait]
impl RpcApi for RpcServer {
    async fn network_call(&self, _: NetworkRequest) -> NetworkResponse {
        NetworkResponse {
            network: self.state.cli().network.to_string(),
        }
    }

    async fn height_call(&self, _: HeightRequest) -> HeightResponse {
        let state = self.state.lock_guard().await;

        HeightResponse {
            height: state.chain.light_state().kernel.header.height.into(),
        }
    }

    async fn tip_call(&self, _: TipRequest) -> TipResponse {
        let state = self.state.lock_guard().await;
        let block = state.chain.light_state();

        TipResponse {
            block: block.into(),
        }
    }

    async fn tip_proof_call(&self, _: TipProofRequest) -> TipProofResponse {
        let state = self.state.lock_guard().await;
        let proof = &state.chain.light_state().proof;

        TipProofResponse {
            proof: proof.into(),
        }
    }

    async fn tip_kernel_call(&self, _: TipKernelRequest) -> TipKernelResponse {
        let state = self.state.lock_guard().await;
        let kernel = &state.chain.light_state().kernel;

        TipKernelResponse {
            kernel: kernel.into(),
        }
    }

    async fn tip_header_call(&self, _: TipHeaderRequest) -> TipHeaderResponse {
        let state = self.state.lock_guard().await;

        TipHeaderResponse {
            header: state.chain.light_state().header().into(),
        }
    }

    async fn tip_body_call(&self, _: TipBodyRequest) -> TipBodyResponse {
        let state = self.state.lock_guard().await;

        TipBodyResponse {
            body: state.chain.light_state().body().into(),
        }
    }

    async fn tip_transaction_kernel_call(
        &self,
        _: TipTransactionKernelRequest,
    ) -> TipTransactionKernelResponse {
        let state = self.state.lock_guard().await;

        TipTransactionKernelResponse {
            kernel: state.chain.light_state().body().transaction_kernel().into(),
        }
    }

    async fn tip_announcements_call(&self, _: TipAnnouncementsRequest) -> TipAnnouncementsResponse {
        let state = self.state.lock_guard().await;

        TipAnnouncementsResponse {
            announcements: state
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
    use macro_rules_attr::apply;

    use crate::api::export::Network;
    use crate::application::config::cli_args;
    use crate::application::json_rpc::core::api::rpc::RpcApi;
    use crate::application::json_rpc::server::http::RpcServer;
    use crate::protocol::consensus::transaction::Transaction;
    use crate::protocol::consensus::transaction::TransactionProof;
    use crate::state::wallet::wallet_entropy::WalletEntropy;
    use crate::tests::shared::blocks::invalid_block_with_transaction;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared::strategies::txkernel;
    use crate::tests::shared_tokio_runtime;
    use crate::Block;

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

    #[test_strategy::proptest(async = "tokio", cases = 5)]
    async fn tip_calls_are_consistent(
        #[strategy(txkernel::with_lengths(0, 2, 2, true))]
        tx_block1: crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel,
    ) {
        let mut rpc_server = test_rpc_server().await;

        let tx_block1 = Transaction {
            kernel: tx_block1,
            proof: TransactionProof::invalid(),
        };
        let block1 = invalid_block_with_transaction(&Block::genesis(Network::Main), tx_block1);
        rpc_server
            .state
            .set_new_tip(block1.clone())
            .await
            .expect("block to be valid");

        let block = rpc_server.tip().await.block;
        let proof = rpc_server.tip_proof().await.proof;
        assert_eq!(block.proof, proof);

        let kernel = rpc_server.tip_kernel().await.kernel;
        let header = rpc_server.tip_header().await.header;
        assert_eq!(kernel.header, header);

        let body = rpc_server.tip_body().await.body;
        let transaction_kernel = rpc_server.tip_transaction_kernel().await.kernel;
        assert_eq!(body.transaction_kernel, transaction_kernel);

        let announcements = rpc_server.tip_announcements().await.announcements;
        assert_eq!(transaction_kernel.announcements, announcements);
    }
}
