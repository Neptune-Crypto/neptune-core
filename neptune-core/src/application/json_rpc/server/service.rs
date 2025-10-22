use async_trait::async_trait;

use crate::application::json_rpc::core::api::rpc::RpcApi;
use crate::application::json_rpc::core::model::message::*;
use crate::application::json_rpc::server::http::RpcServer;
use crate::protocol::consensus::block::block_info::BlockInfo;

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

    async fn cookie_hint_call(&self, _: CookieHintRequest) -> CookieHintResponse {
        let state = self.state.lock_guard().await;
        let data_dir = state
            .wallet_state
            .configuration
            .data_directory()
            .root_dir_path()
            .to_string_lossy()
            .to_string();

        CookieHintResponse {
            data_directory: data_dir,
            network: self.state.cli().network.to_string(),
        }
    }

    async fn block_info_call(&self, request: BlockInfoRequest) -> BlockInfoResponse {
        let state = self.state.lock_guard().await;
        let Some(digest) = request.block_selector.as_digest(&state).await else {
            return BlockInfoResponse { block_info: None };
        };

        let tip_digest = state.chain.light_state().hash();
        let archival_state = state.chain.archival_state();

        let Some(block) = archival_state.get_block(digest).await.ok().flatten() else {
            return BlockInfoResponse { block_info: None };
        };

        let is_canonical = archival_state
            .block_belongs_to_canonical_chain(digest)
            .await;

        let sibling_blocks = archival_state
            .block_height_to_block_digests(block.header().height)
            .await
            .into_iter()
            .filter(|d| *d != digest)
            .collect();

        BlockInfoResponse {
            block_info: Some(BlockInfo::new(
                &block,
                archival_state.genesis_block().hash(),
                tip_digest,
                sibling_blocks,
                is_canonical,
            )),
        }
    }

    async fn block_digest_call(&self, request: BlockDigestRequest) -> BlockDigestResponse {
        let state = self.state.lock_guard().await;
        let digest = request.block_selector.as_digest(&state).await;

        BlockDigestResponse { digest }
    }

    async fn block_digests_by_height_call(
        &self,
        request: BlockDigestsByHeightRequest,
    ) -> BlockDigestsByHeightResponse {
        let state = self.state.lock_guard().await;
        let digests = state
            .chain
            .archival_state()
            .block_height_to_block_digests(request.height)
            .await;

        BlockDigestsByHeightResponse { digests }
    }

    async fn latest_tip_digests_call(
        &self,
        request: LatestTipDigestsRequest,
    ) -> LatestTipDigestsResponse {
        let state = self.state.lock_guard().await;
        let latest_block_digest = state.chain.light_state().hash();
        let digests = state
            .chain
            .archival_state()
            .get_ancestor_block_digests(latest_block_digest, request.n)
            .await;

        LatestTipDigestsResponse { digests }
    }

    async fn confirmations_call(&self, _: ConfirmationsRequest) -> ConfirmationsResponse {
        let state = self.state.lock_guard().await;
        let confirmations = match state.get_latest_balance_height().await {
            Some(latest_balance_height) => {
                let tip_block_header = state.chain.light_state().header();
                let diff = (tip_block_header.height - latest_balance_height) as u64 + 1;
                Some(diff.into())
            }
            None => None,
        };

        ConfirmationsResponse { confirmations }
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
    use crate::twenty_first::bfe;
    use crate::BFieldElement;
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
        assert_eq!(bfe!(0), rpc_server.height().await.height);
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
