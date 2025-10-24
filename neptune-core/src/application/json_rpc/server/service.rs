use async_trait::async_trait;

use crate::application::json_rpc::core::api::rpc::RpcApi;
use crate::application::json_rpc::core::model::block::RpcBlock;
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

    async fn tip_digest_call(&self, _: TipDigestRequest) -> TipDigestResponse {
        let state = self.state.lock_guard().await;
        let block = state.chain.light_state();

        TipDigestResponse {
            digest: block.hash(),
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

    async fn get_block_digest_call(
        &self,
        request: GetBlockDigestRequest,
    ) -> GetBlockDigestResponse {
        let state = self.state.lock_guard().await;
        let digest = request.selector.as_digest(&state).await;

        GetBlockDigestResponse { digest }
    }

    async fn get_block_digests_call(
        &self,
        request: GetBlockDigestsRequest,
    ) -> GetBlockDigestsResponse {
        let state = self.state.lock_guard().await;

        GetBlockDigestsResponse {
            digests: state
                .chain
                .archival_state()
                .block_height_to_block_digests(request.height.into())
                .await,
        }
    }
    async fn get_block_call(&self, request: GetBlockRequest) -> GetBlockResponse {
        let state = self.state.lock_guard().await;

        let digest = request.selector.as_digest(&state).await;
        let block = match digest {
            Some(digest) => state
                .chain
                .archival_state()
                .get_block(digest)
                .await
                .unwrap()
                .as_ref()
                .map(RpcBlock::from),
            None => None,
        };

        GetBlockResponse { block }
    }

    async fn get_block_proof_call(&self, request: GetBlockProofRequest) -> GetBlockProofResponse {
        let state = self.state.lock_guard().await;

        let digest = request.selector.as_digest(&state).await;
        let proof = match digest {
            Some(digest) => state
                .chain
                .archival_state()
                .get_block(digest)
                .await
                .unwrap()
                .as_ref()
                .map(|b| (&b.proof).into()),
            None => None,
        };

        GetBlockProofResponse { proof }
    }

    async fn get_block_kernel_call(
        &self,
        request: GetBlockKernelRequest,
    ) -> GetBlockKernelResponse {
        let state = self.state.lock_guard().await;

        let digest = request.selector.as_digest(&state).await;
        let kernel = match digest {
            Some(digest) => state
                .chain
                .archival_state()
                .get_block(digest)
                .await
                .unwrap()
                .as_ref()
                .map(|b| (&b.kernel).into()),
            None => None,
        };

        GetBlockKernelResponse { kernel }
    }

    async fn get_block_header_call(
        &self,
        request: GetBlockHeaderRequest,
    ) -> GetBlockHeaderResponse {
        let state = self.state.lock_guard().await;

        let digest = request.selector.as_digest(&state).await;
        let header = match digest {
            Some(digest) => state
                .chain
                .archival_state()
                .get_block(digest)
                .await
                .unwrap()
                .as_ref()
                .map(|b| b.header().into()),
            None => None,
        };

        GetBlockHeaderResponse { header }
    }

    async fn get_block_body_call(&self, request: GetBlockBodyRequest) -> GetBlockBodyResponse {
        let state = self.state.lock_guard().await;

        let digest = request.selector.as_digest(&state).await;
        let body = match digest {
            Some(digest) => state
                .chain
                .archival_state()
                .get_block(digest)
                .await
                .unwrap()
                .as_ref()
                .map(|b| b.body().into()),
            None => None,
        };

        GetBlockBodyResponse { body }
    }

    async fn get_block_transaction_kernel_call(
        &self,
        request: GetBlockTransactionKernelRequest,
    ) -> GetBlockTransactionKernelResponse {
        let state = self.state.lock_guard().await;

        let digest = request.selector.as_digest(&state).await;
        let kernel = match digest {
            Some(digest) => state
                .chain
                .archival_state()
                .get_block(digest)
                .await
                .unwrap()
                .as_ref()
                .map(|b| b.body().transaction_kernel().into()),
            None => None,
        };

        GetBlockTransactionKernelResponse { kernel }
    }

    async fn get_block_announcements_call(
        &self,
        request: GetBlockAnnouncementsRequest,
    ) -> GetBlockAnnouncementsResponse {
        let state = self.state.lock_guard().await;

        let digest = request.selector.as_digest(&state).await;
        let announcements = match digest {
            Some(digest) => state
                .chain
                .archival_state()
                .get_block(digest)
                .await
                .unwrap()
                .as_ref()
                .map(|b| {
                    b.body()
                        .transaction_kernel()
                        .announcements
                        .iter()
                        .map(|a| a.message.clone().into())
                        .collect::<Vec<_>>()
                }),
            None => None,
        };

        GetBlockAnnouncementsResponse { announcements }
    }

    async fn is_block_canonical_call(
        &self,
        request: IsBlockCanonicalRequest,
    ) -> IsBlockCanonicalResponse {
        let state = self.state.lock_guard().await;

        IsBlockCanonicalResponse {
            canonical: state
                .chain
                .archival_state()
                .block_belongs_to_canonical_chain(request.digest)
                .await,
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod tests {
    use std::collections::HashSet;

    use macro_rules_attr::apply;
    use tasm_lib::prelude::Digest;

    use crate::api::export::Network;
    use crate::application::config::cli_args;
    use crate::application::json_rpc::core::api::rpc::RpcApi;
    use crate::application::json_rpc::core::model::common::RpcBlockSelector;
    use crate::application::json_rpc::server::http::RpcServer;
    use crate::protocol::consensus::block::block_height::BlockHeight;
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
        rpc_server.state.set_new_tip(block1.clone()).await.unwrap();

        let digest = rpc_server.tip_digest().await.digest;
        assert_eq!(block1.hash(), digest);

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

    #[test_strategy::proptest(async = "tokio", cases = 5)]
    async fn get_block_calls_are_consistent(
        #[strategy(0usize..8)] _num_outputs: usize,
        #[strategy(0usize..8)] _num_announcements: usize,
        #[strategy(txkernel::with_lengths(0, #_num_outputs, #_num_announcements, true))]
    tx_block1: crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel,
    ) {
        let mut rpc_server = test_rpc_server().await;

        let tx_block1 = Transaction {
            kernel: tx_block1,
            proof: TransactionProof::invalid(),
        };
        let block1 = invalid_block_with_transaction(&Block::genesis(Network::Main), tx_block1);
        rpc_server.state.set_new_tip(block1.clone()).await.unwrap();

        for height in [BlockHeight::genesis(), BlockHeight::genesis().next()] {
            let height_selector = RpcBlockSelector::Height(height);
            let digest = rpc_server
                .get_block_digest(height_selector)
                .await
                .digest
                .expect("digest should be available");
            let selector = RpcBlockSelector::Digest(digest);

            let block = rpc_server
                .get_block(selector)
                .await
                .block
                .expect("block should exist");
            let proof = rpc_server
                .get_block_proof(selector)
                .await
                .proof
                .expect("proof should exist");
            assert_eq!(block.proof, proof);

            let kernel = rpc_server
                .get_block_kernel(selector)
                .await
                .kernel
                .expect("kernel should exist");
            let header = rpc_server
                .get_block_header(selector)
                .await
                .header
                .expect("header should exist");
            assert_eq!(kernel.header, header);
            assert_eq!(header.height, height.into());

            let body = rpc_server
                .get_block_body(selector)
                .await
                .body
                .expect("body should exist");
            let transaction_kernel = rpc_server
                .get_block_transaction_kernel(selector)
                .await
                .kernel
                .expect("transaction kernel should exist");
            assert_eq!(body.transaction_kernel, transaction_kernel);

            let announcements = rpc_server
                .get_block_announcements(selector)
                .await
                .announcements
                .expect("announcements should exist");
            assert_eq!(transaction_kernel.announcements, announcements);
        }
    }

    #[test_strategy::proptest(async = "tokio", cases = 5)]
    async fn get_block_digests_returns_competing_blocks(
        #[strategy(txkernel::with_lengths(0, 2, 2, true))]
    tx_block1: crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel,
        #[strategy(txkernel::with_lengths(0, 2, 2, true))]
    tx_block2: crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel,
    ) {
        let mut rpc_server = test_rpc_server().await;

        let tx_block1 = Transaction {
            kernel: tx_block1,
            proof: TransactionProof::invalid(),
        };
        let tx_block2 = Transaction {
            kernel: tx_block2,
            proof: TransactionProof::invalid(),
        };
        let block1 = invalid_block_with_transaction(&Block::genesis(Network::Main), tx_block1);
        let block2 = invalid_block_with_transaction(&Block::genesis(Network::Main), tx_block2);
        rpc_server.state.set_new_tip(block1.clone()).await.unwrap();
        rpc_server.state.set_new_tip(block2.clone()).await.unwrap();

        let digests = rpc_server
            .get_block_digests(BlockHeight::genesis().next().into())
            .await
            .digests;

        let expected: HashSet<_> = [block1.hash(), block2.hash()].into();
        let actual: HashSet<_> = digests.into_iter().collect();

        assert_eq!(expected, actual);
    }

    #[apply(shared_tokio_runtime)]
    async fn is_block_canonical_consistency() {
        let rpc_server = test_rpc_server().await;

        // Test genesis block is canonical
        let genesis_digest = rpc_server.tip_digest().await.digest;
        let is_genesis_canonical = rpc_server
            .is_block_canonical(genesis_digest)
            .await
            .canonical;
        assert!(is_genesis_canonical, "Genesis block should be canonical");

        // Test non-existent block is not canonical
        let fake_digest = Digest::default();
        let is_fake_canonical = rpc_server.is_block_canonical(fake_digest).await.canonical;
        assert!(
            !is_fake_canonical,
            "Non-existent block should not be canonical"
        );
    }
}
