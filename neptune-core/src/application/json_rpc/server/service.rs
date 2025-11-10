use async_trait::async_trait;

use crate::application::json_rpc::core::api::rpc::RpcApi;
use crate::application::json_rpc::core::api::rpc::RpcResult;
use crate::application::json_rpc::core::model::block::RpcBlock;
use crate::application::json_rpc::core::model::message::*;
use crate::application::json_rpc::server::rpc::RpcServer;

#[async_trait]
impl RpcApi for RpcServer {
    async fn network_call(&self, _: NetworkRequest) -> RpcResult<NetworkResponse> {
        Ok(NetworkResponse {
            network: self.state.cli().network.to_string(),
        })
    }

    async fn height_call(&self, _: HeightRequest) -> RpcResult<HeightResponse> {
        let state = self.state.lock_guard().await;

        Ok(HeightResponse {
            height: state.chain.light_state().kernel.header.height.into(),
        })
    }

    async fn tip_digest_call(&self, _: TipDigestRequest) -> RpcResult<TipDigestResponse> {
        let state = self.state.lock_guard().await;
        let block = state.chain.light_state();

        Ok(TipDigestResponse {
            digest: block.hash(),
        })
    }

    async fn tip_call(&self, _: TipRequest) -> RpcResult<TipResponse> {
        let state = self.state.lock_guard().await;
        let block = state.chain.light_state();

        Ok(TipResponse {
            block: block.into(),
        })
    }

    async fn tip_proof_call(&self, _: TipProofRequest) -> RpcResult<TipProofResponse> {
        let state = self.state.lock_guard().await;
        let proof = &state.chain.light_state().proof;

        Ok(TipProofResponse {
            proof: proof.into(),
        })
    }

    async fn tip_kernel_call(&self, _: TipKernelRequest) -> RpcResult<TipKernelResponse> {
        let state = self.state.lock_guard().await;
        let kernel = &state.chain.light_state().kernel;

        Ok(TipKernelResponse {
            kernel: kernel.into(),
        })
    }

    async fn tip_header_call(&self, _: TipHeaderRequest) -> RpcResult<TipHeaderResponse> {
        let state = self.state.lock_guard().await;

        Ok(TipHeaderResponse {
            header: state.chain.light_state().header().into(),
        })
    }

    async fn tip_body_call(&self, _: TipBodyRequest) -> RpcResult<TipBodyResponse> {
        let state = self.state.lock_guard().await;

        Ok(TipBodyResponse {
            body: state.chain.light_state().body().into(),
        })
    }

    async fn tip_transaction_kernel_call(
        &self,
        _: TipTransactionKernelRequest,
    ) -> RpcResult<TipTransactionKernelResponse> {
        let state = self.state.lock_guard().await;

        Ok(TipTransactionKernelResponse {
            kernel: state.chain.light_state().body().transaction_kernel().into(),
        })
    }

    async fn tip_announcements_call(
        &self,
        _: TipAnnouncementsRequest,
    ) -> RpcResult<TipAnnouncementsResponse> {
        let state = self.state.lock_guard().await;

        Ok(TipAnnouncementsResponse {
            announcements: state
                .chain
                .light_state()
                .body()
                .transaction_kernel()
                .announcements
                .iter()
                .map(|a| a.message.clone().into())
                .collect(),
        })
    }

    async fn get_block_digest_call(
        &self,
        request: GetBlockDigestRequest,
    ) -> RpcResult<GetBlockDigestResponse> {
        let state = self.state.lock_guard().await;
        let digest = request.selector.as_digest(&state).await;

        Ok(GetBlockDigestResponse { digest })
    }

    async fn get_block_digests_call(
        &self,
        request: GetBlockDigestsRequest,
    ) -> RpcResult<GetBlockDigestsResponse> {
        let state = self.state.lock_guard().await;

        Ok(GetBlockDigestsResponse {
            digests: state
                .chain
                .archival_state()
                .block_height_to_block_digests(request.height.into())
                .await,
        })
    }

    async fn get_block_call(&self, request: GetBlockRequest) -> RpcResult<GetBlockResponse> {
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

        Ok(GetBlockResponse { block })
    }

    async fn get_block_proof_call(
        &self,
        request: GetBlockProofRequest,
    ) -> RpcResult<GetBlockProofResponse> {
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

        Ok(GetBlockProofResponse { proof })
    }

    async fn get_block_kernel_call(
        &self,
        request: GetBlockKernelRequest,
    ) -> RpcResult<GetBlockKernelResponse> {
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

        Ok(GetBlockKernelResponse { kernel })
    }

    async fn get_block_header_call(
        &self,
        request: GetBlockHeaderRequest,
    ) -> RpcResult<GetBlockHeaderResponse> {
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

        Ok(GetBlockHeaderResponse { header })
    }

    async fn get_block_body_call(
        &self,
        request: GetBlockBodyRequest,
    ) -> RpcResult<GetBlockBodyResponse> {
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

        Ok(GetBlockBodyResponse { body })
    }

    async fn get_block_transaction_kernel_call(
        &self,
        request: GetBlockTransactionKernelRequest,
    ) -> RpcResult<GetBlockTransactionKernelResponse> {
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

        Ok(GetBlockTransactionKernelResponse { kernel })
    }

    async fn get_block_announcements_call(
        &self,
        request: GetBlockAnnouncementsRequest,
    ) -> RpcResult<GetBlockAnnouncementsResponse> {
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

        Ok(GetBlockAnnouncementsResponse { announcements })
    }

    async fn is_block_canonical_call(
        &self,
        request: IsBlockCanonicalRequest,
    ) -> RpcResult<IsBlockCanonicalResponse> {
        let state = self.state.lock_guard().await;

        Ok(IsBlockCanonicalResponse {
            canonical: state
                .chain
                .archival_state()
                .block_belongs_to_canonical_chain(request.digest)
                .await,
        })
    }

    async fn get_utxo_digest_call(
        &self,
        request: GetUtxoDigestRequest,
    ) -> RpcResult<GetUtxoDigestResponse> {
        let state = self.state.lock_guard().await;
        let aocl = &state.chain.archival_state().archival_mutator_set.ams().aocl;

        Ok(GetUtxoDigestResponse {
            digest: aocl.try_get_leaf(request.leaf_index).await,
        })
    }

    async fn find_utxo_origin_call(
        &self,
        request: FindUtxoOriginRequest,
    ) -> RpcResult<FindUtxoOriginResponse> {
        let allowed_search_depth = if self.unrestricted {
            request.search_depth
        } else {
            Some(request.search_depth.unwrap_or(100).min(100))
        };

        let state = self.state.lock_guard().await;
        let block = state
            .chain
            .archival_state()
            .find_canonical_block_with_output(request.addition_record.into(), allowed_search_depth)
            .await;

        Ok(FindUtxoOriginResponse {
            block: block.map(|block| block.hash()),
        })
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
    use crate::application::json_rpc::server::rpc::RpcServer;
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

        RpcServer::new(global_state_lock, None)
    }

    #[apply(shared_tokio_runtime)]
    async fn network_is_consistent() {
        let rpc_server = test_rpc_server().await;
        assert_eq!("main", rpc_server.network().await.unwrap().network);
    }

    #[apply(shared_tokio_runtime)]
    async fn height_is_correct() {
        let rpc_server = test_rpc_server().await;
        assert_eq!(bfe!(0), rpc_server.height().await.unwrap().height);
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

        let digest = rpc_server.tip_digest().await.unwrap().digest;
        assert_eq!(block1.hash(), digest);

        let block = rpc_server.tip().await.unwrap().block;
        let proof = rpc_server.tip_proof().await.unwrap().proof;
        assert_eq!(block.proof, proof);

        let kernel = rpc_server.tip_kernel().await.unwrap().kernel;
        let header = rpc_server.tip_header().await.unwrap().header;
        assert_eq!(kernel.header, header);

        let body = rpc_server.tip_body().await.unwrap().body;
        let transaction_kernel = rpc_server.tip_transaction_kernel().await.unwrap().kernel;
        assert_eq!(body.transaction_kernel, transaction_kernel);

        let announcements = rpc_server.tip_announcements().await.unwrap().announcements;
        assert_eq!(transaction_kernel.announcements, announcements);
    }

    #[test_strategy::proptest(async = "tokio", cases = 5)]
    async fn get_block_calls_are_consistent(
        #[strategy(0usize..8)] _num_announcements: usize,
        #[strategy(txkernel::with_lengths(0, 2, #_num_announcements, true))]
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
                .unwrap()
                .digest
                .expect("digest should be available");
            let selector = RpcBlockSelector::Digest(digest);

            let block = rpc_server
                .get_block(selector)
                .await
                .unwrap()
                .block
                .expect("block should exist");
            let proof = rpc_server
                .get_block_proof(selector)
                .await
                .unwrap()
                .proof
                .expect("proof should exist");
            assert_eq!(block.proof, proof);

            let kernel = rpc_server
                .get_block_kernel(selector)
                .await
                .unwrap()
                .kernel
                .expect("kernel should exist");
            let header = rpc_server
                .get_block_header(selector)
                .await
                .unwrap()
                .header
                .expect("header should exist");
            assert_eq!(kernel.header, header);
            assert_eq!(header.height, height.into());

            let body = rpc_server
                .get_block_body(selector)
                .await
                .unwrap()
                .body
                .expect("body should exist");
            let transaction_kernel = rpc_server
                .get_block_transaction_kernel(selector)
                .await
                .unwrap()
                .kernel
                .expect("transaction kernel should exist");
            assert_eq!(body.transaction_kernel, transaction_kernel);

            let announcements = rpc_server
                .get_block_announcements(selector)
                .await
                .unwrap()
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
            .unwrap()
            .digests;

        let expected: HashSet<_> = [block1.hash(), block2.hash()].into();
        let actual: HashSet<_> = digests.into_iter().collect();

        assert_eq!(expected, actual);
    }

    #[apply(shared_tokio_runtime)]
    async fn is_block_canonical_consistency() {
        let rpc_server = test_rpc_server().await;

        // Test genesis block is canonical
        let genesis_digest = rpc_server.tip_digest().await.unwrap().digest;
        let is_genesis_canonical = rpc_server
            .is_block_canonical(genesis_digest)
            .await
            .unwrap()
            .canonical;
        assert!(is_genesis_canonical, "Genesis block should be canonical");

        // Test non-existent block is not canonical
        let fake_digest = Digest::default();
        let is_fake_canonical = rpc_server
            .is_block_canonical(fake_digest)
            .await
            .unwrap()
            .canonical;
        assert!(
            !is_fake_canonical,
            "Non-existent block should not be canonical"
        );
    }

    #[test_strategy::proptest(async = "tokio", cases = 5)]
    async fn utxo_calls_are_consistent(
        #[strategy(0usize..8)] _num_outputs: usize,
        #[strategy(txkernel::with_lengths(0usize, #_num_outputs, 0usize, true))]
        transaction_kernel: crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel,
    ) {
        let mut rpc_server = test_rpc_server().await;

        // Before new block check size of aocl leaves so we can know exact index of new outputs
        let num_aocl_leaves = rpc_server
            .state
            .lock_guard()
            .await
            .chain
            .archival_state()
            .archival_mutator_set
            .ams()
            .aocl
            .num_leafs()
            .await;

        let transaction = Transaction {
            kernel: transaction_kernel,
            proof: TransactionProof::invalid(),
        };
        let block = invalid_block_with_transaction(&Block::genesis(Network::Main), transaction);
        rpc_server.state.set_new_tip(block.clone()).await.unwrap();

        for (i, output) in block.body().transaction_kernel().outputs.iter().enumerate() {
            let utxo_index = num_aocl_leaves + i as u64;
            let digest_entry = rpc_server
                .get_utxo_digest(utxo_index)
                .await
                .expect("failed to get utxo digest");

            let digest = digest_entry.digest.expect("missing digest for utxo output");

            assert_eq!(
                output.canonical_commitment, digest,
                "canonical commitment mismatch for utxo at index {utxo_index}"
            );

            // Check origin of UTXO
            let origin_response = rpc_server
                .find_utxo_origin((*output).into(), None)
                .await
                .expect("find_utxo_origin RPC failed");

            let origin_block = origin_response.block;
            assert!(
                origin_block.is_some(),
                "expected origin block for utxo {utxo_index}"
            );
            assert_eq!(
                origin_block.unwrap(),
                block.hash(),
                "origin block mismatch for utxo {utxo_index}"
            );
        }
    }
}
