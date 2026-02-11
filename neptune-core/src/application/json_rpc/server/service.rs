use std::collections::HashSet;
use std::time::Duration;

use async_trait::async_trait;
use itertools::Itertools;
use tokio::sync::oneshot;
use tracing::debug;

use crate::api::export::AdditionRecord;
use crate::api::export::ReceivingAddress;
use crate::api::export::Timestamp;
use crate::api::export::Transaction;
use crate::api::export::TransactionProof;
use crate::application::json_rpc::core::api::rpc::*;
use crate::application::json_rpc::core::model::block::header::TransactionKernelWithPriority;
use crate::application::json_rpc::core::model::block::RpcBlock;
use crate::application::json_rpc::core::model::message::*;
use crate::application::json_rpc::core::model::mining::template::RpcBlockTemplate;
use crate::application::json_rpc::core::model::mining::template::RpcBlockTemplateMetadata;
use crate::application::json_rpc::core::model::wallet::mutator_set::RpcMsMembershipSnapshot;
use crate::application::json_rpc::core::model::wallet::adapter;
use crate::application::json_rpc::core::model::json::JsonError;
use crate::application::json_rpc::server::rpc::RpcServer;
use crate::application::loops::channel::RPCServerToMain;
use crate::application::database::storage::storage_vec::traits::StorageVecBase;
use crate::application::database::storage::storage_vec::traits::StorageVecStream;
use crate::twenty_first::prelude::{Digest, Mmr, Tip5};
use crate::protocol::consensus::block::block_selector::BlockSelector;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::block::FUTUREDATING_LIMIT;
use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;

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
            height: state.chain.light_state().kernel.header.height,
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
                .map(|a| a.clone().into())
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
                        .map(|a| a.clone().into())
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

    async fn are_bloom_indices_set_call(
        &self,
        request: AreBloomIndicesSetRequest,
    ) -> RpcResult<AreBloomIndicesSetResponse> {
        Ok(AreBloomIndicesSetResponse {
            are_set: self
                .state
                .lock_guard()
                .await
                .chain
                .archival_state()
                .archival_mutator_set
                .ams()
                .absolute_index_set_was_applied(request.absolute_index_set)
                .await,
        })
    }

    async fn circulating_supply_call(
        &self,
        _request: CirculatingSupplyRequest,
    ) -> RpcResult<CirculatingSupplyResponse> {
        Ok(CirculatingSupplyResponse {
            amount: self
                .state
                .lock_guard()
                .await
                .chain
                .archival_state()
                .circulating_supply()
                .await
                .into(),
        })
    }

    async fn max_supply_call(&self, _request: MaxSupplyRequest) -> RpcResult<MaxSupplyResponse> {
        Ok(MaxSupplyResponse {
            amount: self
                .state
                .lock_guard()
                .await
                .chain
                .archival_state()
                .max_supply()
                .await
                .into(),
        })
    }

    async fn burned_supply_call(
        &self,
        _request: BurnedSupplyRequest,
    ) -> RpcResult<BurnedSupplyResponse> {
        Ok(BurnedSupplyResponse {
            amount: self
                .state
                .lock_guard()
                .await
                .chain
                .archival_state()
                .burned_supply()
                .await
                .into(),
        })
    }

    async fn get_blocks_call(&self, request: GetBlocksRequest) -> RpcResult<GetBlocksResponse> {
        // Reverse get_blocks is not supported yet.
        // Might be reconsidered after "succinctness" as it might give it a purpose.
        if request.to_height < request.from_height {
            return Ok(GetBlocksResponse { blocks: Vec::new() });
        }

        let max_blocks = if self.unrestricted { usize::MAX } else { 100 };

        let state = self.state.lock_guard().await;
        let mut blocks = Vec::new();
        let mut height = request.from_height;

        while height <= request.to_height && blocks.len() < max_blocks {
            let block_selector = BlockSelector::Height(height);
            let Some(digest) = block_selector.as_digest(&state).await else {
                break;
            };
            let Some(block) = state
                .chain
                .archival_state()
                .get_block(digest)
                .await
                .unwrap()
            else {
                break;
            };

            blocks.push((&block).into());
            height = height.next();
        }

        Ok(GetBlocksResponse { blocks })
    }

    async fn restore_membership_proof_call(
        &self,
        request: RestoreMembershipProofRequest,
    ) -> RpcResult<RestoreMembershipProofResponse> {
        if request.absolute_index_sets.len() > 256 && !self.unrestricted {
            return Err(RpcError::RestoreMembershipProof(
                RestoreMembershipProofError::ExceedsAllowed,
            ));
        }

        let state = self.state.lock_guard().await;
        let ams = state.chain.archival_state().archival_mutator_set.ams();
        let mut membership_proofs = Vec::with_capacity(request.absolute_index_sets.len());

        for (index, set) in request.absolute_index_sets.into_iter().enumerate() {
            match ams.restore_membership_proof_privacy_preserving(set).await {
                Ok(msmp) => membership_proofs.push(msmp.into()),
                Err(err) => {
                    debug!("Failed to restore MSMP for {index}: {err}");
                    return Err(RpcError::RestoreMembershipProof(
                        RestoreMembershipProofError::Failed(index),
                    ));
                }
            }
        }

        let current_tip = state.chain.light_state();
        let tip_mutator_set = current_tip
            .mutator_set_accumulator_after()
            .expect("Tip must have valid MSA after");
        let snapshot = RpcMsMembershipSnapshot {
            synced_height: current_tip.header().height.into(),
            synced_hash: current_tip.hash(),
            membership_proofs,
            synced_mutator_set: (&tip_mutator_set).into(),
        };

        Ok(RestoreMembershipProofResponse { snapshot })
    }

    async fn submit_transaction_call(
        &self,
        request: SubmitTransactionRequest,
    ) -> RpcResult<SubmitTransactionResponse> {
        let transaction: Transaction = request.transaction.into();
        let network = self.state.cli().network;
        let consensus_rule_set = self.state.lock_guard().await.consensus_rule_set();

        if !transaction.is_valid(network, consensus_rule_set).await {
            return Err(RpcError::SubmitTransaction(
                SubmitTransactionError::InvalidTransaction,
            ));
        }

        if transaction.kernel.coinbase.is_some() {
            return Err(RpcError::SubmitTransaction(
                SubmitTransactionError::CoinbaseTransaction,
            ));
        }

        if transaction.kernel.fee.is_negative() {
            return Err(RpcError::SubmitTransaction(
                SubmitTransactionError::FeeNegative,
            ));
        }

        let timestamp = transaction.kernel.timestamp;
        let now = Timestamp::now();
        if timestamp >= now + FUTUREDATING_LIMIT {
            return Err(RpcError::SubmitTransaction(
                SubmitTransactionError::FutureDated,
            ));
        }

        let msa = self
            .state
            .lock_guard()
            .await
            .chain
            .light_state()
            .mutator_set_accumulator_after()
            .expect("Tip block must have mutator set");
        if !transaction.is_confirmable_relative_to(&msa) {
            return Err(RpcError::SubmitTransaction(
                SubmitTransactionError::NotConfirmable,
            ));
        }

        let response = self
            .to_main_tx
            .send(RPCServerToMain::SubmitTx(Box::new(transaction)))
            .await;

        Ok(SubmitTransactionResponse {
            success: response.is_ok(),
        })
    }

    async fn rescan_announced_call(
        &self,
        request: RescanAnnouncedRequest,
    ) -> RpcResult<RescanAnnouncedResponse> {
        if request.first > request.last {
            return Err(RpcError::BlockRangeError);
        }

        if !self.state.cli().utxo_index {
            return Err(RpcError::UtxoIndexNotPresent);
        }

        let all_keys = self
            .state
            .lock_guard()
            .await
            .wallet_state
            .get_all_known_spending_keys()
            .collect_vec();

        let _ = self
            .to_main_tx
            .send(RPCServerToMain::RescanAnnounced {
                first: request.first,
                last: request.last,
                keys: all_keys,
            })
            .await;

        Ok(RescanAnnouncedResponse {})
    }

    async fn rescan_expected_call(
        &self,
        request: RescanExpectedRequest,
    ) -> RpcResult<RescanExpectedResponse> {
        if request.first > request.last {
            return Err(RpcError::BlockRangeError);
        }

        let _ = self
            .to_main_tx
            .send(RPCServerToMain::RescanExpected {
                first: request.first,
                last: request.last,
            })
            .await;

        Ok(RescanExpectedResponse {})
    }

    async fn rescan_outgoing_call(
        &self,
        request: RescanOutgoingRequest,
    ) -> RpcResult<RescanOutgoingResponse> {
        if request.first > request.last {
            return Err(RpcError::BlockRangeError);
        }

        if !self.state.cli().utxo_index {
            return Err(RpcError::UtxoIndexNotPresent);
        }

        let _ = self
            .to_main_tx
            .send(RPCServerToMain::RescanOutgoing {
                first: request.first,
                last: request.last,
            })
            .await;

        Ok(RescanOutgoingResponse {})
    }

    async fn rescan_guesser_rewards_call(
        &self,
        request: RescanGuesserRewardsRequest,
    ) -> RpcResult<RescanGuesserRewardsResponse> {
        if request.first > request.last {
            return Err(RpcError::BlockRangeError);
        }

        let _ = self
            .to_main_tx
            .send(RPCServerToMain::RescanGuesserRewards {
                first: request.first,
                last: request.last,
            })
            .await;

        Ok(RescanGuesserRewardsResponse {})
    }

    async fn get_block_template_call(
        &self,
        request: GetBlockTemplateRequest,
    ) -> RpcResult<GetBlockTemplateResponse> {
        let (maybe_proposal, tip) = {
            let global_state = self.state.lock_guard().await;
            let proposal = global_state.mining_state.block_proposal.map(|p| p.clone());
            let tip = *global_state.chain.light_state().header();

            (proposal, tip)
        };

        let Some(mut proposal) = maybe_proposal else {
            return Ok(GetBlockTemplateResponse { template: None });
        };

        let address =
            ReceivingAddress::from_bech32m(&request.guesser_address, self.state.cli().network)
                .map_err(|_| RpcError::InvalidAddress)?;
        proposal.set_header_guesser_address(address);

        let template = RpcBlockTemplate {
            block: RpcBlock::from(&proposal),
            metadata: RpcBlockTemplateMetadata::new(&proposal, tip.difficulty),
        };

        Ok(GetBlockTemplateResponse {
            template: Some(template),
        })
    }

    async fn submit_block_call(
        &self,
        request: SubmitBlockRequest,
    ) -> RpcResult<SubmitBlockResponse> {
        let mut template: Block = request.template.into();

        // Since block comes from external source, we need to check validity.
        let tip = self.state.lock_guard().await.chain.light_state().clone();
        if !template
            .is_valid(&tip, Timestamp::now(), self.state.cli().network)
            .await
        {
            return Err(RpcError::SubmitBlock(SubmitBlockError::InvalidBlock));
        }

        template.set_header_pow(request.pow.into());

        if !template.has_proof_of_work(self.state.cli().network, template.header()) {
            return Err(RpcError::SubmitBlock(SubmitBlockError::InsufficientWork));
        }

        // No time to waste! Inform main_loop!
        let solution = Box::new(template);
        let success = self
            .to_main_tx
            .send(RPCServerToMain::ProofOfWorkSolution(solution))
            .await
            .is_ok();

        Ok(SubmitBlockResponse { success })
    }

    async fn block_heights_by_flags_call(
        &self,
        request: BlockHeightsByFlagsRequest,
    ) -> RpcResult<BlockHeightsByFlagsResponse> {
        let announcement_flags: HashSet<_> = request.announcement_flags.into_iter().collect();
        let heights = self
            .state
            .lock_guard()
            .await
            .chain
            .archival_state()
            .utxo_index
            .as_ref()
            .expect("Utxo index namespace can only be active when UTXO index is present")
            .blocks_by_announcement_flags(&announcement_flags)
            .await;

        let block_heights = BlockHeightsByFlagsResponse {
            block_heights: heights.into_iter().collect(),
        };

        Ok(block_heights)
    }

    async fn block_heights_by_addition_records_call(
        &self,
        request: BlockHeightsByAdditionRecordsRequest,
    ) -> RpcResult<BlockHeightsByAdditionRecordsResponse> {
        let addition_records: HashSet<AdditionRecord> = request
            .addition_records
            .into_iter()
            .map(|x| x.into())
            .collect();

        let block_heights = self
            .state
            .lock_guard()
            .await
            .chain
            .archival_state()
            .addition_records_to_block_height(addition_records)
            .await
            .expect("Utxo index namespace can only be active when UTXO index is present");

        let block_heights = BlockHeightsByAdditionRecordsResponse {
            block_heights: block_heights.into_iter().collect(),
        };

        Ok(block_heights)
    }

    async fn block_heights_by_absolute_index_sets_call(
        &self,
        request: BlockHeightsByAbsoluteIndexSetsRequest,
    ) -> RpcResult<BlockHeightsByAbsoluteIndexSetsResponse> {
        let absolute_index_sets: HashSet<AbsoluteIndexSet> =
            request.absolute_index_sets.into_iter().collect();

        let block_heights = self
            .state
            .lock_guard()
            .await
            .chain
            .archival_state()
            .absolute_index_sets_to_block_heights(absolute_index_sets)
            .await
            .expect("Utxo index namespace can only be active when UTXO index is present");

        let block_heights = BlockHeightsByAbsoluteIndexSetsResponse {
            block_heights: block_heights.into_iter().collect(),
        };

        Ok(block_heights)
    }

    async fn transactions_call(&self, _: TransactionsRequest) -> RpcResult<TransactionsResponse> {
        let transactions = self
            .state
            .lock_guard()
            .await
            .mempool
            .fee_density_iter()
            .map(|(txkid, _)| txkid)
            .collect();

        Ok(TransactionsResponse { transactions })
    }

    async fn get_transaction_kernel_call(
        &self,
        request: GetTransactionKernelRequest,
    ) -> RpcResult<GetTransactionKernelResponse> {
        let transaction = self
            .state
            .lock_guard()
            .await
            .mempool
            .get(request.id)
            .cloned();

        Ok(GetTransactionKernelResponse {
            kernel: transaction.map(|t| (&t.kernel).into()),
        })
    }

    async fn get_transaction_proof_call(
        &self,
        request: GetTransactionProofRequest,
    ) -> RpcResult<GetTransactionProofResponse> {
        let transaction = self
            .state
            .lock_guard()
            .await
            .mempool
            .get(request.id)
            .cloned();

        Ok(GetTransactionProofResponse {
            proof: transaction.and_then(|t| match t.proof {
                // Proofs of witness-backed transactions shouldn't be exposed.
                TransactionProof::Witness(_) => None,
                other => Some(other.into()),
            }),
        })
    }

    async fn get_transactions_by_addition_records_call(
        &self,
        request: GetTransactionsByAdditionRecordsRequest,
    ) -> RpcResult<GetTransactionsByAdditionRecordsResponse> {
        let addition_records = request
            .addition_records
            .into_iter()
            .map(|x| x.into())
            .collect();
        let transactions = self
            .state
            .lock_guard()
            .await
            .mempool
            .with_matching_addition_records(&addition_records);

        let transactions = transactions
            .into_iter()
            .map(|(tx_kernel, queue_order)| {
                TransactionKernelWithPriority::new(
                    &tx_kernel,
                    queue_order.map(|order| {
                        u32::try_from(order)
                            .expect("Cannot have more than u32::MAX transactions in mempool")
                    }),
                )
            })
            .collect_vec();
        let transactions = GetTransactionsByAdditionRecordsResponse { transactions };

        Ok(transactions)
    }

    async fn get_transactions_by_absolute_index_sets_call(
        &self,
        request: GetTransactionsByAbsoluteIndexSetsRequest,
    ) -> RpcResult<GetTransactionsByAbsoluteIndexSetsResponse> {
        let absolute_index_sets = request.absolute_index_sets.into_iter().collect();
        let transactions = self
            .state
            .lock_guard()
            .await
            .mempool
            .with_matching_absolute_index_sets(&absolute_index_sets);

        let transactions = transactions
            .into_iter()
            .map(|(tx_kernel, queue_order)| {
                TransactionKernelWithPriority::new(
                    &tx_kernel,
                    queue_order.map(|order| {
                        u32::try_from(order)
                            .expect("Cannot have more than u32::MAX transactions in mempool")
                    }),
                )
            })
            .collect_vec();
        let transactions = GetTransactionsByAbsoluteIndexSetsResponse { transactions };

        Ok(transactions)
    }

    async fn best_transaction_for_next_block_call(
        &self,
        _: BestTransactionForNextBlockRequest,
    ) -> RpcResult<BestTransactionForNextBlockResponse> {
        let tx = self
            .state
            .lock_guard()
            .await
            .mempool
            .get_transactions_for_block_composition(usize::MAX, Some(1));
        let tx = tx.first();
        let tx = BestTransactionForNextBlockResponse {
            transaction: tx.map(|tx| (&tx.kernel).into()),
        };

        Ok(tx)
    }

    async fn ban_call(&self, request: BanRequest) -> RpcResult<BanResponse> {
        if !self.unrestricted {
            return Err(RpcError::RestrictedAccess);
        }

        let _ = self
            .to_main_tx
            .send(RPCServerToMain::Ban(request.address))
            .await;

        Ok(BanResponse {})
    }

    async fn unban_call(&self, request: UnbanRequest) -> RpcResult<UnbanResponse> {
        if !self.unrestricted {
            return Err(RpcError::RestrictedAccess);
        }

        let _ = self
            .to_main_tx
            .send(RPCServerToMain::Unban(request.address))
            .await;

        Ok(UnbanResponse {})
    }

    async fn unban_all_call(&self, _request: UnbanAllRequest) -> RpcResult<UnbanAllResponse> {
        if !self.unrestricted {
            return Err(RpcError::RestrictedAccess);
        }

        let _ = self.to_main_tx.send(RPCServerToMain::UnbanAll).await;

        Ok(UnbanAllResponse {})
    }

    async fn dial_call(&self, request: DialRequest) -> RpcResult<DialResponse> {
        if !self.unrestricted {
            return Err(RpcError::RestrictedAccess);
        }

        let _ = self
            .to_main_tx
            .send(RPCServerToMain::Dial(request.address))
            .await;

        Ok(DialResponse {})
    }

    async fn probe_nat_call(&self, _request: ProbeNatRequest) -> RpcResult<ProbeNatResponse> {
        if !self.unrestricted {
            return Err(RpcError::RestrictedAccess);
        }

        let _ = self.to_main_tx.send(RPCServerToMain::ProbeNat).await;

        Ok(ProbeNatResponse {})
    }

    async fn reset_relay_reservations_call(
        &self,
        _request: ResetRelayReservationsRequest,
    ) -> RpcResult<ResetRelayReservationsResponse> {
        if !self.unrestricted {
            return Err(RpcError::RestrictedAccess);
        }

        let _ = self
            .to_main_tx
            .send(RPCServerToMain::ResetRelayReservations)
            .await;

        Ok(ResetRelayReservationsResponse {})
    }

    async fn network_overview_call(
        &self,
        _request: NetworkOverviewRequest,
    ) -> RpcResult<NetworkOverviewResponse> {
        if !self.unrestricted {
            return Err(RpcError::RestrictedAccess);
        }

        // Create one-shot channel.
        let (tx, rx) = oneshot::channel();

        // Send one-shot channel to NetworkActor, via main loop.
        let _ = self
            .to_main_tx
            .send(RPCServerToMain::GetNetworkOverview(tx))
            .await;

        // Await receipt.
        let timeout_period = Duration::from_secs(1);
        match tokio::time::timeout(timeout_period, rx).await {
            Ok(Ok(network_overview)) => Ok(NetworkOverviewResponse { network_overview }),
            Ok(Err(_e)) => Err(RpcError::RxChannel),
            Err(_e) => Err(RpcError::Timeout(timeout_period)),
        }
    }

    async fn get_balance_call(&self, _request: GetBalanceRequest) -> RpcResult<GetBalanceResponse> {
        let state = self.state.lock_guard().await;
        let wallet_status = state.get_wallet_status_for_tip().await;
        let timestamp = Timestamp::now();
        let balance = wallet_status.available_confirmed(timestamp);

        Ok(GetBalanceResponse {
            balance: adapter::BalanceResponse {
                balance: balance.to_string(),
            },
        })
    }

    async fn generate_address_call(
        &self,
        _request: GenerateAddressRequest,
    ) -> RpcResult<GenerateAddressResponse> {
        use crate::api::export::KeyType;

        let mut state_lock = self.state.clone();
        let (spending_key, _new_counter) = {
            let mut state = state_lock.lock_guard_mut().await;
            let old_counter = state.wallet_state.spending_key_counter(KeyType::Generation);
            let spending_key = state
                .wallet_state
                .next_unused_spending_key(KeyType::Generation)
                .await;
            let new_counter = state.wallet_state.spending_key_counter(KeyType::Generation);
            tracing::debug!(
                "Generated new address: counter {} -> {}",
                old_counter,
                new_counter
            );
            (spending_key, new_counter)
        };
        
        let address = spending_key.to_address();

        let network = self.state.cli().network;
        let address_string = address.to_bech32m(network).map_err(|e| {
            RpcError::Server(JsonError::Custom {
                code: -32603,
                message: format!("Failed to encode address: {e}"),
                data: None,
            })
        })?;

        Ok(GenerateAddressResponse {
            address: adapter::GenerateAddressResponse {
                address: address_string,
            },
        })
    }

    async fn block_info_call(&self, request: BlockInfoRequest) -> RpcResult<BlockInfoResponse> {
        let state = self.state.lock_guard().await;
        let network = self.state.cli().network;

        let Some(block_digest) = request.selector.as_digest(&state).await else {
            return Ok(None);
        };

        let Some(block) = state
            .chain
            .archival_state()
            .get_block(block_digest)
            .await
            .unwrap()
        else {
            return Ok(None);
        };

        let header = block.header();
        let tx_kernel = block.body().transaction_kernel.clone();

        let mut inputs = Vec::new();
        for (n, rr) in tx_kernel.inputs.iter().enumerate() {
            let index_set = &rr.absolute_indices;
            if let Some((mutxo, _)) = state
                .wallet_state
                .wallet_db
                .monitored_utxo_by_index_set(index_set)
                .await
            {
                let (_, _, confirmed_height) = mutxo.confirmed_in_block;

                inputs.push(BlockInfoInput {
                    n,
                    leaf_index: mutxo.aocl_leaf_index,
                    utxo_digest: mutxo.addition_record().canonical_commitment,
                    sender_randomness: mutxo.sender_randomness,
                    confirmed_height,
                    utxo: ApiUtxo::new(&mutxo.utxo),
                });
            }
        }

        // Get parent block to find starting AOCL index for outputs
        let parent_digest = header.prev_block_digest;
        let parent_aocl_num_leafs = if let Some(parent_block) = state
            .chain
            .archival_state()
            .get_block(parent_digest)
            .await
            .unwrap()
        {
            parent_block
                .mutator_set_accumulator_after()
                .map(|msa| msa.aocl.num_leafs())
                .unwrap_or(0)
        } else {
            0
        };

        // Collect known outputs from wallet
        let known_outputs: std::collections::HashMap<Digest, _> = state
            .wallet_state
            .scan_for_utxos_announced_to_known_keys(&tx_kernel)
            .map(|incoming| (incoming.addition_record().canonical_commitment, incoming))
            .collect();

        // Show all outputs, with wallet info when known
        let outputs: Vec<BlockInfoOutput> = tx_kernel
            .outputs
            .iter()
            .enumerate()
            .map(|(n, ar)| {
                let leaf_index = parent_aocl_num_leafs + n as u64;
                let utxo_digest = ar.canonical_commitment;

                if let Some(incoming) = known_outputs.get(&utxo_digest) {
                    let spending_key = state
                        .wallet_state
                        .find_spending_key_for_utxo(&incoming.utxo);
                    let receiving_address = spending_key
                        .as_ref()
                        .and_then(|key| key.to_address().to_bech32m(network).ok());
                    let receiver_identifier = spending_key
                        .as_ref()
                        .map(|key| key.receiver_identifier().value());

                    BlockInfoOutput {
                        n,
                        leaf_index,
                        utxo_digest,
                        sender_randomness: Some(incoming.sender_randomness),
                        receiving_address,
                        receiver_digest: Some(incoming.receiver_preimage),
                        receiver_identifier,
                        utxo: Some(ApiUtxo::new(&incoming.utxo)),
                    }
                } else {
                    BlockInfoOutput {
                        n,
                        leaf_index,
                        utxo_digest,
                        sender_randomness: None,
                        receiving_address: None,
                        receiver_digest: None,
                        receiver_identifier: None,
                        utxo: None,
                    }
                }
            })
            .collect();

        Ok(Some(BlockInfo {
            height: header.height,
            digest: block.hash(),
            timestamp: header.timestamp,
            difficulty: header.difficulty,
            size: block.size(),
            fee: tx_kernel.fee.to_string(),
            inputs,
            outputs,
        }))
    }

    async fn send_tx_call(&self, request: SendTxRequest) -> RpcResult<SendTxResponse> {
        use crate::api::tx_initiation::builder::tx_output_list_builder::OutputFormat;
        use crate::api::tx_initiation::initiator::TransactionInitiator;
        use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
        use crate::state::wallet::address::ReceivingAddress;
        use crate::state::wallet::change_policy::ChangePolicy;
        use crate::state::wallet::utxo_notification::UtxoNotificationMedium;
        use crate::api::export::KeyType;

        let Ok(valid_amount) = NativeCurrencyAmount::coins_from_str(&request.amount) else {
            return Err(RpcError::Server(JsonError::Custom {
                code: -32602,
                message: "Invalid amount format".to_string(),
                data: None,
            }));
        };

        let Ok(valid_fee) = NativeCurrencyAmount::coins_from_str(&request.fee) else {
            return Err(RpcError::Server(JsonError::Custom {
                code: -32602,
                message: "Invalid fee format".to_string(),
                data: None,
            }));
        };

        let network = self.state.cli().network;
        let Ok(to_address) = ReceivingAddress::from_bech32m(&request.to_address, network) else {
            return Err(RpcError::Server(JsonError::Custom {
                code: -32602,
                message: "Invalid address format".to_string(),
                data: None,
            }));
        };

        let outputs: Vec<OutputFormat> = vec![OutputFormat::AddressAndAmountAndMedium(
            to_address,
            valid_amount,
            UtxoNotificationMedium::OnChain,
        )];

        let change_policy = ChangePolicy::recover_to_next_unused_key(
            KeyType::Generation,
            UtxoNotificationMedium::OnChain,
        );

        let mut tx_initiator: TransactionInitiator = self.state.clone().into();
        let resp = tx_initiator
            .send(
                outputs,
                change_policy,
                valid_fee,
                Timestamp::now(),
                request.max_inputs,
            )
            .await
            .map_err(|e| {
                RpcError::Server(JsonError::Custom {
                    code: -32000,
                    message: format!("Failed to send transaction: {e}"),
                    data: None,
                })
            })?;

        let timestamp = resp.details().timestamp;
        let tip_when_sent = self.state.lock_guard().await.chain.light_state().hash();

        let inputs: Vec<SendTxInput> = resp
            .details()
            .tx_inputs
            .iter()
            .map(|input| SendTxInput {
                leaf_index: input.mutator_set_mp().aocl_leaf_index,
                utxo_digest: input.addition_record().canonical_commitment,
                utxo: SendTxUtxo {
                    lock_script_hash: input.utxo.lock_script_hash(),
                    amount: input.utxo.get_native_currency_amount().to_string(),
                },
            })
            .collect();

        let outputs: Vec<SendTxOutput> = resp
            .details()
            .tx_outputs
            .iter()
            .map(|output| SendTxOutput {
                utxo: SendTxUtxo {
                    lock_script_hash: output.utxo().lock_script_hash(),
                    amount: output.utxo().get_native_currency_amount().to_string(),
                },
                utxo_digest: output.addition_record().canonical_commitment,
                sender_randomness: output.sender_randomness(),
                is_owned: output.is_owned(),
                is_change: output.is_change(),
            })
            .collect();

        Ok(SendTxResponse {
            timestamp,
            tip_when_sent,
            inputs,
            outputs,
        })
    }

    async fn validate_address_call(
        &self,
        request: ValidateAddressRequest,
    ) -> RpcResult<ValidateAddressResponse> {
        use crate::state::wallet::address::ReceivingAddress;

        let network = self.state.cli().network;
        let parsed = ReceivingAddress::from_bech32m(&request.address_string, network).ok();

        match parsed {
            Some(addr) => {
                let address = addr.to_bech32m(network).ok();
                let address_type = Some(match &addr {
                    ReceivingAddress::Generation(_) => "generation".to_string(),
                    ReceivingAddress::Symmetric(_) => "symmetric".to_string(),
                });
                let receiver_identifier = Some(addr.receiver_identifier().value());

                Ok(ValidateAddressResponse {
                    address,
                    address_type,
                    receiver_identifier,
                    base_address: None,
                })
            }
            None => Ok(ValidateAddressResponse {
                address: None,
                address_type: None,
                receiver_identifier: None,
                base_address: None,
            }),
        }
    }

    async fn validate_amount_call(
        &self,
        request: ValidateAmountRequest,
    ) -> RpcResult<ValidateAmountResponse> {
        use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

        let amount = NativeCurrencyAmount::coins_from_str(&request.amount_string)
            .ok()
            .map(|amt| amt.to_string());

        Ok(ValidateAmountResponse {
            amount: adapter::ValidateAmountResponse {
                amount: amount,
            },
        })
    }

    async fn unspent_utxos_call(
        &self,
        request: UnspentUtxosRequest,
    ) -> RpcResult<UnspentUtxosResponse> {
        use futures::StreamExt;

        let state = self.state.lock_guard().await;
        let wallet_status = state.get_wallet_status_for_tip().await;
        let timestamp = Timestamp::now();

        let recent_tips: HashSet<Digest> = if request.exclude_recent_blocks > 0 && state.chain.is_archival_node() {
            let current_tip = state.chain.light_state().hash();
            let mut tips = HashSet::new();
            tips.insert(current_tip);

            let ancestors = state
                .chain
                .archival_state()
                .get_ancestor_block_digests(current_tip, request.exclude_recent_blocks)
                .await;
            tips.extend(ancestors);
            tips
        } else {
            HashSet::new()
        };

        let excluded_aocl_indices: HashSet<u64> = if !recent_tips.is_empty() {
            let sent_txs = state.wallet_state.wallet_db.sent_transactions();
            let len = sent_txs.len().await;
            let stream = sent_txs.stream_many_values((0..len).rev().take(1000));
            let mut stream = Box::pin(stream);

            let mut indices = HashSet::new();
            while let Some(sent_tx) = stream.next().await {
                // Only filter UTXOs from transactions sent within recent blocks
                if recent_tips.contains(&sent_tx.tip_when_sent) {
                    for (aocl_index, _utxo) in &sent_tx.tx_inputs {
                        indices.insert(*aocl_index);
                    }
                }
            }
            indices
        } else {
            HashSet::new()
        };

        let mut utxos = Vec::new();
        for (wse, _msmp) in &wallet_status.synced_unspent {
            // Only include spendable UTXOs (not timelocked)
            if !wse.utxo.can_spend_at(timestamp) {
                continue;
            }

            // Exclude UTXOs from recent sent transactions
            if excluded_aocl_indices.contains(&wse.aocl_leaf_index) {
                continue;
            }

            let utxo = UnspentUtxo {
                leaf_index: wse.aocl_leaf_index,
                lock_script_hash: wse.utxo.lock_script_hash(),
                amount: wse.utxo.get_native_currency_amount().to_string(),
            };
            utxos.push(utxo);
        }

        Ok(utxos)
    }

    async fn history_call(&self, request: HistoryRequest) -> RpcResult<HistoryResponse> {
        use futures::StreamExt;

        let state = self.state.lock_guard().await;
        let network = self.state.cli().network;

        let query_lock_script_hash = request
            .receiving_address
            .as_ref()
            .and_then(|addr| ReceivingAddress::from_bech32m(addr, network).ok())
            .map(|addr| addr.lock_script_hash());

        let tip_digest = state.chain.light_state().hash();
        let aocl = &state.chain.archival_state().archival_mutator_set.ams().aocl;
        let num_leafs = aocl.num_leafs().await;
        let current_msa = state
            .chain
            .light_state()
            .mutator_set_accumulator_after()
            .expect("block from state must have mutator set after");

        let monitored_utxos = state.wallet_state.wallet_db.monitored_utxos();
        let stream = monitored_utxos.stream_values().await;
        futures::pin_mut!(stream);

        let mut history_rows = Vec::new();

        while let Some(mutxo) = stream.next().await {
            let Some(msmp) = mutxo.membership_proof_ref_for_block(tip_digest) else {
                continue;
            };

            let leaf_index = mutxo.aocl_leaf_index;
            let lock_script_hash = mutxo.utxo.lock_script_hash();
            let (block_digest, timestamp, confirmed_height) = mutxo.confirmed_in_block;

            let utxo_digest = if leaf_index > 0 && leaf_index < num_leafs {
                Some(aocl.get_leaf_async(leaf_index).await)
            } else {
                None
            };

            let spent_height = mutxo.spent_in_block.and_then(|(_, _, h)| {
                let is_spent = !current_msa.verify(Tip5::hash(&mutxo.utxo), msmp);
                is_spent.then_some(h)
            });

            let matches = request.leaf_index.is_none_or(|q| leaf_index == q)
                && request.utxo_digest.is_none_or(|q| utxo_digest == Some(q))
                && query_lock_script_hash.is_none_or(|q| lock_script_hash == q)
                && request
                    .sender_randomness
                    .is_none_or(|q| msmp.sender_randomness == q)
                && request
                    .confirmed_height
                    .is_none_or(|q| confirmed_height == q)
                && request.spent_height.is_none_or(|q| spent_height == Some(q));

            if !matches {
                continue;
            }

            let receiving_address = state
                .wallet_state
                .get_all_known_addressable_spending_keys()
                .find(|k| k.lock_script_hash() == lock_script_hash)
                .and_then(|key| key.to_address().to_bech32m(network).ok());

            history_rows.push(History {
                leaf_index,
                utxo_digest,
                sender_randomness: msmp.sender_randomness,
                digest: block_digest,
                confirmed_height,
                spent_height,
                timestamp,
                receiving_address,
                utxo: ApiUtxo::new(&mutxo.utxo),
            });
        }

        Ok(history_rows)
    }

    async fn sent_transaction_call(
        &self,
        request: SentTransactionRequest,
    ) -> RpcResult<SentTransactionResponse> {
        use futures::StreamExt;

        let state = self.state.lock_guard().await;

        let aocl = &state.chain.archival_state().archival_mutator_set.ams().aocl;
        let num_leafs = aocl.num_leafs().await;

        let matches_filter = |tx: &crate::state::wallet::sent_transaction::SentTransaction| {
            request
                .sender_randomness
                .is_none_or(|q| tx.tx_outputs.iter().any(|o| o.sender_randomness() == q))
                && request
                    .receiver_digest
                    .is_none_or(|q| tx.tx_outputs.iter().any(|o| o.receiver_digest() == q))
                && request.lock_script_hash.is_none_or(|q| {
                    tx.tx_outputs
                        .iter()
                        .any(|o| o.utxo().lock_script_hash() == q)
                })
                && request.utxo_digest.is_none_or(|q| {
                    tx.tx_outputs
                        .iter()
                        .any(|o| o.addition_record().canonical_commitment == q)
                })
                && request.timestamp.is_none_or(|q| tx.timestamp == q)
        };

        let limit = request.limit.unwrap_or(100).min(1000) as usize;
        let page = request.page.unwrap_or(1);
        let offset = ((page.saturating_sub(1)) * limit as u64) as usize;

        let send_txs_db = state.wallet_state.wallet_db.sent_transactions();
        let stream = send_txs_db.stream_values().await;
        futures::pin_mut!(stream);

        let mut sent_txs = Vec::new();
        let mut i = 0;

        while let Some(tx) = stream.next().await {
            if !matches_filter(&tx) {
                continue;
            }

            i += 1;

            if i <= offset {
                continue;
            }

            if i > offset + limit {
                break;
            }

            let tx_outputs: Vec<SentTxOutput> = tx
                .tx_outputs
                .iter()
                .map(|o| SentTxOutput {
                    utxo: ApiUtxo::new(&o.utxo()),
                    utxo_digest: o.addition_record().canonical_commitment,
                    sender_randomness: o.sender_randomness(),
                    receiver_digest: o.receiver_digest(),
                })
                .collect();

            let tx_inputs: Vec<SentTxInput> =
                futures::future::join_all(tx.tx_inputs.iter().map(|(leaf_index, utxo)| async {
                    let utxo_digest = if *leaf_index > 0 && *leaf_index < num_leafs {
                        Some(aocl.get_leaf_async(*leaf_index).await)
                    } else {
                        None
                    };
                    SentTxInput {
                        leaf_index: *leaf_index,
                        utxo_digest,
                        utxo: ApiUtxo::new(utxo),
                    }
                }))
                .await;

            sent_txs.push(SentTxToRespResponse {
                tx_inputs,
                tx_outputs,
                fee: tx.fee.to_string(),
                timestamp: tx.timestamp,
                tip_when_sent: tx.tip_when_sent,
            });
        }

        Ok(sent_txs)
    }

    async fn count_sent_transactions_at_block_call(
        &self,
        request: CountSentTransactionsAtBlockRequest,
    ) -> RpcResult<CountSentTransactionsAtBlockResponse> {
        let state = self.state.lock_guard().await;

        let Some(digest) = request.block.as_digest(&state).await else {
            return Ok(CountSentTransactionsAtBlockResponse { count: 0 });
        };

        let count = state
            .wallet_state
            .count_sent_transactions_at_block(digest)
            .await;

        Ok(CountSentTransactionsAtBlockResponse { count })
    }

    async fn find_utxo_leaf_index_call(
        &self,
        request: FindUtxoLeafIndexRequest,
    ) -> RpcResult<FindUtxoLeafIndexResponse> {
        let state = self.state.lock_guard().await;

        // Check if utxo_digest is in mempool first
        let in_mempool = state.mempool.fee_density_iter().any(|(txid, _)| {
            state.mempool.get(txid).is_some_and(|tx| {
                tx.kernel
                    .outputs
                    .iter()
                    .any(|o| o.canonical_commitment == request.utxo_digest)
            })
        });

        if in_mempool {
            return Ok(FindUtxoLeafIndexResponse {
                leaf_index: None,
                mempool: true,
                block_height: None,
                block_digest: None,
            });
        }

        let aocl = &state.chain.archival_state().archival_mutator_set.ams().aocl;
        let num_leafs = aocl.num_leafs().await;

        let to_leaf_index = request.to_leaf_index.unwrap_or(num_leafs).min(num_leafs);
        let from_leaf_index = request.from_leaf_index.unwrap_or(0);

        let max_range: u64 = if self.unrestricted { u64::MAX } else { 10000 };
        let range = to_leaf_index.saturating_sub(from_leaf_index).min(max_range);
        let from_leaf_index = to_leaf_index.saturating_sub(range);

        match state
            .chain
            .archival_state()
            .find_utxo_leaf_index(request.utxo_digest, from_leaf_index, to_leaf_index)
            .await
        {
            Some((leaf_index, block_height, block_digest)) => Ok(FindUtxoLeafIndexResponse {
                leaf_index: Some(leaf_index),
                mempool: false,
                block_height: Some(block_height),
                block_digest: Some(block_digest),
            }),
            None => Ok(FindUtxoLeafIndexResponse {
                leaf_index: None,
                mempool: false,
                block_height: None,
                block_digest: None,
            }),
        }
    }

    async fn get_aocl_leaf_indices_call(
        &self,
        request: GetAoclLeafIndicesRequest,
    ) -> RpcResult<GetAoclLeafIndicesResponse> {
        let state = self.state.lock_guard().await;

        let utxo_index = state
            .chain
            .archival_state()
            .utxo_index
            .as_ref()
            .ok_or(RpcError::UtxoIndexNotPresent)?;

        let indices = utxo_index
            .get_aocl_leaf_indices(&request.commitments)
            .await;

        Ok(GetAoclLeafIndicesResponse { indices })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod tests {
    use std::collections::HashSet;

    use libp2p::Multiaddr;
    use macro_rules_attr::apply;
    use num_traits::Zero;
    use tasm_lib::prelude::Digest;
    use tasm_lib::prelude::Tip5;
    use tasm_lib::twenty_first::bfe;
    use tasm_lib::twenty_first::bfe_vec;

    use crate::api::export::Announcement;
    use crate::api::export::AnnouncementFlag;
    use crate::api::export::KeyType;
    use crate::api::export::NativeCurrencyAmount;
    use crate::api::export::Network;
    use crate::api::export::OutputFormat;
    use crate::api::export::Timestamp;
    use crate::api::export::TxProvingCapability;
    use crate::application::config::cli_args;
    use crate::application::json_rpc::core::api::rpc::RpcApi;
    use crate::application::json_rpc::core::api::rpc::RpcError;
    use crate::application::json_rpc::core::model::common::RpcBlockSelector;
    use crate::application::json_rpc::core::model::message::BlockHeightsByFlagsRequest;
    use crate::application::json_rpc::core::model::mining::template::RpcBlockTemplate;
    use crate::application::json_rpc::server::rpc::RpcServer;
    use crate::application::network::arbitrary::arb_multiaddr;
    use crate::protocol::consensus::block::block_height::BlockHeight;
    use crate::protocol::consensus::block::block_height::NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT;
    use crate::protocol::consensus::block::INITIAL_BLOCK_SUBSIDY;
    use crate::protocol::consensus::block::PREMINE_MAX_SIZE;
    use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
    use crate::protocol::consensus::transaction::Transaction;
    use crate::protocol::consensus::transaction::TransactionProof;
    use crate::state::mempool::upgrade_priority::UpgradePriority;
    use crate::state::mining::block_proposal::BlockProposal;
    use crate::state::transaction::tx_creation_config::TxCreationConfig;
    use crate::state::wallet::wallet_entropy::WalletEntropy;
    use crate::tests::shared::blocks::fake_valid_deterministic_successor;
    use crate::tests::shared::blocks::invalid_block_with_transaction;
    use crate::tests::shared::blocks::invalid_empty_block_with_announcements;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared::mock_tx::testrunning::make_plenty_mock_transaction_supported_by_primitive_witness;
    use crate::tests::shared::strategies::txkernel;
    use crate::tests::shared_tokio_runtime;
    use crate::BFieldElement;
    use crate::Block;

    async fn test_rpc_server_with_cli_args(cli: cli_args::Args) -> RpcServer {
        let global_state_lock =
            mock_genesis_global_state(2, WalletEntropy::new_random(), cli).await;

        RpcServer::new(global_state_lock, None)
    }

    pub async fn test_rpc_server() -> RpcServer {
        let mut cli = cli_args::Args::default_with_network(Network::Main);
        cli.tx_proving_capability = Some(TxProvingCapability::ProofCollection);
        test_rpc_server_with_cli_args(cli).await
    }

    #[apply(shared_tokio_runtime)]
    async fn network_is_consistent() {
        let rpc_server = test_rpc_server().await;
        assert_eq!("main", rpc_server.network().await.unwrap().network);
    }

    #[apply(shared_tokio_runtime)]
    async fn height_is_correct() {
        let rpc_server = test_rpc_server().await;
        assert_eq!(
            BlockHeight::genesis(),
            rpc_server.height().await.unwrap().height
        );
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
            assert_eq!(header.height, height);

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

    #[apply(shared_tokio_runtime)]
    async fn remote_wallets_behave_correctly() {
        let mut rpc_server = test_rpc_server().await;
        let network = rpc_server.state.cli().network;

        // Prepare a transaction to our wallet coming from devnet wallet.
        let mut devnet_node = mock_genesis_global_state(
            0,
            WalletEntropy::devnet_wallet(),
            rpc_server.state.cli().clone(),
        )
        .await;

        let rpc_address = rpc_server
            .state
            .api()
            .wallet()
            .next_receiving_address(KeyType::Generation)
            .await
            .unwrap();
        let mock_amount = NativeCurrencyAmount::coins_from_str("1").unwrap();
        let devnet_artifacts = devnet_node
            .api_mut()
            .tx_sender_mut()
            .send(
                vec![OutputFormat::AddressAndAmount(rpc_address, mock_amount)],
                Default::default(),
                mock_amount,
                network.launch_date() + Timestamp::months(3),
                None,
            )
            .await
            .unwrap();

        // Pass transaction into rpc_server network.
        let block_1 = invalid_block_with_transaction(
            &Block::genesis(network),
            devnet_artifacts.transaction().clone(),
        );
        rpc_server.state.set_new_tip(block_1.clone()).await.unwrap();

        // Fetch genesis and tip and ensure announcement (on tip) matches after de/serialization.
        let blocks = rpc_server
            .get_blocks(BlockHeight::genesis(), BlockHeight::genesis().next())
            .await
            .unwrap()
            .blocks;
        assert_eq!(blocks.len(), 2);

        let announcement: Announcement = blocks[1].kernel.body.transaction_kernel.announcements[0]
            .clone()
            .into();
        let expected_announcement = devnet_artifacts.details().announcements()[0].clone();
        assert_eq!(announcement, expected_announcement);

        // Try restoring MSMP thru RPC and ensure it matches the one maintained by our wallet.
        let msa = rpc_server
            .state
            .lock_guard()
            .await
            .chain
            .light_state()
            .mutator_set_accumulator_after()
            .unwrap();
        let wallet_status = rpc_server
            .state
            .lock_guard()
            .await
            .wallet_state
            .get_wallet_status(block_1.hash(), &msa)
            .await;

        let (utxo, msmp) = &wallet_status.synced_unspent[0];
        let item = Tip5::hash(&utxo.utxo);

        let msmp_snapshot = rpc_server
            .restore_membership_proof(vec![msmp.compute_indices(item)])
            .await
            .expect("restore to succeed")
            .snapshot;
        let extracted_msmp = msmp_snapshot.membership_proofs[0]
            .clone()
            .extract_ms_membership_proof(
                utxo.aocl_leaf_index,
                msmp.sender_randomness,
                msmp.receiver_preimage,
            )
            .unwrap();
        assert_eq!(msmp, &extracted_msmp);

        // Try submitting a valid transaction (ProofCollection) by RPC.
        let tx_creation_config = TxCreationConfig::default()
            .with_prover_capability(TxProvingCapability::ProofCollection);
        let artifacts = rpc_server
            .state
            .api()
            .tx_initiator_internal()
            .create_transaction(
                Default::default(),
                mock_amount,
                network.launch_date() + Timestamp::months(3) + Timestamp::minutes(3),
                tx_creation_config,
                ConsensusRuleSet::infer_from(network, block_1.header().height),
            )
            .await
            .unwrap();
        let rpc_transaction = artifacts.transaction().clone().into();
        let submit_tx_response = rpc_server
            .submit_transaction(rpc_transaction)
            .await
            .expect("submission to succeed");

        assert!(submit_tx_response.success);
    }

    #[apply(shared_tokio_runtime)]
    async fn mining_scenarios_validated_properly() {
        use crate::application::json_rpc::core::api::rpc::SubmitBlockError;

        let mut rpc_server = test_rpc_server().await;
        let network = rpc_server.state.cli().network;

        let genesis = Block::genesis(network);
        let block1 = fake_valid_deterministic_successor(&genesis, network).await;
        rpc_server
            .state
            .lock_mut(|x| {
                x.mining_state.block_proposal = BlockProposal::ForeignComposition(block1.clone())
            })
            .await;
        let guesser_address = rpc_server
            .state
            .lock_guard_mut()
            .await
            .wallet_state
            .next_unused_spending_key(KeyType::Generation)
            .await
            .to_address();

        let RpcBlockTemplate { block, metadata } = rpc_server
            .get_block_template(guesser_address.to_bech32m(network).unwrap())
            .await
            .unwrap()
            .template
            .unwrap();

        assert_eq!(
            rpc_server
                .submit_block(block.clone(), block.kernel.header.pow.clone())
                .await
                .unwrap_err(),
            RpcError::SubmitBlock(SubmitBlockError::InsufficientWork)
        );

        let solution = metadata.solve(ConsensusRuleSet::Reboot);
        assert!(
            rpc_server
                .submit_block(block.clone(), solution.clone())
                .await
                .unwrap()
                .success,
            "Node must accept valid new tip."
        );

        let mut bad_proposal = block;
        bad_proposal.proof = None;
        assert_eq!(
            rpc_server
                .submit_block(bad_proposal.clone(), solution)
                .await
                .unwrap_err(),
            RpcError::SubmitBlock(SubmitBlockError::InvalidBlock)
        );
    }

    #[test_strategy::proptest(async = "tokio", cases = 5)]
    async fn mempool_calls_are_consistent(
        #[strategy(0usize..10)] tx_count: usize,
        #[strategy(0usize..=#tx_count)] sp_count: usize,
    ) {
        let mut rpc_server = test_rpc_server().await;

        // Create some witness txs to be added into mempool.
        let mut txs = make_plenty_mock_transaction_supported_by_primitive_witness(tx_count);
        // Make some of txs SP-backed so we can test proof extraction.
        for txi in txs.iter_mut().take(sp_count) {
            txi.proof = TransactionProof::invalid();
        }

        // Insert transactions to mempool.
        for tx in &txs {
            rpc_server
                .state
                .lock_guard_mut()
                .await
                .mempool_insert(tx.clone(), UpgradePriority::Irrelevant)
                .await;
        }

        // Test mempool size matches what we are expecting.
        let mempool_txs = rpc_server.transactions().await.unwrap().transactions;
        assert_eq!(mempool_txs.len(), tx_count);

        for tx in txs {
            let id = tx.txid();

            // Test transaction kernel can be extracted and contents match.
            let kernel = rpc_server.get_transaction_kernel(id).await.unwrap().kernel;
            assert!(kernel.is_some());
            assert_eq!(tx.kernel, kernel.unwrap().into());

            // Test transaction proofs can be extracted and contents match.
            let proof = rpc_server.get_transaction_proof(id).await.unwrap().proof;
            match tx.proof {
                // Witness-backed transactions proofs cannot be exposed as it exposes private data.
                TransactionProof::Witness(_) => assert!(proof.is_none()),
                _ => {
                    assert!(proof.is_some());
                    assert_eq!(proof.unwrap(), tx.proof.into());
                }
            }
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn supply_methods_return_reasonable_results() {
        let rpc_server = test_rpc_server().await;
        let circulating_supply = rpc_server.circulating_supply().await.unwrap();
        let max_supply = rpc_server.max_supply().await.unwrap();
        let burned_supply = rpc_server.burned_supply().await.unwrap();

        let premine = PREMINE_MAX_SIZE;
        let claims_pool = INITIAL_BLOCK_SUBSIDY
            .scalar_mul(u32::try_from(NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT).unwrap());
        assert_eq!(premine + claims_pool, circulating_supply.amount.into());

        // equal up to tiny error
        assert!(NativeCurrencyAmount::coins(42_000_000) >= max_supply.amount.into());

        assert_eq!(NativeCurrencyAmount::zero(), burned_supply.amount.into());
    }

    #[apply(shared_tokio_runtime)]
    async fn block_heights_by_flag_empty() {
        let cli_args = cli_args::Args {
            utxo_index: true,
            network: Network::Main,
            ..Default::default()
        };
        let rpc_server = test_rpc_server_with_cli_args(cli_args).await;
        assert!(
            rpc_server
                .block_heights_by_flags_call(BlockHeightsByFlagsRequest {
                    announcement_flags: vec![],
                })
                .await
                .unwrap()
                .block_heights
                .is_empty(),
            "Response to empty request must be empty when no blocks are indexed"
        );

        let an_announcement_flag = AnnouncementFlag {
            flag: bfe!(0),
            receiver_id: bfe!(0),
        };
        assert!(
            rpc_server
                .block_heights_by_flags_call(BlockHeightsByFlagsRequest {
                    announcement_flags: vec![an_announcement_flag],
                })
                .await
                .unwrap()
                .block_heights
                .is_empty(),
            "Response to non-empty request must be empty when no blocks are indexed"
        );
    }

    #[apply(shared_tokio_runtime)]
    async fn block_heights_by_flag_with_match() {
        let cli_args = cli_args::Args {
            utxo_index: true,
            network: Network::Main,
            ..Default::default()
        };
        let mut rpc_server = test_rpc_server_with_cli_args(cli_args).await;
        let network = rpc_server.state.cli().network;
        let genesis = Block::genesis(network);
        let some_announcements = vec![
            Announcement::new(bfe_vec![4, 6, 7, 2]),
            Announcement::new(bfe_vec![4446, 4447, 7, 2]),
            Announcement::new(bfe_vec![1, 6, 7, 2]),
        ];
        let block1 = invalid_empty_block_with_announcements(&genesis, network, some_announcements);

        let with_match = vec![AnnouncementFlag {
            flag: bfe!(4446),
            receiver_id: bfe!(4447),
        }];
        assert!(rpc_server
            .block_heights_by_flags(with_match.clone())
            .await
            .unwrap()
            .block_heights
            .is_empty());

        rpc_server.state.set_new_tip(block1.clone()).await.unwrap();

        assert_eq!(
            vec![BlockHeight::from(1u64)],
            rpc_server
                .block_heights_by_flags(with_match)
                .await
                .unwrap()
                .block_heights
        );

        let no_match = vec![AnnouncementFlag {
            flag: bfe!(4446),
            receiver_id: bfe!(1_001),
        }];
        assert!(rpc_server
            .block_heights_by_flags(no_match)
            .await
            .unwrap()
            .block_heights
            .is_empty());
    }

    fn random_multiaddr() -> Multiaddr {
        let mut test_runner =
            proptest::test_runner::TestRunner::new(proptest::test_runner::Config::default());
        proptest::strategy::ValueTree::current(
            &proptest::prelude::Strategy::new_tree(&arb_multiaddr(), &mut test_runner).unwrap(),
        )
    }

    #[apply(shared_tokio_runtime)]
    async fn network_commands_do_not_crash() {
        // Network commands have an *indirect* effect on state. The main loop
        // receives messages from the RPC server and may modify state directly
        // or may pass on messages to the network actor or to the peer loop
        // which then modify state. These secondary effects are not in the
        // scope of this test module. For now it suffices to verify that the
        // network commands can be delivered without crashing.
        let mut rpc_server = test_rpc_server().await;
        rpc_server.unrestricted = true;

        let multiaddr = random_multiaddr();

        rpc_server.ban(multiaddr.clone()).await.unwrap();
        rpc_server.unban(multiaddr.clone()).await.unwrap();
        rpc_server.unban_all().await.unwrap();
        rpc_server.dial(multiaddr).await.unwrap();
        rpc_server.probe_nat().await.unwrap();
        rpc_server.reset_relay_reservations().await.unwrap();
        rpc_server.get_network_overview().await
            .expect_err("dummy main loop consumes and drops incoming messages including oneshot back-communication channel");
    }

    #[apply(shared_tokio_runtime)]
    async fn network_commands_require_unrestricted_access() {
        let rpc_server = test_rpc_server().await;

        let multiaddr = random_multiaddr();

        let err = RpcError::RestrictedAccess;
        assert_eq!(err, rpc_server.ban(multiaddr.clone()).await.unwrap_err());
        assert_eq!(err, rpc_server.unban(multiaddr.clone()).await.unwrap_err());
        assert_eq!(err, rpc_server.unban_all().await.unwrap_err());
        assert_eq!(err, rpc_server.dial(multiaddr).await.unwrap_err());
        assert_eq!(err, rpc_server.probe_nat().await.unwrap_err());
        assert_eq!(
            err,
            rpc_server.reset_relay_reservations().await.unwrap_err()
        );
        assert_eq!(err, rpc_server.get_network_overview().await.unwrap_err());
    }
}
