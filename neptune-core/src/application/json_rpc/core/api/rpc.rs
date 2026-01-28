use std::time::Duration;

use async_trait::async_trait;
use libp2p::Multiaddr;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldElement;
use thiserror::Error;

use crate::api::export::AnnouncementFlag;
use crate::application::json_rpc::core::model::block::header::RpcBlockHeight;
use crate::application::json_rpc::core::model::block::header::RpcBlockPow;
use crate::application::json_rpc::core::model::block::transaction_kernel::RpcAbsoluteIndexSet;
use crate::application::json_rpc::core::model::block::transaction_kernel::RpcAdditionRecord;
use crate::application::json_rpc::core::model::block::transaction_kernel::RpcTransactionKernelId;
use crate::application::json_rpc::core::model::block::RpcBlock;
use crate::application::json_rpc::core::model::common::RpcBlockSelector;
use crate::application::json_rpc::core::model::json::JsonError;
use crate::application::json_rpc::core::model::message::*;
use crate::application::json_rpc::core::model::wallet::transaction::RpcTransaction;

#[derive(Debug, Clone, Copy, Error, Eq, PartialEq, Serialize, Deserialize)]
pub enum RestoreMembershipProofError {
    #[error("Failed for index {0}")]
    Failed(usize),

    #[error("Exceeds the allowed limit")]
    ExceedsAllowed,
}

#[derive(Debug, Clone, Copy, Error, Eq, PartialEq, Serialize, Deserialize)]
pub enum SubmitTransactionError {
    #[error("Invalid transaction")]
    InvalidTransaction,

    #[error("Coinbase transactions are not allowed")]
    CoinbaseTransaction,

    #[error("Transaction fee is negative")]
    FeeNegative,

    #[error("Transaction is future-dated")]
    FutureDated,

    #[error("Transaction not confirmable relative to the mutator set")]
    NotConfirmable,
}

#[derive(Debug, Clone, Copy, Error, Eq, PartialEq, Serialize, Deserialize)]
pub enum SubmitBlockError {
    #[error("Invalid block")]
    InvalidBlock,

    #[error("The block's proof-of-work does not meet the required target")]
    InsufficientWork,
}

#[derive(Debug, Clone, Error, Eq, PartialEq, Serialize, Deserialize)]
pub enum RpcError {
    #[error("JSON-RPC server error: {0}")]
    Server(JsonError),

    // Call-specific errors
    #[error("Failed to restore membership proof: {0}")]
    RestoreMembershipProof(RestoreMembershipProofError),

    #[error("Failed to submit transaction: {0}")]
    SubmitTransaction(SubmitTransactionError),

    #[error("Failed to submit block: {0}")]
    SubmitBlock(SubmitBlockError),

    #[error("Invalid block range")]
    BlockRangeError,

    #[error("Endpoint requires UTXO index which is not present")]
    UtxoIndexNotPresent,

    // Common case errors
    #[error("Invalid address provided in arguments")]
    InvalidAddress,

    #[error("Access to this endpoint is restricted")]
    RestrictedAccess,

    // Application-level errors
    #[error("Internal response timed out: {0:?}.")]
    Timeout(Duration),

    #[error("Sender dropped while awaiting response.")]
    RxChannel,
}

pub type RpcResult<T> = Result<T, RpcError>;

#[async_trait]
pub trait RpcApi: Sync + Send {
    /* Node */

    async fn network(&self) -> RpcResult<NetworkResponse> {
        self.network_call(NetworkRequest {}).await
    }
    async fn network_call(&self, request: NetworkRequest) -> RpcResult<NetworkResponse>;

    /* Chain */

    async fn height(&self) -> RpcResult<HeightResponse> {
        self.height_call(HeightRequest {}).await
    }
    async fn height_call(&self, request: HeightRequest) -> RpcResult<HeightResponse>;

    async fn tip_digest(&self) -> RpcResult<TipDigestResponse> {
        self.tip_digest_call(TipDigestRequest {}).await
    }
    async fn tip_digest_call(&self, request: TipDigestRequest) -> RpcResult<TipDigestResponse>;

    async fn tip(&self) -> RpcResult<TipResponse> {
        self.tip_call(TipRequest {}).await
    }
    async fn tip_call(&self, request: TipRequest) -> RpcResult<TipResponse>;

    async fn tip_proof(&self) -> RpcResult<TipProofResponse> {
        self.tip_proof_call(TipProofRequest {}).await
    }
    async fn tip_proof_call(&self, request: TipProofRequest) -> RpcResult<TipProofResponse>;

    async fn tip_kernel(&self) -> RpcResult<TipKernelResponse> {
        self.tip_kernel_call(TipKernelRequest {}).await
    }
    async fn tip_kernel_call(&self, request: TipKernelRequest) -> RpcResult<TipKernelResponse>;

    async fn tip_header(&self) -> RpcResult<TipHeaderResponse> {
        self.tip_header_call(TipHeaderRequest {}).await
    }
    async fn tip_header_call(&self, request: TipHeaderRequest) -> RpcResult<TipHeaderResponse>;

    async fn tip_body(&self) -> RpcResult<TipBodyResponse> {
        self.tip_body_call(TipBodyRequest {}).await
    }
    async fn tip_body_call(&self, request: TipBodyRequest) -> RpcResult<TipBodyResponse>;

    async fn tip_transaction_kernel(&self) -> RpcResult<TipTransactionKernelResponse> {
        self.tip_transaction_kernel_call(TipTransactionKernelRequest {})
            .await
    }
    async fn tip_transaction_kernel_call(
        &self,
        request: TipTransactionKernelRequest,
    ) -> RpcResult<TipTransactionKernelResponse>;

    async fn tip_announcements(&self) -> RpcResult<TipAnnouncementsResponse> {
        self.tip_announcements_call(TipAnnouncementsRequest {})
            .await
    }
    async fn tip_announcements_call(
        &self,
        request: TipAnnouncementsRequest,
    ) -> RpcResult<TipAnnouncementsResponse>;

    /* Archival */

    async fn get_block_digests(&self, height: BFieldElement) -> RpcResult<GetBlockDigestsResponse> {
        self.get_block_digests_call(GetBlockDigestsRequest { height })
            .await
    }
    async fn get_block_digests_call(
        &self,
        request: GetBlockDigestsRequest,
    ) -> RpcResult<GetBlockDigestsResponse>;

    async fn get_block_digest(
        &self,
        selector: RpcBlockSelector,
    ) -> RpcResult<GetBlockDigestResponse> {
        self.get_block_digest_call(GetBlockDigestRequest { selector })
            .await
    }
    async fn get_block_digest_call(
        &self,
        request: GetBlockDigestRequest,
    ) -> RpcResult<GetBlockDigestResponse>;

    async fn get_block(&self, selector: RpcBlockSelector) -> RpcResult<GetBlockResponse> {
        self.get_block_call(GetBlockRequest { selector }).await
    }
    async fn get_block_call(&self, request: GetBlockRequest) -> RpcResult<GetBlockResponse>;

    async fn get_block_proof(
        &self,
        selector: RpcBlockSelector,
    ) -> RpcResult<GetBlockProofResponse> {
        self.get_block_proof_call(GetBlockProofRequest { selector })
            .await
    }
    async fn get_block_proof_call(
        &self,
        request: GetBlockProofRequest,
    ) -> RpcResult<GetBlockProofResponse>;

    async fn get_block_kernel(
        &self,
        selector: RpcBlockSelector,
    ) -> RpcResult<GetBlockKernelResponse> {
        self.get_block_kernel_call(GetBlockKernelRequest { selector })
            .await
    }
    async fn get_block_kernel_call(
        &self,
        request: GetBlockKernelRequest,
    ) -> RpcResult<GetBlockKernelResponse>;

    async fn get_block_header(
        &self,
        selector: RpcBlockSelector,
    ) -> RpcResult<GetBlockHeaderResponse> {
        self.get_block_header_call(GetBlockHeaderRequest { selector })
            .await
    }
    async fn get_block_header_call(
        &self,
        request: GetBlockHeaderRequest,
    ) -> RpcResult<GetBlockHeaderResponse>;

    async fn get_block_body(&self, selector: RpcBlockSelector) -> RpcResult<GetBlockBodyResponse> {
        self.get_block_body_call(GetBlockBodyRequest { selector })
            .await
    }
    async fn get_block_body_call(
        &self,
        request: GetBlockBodyRequest,
    ) -> RpcResult<GetBlockBodyResponse>;

    async fn get_block_transaction_kernel(
        &self,
        selector: RpcBlockSelector,
    ) -> RpcResult<GetBlockTransactionKernelResponse> {
        self.get_block_transaction_kernel_call(GetBlockTransactionKernelRequest { selector })
            .await
    }
    async fn get_block_transaction_kernel_call(
        &self,
        request: GetBlockTransactionKernelRequest,
    ) -> RpcResult<GetBlockTransactionKernelResponse>;

    async fn get_block_announcements(
        &self,
        selector: RpcBlockSelector,
    ) -> RpcResult<GetBlockAnnouncementsResponse> {
        self.get_block_announcements_call(GetBlockAnnouncementsRequest { selector })
            .await
    }
    async fn get_block_announcements_call(
        &self,
        request: GetBlockAnnouncementsRequest,
    ) -> RpcResult<GetBlockAnnouncementsResponse>;

    async fn is_block_canonical(&self, digest: Digest) -> RpcResult<IsBlockCanonicalResponse> {
        self.is_block_canonical_call(IsBlockCanonicalRequest { digest })
            .await
    }
    async fn is_block_canonical_call(
        &self,
        request: IsBlockCanonicalRequest,
    ) -> RpcResult<IsBlockCanonicalResponse>;

    async fn get_utxo_digest(&self, leaf_index: u64) -> RpcResult<GetUtxoDigestResponse> {
        self.get_utxo_digest_call(GetUtxoDigestRequest { leaf_index })
            .await
    }
    async fn get_utxo_digest_call(
        &self,
        request: GetUtxoDigestRequest,
    ) -> RpcResult<GetUtxoDigestResponse>;

    async fn find_utxo_origin(
        &self,
        addition_record: RpcAdditionRecord,
        search_depth: Option<u64>,
    ) -> RpcResult<FindUtxoOriginResponse> {
        self.find_utxo_origin_call(FindUtxoOriginRequest {
            addition_record,
            search_depth,
        })
        .await
    }
    async fn find_utxo_origin_call(
        &self,
        request: FindUtxoOriginRequest,
    ) -> RpcResult<FindUtxoOriginResponse>;

    async fn are_bloom_indices_set(
        &self,
        absolute_index_set: RpcAbsoluteIndexSet,
    ) -> RpcResult<AreBloomIndicesSetResponse> {
        self.are_bloom_indices_set_call(AreBloomIndicesSetRequest { absolute_index_set })
            .await
    }

    async fn are_bloom_indices_set_call(
        &self,
        request: AreBloomIndicesSetRequest,
    ) -> RpcResult<AreBloomIndicesSetResponse>;

    async fn circulating_supply(&self) -> RpcResult<CirculatingSupplyResponse> {
        self.circulating_supply_call(CirculatingSupplyRequest {})
            .await
    }
    async fn circulating_supply_call(
        &self,
        _request: CirculatingSupplyRequest,
    ) -> RpcResult<CirculatingSupplyResponse>;

    async fn max_supply(&self) -> RpcResult<MaxSupplyResponse> {
        self.max_supply_call(MaxSupplyRequest {}).await
    }
    async fn max_supply_call(&self, _request: MaxSupplyRequest) -> RpcResult<MaxSupplyResponse>;

    async fn burned_supply(&self) -> RpcResult<BurnedSupplyResponse> {
        self.burned_supply_call(BurnedSupplyRequest {}).await
    }

    async fn burned_supply_call(
        &self,
        _request: BurnedSupplyRequest,
    ) -> RpcResult<BurnedSupplyResponse>;

    /* Wallet */

    async fn get_blocks(
        &self,
        from_height: RpcBlockHeight,
        to_height: RpcBlockHeight,
    ) -> RpcResult<GetBlocksResponse> {
        self.get_blocks_call(GetBlocksRequest {
            from_height,
            to_height,
        })
        .await
    }
    async fn get_blocks_call(&self, request: GetBlocksRequest) -> RpcResult<GetBlocksResponse>;

    async fn restore_membership_proof(
        &self,
        absolute_index_sets: Vec<RpcAbsoluteIndexSet>,
    ) -> RpcResult<RestoreMembershipProofResponse> {
        self.restore_membership_proof_call(RestoreMembershipProofRequest {
            absolute_index_sets,
        })
        .await
    }
    async fn restore_membership_proof_call(
        &self,
        request: RestoreMembershipProofRequest,
    ) -> RpcResult<RestoreMembershipProofResponse>;

    async fn submit_transaction(
        &self,
        transaction: RpcTransaction,
    ) -> RpcResult<SubmitTransactionResponse> {
        self.submit_transaction_call(SubmitTransactionRequest { transaction })
            .await
    }
    async fn submit_transaction_call(
        &self,
        request: SubmitTransactionRequest,
    ) -> RpcResult<SubmitTransactionResponse>;

    async fn rescan_announced(
        &self,
        first: RpcBlockHeight,
        last: RpcBlockHeight,
    ) -> RpcResult<RescanAnnouncedResponse> {
        self.rescan_announced_call(RescanAnnouncedRequest { first, last })
            .await
    }

    async fn rescan_announced_call(
        &self,
        request: RescanAnnouncedRequest,
    ) -> RpcResult<RescanAnnouncedResponse>;

    async fn rescan_expected(
        &self,
        first: RpcBlockHeight,
        last: RpcBlockHeight,
    ) -> RpcResult<RescanExpectedResponse> {
        self.rescan_expected_call(RescanExpectedRequest { first, last })
            .await
    }

    async fn rescan_expected_call(
        &self,
        request: RescanExpectedRequest,
    ) -> RpcResult<RescanExpectedResponse>;

    async fn rescan_outgoing(
        &self,
        first: RpcBlockHeight,
        last: RpcBlockHeight,
    ) -> RpcResult<RescanOutgoingResponse> {
        self.rescan_outgoing_call(RescanOutgoingRequest { first, last })
            .await
    }

    async fn rescan_outgoing_call(
        &self,
        request: RescanOutgoingRequest,
    ) -> RpcResult<RescanOutgoingResponse>;

    async fn rescan_guesser_rewards(
        &self,
        first: RpcBlockHeight,
        last: RpcBlockHeight,
    ) -> RpcResult<RescanGuesserRewardsResponse> {
        self.rescan_guesser_rewards_call(RescanGuesserRewardsRequest { first, last })
            .await
    }

    async fn rescan_guesser_rewards_call(
        &self,
        request: RescanGuesserRewardsRequest,
    ) -> RpcResult<RescanGuesserRewardsResponse>;

    /* Mining */

    async fn get_block_template(
        &self,
        guesser_address: String,
    ) -> RpcResult<GetBlockTemplateResponse> {
        self.get_block_template_call(GetBlockTemplateRequest { guesser_address })
            .await
    }
    async fn get_block_template_call(
        &self,
        request: GetBlockTemplateRequest,
    ) -> RpcResult<GetBlockTemplateResponse>;

    async fn submit_block(
        &self,
        template: RpcBlock,
        pow: RpcBlockPow,
    ) -> RpcResult<SubmitBlockResponse> {
        self.submit_block_call(SubmitBlockRequest { template, pow })
            .await
    }
    async fn submit_block_call(
        &self,
        request: SubmitBlockRequest,
    ) -> RpcResult<SubmitBlockResponse>;

    /* Utxo Index */

    async fn block_heights_by_flags(
        &self,
        announcement_flags: Vec<AnnouncementFlag>,
    ) -> RpcResult<BlockHeightsByFlagsResponse> {
        self.block_heights_by_flags_call(BlockHeightsByFlagsRequest { announcement_flags })
            .await
    }

    async fn block_heights_by_flags_call(
        &self,
        request: BlockHeightsByFlagsRequest,
    ) -> RpcResult<BlockHeightsByFlagsResponse>;

    async fn block_heights_by_addition_records(
        &self,
        addition_records: Vec<RpcAdditionRecord>,
    ) -> RpcResult<BlockHeightsByAdditionRecordsResponse> {
        self.block_heights_by_addition_records_call(BlockHeightsByAdditionRecordsRequest {
            addition_records,
        })
        .await
    }

    async fn block_heights_by_addition_records_call(
        &self,
        request: BlockHeightsByAdditionRecordsRequest,
    ) -> RpcResult<BlockHeightsByAdditionRecordsResponse>;

    async fn block_heights_by_absolute_index_sets(
        &self,
        absolute_index_sets: Vec<RpcAbsoluteIndexSet>,
    ) -> RpcResult<BlockHeightsByAbsoluteIndexSetsResponse> {
        self.block_heights_by_absolute_index_sets_call(BlockHeightsByAbsoluteIndexSetsRequest {
            absolute_index_sets,
        })
        .await
    }

    async fn block_heights_by_absolute_index_sets_call(
        &self,
        request: BlockHeightsByAbsoluteIndexSetsRequest,
    ) -> RpcResult<BlockHeightsByAbsoluteIndexSetsResponse>;

    /* Mempool */

    async fn transactions(&self) -> RpcResult<TransactionsResponse> {
        self.transactions_call(TransactionsRequest {}).await
    }
    async fn transactions_call(
        &self,
        request: TransactionsRequest,
    ) -> RpcResult<TransactionsResponse>;

    async fn get_transaction_kernel(
        &self,
        id: RpcTransactionKernelId,
    ) -> RpcResult<GetTransactionKernelResponse> {
        self.get_transaction_kernel_call(GetTransactionKernelRequest { id })
            .await
    }
    async fn get_transaction_kernel_call(
        &self,
        request: GetTransactionKernelRequest,
    ) -> RpcResult<GetTransactionKernelResponse>;

    async fn get_transaction_proof(
        &self,
        id: RpcTransactionKernelId,
    ) -> RpcResult<GetTransactionProofResponse> {
        self.get_transaction_proof_call(GetTransactionProofRequest { id })
            .await
    }
    async fn get_transaction_proof_call(
        &self,
        request: GetTransactionProofRequest,
    ) -> RpcResult<GetTransactionProofResponse>;

    async fn get_transactions_by_addition_records(
        &self,
        addition_records: Vec<RpcAdditionRecord>,
    ) -> RpcResult<GetTransactionsByAdditionRecordsResponse> {
        self.get_transactions_by_addition_records_call(GetTransactionsByAdditionRecordsRequest {
            addition_records,
        })
        .await
    }
    async fn get_transactions_by_addition_records_call(
        &self,
        request: GetTransactionsByAdditionRecordsRequest,
    ) -> RpcResult<GetTransactionsByAdditionRecordsResponse>;

    async fn get_transactions_by_absolute_index_sets(
        &self,
        absolute_index_sets: Vec<RpcAbsoluteIndexSet>,
    ) -> RpcResult<GetTransactionsByAbsoluteIndexSetsResponse> {
        self.get_transactions_by_absolute_index_sets_call(
            GetTransactionsByAbsoluteIndexSetsRequest {
                absolute_index_sets,
            },
        )
        .await
    }
    async fn get_transactions_by_absolute_index_sets_call(
        &self,
        request: GetTransactionsByAbsoluteIndexSetsRequest,
    ) -> RpcResult<GetTransactionsByAbsoluteIndexSetsResponse>;

    async fn best_transaction_for_next_block(
        &self,
    ) -> RpcResult<BestTransactionForNextBlockResponse> {
        self.best_transaction_for_next_block_call(BestTransactionForNextBlockRequest {})
            .await
    }
    async fn best_transaction_for_next_block_call(
        &self,
        request: BestTransactionForNextBlockRequest,
    ) -> RpcResult<BestTransactionForNextBlockResponse>;
    /* Networking */

    async fn ban_call(&self, request: BanRequest) -> RpcResult<BanResponse>;
    async fn ban(&self, address: Multiaddr) -> RpcResult<BanResponse> {
        self.ban_call(BanRequest { address }).await
    }
    async fn unban_call(&self, request: UnbanRequest) -> RpcResult<UnbanResponse>;
    async fn unban(&self, address: Multiaddr) -> RpcResult<UnbanResponse> {
        self.unban_call(UnbanRequest { address }).await
    }
    async fn unban_all_call(&self, request: UnbanAllRequest) -> RpcResult<UnbanAllResponse>;
    async fn unban_all(&self) -> RpcResult<UnbanAllResponse> {
        self.unban_all_call(UnbanAllRequest {}).await
    }
    async fn dial_call(&self, request: DialRequest) -> RpcResult<DialResponse>;
    async fn dial(&self, address: Multiaddr) -> RpcResult<DialResponse> {
        self.dial_call(DialRequest { address }).await
    }
    async fn probe_nat_call(&self, request: ProbeNatRequest) -> RpcResult<ProbeNatResponse>;
    async fn probe_nat(&self) -> RpcResult<ProbeNatResponse> {
        self.probe_nat_call(ProbeNatRequest {}).await
    }
    async fn reset_relay_reservations_call(
        &self,
        request: ResetRelayReservationsRequest,
    ) -> RpcResult<ResetRelayReservationsResponse>;
    async fn reset_relay_reservations(&self) -> RpcResult<ResetRelayReservationsResponse> {
        self.reset_relay_reservations_call(ResetRelayReservationsRequest {})
            .await
    }

    async fn get_network_overview(&self) -> RpcResult<NetworkOverviewResponse> {
        self.network_overview_call(NetworkOverviewRequest {}).await
    }
    async fn network_overview_call(
        &self,
        _request: NetworkOverviewRequest,
    ) -> RpcResult<NetworkOverviewResponse>;
}
