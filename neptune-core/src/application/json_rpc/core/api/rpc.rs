use std::time::Duration;

use async_trait::async_trait;
use libp2p::Multiaddr;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldElement;
use thiserror::Error;

use crate::api::export::AnnouncementFlag;
use crate::api::export::KeyType;
use crate::api::export::Timestamp;
use crate::application::json_rpc::core::model::block::header::RpcBlockHeight;
use crate::application::json_rpc::core::model::block::header::RpcBlockPow;
use crate::application::json_rpc::core::model::block::transaction_kernel::RpcAbsoluteIndexSet;
use crate::application::json_rpc::core::model::block::transaction_kernel::RpcAdditionRecord;
use crate::application::json_rpc::core::model::block::transaction_kernel::RpcTransactionKernelId;
use crate::application::json_rpc::core::model::block::RpcBlock;
use crate::application::json_rpc::core::model::common::RpcBlockSelector;
use crate::application::json_rpc::core::model::common::RpcNativeCurrencyAmount;
use crate::application::json_rpc::core::model::json::JsonError;
use crate::application::json_rpc::core::model::message::*;
use crate::application::json_rpc::core::model::wallet::transaction::RpcTransaction;
use crate::protocol::consensus::transaction::validity::neptune_proof::NeptuneProof;

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

    #[error("Filtering conditions may not be empty")]
    EmptyFilteringConditions,

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

    #[error("Derivation index must be in range [{0}; {1}].")]
    InvalidDerivationIndexRange(u64, u64),

    #[error("Wallet key counter is zero.")]
    WalletKeyCounterIsZero,

    #[error("Number of confirmations is wrong.")]
    BadConfirmationCount,

    #[error("Failed to create transaction. Error: {0}")]
    SendError(String),

    #[error("The UTXO that you try to claim cannot be registered by the wallet. Error: {0}")]
    CannotClaimUtxo(String),
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

    /// Check if indices in an absolute index set are set in the node's archival
    /// mutator set. Can be used to check  if a UTXO is spent without having to
    /// know the mutator set membership proof.
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

    /// Check if a string is a valid Neptune address. Returns metadata about
    /// the address if the address is valid.
    async fn validate_address(&self, address_string: String) -> RpcResult<ValidateAddressResponse> {
        self.validate_address_call(ValidateAddressRequest { address_string })
            .await
    }

    async fn validate_address_call(
        &self,
        request: ValidateAddressRequest,
    ) -> RpcResult<ValidateAddressResponse>;

    /// Check if a string represents a valid, non-negative amount of NPT,
    /// Neptune coins.
    ///
    /// If the amount is valid, returns the amount.
    async fn validate_coins_amount(
        &self,
        amount_string: String,
    ) -> RpcResult<ValidateCoinsAmountResponse> {
        self.validate_coins_amount_call(ValidateCoinsAmountRequest { amount_string })
            .await
    }

    async fn validate_coins_amount_call(
        &self,
        request: ValidateCoinsAmountRequest,
    ) -> RpcResult<ValidateCoinsAmountResponse>;

    /// Check if a string represents a valid, non-negative amount of NPT,
    /// atomical units, AKA NAU. This is equivalent to checking if the string
    /// represents a valid, non-negative i128 not exceeding the maximum allowed
    /// coins amount of 42.000.000.
    ///
    /// If the amount is valid, returns the amount.
    async fn validate_nau_amount(
        &self,
        nau_string: String,
    ) -> RpcResult<ValidateNauAmountResponse> {
        self.validate_nau_amount_call(ValidateNauAmountRequest { nau_string })
            .await
    }

    async fn validate_nau_amount_call(
        &self,
        request: ValidateNauAmountRequest,
    ) -> RpcResult<ValidateNauAmountResponse>;

    /// Return all blocks in the specified range (inclusive). Will not return
    /// the genesis block.
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
        derivation_path: Option<(KeyType, u64)>,
    ) -> RpcResult<RescanAnnouncedResponse> {
        self.rescan_announced_call(RescanAnnouncedRequest {
            first,
            last,
            derivation_path,
        })
        .await
    }

    /* Personal */

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

    async fn rescan_outgoing(&self) -> RpcResult<RescanOutgoingResponse> {
        self.rescan_outgoing_call(RescanOutgoingRequest {}).await
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

    async fn derivation_index(&self, key_type: KeyType) -> RpcResult<DerivationIndexResponse> {
        self.derivation_index_call(DerivationIndexRequest { key_type })
            .await
    }

    async fn derivation_index_call(
        &self,
        request: DerivationIndexRequest,
    ) -> RpcResult<DerivationIndexResponse>;

    async fn set_derivation_index(
        &self,
        key_type: KeyType,
        derivation_index: u64,
    ) -> RpcResult<SetDerivationIndexResponse> {
        self.set_derivation_index_call(SetDerivationIndexRequest {
            key_type,
            derivation_index,
        })
        .await
    }

    async fn set_derivation_index_call(
        &self,
        request: SetDerivationIndexRequest,
    ) -> RpcResult<SetDerivationIndexResponse>;

    async fn generate_address(&self, key_type: KeyType) -> RpcResult<GenerateAddressResponse> {
        self.generate_address_call(GenerateAddressRequest { key_type })
            .await
    }

    async fn generate_address_call(
        &self,
        request: GenerateAddressRequest,
    ) -> RpcResult<GenerateAddressResponse>;

    /// Return all incoming UTXOs tracked by this node's wallet matching the
    /// specified filters.
    ///
    /// Returns all incoming UTXOs if no filter is specified. Allows for
    /// pagination.
    #[expect(clippy::too_many_arguments)]
    async fn incoming_history(
        &self,
        include_orphaned: bool,
        aocl_leaf_index: Option<u64>,
        output: Option<RpcAdditionRecord>,
        receiver_preimage: Option<Digest>,
        receiver_digest: Option<Digest>,
        lock_script_hash: Option<Digest>,
        sender_randomness: Option<Digest>,
        confirmed_height: Option<RpcBlockHeight>,
        confirmed_block_hash: Option<Digest>,
        max_num_elements: Option<u64>,
        page: Option<u64>,
    ) -> RpcResult<IncomingHistoryResponse> {
        self.incoming_history_call(IncomingHistoryRequest {
            aocl_leaf_index,
            output,
            receiver_preimage,
            receiver_digest,
            lock_script_hash,
            sender_randomness,
            confirmed_height,
            confirmed_block_hash,
            include_orphaned,
            max_num_elements,
            page,
        })
        .await
    }

    async fn incoming_history_call(
        &self,
        request: IncomingHistoryRequest,
    ) -> RpcResult<IncomingHistoryResponse>;

    /// Return all outgoing transactions intiated by this node's wallet matching
    /// the specified filters.
    ///
    /// Returns all outgoing transactions if no filter is specified. Allows for
    /// pagination.
    #[expect(clippy::too_many_arguments)]
    async fn outgoing_history(
        &self,
        sender_randomness: Option<Digest>,
        receiver_digest: Option<Digest>,
        output_lock_script_hash: Option<Digest>,
        output: Option<RpcAdditionRecord>,
        timestamp: Option<Timestamp>,
        max_num_elements: Option<u64>,
        page: Option<u64>,
    ) -> RpcResult<OutgoingHistoryResponse> {
        self.outgoing_history_call(OutgoingHistoryRequest {
            sender_randomness,
            receiver_digest,
            output_lock_script_hash,
            output,
            timestamp,
            max_num_elements,
            page,
        })
        .await
    }

    async fn outgoing_history_call(
        &self,
        request: OutgoingHistoryRequest,
    ) -> RpcResult<OutgoingHistoryResponse>;

    async fn unspent_utxos(&self) -> RpcResult<UnspentUtxosResponse> {
        self.unspent_utxos_call(UnspentUtxosRequest {}).await
    }

    async fn unspent_utxos_call(
        &self,
        request: UnspentUtxosRequest,
    ) -> RpcResult<UnspentUtxosResponse>;

    async fn get_balance(&self, number_of_confirmations: u32) -> RpcResult<GetBalanceResponse> {
        self.get_balance_call(GetBalanceRequest {
            number_of_confirmations,
        })
        .await
    }

    async fn get_balance_call(&self, request: GetBalanceRequest) -> RpcResult<GetBalanceResponse>;

    /// Return the number of transactions initiated while this block was tip.
    ///
    /// Does not check if the transactions have been mined, only initiated.
    async fn count_sent_transactions_at_block(
        &self,
        selector: RpcBlockSelector,
    ) -> RpcResult<CountSentTransactionsAtBlockResponse> {
        self.count_sent_transactions_at_block_call(CountSentTransactionsAtBlockRequest { selector })
            .await
    }

    async fn count_sent_transactions_at_block_call(
        &self,
        request: CountSentTransactionsAtBlockRequest,
    ) -> RpcResult<CountSentTransactionsAtBlockResponse>;

    #[expect(clippy::too_many_arguments)]
    async fn send(
        &self,
        amount: RpcNativeCurrencyAmount,
        fee: RpcNativeCurrencyAmount,
        to_address: String,
        min_input_confirmations: Option<usize>,
        max_num_inputs: Option<usize>,
        notify_self: Option<String>,
        notify_other: Option<String>,
        utxo_priority: Option<String>,
    ) -> RpcResult<SendResponse> {
        self.send_call(SendRequest {
            amount,
            fee,
            to_address,
            min_input_confirmations,
            max_num_inputs,
            notify_self,
            notify_other,
            utxo_priority,
        })
        .await
    }

    async fn send_call(&self, request: SendRequest) -> RpcResult<SendResponse>;

    /// Claim a UTXO which does not have an onchain announcement but whose
    /// receiver data is shared through an offchain ciphertext.
    async fn claim_utxo(
        &self,
        ciphertext: String,
        max_search_depth: Option<u64>,
    ) -> RpcResult<ClaimUtxoResponse> {
        self.claim_utxo_call(ClaimUtxoRequest {
            ciphertext,
            max_search_depth,
        })
        .await
    }

    async fn claim_utxo_call(&self, request: ClaimUtxoRequest) -> RpcResult<ClaimUtxoResponse>;

    /// Prove a transfer of the native coin from the current wallet.
    /// Discloses amount, addresses, and other transfer information while
    /// keeping sensitive data hidden in the proof.
    async fn prove_an_transfer(
        &self,
        tx_ix: u64,
        utxo_ix: usize,
        block: Digest,
    ) -> RpcResult<ProveAnTransferResponse> {
        self.prove_an_transfer_call(ProveAnTransferRequest {
            tx_ix,
            utxo_ix,
            block,
        })
        .await
    }

    async fn prove_an_transfer_call(
        &self,
        request: ProveAnTransferRequest,
    ) -> RpcResult<ProveAnTransferResponse>;

    /// Verify a Triton VM (claim, proof) pair.
    /// Returns `true` if the proof is valid for the given claim.
    async fn triton_verify(
        &self,
        claim: tasm_lib::triton_vm::proof::Claim,
        proof: NeptuneProof,
    ) -> TritonVerifyResponse {
        self.triton_verify_call(TritonVerifyRequest { claim, proof })
            .await
            .expect("infallible")
    }

    async fn triton_verify_call(
        &self,
        request: TritonVerifyRequest,
    ) -> RpcResult<TritonVerifyResponse>;

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

    /* Utxoindex */

    /// Return block heights for blocks containing announcements with specified
    /// announcement flags. May return results from orphaned blocks.
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

    /// Return block heights for blocks containing specified addition records.
    /// Returned block heights are guaranteed to reference blocks belonging to
    /// the canonical chain.
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

    /// Return block heights for blocks containing specified absolute index
    /// sets. Returned block heights are guaranteed to reference blocks
    /// belonging to the canonical chain.
    async fn block_heights_by_absolute_index_sets_call(
        &self,
        request: BlockHeightsByAbsoluteIndexSetsRequest,
    ) -> RpcResult<BlockHeightsByAbsoluteIndexSetsResponse>;

    /// Return the block heights for blocks matching *all* elements in the
    /// specified input/output lists, for blocks belonging to the canonical
    /// chain. Will not return block heights were e.g. only one of the outputs
    /// was included if more than one output is included in the outputs list.
    ///
    /// Can return multiple blocks in the case where blocks are selected only
    /// based on addition records and multiple blocks contain the same addition
    /// records.
    ///
    /// Returns an error if no filtering conditions are set.
    async fn was_mined(
        &self,
        inputs: Vec<RpcAbsoluteIndexSet>,
        outputs: Vec<RpcAdditionRecord>,
    ) -> RpcResult<WasMinedResponse> {
        self.was_mined_call(WasMinedRequest {
            absolute_index_sets: inputs,
            addition_records: outputs,
        })
        .await
    }

    async fn was_mined_call(&self, request: WasMinedRequest) -> RpcResult<WasMinedResponse>;

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

    /// Return transaction most likely to be mined in next block, based on fee
    /// density, sync status, and proof quality.
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
