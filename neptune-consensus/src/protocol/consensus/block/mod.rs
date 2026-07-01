pub mod block_appendix;
pub mod block_body;
pub mod block_header;
pub mod block_height;
pub mod block_info;
pub mod block_kernel;
pub mod block_transaction;
pub mod block_validation_error;
pub mod difficulty_control;
pub mod guesser_receiver_data;
pub mod mutator_set_update;
pub mod pow;
pub(crate) mod premine;
pub mod proof_of_work_puzzle;
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers;
pub mod validity;

use std::sync::Arc;
use std::sync::OnceLock;

use block_appendix::BlockAppendix;
use block_appendix::MAX_NUM_CLAIMS;
use block_body::BlockBody;
use block_header::BlockHeader;
use block_height::BlockHeight;
use block_kernel::BlockKernel;
use block_validation_error::BlockValidationError;
use difficulty_control::Difficulty;
use get_size2::GetSize;
use itertools::Itertools;
use mutator_set_update::MutatorSetUpdate;
use neptune_mutator_set::addition_record::AdditionRecord;
use neptune_mutator_set::commit;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_mutator_set::removal_record::removal_record_list::RemovalRecordList;
use neptune_primitives::mast_hash::HasDiscriminant;
use neptune_primitives::mast_hash::MastHash;
use neptune_primitives::timestamp::Timestamp;
use num_traits::CheckedSub;
use num_traits::Zero;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use rayon::ThreadPoolBuilder;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumCount;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::tip5::digest::Digest;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;
use tracing::warn;
use validity::block_primitive_witness::BlockPrimitiveWitness;
use validity::block_program::BlockProgram;
use validity::block_proof_witness::BlockProofWitness;

use super::transaction::transaction_kernel::TransactionKernelProxy;
use super::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::consensus::block::block_header::BlockHeaderField;
use crate::protocol::consensus::block::block_header::BlockPow;
use crate::protocol::consensus::block::block_height::BLOCKS_PER_GENERATION;
use crate::protocol::consensus::block::block_height::NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT;
use crate::protocol::consensus::block::block_kernel::BlockKernelField;
use crate::protocol::consensus::block::block_transaction::BlockTransaction;
use crate::protocol::consensus::block::difficulty_control::difficulty_control;
use crate::protocol::consensus::block::difficulty_control::ProofOfWork;
use crate::protocol::consensus::block::guesser_receiver_data::GuesserReceiverData;
use crate::protocol::consensus::block::pow::Cancelable;
use crate::protocol::consensus::block::pow::GuesserBuffer;
use crate::protocol::consensus::block::pow::LustrationStatus;
use crate::protocol::consensus::block::pow::Pow;
use crate::protocol::consensus::block::pow::PowMastPaths;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::consensus_rule_set::LustrationRule;
use crate::protocol::consensus::network::Network;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionLustrationError;
use crate::protocol::consensus::transaction::validity::neptune_proof::Proof;
use crate::protocol::proof_abstractions::proof_builder::ProofBuilder;
use crate::protocol::proof_abstractions::tasm::program::TritonProgram;
use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::protocol::proof_abstractions::triton_vm_job_queue::TritonVmJobQueue;
use crate::protocol::proof_abstractions::verifier::verify;
use crate::protocol::proof_abstractions::SecretWitness;

/// With removal records only represented by their absolute index set, the block
/// size limit of 1.000.000 `BFieldElement`s allows for a "balanced" block
/// (equal number of inputs and outputs, no announcements) of ~10.000
/// input and outputs. To prevent an attacker from making it costly to run an
/// archival node, the number of outputs is restricted. For simplicity though
/// this limit is enforced for inputs, outputs, and announcements. This
/// restriction on the number of announcements also makes it feasible for
/// wallets to scan through all.
pub(crate) const MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS: usize = 1 << 14;

/// Duration of timelock for half of all mining rewards.
///
/// Half the block subsidy is liquid immediately. Half of it is locked for this
/// time period. Likewise, half the guesser fee is liquid immediately; and half
/// is time locked for this period.
pub const MINING_REWARD_TIME_LOCK_PERIOD: Timestamp = Timestamp::years(3);

pub const INITIAL_BLOCK_SUBSIDY: NativeCurrencyAmount = NativeCurrencyAmount::coins(128);

/// Blocks with timestamps too far into the future are invalid. Reject blocks
/// whose timestamp exceeds now with this value or more.
pub const FUTUREDATING_LIMIT: Timestamp = Timestamp::millis(60001);

/// The size of the premine, 831488 coins.
pub const PREMINE_MAX_SIZE: NativeCurrencyAmount = NativeCurrencyAmount::coins(831488);

/// All blocks have proofs except the genesis block
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BFieldCodec, GetSize, Default)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(arbitrary::Arbitrary))]
pub enum BlockProof {
    Genesis,
    #[default]
    Invalid,
    SingleProof(Proof),
}

/// Public fields of `Block` are read-only, enforced by #[readonly::make].
/// Modifications are possible only through `Block` methods.
///
/// Example:
///
/// test: verify that compile fails on an attempt to mutate block
/// internals directly (bypassing encapsulation)
///
/// ```compile_fail,E0594
/// use neptune_consensus::protocol::consensus::block::Block;
/// use neptune_consensus::protocol::consensus::network::Network;
/// use neptune_consensus::prelude::twenty_first::math::b_field_element::BFieldElement;
/// use tasm_lib::prelude::Digest;
///
/// let mut block = Block::genesis(Network::RegTest);
///
/// let height = block.kernel.header.height;
///
/// let nonce = Digest::default();
///
/// // this line fails to compile because we try to
/// // mutate an internal field.
/// block.kernel.header.pow.nonce = nonce;
/// ```
// ## About the private `digest` field:
//
// The `digest` field represents the `Block` hash.  It is an optimization so
// that the hash can be lazily computed at most once (per modification).
//
// It is wrapped in `OnceLock<_>` for interior mutability because (a) the hash()
// method is used in many methods that are `&self` and (b) because `Block` is
// passed between tasks/threads, and thus `Rc<RefCell<_>>` is not an option.
//
// The field must be reset whenever the Block is modified.  As such, we should
// not permit direct modification of internal fields, particularly `kernel`
//
// Therefore `[readonly::make]` is used to make public `Block` fields read-only
// (not mutable) outside of this module.  All methods that modify Block also
// reset the `digest` field.
//
// We manually implement `PartialEq` and `Eq` so that digest field will not be
// compared.  Otherwise, we could have identical blocks except one has
// initialized digest field and the other has not.
//
// The field should not be serialized, so it has the `#[serde(skip)]` attribute.
// Upon deserialization, the field will have Digest::default() which is desired
// so that the digest will be recomputed if/when hash() is called.
//
// We likewise skip the field for `BFieldCodec`, and `GetSize` because there
// exist no impls for `OnceLock<_>` so derive fails.
//
// A unit test-suite exists in module tests::digest_encapsulation.
#[readonly::make]
#[derive(Debug, Clone, Serialize, Deserialize, BFieldCodec, GetSize)]
pub struct Block {
    /// Everything but the proof
    pub kernel: BlockKernel,

    pub proof: BlockProof,

    // this is only here as an optimization for Block::hash()
    // so that we lazily compute the hash at most once.
    #[serde(skip)]
    #[bfield_codec(ignore)]
    #[get_size(ignore)]
    digest: OnceLock<Digest>,
}

impl MastHash for Block {
    type FieldEnum = BlockField;

    fn mast_sequences(&self) -> Vec<Vec<BFieldElement>> {
        vec![self.kernel.mast_hash().encode(), self.proof.encode()]
    }
}

#[derive(Debug, Copy, Clone, EnumCount)]
pub enum BlockField {
    Kernel,
    Proof,
}

impl HasDiscriminant for BlockField {
    fn discriminant(&self) -> usize {
        *self as usize
    }
}

impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        // TBD: is it faster overall to compare hashes or equality
        // of kernel and blocktype fields?
        // In the (common?) case where hash has already been
        // computed for both `Block` comparing hash equality
        // should be faster.
        self.hash() == other.hash()
    }
}
impl Eq for Block {}

impl Block {
    pub async fn block_template_from_block_primitive_witness(
        primitive_witness: BlockPrimitiveWitness,
        timestamp: Timestamp,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
    ) -> anyhow::Result<Block> {
        let network = proof_job_options.job_settings.network;
        let body = primitive_witness.body().to_owned();
        let header = primitive_witness.header(timestamp, network.target_block_interval());
        let (appendix, proof) = {
            let block_proof_witness = BlockProofWitness::produce(primitive_witness);
            let appendix = block_proof_witness.appendix();
            let consensus_rule_set = ConsensusRuleSet::infer_from(network, header.height);
            let claim = BlockProgram::claim(&body, &appendix, consensus_rule_set);

            let proof = ProofBuilder::new()
                .program(BlockProgram.program())
                .claim(claim)
                .nondeterminism(|| block_proof_witness.nondeterminism())
                .job_queue(triton_vm_job_queue)
                .proof_job_options(proof_job_options)
                .build()
                .await?;

            (appendix, BlockProof::SingleProof(proof))
        };

        Ok(Block::new(header, body, appendix, proof))
    }

    async fn make_block_template_with_valid_proof(
        predecessor: Block,
        transaction: BlockTransaction,
        block_timestamp: Timestamp,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
    ) -> anyhow::Result<Block> {
        let new_height = predecessor.header().height.next();
        let network = proof_job_options.job_settings.network;
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, new_height);
        let tx_claim = BlockAppendix::transaction_validity_claim(
            transaction.kernel.mast_hash(),
            consensus_rule_set,
        );
        assert!(
            verify(
                tx_claim.clone(),
                transaction.proof.clone().into_single_proof(),
                network
            )
            .await,
            "Transaction proof must be valid to generate a block"
        );

        assert!(
            transaction.kernel.merge_bit,
            "Merge-bit must be set in transactions before they can be included in blocks."
        );
        let primitive_witness = BlockPrimitiveWitness::new(predecessor, transaction, network);
        Self::block_template_from_block_primitive_witness(
            primitive_witness,
            block_timestamp,
            triton_vm_job_queue,
            proof_job_options,
        )
        .await
    }

    /// Compose a block.
    ///
    /// Create a block with valid block proof, but without proof-of-work.
    pub async fn compose(
        predecessor: Block,
        transaction: BlockTransaction,
        block_timestamp: Timestamp,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
    ) -> anyhow::Result<Block> {
        Self::make_block_template_with_valid_proof(
            predecessor,
            transaction,
            block_timestamp,
            triton_vm_job_queue,
            proof_job_options,
        )
        .await
    }

    /// Returns the block Digest
    ///
    /// performance note:
    ///
    /// The digest is never computed until hash() is called.  Subsequent calls
    /// will not recompute it unless the Block was modified since the last call.
    #[inline]
    pub fn hash(&self) -> Digest {
        *self.digest.get_or_init(|| self.mast_hash())
    }

    #[inline]
    fn unset_digest(&mut self) {
        // note: this replaces the OnceLock so the digest will be calc'd in hash()
        self.digest = Default::default();
    }

    /// Set the guesser digest in the block's header.
    ///
    /// Note: this causes the block digest to change.
    #[inline]
    pub fn set_header_guesser_data(&mut self, guesser_data: GuesserReceiverData) {
        self.kernel.header.guesser_receiver_data = guesser_data;
        self.unset_digest();
    }

    /// Set the lustration status found in the block's header.
    ///
    /// Note: this causes the block digest to change.
    pub fn set_lustration_status(&mut self, lustration_status: LustrationStatus) {
        self.kernel
            .header
            .pow
            .set_lustration_status(lustration_status);
        self.unset_digest();
    }

    #[cfg(any(test, feature = "test-helpers"))]
    pub fn set_unparseable_lustration_status(&mut self) {
        self.kernel.header.pow.set_unparseable_lustration_status();
        self.unset_digest();
    }

    /// Test-only mutable access to the block kernel.
    ///
    /// `Block`'s fields are read-only outside the module in which the type is
    /// defined (see `#[readonly::make]`). Tests that need to corrupt a block's
    /// internals from elsewhere in the crate go through this accessor. Mutating
    /// the kernel invalidates the cached digest.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn kernel_mut(&mut self) -> &mut BlockKernel {
        self.unset_digest();
        &mut self.kernel
    }

    /// Test-only mutable access to the block proof.
    ///
    /// See [`Block::kernel_mut`] for why this accessor exists.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn proof_mut(&mut self) -> &mut BlockProof {
        self.unset_digest();
        &mut self.proof
    }

    /// sets header timestamp, difficulty and, optionally, cumulative proof of
    /// work.
    ///
    /// These must be set as a pair or triplet because the difficulty depends
    /// on the timestamp, and may change with it. Depending on the consensus
    /// rules, the cumulative proof of work must also be updated.
    ///
    /// note: this causes block digest to change.
    #[inline]
    pub fn set_difficulty_related_fields(
        &mut self,
        timestamp: Timestamp,
        difficulty: Difficulty,
        cumulative_proof_of_work: Option<ProofOfWork>,
    ) {
        self.kernel.header.timestamp = timestamp;
        self.kernel.header.difficulty = difficulty;
        if let Some(cumulative_proof_of_work) = cumulative_proof_of_work {
            self.kernel.header.cumulative_proof_of_work = cumulative_proof_of_work;
        }

        self.unset_digest();
    }

    #[inline]
    pub fn header(&self) -> &BlockHeader {
        &self.kernel.header
    }

    #[inline]
    pub fn body(&self) -> &BlockBody {
        &self.kernel.body
    }

    /// Return the mutator set as it looks after the application of this block.
    ///
    /// Includes the guesser-fee UTXOs which are not included by the
    /// `mutator_set_accumulator` field on the block body.
    pub fn mutator_set_accumulator_after(
        &self,
    ) -> Result<MutatorSetAccumulator, BlockValidationError> {
        let guesser_fee_addition_records = self.guesser_fee_addition_records()?;
        let msa = self
            .body()
            .mutator_set_accumulator_after(guesser_fee_addition_records);

        Ok(msa)
    }

    #[inline]
    pub fn appendix(&self) -> &BlockAppendix {
        &self.kernel.appendix
    }

    /// The number of coins that can be printed into existence with the mining
    /// a block with this height.
    pub fn block_subsidy(block_height: BlockHeight) -> NativeCurrencyAmount {
        let mut reward: NativeCurrencyAmount = INITIAL_BLOCK_SUBSIDY;
        let generation = block_height.get_generation();

        for _ in 0..generation {
            reward.div_two();

            // Early return here is important bc of test-case generators with
            // arbitrary block heights.
            if reward.is_zero() {
                return NativeCurrencyAmount::zero();
            }
        }

        reward
    }

    /// returns coinbase reward amount for this block.
    ///
    /// note that this amount may differ from self::block_subsidy(self.height)
    /// because a miner can choose to accept less than the calculated reward amount.
    pub fn coinbase_amount(&self) -> NativeCurrencyAmount {
        // A block must always have a Coinbase.
        // we impl this method in part to cement that guarantee.
        self.body()
            .transaction_kernel
            .coinbase
            .unwrap_or_else(NativeCurrencyAmount::zero)
    }

    pub fn genesis(network: Network) -> Self {
        let premine_distribution = Self::premine_distribution();
        let total_premine_amount = premine_distribution
            .iter()
            .map(|(_receiving_address, amount)| *amount)
            .sum();

        let mut genesis_tx_outputs = vec![];
        for ((receiving_address, _amount), utxo) in
            premine_distribution.iter().zip(Self::premine_utxos())
        {
            let utxo_digest = Tip5::hash(&utxo);
            // generate randomness for mutator set commitment
            // Sender randomness cannot be random because there is no sender.
            let bad_randomness = Self::premine_sender_randomness(network);

            let receiver_digest = receiving_address.receiver_digest;

            // Add pre-mine UTXO to MutatorSet
            let addition_record = commit(utxo_digest, bad_randomness, receiver_digest);

            // Add pre-mine UTXO + commitment to coinbase transaction
            genesis_tx_outputs.push(addition_record)
        }

        let mut genesis_mutator_set = MutatorSetAccumulator::default();
        for addition_record in &genesis_tx_outputs {
            genesis_mutator_set.add(addition_record);
        }

        let genesis_txk = TransactionKernelProxy {
            inputs: vec![],
            outputs: genesis_tx_outputs,
            fee: NativeCurrencyAmount::coins(0),
            timestamp: network.launch_date(),
            announcements: vec![],
            coinbase: Some(total_premine_amount),
            mutator_set_hash: MutatorSetAccumulator::default().hash(),
            merge_bit: false,
        }
        .into_kernel();

        let body: BlockBody = BlockBody::new(
            genesis_txk,
            genesis_mutator_set.clone(),
            MmrAccumulator::new_from_leafs(vec![]),
            MmrAccumulator::new_from_leafs(vec![]),
        );

        let header = BlockHeader::genesis(network);

        let appendix = BlockAppendix::default();

        Self::new(header, body, appendix, BlockProof::Genesis)
    }

    pub fn new(
        header: BlockHeader,
        body: BlockBody,
        appendix: BlockAppendix,
        block_proof: BlockProof,
    ) -> Self {
        let kernel = BlockKernel::new(header, body, appendix);
        Self {
            digest: OnceLock::default(), // calc'd in hash()
            kernel,
            proof: block_proof,
        }
    }

    /// Verify a block. It is assumed that `previous_block` is valid.
    /// Note that this function does **not** check that the block has enough
    /// proof of work; that must be done separately by the caller, for instance
    /// by calling [`Self::has_proof_of_work`].
    pub async fn is_valid(&self, previous_block: &Block, now: Timestamp, network: Network) -> bool {
        match self.validate(previous_block, now, network).await {
            Ok(_) => true,
            Err(e) => {
                warn!("{e}");
                false
            }
        }
    }

    /// Verify a block against previous block and return detailed error
    ///
    /// This method assumes that the previous block is valid.
    ///
    /// Note that this function does **not** check that the block has enough
    /// proof of work; that must be done separately by the caller, for instance
    /// by calling [`Self::has_proof_of_work`].
    pub async fn validate(
        &self,
        previous_block: &Block,
        now: Timestamp,
        network: Network,
    ) -> Result<(), BlockValidationError> {
        // Note that there is a correspondence between the logic here and the
        // error types in `BlockValidationError`.

        let new_height = self.header().height;
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, new_height);

        // 0.a)
        if previous_block.kernel.header.height.next() != new_height {
            return Err(BlockValidationError::BlockHeight);
        }

        // 0.b)
        if previous_block.hash() != self.kernel.header.prev_block_digest {
            return Err(BlockValidationError::PrevBlockDigest);
        }

        // 0.c)
        let mut mmra = previous_block.kernel.body.block_mmr_accumulator.clone();
        mmra.append(previous_block.hash());
        if mmra != self.kernel.body.block_mmr_accumulator {
            return Err(BlockValidationError::BlockMmrUpdate);
        }

        // 0.d)
        if previous_block.kernel.header.timestamp + network.minimum_block_time()
            > self.kernel.header.timestamp
        {
            return Err(BlockValidationError::MinimumBlockTime);
        }

        // 0.e)
        let expected_difficulty = if Self::should_reset_difficulty(
            network,
            self.header().timestamp,
            previous_block.header().timestamp,
        ) {
            network.genesis_difficulty()
        } else {
            difficulty_control(
                self.header().timestamp,
                previous_block.header().timestamp,
                previous_block.header().difficulty,
                network.target_block_interval(),
                previous_block.header().height,
            )
        };

        let new_difficulty = self.kernel.header.difficulty;
        if new_difficulty != expected_difficulty {
            return Err(BlockValidationError::Difficulty);
        }

        // 0.f)
        let delta_difficulty = if consensus_rule_set.use_parent_difficulty() {
            previous_block.header().difficulty
        } else {
            new_difficulty
        };
        let expected_cumulative_proof_of_work =
            previous_block.header().cumulative_proof_of_work + delta_difficulty;
        if self.header().cumulative_proof_of_work != expected_cumulative_proof_of_work {
            return Err(BlockValidationError::CumulativeProofOfWork);
        }

        // 0.g)
        let future_limit = now + FUTUREDATING_LIMIT;
        if self.kernel.header.timestamp >= future_limit {
            return Err(BlockValidationError::FutureDating);
        }

        // 1.a, 1.b, 1.c, 1.d
        self.validate_block_proof(network).await?;

        // 1.e)
        if self.size() > consensus_rule_set.max_block_size() {
            return Err(BlockValidationError::MaxSize);
        }

        // 1.f)
        if consensus_rule_set.requires_version_in_pow()
            && self.header().version != self.header().pow.version_in_pow()
        {
            return Err(BlockValidationError::VersionMismatch);
        }

        // 2.a)
        let inputs = RemovalRecordList::try_unpack(self.body().transaction_kernel.inputs.clone())
            .map_err(BlockValidationError::from)?;

        // 2.b)
        let msa_before = previous_block.mutator_set_accumulator_after()?;
        for removal_record in &inputs {
            if !msa_before.can_remove(removal_record) {
                return Err(BlockValidationError::RemovalRecordsValidity);
            }
        }

        // 2.t)
        if msa_before.hash() != self.body().transaction_kernel.mutator_set_hash {
            return Err(BlockValidationError::TransactionMutatorSetMismatch);
        }

        // 2.c)
        let mut absolute_index_sets = inputs
            .iter()
            .map(|removal_record| removal_record.absolute_indices.to_vec())
            .collect_vec();
        absolute_index_sets.sort();
        absolute_index_sets.dedup();
        if absolute_index_sets.len() != inputs.len() {
            return Err(BlockValidationError::RemovalRecordsUniqueness);
        }

        let mutator_set_update = MutatorSetUpdate::new(
            inputs.clone(),
            self.body().transaction_kernel.outputs.clone(),
        );
        let mut msa = msa_before;
        let ms_update_result = mutator_set_update.apply_to_accumulator(&mut msa);

        // 2.d)
        if ms_update_result.is_err() {
            return Err(BlockValidationError::MutatorSetUpdateImpossible);
        };

        // 2.e)
        if msa.hash() != self.body().mutator_set_accumulator.hash() {
            return Err(BlockValidationError::MutatorSetUpdateIntegrity);
        }

        // 2.f)
        let tx_timestamp = self.body().transaction_kernel.timestamp;
        let block_timestamp = self.header().timestamp;
        if tx_timestamp > block_timestamp
            || consensus_rule_set
                .transaction_backdating_threshold()
                .is_some_and(|limit| block_timestamp - tx_timestamp > limit)
        {
            return Err(BlockValidationError::TransactionTimestamp);
        }

        let block_subsidy = Self::block_subsidy(self.kernel.header.height);
        let coinbase = self.kernel.body.transaction_kernel.coinbase;
        if let Some(coinbase) = coinbase {
            // 2.g)
            if coinbase > block_subsidy {
                return Err(BlockValidationError::CoinbaseTooBig);
            }

            // 2.h)
            if coinbase.is_negative() {
                return Err(BlockValidationError::NegativeCoinbase);
            }
        }

        // 2.i)
        let fee = self.kernel.body.transaction_kernel.fee;
        if fee.is_negative() {
            return Err(BlockValidationError::NegativeFee);
        }

        // 2.j)
        if inputs.len() > consensus_rule_set.max_num_inputs() {
            return Err(BlockValidationError::TooManyInputs);
        }

        // 2.k)
        if self.body().transaction_kernel.outputs.len() > consensus_rule_set.max_num_outputs() {
            return Err(BlockValidationError::TooManyOutputs);
        }

        // 2.l)
        if self.body().transaction_kernel.announcements.len()
            > consensus_rule_set.max_num_announcements()
        {
            return Err(BlockValidationError::TooManyAnnouncements);
        }

        let first_lustration_block = ConsensusRuleSet::first_lustration_block(network);
        if new_height >= first_lustration_block {
            let last_aocl_leaf_index = self.body().max_aocl_leaf_index();
            let transparency_rule =
                ConsensusRuleSet::lustration_rule(network, new_height, last_aocl_leaf_index)
                    .expect("Must have transparency rule if height exceeds first such block");

            // 2.m)
            let Ok(read) = self.header().pow.lustration_status() else {
                return Err(BlockValidationError::BadLustrationCounterEncoding);
            };

            match transparency_rule {
                LustrationRule::Initial(expected) => {
                    // 2.p
                    if read.counter != expected.counter {
                        return Err(BlockValidationError::BadLustrationCounter {
                            got: read.counter,
                            expected: expected.counter,
                        });
                    }

                    // 2.q
                    if read.max_lustrating_aocl_leaf_index
                        != expected.max_lustrating_aocl_leaf_index
                    {
                        return Err(BlockValidationError::BadLustrationAoclThreshold {
                            got: read.max_lustrating_aocl_leaf_index,
                            expected: expected.max_lustrating_aocl_leaf_index,
                        });
                    }
                }
                LustrationRule::Updated { initial_counter } => {
                    // 2.n)
                    let Ok(parent) = previous_block.header().pow.lustration_status() else {
                        return Err(BlockValidationError::BadLustrationCounterEncodingOfParent);
                    };

                    // 2.q
                    if read.max_lustrating_aocl_leaf_index != parent.max_lustrating_aocl_leaf_index
                    {
                        return Err(BlockValidationError::BadLustrationAoclThreshold {
                            got: read.max_lustrating_aocl_leaf_index,
                            expected: parent.max_lustrating_aocl_leaf_index,
                        });
                    }

                    let aocl_threshold = parent.max_lustrating_aocl_leaf_index;
                    let lustration_result =
                        self.body().transaction_kernel.verified_lustration_amount(
                            aocl_threshold,
                            consensus_rule_set.fix_lustration_double_counting(),
                        );
                    let verified_lustrated_amt = match lustration_result {
                        Ok(amount) => amount,
                        // 2.o
                        Err(TransactionLustrationError::MissingLustrationAnnouncement) => {
                            return Err(BlockValidationError::MissingLustrationAnnouncement);
                        }
                        // xxx
                        Err(_) => return Err(BlockValidationError::UnknownLustrationProblem),
                    };

                    // 2.r
                    let Some(expected_counter) =
                        parent.counter.checked_sub(&verified_lustrated_amt)
                    else {
                        return Err(BlockValidationError::NegativeLustrationCounter {
                            got: -verified_lustrated_amt
                                .checked_sub(&parent.counter)
                                .expect("subtracting smaller amount from bigger amount"),
                        });
                    };

                    // I don't think this error *can* be hit without the next
                    // error also being hit. But security-in-depth!
                    // 2.s
                    if read.counter > initial_counter {
                        return Err(BlockValidationError::LustrationCounterExceedsInitialValue {
                            got: read.counter,
                            initial: initial_counter,
                        });
                    }

                    // 2.p
                    if expected_counter != read.counter {
                        return Err(BlockValidationError::BadLustrationCounter {
                            got: read.counter,
                            expected: expected_counter,
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Validate the proof of a block, an that the proof relates to the expected
    /// appendices.
    pub async fn validate_block_proof(&self, network: Network) -> Result<(), BlockValidationError> {
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, self.header().height);

        // 1.a)
        for required_claim in BlockAppendix::consensus_claims(self.body(), consensus_rule_set) {
            if !self.appendix().contains(&required_claim) {
                return Err(BlockValidationError::AppendixMissingClaim);
            }
        }

        // 1.b)
        if self.appendix().len() > MAX_NUM_CLAIMS {
            return Err(BlockValidationError::AppendixTooLarge);
        }

        // 1.c)
        let BlockProof::SingleProof(block_proof) = &self.proof else {
            return Err(BlockValidationError::ProofQuality);
        };

        // 1.d)
        if !BlockProgram::verify(self.body(), self.appendix(), block_proof, network).await {
            return Err(BlockValidationError::ProofValidity);
        }

        Ok(())
    }

    /// indicates if a difficulty reset should be performed.
    ///
    /// Reset only occurs for network(s) that define a difficulty-reset-interval,
    /// typically testnet(s).
    ///
    /// A reset should be performed any time the interval between a block
    /// and its parent block is >= the network's reset interval.
    pub fn should_reset_difficulty(
        network: Network,
        current_block_timestamp: Timestamp,
        previous_block_timestamp: Timestamp,
    ) -> bool {
        let Some(reset_interval) = network.difficulty_reset_interval() else {
            return false;
        };
        let elapsed_interval = current_block_timestamp - previous_block_timestamp;
        elapsed_interval >= reset_interval
    }

    /// Determine whether the proof-of-work puzzle was solved correctly.
    ///
    /// Specifically, compare the hash of the current block against the
    /// required target. Depending on the consensus rule set that applies, this
    /// may be either the parent block's difficulty, or the block's own
    /// difficulty. Returns true if the target is met.
    pub fn has_proof_of_work(&self, network: Network, previous_block_header: &BlockHeader) -> bool {
        // enforce network difficulty-reset-interval if present. Note that *no*
        // pow checks are enforced in this case, not even Merkle authentication
        // path checks. Consequently, very little memory is required to produce
        // blocks on networks that reset difficulty.
        if Self::should_reset_difficulty(
            network,
            self.header().timestamp,
            previous_block_header.timestamp,
        ) && self.header().difficulty == network.genesis_difficulty()
        {
            return true;
        }

        let parent_threshold = previous_block_header.difficulty.target();
        if network.allows_mock_pow() && self.is_valid_mock_pow(parent_threshold) {
            return true;
        }

        let consensus_rule_set = ConsensusRuleSet::infer_from(network, self.header().height);
        self.pow_verify(parent_threshold, consensus_rule_set)
    }

    /// Produce the MAST authentication paths for the `pow` field on
    /// [`BlockHeader`], against the block MAST hash.
    pub fn pow_mast_paths(&self) -> PowMastPaths {
        let pow = BlockHeader::mast_path(self.header(), BlockHeaderField::Pow)
            .try_into()
            .unwrap();
        let header = BlockKernel::mast_path(&self.kernel, BlockKernelField::Header)
            .try_into()
            .unwrap();
        let kernel = Block::mast_path(self, BlockField::Kernel)
            .try_into()
            .unwrap();

        PowMastPaths {
            pow,
            header,
            kernel,
        }
    }

    /// Preprocess block for PoW guessing
    pub fn guess_preprocess(
        &self,
        maybe_cancel_channel: Option<&dyn Cancelable>,
        num_guesser_threads: Option<usize>,
        consensus_rule_set: ConsensusRuleSet,
    ) -> GuesserBuffer<{ BlockPow::MERKLE_TREE_HEIGHT }> {
        // build a rayon thread pool that respects the limitation on the number
        // of threads
        let num_threads = num_guesser_threads.unwrap_or_else(rayon::current_num_threads);
        let thread_pool = ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .unwrap();

        let auth_paths = self.pow_mast_paths();
        let prev_block_digest = self.header().prev_block_digest;
        thread_pool.install(|| {
            Pow::<{ BlockPow::MERKLE_TREE_HEIGHT }>::preprocess(
                auth_paths,
                maybe_cancel_channel,
                consensus_rule_set,
                prev_block_digest,
            )
        })
    }

    /// Mock verification of Pow. Use only on networks that allow for PoW
    /// mocking. Only checks that block hash is less than target. Does not
    /// verify other aspects of PoW.
    pub fn is_valid_mock_pow(&self, target: Digest) -> bool {
        self.hash() <= target
    }

    /// Satisfy mock-PoW, meaning that only the hash needs to be lower than the
    /// threshold, does not set valid root/authentication paths of the PoW
    /// field.
    pub fn satisfy_mock_pow(
        &mut self,
        difficulty: Difficulty,
        seed: [u8; 32],
        lustration_status: Option<LustrationStatus>,
        version: BFieldElement,
    ) {
        let mut rng = StdRng::from_seed(seed);

        // Guessing loop.
        let threshold = difficulty.target();
        while !self.is_valid_mock_pow(threshold) {
            let mut pow: BlockPow = rng.random();
            if let Some(lustration_status) = lustration_status {
                pow.set_lustration_status(lustration_status);
            }

            pow.set_version_in_pow(version);

            self.set_header_pow(pow);
        }
    }

    /// Verify that block digest is less than the required threshold, and follow
    /// any other proof-of-work rules defined by the consensus rule set.
    ///
    /// Parent target is only used if the consensus rules dicate that.
    /// Otherwise, the block's own difficulty is used.
    ///
    /// Internal function. For checking if a block has sufficient proof of work,
    /// you should use [`Self::has_proof_of_work`] instead since that function
    /// automatically uses the correct consensus rule set.
    fn pow_verify(&self, parent_target: Digest, consensus_rule_set: ConsensusRuleSet) -> bool {
        let target = if consensus_rule_set.use_parent_difficulty() {
            parent_target
        } else {
            self.header().difficulty.target()
        };
        let auth_paths = self.pow_mast_paths();
        self.header()
            .pow
            .validate(
                auth_paths,
                target,
                consensus_rule_set,
                self.header().prev_block_digest,
            )
            .is_ok()
    }

    pub fn set_header_pow(&mut self, pow: BlockPow) {
        self.kernel.header.pow = pow;
        self.unset_digest();
    }

    /// Evaluate the fork choice rule.
    ///
    /// Given two blocks, determine which one is more canonical. This function
    /// evaluates the following logic:
    ///  - if the height is different, prefer the block with more accumulated
    ///    proof-of-work;
    ///  - otherwise, if exactly one of the blocks' transactions has no inputs,
    ///    reject that one;
    ///  - otherwise, prefer the current tip.
    ///
    /// This function assumes the blocks are valid and have the self-declared
    /// accumulated proof-of-work.
    ///
    /// This function is called exclusively in
    /// `GlobalState::incoming_block_is_more_canonical`, which is in turn
    /// called in two places:
    ///  1. In `peer_loop`, when a peer sends a block. The `peer_loop` task only
    ///     sends the incoming block to the `main_loop` if it is more canonical.
    ///  2. In `main_loop`, when it receives a block from a `peer_loop` or from
    ///     the `mine_loop`. It is possible that despite (1), race conditions
    ///     arise, and they must be solved here.
    pub fn fork_choice_rule<'a>(current_tip: &'a Self, incoming_block: &'a Self) -> &'a Self {
        if current_tip.header().height != incoming_block.header().height {
            if current_tip.header().cumulative_proof_of_work
                >= incoming_block.header().cumulative_proof_of_work
            {
                current_tip
            } else {
                incoming_block
            }
        } else if current_tip.body().transaction_kernel.inputs.is_empty() {
            incoming_block
        } else {
            current_tip
        }
    }

    /// Size in number of BFieldElements of the block
    // Why defined in terms of BFieldElements and not bytes? Anticipates
    // recursive block validation, where we need to test a block's size against
    // the limit. The size is easier to calculate if it relates to a block's
    // encoding on the VM, rather than its serialization as a vector of bytes.
    pub(crate) fn size(&self) -> usize {
        self.encode().len()
    }

    /// A number showing how big the guesser reward is relative to the block
    /// subsidy.  Notice that this number can exceed 1 because of transaction
    /// fees.
    ///
    /// May not be used in any consensus-related setting, as precision is lost
    /// because of the use of floats.
    pub fn relative_guesser_reward(&self) -> Result<f64, BlockValidationError> {
        let guesser_reward = self.body().total_guesser_reward()?;
        let block_subsidy = Self::block_subsidy(self.header().height);

        Ok(guesser_reward.to_nau_f64() / block_subsidy.to_nau_f64())
    }

    /// Compute the addition records that correspond to the UTXOs generated for
    /// the block's guesser
    ///
    /// The genesis block does not have this addition record.
    pub fn guesser_fee_addition_records(
        &self,
    ) -> Result<Vec<AdditionRecord>, BlockValidationError> {
        let block_hash = self.hash();
        self.kernel.guesser_fee_addition_records(block_hash)
    }

    /// Return all addition records (transaction outputs) in this block,
    /// including guesser rewards.
    pub fn all_addition_records(&self) -> Result<Vec<AdditionRecord>, BlockValidationError> {
        let block_hash = self.hash();
        self.kernel.all_addition_records(block_hash)
    }

    /// Return the mutator set update corresponding to this block, which sends
    /// the mutator set accumulator after the predecessor to the mutator set
    /// accumulator after self.
    pub fn mutator_set_update(&self) -> Result<MutatorSetUpdate, BlockValidationError> {
        let block_hash = self.hash();
        self.kernel.mutator_set_update(block_hash)
    }

    /// Compute the total supply of coins that were liquid immediately after
    /// being mined.
    pub fn mined_immediately_liquid_supply(current_height: BlockHeight) -> NativeCurrencyAmount {
        Self::mined_supply(current_height).half()
    }

    /// Compute the total supply of coins that were time-locked after mining and
    /// are now (heuristically) released.
    ///
    /// The heuristic is to pretend that the blocks came in spaced apart by
    /// exactly the target block interval. This model allows us to consider as
    /// as expired the time-locks on subsidies for blocks more than one full
    /// generation (`BLOCKS_PER_GENERATION`) ago, and all other time-locks still
    /// in effect. In practice, the time-locks are released at a timestamp (not
    /// a block height) and that timestamp does not need  to coincide with
    /// exactly one full generation since the block was mined.
    pub fn mined_timelocked_and_released_supply(
        current_height: BlockHeight,
    ) -> NativeCurrencyAmount {
        let one_generation_ago =
            BlockHeight::from(current_height.value().saturating_sub(BLOCKS_PER_GENERATION));
        Self::mined_supply(one_generation_ago).half()
    }

    /// Compute the total mined money supply at a given block height, measured
    /// in number of Neptune coins.
    ///
    /// The number does not count
    ///  - the original premine,
    ///  - the claims fund or claims, and
    ///  - burns.
    ///
    /// It *does* count time-locked coins.
    ///
    /// This number is computed via arithmetic and geometric sums, implicitly
    /// assuming that the miners rationally mint the maximum allowable coinbase.
    pub fn mined_supply(current_height: BlockHeight) -> NativeCurrencyAmount {
        // The first generation is special because of the genesis block and
        // because of the skipped blocks due to reboot.
        let num_blocks_in_generation_zero =
            BLOCKS_PER_GENERATION - NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT;
        if num_blocks_in_generation_zero > current_height.into() {
            // Number of blocks mined in this generation is equal to current
            // block height because the genesis block (height 0) is not mined.
            let num_mined_blocks = u64::from(current_height);
            return INITIAL_BLOCK_SUBSIDY.scalar_mul(num_mined_blocks.try_into().unwrap());
        }

        // Nothing is mined in genesis block. All other blocks in generation
        // zero did mine.
        let num_coins_mined_in_generation_zero = INITIAL_BLOCK_SUBSIDY
            .scalar_mul(u32::try_from(num_blocks_in_generation_zero).unwrap() - 1);
        let mut total = num_coins_mined_in_generation_zero;

        // Account for the blocks skipped because of the reboot. Do this by
        // offsetting the current high so that we get clean wrap arounds modulo
        // the number of blocks per generation.
        let effective_block_height: u64 = u64::from(current_height) - num_blocks_in_generation_zero;
        let current_generation = 1 + effective_block_height / BLOCKS_PER_GENERATION;
        let current_block_in_generation = (effective_block_height) % BLOCKS_PER_GENERATION;

        // Generation 40 is the first generation where precision is lost in the
        // block subsidy. From that generation onwards, the geometric sum is not
        // exact. So we use the geometric sum up until generation 39 and switch
        // to an iterative rectangular formula after that.
        let max_generation = 39;

        // In the following we need the geometric sum. The formula is
        // re-derived for your convenience here.
        // L = sum from { i = 1 } to { C-1 } of { I * B / 2^i }
        // L / 2 = B * sum from { i = 1 } to { C-1 } of { I / 2^(i+1) }
        // L / 2 = B * sum from { i = 2 } to { C } of { I / 2^i }
        // L - L / 2 = B * ( I/2 - I/2^C ) = L / 2 .
        // So L = 2 * B * (I/2 - I/2^C) .

        // Compute the total mined coins from all complete generations, except
        // 0, and up to 40, using the geometric sum with
        //  - I = INITIAL_BLOCK_SUBSIDY
        //  - B = BLOCKS_PER_GENERATION
        //  - C = current_generation.
        let mut final_block_subsidy = NativeCurrencyAmount::from_nau(
            INITIAL_BLOCK_SUBSIDY.to_nau() >> u64::min(max_generation, current_generation),
        );
        total += (INITIAL_BLOCK_SUBSIDY
            .half()
            .checked_sub(&final_block_subsidy)
            .unwrap())
        .scalar_mul(2 * u32::try_from(BLOCKS_PER_GENERATION).unwrap());

        // If we are in a generation beyond the point where precision is lost,
        // iterate over all generations between 40 and now and compute a
        // contribution per generation.
        if current_generation > max_generation {
            for _ in max_generation..current_generation {
                total +=
                    final_block_subsidy.scalar_mul(u32::try_from(BLOCKS_PER_GENERATION).unwrap());
                final_block_subsidy = final_block_subsidy.half();
            }
        }

        // Count the liquid mined coins in the current (incomplete) generation
        // using the rectangular formula.
        total +=
            final_block_subsidy.scalar_mul(u32::try_from(current_block_in_generation).unwrap() + 1);

        total
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl rand::distr::Distribution<Block> for rand::distr::StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Block {
        use crate::protocol::consensus::transaction::validity::neptune_proof::NeptuneProof;

        let kernel = rng.random::<BlockKernel>();
        let proof = BlockProof::SingleProof(NeptuneProof::from(
            (0..10).map(|_| rng.random()).collect_vec(),
        ));
        let digest = OnceLock::new();
        Block {
            kernel,
            proof,
            digest,
        }
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl Block {
    pub fn set_proof(&mut self, proof: BlockProof) {
        self.proof = proof;
        self.unset_digest();
    }

    /// Create a block template with an invalid block proof.
    ///
    /// To be used in tests where you don't care about block validity.
    pub fn block_template_invalid_proof(
        predecessor: &Block,
        block_transaction: BlockTransaction,
        block_timestamp: Timestamp,
        override_target_block_interval: Option<Timestamp>,
        network: Network,
    ) -> Block {
        let primitive_witness =
            BlockPrimitiveWitness::new(predecessor.to_owned(), block_transaction, network);
        let target_block_interval =
            override_target_block_interval.unwrap_or(network.target_block_interval());
        Self::block_template_invalid_proof_from_witness(
            primitive_witness,
            block_timestamp,
            target_block_interval,
        )
    }

    /// Create a block template with an invalid block proof, from a block
    /// primitive witness.
    pub(crate) fn block_template_invalid_proof_from_witness(
        primitive_witness: BlockPrimitiveWitness,
        block_timestamp: Timestamp,
        target_block_interval: Timestamp,
    ) -> Block {
        let body = primitive_witness.body().to_owned();
        let header = primitive_witness.header(block_timestamp, target_block_interval);
        let proof = BlockProof::Invalid;
        let appendix = BlockAppendix::default();

        Block::new(header, body, appendix, proof)
    }
}

#[cfg(any(test, feature = "test-helpers"))]
pub const DIFFICULTY_LIMIT_FOR_TESTS: u32 = 20_000;

#[cfg(any(test, feature = "test-helpers"))]
mod test_support {
    use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;

    use super::*;
    use crate::protocol::consensus::block::proof_of_work_puzzle::ProofOfWorkPuzzle;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::protocol::proof_abstractions::triton_vm_job_queue::vm_job_queue;

    impl Block {
        /// Return all absolute index sets (transaction inputs) in this block.
        pub fn all_absolute_index_sets(&self) -> Vec<AbsoluteIndexSet> {
            self.body()
                .transaction_kernel
                .inputs
                .iter()
                .map(|x| x.absolute_indices)
                .collect()
        }

        pub fn fix_mutator_set_fields(&mut self, prev_block: &Block) {
            let mut msa = prev_block.mutator_set_accumulator_after().unwrap();

            let new_kernel = TransactionKernelModifier::default()
                .mutator_set_hash(msa.hash())
                .modify(self.kernel.body.transaction_kernel.clone());
            self.kernel.body.transaction_kernel = new_kernel;

            let ms_update = MutatorSetUpdate::new(
                self.body().transaction_kernel.inputs.clone(),
                self.body().transaction_kernel.outputs.clone(),
            );

            ms_update.apply_to_accumulator(&mut msa).unwrap();
            self.kernel.body.mutator_set_accumulator = msa;
            self.unset_digest();
        }

        pub fn set_appendix(&mut self, appendix: BlockAppendix) {
            self.kernel.appendix = appendix;
            self.unset_digest();
        }

        /// Produce two fake blocks, parent and child.
        pub async fn fake_block_pair_genesis_and_child_from_witness(
            primitive_witness: BlockPrimitiveWitness,
        ) -> (Block, Block) {
            let mut fake_genesis = primitive_witness.predecessor_block().to_owned();
            fake_genesis.proof = BlockProof::Genesis;
            let block_timestamp = primitive_witness.transaction().kernel.timestamp;
            let fake_child = Self::block_template_from_block_primitive_witness(
                primitive_witness,
                block_timestamp,
                vm_job_queue(),
                TritonVmProofJobOptions::default(),
            )
            .await
            .unwrap();

            (fake_genesis, fake_child)
        }

        /// Satisfy PoW for this block. Only to be used for tests since this
        /// function cannot be cancelled. Deterministic, will always return the
        /// same solution for the same input.
        pub fn satisfy_pow(
            &mut self,
            parent_difficulty: Difficulty,
            consensus_rule_set: ConsensusRuleSet,
        ) {
            let difficulty = if consensus_rule_set.use_parent_difficulty() {
                parent_difficulty
            } else {
                self.header().difficulty
            };

            println!("Trying to guess for difficulty: {difficulty}");
            assert!(
                difficulty < Difficulty::from(DIFFICULTY_LIMIT_FOR_TESTS),
                "Don't use high difficulty in test. Got: {difficulty}"
            );

            let puzzle = ProofOfWorkPuzzle::new(self.clone(), difficulty);
            let valid_pow = puzzle.solve(consensus_rule_set);

            self.set_header_pow(valid_pow);
        }

        /// Check if PoW requirement has been fulfilled, allowing for the
        /// overriding of the consensus rule set.
        pub fn pow_verify_for_tests(
            &self,
            parent_target: Digest,
            consensus_rule_set: ConsensusRuleSet,
        ) -> bool {
            self.pow_verify(parent_target, consensus_rule_set)
        }

        #[inline]
        pub fn set_header_height(&mut self, block_height: BlockHeight) {
            self.kernel.header.height = block_height;

            self.unset_digest();
        }

        pub fn set_header_version_in_pow_only(&mut self, value: BFieldElement) {
            self.kernel.header.pow.set_version_in_pow(value);

            self.unset_digest();
        }

        pub fn set_version_in_header_only(&mut self, value: BFieldElement) {
            self.kernel.header.version = value;

            self.unset_digest();
        }

        pub fn set_version_consistently(&mut self, value: BFieldElement) {
            self.kernel.header.version = value;
            self.kernel.header.pow.set_version_in_pow(value);

            self.unset_digest();
        }
    }
}

#[cfg(any(test, feature = "test-helpers"))]
proptest::prop_compose! {
    /// Relies on the private fields hence is here for re-export via `tests::shared::strategies`.
    pub fn arbitrary_kernel() (
        header in proptest_arbitrary_interop::arb::<BlockHeader>(),
        transaction_kernel in crate::protocol::consensus::transaction::test_helpers::txkernel::default(true),
        lock_free_mmr_accumulator in proptest_arbitrary_interop::arb::<MmrAccumulator>(),
        block_mmr_accumulator in proptest_arbitrary_interop::arb::<MmrAccumulator>(),
        appendix in proptest_arbitrary_interop::arb::<BlockAppendix>(),
        mutator_set_accumulator in proptest_arbitrary_interop::arb::<MutatorSetAccumulator>(),
    ) -> Block {
        Block {
            kernel: BlockKernel {
                header, body: BlockBody::new(
                    transaction_kernel,
                    mutator_set_accumulator,
                    lock_free_mmr_accumulator,
                    block_mmr_accumulator
                ),
                appendix
            },
            proof: Default::default(),
            digest: Default::default(),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {

    use proptest_arbitrary_interop::arb;
    use rand::rng;
    use rand::Rng;
    use strum::IntoEnumIterator;

    use super::*;
    use crate::protocol::consensus::block::test_helpers::invalid_empty_block;
    use crate::protocol::consensus::network::Network;
    use crate::protocol::consensus::type_scripts::native_currency::NativeCurrency;
    use crate::protocol::consensus::type_scripts::TypeScript;

    #[test]
    fn all_genesis_blocks_have_unique_sender_randomnesses() {
        assert!(
            Network::all_networks()
                .map(Block::premine_sender_randomness)
                .all_unique(),
            "All genesis blocks must have unique sender randomness for the premine UTXOs",
        );
    }

    #[test]
    fn all_genesis_blocks_have_unique_mutator_set_hashes() {
        let mutator_set_hash = |network| {
            Block::genesis(network)
                .body()
                .mutator_set_accumulator
                .hash()
        };

        assert!(
            Network::all_networks().map(mutator_set_hash).all_unique(),
            "All genesis blocks must have unique MSA digests, else replay attacks are possible",
        );
    }

    #[test]
    fn guess_nonce_happy_path() {
        let network = Network::Main;
        let genesis = Block::genesis(network);
        let parent_target = genesis.header().difficulty.target();

        for consensus_rule_set in ConsensusRuleSet::iter() {
            let mut invalid_block = invalid_empty_block(&genesis, network);
            let mast_auth_paths = invalid_block.pow_mast_paths();
            let guesser_buffer = invalid_block.guess_preprocess(None, None, consensus_rule_set);
            let target = if consensus_rule_set.use_parent_difficulty() {
                parent_target
            } else {
                invalid_block.header().difficulty.target()
            };
            let mut rng = rng();
            let index_picker_preimage = guesser_buffer.index_picker_preimage(&mast_auth_paths);

            let version = invalid_block.header().version;

            let valid_pow = loop {
                if let Some(valid_pow) = Pow::guess(
                    &guesser_buffer,
                    &mast_auth_paths,
                    index_picker_preimage,
                    rng.random(),
                    target,
                    None,
                    Some(version),
                ) {
                    break valid_pow;
                }
            };

            assert!(
                !invalid_block.pow_verify(parent_target, consensus_rule_set),
                "Pow verification must fail prior to setting PoW"
            );
            invalid_block.set_header_pow(valid_pow);
            assert!(
                invalid_block.pow_verify(parent_target, consensus_rule_set,),
                "pow for {consensus_rule_set} rules must be satisfied after correct guess"
            );
        }
    }

    #[test]
    fn halving_happens_when_expected() {
        // 1st halving should happen at block height `BLOCKS_PER_GENERATION` =
        // 160.815, minus `NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT` = 21310. So at
        // block height 139505, with that block being the first to have half the
        // block subsidy of the initial block subsidy. The first block to have a
        // quarter of the initial block subsidy should be of height 300320 =
        // `2 * BLOCKS_PER_GENERATION - NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT`.
        assert_eq!(INITIAL_BLOCK_SUBSIDY, Block::block_subsidy(bfe!(2).into()));
        assert_eq!(
            INITIAL_BLOCK_SUBSIDY,
            Block::block_subsidy(bfe!(100_000).into())
        );
        assert_eq!(
            INITIAL_BLOCK_SUBSIDY,
            Block::block_subsidy(bfe!(130_000).into())
        );
        assert_eq!(
            INITIAL_BLOCK_SUBSIDY,
            Block::block_subsidy(bfe!(139_503).into())
        );
        assert_eq!(
            INITIAL_BLOCK_SUBSIDY,
            Block::block_subsidy(bfe!(139_504).into())
        );
        assert_eq!(
            INITIAL_BLOCK_SUBSIDY.half(),
            Block::block_subsidy(bfe!(139_505).into())
        );
        assert_eq!(
            INITIAL_BLOCK_SUBSIDY.half(),
            Block::block_subsidy(bfe!(139_506).into())
        );
        assert_eq!(
            INITIAL_BLOCK_SUBSIDY.half(),
            Block::block_subsidy(bfe!(300_319).into())
        );
        assert_eq!(
            INITIAL_BLOCK_SUBSIDY.half().half(),
            Block::block_subsidy(bfe!(300_320).into())
        );
        assert_eq!(
            INITIAL_BLOCK_SUBSIDY.half().half(),
            Block::block_subsidy(bfe!(300_321).into())
        );
    }

    proptest::proptest! {
        #[test]
        fn block_subsidy_calculation_terminates(height_arb in arb::<BFieldElement>()) {
            Block::block_subsidy(BFieldElement::MAX.into());

            Block::block_subsidy(height_arb.into());
        }
    }

    #[test]
    fn block_subsidy_generation_0() {
        let block_height_generation_0 = 199u64.into();
        assert_eq!(
            NativeCurrencyAmount::coins(128),
            Block::block_subsidy(block_height_generation_0)
        );
    }

    #[test]
    fn observed_total_mining_reward_matches_block_subsidy() {
        // Data read from a node composing and guessing on test net. It
        // composed and guessed block number #115 and got four UTXOs, where the
        // native currency type script recorded these states. Those states must
        // sum to the total block subsidy for generation 0, 128 coins. This
        // were the recorded states for block
        // a1cd0ea9103c19444dd0342e7c772b0a02ed610b71a73ea37e4fe48357c619bb4fa0c3e866000000
        let state0 = [0u64, 980281920, 2521720867, 1615].map(BFieldElement::new);
        let state1 = [0u64, 980281920, 2521720867, 1615].map(BFieldElement::new);
        let state2 = [0u64, 981467136, 2521720867, 1615].map(BFieldElement::new);
        let state3 = [0u64, 981467136, 2521720867, 1615].map(BFieldElement::new);

        let mut total_amount = NativeCurrencyAmount::zero();
        for state in [state0, state1, state2, state3] {
            total_amount += *NativeCurrency.try_decode_state(&state).unwrap();
        }

        assert_eq!(NativeCurrencyAmount::coins(128), total_amount);
    }

    #[test]
    fn difficulty_to_threshold_test() {
        // Verify that a difficulty of 2 accepts half of the digests
        let difficulty: u32 = 2;
        let difficulty_u32s = Difficulty::from(difficulty);
        let threshold_for_difficulty_two: Digest = difficulty_u32s.target();

        for elem in threshold_for_difficulty_two.values() {
            assert_eq!(BFieldElement::MAX / u64::from(difficulty), elem.value());
        }

        // Verify that a difficulty of BFieldElement::MAX accepts all digests where the
        // last BFieldElement is zero
        let some_difficulty = Difficulty::new([1, u32::MAX, 0, 0, 0]);
        let some_threshold_actual: Digest = some_difficulty.target();

        let bfe_max_elem = BFieldElement::new(BFieldElement::MAX);
        let some_threshold_expected = Digest::new([
            bfe_max_elem,
            bfe_max_elem,
            bfe_max_elem,
            bfe_max_elem,
            BFieldElement::zero(),
        ]);

        assert_eq!(0u64, some_threshold_actual.values()[4].value());
        assert_eq!(some_threshold_actual, some_threshold_expected);
        assert_eq!(bfe_max_elem, some_threshold_actual.values()[3]);
    }

    /// This module has tests that verify a block's digest
    /// is always in a correct state.
    ///
    /// All operations that create or modify a Block should
    /// have a test here.
    mod digest_encapsulation {

        use super::*;
        use crate::protocol::consensus::transaction::validity::neptune_proof::NeptuneProof;

        // test: verify clone + modify does not change original.
        //
        // note: a naive impl that derives `Clone` on `Block` containing
        //       `Arc<Mutex<Option<Digest>>>` would link the digest in the clone
        #[test]
        fn clone_and_modify() {
            let gblock = Block::genesis(Network::RegTest);
            let g_hash = gblock.hash();

            let mut g2 = gblock.clone();
            assert_eq!(gblock.hash(), g_hash);
            assert_eq!(gblock.hash(), g2.hash());

            g2.set_header_pow(Default::default());
            assert_ne!(gblock.hash(), g2.hash());
            assert_eq!(gblock.hash(), g_hash);
        }

        // test: verify digest is correct after Block::new().
        #[test]
        fn new() {
            let gblock = Block::genesis(Network::RegTest);
            let g2 = gblock.clone();

            let block = Block::new(
                g2.kernel.header,
                g2.kernel.body,
                g2.kernel.appendix,
                g2.proof,
            );
            assert_eq!(gblock.hash(), block.hash());
        }

        #[test]
        fn hash_depends_on_proof() {
            let network = Network::Main;
            let mut block = invalid_empty_block(&Block::genesis(network), network);
            let original_hash = block.hash();
            block.set_proof(BlockProof::SingleProof(NeptuneProof::invalid_with_size(65)));
            assert_ne!(original_hash, block.hash());
        }

        // test: verify digest changes after pow is updated.
        #[test]
        fn set_header_pow() {
            let gblock = Block::genesis(Network::RegTest);
            let mut rng = rand::rng();

            let mut new_block = gblock.clone();
            new_block.set_header_pow(rng.random());
            assert_ne!(gblock.hash(), new_block.hash());
        }

        // test: verify digest is correct after deserializing
        #[test]
        fn deserialize() {
            let gblock = Block::genesis(Network::RegTest);

            let bytes = bincode::serialize(&gblock).unwrap();
            let block: Block = bincode::deserialize(&bytes).unwrap();

            assert_eq!(gblock.hash(), block.hash());
        }

        // test: verify block digest matches after BFieldCodec encode+decode
        //       round trip.
        #[test]
        fn bfieldcodec_encode_and_decode() {
            let gblock = Block::genesis(Network::RegTest);

            let encoded: Vec<BFieldElement> = gblock.encode();
            let decoded: Block = *Block::decode(&encoded).unwrap();

            assert_eq!(gblock, decoded);
            assert_eq!(gblock.hash(), decoded.hash());
        }
    }

    mod currency_supply {
        use proptest::prop_assert_eq;
        use test_strategy::proptest;

        use super::*;

        /// Compute the liquid mined money supply at a given block height,
        /// measured in number of Neptune coins. This is a slow, but explicit,
        /// algorithm for computing (hopefully) the same result as
        /// [`Block::mined_supply`]. That's "hopefully" because this
        /// method is what that faster one is being tested against.
        pub(crate) fn mined_supply_slow(current_height: BlockHeight) -> NativeCurrencyAmount {
            // Nothing is mined in genesis block.
            let mut total = NativeCurrencyAmount::coins(0);

            // For all blocks until and including now (but skipping the genesis)
            // block, add the block subsidy.
            let mut last_generation = BlockHeight::genesis().get_generation();
            for height in 1_u64..=current_height.into() {
                if BlockHeight::from(height).get_generation() != last_generation {
                    last_generation = BlockHeight::from(height).get_generation();
                }
                total += Block::block_subsidy(height.into());
            }

            total
        }

        #[proptest(cases = 4)]
        fn fast_and_slow_methods_for_supply_agree_prop(
            #[strategy(0u64..=20584320)] current_block_height: u64,
        ) {
            prop_assert_eq!(
                Block::mined_supply(current_block_height.into()).to_nau(),
                mined_supply_slow(current_block_height.into()).to_nau()
            );
        }

        #[test]
        fn fast_and_slow_methods_for_supply_agree_unit() {
            for current_block_height in [
                1395, 13950, 80827, 139505, 6057182, 7957182, 209766, 220232, 300320, 20584320,
            ] {
                println!("testing current block height {current_block_height} ...");
                assert_eq!(
                    Block::mined_supply(current_block_height.into()).to_nau(),
                    mined_supply_slow(current_block_height.into()).to_nau()
                );
            }
        }

        #[test]
        fn mined_supply_has_sane_limit() {
            let claims_pool = INITIAL_BLOCK_SUBSIDY
                .scalar_mul(u32::try_from(NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT).unwrap());
            let premine_max_size = PREMINE_MAX_SIZE;

            let very_far_future = BLOCKS_PER_GENERATION * 128;
            let total_mined = mined_supply_slow(very_far_future.into());

            assert!(
                (total_mined + premine_max_size + claims_pool)
                    <= NativeCurrencyAmount::coins(42000000)
            );

            // total: 41999999.9999999999999999999999985124612500
            println!(
                "total: {}",
                (total_mined + premine_max_size + claims_pool).display_lossless()
            );

            assert_eq!(
                (total_mined + premine_max_size + claims_pool).display_n_decimals(20),
                NativeCurrencyAmount::coins(42000000).display_n_decimals(20),
                "total mined: {}\npremine max size: {}\nclaims pool: {}\nsum is {}",
                total_mined.display_n_decimals(20),
                premine_max_size.display_n_decimals(20),
                claims_pool.display_n_decimals(20),
                (total_mined + premine_max_size + claims_pool).display_n_decimals(20)
            );
        }
    }
}
