use std::sync::OnceLock;

use get_size2::GetSize;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_primitives::block_height::BlockHeight;
use neptune_primitives::difficulty_control::Difficulty;
use neptune_primitives::difficulty_control::ProofOfWork;
use neptune_primitives::mast_hash::MastHash;
use neptune_primitives::network::Network;
use neptune_primitives::timestamp::Timestamp;
use num_bigint::BigUint;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::arithmetic::i128::lt::Lt as I128Lt;
use tasm_lib::arithmetic::u128::sub::Sub as U128Sub;
use tasm_lib::arithmetic::u160::lt::Lt as U160Lt;
use tasm_lib::arithmetic::u192::safe_add::SafeAdd as U192SafeAdd;
use tasm_lib::arithmetic::u64::add::Add as U64Add;
use tasm_lib::arithmetic::u64::lt::Lt as U64Lt;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::hashing::hash_from_stack::HashFromStack;
use tasm_lib::hashing::merkle_root::MerkleRoot;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::library::Library;
use tasm_lib::list::new::New;
use tasm_lib::list::push::Push;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::memcpy::MemCpy;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::mmr::calculate_new_peaks_from_append::CalculateNewPeaksFromAppend;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::twenty_first::prelude::Mmr;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::verifier::own_program_digest::OwnProgramDigest;
use tasm_lib::verifier::stark_verify::StarkVerify;

use super::apply_addition_records::ApplyAdditionRecords;
use super::block_program::BlockProgram;
use super::block_subsidy::BlockSubsidy;
use super::difficulty_control::DifficultyControl;
use super::epoch_table::Epoch;
use super::epoch_table::EpochTable;
use super::epoch_table::NUM_EPOCHS;
use super::guesser_fee_addition_records::GuesserFeeAdditionRecords;
use super::meets_threshold::MeetsThreshold;
use super::mutator_set_hash::MutatorSetHash;
use super::mutator_set_hash::MutatorSetHashFromComponents;
use super::mutator_set_update_from_state_hash::MutatorSetUpdateFromStateHash;
use super::removal_records_are_unique::RemovalRecordsAreUnique;
use super::swbf_update::leaf::CorrectSwbfUpdate;
use super::swbf_update::removal_index_commitment::RemovalIndexCommitment;
use super::swbf_update::swbfi_peaks_after_removals::SwbfiPeaksAfterRemovals;
use super::swbf_update::INPUT_FIRST_LEAF_INDEX;
use super::swbf_update::INPUT_LEN;
use super::swbf_update::OUTPUT_COUNT;
use super::swbf_update::OUTPUT_MUTATOR_SET_HASH;
use super::swbf_update::OUTPUT_NUM_PEAKS;
use super::swbf_update::OUTPUT_PADDED_ROWS;
use super::swbf_update::OUTPUT_PEAKS;
use super::swbfi_reveal::GuesserSwbfiReveal;
use super::verified_lustration_amount::VerifiedLustrationAmount;
use crate::block::block_appendix::BlockAppendix;
use crate::block::block_appendix::MAX_NUM_CLAIMS;
use crate::block::block_body::BlockBody;
use crate::block::block_body::BlockBodyField;
use crate::block::block_body::NUM_GUESSER_FEE_OUTPUTS;
use crate::block::block_header::BlockHeader;
use crate::block::block_header::BlockPow;
use crate::block::block_validation_error::BlockValidationRule;
use crate::block::pow::LustrationStatus;
use crate::block::pow::PowValidationError;
use crate::block::pow::POW_MEMORY_TREE_HEIGHT;
use crate::block::Block;
use crate::block::BlockProof;
use crate::consensus_rule_set::ConsensusRuleSet;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::transaction::announcement::RETIREMENT_FLAG;
use crate::transaction::transaction_kernel::TransactionKernel;
use crate::transaction::transaction_kernel::LUSTRATION_FLAG;
use crate::transaction::validity::single_proof::single_proof_claim;
use crate::transaction::validity::tasm::claims::generate_single_proof_claim::GenerateSingleProofClaim;
use crate::transaction::validity::tasm::claims::new_claim::NewClaim;
use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

/// The witness for [`PredecessorIsValid`]: the previous block, the next
/// block's body, and the mutator set the previous block's transaction is
/// built on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PredecessorIsValidWitness {
    prev_block: Block,
    next_block_body: BlockBody,
    prev_block_transaction_mutator_set: MutatorSetAccumulator,

    /// SWBFI peaks after the previous block's removals.
    prev_block_swbfi_peaks_after_removals: Vec<Digest>,
}

impl PredecessorIsValidWitness {
    /// The mutator set is the one after the previous block's predecessor.
    /// It is only read when the previous block is at or past the activation
    /// height, whose copy of the claim then attests to it.
    pub fn new(
        prev_block: &Block,
        next_block_body: &BlockBody,
        prev_block_transaction_mutator_set: MutatorSetAccumulator,
    ) -> Self {
        // From the kernel's own chunks, where it carries them and they apply;
        // empty otherwise, to be supplied.
        let prev_block_swbfi_peaks_after_removals = SwbfiPeaksAfterRemovals::try_apply_removals(
            &prev_block.body().transaction_kernel.inputs,
            &prev_block_transaction_mutator_set,
        )
        .map(|mutator_set_after| mutator_set_after.swbf_inactive.peaks())
        .unwrap_or_default();

        Self {
            prev_block: prev_block.clone(),
            next_block_body: next_block_body.clone(),
            prev_block_transaction_mutator_set,
            prev_block_swbfi_peaks_after_removals,
        }
    }

    /// With these peaks of the inactive SWBF after the previous block's
    /// removals, for a block whose kernel carries its inputs without chunks.
    pub fn with_swbfi_peaks_after_removals(mut self, peaks: Vec<Digest>) -> Self {
        self.prev_block_swbfi_peaks_after_removals = peaks;
        self
    }

    /// Under the network's table.
    pub fn nondeterminism(&self, program: &PredecessorIsValid, network: Network) -> NonDeterminism {
        self.nondeterminism_under(program, &ConsensusRuleSet::epoch_table(network))
    }

    fn nondeterminism_under(
        &self,
        program: &PredecessorIsValid,
        epochs: &EpochTable,
    ) -> NonDeterminism {
        let mut nondeterminism = NonDeterminism::default();
        encode_to_memory(
            &mut nondeterminism.ram,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            &PredecessorIsValidWitnessMemory::from(self),
        );

        // 0.a, 0.c)
        nondeterminism.digests.extend_from_slice(
            &self
                .next_block_body
                .mast_path(BlockBodyField::BlockMmrAccumulator),
        );

        if program.verifies_prev_block_proof {
            // 1.d)
            if let BlockProof::SingleProof(prev_block_proof) = &self.prev_block.proof {
                let prev_block_claim = BlockProgram::claim(
                    self.prev_block.body(),
                    self.prev_block.appendix(),
                    ConsensusRuleSet::HardforkDelta,
                );
                StarkVerify::new_with_dynamic_layout(Stark::default()).update_nondeterminism(
                    &mut nondeterminism,
                    prev_block_proof,
                    &prev_block_claim,
                );
            }
        }

        // 2.c)
        nondeterminism
            .individual_tokens
            .extend(RemovalRecordsAreUnique::divined_tokens(
                &self.prev_block.body().transaction_kernel.inputs,
            ));

        let prev_block_height = self.prev_block.header().height;
        if prev_block_height >= epochs.activation_height() {
            // 0.e)
            nondeterminism
                .individual_tokens
                .extend(DifficultyControl::divined_tokens(
                    epochs.in_force_at(prev_block_height).target_block_interval,
                    prev_block_height.previous().unwrap(),
                ));

            // 2.a, 2.b, 2.e)
            nondeterminism
                .individual_tokens
                .extend(MutatorSetUpdateFromStateHash::divined_tokens(
                    &self.prev_block.body().transaction_kernel.inputs,
                    &self.prev_block_transaction_mutator_set,
                    &self.prev_block_swbfi_peaks_after_removals,
                ));

            // 2.o)
            let prev_epoch = epochs.in_force_at(prev_block_height);
            let prev_block_resets_lustration_status = prev_epoch.resets_lustration_status.value()
                != 0
                && prev_epoch.height.value() == prev_block_height.value();
            let status = self.prev_block.header().pow.lustration_status();
            if let (Ok(status), false) = (status, prev_block_resets_lustration_status) {
                let kernel = &self.prev_block.body().transaction_kernel;
                nondeterminism
                    .individual_tokens
                    .extend(VerifiedLustrationAmount::divined_tokens(
                        &kernel.inputs,
                        &kernel.announcements,
                        status.max_lustrating_aocl_leaf_index,
                    ));
            }
        }

        nondeterminism
    }
}

/// The part of the witness the program reads from memory.
#[derive(Debug, Clone, PartialEq, Eq, BFieldCodec, TasmObject)]
struct PredecessorIsValidWitnessMemory {
    /// Merkle-verified against the next block's body hash, the public input.
    next_block_mmr_accumulator: MmrAccumulator,

    /// Hashed into the previous block's hash, which rule 0.c ties to the next
    /// block's MMR.
    prev_block_header: BlockHeader,

    /// As [Self::prev_block_header]. Plus verified through rule 1.d on the
    /// previous block.
    prev_block_body: BlockBody,

    /// As [Self::prev_block_header].
    prev_block_appendix: BlockAppendix,

    /// The encoding of the previous block's `BlockProof`. As above
    /// [Self::prev_block_header], Plus proof is verified.
    prev_block_proof: Vec<BFieldElement>,

    /// The mutator set the previous block's transaction is built on. Hashed
    /// and compared against the previous block's copy of this claim.
    prev_block_transaction_mutator_set: MutatorSetAccumulator,
}

impl PredecessorIsValidWitnessMemory {
    /// The part of the previous block's encoding length that does not depend
    /// on the block: the header, and the length prefixes of kernel, body,
    /// appendix and proof.
    fn prev_block_fixed_size() -> usize {
        BlockHeader::static_length().unwrap() + 4
    }
}

impl From<&PredecessorIsValidWitness> for PredecessorIsValidWitnessMemory {
    fn from(witness: &PredecessorIsValidWitness) -> Self {
        let prev_block = &witness.prev_block;
        Self {
            next_block_mmr_accumulator: witness.next_block_body.block_mmr_accumulator.clone(),
            prev_block_header: *prev_block.header(),
            prev_block_body: prev_block.body().clone(),
            prev_block_appendix: prev_block.appendix().clone(),
            prev_block_proof: prev_block.proof.encode(),
            prev_block_transaction_mutator_set: witness.prev_block_transaction_mutator_set.clone(),
        }
    }
}

/// Asserts validity of the previous block and its relation to the next block.
///
/// Certifies, about the previous block, that it is the block whose hash the
/// next block's MMR was last extended with, that the block heights agree with
/// that MMR, and that its header follows from its own predecessor's.
///
/// The next block's header is not known when its proof is produced: because the
/// guesser sets the timestamp, difficulty, cumulative proof-of-work, and
/// guesser reward field. So the rules about those fields are checked for the
/// previous block instead. Stated differently: This program only asserts
/// qualities of the next block's body, and the parent header. It does not bind
/// its own header in any way. So all header requirements can only be checked
/// for the previous block.
///
/// If grandparent values are required to bind values in the parent's header,
/// those values must be the output of the program execution. That means that
/// the execution outputs whatever is required to bind grandparent block to
/// parent header. This allows the following block to verify updates to current
/// block's header.
///
/// Parent verification is also used for the proof-of-work requirement: it can
/// only be checked against the previous block, not the next block.
///
/// Input:
/// - next block body's MAST hash
/// - next block's height
/// - the epoch table
///
/// Output:
///  - previous block's hash
///  - previous block's lustration status
///  - previous block's timestamp
///  - previous block's cumulative proof-of-work
///  - previous block's difficulty
///  - hash of the mutator set after the previous block
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, GetSize, BFieldCodec)]
pub struct PredecessorIsValid {
    /// Whether to verify the previous block's proof. Only ever false in tests.
    ///
    /// A compile-time variable from the TASM perspective, *not* a run-time
    /// variable, meaning that two different programs are produced based on
    /// this value.
    verifies_prev_block_proof: bool,
}

impl PredecessorIsValid {
    #[expect(
        clippy::new_without_default,
        reason = "the other variant is for tests only"
    )]
    pub fn new() -> Self {
        Self {
            verifies_prev_block_proof: true,
        }
    }

    /// The sign bit is the top bit of the most significant limb. Crashes
    /// unless every limb is a u32.
    ///
    /// ```text
    /// BEFORE: _ [amount: i128]
    /// AFTER:  _ (amount >= 0)
    /// ```
    fn is_non_negative() -> Vec<LabelledInstruction> {
        triton_asm!(
            pop_count pop 1 pop_count pop 1 pop_count pop 1
            push {1_u64 << 31} swap 1 lt
        )
    }

    /// The claim a block at this height with this body must carry, by
    /// program, version and input, under the network's genesis block and
    /// table. The output is unbound in this context.
    pub fn required_claim(
        next_block_body_mh: Digest,
        height: BlockHeight,
        network: Network,
    ) -> Claim {
        let input = Self::claim_input(
            next_block_body_mh,
            height,
            Block::genesis_digest(network),
            &ConsensusRuleSet::epoch_table(network),
        );
        let version = ConsensusRuleSet::infer_from(network, height)
            .triton_proof_version()
            .version();
        Claim::new(Self::new().hash())
            .with_input(input)
            .about_version(version)
    }

    /// The claim's input: the block's body hash and height, the network's
    /// genesis block hash, and the epoch table.
    fn claim_input(
        body_mast_hash: Digest,
        height: BlockHeight,
        genesis_digest: Digest,
        epochs: &EpochTable,
    ) -> Vec<BFieldElement> {
        [
            body_mast_hash.reversed().values().to_vec(),
            vec![height.into()],
            genesis_digest.reversed().values().to_vec(),
            epochs.encode(),
        ]
        .concat()
    }

    /// Where in the claim's output the previous block's timestamp is.
    fn output_timestamp_offset() -> usize {
        Digest::LEN + LustrationStatus::static_length().unwrap()
    }

    /// Where in the claim's output the previous block's cumulative proof of
    /// work is.
    fn output_cumulative_pow_offset() -> usize {
        Self::output_timestamp_offset() + Timestamp::static_length().unwrap()
    }

    /// Where in the claim's output the previous block's difficulty is.
    fn output_difficulty_offset() -> usize {
        Self::output_cumulative_pow_offset() + ProofOfWork::static_length().unwrap()
    }

    /// Where in the claim's output the hash of the mutator set after the
    /// previous block starts.
    fn output_mutator_set_offset() -> usize {
        Self::output_difficulty_offset() + Difficulty::NUM_LIMBS
    }

    /// Number of words in the claim's standard-in stream.
    ///
    /// Same number as the number of words read from standard-in in this
    /// program.
    fn input_len() -> usize {
        // - Next block body MAST hash (5 words)
        // - Next block height (1)
        // - genesis block hash (5)
        // - epoch table
        2 * Digest::LEN + 1 + EpochTable::static_length().unwrap()
    }

    /// The claim for this program execution.
    pub fn claim(
        &self,
        next_block_body_mh: Digest,
        next_header: &BlockHeader,
        prev_block: &Block,
        genesis_digest: Digest,
        epochs: &EpochTable,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Claim {
        self.claim_at(
            next_block_body_mh,
            next_header.height,
            prev_block,
            genesis_digest,
            epochs,
            consensus_rule_set,
        )
    }

    /// The claim a block on this parent with this body carries, under the
    /// network's genesis block, table and rule set at the block's height.
    pub fn claim_about(prev_block: &Block, next_block_body_mh: Digest, network: Network) -> Claim {
        let height = prev_block.header().height.next();
        Self::new().claim_at(
            next_block_body_mh,
            height,
            prev_block,
            Block::genesis_digest(network),
            &ConsensusRuleSet::epoch_table(network),
            ConsensusRuleSet::infer_from(network, height),
        )
    }

    fn claim_at(
        &self,
        next_block_body_mh: Digest,
        next_block_height: BlockHeight,
        prev_block: &Block,
        genesis_digest: Digest,
        epochs: &EpochTable,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Claim {
        let prev_block_header = prev_block.header();
        let input = Self::claim_input(
            next_block_body_mh,
            next_block_height,
            genesis_digest,
            epochs,
        );

        let prev_lustration_status = prev_block_header
            .pow
            .lustration_status()
            .map(|status| status.encode())
            .unwrap_or_default();
        // The mutator set the next block's transaction is built on. A
        // previous block whose fee is negative is rejected regardless, so
        // any value serves for it.
        let mutator_set_after_prev_block = prev_block
            .mutator_set_accumulator_after()
            .map(|mutator_set| mutator_set.hash())
            .unwrap_or_default();
        let output = [
            prev_block.hash().values().to_vec(),
            prev_lustration_status,
            vec![prev_block_header.timestamp.0],
            prev_block_header.cumulative_proof_of_work.encode(),
            prev_block_header.difficulty.encode(),
            mutator_set_after_prev_block.values().to_vec(),
        ]
        .concat();

        Claim::new(self.hash())
            .with_input(input)
            .with_output(output)
            .about_version(consensus_rule_set.triton_proof_version().version())
    }
}

impl TritonProgram for PredecessorIsValid {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        let mut library = Library::new();

        // Every rule check is a subroutine such that profiling the program
        // attributes a row count to each check.
        let subroutine = |label: &str, body: Vec<LabelledInstruction>| {
            let label = format!("predecessor_is_valid_{label}");
            let code = triton_asm!({label}: {&body} return);
            (label, code)
        };

        let own_program_digest = library.import(Box::new(OwnProgramDigest));

        let own_program_digest_alloc = library.kmalloc(Digest::LEN as u32);
        // The genesis block hash the claim names.
        let genesis_alloc = library.kmalloc(Digest::LEN as u32);

        let prev_block_body_mh_alloc = library.kmalloc(Digest::LEN as u32);
        let prev_block_txk_mh_alloc = library.kmalloc(Digest::LEN as u32);
        let expected_prev_height_alloc = library.kmalloc(1);
        // Pointer to the epoch in force at the previous block's height.
        let prev_epoch_alloc = library.kmalloc(1);
        let epochs_alloc = library.kmalloc(EpochTable::static_length().unwrap() as u32);

        // Minimum block time and target block interval that parent block must
        // satisfy.
        let prev_timing_alloc = library.kmalloc(2);

        // Pointer to grandparent block height
        let prev_prev_block_height_alloc = library.kmalloc(1);
        let audit_witness = library.import(Box::new(VerifyNdSiIntegrity::<
            PredecessorIsValidWitnessMemory,
        >::default()));

        let hash_varlen = library.import(Box::new(HashVarlen));
        let hash_digest = library.import(Box::new(HashFromStack::new(DataType::Digest)));
        let merkle_verify = library.import(Box::new(MerkleVerify));
        let merkle_root = library.import(Box::new(MerkleRoot));
        let new_list = library.import(Box::new(New));
        let push_digest = library.import(Box::new(Push::new(DataType::Digest)));
        let append_to_mmr = library.import(Box::new(CalculateNewPeaksFromAppend));
        let memcpy = library.import(Box::new(MemCpy));
        let i128_lt = library.import(Box::new(I128Lt));
        let block_subsidy = library.import(Box::new(BlockSubsidy));
        let u160_lt = library.import(Box::new(U160Lt));
        let u64_lt = library.import(Box::new(U64Lt));
        let u192_safe_add = library.import(Box::new(U192SafeAdd));
        let difficulty_control = library.import(Box::new(DifficultyControl));
        let removal_records_are_unique = library.import(Box::new(RemovalRecordsAreUnique));
        let verified_lustration_amount = library.import(Box::new(VerifiedLustrationAmount));
        let push_pointer = library.import(Box::new(Push::new(DataType::Bfe)));
        let u128_sub = library.import(Box::new(U128Sub));
        let u64_add = library.import(Box::new(U64Add));
        let guesser_fee_addition_records = library.import(Box::new(GuesserFeeAdditionRecords));
        let apply_addition_records = library.import(Box::new(ApplyAdditionRecords));
        let mutator_set_hash_from_components =
            library.import(Box::new(MutatorSetHashFromComponents));
        let mutator_set_hash = library.import(Box::new(MutatorSetHash));
        let mutator_set_update = library.import(Box::new(MutatorSetUpdateFromStateHash));
        let removal_index_commitment = library.import(Box::new(RemovalIndexCommitment));
        let guesser_swbfi_reveal = library.import(Box::new(GuesserSwbfiReveal));
        // What the claim to know the mutator set in the previous block's
        // appendix must bind: the previous block's parent, its AOCL and its
        // inactive SWBF.
        // What the SWBF update claim in the previous block's appendix must
        // bind: the mutator set after the previous block's predecessor, and
        // the previous block's inputs.
        let swbf_claim_mutator_set_alloc = library.kmalloc(Digest::LEN as u32);
        // The messages of the previous block's lustration announcements.
        let lustrations_alloc = library.kmalloc(1);
        // The hash of the mutator set after the previous block, for the
        // claim's output.
        let mutator_set_after_prev_block_alloc = library.kmalloc(Digest::LEN as u32);
        let new_claim = library.import(Box::new(NewClaim::new(ConsensusRuleSet::HardforkDelta)));
        let generate_single_proof_claim = library.import(Box::new(GenerateSingleProofClaim::new(
            ConsensusRuleSet::HardforkDelta,
        )));
        let transaction_claim_size =
            single_proof_claim(Digest::default(), ConsensusRuleSet::HardforkDelta)
                .encode()
                .len();
        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));
        // The `BlockProof`'s encoding lies inside the `Vec` field, after the
        // `Vec`'s own length word.
        let prev_block_proof_encoding = triton_asm!(
            {&field_with_size!(PredecessorIsValidWitnessMemory::prev_block_proof)}
            // _ *vec vec_size
            addi -1 pick 1 addi 1 pick 1
            // _ *block_proof block_proof_size
        );
        let meets_threshold = library.import(Box::new(MeetsThreshold));

        let read_digest = triton_asm!(addi {Digest::LEN - 1} read_mem {Digest::LEN} pop 1);

        // The digests of the programs the previous block's proof and
        // transaction claim are about, from the epoch in force at its height.
        // BEFORE: _
        // AFTER:  _ [digest]
        let read_prev_epoch_block_program_digest = triton_asm!(
            push {prev_epoch_alloc.read_address()} read_mem 1 pop 1
            {&field!(Epoch::block_program_digest)} {&read_digest}
        );
        let read_prev_epoch_single_proof_digest = triton_asm!(
            push {prev_epoch_alloc.read_address()} read_mem 1 pop 1
            {&field!(Epoch::single_proof_digest)} {&read_digest}
        );
        let read_prev_epoch_swbf_aggregation_digest = triton_asm!(
            push {prev_epoch_alloc.read_address()} read_mem 1 pop 1
            {&field!(Epoch::swbf_aggregation_digest)} {&read_digest}
        );
        let read_u64 = triton_asm!(addi 1 read_mem 2 pop 1);
        let read_difficulty =
            triton_asm!(addi {Difficulty::NUM_LIMBS - 1} read_mem {Difficulty::NUM_LIMBS} pop 1);
        let read_cumulative_pow = triton_asm!(
            addi {DataType::U192.stack_size() - 1}
            {&DataType::U192.read_value_from_memory_pop_pointer()}
        );
        let lustration_status_type = DataType::Tuple(vec![DataType::I128, DataType::U64]);
        let lustration_status_size = lustration_status_type.stack_size();

        // BEFORE: _ *w
        // AFTER:  _ *header
        let prev_block_header = field!(PredecessorIsValidWitnessMemory::prev_block_header);
        let read_prev_block_height = triton_asm!(
            {&prev_block_header} {&field!(BlockHeader::height)} read_mem 1 pop 1
        );
        let read_prev_block_timestamp = triton_asm!(
            {&prev_block_header} {&field!(BlockHeader::timestamp)} read_mem 1 pop 1
        );
        let read_prev_block_difficulty = triton_asm!(
            {&prev_block_header} {&field!(BlockHeader::difficulty)} {&read_difficulty}
        );
        let read_prev_block_cumulative_pow = triton_asm!(
            {&prev_block_header} {&field!(BlockHeader::cumulative_proof_of_work)}
            {&read_cumulative_pow}
        );

        // The status occupies the last words of the PoW field's first path;
        // see `Pow::lustration_status`.
        // BEFORE: _ *w
        // AFTER:  _ *prev_lustration_status
        let prev_lustration_status = triton_asm!(
            {&prev_block_header} {&field!(BlockHeader::pow)} {&field!(BlockPow::path_a)}
            addi {Digest::LEN * (POW_MEMORY_TREE_HEIGHT - 2)}
        );

        // BEFORE: _ *w
        // AFTER:  _ [prev_lustration_status]
        let read_prev_lustration_status = triton_asm!(
            {&prev_lustration_status}
            addi {lustration_status_size - 1}
            {&lustration_status_type.read_value_from_memory_pop_pointer()}
        );

        // Hash a field of the object, and append it to the list of all leafs.
        // BEFORE: _ *object *leafs
        // AFTER:  _ *object *leafs
        let push_leaf = |field_with_size: Vec<LabelledInstruction>| {
            triton_asm!(
                dup 1 {&field_with_size}
                // _ *object *leafs *field size

                call {hash_varlen}
                // _ *object *leafs [leaf]

                dup 5 place 5
                // _ *object *leafs *leafs [leaf]

                call {push_digest}
                // _ *object *leafs
            )
        };

        // Construct header MAST hash from ND memory.
        let header_mast_hash = "predecessor_is_valid_header_mast_hash".to_string();
        let header_mast_hash_code = triton_asm!(
            // BEFORE: _ *header
            // AFTER:  _ [header_mast_hash]
            {header_mast_hash}:
                call {new_list}
                // _ *header *leafs

                {&push_leaf(field_with_size!(BlockHeader::version))}
                {&push_leaf(field_with_size!(BlockHeader::height))}
                {&push_leaf(field_with_size!(BlockHeader::prev_block_digest))}
                {&push_leaf(field_with_size!(BlockHeader::timestamp))}
                {&push_leaf(field_with_size!(BlockHeader::pow))}
                {&push_leaf(field_with_size!(BlockHeader::cumulative_proof_of_work))}
                {&push_leaf(field_with_size!(BlockHeader::difficulty))}
                {&push_leaf(field_with_size!(BlockHeader::guesser_receiver_data))}
                // _ *header *leafs

                pick 1 pop 1
                call {merkle_root}
                // _ [header_mast_hash]

                return
        );

        let transaction_kernel_mast_hash =
            "predecessor_is_valid_transaction_kernel_mast_hash".to_string();
        let transaction_kernel_mast_hash_code = triton_asm!(
            // BEFORE: _ *txk
            // AFTER:  _ [txk_mast_hash]
            {transaction_kernel_mast_hash}:
                call {new_list}
                // _ *txk *leafs

                {&push_leaf(field_with_size!(TransactionKernel::inputs))}
                {&push_leaf(field_with_size!(TransactionKernel::outputs))}
                {&push_leaf(field_with_size!(TransactionKernel::announcements))}
                {&push_leaf(field_with_size!(TransactionKernel::fee))}
                {&push_leaf(field_with_size!(TransactionKernel::coinbase))}
                {&push_leaf(field_with_size!(TransactionKernel::timestamp))}
                {&push_leaf(field_with_size!(TransactionKernel::mutator_set_hash))}
                {&push_leaf(field_with_size!(TransactionKernel::merge_bit))}
                // _ *txk *leafs

                pick 1 pop 1
                call {merkle_root}
                // _ [txk_mast_hash]

                return
        );

        // Hash the previous block's body, and keep its and its transaction
        // kernel's MAST hashes in static memory.
        // BEFORE: _ *w
        // AFTER:  _ *w
        let hash_prev_block_body = triton_asm!(
            dup 0 {&field!(PredecessorIsValidWitnessMemory::prev_block_body)}
            // _ *w *body

            dup 0 {&field!(BlockBody::transaction_kernel)}
            call {transaction_kernel_mast_hash}
            // _ *w *body [txk_mast_hash]

            push {prev_block_txk_mh_alloc.write_address()} write_mem {Digest::LEN} pop 1
            // _ *w *body

            call {new_list}
            // _ *w *body *leafs

            push {prev_block_txk_mh_alloc.read_address()} read_mem {Digest::LEN} pop 1
            call {hash_digest}
            // _ *w *body *leafs [txk_leaf]

            dup 5 place 5
            call {push_digest}
            // _ *w *body *leafs

            {&push_leaf(field_with_size!(BlockBody::mutator_set_accumulator))}
            {&push_leaf(field_with_size!(BlockBody::lock_free_mmr_accumulator))}
            {&push_leaf(field_with_size!(BlockBody::block_mmr_accumulator))}
            // _ *w *body *leafs

            pick 1 pop 1
            call {merkle_root}
            // _ *w [prev_block_body_mh]

            push {prev_block_body_mh_alloc.write_address()} write_mem {Digest::LEN} pop 1
            // _ *w
        );

        // BEFORE: _ *w
        // AFTER:  _ *w [prev_block_hash]
        let prev_block_hash = triton_asm!(
            // A MAST over kernel and proof, where the kernel is a MAST over
            // header, body, appendix and a default digest.
            dup 0 {&prev_block_proof_encoding}
            call {hash_varlen}
            // _ *w [prev_block_proof_leaf]

            push 0 push 0 push 0 push 0 push 0
            // _ *w [prev_block_proof_leaf] [default_digest]

            dup 10 {&field_with_size!(PredecessorIsValidWitnessMemory::prev_block_appendix)}
            call {hash_varlen}
            // _ *w [prev_block_proof_leaf] [default_digest] [appendix_leaf]

            hash
            // _ *w [prev_block_proof_leaf] [right_node]

            push {prev_block_body_mh_alloc.read_address()} read_mem {Digest::LEN} pop 1
            call {hash_digest}
            // _ *w [prev_block_proof_leaf] [right_node] [body_leaf]

            dup 15 {&prev_block_header}
            call {header_mast_hash}
            call {hash_digest}
            // _ *w [prev_block_proof_leaf] [right_node] [body_leaf] [header_leaf]

            hash
            // _ *w [prev_block_proof_leaf] [right_node] [left_node]

            hash
            // _ *w [prev_block_proof_leaf] [kernel_mast_hash]

            call {hash_digest}
            // _ *w [prev_block_proof_leaf] [kernel_leaf]

            hash
            // _ *w [prev_block_hash]
        );

        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        // STDIN:  next_block_height
        let rule_0a = triton_asm!(
            read_io 1
            read_io {Digest::LEN}
            push {genesis_alloc.write_address()} write_mem {Digest::LEN} pop 1
            // _ *w [prev_block_hash] next_block_height

            dup 6 {&read_prev_block_height}
            // _ *w [prev_block_hash] next_block_height prev_block_height

            addi 1 dup 1
            // _ *w [prev_block_hash] next_block_height (prev_block_height + 1) next_block_height

            eq assert error_id {BlockValidationRule::BlockHeight.error_id()}
            // _ *w [prev_block_hash] next_block_height

            dup 6 {&field!(PredecessorIsValidWitnessMemory::next_block_mmr_accumulator)}
            {&field!(MmrAccumulator::leaf_count)} {&read_u64}
            // _ *w [prev_block_hash] next_block_height [next_leaf_count]

            pick 2 split
            // _ *w [prev_block_hash] [next_leaf_count] [next_block_height]

            pick 2 eq assert error_id {BlockValidationRule::BlockHeight.error_id()}
            eq assert error_id {BlockValidationRule::BlockHeight.error_id()}
            // _ *w [prev_block_hash]
        );

        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        let rule_0c = triton_asm!(
            dup 4 dup 4 dup 4 dup 4 dup 4
            // _ *w [prev_block_hash] [prev_block_hash]

            dup 10 {&field!(PredecessorIsValidWitnessMemory::prev_block_body)}
            {&field!(BlockBody::block_mmr_accumulator)}
            // _ *w [prev_block_hash] [prev_block_hash] *prev_block_mmra

            dup 0 {&field!(MmrAccumulator::leaf_count)} {&read_u64}
            // _ *w [prev_block_hash] [prev_block_hash] *prev_block_mmra [prev_leaf_count]

            pick 2 {&field_with_size!(MmrAccumulator::peaks)}
            // _ *w [prev_block_hash] [prev_block_hash] [prev_leaf_count] *peaks size

            call {new_list}
            // _ *w [prev_block_hash] [prev_block_hash] [prev_leaf_count] *peaks size *peaks_copy

            dup 0 place 3
            // _ *w [prev_block_hash] [prev_block_hash] [prev_leaf_count] *peaks_copy *peaks size *peaks_copy

            pick 1
            // _ *w [prev_block_hash] [prev_block_hash] [prev_leaf_count] *peaks_copy *peaks *peaks_copy size

            call {memcpy}
            // _ *w [prev_block_hash] [prev_block_hash] [prev_leaf_count] *peaks_copy

            pick 7 pick 7 pick 7 pick 7 pick 7
            // _ *w [prev_block_hash] [prev_leaf_count: u64] *peaks_copy [prev_block_hash]

            call {append_to_mmr}
            // _ *w [prev_block_hash] *new_peaks *auth_path

            pop 1
            // _ *w [prev_block_hash] *new_peaks

            dup 0 read_mem 1 pop 1
            push {Digest::LEN} mul addi 1
            // _ *w [prev_block_hash] *new_peaks size

            call {hash_varlen}
            // _ *w [prev_block_hash] [new_peaks_hash]

            dup 10 {&field!(PredecessorIsValidWitnessMemory::next_block_mmr_accumulator)}
            {&field_with_size!(MmrAccumulator::peaks)}
            call {hash_varlen}
            // _ *w [prev_block_hash] [new_peaks_hash] [peaks_hash]

            assert_vector error_id {BlockValidationRule::BlockMmrUpdate.error_id()}
            pop {Digest::LEN}
            // _ *w [prev_block_hash]
        );

        // BEFORE: _ [a: Digest] [b: Digest]
        // AFTER:  _ (a == b)
        let digests_are_equal = DataType::Digest.compare();

        // Claims of other proof versions are not this program's, nor the
        // SWBF update's, even if the program digests agree.
        let version = ConsensusRuleSet::HardforkDelta
            .triton_proof_version()
            .version();

        let epoch_size = Epoch::static_length().unwrap();
        // Never written, so all zeros: what an unused epoch looks like.
        let unused_epoch_alloc = library.kmalloc(epoch_size as u32);

        // An epoch is too wide to compare on the stack, so compare the hashes instead.
        let epochs_are_equal = "predecessor_is_valid_epochs_are_equal".to_string();
        let epochs_are_equal_code = triton_asm!(
            // BEFORE: _ *a *b
            // AFTER:  _ (a == b)
            {epochs_are_equal}:
                push {epoch_size} call {hash_varlen}
                pick 5 push {epoch_size} call {hash_varlen}
                // _ [hash_b] [hash_a]

                {&digests_are_equal}
                return
        );

        // Whether the epoch has started by the height. Unused entries, with
        // height zero, never have.
        let epoch_has_started = "predecessor_is_valid_epoch_has_started".to_string();
        let epoch_has_started_code = triton_asm!(
            // BEFORE: _ height epoch_height
            // AFTER:  _ (epoch_height != 0 && epoch_height <= height)
            {epoch_has_started}:
                dup 0 push 0 eq push 0 eq
                // _ height epoch_height (epoch_height != 0)

                place 2 split
                // _ (epoch_height != 0) height [epoch_height: u64]

                pick 2 split
                // _ (epoch_height != 0) [epoch_height] [height]

                call {u64_lt}
                // _ (epoch_height != 0) (height < epoch_height)

                push 0 eq mul
                // _ (epoch_height != 0 && epoch_height <= height)

                return
        );

        // The last epoch in the table that has started by the height. Found
        // by locating the first epoch that has not started and then taking the
        // preceding one.
        let epoch_in_force = "predecessor_is_valid_epoch_in_force".to_string();
        let epoch_in_force_loop = format!("{epoch_in_force}_loop");
        let epoch_in_force_code = triton_asm!(
            // BEFORE: _ height
            // AFTER:  _ *epoch
            {epoch_in_force}:
                push {epochs_alloc.write_address()} push 1
                call {epoch_in_force_loop}
                // _ height *epoch i

                pop 1 place 1 pop 1
                // _ *epoch

                return

            // INVARIANT: _ height *epoch[i - 1] i
            {epoch_in_force_loop}:
                dup 0 push {NUM_EPOCHS} eq skiz return
                // _ height *epoch[i - 1] i

                dup 2 dup 2 addi {epoch_size} {&field!(Epoch::height)} read_mem 1 pop 1
                // _ height *epoch[i - 1] i height epoch[i].height

                call {epoch_has_started}
                // _ height *epoch[i - 1] i epoch[i]_has_started

                push 0 eq skiz return
                // _ height *epoch[i - 1] i

                pick 1 addi {epoch_size} place 1 addi 1
                // _ height *epoch[i] (i + 1)

                recurse
        );

        // Whether the table read from standard-in holds all of the claim's
        // epochs, and any epochs it holds beyond those had not started by the
        // previous block's height.
        let epoch_tables_agree = "predecessor_is_valid_epoch_tables_agree".to_string();
        let epoch_tables_agree_loop = format!("{epoch_tables_agree}_loop");
        let epoch_tables_agree_code = triton_asm!(
            // BEFORE: _ *claim_epochs
            // AFTER:  _ tables_agree
            {epoch_tables_agree}:
                push {expected_prev_height_alloc.read_address()} read_mem 1 pop 1
                push {epochs_alloc.write_address()} push 1 push 0
                call {epoch_tables_agree_loop}
                // _ *claim_epoch[n] height *epoch[n] tables_agree n

                pop 1 place 3 pop 3
                // _ tables_agree

                return

            // INVARIANT: _ *claim_epoch[i] height *epoch[i] tables_agree i
            {epoch_tables_agree_loop}:
                dup 0 push {NUM_EPOCHS} eq skiz return
                // _ *claim_epoch[i] height *epoch[i] tables_agree i

                dup 4 dup 3 call {epochs_are_equal}
                // _ *claim_epoch[i] height *epoch[i] tables_agree i epochs_are_equal

                dup 5 push {unused_epoch_alloc.write_address()} call {epochs_are_equal}
                // _ *claim_epoch[i] height *epoch[i] tables_agree i epochs_are_equal claim_epoch_is_unused

                dup 5 dup 5 {&field!(Epoch::height)} read_mem 1 pop 1
                call {epoch_has_started}
                // _ *claim_epoch[i] height *epoch[i] tables_agree i epochs_are_equal claim_epoch_is_unused epoch_has_started

                push 0 eq mul
                // _ *claim_epoch[i] height *epoch[i] tables_agree i epochs_are_equal (claim_epoch_is_unused && !epoch_has_started)

                add push 0 eq push 0 eq
                // _ *claim_epoch[i] height *epoch[i] tables_agree i (epochs_are_equal || (claim_epoch_is_unused && !epoch_has_started))

                pick 2 mul place 1
                // _ *claim_epoch[i] height *epoch[i] tables_agree' i

                pick 2 addi {epoch_size} place 2
                pick 4 addi {epoch_size} place 4
                addi 1
                // _ *claim_epoch[i + 1] height *epoch[i + 1] tables_agree' (i + 1)

                recurse
        );

        // Whether the claim input, whose program digest and length already
        // match this program's, is about the previous block.
        let own_claim_input_matches = "predecessor_is_valid_own_claim_input_matches".to_string();
        let own_claim_input_matches_code = triton_asm!(
            // BEFORE: _ *input 1
            // AFTER:  _ *input input_matches
            {own_claim_input_matches}:
                pop 1
                dup 0 addi {Digest::LEN} read_mem {Digest::LEN} pop 1
                swap 4 swap 1 swap 3 swap 1
                // _ *input [body_mh_in_input]

                push {prev_block_body_mh_alloc.read_address()} read_mem {Digest::LEN} pop 1
                // _ *input [body_mh_in_input] [prev_block_body_mh]

                {&digests_are_equal}
                // _ *input body_mh_matches

                dup 1 addi {Digest::LEN + 1} read_mem 1 pop 1
                push {expected_prev_height_alloc.read_address()} read_mem 1 pop 1
                eq
                // _ *input body_mh_matches height_matches
                dup 2 addi {2 * Digest::LEN + 1} read_mem {Digest::LEN} pop 1
                swap 4 swap 1 swap 3 swap 1
                push {genesis_alloc.read_address()} read_mem {Digest::LEN} pop 1
                {&digests_are_equal}
                // _ *input body_mh_matches height_matches genesis_matches
                dup 3 addi {2 * Digest::LEN + 2}
                call {epoch_tables_agree}
                // _ *input body_mh_matches height_matches genesis_matches tables_agree
                mul mul mul
                // _ *input input_matches
                return
        );

        // Find this program's claim for the previous block, in the previous
        // block's appendix. Sets the index to the matching claim.
        // It is not sufficient to match on program digest. The block body MAST
        // hash, height and epoch table must also agree. Match on everything
        // that must be true in the looked-for claim.
        let find_own_claim = "predecessor_is_valid_find_own_claim".to_string();
        let find_own_claim_code = triton_asm!(
            // INVARIANT: _ *claim[i]_si num_claims i
            {find_own_claim}:
                dup 1 dup 1 eq
                push 0 eq assert error_id {BlockValidationRule::AppendixMissingClaim.error_id()}
                // _ *claim[i]_si num_claims i

                dup 2 addi 1 {&field!(Claim::program_digest)} {&read_digest}
                // _ *claim[i]_si num_claims i [claim_program_digest]

                push {own_program_digest_alloc.read_address()} read_mem {Digest::LEN} pop 1
                // _ *claim[i]_si num_claims i [claim_program_digest] [own_program_digest]

                {&digests_are_equal}
                dup 3 addi 1 {&field!(Claim::version)} read_mem 1 pop 1
                push {version} eq mul
                // _ *claim[i]_si num_claims i program_and_version_match

                dup 3 addi 1 {&field_with_size!(Claim::input)}
                // _ *claim[i]_si num_claims i program_matches *input input_size

                // The size counts the length word the pointer points at.
                push {Self::input_len() + 1} eq
                // _ *claim[i]_si num_claims i program_matches *input size_matches

                pick 2 mul
                // _ *claim[i]_si num_claims i *input shape_matches

                dup 0 skiz call {own_claim_input_matches}
                // _ *claim[i]_si num_claims i *input is_own_claim_about_prev_block

                place 1 pop 1
                // _ *claim[i]_si num_claims i is_own_claim_about_prev_block

                skiz return
                // _ *claim[i]_si num_claims i

                pick 2 read_mem 1
                // _ num_claims i claim_size (*claim[i]_si - 1)

                // Crashes unless the size is a u32.
                dup 1 pop_count pop 1

                addi 2 add
                // _ num_claims i *claim[i+1]_si

                place 2 addi 1
                // _ *claim[i+1]_si num_claims (i + 1)

                recurse
        );

        // BEFORE: _ *w [prev_block_hash] *prev_claim_output
        // AFTER:  _ *w [prev_block_hash] *prev_claim_output
        let rule_0b_prev = triton_asm!(
            dup 0 addi {Digest::LEN} read_mem {Digest::LEN} pop 1
            // _ *w [prev_block_hash] *prev_claim_output [prev_prev_block_hash]

            dup 11 {&prev_block_header} {&field!(BlockHeader::prev_block_digest)} {&read_digest}
            // _ *w [prev_block_hash] *prev_claim_output [prev_prev_block_hash] [prev_block_prev_block_digest]

            assert_vector error_id {BlockValidationRule::PrevBlockDigest.error_id()}
            pop {Digest::LEN}
            // _ *w [prev_block_hash] *prev_claim_output
        );

        // BEFORE: _ *w [prev_block_hash] *prev_claim_output
        // AFTER:  _ *w [prev_block_hash] *prev_claim_output
        let rule_0d_prev = triton_asm!(
            dup 0 addi {Self::output_timestamp_offset() + 1} read_mem 1 pop 1
            // _ *w [prev_block_hash] *prev_claim_output prev_prev_block_timestamp

            push {prev_timing_alloc.write_address()} read_mem 1 pop 1
            // _ *w [prev_block_hash] *prev_claim_output prev_prev_block_timestamp min_block_interval

            add split
            // _ *w [prev_block_hash] *prev_claim_output [earliest_prev_block_timestamp: u64]

            dup 8 {&read_prev_block_timestamp} split
            // _ *w [prev_block_hash] *prev_claim_output [earliest_prev_block_timestamp] [prev_block_timestamp]

            call {u64_lt}
            // _ *w [prev_block_hash] *prev_claim_output (prev_block_timestamp < earliest_prev_block_timestamp)

            push 0 eq
            // _ *w [prev_block_hash] *prev_claim_output (prev_block_timestamp >= earliest_prev_block_timestamp)

            assert error_id {BlockValidationRule::MinimumBlockTime.error_id()}
            // _ *w [prev_block_hash] *prev_claim_output
        );

        // BEFORE: _ *w [prev_block_hash] *prev_claim_output
        // AFTER:  _ *w [prev_block_hash] *prev_claim_output
        let rule_0e_prev = triton_asm!(
            dup 6 {&read_prev_block_height} addi -1
            // _ *w [prev_block_hash] prev_prev_height

            push {prev_prev_block_height_alloc.write_address()} write_mem 1 pop 1
            // _ *w [prev_block_hash] *prev_claim_output

            dup 0 addi {Self::output_difficulty_offset() + 1} {&read_difficulty}
            // _ *w [prev_block_hash] *prev_claim_output [prev_prev_block_difficulty: u160]

            push {prev_timing_alloc.read_address()} read_mem 1 pop 1 split
            // _ *w [prev_block_hash] *prev_claim_output [prev_prev_block_difficulty: u160] [prev_target_block_interval: u64]

            dup 7 addi {Self::output_timestamp_offset() + 1} read_mem 1 pop 1 split
            // _ *w [prev_block_hash] *prev_claim_output [prev_prev_block_difficulty] [prev_target_block_interval] [prev_prev_block_timestamp: u64]

            dup 15 {&read_prev_block_timestamp} split
            // _ *w [prev_block_hash] *prev_claim_output [prev_prev_block_difficulty] [prev_target_block_interval] [prev_prev_block_timestamp] [prev_block_timestamp]

            push {prev_prev_block_height_alloc.read_address()} read_mem 1 pop 1
            // _ *w [prev_block_hash] *prev_claim_output [prev_prev_block_difficulty] [prev_target_block_interval] [prev_prev_block_timestamp] [prev_block_timestamp] prev_prev_block_height

            call {difficulty_control}
            // _ *w [prev_block_hash] *prev_claim_output [expected_difficulty]

            dup 11 {&read_prev_block_difficulty}
            // _ *w [prev_block_hash] *prev_claim_output [expected_difficulty] [prev_block_difficulty]

            {&DataType::U160.compare()}
            assert error_id {BlockValidationRule::Difficulty.error_id()}
            // _ *w [prev_block_hash] *prev_claim_output
        );

        // BEFORE: _ *w [prev_block_hash] *prev_claim_output
        // AFTER:  _ *w [prev_block_hash] *prev_claim_output
        let rule_0f_prev = triton_asm!(
            dup 0 addi {Self::output_cumulative_pow_offset() + 1} {&read_cumulative_pow}
            // _ *w [prev_block_hash] *prev_claim_output [prev_prev_block_cumulative_pow: u192]

            push 0 dup 13 {&read_prev_block_difficulty}
            // _ *w [prev_block_hash] *prev_claim_output [prev_prev_block_cumulative_pow: u192] [prev_block_difficulty: u192]

            call {u192_safe_add}
            // _ *w [prev_block_hash] *prev_claim_output [expected_cumulative_pow: u192]

            dup 12 {&read_prev_block_cumulative_pow}
            // _ *w [prev_block_hash] *prev_claim_output [expected_cumulative_pow: u192] [prev_block_cumulative_pow: u192]

            {&DataType::U192.compare()}
            assert error_id {BlockValidationRule::CumulativeProofOfWork.error_id()}
            // _ *w [prev_block_hash] *prev_claim_output
        );

        // BEFORE: _ *w
        // AFTER:  _ *txk
        let prev_block_txk = triton_asm!(
            {&field!(PredecessorIsValidWitnessMemory::prev_block_body)}
            {&field!(BlockBody::transaction_kernel)}
        );

        let amount_size = NativeCurrencyAmount::static_length().unwrap();

        // The previous block's transaction must be built on the mutator set
        // after its predecessor, which the previous block's copy of this
        // claim carries. The witness's mutator set must be that one, too.
        // BEFORE: _ *w [prev_block_hash] *prev_claim_output
        // AFTER:  _ *w [prev_block_hash] *prev_claim_output
        let rule_2t_prev = triton_asm!(
            dup 0 addi {Self::output_mutator_set_offset() + Digest::LEN}
            read_mem {Digest::LEN} pop 1
            // _ *w [prev_block_hash] *prev_claim_output [mutator_set_after_prev_prev_block]

            dup 11 {&prev_block_txk} {&field!(TransactionKernel::mutator_set_hash)} {&read_digest}
            // _ *w [prev_block_hash] *prev_claim_output [mutator_set_after_prev_prev_block] [prev_block_transaction_mutator_set]

            assert_vector error_id {BlockValidationRule::TransactionMutatorSetMismatch.error_id()}
            pop {Digest::LEN}
            // _ *w [prev_block_hash] *prev_claim_output

            dup 6 {&field!(PredecessorIsValidWitnessMemory::prev_block_transaction_mutator_set)}
            call {mutator_set_hash}
            // _ *w [prev_block_hash] *prev_claim_output [witness_mutator_set_hash]

            dup 5 addi {Self::output_mutator_set_offset() + Digest::LEN}
            read_mem {Digest::LEN} pop 1
            // _ *w [prev_block_hash] *prev_claim_output [witness_mutator_set_hash] [mutator_set_after_prev_prev_block]

            assert_vector error_id {BlockValidationRule::TransactionMutatorSetMismatch.error_id()}
            pop {Digest::LEN}
            // _ *w [prev_block_hash] *prev_claim_output
        );

        // Copies a list of digests: appending to an MMR modifies its peaks
        // list in place.
        // BEFORE: _ *list
        // AFTER:  _ *copy
        let copy_digest_list = triton_asm!(
            dup 0 read_mem 1 pop 1 push {Digest::LEN} mul addi 1
            // _ *list size

            call {new_list}
            // _ *list size *copy

            place 1 dup 1 place 3
            // _ *copy *list *copy size

            call {memcpy}
            // _ *copy
        );

        // Whether the claim input, whose program digest and length already
        // match the SWBF update claim's, binds the mutator set after the
        // previous block's predecessor and starts at the first leaf.
        let swbf_claim_input_matches = "predecessor_is_valid_swbf_claim_input_matches".to_string();
        let swbf_claim_input_matches_code = triton_asm!(
            // BEFORE: _ *input 1
            // AFTER:  _ *input input_matches
            {swbf_claim_input_matches}:
                pop 1
                dup 0 addi {Digest::LEN} read_mem {Digest::LEN} pop 1
                swap 4 swap 1 swap 3 swap 1
                // _ *input [mutator_set_hash_in_input]

                push {swbf_claim_mutator_set_alloc.read_address()} read_mem {Digest::LEN} pop 1
                {&digests_are_equal}
                // _ *input mutator_set_matches

                dup 1 addi {1 + INPUT_FIRST_LEAF_INDEX} read_mem 1 pop 1
                push {CorrectSwbfUpdate::FIRST_LEAF_INDEX} eq mul
                // _ *input input_matches

                return
        );

        // Find the aggregated SWBF update claim for the previous block's
        // transaction in the previous block's appendix. Sets the index to the
        // matching claim.
        let find_swbf_claim = "predecessor_is_valid_find_swbf_claim".to_string();
        let find_swbf_claim_code = triton_asm!(
            // INVARIANT: _ *claim[i]_si num_claims i
            {find_swbf_claim}:
                dup 1 dup 1 eq
                push 0 eq assert error_id {BlockValidationRule::AppendixMissingClaim.error_id()}
                // _ *claim[i]_si num_claims i

                dup 2 addi 1 {&field!(Claim::program_digest)} {&read_digest}
                {&read_prev_epoch_swbf_aggregation_digest}
                {&digests_are_equal}
                dup 3 addi 1 {&field!(Claim::version)} read_mem 1 pop 1
                push {version} eq mul
                // _ *claim[i]_si num_claims i program_and_version_match

                dup 3 addi 1 {&field_with_size!(Claim::input)}
                // _ *claim[i]_si num_claims i program_matches *input input_size

                // The size counts the length word the pointer points at.
                push {INPUT_LEN + 1} eq
                pick 2 mul
                // _ *claim[i]_si num_claims i *input shape_matches

                dup 0 skiz call {swbf_claim_input_matches}
                place 1 pop 1
                // _ *claim[i]_si num_claims i is_swbf_claim_about_prev_block

                skiz return
                // _ *claim[i]_si num_claims i

                pick 2 read_mem 1
                // _ num_claims i claim_size (*claim[i]_si - 1)

                // Crashes unless the size is a u32.
                dup 1 pop_count pop 1

                addi 2 add
                // _ num_claims i *claim[i+1]_si

                place 2 addi 1
                // _ *claim[i+1]_si num_claims (i + 1)

                recurse
        );

        // BEFORE: _ *list
        // AFTER:  _ [digest]
        let hash_digest_list = triton_asm!(
            dup 0 read_mem 1 pop 1 push {Digest::LEN} mul addi 1
            // _ *list size

            call {hash_varlen}
            // [digest]
        );

        // Rules 2.a, 2.b, 2.d and 2.e: the transaction applied to the
        // witness's mutator set yields the body's. The mutator set after the
        // removals comes, by hash, from the SWBF update claim the previous
        // block carries, which its proof covers; the rest is computed here.
        // BEFORE: _ *w [prev_block_hash] *prev_claim_output
        // AFTER:  _ *w [prev_block_hash] *prev_claim_output
        let mutator_set_update_prev = triton_asm!(
            dup 0 addi {Self::output_mutator_set_offset() + Digest::LEN}
            read_mem {Digest::LEN} pop 1
            push {swbf_claim_mutator_set_alloc.write_address()} write_mem {Digest::LEN} pop 1
            // _ *w [prev_block_hash] *prev_claim_output

            dup 6 {&field!(PredecessorIsValidWitnessMemory::prev_block_appendix)}
            {&field!(BlockAppendix::claims)}
            read_mem 1 addi 2 place 1 push 0
            // _ *w [prev_block_hash] *prev_claim_output *claim[0]_si num_claims 0

            call {find_swbf_claim}
            pop 2 addi 1 {&field!(Claim::output)}
            // _ *w [prev_block_hash] *prev_claim_output *swbf_claim_output

            // The output has the leaf's layout: the padded rows of the leaf
            // proofs beneath the claim, the number of index sets covered, the
            // hash of the mutator set after the removals, the last leaf
            // index, then the peaks of the MMR over the index sets as a list.
            // The leaf proofs must total the epoch's floor, and the claim
            // must cover all inputs, whose peaks are recomputed here.
            dup 0 read_mem 1 pop 1
            dup 1 addi {1 + OUTPUT_NUM_PEAKS} read_mem 1 pop 1
            push {Digest::LEN} mul addi {OUTPUT_PEAKS} eq
            assert error_id {BlockValidationRule::MutatorSetUpdateIntegrity.error_id()}
            push {prev_epoch_alloc.read_address()} read_mem 1 pop 1
            {&field!(Epoch::min_swbf_padded_rows)} read_mem 1 pop 1 split
            dup 2 addi {1 + OUTPUT_PADDED_ROWS} read_mem 1 pop 1 split
            // _ *w [prev_block_hash] *prev_claim_output *swbf_claim_output [min_padded_rows] [padded_rows]

            call {u64_lt} push 0 eq
            assert error_id {BlockValidationRule::SwbfUpdateBelowWorkFloor.error_id()}
            dup 0 addi {1 + OUTPUT_COUNT} read_mem 1 pop 1
            dup 8 {&prev_block_txk} {&field!(TransactionKernel::inputs)} read_mem 1 pop 1 eq
            assert error_id {BlockValidationRule::RemovalIndexCommitmentMismatch.error_id()}
            // _ *w [prev_block_hash] *prev_claim_output *swbf_claim_output

            dup 7 {&prev_block_txk} {&field!(TransactionKernel::inputs)}
            call {removal_index_commitment}
            {&hash_digest_list}
            dup 5 addi {1 + OUTPUT_NUM_PEAKS} {&hash_digest_list}
            assert_vector error_id {BlockValidationRule::RemovalIndexCommitmentMismatch.error_id()}
            pop {Digest::LEN}
            // _ *w [prev_block_hash] *prev_claim_output *swbf_claim_output

            addi {OUTPUT_MUTATOR_SET_HASH + Digest::LEN} read_mem {Digest::LEN} pop 1
            // _ *w [prev_block_hash] *prev_claim_output [mutator_set_after_removals_hash]

            dup 11 {&prev_block_txk} {&field!(TransactionKernel::inputs)}
            dup 12 {&prev_block_txk} {&field!(TransactionKernel::outputs)}
            dup 13 {&field!(PredecessorIsValidWitnessMemory::prev_block_transaction_mutator_set)}
            dup 14 {&field!(PredecessorIsValidWitnessMemory::prev_block_body)}
            {&field!(BlockBody::mutator_set_accumulator)}
            pick 8 pick 8 pick 8 pick 8 pick 8
            // _ *w [prev_block_hash] *prev_claim_output *inputs *outputs *mutator_set *body_mutator_set [mutator_set_after_removals_hash]

            call {mutator_set_update}
            // _ *w [prev_block_hash] *prev_claim_output
        );

        let is_non_negative = Self::is_non_negative();

        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        let rule_2i_prev = triton_asm!(
            dup 5 {&prev_block_txk} {&field!(TransactionKernel::fee)}
            addi {amount_size - 1} read_mem {amount_size} pop 1
            // _ *w [prev_block_hash] [fee]

            {&is_non_negative}
            assert error_id {BlockValidationRule::NegativeFee.error_id()}
            // _ *w [prev_block_hash]
        );

        // The divined tokens are the positions of the inputs sorted by index
        // set; see [RemovalRecordsAreUnique::divined_tokens].
        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        let rule_2c_prev = triton_asm!(
            dup 5 {&prev_block_txk} {&field!(TransactionKernel::inputs)}
            // _ *w [prev_block_hash] *inputs

            call {removal_records_are_unique}
            // _ *w [prev_block_hash]
        );

        // The mutator set after the previous block: its body's accumulator
        // with the addition records of its guesser reward added. The hash is
        // stored for the claim's output.
        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        let mutator_set_after_prev_block = triton_asm!(
            dup 5 {&prev_block_header}
            dup 5 dup 5 dup 5 dup 5 dup 5
            // _ *w [prev_block_hash] *header [prev_block_hash]

            dup 11 {&prev_block_txk} {&field!(TransactionKernel::fee)}
            addi {amount_size - 1} read_mem {amount_size} pop 1
            // _ *w [prev_block_hash] *header [prev_block_hash] [fee]

            call {guesser_fee_addition_records}
            // _ *w [prev_block_hash] *records

            dup 6 {&field!(PredecessorIsValidWitnessMemory::prev_block_body)}
            {&field!(BlockBody::mutator_set_accumulator)}
            {&MutatorSetHash::read_components()}
            // _ *w [prev_block_hash] *records *window *swbfi_peaks [swbfi_leaf_count] [aocl_leaf_count] *aocl_peaks

            {&copy_digest_list}
            pick 5 {&copy_digest_list} place 5
            // _ *w [prev_block_hash] *records [components]

            pick 7
            // _ *w [prev_block_hash] [components] *records

            call {apply_addition_records}
            // _ *w [prev_block_hash] [components']

            call {mutator_set_hash_from_components}
            // _ *w [prev_block_hash] [mutator_set_hash]

            push {mutator_set_after_prev_block_alloc.write_address()}
            write_mem {Digest::LEN} pop 1
            // _ *w [prev_block_hash]
        );

        let coinbase_is_non_negative = "predecessor_is_valid_coinbase_is_non_negative".to_string();
        let coinbase_is_non_negative_code = triton_asm!(
            // BEFORE: _ *coinbase
            // AFTER:  _ *coinbase
            {coinbase_is_non_negative}:
                dup 0 addi {amount_size} read_mem {amount_size} pop 1
                // _ *coinbase [coinbase]

                {&is_non_negative}
                assert error_id {BlockValidationRule::NegativeCoinbase.error_id()}
                // _ *coinbase

                return
        );

        let coinbase_is_within_subsidy =
            "predecessor_is_valid_coinbase_is_within_subsidy".to_string();
        let coinbase_is_within_subsidy_code = triton_asm!(
            // BEFORE: _ *w [prev_block_hash] *coinbase
            // AFTER:  _ *w [prev_block_hash] *coinbase
            {coinbase_is_within_subsidy}:
                dup 0 addi {amount_size} read_mem {amount_size} pop 1
                // _ *w [prev_block_hash] *coinbase [coinbase]

                dup 10 {&read_prev_block_height}
                call {block_subsidy}
                // _ *w [prev_block_hash] *coinbase [coinbase] [block_subsidy]

                call {i128_lt}
                // _ *w [prev_block_hash] *coinbase (block_subsidy < coinbase)

                push 0 eq
                // _ *w [prev_block_hash] *coinbase (block_subsidy >= coinbase)

                assert error_id {BlockValidationRule::CoinbaseTooBig.error_id()}
                // _ *w [prev_block_hash] *coinbase

                return
        );

        // A retirement announcement is three words: the two flag words and the
        // retirement timestamp. The announcement's words follow its size
        // indicator and its message's length prefix.
        let announcement_is_not_retired =
            "predecessor_is_valid_announcement_is_not_retired".to_string();
        let announcement_is_not_retired_code = triton_asm!(
            // BEFORE: _ prev_block_timestamp *announcement[i]_si num_announcements i
            // AFTER:  _ prev_block_timestamp *announcement[i]_si num_announcements i
            {announcement_is_not_retired}:
                dup 3 split
                // _ prev_block_timestamp *announcement[i]_si num_announcements i [prev_block_timestamp]

                dup 4 addi 5 read_mem 1 pop 1 split
                // _ prev_block_timestamp *announcement[i]_si num_announcements i [prev_block_timestamp] [retirement]

                call {u64_lt}
                push 0 eq assert error_id {BlockValidationRule::TransactionRetired.error_id()}
                // _ prev_block_timestamp *announcement[i]_si num_announcements i

                return
        );

        // Appends the announcement's message to the lustration announcements.
        let remember_lustration = "predecessor_is_valid_remember_lustration".to_string();
        let remember_lustration_code = triton_asm!(
            // BEFORE: _ prev_block_timestamp *announcement[i]_si num_announcements i
            // AFTER:  _ prev_block_timestamp *announcement[i]_si num_announcements i
            {remember_lustration}:
                push {lustrations_alloc.read_address()} read_mem 1 pop 1
                dup 3 addi 2
                // _ prev_block_timestamp *announcement[i]_si num_announcements i *lustrations *message

                call {push_pointer}
                // _ prev_block_timestamp *announcement[i]_si num_announcements i

                return
        );

        // The rules that look at each announcement of the previous block's
        // transaction, in one pass over the list. An announcement is
        // classified by its length and first words. The values the checks
        // compare against sit below the loop's own words.
        let for_each_announcement = "predecessor_is_valid_for_each_announcement".to_string();
        let for_each_announcement_code = triton_asm!(
            // INVARIANT: _ prev_block_timestamp *announcement[i]_si num_announcements i
            {for_each_announcement}:
                dup 1 dup 1 eq skiz return
                // _ prev_block_timestamp *announcement[i]_si num_announcements i

                dup 2 addi 3 read_mem 2 pop 1
                // _ prev_block_timestamp *announcement[i]_si num_announcements i message[0] message_length

                push 0 eq push 0 eq swap 1 push {LUSTRATION_FLAG} eq mul
                // _ prev_block_timestamp *announcement[i]_si num_announcements i is_lustration

                // 2.o)
                skiz call {remember_lustration}
                // _ prev_block_timestamp *announcement[i]_si num_announcements i

                dup 2 addi 4 read_mem 3 pop 1
                // _ prev_block_timestamp *announcement[i]_si num_announcements i message[1] message[0] message_length

                push 3 eq place 2
                push {RETIREMENT_FLAG[0]} eq swap 1
                push {RETIREMENT_FLAG[1]} eq
                mul mul
                // _ prev_block_timestamp *announcement[i]_si num_announcements i is_retirement

                // 2.u)
                skiz call {announcement_is_not_retired}
                // _ prev_block_timestamp *announcement[i]_si num_announcements i

                pick 2 read_mem 1
                // _ prev_block_timestamp num_announcements i announcement_size (*announcement[i]_si - 1)

                // Crashes unless the size is a u32.
                dup 1 pop_count pop 1

                addi 2 add
                // _ prev_block_timestamp num_announcements i *announcement[i + 1]_si

                place 2 addi 1
                // _ prev_block_timestamp *announcement[i + 1]_si num_announcements (i + 1)

                recurse
        );

        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        let prev_block_announcement_rules = triton_asm!(
            call {new_list}
            push {lustrations_alloc.write_address()} write_mem 1 pop 1
            // _ *w [prev_block_hash]

            dup 5 {&read_prev_block_timestamp}
            dup 6 {&prev_block_txk} {&field!(TransactionKernel::announcements)}
            // _ *w [prev_block_hash] prev_block_timestamp *announcements

            read_mem 1 addi 2 place 1 push 0
            // _ *w [prev_block_hash] prev_block_timestamp *announcement[0]_si num_announcements 0

            call {for_each_announcement}
            pop 4
            // _ *w [prev_block_hash]
        );

        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        let rule_2g_prev = triton_asm!(
            dup 5 {&prev_block_txk} {&field!(TransactionKernel::coinbase)}
            // _ *w [prev_block_hash] *coinbase

            dup 0 read_mem 1 pop 1
            // _ *w [prev_block_hash] *coinbase coinbase_is_some

            skiz call {coinbase_is_within_subsidy}
            pop 1
            // _ *w [prev_block_hash]
        );

        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        let rule_2h_prev = triton_asm!(
            dup 5 {&prev_block_txk} {&field!(TransactionKernel::coinbase)}
            // _ *w [prev_block_hash] *coinbase

            dup 0 read_mem 1 pop 1
            // _ *w [prev_block_hash] *coinbase coinbase_is_some

            skiz call {coinbase_is_non_negative}
            pop 1
            // _ *w [prev_block_hash]
        );

        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        let rule_1e_prev = triton_asm!(
            push {prev_epoch_alloc.read_address()} read_mem 1 pop 1
            // _ *w [prev_block_hash] *epoch

            dup 6 {&field_with_size!(PredecessorIsValidWitnessMemory::prev_block_body)}
            pick 1 pop 1
            // _ *w [prev_block_hash] *epoch body_size

            dup 7 {&field_with_size!(PredecessorIsValidWitnessMemory::prev_block_appendix)}
            pick 1 pop 1 add
            // _ *w [prev_block_hash] *epoch (body_size + appendix_size)

            dup 7 {&field!(PredecessorIsValidWitnessMemory::prev_block_proof)}
            read_mem 1 pop 1 add
            // _ *w [prev_block_hash] *epoch (body_size + appendix_size + proof_size)

            addi {PredecessorIsValidWitnessMemory::prev_block_fixed_size()}
            // _ *w [prev_block_hash] *epoch prev_block_size

            dup 1 {&field!(Epoch::max_block_size)} read_mem 1 pop 1
            addi 1 swap 1 lt
            // _ *w [prev_block_hash] *epoch (prev_block_size <= max_block_size)

            assert error_id {BlockValidationRule::MaxSize.error_id()}
            pop 1
            // _ *w [prev_block_hash]
        );

        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        let rule_2f_prev = triton_asm!(
            push {prev_epoch_alloc.read_address()} read_mem 1 pop 1
            // _ *w [prev_block_hash] *epoch

            dup 6 {&prev_block_txk} {&field!(TransactionKernel::timestamp)} read_mem 1 pop 1
            dup 7 {&read_prev_block_timestamp}
            // _ *w [prev_block_hash] *epoch tx_timestamp prev_block_timestamp

            dup 1 split dup 2 split
            // _ *w [prev_block_hash] *epoch tx_timestamp prev_block_timestamp [tx_timestamp] [prev_block_timestamp]

            call {u64_lt}
            push 0 eq assert error_id {BlockValidationRule::TransactionTimestamp.error_id()}
            // _ *w [prev_block_hash] *epoch tx_timestamp prev_block_timestamp

            pick 1 push -1 mul add split
            // _ *w [prev_block_hash] *epoch [prev_block_timestamp - tx_timestamp]

            dup 2 {&field!(Epoch::transaction_backdating_threshold)} read_mem 1 pop 1 split
            // _ *w [prev_block_hash] *epoch [prev_block_timestamp - tx_timestamp] [backdating_threshold]

            call {u64_lt}
            push 0 eq assert error_id {BlockValidationRule::TransactionTimestamp.error_id()}
            pop 1
            // _ *w [prev_block_hash]
        );

        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        let rule_2j_prev = triton_asm!(
            push {prev_epoch_alloc.read_address()} read_mem 1 pop 1
            // _ *w [prev_block_hash] *epoch

            dup 6 {&prev_block_txk} {&field!(TransactionKernel::inputs)}
            read_mem 1 pop 1
            // _ *w [prev_block_hash] *epoch num_inputs

            dup 1 {&field!(Epoch::max_num_inputs)} read_mem 1 pop 1
            addi 1 swap 1 lt
            // _ *w [prev_block_hash] *epoch (num_inputs <= max_num_inputs)

            assert error_id {BlockValidationRule::TooManyInputs.error_id()}
            pop 1
            // _ *w [prev_block_hash]
        );

        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        let rule_2k_prev = triton_asm!(
            push {prev_epoch_alloc.read_address()} read_mem 1 pop 1
            // _ *w [prev_block_hash] *epoch

            dup 6 {&prev_block_txk} {&field!(TransactionKernel::outputs)}
            read_mem 1 pop 1
            // _ *w [prev_block_hash] *epoch num_outputs

            dup 1 {&field!(Epoch::max_num_outputs)} read_mem 1 pop 1
            addi 1 swap 1 lt
            // _ *w [prev_block_hash] *epoch (num_outputs <= max_num_outputs)

            assert error_id {BlockValidationRule::TooManyOutputs.error_id()}
            pop 1
            // _ *w [prev_block_hash]
        );

        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        let rule_2l_prev = triton_asm!(
            push {prev_epoch_alloc.read_address()} read_mem 1 pop 1
            // _ *w [prev_block_hash] *epoch

            dup 6 {&prev_block_txk} {&field!(TransactionKernel::announcements)}
            read_mem 1 pop 1
            // _ *w [prev_block_hash] *epoch num_announcements

            dup 1 {&field!(Epoch::max_num_announcements)} read_mem 1 pop 1
            addi 1 swap 1 lt
            // _ *w [prev_block_hash] *epoch (num_announcements <= max_num_announcements)

            assert error_id {BlockValidationRule::TooManyAnnouncements.error_id()}
            pop 1
            // _ *w [prev_block_hash]
        );

        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        let rule_2s_prev = triton_asm!(
            dup 5 {&prev_lustration_status} {&field!(LustrationStatus::counter)}
            addi {amount_size - 1} read_mem {amount_size} pop 1
            // _ *w [prev_block_hash] [prev_lustration_counter]

            push {prev_epoch_alloc.read_address()} read_mem 1 pop 1
            {&field!(Epoch::lustration_counter_initial)}
            addi {amount_size - 1} read_mem {amount_size} pop 1
            // _ *w [prev_block_hash] [prev_lustration_counter] [lustration_counter_initial]

            call {i128_lt}
            // _ *w [prev_block_hash] (lustration_counter_initial < prev_lustration_counter)

            push 0 eq
            assert error_id {BlockValidationRule::LustrationCounterExceedsInitialValue.error_id()}
            // _ *w [prev_block_hash]
        );

        // BEFORE: _ *w [prev_block_hash] *prev_claim_output
        // AFTER:  _ *w [prev_block_hash] *prev_claim_output
        let rule_2q_prev = triton_asm!(
            dup 6 {&prev_lustration_status}
            {&field!(LustrationStatus::max_lustrating_aocl_leaf_index)} {&read_u64}
            // _ *w [prev_block_hash] *prev_claim_output [prev_threshold]

            dup 2 addi {Digest::LEN + 1}
            {&field!(LustrationStatus::max_lustrating_aocl_leaf_index)} {&read_u64}
            // _ *w [prev_block_hash] *prev_claim_output [prev_threshold] [prev_prev_threshold]

            {&DataType::U64.compare()}
            assert error_id {BlockValidationRule::BadLustrationAoclThreshold.error_id()}
            // _ *w [prev_block_hash] *prev_claim_output
        );

        // The previous block's lustration counter must be its predecessor's
        // less what its transaction lustrates, and must not fall below zero.
        // BEFORE: _ *w [prev_block_hash] *prev_claim_output
        // AFTER:  _ *w [prev_block_hash] *prev_claim_output
        let rules_2o_2p_2r_prev = triton_asm!(
            dup 6 {&prev_block_txk} {&field!(TransactionKernel::inputs)}
            push {lustrations_alloc.read_address()} read_mem 1 pop 1
            dup 2 addi {Digest::LEN + 1}
            {&field!(LustrationStatus::max_lustrating_aocl_leaf_index)} {&read_u64}
            // _ *w [prev_block_hash] *prev_claim_output *inputs *lustrations [prev_prev_threshold]

            // 2.o)
            call {verified_lustration_amount}
            // _ *w [prev_block_hash] *prev_claim_output [lustrated]

            dup 4 addi {Digest::LEN + 1} {&field!(LustrationStatus::counter)}
            addi {amount_size - 1} read_mem {amount_size} pop 1
            // _ *w [prev_block_hash] *prev_claim_output [lustrated] [prev_prev_counter]

            // 2.r)
            push {1_u64 << 31} dup 4 lt
            push {1_u64 << 31} dup 9 lt
            mul assert error_id {BlockValidationRule::NegativeLustrationCounter.error_id()}
            // _ *w [prev_block_hash] *prev_claim_output [lustrated] [prev_prev_counter]

            dup 7 dup 7 dup 7 dup 7 dup 7 dup 7 dup 7 dup 7
            call {i128_lt}
            // _ *w [prev_block_hash] *prev_claim_output [lustrated] [prev_prev_counter] (prev_prev_counter < lustrated)

            push 0 eq
            assert error_id {BlockValidationRule::NegativeLustrationCounter.error_id()}
            call {u128_sub}
            // _ *w [prev_block_hash] *prev_claim_output [expected_counter]

            // 2.p)
            dup 10 {&prev_lustration_status} {&field!(LustrationStatus::counter)}
            addi {amount_size - 1} read_mem {amount_size} pop 1
            {&DataType::U128.compare()}
            assert error_id {BlockValidationRule::BadLustrationCounter.error_id()}
            // _ *w [prev_block_hash] *prev_claim_output
        );

        // The rules about the previous block that depend on the epoch in
        // force at its height: its header fields that its own program
        // execution could not assert, since they were not fixed when that
        // program execution was run, and the limits on its transaction. The
        // required values of *its* predecessor (next block's grandparent) come
        // from the previous block's copy of this claim.
        let (rule_0b_prev, rule_0b_prev_code) = subroutine("rule_0b_prev", rule_0b_prev);
        let (rule_0d_prev, rule_0d_prev_code) = subroutine("rule_0d_prev", rule_0d_prev);
        let (rule_0e_prev, rule_0e_prev_code) = subroutine("rule_0e_prev", rule_0e_prev);
        let (rule_0f_prev, rule_0f_prev_code) = subroutine("rule_0f_prev", rule_0f_prev);
        let (rule_2t_prev, rule_2t_prev_code) = subroutine("rule_2t_prev", rule_2t_prev);
        let (mutator_set_update_prev, mutator_set_update_prev_code) =
            subroutine("mutator_set_update_prev", mutator_set_update_prev);
        let (rule_2q_prev, rule_2q_prev_code) = subroutine("rule_2q_prev", rule_2q_prev);
        let (rules_2o_2p_2r_prev, rules_2o_2p_2r_prev_code) =
            subroutine("rules_2o_2p_2r_prev", rules_2o_2p_2r_prev);

        // Whether the previous block is the first of an epoch that resets the
        // lustration status.
        // BEFORE: _ *w [prev_block_hash] *prev_claim_output
        // AFTER:  _ *w [prev_block_hash] *prev_claim_output resets_lustration_status
        let prev_block_resets_lustration_status = triton_asm!(
            push {prev_epoch_alloc.read_address()} read_mem 1 pop 1
            dup 0 {&field!(Epoch::resets_lustration_status)} read_mem 1 pop 1
            swap 1 {&field!(Epoch::height)} read_mem 1 pop 1
            // _ *w [prev_block_hash] *prev_claim_output resets_lustration_status epoch_height

            dup 8 {&read_prev_block_height} eq mul
            // _ *w [prev_block_hash] *prev_claim_output (resets_lustration_status && epoch_height == prev_block_height)
        );

        // At a reset, the previous block's counter must be the initial one
        // and its threshold its own last AOCL leaf index.
        // BEFORE: _ *w [prev_block_hash] *prev_claim_output 1
        // AFTER:  _ *w [prev_block_hash] *prev_claim_output 1
        let lustration_reset_prev = triton_asm!(
            // 2.p)
            dup 7 {&prev_lustration_status} {&field!(LustrationStatus::counter)}
            addi {amount_size - 1} read_mem {amount_size} pop 1
            push {prev_epoch_alloc.read_address()} read_mem 1 pop 1
            {&field!(Epoch::lustration_counter_initial)}
            addi {amount_size - 1} read_mem {amount_size} pop 1
            // _ *w [prev_block_hash] *prev_claim_output 1 [prev_counter] [lustration_counter_initial]

            {&DataType::U128.compare()}
            assert error_id {BlockValidationRule::BadLustrationCounter.error_id()}
            // _ *w [prev_block_hash] *prev_claim_output 1

            // 2.q)
            dup 7 {&prev_lustration_status}
            {&field!(LustrationStatus::max_lustrating_aocl_leaf_index)} {&read_u64}
            dup 9 {&field!(PredecessorIsValidWitnessMemory::prev_block_body)}
            {&field!(BlockBody::mutator_set_accumulator)}
            {&field!(MutatorSetAccumulator::aocl)}
            {&field!(MmrAccumulator::leaf_count)} {&read_u64}
            push 0 push {NUM_GUESSER_FEE_OUTPUTS - 1}
            call {u64_add}
            // _ *w [prev_block_hash] *prev_claim_output 1 [prev_threshold] [prev_block_max_aocl_leaf_index]

            {&DataType::U64.compare()}
            assert error_id {BlockValidationRule::BadLustrationAoclThreshold.error_id()}
            // _ *w [prev_block_hash] *prev_claim_output 1
        );
        let (lustration_reset_prev, lustration_reset_prev_code) =
            subroutine("lustration_reset_prev", lustration_reset_prev);
        let (lustration_update_prev, lustration_update_prev_code) = subroutine(
            "lustration_update_prev",
            triton_asm!(call {rule_2q_prev} call {rules_2o_2p_2r_prev}),
        );
        let (rule_1e_prev, rule_1e_prev_code) = subroutine("rule_1e_prev", rule_1e_prev);
        let (rule_2f_prev, rule_2f_prev_code) = subroutine("rule_2f_prev", rule_2f_prev);
        let (rule_2j_prev, rule_2j_prev_code) = subroutine("rule_2j_prev", rule_2j_prev);
        let (rule_2k_prev, rule_2k_prev_code) = subroutine("rule_2k_prev", rule_2k_prev);
        let (rule_2l_prev, rule_2l_prev_code) = subroutine("rule_2l_prev", rule_2l_prev);
        let (rule_2s_prev, rule_2s_prev_code) = subroutine("rule_2s_prev", rule_2s_prev);

        // The mutator set after the previous block's parent, which its
        // transaction is built on; rule 2.t authenticates it.
        // BEFORE: _ *w
        // AFTER:  _ *mutator_set
        let prev_block_mutator_set = triton_asm!({
            &field!(PredecessorIsValidWitnessMemory::prev_block_transaction_mutator_set)
        });
        // 2.v) The guesser's reveal in the proof-of-work field, of the
        // mutator set after the previous block's parent.
        let mutator_set_reveals_required_prev =
            "predecessor_is_valid_mutator_set_reveals_required_prev".to_string();
        let mutator_set_reveals_required_prev_code = triton_asm!(
            // BEFORE: _ *w [prev_block_hash] *prev_claim_output
            // AFTER:  _ *w [prev_block_hash] *prev_claim_output
            {mutator_set_reveals_required_prev}:
                dup 6 {&prev_block_header}
                dup 7 {&prev_block_mutator_set} {&field!(MutatorSetAccumulator::swbf_inactive)}
                // _ *w [prev_block_hash] *prev_claim_output *header *swbfi

                call {guesser_swbfi_reveal}
                // _ *w [prev_block_hash] *prev_claim_output
                return
        );

        // BEFORE: _ *w [prev_block_hash] *prev_claim_output
        // AFTER:  _ *w [prev_block_hash] *prev_claim_output
        let mutator_set_reveals_prev = triton_asm!(
            push {prev_epoch_alloc.read_address()} read_mem 1 pop 1
            {&field!(Epoch::requires_mutator_set_reveals)} read_mem 1 pop 1
            skiz call {mutator_set_reveals_required_prev}
        );

        let prev_block_epoch_rules = "predecessor_is_valid_prev_block_epoch_rules".to_string();
        let prev_block_epoch_rules_code = triton_asm!(
            // BEFORE: _ *w [prev_block_hash]
            // AFTER:  _ *w [prev_block_hash]
            {prev_block_epoch_rules}:
                push {prev_epoch_alloc.read_address()} read_mem 1 pop 1
                // _ *w [prev_block_hash] *epoch

                dup 0 {&field!(Epoch::target_block_interval)} read_mem 1 pop 1
                swap 1 {&field!(Epoch::minimum_block_time)} read_mem 1 pop 1
                // _ *w [prev_block_hash] prev_target_block_interval prev_minimum_block_time

                push {prev_timing_alloc.write_address()} write_mem 2 pop 1
                // _ *w [prev_block_hash]

                dup 5 {&field!(PredecessorIsValidWitnessMemory::prev_block_appendix)}
                {&field!(BlockAppendix::claims)}
                // _ *w [prev_block_hash] *claims

                read_mem 1 addi 2 place 1 push 0
                // _ *w [prev_block_hash] *claim[0]_si num_claims 0

                call {find_own_claim}
                // _ *w [prev_block_hash] *claim_si num_claims i

                pop 2 addi 1
                {&field!(Claim::output)}
                // _ *w [prev_block_hash] *prev_claim_output

                call {rule_0b_prev}
                // _ *w [prev_block_hash] *prev_claim_output

                call {rule_0d_prev}
                // _ *w [prev_block_hash] *prev_claim_output

                call {rule_0e_prev}
                // _ *w [prev_block_hash] *prev_claim_output

                call {rule_0f_prev}
                // _ *w [prev_block_hash] *prev_claim_output

                call {rule_2t_prev}
                // _ *w [prev_block_hash] *prev_claim_output

                call {mutator_set_update_prev}
                // _ *w [prev_block_hash] *prev_claim_output
                {&mutator_set_reveals_prev}
                // _ *w [prev_block_hash] *prev_claim_output

                {&prev_block_resets_lustration_status}
                // _ *w [prev_block_hash] *prev_claim_output resets_lustration_status

                dup 0 skiz call {lustration_reset_prev}
                push 0 eq skiz call {lustration_update_prev}
                // _ *w [prev_block_hash] *prev_claim_output

                pop 1
                // _ *w [prev_block_hash]

                call {rule_1e_prev}
                // _ *w [prev_block_hash]

                call {rule_2f_prev}
                // _ *w [prev_block_hash]

                call {rule_2j_prev}
                // _ *w [prev_block_hash]

                call {rule_2k_prev}
                // _ *w [prev_block_hash]

                call {rule_2l_prev}
                // _ *w [prev_block_hash]

                call {rule_2s_prev}
                // _ *w [prev_block_hash]

                return
        );

        // Reads the entire epoch table from this execution's standard-in.
        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        // STDIN:  [epoch_table]
        let read_epoch_table = triton_asm!(
            push {epochs_alloc.write_address()}
            {&vec![triton_asm!(read_io 1 pick 1 write_mem 1); epochs_alloc.num_words() as usize].concat()}
            pop 1
            // _ *w [prev_block_hash]

            dup 5 {&read_prev_block_height}
            push {expected_prev_height_alloc.write_address()} write_mem 1 pop 1
            // _ *w [prev_block_hash]
        );
        let (read_epoch_table, read_epoch_table_code) =
            subroutine("read_epoch_table", read_epoch_table);

        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        let prev_block_epoch_rules_if_activated = triton_asm!(
            push {epochs_alloc.write_address()} {&field!(Epoch::height)} read_mem 1 pop 1 split
            // _ *w [prev_block_hash] [activation_height: u64]

            dup 7 {&read_prev_block_height} split
            // _ *w [prev_block_hash] [activation_height] [prev_block_height]

            call {u64_lt}
            // _ *w [prev_block_hash] (prev_block_height < activation_height)

            push 0 eq
            // _ *w [prev_block_hash] (prev_block_height >= activation_height)

            skiz call {prev_block_epoch_rules}
            // _ *w [prev_block_hash]
        );

        // BEFORE: _ [next_block_body_mh] *w
        // AFTER:  _ [next_block_body_mh] *w
        let authenticate_next_block_mmr_accumulator = triton_asm!(
            dup 5 dup 5 dup 5 dup 5 dup 5
            push {BlockBody::MAST_HEIGHT}
            push {BlockBodyField::BlockMmrAccumulator as u32}
            // _ [next_block_body_mh] *w [next_block_body_mh] height index

            dup 7 {&field_with_size!(PredecessorIsValidWitnessMemory::next_block_mmr_accumulator)}
            call {hash_varlen}
            // _ [next_block_body_mh] *w [next_block_body_mh] height index [leaf]

            call {merkle_verify}
            // _ [next_block_body_mh] *w
        );

        let mut minimum_difficulty_limbs = BigUint::from(Difficulty::MINIMUM).to_u32_digits();
        minimum_difficulty_limbs.resize(Difficulty::NUM_LIMBS, 0);
        let push_minimum_difficulty = minimum_difficulty_limbs
            .iter()
            .rev()
            .flat_map(|&limb| triton_asm!(push { limb }))
            .collect::<Vec<_>>();

        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        let prev_block_pow = triton_asm!(
                {&push_minimum_difficulty}
                // _ *w [prev_block_hash] [minimum_difficulty]

                dup 10 {&read_prev_block_difficulty}
                // _ *w [prev_block_hash] [minimum_difficulty] [difficulty]

                call {u160_lt}
                // _ *w [prev_block_hash] (difficulty < minimum_difficulty)

                push 0 eq assert error_id {PowValidationError::ThresholdNotMet.error_id()}
                // _ *w [prev_block_hash]

                dup 5 {&read_prev_block_difficulty}
                // _ *w [prev_block_hash] [difficulty]

                dup 9 dup 9 dup 9 dup 9 dup 9
                // _ *w [prev_block_hash] [difficulty] [prev_block_hash]

                call {meets_threshold}
                assert error_id {PowValidationError::ThresholdNotMet.error_id()}
                // _ *w [prev_block_hash]
        );

        // The status parses when each of its words is a u32.
        // BEFORE: _ *w
        // AFTER:  _ *w
        let rule_2m_prev = triton_asm!(
            dup 0 {&read_prev_lustration_status}
            // _ *w [prev_lustration_status]

            {&vec![triton_asm!(
                dup 0 split pop 1 push 0 eq
                assert error_id {BlockValidationRule::BadLustrationCounterEncoding.error_id()}
                place {lustration_status_size - 1}
            ); lustration_status_size].concat()}
            // _ *w [prev_lustration_status]

            pop {Digest::LEN} pop {lustration_status_size - Digest::LEN}
            // _ *w
        );

        // BEFORE: _ *w
        // AFTER:  _
        let write_prev_block_header_fields = triton_asm!(
            {&prev_block_header}
            // _ *header

            dup 0 {&field!(BlockHeader::timestamp)} read_mem 1 pop 1
            write_io 1
            // _ *header

            dup 0 {&field!(BlockHeader::cumulative_proof_of_work)} {&read_cumulative_pow}
            {&DataType::U192.write_value_to_stdout()}
            // _ *header

            {&field!(BlockHeader::difficulty)} {&read_difficulty}
            write_io {Digest::LEN}
            // _
        );

        // BEFORE: _ *header
        // AFTER:  _ version_in_pow
        let read_version_in_pow = triton_asm!(
            {&field!(BlockHeader::pow)} {&field!(BlockPow::path_a)}
            addi {Digest::LEN * (POW_MEMORY_TREE_HEIGHT - 3) + Digest::LEN - 1} read_mem 1 pop 1
        );

        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        let rule_1f_prev = triton_asm!(
            dup 5 {&prev_block_header} {&field!(BlockHeader::version)} read_mem 1 pop 1
            // _ *w [prev_block_hash] version

            dup 6 {&prev_block_header} {&read_version_in_pow}
            // _ *w [prev_block_hash] version version_in_pow

            eq assert error_id {BlockValidationRule::VersionMismatch.error_id()}
            // _ *w [prev_block_hash]
        );

        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        let rule_1b_prev = triton_asm!(
            dup 5 {&field!(PredecessorIsValidWitnessMemory::prev_block_appendix)}
            {&field!(BlockAppendix::claims)}
            read_mem 1 pop 1
            // _ *w [prev_block_hash] num_claims

            push {MAX_NUM_CLAIMS + 1} swap 1 lt
            // _ *w [prev_block_hash] (num_claims <= MAX_NUM_CLAIMS)

            assert error_id {BlockValidationRule::AppendixTooLarge.error_id()}
            // _ *w [prev_block_hash]
        );

        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        let rule_1c_prev = triton_asm!(
            dup 5 {&field!(PredecessorIsValidWitnessMemory::prev_block_proof)}
            addi 1 read_mem 1 pop 1
            // _ *w [prev_block_hash] block_proof_discriminant

            push {BlockProof::SINGLE_PROOF_DISCRIMINANT} eq
            assert error_id {BlockValidationRule::ProofQuality.error_id()}
            // _ *w [prev_block_hash]
        );

        // Hash each appendix claim into the block program claim's output.
        let hash_appendix_claims = "predecessor_is_valid_hash_appendix_claims".to_string();
        let hash_appendix_claims_code = triton_asm!(
            // INVARIANT: _ *claim[i]_si *output[i] num_claims i
            {hash_appendix_claims}:
                dup 1 dup 1 eq skiz return
                // _ *claim[i]_si *output[i] num_claims i

                dup 3 read_mem 1 addi 2
                // _ *claim[i]_si *output[i] num_claims i claim_size *claim[i]

                // Crashes unless the size is a u32.
                dup 1 pop_count pop 1

                dup 1 call {hash_varlen}
                // _ *claim[i]_si *output[i] num_claims i claim_size [claim_hash]

                dup 8 write_mem {Digest::LEN}
                // _ *claim[i]_si *output[i] num_claims i claim_size *output[i + 1]

                pick 4 pop 1 place 3
                // _ *claim[i]_si *output[i + 1] num_claims i claim_size

                pick 4 add addi 1 place 3
                // _ *claim[i + 1]_si *output[i + 1] num_claims i

                addi 1
                recurse
        );

        // The verifier crashes on an invalid proof; that crash carries no
        // error ID.
        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        let rule_1d_prev = triton_asm!(
            dup 5 {&field!(PredecessorIsValidWitnessMemory::prev_block_appendix)}
            {&field!(BlockAppendix::claims)}
            read_mem 1 addi 2 place 1
            // _ *w [prev_block_hash] *claim[0]_si num_claims

            push {Digest::LEN} dup 1 push {Digest::LEN} mul
            call {new_claim}
            // _ *w [prev_block_hash] *claim[0]_si num_claims *claim *output *input *program_digest

            {&read_prev_epoch_block_program_digest}
            pick 5 write_mem {Digest::LEN} pop 1
            // _ *w [prev_block_hash] *claim[0]_si num_claims *claim *output *input

            push {prev_block_body_mh_alloc.read_address()} read_mem {Digest::LEN} pop 1
            swap 4 swap 1 swap 3 swap 1
            // _ *w [prev_block_hash] *claim[0]_si num_claims *claim *output *input [prev_block_body_mh_reversed]

            pick 5 write_mem {Digest::LEN} pop 1
            // _ *w [prev_block_hash] *claim[0]_si num_claims *claim *output

            pick 1 place 3 swap 1 push 0
            // _ *w [prev_block_hash] *claim *claim[0]_si *output num_claims 0

            call {hash_appendix_claims}
            // _ *w [prev_block_hash] *claim *claim[n]_si *output[n] num_claims num_claims

            pop 4
            // _ *w [prev_block_hash] *claim

            dup 6 {&field!(PredecessorIsValidWitnessMemory::prev_block_proof)}
            addi {1 + BlockProof::SINGLE_PROOF_PREFIX_LEN}
            // _ *w [prev_block_hash] *claim *proof

            call {stark_verify}
            // _ *w [prev_block_hash]
        );

        // Find the claim with this hash in the previous block's appendix.
        let find_claim_by_hash = "predecessor_is_valid_find_claim_by_hash".to_string();
        let find_claim_by_hash_code = triton_asm!(
            // INVARIANT: _ [claim_hash] *claim[i]_si num_claims i
            {find_claim_by_hash}:
                dup 1 dup 1 eq
                push 0 eq assert error_id {BlockValidationRule::AppendixMissingClaim.error_id()}
                // _ [claim_hash] *claim[i]_si num_claims i

                dup 2 read_mem 1 addi 2
                // _ [claim_hash] *claim[i]_si num_claims i claim_size *claim[i]

                // Crashes unless the size is a u32.
                dup 1 pop_count pop 1

                dup 1 call {hash_varlen}
                // _ [claim_hash] *claim[i]_si num_claims i claim_size [claim[i]_hash]

                dup 13 dup 13 dup 13 dup 13 dup 13
                {&digests_are_equal}
                // _ [claim_hash] *claim[i]_si num_claims i claim_size hashes_match

                pick 1 pop 1
                skiz return
                // _ [claim_hash] *claim[i]_si num_claims i

                pick 2 read_mem 1
                // _ [claim_hash] num_claims i claim_size (*claim[i]_si - 1)

                // Crashes unless the size is a u32.
                dup 1 pop_count pop 1

                addi 2 add
                // _ [claim_hash] num_claims i *claim[i+1]_si

                place 2 addi 1
                // _ [claim_hash] *claim[i+1]_si num_claims (i + 1)

                recurse
        );

        // The transaction claim; this program's own claim is found under the
        // header rules.
        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        let rule_1a_txproof_prev = triton_asm!(
            push {prev_block_txk_mh_alloc.read_address()} read_mem {Digest::LEN} pop 1
            {&read_prev_epoch_single_proof_digest}
            call {generate_single_proof_claim}
            // _ *w [prev_block_hash] *transaction_claim

            push {transaction_claim_size} call {hash_varlen}
            // _ *w [prev_block_hash] [transaction_claim_hash]

            dup 10 {&field!(PredecessorIsValidWitnessMemory::prev_block_appendix)}
            {&field!(BlockAppendix::claims)}
            read_mem 1 addi 2 place 1 push 0
            // _ *w [prev_block_hash] [transaction_claim_hash] *claim[0]_si num_claims 0

            call {find_claim_by_hash}
            // _ *w [prev_block_hash] [transaction_claim_hash] *claim[i]_si num_claims i

            pop 3 pop {Digest::LEN}
            // _ *w [prev_block_hash]
        );

        let (rule_1c_prev, rule_1c_prev_code) = subroutine("rule_1c_prev", rule_1c_prev);
        let (rule_1d_prev, rule_1d_prev_code) = subroutine("rule_1d_prev", rule_1d_prev);

        // 1.g) A parent at height zero is the genesis block the claim names;
        // no other rule applies to it.
        // BEFORE: _ *w [prev_block_hash] prev_block_is_genesis
        // AFTER:  _ *w [prev_block_hash] prev_block_is_genesis
        let rule_1g_prev = triton_asm!(
            dup 5 dup 5 dup 5 dup 5 dup 5
            push {genesis_alloc.read_address()} read_mem {Digest::LEN} pop 1
            assert_vector error_id {BlockValidationRule::GenesisHash.error_id()}
            pop {Digest::LEN}
        );
        let (rule_1g_prev, rule_1g_prev_code) = subroutine("rule_1g_prev", rule_1g_prev);

        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash] prev_block_is_genesis
        let prev_block_is_genesis = triton_asm!(dup 5 {&read_prev_block_height} push 0 eq);
        let (verify_prev_block_proof, verify_prev_block_proof_code) =
            if self.verifies_prev_block_proof {
                (
                    triton_asm!(call {rule_1c_prev} call {rule_1d_prev}),
                    [rule_1c_prev_code, rule_1d_prev_code].concat(),
                )
            } else {
                (Vec::new(), Vec::new())
            };

        // The claim's output: the previous block's hash, lustration status,
        // timestamp, cumulative proof-of-work and difficulty, and the hash
        // of the mutator set after it.
        // BEFORE: _ [next_block_body_mh] *w [prev_block_hash]
        // AFTER:  _ [next_block_body_mh]
        let write_output = triton_asm!(
            // 0.b)
            write_io {Digest::LEN}
            // _ [next_block_body_mh] *w

            dup 0 {&read_prev_lustration_status}
            {&lustration_status_type.write_value_to_stdout()}
            // _ [next_block_body_mh] *w

            {&write_prev_block_header_fields}
            // _ [next_block_body_mh]

            push {mutator_set_after_prev_block_alloc.read_address()}
            read_mem {Digest::LEN} pop 1
            write_io {Digest::LEN}
            // _ [next_block_body_mh]
        );

        let (authenticate_next_block_mmr_accumulator, authenticate_next_block_mmr_accumulator_code) =
            subroutine(
                "authenticate_next_block_mmr_accumulator",
                authenticate_next_block_mmr_accumulator,
            );
        let (hash_prev_block_body, hash_prev_block_body_code) =
            subroutine("hash_prev_block_body", hash_prev_block_body);
        let (prev_block_hash, prev_block_hash_code) =
            subroutine("prev_block_hash", prev_block_hash);
        let (rule_0a, rule_0a_code) = subroutine("rule_0a", rule_0a);
        let (rule_0c, rule_0c_code) = subroutine("rule_0c", rule_0c);
        let (rule_1f_prev, rule_1f_prev_code) = subroutine("rule_1f_prev", rule_1f_prev);
        let (prev_block_pow, prev_block_pow_code) =
            subroutine("proof_of_work_prev", prev_block_pow);
        let (rule_1b_prev, rule_1b_prev_code) = subroutine("rule_1b_prev", rule_1b_prev);
        let (rule_1a_txproof_prev, rule_1a_txproof_prev_code) =
            subroutine("rule_1a_prev", rule_1a_txproof_prev);
        let (rule_2g_prev, rule_2g_prev_code) = subroutine("rule_2g_prev", rule_2g_prev);
        let (rule_2h_prev, rule_2h_prev_code) = subroutine("rule_2h_prev", rule_2h_prev);
        let (rule_2i_prev, rule_2i_prev_code) = subroutine("rule_2i_prev", rule_2i_prev);
        let (rule_2c_prev, rule_2c_prev_code) = subroutine("rule_2c_prev", rule_2c_prev);
        let (mutator_set_after_prev_block, mutator_set_after_prev_block_code) =
            subroutine("mutator_set_after_prev_block", mutator_set_after_prev_block);
        let (prev_block_announcement_rules, prev_block_announcement_rules_code) = subroutine(
            "rules_2o_2u_announcements_prev",
            prev_block_announcement_rules,
        );
        let (rule_2m_prev, rule_2m_prev_code) = subroutine("rule_2m_prev", rule_2m_prev);
        let (write_output, write_output_code) = subroutine("write_output", write_output);

        // The rules of a parent that was mined, which a genesis parent is not.
        // BEFORE: _ [next_block_body_mh] *w [prev_block_hash]
        // AFTER:  _ [next_block_body_mh] *w [prev_block_hash]
        let (rules_for_mined_parent, rules_for_mined_parent_code) = subroutine(
            "rules_for_mined_parent",
            triton_asm!(
            call {rule_1f_prev}
            // _ [next_block_body_mh] *w [prev_block_hash]

            call {prev_block_pow}
            // _ [next_block_body_mh] *w [prev_block_hash]

            call {rule_1b_prev}
            // _ [next_block_body_mh] *w [prev_block_hash]

            {&verify_prev_block_proof}
            // _ [next_block_body_mh] *w [prev_block_hash]

            call {rule_1a_txproof_prev}
            // _ [next_block_body_mh] *w [prev_block_hash]


            call {rule_2g_prev}
            // _ [next_block_body_mh] *w [prev_block_hash]


            call {rule_2h_prev}
            // _ [next_block_body_mh] *w [prev_block_hash]


            call {rule_2i_prev}
            // _ [next_block_body_mh] *w [prev_block_hash]


            call {rule_2c_prev}
            // _ [next_block_body_mh] *w [prev_block_hash]

            // _ [next_block_body_mh] *w [prev_block_hash]


            call {prev_block_announcement_rules}
            // _ [next_block_body_mh] *w [prev_block_hash]


            ),
        );

        let code = triton_asm!(
            call {own_program_digest}
            push {own_program_digest_alloc.write_address()} write_mem {Digest::LEN} pop 1
            // _

            read_io {Digest::LEN}
            // _ [next_block_body_mh]

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            hint witness = stack[0]
            // _ [next_block_body_mh] *w

            dup 0 call {audit_witness} pop 1
            call {authenticate_next_block_mmr_accumulator}
            call {hash_prev_block_body}
            // _ [next_block_body_mh] *w

            /* Construct previous block hash from non-deterministic memory,
            reconstructing the MAST hash construction. Along with its proof
            verification, this established that the ND memory for the previous
            block is authentic. */
            call {prev_block_hash}
            // _ [next_block_body_mh] *w [prev_block_hash]

            call {rule_0a}
            // _ [next_block_body_mh] *w [prev_block_hash]

            call {rule_0c}
            // _ [next_block_body_mh] *w [prev_block_hash]

            // STDIN: [epoch_table]
            call {read_epoch_table}
            // _ [next_block_body_mh] *w [prev_block_hash]

            /* The epoch in force at the previous block's height, dictated by
               the table from std-in: the first epoch for a previous block
               before activation, whose program digests apply to it. */
            dup 5 {&read_prev_block_height}
            call {epoch_in_force}
            push {prev_epoch_alloc.write_address()} write_mem 1 pop 1
            // _ [next_block_body_mh] *w [prev_block_hash]

            {&prev_block_is_genesis}
            dup 0 skiz call {rule_1g_prev}
            push 0 eq skiz call {rules_for_mined_parent}
            // _ [next_block_body_mh] *w [prev_block_hash]

            call {mutator_set_after_prev_block}
            // _ [next_block_body_mh] *w [prev_block_hash]

            dup 5 call {rule_2m_prev} pop 1
            // _ [next_block_body_mh] *w [prev_block_hash]


            {&prev_block_epoch_rules_if_activated}
            // _ [next_block_body_mh] *w [prev_block_hash]

            call {write_output}
            // _ [next_block_body_mh]

            pop {Digest::LEN}
            halt

            {&header_mast_hash_code}
            {&transaction_kernel_mast_hash_code}
            {&hash_appendix_claims_code}
            {&find_claim_by_hash_code}
            {&epochs_are_equal_code}
            {&epoch_has_started_code}
            {&epoch_in_force_code}
            {&epoch_tables_agree_code}
            {&own_claim_input_matches_code}
            {&find_own_claim_code}
            {&coinbase_is_within_subsidy_code}
            {&coinbase_is_non_negative_code}
            {&for_each_announcement_code}
            {&announcement_is_not_retired_code}
            {&remember_lustration_code}
            {&prev_block_epoch_rules_code}
            {&authenticate_next_block_mmr_accumulator_code}
            {&hash_prev_block_body_code}
            {&prev_block_hash_code}
            {&rule_0a_code}
            {&rule_0c_code}
            {&rule_1f_prev_code}
            {&prev_block_pow_code}
            {&rule_1b_prev_code}
            {&verify_prev_block_proof_code}
            {&rule_1g_prev_code}
            {&rules_for_mined_parent_code}
            {&rule_1a_txproof_prev_code}
            {&rule_2g_prev_code}
            {&rule_2h_prev_code}
            {&rule_2i_prev_code}
            {&rule_2c_prev_code}
            {&mutator_set_after_prev_block_code}
            {&prev_block_announcement_rules_code}
            {&rule_2m_prev_code}
            {&read_epoch_table_code}
            {&rule_0b_prev_code}
            {&rule_0d_prev_code}
            {&rule_0e_prev_code}
            {&rule_0f_prev_code}
            {&rule_2t_prev_code}
            {&mutator_set_update_prev_code}
            {&swbf_claim_input_matches_code}
            {&find_swbf_claim_code}
            {&mutator_set_reveals_required_prev_code}
            {&rule_2q_prev_code}
            {&rules_2o_2p_2r_prev_code}
            {&lustration_reset_prev_code}
            {&lustration_update_prev_code}
            {&rule_1e_prev_code}
            {&rule_2f_prev_code}
            {&rule_2j_prev_code}
            {&rule_2k_prev_code}
            {&rule_2l_prev_code}
            {&rule_2s_prev_code}
            {&write_output_code}
            {&library.all_imports()}
        );

        (library, code)
    }

    fn hash(&self) -> Digest {
        static VERIFYING: OnceLock<Digest> = OnceLock::new();
        static SKIPPING: OnceLock<Digest> = OnceLock::new();

        let cache = if self.verifies_prev_block_proof {
            &VERIFYING
        } else {
            &SKIPPING
        };

        *cache.get_or_init(|| self.program().hash())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;
    use std::convert::Infallible;

    use itertools::Itertools;
    use neptune_mutator_set::addition_record::AdditionRecord;
    use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
    use neptune_mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
    use neptune_mutator_set::removal_record::removal_record_list::RemovalRecordList;
    use neptune_mutator_set::removal_record::RemovalRecord;
    use neptune_mutator_set::shared::CHUNK_SIZE;
    use neptune_mutator_set::shared::NUM_TRIALS;
    use neptune_mutator_set::shared::WINDOW_SIZE;
    use neptune_primitives::block_height::BlockHeight;
    use neptune_primitives::block_height::BLOCKS_PER_GENERATION;
    use neptune_primitives::difficulty_control::difficulty_control;
    use neptune_primitives::network::Network;
    use num_traits::CheckedSub;
    use num_traits::Zero;
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::triton_vm::execution_trace_profiler::ExecutionTraceProfile;
    use tasm_lib::triton_vm::execution_trace_profiler::VMTableHeights;

    use super::super::extension_claim::ExtensionClaim;
    use super::super::extension_claim::ExtensionClaimWitness;
    use super::super::extension_claim::ParentForExtension;
    use super::super::knows_mutator_set::KnowsMutatorSet;
    use super::super::swbf_update::aggregation::tests::claim_over_halves;
    use super::super::swbf_update::aggregation::SwbfUpdateAggregation;
    use super::super::swbf_update::chunk_witness::ChunkWitness;
    use super::super::swbf_update::leaf::CorrectSwbfUpdateWitness;
    use super::super::swbf_update::ClaimOutput;
    use super::super::swbfi_reveal::guesser_reveal_is_valid;
    use super::*;
    use crate::block::block_kernel::BlockKernel;
    use crate::block::mutator_set_update::MutatorSetUpdate;
    use crate::block::test_helpers::block_mmra_with_num_leafs;
    use crate::block::validity::block_primitive_witness::deterministic_block_primitive_witness;
    use crate::block::validity::block_primitive_witness::BlockPrimitiveWitness;
    use crate::block::validity::block_proof_witness::BlockProofWitness;
    use crate::block::BlockProof;
    use crate::block::BlockValidationError;
    use crate::consensus_rule_set::LustrationRule;
    use crate::proof_abstractions::tasm::builtins as tasm;
    use crate::proof_abstractions::tasm::builtins::verify_stark;
    use crate::proof_abstractions::tasm::program::proof_cache::load_proof_or_produce_and_save;
    use crate::proof_abstractions::tasm::program::spec::TritonProgramSpecification;
    use crate::proof_abstractions::test_runtime::tokio_runtime;
    use crate::proof_abstractions::SecretWitness;
    use crate::transaction::announcement::Announcement;
    use crate::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::transaction::transparent_input::TransparentInput;
    use crate::transaction::validity::neptune_proof::Proof as NeptuneProof;
    use crate::transaction::validity::single_proof::SingleProof;

    #[test]
    fn sign_test_refuses_non_canonical_limbs() {
        use tasm_lib::triton_vm::isa::instruction::InstructionError;
        use tasm_lib::triton_vm::isa::op_stack::OpStackError;
        use tasm_lib::triton_vm::vm::VMState;

        let sign = |limbs: [u64; 4]| {
            let program = Program::new(&triton_asm!(
                push {limbs[3]} push {limbs[2]} push {limbs[1]} push {limbs[0]}
                {&PredecessorIsValid::is_non_negative()}
                halt
            ));
            let mut state =
                VMState::new(program, PublicInput::default(), NonDeterminism::default());
            state.run().map(|()| *state.op_stack.stack.last().unwrap())
        };
        let max = u64::from(u32::MAX);
        assert_eq!(bfe!(1), sign([5, 0, 0, 0]).unwrap());
        assert_eq!(bfe!(1), sign([max, max, max, (1 << 31) - 1]).unwrap());
        assert_eq!(bfe!(0), sign([0, 0, 0, 1 << 31]).unwrap());
        for limbs in [
            [1 << 32, 0, 0, 0],
            [0, 1 << 40, 0, 0],
            [0, 0, 1 << 32, 0],
            [0, 0, 0, 1 << 32],
        ] {
            assert!(matches!(
                sign(limbs),
                Err(InstructionError::OpStackError(
                    OpStackError::FailedU32Conversion(_)
                ))
            ));
        }
    }

    impl PredecessorIsValidWitnessMemory {
        /// The previous block's size, as [Block::size] computes it.
        fn prev_block_size(&self) -> usize {
            Self::prev_block_fixed_size()
                + self.prev_block_body.encode().len()
                + self.prev_block_appendix.encode().len()
                + self.prev_block_proof.len()
        }
    }

    impl TritonProgramSpecification for PredecessorIsValid {
        fn source(&self) {
            let own_program_digest = tasm::own_program_digest();
            let version = ConsensusRuleSet::HardforkDelta
                .triton_proof_version()
                .version();
            let next_block_body_mh: Digest = tasm::tasmlib_io_read_stdin___digest();
            let witness: PredecessorIsValidWitnessMemory =
                tasm::decode_from_memory(FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS);

            tasm::tasmlib_hashing_merkle_verify(
                next_block_body_mh,
                BlockBodyField::BlockMmrAccumulator as u32,
                Tip5::hash_varlen(&witness.next_block_mmr_accumulator.encode()),
                BlockBody::MAST_HEIGHT as u32,
            );
            let prev_block_txk_mh = witness.prev_block_body.transaction_kernel.mast_hash();
            let prev_block_body_mh = witness.prev_block_body.mast_hash();

            // 0.b)
            let header_leaf = Tip5::hash(&witness.prev_block_header.mast_hash());
            let body_leaf = Tip5::hash(&prev_block_body_mh);
            let appendix_leaf = Tip5::hash_varlen(&witness.prev_block_appendix.encode());
            let kernel_mast_hash = Tip5::hash_pair(
                Tip5::hash_pair(header_leaf, body_leaf),
                Tip5::hash_pair(appendix_leaf, Digest::default()),
            );
            let prev_block_proof_leaf = Tip5::hash_varlen(&witness.prev_block_proof);
            let prev_block_hash =
                Tip5::hash_pair(Tip5::hash(&kernel_mast_hash), prev_block_proof_leaf);

            // 0.a)
            let next_block_height: BlockHeight = tasm::tasmlib_io_read_stdin___bfe().into();
            let genesis_digest = tasm::tasmlib_io_read_stdin___digest();
            assert_eq!(witness.prev_block_header.height.next(), next_block_height);
            assert_eq!(
                witness.next_block_mmr_accumulator.num_leafs(),
                next_block_height.value()
            );

            // 0.c)
            let mut expected_next_block_mmr = witness.prev_block_body.block_mmr_accumulator.clone();
            expected_next_block_mmr.append(prev_block_hash);
            assert_eq!(
                expected_next_block_mmr.peaks(),
                witness.next_block_mmr_accumulator.peaks()
            );

            let epoch_table_words = (0..EpochTable::static_length().unwrap())
                .map(|_| tasm::tasmlib_io_read_stdin___bfe())
                .collect::<Vec<_>>();
            let epochs = *EpochTable::decode(&epoch_table_words).unwrap();
            let prev_block_height = witness.prev_block_header.height;
            let prev_epoch = epochs.in_force_at(prev_block_height);

            let prev_transaction_kernel = &witness.prev_block_body.transaction_kernel;
            if witness.prev_block_header.height.is_genesis() {
                // 1.g) The parent at height zero is the named genesis block;
                // no other rule applies to it.
                assert_eq!(genesis_digest, prev_block_hash);
            } else {
                // 1.f)
                assert_eq!(
                    witness.prev_block_header.version,
                    witness.prev_block_header.pow.version_in_pow()
                );

                let difficulty = witness.prev_block_header.difficulty;
                assert!(difficulty >= Difficulty::MINIMUM);
                assert!(prev_block_hash <= difficulty.target());

                // 1.b)
                assert!(witness.prev_block_appendix.len() <= MAX_NUM_CLAIMS);

                if self.verifies_prev_block_proof {
                    // 1.c)
                    let BlockProof::SingleProof(prev_block_proof) =
                        *BlockProof::decode(&witness.prev_block_proof).unwrap()
                    else {
                        panic!("previous block must carry a single proof");
                    };

                    // 1.d)
                    let prev_block_claim = Claim::new(prev_epoch.block_program_digest)
                        .with_input(prev_block_body_mh.reversed().values().to_vec())
                        .with_output(witness.prev_block_appendix.claims_as_output())
                        .about_version(
                            ConsensusRuleSet::HardforkDelta
                                .triton_proof_version()
                                .version(),
                        );
                    verify_stark(Stark::default(), &prev_block_claim, &prev_block_proof);
                }

                // 1.a) The transaction claim; this program's own claim is found
                // under the header rules.
                let transaction_claim = Claim::new(prev_epoch.single_proof_digest)
                    .with_input(prev_block_txk_mh.reversed().values().to_vec())
                    .about_version(version);
                assert!(witness.prev_block_appendix.contains(&transaction_claim));

                // 2.g)
                if let Some(coinbase) = prev_transaction_kernel.coinbase {
                    assert!(coinbase <= Block::block_subsidy(witness.prev_block_header.height));
                }

                // 2.h)
                if let Some(coinbase) = prev_transaction_kernel.coinbase {
                    assert!(!coinbase.is_negative());
                }

                // 2.i)
                assert!(!prev_transaction_kernel.fee.is_negative());

                // 2.c) The divined positions must be a permutation of the inputs,
                // along which the index sets are strictly increasing.
                let num_inputs = prev_transaction_kernel.inputs.len();
                let mut taken = vec![false; num_inputs];
                let mut previous_index_set: Option<Vec<u128>> = None;
                for _ in 0..num_inputs {
                    let position = usize::try_from(tasm::tasmlib_io_read_secin___bfe().value())
                        .expect("position must fit");
                    assert!(position < num_inputs);
                    assert!(!taken[position]);
                    taken[position] = true;
                    let index_set = prev_transaction_kernel.inputs[position]
                        .absolute_indices
                        .to_vec();
                    assert!(previous_index_set.is_none_or(|previous| previous < index_set));
                    previous_index_set = Some(index_set);
                }

                // 2.u)
                assert!(
                    !prev_transaction_kernel.retires_before(witness.prev_block_header.timestamp)
                );
            }
            // 2.m)
            let prev_lustration_status = witness
                .prev_block_header
                .pow
                .lustration_status()
                .expect("previous block's header must carry a lustration status");

            // The header rules, for the previous block. Its predecessor's
            // values come from the previous block's copy of the claim for this
            // program execution.
            let cumulative_pow_size = ProofOfWork::static_length().unwrap();
            if prev_block_height >= epochs.activation_height() {
                let prev_minimum_block_time = prev_epoch.minimum_block_time;
                let prev_target_block_interval = prev_epoch.target_block_interval;

                let expected_input_start = [
                    prev_block_body_mh.reversed().values().to_vec(),
                    vec![prev_block_height.into()],
                    genesis_digest.reversed().values().to_vec(),
                ]
                .concat();
                let parent_claim = witness
                    .prev_block_appendix
                    .iter()
                    .find(|claim| {
                        claim.program_digest == own_program_digest
                            && claim.version == version
                            && claim.input.len() == Self::input_len()
                            && claim.input.starts_with(&expected_input_start)
                            && EpochTable::decode(&claim.input[expected_input_start.len()..])
                                .is_ok_and(|table| {
                                    table.is_prefix_of_up_to(&epochs, prev_block_height)
                                })
                    })
                    .expect("previous block must carry this claim about itself");

                // 0.b)
                assert_eq!(
                    parent_claim.output[..Digest::LEN],
                    witness.prev_block_header.prev_block_digest.values()
                );

                let prev_prev_block_timestamp =
                    Timestamp(parent_claim.output[Self::output_timestamp_offset()]);

                // 0.d)
                assert!(
                    prev_prev_block_timestamp + prev_minimum_block_time
                        <= witness.prev_block_header.timestamp
                );

                // 0.e)
                let difficulty_offset = Self::output_difficulty_offset();
                let prev_prev_block_difficulty = *Difficulty::decode(
                    &parent_claim.output
                        [difficulty_offset..difficulty_offset + Difficulty::NUM_LIMBS],
                )
                .unwrap();
                let divined_tokens = (0..4)
                    .map(|_| tasm::tasmlib_io_read_secin___bfe())
                    .collect::<Vec<_>>();
                assert_eq!(
                    DifficultyControl::divined_tokens(
                        prev_target_block_interval,
                        prev_block_height.previous().unwrap(),
                    ),
                    divined_tokens
                );
                assert_eq!(
                    difficulty_control(
                        witness.prev_block_header.timestamp,
                        prev_prev_block_timestamp,
                        prev_prev_block_difficulty,
                        prev_target_block_interval,
                        prev_block_height.previous().unwrap(),
                    ),
                    witness.prev_block_header.difficulty
                );

                // 0.f)
                let cumulative_pow_offset = Self::output_cumulative_pow_offset();
                let prev_prev_block_cumulative_pow = *ProofOfWork::decode(
                    &parent_claim.output
                        [cumulative_pow_offset..cumulative_pow_offset + cumulative_pow_size],
                )
                .unwrap();
                assert_eq!(
                    prev_prev_block_cumulative_pow + witness.prev_block_header.difficulty,
                    witness.prev_block_header.cumulative_proof_of_work
                );
                // 2.t)
                let mutator_set_offset = Self::output_mutator_set_offset();
                assert_eq!(
                    parent_claim.output[mutator_set_offset..mutator_set_offset + Digest::LEN],
                    prev_transaction_kernel.mutator_set_hash.values()
                );

                // 2.t) The witness's mutator set is the one the transaction
                // is built on.
                let mutator_set = &witness.prev_block_transaction_mutator_set;
                assert_eq!(
                    parent_claim.output[mutator_set_offset..mutator_set_offset + Digest::LEN],
                    mutator_set.hash().values()
                );

                // 2.a, 2.b, 2.d, 2.e) The previous block's appendix carries
                // the aggregated SWBF update claim about its transaction's
                // removals on the mutator set it is built on; its proof was
                // verified with the block's, and the leaf proofs beneath it
                // must total the epoch's floor. The rest of the update is
                // computed here.
                let claim_input = CorrectSwbfUpdate::claim_input(
                    mutator_set,
                    bfe!(CorrectSwbfUpdate::FIRST_LEAF_INDEX),
                );
                let swbf_claim = witness
                    .prev_block_appendix
                    .claims()
                    .iter()
                    .find(|claim| {
                        claim.program_digest == prev_epoch.swbf_aggregation_digest
                            && claim.version == version
                            && claim.input == claim_input
                    })
                    .expect("previous block must carry the SWBF update claim");
                let output = ClaimOutput::parse(&swbf_claim.output);
                assert!(output.padded_rows.value() >= prev_epoch.min_swbf_padded_rows.value());
                assert_eq!(prev_transaction_kernel.inputs.len(), output.count);
                assert_eq!(
                    RemovalIndexCommitment::peaks(&prev_transaction_kernel.inputs),
                    output.peaks
                );
                MutatorSetUpdateFromStateHash::verify(
                    &prev_transaction_kernel.inputs,
                    &prev_transaction_kernel.outputs,
                    mutator_set,
                    output.mutator_set_hash,
                    &witness.prev_block_body.mutator_set_accumulator,
                );
                // 2.v) The guesser's reveal of the mutator set after the
                // previous block's parent, where the epoch requires it.
                if !prev_epoch.requires_mutator_set_reveals.is_zero() {
                    assert!(guesser_reveal_is_valid(
                        &witness.prev_block_header,
                        &witness.prev_block_transaction_mutator_set.swbf_inactive
                    ));
                }

                // 1.e)
                assert!(
                    u64::try_from(witness.prev_block_size()).unwrap()
                        <= prev_epoch.max_block_size.value()
                );

                // 2.f)
                let prev_transaction_timestamp = prev_transaction_kernel.timestamp;
                assert!(prev_transaction_timestamp <= witness.prev_block_header.timestamp);
                assert!(
                    witness.prev_block_header.timestamp - prev_transaction_timestamp
                        <= prev_epoch.transaction_backdating_threshold
                );

                // 2.j)
                assert!(
                    u64::try_from(prev_transaction_kernel.inputs.len()).unwrap()
                        <= prev_epoch.max_num_inputs.value()
                );

                // 2.k)
                assert!(
                    u64::try_from(prev_transaction_kernel.outputs.len()).unwrap()
                        <= prev_epoch.max_num_outputs.value()
                );

                // 2.l)
                assert!(
                    u64::try_from(prev_transaction_kernel.announcements.len()).unwrap()
                        <= prev_epoch.max_num_announcements.value()
                );

                let prev_block_resets_lustration_status =
                    prev_epoch.resets_lustration_status.value() != 0
                        && prev_epoch.height.value() == prev_block_height.value();
                if prev_block_resets_lustration_status {
                    // 2.p)
                    assert_eq!(
                        prev_epoch.lustration_counter_initial,
                        prev_lustration_status.counter
                    );

                    // 2.q)
                    assert_eq!(
                        witness.prev_block_body.max_aocl_leaf_index(),
                        prev_lustration_status.max_lustrating_aocl_leaf_index
                    );
                } else {
                    let prev_prev_lustration_status = *LustrationStatus::decode(
                        &parent_claim.output[Digest::LEN..Self::output_timestamp_offset()],
                    )
                    .unwrap();
                    let threshold = prev_prev_lustration_status.max_lustrating_aocl_leaf_index;

                    // 2.q)
                    assert_eq!(
                        threshold,
                        prev_lustration_status.max_lustrating_aocl_leaf_index
                    );

                    for input in &prev_transaction_kernel.inputs {
                        let (range_start, _) = input
                            .absolute_indices
                            .aocl_range()
                            .expect("every input's AOCL range is representable");
                        if range_start <= threshold {
                            tasm::tasmlib_io_read_secin___bfe();
                        }
                    }
                    // 2.o)
                    let lustrated = prev_transaction_kernel
                        .verified_lustration_amount(threshold, true)
                        .expect("every input that must lustrate is announced");

                    // 2.r)
                    let expected_counter = prev_prev_lustration_status
                        .counter
                        .checked_sub(&lustrated)
                        .expect("the lustration counter must not fall below zero");

                    // 2.p)
                    assert_eq!(expected_counter, prev_lustration_status.counter);
                }

                // 2.s)
                assert!(prev_lustration_status.counter <= prev_epoch.lustration_counter_initial);
            }

            tasm::tasmlib_io_write_to_stdout___digest(prev_block_hash);

            tasm::tasmlib_io_write_to_stdout___encoding(prev_lustration_status);
            tasm::tasmlib_io_write_to_stdout___bfe(witness.prev_block_header.timestamp.0);
            tasm::tasmlib_io_write_to_stdout___encoding(
                witness.prev_block_header.cumulative_proof_of_work,
            );
            tasm::tasmlib_io_write_to_stdout___encoding(witness.prev_block_header.difficulty);

            // The mutator set after the previous block: its body's
            // accumulator with its guesser reward added.
            let prev_block_kernel = BlockKernel::new(
                witness.prev_block_header,
                witness.prev_block_body.clone(),
                witness.prev_block_appendix.clone(),
            );
            let mut mutator_set_after_prev_block =
                witness.prev_block_body.mutator_set_accumulator.clone();
            for addition_record in prev_block_kernel
                .guesser_fee_addition_records(prev_block_hash)
                .unwrap()
            {
                mutator_set_after_prev_block.add(&addition_record);
            }
            tasm::tasmlib_io_write_to_stdout___digest(mutator_set_after_prev_block.hash());
        }
    }

    /// At or past hard fork delta on main net, so that the fixture
    /// transaction is proved under the delta rules.
    fn activation_height() -> BlockHeight {
        BlockHeight::from(60_000u64)
    }

    fn minimum_block_time() -> Timestamp {
        Network::Main.minimum_block_time()
    }

    fn target_block_interval() -> Timestamp {
        Network::Main.target_block_interval()
    }

    fn activation_epoch() -> Epoch {
        let consensus_rule_set = ConsensusRuleSet::HardforkDelta;
        Epoch {
            height: activation_height().into(),
            minimum_block_time: minimum_block_time(),
            target_block_interval: target_block_interval(),
            max_num_inputs: bfe!(consensus_rule_set.max_num_inputs() as u64),
            max_num_outputs: bfe!(consensus_rule_set.max_num_outputs() as u64),
            max_num_announcements: bfe!(consensus_rule_set.max_num_announcements() as u64),
            max_block_size: bfe!(consensus_rule_set.max_block_size() as u64),
            transaction_backdating_threshold: consensus_rule_set
                .transaction_backdating_threshold()
                .unwrap(),
            lustration_counter_initial: lustration_counter_initial(),
            resets_lustration_status: bfe!(0),
            min_swbf_padded_rows: bfe!(2 << FIXTURE_LEAF_LOG2_PADDED_HEIGHT),
            requires_mutator_set_reveals: bfe!(0),
            block_program_digest: BlockProgram.hash(),
            single_proof_digest: SingleProof::new(consensus_rule_set).hash(),
            swbf_aggregation_digest: SwbfUpdateAggregation::new().hash(),
        }
    }

    /// The padded height of each of the two leaf proofs beneath a fixture
    /// block's SWBF update claim, which together reach the fixture epoch's
    /// floor exactly.
    const FIXTURE_LEAF_LOG2_PADDED_HEIGHT: u32 = 22;

    /// The initial lustration counter of the latest lustration rule.
    fn lustration_counter_initial() -> NativeCurrencyAmount {
        let far_future = BlockHeight::from(u64::MAX >> 1);
        let LustrationRule::Updated { initial_counter } =
            ConsensusRuleSet::lustration_rule(Network::Main, far_future, 0).unwrap()
        else {
            panic!("latest lustration rule must be an update");
        };
        initial_counter
    }

    fn epochs() -> EpochTable {
        EpochTable::new(&[activation_epoch()])
    }

    /// Give the header the difficulty and cumulative proof of work its
    /// timestamp calls for on top of the previous block.
    fn set_difficulty_fields(header: &mut BlockHeader, prev_block: &Block) {
        header.difficulty = difficulty_control(
            header.timestamp,
            prev_block.header().timestamp,
            prev_block.header().difficulty,
            target_block_interval(),
            prev_block.header().height,
        );
        header.cumulative_proof_of_work =
            prev_block.header().cumulative_proof_of_work + header.difficulty;
    }

    impl PredecessorIsValid {
        /// The program that does not verify the previous block's proof, for
        /// testing the other rules on blocks, without-expensive-to-build
        /// proofs.
        fn skipping_proof_verification() -> Self {
            Self {
                verifies_prev_block_proof: false,
            }
        }
    }

    fn skipping() -> PredecessorIsValid {
        PredecessorIsValid::skipping_proof_verification()
    }

    /// A transaction kernel with its single proof, shared by every fixture
    /// body.
    /// The kernel and proof of a transaction from a block that has no
    /// particular relation to the fixture chain.
    fn unrelated_transaction_kernel_and_proof() -> &'static (TransactionKernel, NeptuneProof) {
        static KERNEL_AND_PROOF: OnceLock<(TransactionKernel, NeptuneProof)> = OnceLock::new();
        KERNEL_AND_PROOF.get_or_init(|| {
            let transaction = deterministic_block_primitive_witness(Network::Main)
                .transaction()
                .clone();
            let proof = transaction.proof().clone().into_single_proof();
            (transaction.kernel().clone(), proof)
        })
    }

    /// The proof of the block with this body and these appendix claims, from
    /// the proof cache.
    fn block_proof(body: &BlockBody, claims: &[(Claim, NeptuneProof)]) -> NeptuneProof {
        let appendix = BlockAppendix::new(claims.iter().map(|(claim, _)| claim.clone()).collect());
        let block_claim = BlockProgram::claim(body, &appendix, ConsensusRuleSet::HardforkDelta);
        let mut witness = BlockProofWitness::new(body.clone());
        for (claim, proof) in claims {
            witness = witness.with_claim_test(claim.clone(), proof.clone());
        }

        load_proof_or_produce_and_save(
            &block_claim,
            BlockProgram.program(),
            witness.nondeterminism(),
        )
    }

    /// The header of a fixture grandparent: random, at the generated height
    /// and timestamp, with the minimum difficulty and the fixture lustration
    /// status.
    fn fixture_grandparent_header(generated_header: &BlockHeader) -> BlockHeader {
        let mut rng = StdRng::seed_from_u64(0);
        let mut header: BlockHeader = rng.random();
        header.height = generated_header.height;
        header.timestamp = generated_header.timestamp;
        header.difficulty = Difficulty::MINIMUM;
        header
            .pow
            .set_lustration_status(fixture_lustration_status(&mut rng));
        header
    }

    /// Builds the fixture chain's grandparent from the generated header, body
    /// and appendix: a block just below the activation height with the
    /// minimum difficulty, carrying an unrelated transaction, with its proof
    /// and proof of work. The fixture transaction is built on the mutator set
    /// after this block.
    fn proven_fixture_grandparent(
        generated_header: BlockHeader,
        generated_body: BlockBody,
        _appendix: BlockAppendix,
    ) -> Block {
        let header = fixture_grandparent_header(&generated_header);

        let (transaction_kernel, transaction_proof) = unrelated_transaction_kernel_and_proof();
        let body = BlockBody::new(
            transaction_kernel.clone(),
            generated_body.mutator_set_accumulator.clone(),
            generated_body.lock_free_mmr_accumulator.clone(),
            generated_body.block_mmr_accumulator.clone(),
        );
        let transaction_claim = single_proof_claim(
            transaction_kernel.mast_hash(),
            ConsensusRuleSet::HardforkDelta,
        );
        let claims = vec![(transaction_claim, transaction_proof.clone())];
        let proof = block_proof(&body, &claims);
        let appendix = BlockAppendix::new(claims.into_iter().map(|(claim, _)| claim).collect());

        block(header, body, appendix, BlockProof::SingleProof(proof))
    }

    /// The fixture chain's grandparent and the transaction built on the
    /// mutator set after it, which every fixture parent carries.
    fn fixture_witness() -> &'static BlockPrimitiveWitness {
        static WITNESS: OnceLock<BlockPrimitiveWitness> = OnceLock::new();
        WITNESS.get_or_init(|| {
            BlockPrimitiveWitness::deterministic_with_height_difficulty_and_predecessor_builder(
                activation_height(),
                Difficulty::MINIMUM,
                Network::Main,
                proven_fixture_grandparent,
            )
        })
    }

    /// The block just below the activation height on whose mutator set the
    /// shared transaction is built: the grandparent of every fixture parent
    /// that carries that transaction.
    fn fixture_grandparent() -> Block {
        fixture_witness().predecessor_block().clone()
    }

    fn transaction_kernel_and_proof() -> &'static (TransactionKernel, NeptuneProof) {
        static KERNEL_AND_PROOF: OnceLock<(TransactionKernel, NeptuneProof)> = OnceLock::new();
        KERNEL_AND_PROOF.get_or_init(|| {
            let transaction = fixture_witness().transaction().clone();
            let proof = transaction.proof().clone().into_single_proof();
            (transaction.kernel().clone(), proof)
        })
    }

    /// The transaction claim of the body's transaction with its proof, for
    /// the transactions that have one: the shared one and the unrelated one.
    fn transaction_claim_and_proof_for(body: &BlockBody) -> (Claim, NeptuneProof) {
        let kernel = &body.transaction_kernel;
        let (_, proof) = [
            transaction_kernel_and_proof(),
            unrelated_transaction_kernel_and_proof(),
        ]
        .into_iter()
        .find(|(known_kernel, _)| known_kernel == kernel)
        .expect("body must carry a transaction with a proof");
        let claim = single_proof_claim(kernel.mast_hash(), ConsensusRuleSet::HardforkDelta);
        (claim, proof.clone())
    }

    /// The inactive SWBF's peaks after the removals of each fixture block that
    /// carries its inputs without chunks, by the block's hash: what the
    /// archival mutator set supplies the witness with under e1.
    fn swbfi_peaks_after_removals() -> &'static std::sync::Mutex<HashMap<Digest, Vec<Digest>>> {
        static PEAKS: OnceLock<std::sync::Mutex<HashMap<Digest, Vec<Digest>>>> = OnceLock::new();
        PEAKS.get_or_init(Default::default)
    }

    fn remember_swbfi_peaks_after_removals(block: &Block, peaks: Vec<Digest>) {
        swbfi_peaks_after_removals()
            .lock()
            .unwrap()
            .insert(block.hash(), peaks);
    }

    /// The witness for the previous block, with the peaks from the registry
    /// if the block carries its inputs without chunks.
    fn witness_for(prev_block: &Block, next_body: &BlockBody) -> PredecessorIsValidWitness {
        let witness = PredecessorIsValidWitness::new(
            prev_block,
            next_body,
            transaction_mutator_set(prev_block),
        );
        match swbfi_peaks_after_removals()
            .lock()
            .unwrap()
            .get(&prev_block.hash())
        {
            Some(peaks) => witness.with_swbfi_peaks_after_removals(peaks.clone()),
            None => witness,
        }
    }

    /// Each block a fixture parent has been built on, by its hash.
    fn predecessors() -> &'static std::sync::Mutex<HashMap<Digest, Block>> {
        static PREDECESSORS: OnceLock<std::sync::Mutex<HashMap<Digest, Block>>> = OnceLock::new();
        PREDECESSORS.get_or_init(Default::default)
    }

    fn remember_predecessor(block: &Block) {
        predecessors()
            .lock()
            .unwrap()
            .insert(block.hash(), block.clone());
    }

    /// The block this one was built on, if the test case built it on one.
    fn predecessor_of(block: &Block) -> Option<Block> {
        predecessor_by_hash(block.header().prev_block_digest)
    }

    fn predecessor_by_hash(hash: Digest) -> Option<Block> {
        predecessors().lock().unwrap().get(&hash).cloned()
    }

    /// The mutator set the block's transaction is built on: the one after
    /// its predecessor, if the fixtures built the block on it. Any value
    /// serves a previous block below the activation height.
    fn transaction_mutator_set(block: &Block) -> MutatorSetAccumulator {
        predecessor_of(block)
            .and_then(|predecessor| predecessor.mutator_set_accumulator_after().ok())
            .unwrap_or_default()
    }

    /// A random body with the given block MMR, transaction and mutator set
    /// accumulator: the one the transaction is built on, so that the
    /// transaction's inputs are unspent in the mutator set after any block
    /// with this body.
    fn random_body(
        rng: &mut StdRng,
        transaction_kernel: &TransactionKernel,
        mutator_set: &MutatorSetAccumulator,
        block_mmr_accumulator: MmrAccumulator,
    ) -> BlockBody {
        let body: BlockBody = rng.random();

        BlockBody::new(
            transaction_kernel.clone(),
            mutator_set.clone(),
            body.lock_free_mmr_accumulator.clone(),
            block_mmr_accumulator,
        )
    }

    /// A lustration status with a random counter under which no fixture
    /// input must lustrate: the threshold lies below every AOCL leaf index
    /// the shared transaction spends.
    fn fixture_lustration_status(rng: &mut StdRng) -> LustrationStatus {
        LustrationStatus {
            counter: NativeCurrencyAmount::coins(rng.random_range(0..1000)),
            max_lustrating_aocl_leaf_index: 0,
        }
    }

    /// The lustration status a block must carry after a parent with this
    /// status when it carries this transaction: the threshold unchanged and
    /// the counter reduced by what the transaction lustrates.
    fn lustration_status_after(
        parent: LustrationStatus,
        transaction_kernel: &TransactionKernel,
    ) -> LustrationStatus {
        let lustrated = transaction_kernel
            .verified_lustration_amount(parent.max_lustrating_aocl_leaf_index, true)
            .unwrap_or_else(|_| NativeCurrencyAmount::zero());
        LustrationStatus {
            counter: parent
                .counter
                .checked_sub(&lustrated)
                .unwrap_or(parent.counter),
            ..parent
        }
    }

    fn random_header_and_body(
        seed: u64,
        height: u64,
        timestamp: Timestamp,
    ) -> (BlockHeader, BlockBody) {
        let mut rng = StdRng::seed_from_u64(seed);

        let mut header: BlockHeader = rng.random();
        header.height = BlockHeight::from(height);
        header.timestamp = timestamp;
        header.difficulty = Difficulty::MINIMUM;
        header
            .pow
            .set_lustration_status(fixture_lustration_status(&mut rng));

        let peaks = rng.random::<BlockBody>().block_mmr_accumulator.peaks();
        let body = random_body(
            &mut rng,
            &transaction_kernel_and_proof().0,
            &fixture_grandparent().body().mutator_set_accumulator,
            block_mmra_with_num_leafs(height, peaks),
        );

        (header, body)
    }

    /// The block with this header, body, appendix and proof, with proof of
    /// work for the minimum difficulty.
    fn block(
        header: BlockHeader,
        body: BlockBody,
        appendix: BlockAppendix,
        proof: BlockProof,
    ) -> Block {
        let mut block = Block::new(header, body, appendix, proof);
        block.satisfy_pow(Difficulty::MINIMUM, ConsensusRuleSet::HardforkDelta);

        block
    }

    /// The block with this header and body, whose appendix holds the
    /// transaction claim and then these claims, without a proof. For the
    /// program that skips proof verification.
    fn unproven_block(header: BlockHeader, body: BlockBody, claims: Vec<Claim>) -> Block {
        let swbf_claim = swbf_update_claim(&header, &body);
        unproven_block_with_swbf_claim(header, body, claims, swbf_claim)
    }

    /// The SWBF update claim a block's appendix must carry, if the fixtures
    /// built the block on a known predecessor its transaction applies to.
    fn swbf_update_claim(header: &BlockHeader, body: &BlockBody) -> Option<Claim> {
        let predecessor = predecessor_by_hash(header.prev_block_digest)?;
        let mutator_set = predecessor.mutator_set_accumulator_after().ok()?;
        let inputs = &body.transaction_kernel.inputs;
        let unpacked = RemovalRecordList::try_unpack(inputs.clone(), true).ok()?;
        if !unpacked.iter().all(|record| mutator_set.can_remove(record)) {
            return None;
        }

        Some(claim_over_halves(
            inputs,
            &mutator_set,
            [FIXTURE_LEAF_LOG2_PADDED_HEIGHT; 2],
        ))
    }

    /// The claims Main requires from its activation on that the fixtures
    /// cannot otherwise carry, the verifying program's and the composer's
    /// reveal claim, as data: the host must accept a fixture block the
    /// program accepts. None below activation or on a block the fixtures
    /// did not build on a known predecessor.
    fn main_host_claims(header: &BlockHeader, body: &BlockBody) -> Vec<Claim> {
        let network = Network::Main;
        let activation = ConsensusRuleSet::epsilon_activation_block_height(network);
        let Some(parent) = predecessor_by_hash(header.prev_block_digest) else {
            return vec![];
        };
        if header.height < activation {
            return vec![];
        }
        let mutator_set = parent.mutator_set_accumulator_after().unwrap();
        vec![
            PredecessorIsValid::claim_about(&parent, body.mast_hash(), network),
            KnowsMutatorSet::claim(
                parent.hash(),
                &mutator_set,
                ConsensusRuleSet::knows_mutator_set_activation_height(network),
                ConsensusRuleSet::infer_from(network, header.height),
            ),
        ]
    }

    /// As [unproven_block], with this SWBF update claim, or none.
    fn unproven_block_with_swbf_claim(
        header: BlockHeader,
        body: BlockBody,
        claims: Vec<Claim>,
        swbf_claim: Option<Claim>,
    ) -> Block {
        let transaction_claim = single_proof_claim(
            body.transaction_kernel.mast_hash(),
            ConsensusRuleSet::HardforkDelta,
        );
        let claims = [
            vec![transaction_claim],
            swbf_claim.into_iter().collect(),
            claims,
            main_host_claims(&header, &body),
        ]
        .concat();

        block(
            header,
            body,
            BlockAppendix::new(claims),
            BlockProof::Invalid,
        )
    }

    /// The height just below activation: a block there carries no claim of
    /// this program, and its successor is the first that must.
    fn height_below_activation() -> u64 {
        activation_height().value() - 1
    }

    /// A random timestamp within a day after the fixture transaction's, so
    /// that the blocks holding that transaction satisfy rule 2.f.
    fn random_timestamp(seed: u64) -> Timestamp {
        let transaction_timestamp = transaction_kernel_and_proof().0.timestamp;
        let offset = StdRng::seed_from_u64(seed).random_range(0..Timestamp::days(1).to_millis());
        transaction_timestamp + Timestamp::millis(offset)
    }

    /// A random block at the given height, without a proof. Just below the
    /// activation height, it is the fixture grandparent instead: the block
    /// the shared transaction is built on. That one carries a proof, which
    /// the program that skips proof verification ignores.
    fn random_unproven_block_at_height(seed: u64, height: u64) -> Block {
        if height == height_below_activation() {
            return fixture_grandparent();
        }
        let (header, body) = random_header_and_body(seed, height, random_timestamp(seed));
        unproven_block(header, body, vec![])
    }

    /// The block just below the activation height that the fixture parents
    /// build on.
    fn random_unproven_block(seed: u64) -> Block {
        random_unproven_block_at_height(seed, height_below_activation())
    }

    /// The hash of the mutator set after the block, which a transaction in
    /// its successor must be built on.
    fn mutator_set_hash_after(block: &Block) -> Digest {
        block.mutator_set_accumulator_after().unwrap().hash()
    }

    /// The mutator set after the block with this transaction on the mutator
    /// set after its predecessor, if the transaction applies to it: the
    /// shared transaction does not apply after a block that carries it.
    fn mutator_set_after_transaction(
        prev_block: &Block,
        transaction_kernel: &TransactionKernel,
    ) -> Option<MutatorSetAccumulator> {
        let mut mutator_set = prev_block.mutator_set_accumulator_after().ok()?;
        let inputs = RemovalRecordList::try_unpack(transaction_kernel.inputs.clone(), true).ok()?;
        MutatorSetUpdate::new(inputs, transaction_kernel.outputs.clone())
            .apply_to_accumulator(&mut mutator_set)
            .ok()?;
        Some(mutator_set)
    }

    /// The body with its mutator set accumulator replaced by the one after
    /// its transaction on the previous block, if the transaction applies.
    fn body_with_mutator_set_after_transaction(prev_block: &Block, body: BlockBody) -> BlockBody {
        let mutator_set = mutator_set_after_transaction(prev_block, &body.transaction_kernel)
            .unwrap_or_else(|| body.mutator_set_accumulator.clone());
        body_with_mutator_set(body, mutator_set)
    }

    fn body_with_mutator_set(body: BlockBody, mutator_set: MutatorSetAccumulator) -> BlockBody {
        BlockBody::new(
            body.transaction_kernel.clone(),
            mutator_set,
            body.lock_free_mmr_accumulator.clone(),
            body.block_mmr_accumulator.clone(),
        )
    }

    /// A random next body that extends the previous block's MMR, and a
    /// header for that body whose timestamp respects the minimum block time.
    /// The body's mutator set is the one after its transaction, where the
    /// transaction applies.
    fn next_body_and_header(prev_block: &Block, seed: u64) -> (BlockBody, BlockHeader) {
        next_body_and_header_with_transaction(
            prev_block,
            seed,
            &transaction_kernel_and_proof().0,
            &fixture_grandparent().body().mutator_set_accumulator,
        )
    }

    /// A next body carrying this transaction, built on this mutator set,
    /// and a header for it.
    fn next_body_and_header_with_transaction(
        prev_block: &Block,
        seed: u64,
        transaction_kernel: &TransactionKernel,
        mutator_set: &MutatorSetAccumulator,
    ) -> (BlockBody, BlockHeader) {
        remember_predecessor(prev_block);
        let mut rng = StdRng::seed_from_u64(seed);

        let mut next_block_mmr_accumulator = prev_block.body().block_mmr_accumulator.clone();
        next_block_mmr_accumulator.append(prev_block.hash());
        let next_body = random_body(
            &mut rng,
            transaction_kernel,
            mutator_set,
            next_block_mmr_accumulator,
        );
        let next_body = body_with_mutator_set_after_transaction(prev_block, next_body);

        let mut next_header: BlockHeader = rng.random();
        next_header.height = prev_block.header().height.next();
        next_header.prev_block_digest = prev_block.hash();
        // Not before the transaction the next body carries.
        let earliest = prev_block.header().timestamp + minimum_block_time();
        let earliest = std::cmp::max(earliest, transaction_kernel.timestamp);
        next_header.timestamp =
            earliest + Timestamp::millis(rng.random_range(0..Timestamp::days(1).to_millis()));
        set_difficulty_fields(&mut next_header, prev_block);
        let random_status = fixture_lustration_status(&mut rng);
        let status = prev_block
            .header()
            .pow
            .lustration_status()
            .map(|parent| lustration_status_after(parent, transaction_kernel))
            .unwrap_or(random_status);
        next_header.pow.set_lustration_status(status);

        (next_body, next_header)
    }

    /// The program's claim about the previous block, for the next block with
    /// this body and header.
    fn own_claim(
        program: &PredecessorIsValid,
        prev_block: &Block,
        next_body: &BlockBody,
        next_header: &BlockHeader,
    ) -> Claim {
        own_claim_with_epochs(program, prev_block, next_body, next_header, &epochs())
    }

    fn own_claim_with_epochs(
        program: &PredecessorIsValid,
        prev_block: &Block,
        next_body: &BlockBody,
        next_header: &BlockHeader,
        epochs: &EpochTable,
    ) -> Claim {
        program.claim(
            next_body.mast_hash(),
            next_header,
            prev_block,
            fixture_genesis().hash(),
            epochs,
            ConsensusRuleSet::HardforkDelta,
        )
    }

    /// The genesis block the fixture chains name.
    fn fixture_genesis() -> Block {
        Block::genesis(Network::Main)
    }

    /// A claim that a trivial program halts, with its proof: filler for an
    /// appendix.
    fn halt_claim_and_proof() -> (Claim, NeptuneProof) {
        let program = Program::new(&triton_asm!(halt));
        let claim = Claim::about_program(&program);
        let proof = tasm_lib::triton_vm::prove(
            Stark::default(),
            &claim,
            program,
            NonDeterminism::default(),
        )
        .unwrap();

        (claim, proof.into())
    }

    /// Where the own claim goes among two fillers.
    fn own_claim_position(seed: u64) -> usize {
        StdRng::seed_from_u64(seed).random_range(0..=2)
    }

    /// A successor of the previous block with this body and header, whose
    /// appendix holds the skipping program's claim among fillers, without a
    /// proof.
    fn unproven_block_with_own_claim(
        prev_block: &Block,
        body: BlockBody,
        header: BlockHeader,
        seed: u64,
    ) -> Block {
        unproven_block_with_own_claim_with_epochs(prev_block, body, header, seed, &epochs())
    }

    fn unproven_block_with_own_claim_with_epochs(
        prev_block: &Block,
        body: BlockBody,
        header: BlockHeader,
        seed: u64,
        epochs: &EpochTable,
    ) -> Block {
        let own_claim = own_claim_with_epochs(&skipping(), prev_block, &body, &header, epochs);
        let mut claims = vec![halt_claim_and_proof().0, halt_claim_and_proof().0];
        claims.insert(own_claim_position(seed), own_claim);

        unproven_block(header, body, claims)
    }

    /// An unproven previous block that carries the skipping program's claim,
    /// and a next body and header for it.
    fn unproven_prev_block_and_next_body_and_header(seed: u64) -> (Block, BlockBody, BlockHeader) {
        let prev_prev_block = random_unproven_block(seed);
        let (body, header) = next_body_and_header(&prev_prev_block, seed);
        let prev_block = unproven_block_with_own_claim(&prev_prev_block, body, header, seed);
        let (next_body, next_header) = next_body_and_header(&prev_block, seed);

        (prev_block, next_body, next_header)
    }

    fn claim_and_nondeterminism(
        program: &PredecessorIsValid,
        prev_block: &Block,
        next_body: &BlockBody,
        next_header: &BlockHeader,
        epochs: &EpochTable,
    ) -> (Claim, NonDeterminism) {
        let claim = own_claim_with_epochs(program, prev_block, next_body, next_header, epochs);
        let witness = witness_for(prev_block, next_body);

        (claim, witness.nondeterminism_under(program, epochs))
    }

    /// Run the program in Rust and in Triton VM, and check that both agree
    /// with the claim.
    fn assert_accepts(
        program: &PredecessorIsValid,
        prev_block: &Block,
        next_body: &BlockBody,
        next_header: &BlockHeader,
    ) {
        assert_accepts_with_epochs(program, prev_block, next_body, next_header, &epochs());
    }

    fn assert_accepts_with_epochs(
        program: &PredecessorIsValid,
        prev_block: &Block,
        next_body: &BlockBody,
        next_header: &BlockHeader,
        epochs: &EpochTable,
    ) {
        let (claim, nondeterminism) =
            claim_and_nondeterminism(program, prev_block, next_body, next_header, epochs);
        let input = PublicInput::new(claim.input);

        let rust_output = program.run_rust(&input, nondeterminism.clone()).unwrap();
        let tasm_output = program.run_tasm(&input, nondeterminism).unwrap();
        assert_eq!(rust_output, tasm_output);
        assert_eq!(claim.output, tasm_output);

        let mirrors_host =
            *epochs == self::epochs() && prev_block.header().height >= epochs.activation_height();
        if mirrors_host {
            let predecessor =
                predecessor_of(prev_block).expect("test case must be built on a block");
            prev_block
                .validate_without_proof_or_reveal(
                    &predecessor,
                    prev_block.header().timestamp,
                    Network::Main,
                )
                .expect("host must accept a previous block the program accepts");
        }
    }

    fn assert_rejects(
        program: &PredecessorIsValid,
        prev_block: &Block,
        next_body: &BlockBody,
        next_header: &BlockHeader,
        error_id: i128,
    ) {
        assert_rejects_with_epochs(
            program,
            prev_block,
            next_body,
            next_header,
            &epochs(),
            error_id,
        );
    }

    fn assert_rejects_with_epochs(
        program: &PredecessorIsValid,
        prev_block: &Block,
        next_body: &BlockBody,
        next_header: &BlockHeader,
        epochs: &EpochTable,
        error_id: i128,
    ) {
        let (claim, nondeterminism) =
            claim_and_nondeterminism(program, prev_block, next_body, next_header, epochs);
        program
            .test_assertion_failure(PublicInput::new(claim.input), nondeterminism, &[error_id])
            .unwrap();
    }

    /// The tests that need a block proof in the witness: they run the
    /// variant of this program that verifies it.
    mod require_proof {
        use super::*;

        /// The block with this header and body, whose appendix holds the
        /// transaction claim and then these claims, with its proof.
        fn proven_block(
            header: BlockHeader,
            body: BlockBody,
            claims: Vec<(Claim, NeptuneProof)>,
        ) -> Block {
            let swbf_claim = swbf_update_claim(&header, &body).map(|_| {
                let predecessor = predecessor_by_hash(header.prev_block_digest).unwrap();
                let inputs = &body.transaction_kernel.inputs;
                let split = inputs.len() / 2;
                let leaves = CorrectSwbfUpdateWitness::segments(
                    inputs,
                    &predecessor.mutator_set_accumulator_after().unwrap(),
                    &[split, inputs.len() - split],
                )
                .into_iter()
                .map(|leaf| leaf.with_padded_height(FIXTURE_LEAF_LOG2_PADDED_HEIGHT))
                .collect::<Vec<_>>();
                let (claim, proof) = futures::executor::block_on(
                    SwbfUpdateAggregation::new().tree(&leaves, |claim, program, nondeterminism| {
                        std::future::ready(Ok::<_, Infallible>(
                            load_proof_or_produce_and_save(&claim, program, nondeterminism).into(),
                        ))
                    }),
                )
                .unwrap();
                (claim, NeptuneProof::from(proof))
            });
            let claims = [
                vec![transaction_claim_and_proof_for(&body)],
                swbf_claim.into_iter().collect(),
                claims,
            ]
            .concat();
            let proof = block_proof(&body, &claims);
            let appendix = BlockAppendix::new(claims.into_iter().map(|(claim, _)| claim).collect());

            block(header, body, appendix, BlockProof::SingleProof(proof))
        }

        /// The proven block just below the activation height that the
        /// fixture parents build on.
        fn random_block(_seed: u64) -> Block {
            fixture_grandparent()
        }

        /// The verifying program's claim about the previous block, for the next
        /// block with this body and header, with its proof from the proof cache.
        fn own_claim_and_proof(
            prev_block: &Block,
            next_body: &BlockBody,
            next_header: &BlockHeader,
        ) -> (Claim, NeptuneProof) {
            let program = PredecessorIsValid::new();
            let claim = own_claim(&program, prev_block, next_body, next_header);
            let witness = PredecessorIsValidWitness::new(
                prev_block,
                next_body,
                transaction_mutator_set(prev_block),
            );
            let proof = load_proof_or_produce_and_save(
                &claim,
                program.program(),
                witness.nondeterminism_under(&program, &epochs()),
            );

            (claim, proof)
        }

        /// A successor of the previous block with this body and header, whose
        /// appendix holds the verifying program's claim among fillers, with its
        /// proof.
        fn proven_block_with_own_claim(
            prev_block: &Block,
            body: BlockBody,
            header: BlockHeader,
            seed: u64,
        ) -> Block {
            let own_claim = own_claim_and_proof(prev_block, &body, &header);
            let mut claims = vec![halt_claim_and_proof(), halt_claim_and_proof()];
            claims.insert(own_claim_position(seed), own_claim);

            proven_block(header, body, claims)
        }

        /// A proven previous block that carries the verifying program's claim,
        /// and a next body and header for it.
        fn prev_block_and_next_body_and_header(seed: u64) -> (Block, BlockBody, BlockHeader) {
            let prev_prev_block = random_block(seed);
            let (body, header) = next_body_and_header(&prev_prev_block, seed);
            let prev_block = proven_block_with_own_claim(&prev_prev_block, body, header, seed);
            let (next_body, next_header) = next_body_and_header(&prev_block, seed);

            (prev_block, next_body, next_header)
        }

        #[test]
        fn rust_and_tasm_agree_and_output_is_the_prev_block_hash() {
            let (prev_block, next_body, next_header) = prev_block_and_next_body_and_header(0);
            assert_accepts(
                &PredecessorIsValid::new(),
                &prev_block,
                &next_body,
                &next_header,
            );
        }

        #[test]
        fn prev_block_with_modified_proof_fails_verification() {
            let (mut prev_block, _, _) = prev_block_and_next_body_and_header(0);
            let BlockProof::SingleProof(proof) = prev_block.proof.clone() else {
                panic!("fixture must carry a single proof");
            };
            let mut words = proof.0.clone();
            *words.last_mut().unwrap() += bfe!(1);
            prev_block.set_proof(BlockProof::SingleProof(NeptuneProof::from(words)));
            prev_block.satisfy_pow(Difficulty::MINIMUM, ConsensusRuleSet::HardforkDelta);
            let (next_body, next_header) = next_body_and_header(&prev_block, 0);

            let program = PredecessorIsValid::new();
            let (claim, nondeterminism) = claim_and_nondeterminism(
                &program,
                &prev_block,
                &next_body,
                &next_header,
                &epochs(),
            );
            let input = PublicInput::new(claim.input);
            assert!(program.run_tasm(&input, nondeterminism.clone()).is_err());
            assert!(program.run_rust(&input, nondeterminism).is_err());
        }
    }

    /// The tests that need no block proof in the witness: they run the
    /// variant of this program that skips proof verification.
    mod proof_free {
        use std::cell::Cell;

        use super::*;

        #[test]
        fn skipping_program_agrees_with_rust_and_outputs_the_prev_block_hash() {
            for seed in 0..3 {
                let (prev_block, next_body, next_header) =
                    unproven_prev_block_and_next_body_and_header(seed);
                assert_accepts(&skipping(), &prev_block, &next_body, &next_header);
            }
        }

        #[test]
        fn prev_block_carrying_an_unknown_claim_is_accepted() {
            let prev_prev_block = random_unproven_block(0);
            let (body, header) = next_body_and_header(&prev_prev_block, 0);

            // The new "extension" claim carries its *own* check that the
            // claim was present in the parent. Together with the parent-proof
            // verification in PredecessorIsValid, these two checks allow new
            // rules to be added as a softfork, where the new rules enforce
            // their own recursion, i.e., their own presence in the parent
            // block.
            let extension = ExtensionClaim::new(&skipping(), activation_height().value());
            let extension_claim = extension.claim(prev_prev_block.hash(), body.mast_hash());
            let own_claim = own_claim(&skipping(), &prev_prev_block, &body, &header);
            let prev_block = unproven_block(header, body, vec![extension_claim, own_claim]);
            let (next_body, next_header) = next_body_and_header(&prev_block, 0);
            assert_accepts(&skipping(), &prev_block, &next_body, &next_header);

            let witness = ExtensionClaimWitness::new(
                extension,
                prev_block.hash(),
                next_body.mast_hash(),
                ParentForExtension::new(&prev_block),
            );
            let input = witness.standard_input();
            assert!(extension.run_tasm(&input, witness.nondeterminism()).is_ok());
        }

        #[test]
        fn prev_block_below_activation_height_needs_no_claim() {
            let prev_prev_block =
                random_unproven_block_at_height(0, activation_height().value() - 2);
            let (body, header) = next_body_and_header(&prev_prev_block, 0);
            let prev_block = unproven_block(header, body, vec![]);
            let (next_body, next_header) = next_body_and_header(&prev_block, 0);

            assert_accepts(&skipping(), &prev_block, &next_body, &next_header);
        }

        #[test]
        fn prev_block_at_activation_height_without_the_claim_fails() {
            let prev_prev_block = random_unproven_block(0);
            let (body, header) = next_body_and_header(&prev_prev_block, 0);
            let prev_block = unproven_block(header, body, vec![]);
            let (next_body, next_header) = next_body_and_header(&prev_block, 0);

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::AppendixMissingClaim.error_id(),
            );
        }

        #[test]
        fn prev_block_without_transaction_claim_fails() {
            let prev_prev_block = random_unproven_block(0);
            let (body, header) = next_body_and_header(&prev_prev_block, 0);
            let own_claim = own_claim(&skipping(), &prev_prev_block, &body, &header);
            let prev_block = block(
                header,
                body,
                BlockAppendix::new(vec![own_claim]),
                BlockProof::Invalid,
            );
            let (next_body, next_header) = next_body_and_header(&prev_block, 0);

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::AppendixMissingClaim.error_id(),
            );
        }

        /// The previous block whose header carries this lustration counter,
        /// with its own claim, and a next body and header for it.
        /// The previous block with this lustration status in place of the
        /// one its predecessor and transaction dictate, and a next body and
        /// header for it.
        fn prev_block_with_lustration_status(
            status: LustrationStatus,
        ) -> (Block, BlockBody, BlockHeader) {
            let prev_prev_block = random_unproven_block(0);
            let (body, mut header) = next_body_and_header(&prev_prev_block, 0);
            header.pow.set_lustration_status(status);
            let prev_block = unproven_block_with_own_claim(&prev_prev_block, body, header, 0);
            let (next_body, next_header) = next_body_and_header(&prev_block, 0);

            (prev_block, next_body, next_header)
        }

        fn dictated_lustration_status() -> LustrationStatus {
            let (_, header) = next_body_and_header(&random_unproven_block(0), 0);
            header.pow.lustration_status().unwrap()
        }

        #[test]
        fn prev_block_with_other_lustration_counter_fails() {
            let mut status = dictated_lustration_status();
            status.counter += NativeCurrencyAmount::one_nau();
            let (prev_block, next_body, next_header) = prev_block_with_lustration_status(status);

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::BadLustrationCounter.error_id(),
            );
        }

        #[test]
        fn prev_block_with_other_lustration_threshold_fails() {
            let mut status = dictated_lustration_status();
            status.max_lustrating_aocl_leaf_index += 1;
            let (prev_block, next_body, next_header) = prev_block_with_lustration_status(status);

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::BadLustrationAoclThreshold.error_id(),
            );
        }

        #[test]
        fn prev_block_whose_lustration_status_does_not_parse_fails() {
            let prev_prev_block = random_unproven_block_at_height(0, height_below_activation() - 1);
            let (body, mut header) = next_body_and_header(&prev_prev_block, 0);
            header.pow.path_a[POW_MEMORY_TREE_HEIGHT - 2].0[2] = bfe!(1_u64 << 32);
            assert!(header.pow.lustration_status().is_err());
            let appendix = BlockAppendix::new(vec![transaction_claim_and_proof_for(&body).0]);
            let prev_block =
                block_solved_by_nonce_search(header, body, appendix, BlockProof::Invalid);
            let (next_body, next_header) = next_body_and_header(&prev_block, 0);

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::BadLustrationCounterEncoding.error_id(),
            );
        }

        #[test]
        fn prev_block_whose_version_disagrees_with_its_copy_in_pow_fails() {
            let mut prev_block = random_unproven_block(0);
            let version = prev_block.header().version;
            prev_block.set_header_version_in_pow_only(version + bfe!(1));
            let (next_body, next_header) = next_body_and_header(&prev_block, 0);

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::VersionMismatch.error_id(),
            );
        }

        #[test]
        fn prev_block_without_proof_of_work_fails() {
            let prev_prev_block = random_unproven_block(0);
            let (body, mut header) = next_body_and_header(&prev_prev_block, 0);
            header.difficulty = Difficulty::new([1, 2, 3, 4, 5]);
            header.pow.set_version_in_pow(header.version);
            let prev_block =
                Block::new(header, body, BlockAppendix::default(), BlockProof::Invalid);
            let (next_body, next_header) = next_body_and_header(&prev_block, 0);

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                PowValidationError::ThresholdNotMet.error_id(),
            );
        }

        #[test]
        fn single_proof_encoding_has_the_layout_the_program_reads() {
            let proof = NeptuneProof::from(vec![bfe!(7), bfe!(8), bfe!(9)]);
            let encoding = BlockProof::SingleProof(proof.clone()).encode();
            let expected = [
                vec![
                    bfe!(BlockProof::SINGLE_PROOF_DISCRIMINANT),
                    bfe!(proof.encode().len() as u64),
                ],
                proof.encode(),
            ]
            .concat();
            assert_eq!(expected, encoding);
            assert_eq!(
                BlockProof::SINGLE_PROOF_PREFIX_LEN as usize,
                encoding.len() - proof.encode().len()
            );
        }

        /// The previous block with its own claim, and a single proof of as many
        /// words as it takes for the block to have this size.
        fn prev_block_of_size(size: usize) -> (Block, BlockBody, BlockHeader) {
            let (prev_block, _, _) = unproven_prev_block_and_next_body_and_header(0);
            let header = *prev_block.header();
            let body = prev_block.body().clone();
            let appendix = prev_block.appendix().clone();

            let empty_proof = BlockProof::SingleProof(NeptuneProof::from(vec![]));
            let smallest = Block::new(header, body.clone(), appendix.clone(), empty_proof);
            let num_words = size - smallest.size();
            let proof = BlockProof::SingleProof(NeptuneProof::from(vec![bfe!(0); num_words]));

            let prev_block = block(header, body, appendix, proof);
            let (next_body, next_header) = next_body_and_header(&prev_block, 0);

            (prev_block, next_body, next_header)
        }

        /// The fixture grandparent's header and body as generated, without
        /// a proof or claims.
        fn unproven_fixture_grandparent(
            generated_header: BlockHeader,
            body: BlockBody,
            _appendix: BlockAppendix,
        ) -> Block {
            unproven_block(fixture_grandparent_header(&generated_header), body, vec![])
        }

        thread_local! {
            /// The lustration status the grandparent of a lustration chain
            /// carries, set by the test that builds the chain.
            static GRANDPARENT_LUSTRATION_STATUS: Cell<Option<LustrationStatus>> =
                const { Cell::new(None) };
        }

        /// As [unproven_fixture_grandparent], with the lustration status the
        /// test set.
        fn lustrating_grandparent(
            generated_header: BlockHeader,
            body: BlockBody,
            _appendix: BlockAppendix,
        ) -> Block {
            let mut header = fixture_grandparent_header(&generated_header);
            let status = GRANDPARENT_LUSTRATION_STATUS
                .get()
                .expect("the test sets the grandparent's lustration status");
            header.pow.set_lustration_status(status);

            unproven_block(header, body, vec![])
        }

        /// The chain with the chunk data stripped from the previous block's
        /// inputs, as blocks carry them under e1. The SWBF update claim
        /// stays, since it was built from the chunks and reads only the index
        /// sets; the own claim is recomputed for the new body, the proof of
        /// work is redone, and the next body and header are rebuilt on the
        /// new hash with the chain's own transaction, as [chain_with_inputs]
        /// builds them.
        fn without_chunk_data(
            (prev_block, _, _): (Block, BlockBody, BlockHeader),
        ) -> (Block, BlockBody, BlockHeader) {
            let body = prev_block.body();
            let kernel = &body.transaction_kernel;
            let kernel_with_chunks = kernel.clone();
            let mutator_set = transaction_mutator_set(&prev_block);
            let grandparent = predecessor_by_hash(prev_block.header().prev_block_digest)
                .expect("the chain's grandparent must be known");
            let swbf_claim = prev_block
                .appendix()
                .claims()
                .iter()
                .find(|claim| claim.program_digest == SwbfUpdateAggregation::new().hash())
                .cloned();
            let inputs = kernel
                .inputs
                .iter()
                .map(|record| RemovalRecord {
                    absolute_indices: record.absolute_indices,
                    target_chunks: ChunkDictionary::empty(),
                })
                .collect();
            let kernel = TransactionKernelModifier::default()
                .inputs(inputs)
                .modify(kernel.clone());
            let body = BlockBody::new(
                kernel,
                body.mutator_set_accumulator.clone(),
                body.lock_free_mmr_accumulator.clone(),
                body.block_mmr_accumulator.clone(),
            );
            let header = *prev_block.header();
            let own_claim =
                own_claim_with_epochs(&skipping(), &grandparent, &body, &header, &epochs());
            let prev_block =
                unproven_block_with_swbf_claim(header, body, vec![own_claim], swbf_claim);
            let peaks =
                SwbfiPeaksAfterRemovals::apply_removals(&kernel_with_chunks.inputs, &mutator_set)
                    .swbf_inactive
                    .peaks();
            remember_swbfi_peaks_after_removals(&prev_block, peaks);
            let (next_body, next_header) = next_body_and_header_with_transaction(
                &prev_block,
                0,
                &kernel_with_chunks,
                &mutator_set,
            );

            (prev_block, next_body, next_header)
        }

        /// A chain built without proofs: a grandparent built by this
        /// function, a previous block at the activation height whose
        /// transaction is the deterministic one with this many inputs, packed
        /// and then edited by this function, and a next body and header for
        /// it. Also returns the transparent inputs.
        fn chain_with_inputs(
            num_inputs: usize,
            build_grandparent: fn(BlockHeader, BlockBody, BlockAppendix) -> Block,
            edit_kernel: impl FnOnce(&[TransparentInput], TransactionKernel) -> TransactionKernel,
        ) -> ((Block, BlockBody, BlockHeader), Vec<TransparentInput>) {
            chain_with_inputs_under(
                num_inputs,
                build_grandparent,
                edit_kernel,
                &epochs(),
                |_, header| header,
            )
        }

        /// As [chain_with_inputs], with the previous block's claim under these
        /// epochs and its header edited by this function, given its body.
        fn chain_with_inputs_under(
            num_inputs: usize,
            build_grandparent: fn(BlockHeader, BlockBody, BlockAppendix) -> Block,
            edit_kernel: impl FnOnce(&[TransparentInput], TransactionKernel) -> TransactionKernel,
            epochs: &EpochTable,
            edit_header: impl FnOnce(&BlockBody, BlockHeader) -> BlockHeader,
        ) -> ((Block, BlockBody, BlockHeader), Vec<TransparentInput>) {
            let (grandparent, _, inputs) =
                BlockPrimitiveWitness::deterministic_predecessor_and_primitive_witnesses(
                    num_inputs,
                    activation_height(),
                    Difficulty::MINIMUM,
                    Network::Main,
                    build_grandparent,
                );
            let transparent_inputs = inputs
                .input_utxos
                .utxos
                .iter()
                .cloned()
                .zip(&inputs.input_membership_proofs)
                .map(|(utxo, membership_proof)| TransparentInput {
                    utxo,
                    aocl_leaf_index: membership_proof.aocl_leaf_index,
                    sender_randomness: membership_proof.sender_randomness,
                    receiver_preimage: membership_proof.receiver_preimage,
                })
                .collect_vec();
            // With its inputs packed, as a block transaction has them.
            let kernel = TransactionKernelModifier::default()
                .merge_bit(true)
                .inputs(RemovalRecordList::pack(inputs.kernel.inputs.clone(), true))
                .modify(inputs.kernel.clone());
            let kernel = edit_kernel(&transparent_inputs, kernel);
            let mutator_set = &inputs.mutator_set_accumulator;
            let (body, header) =
                next_body_and_header_with_transaction(&grandparent, 0, &kernel, mutator_set);
            let header = edit_header(&body, header);
            let prev_block =
                unproven_block_with_own_claim_with_epochs(&grandparent, body, header, 0, epochs);
            let (next_body, next_header) =
                next_body_and_header_with_transaction(&prev_block, 0, &kernel, mutator_set);

            ((prev_block, next_body, next_header), transparent_inputs)
        }

        /// The epoch table whose activation epoch resets the lustration
        /// status.
        fn resetting_epochs() -> EpochTable {
            EpochTable::new(&[Epoch {
                resets_lustration_status: bfe!(1),
                ..activation_epoch()
            }])
        }

        /// The lustration status a block at a reset must carry.
        fn reset_status(body: &BlockBody) -> LustrationStatus {
            LustrationStatus {
                counter: lustration_counter_initial(),
                max_lustrating_aocl_leaf_index: body.max_aocl_leaf_index(),
            }
        }

        /// The lustration chain under these epochs: every input must
        /// lustrate under the grandparent's status, none is announced, and
        /// the previous block carries the status this function makes from
        /// its body.
        fn reset_chain(
            epochs: &EpochTable,
            prev_status: impl FnOnce(&BlockBody) -> LustrationStatus,
        ) -> (Block, BlockBody, BlockHeader) {
            GRANDPARENT_LUSTRATION_STATUS
                .set(Some(lustrating_status(NativeCurrencyAmount::coins(1))));
            let ((prev_block, next_body, next_header), _) = chain_with_inputs_under(
                2,
                lustrating_grandparent,
                |_, kernel| kernel,
                epochs,
                |body, mut header| {
                    header.pow.set_lustration_status(prev_status(body));
                    header
                },
            );

            (prev_block, next_body, next_header)
        }

        #[test]
        fn prev_block_at_a_lustration_reset_passes() {
            let (prev_block, next_body, next_header) =
                reset_chain(&resetting_epochs(), reset_status);

            assert_accepts_with_epochs(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                &resetting_epochs(),
            );
        }

        #[test]
        fn prev_block_at_a_lustration_reset_with_other_counter_fails() {
            let (prev_block, next_body, next_header) =
                reset_chain(&resetting_epochs(), |body| LustrationStatus {
                    counter: lustration_counter_initial()
                        .checked_sub(&NativeCurrencyAmount::one_nau())
                        .unwrap(),
                    ..reset_status(body)
                });

            assert_rejects_with_epochs(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                &resetting_epochs(),
                BlockValidationRule::BadLustrationCounter.error_id(),
            );
        }

        #[test]
        fn prev_block_at_a_lustration_reset_with_other_threshold_fails() {
            let (prev_block, next_body, next_header) =
                reset_chain(&resetting_epochs(), |body| LustrationStatus {
                    max_lustrating_aocl_leaf_index: body.max_aocl_leaf_index() + 1,
                    ..reset_status(body)
                });

            assert_rejects_with_epochs(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                &resetting_epochs(),
                BlockValidationRule::BadLustrationAoclThreshold.error_id(),
            );
        }

        #[test]
        fn prev_block_before_a_lustration_reset_updates() {
            let epochs = EpochTable::new(&[
                activation_epoch(),
                Epoch {
                    height: activation_height().next().into(),
                    resets_lustration_status: bfe!(1),
                    ..activation_epoch()
                },
            ]);
            let ((prev_block, next_body, next_header), _) = lustration_chain(
                lustrating_status(lustration_counter_initial()),
                all_lustrations,
            );

            assert_accepts_with_epochs(&skipping(), &prev_block, &next_body, &next_header, &epochs);

            let (prev_block, next_body, next_header) = reset_chain(&epochs, reset_status);
            assert_rejects_with_epochs(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                &epochs,
                BlockValidationRule::BadLustrationAoclThreshold.error_id(),
            );
        }

        /// A chain built without proofs: a grandparent with this lustration
        /// status, a previous block at the activation height whose
        /// transaction spends this many inputs and carries the announcements
        /// this function makes for them, and a next body and header for it.
        /// Also returns the transparent inputs.
        fn lustration_chain_with_inputs(
            num_inputs: usize,
            status: LustrationStatus,
            announcements: impl FnOnce(&[TransparentInput]) -> Vec<Announcement>,
        ) -> ((Block, BlockBody, BlockHeader), Vec<TransparentInput>) {
            GRANDPARENT_LUSTRATION_STATUS.set(Some(status));
            chain_with_inputs(num_inputs, lustrating_grandparent, |inputs, kernel| {
                TransactionKernelModifier::default()
                    .announcements(announcements(inputs))
                    .modify(kernel)
            })
        }

        /// As [lustration_chain_with_inputs], with two inputs.
        fn lustration_chain(
            status: LustrationStatus,
            announcements: impl FnOnce(&[TransparentInput]) -> Vec<Announcement>,
        ) -> ((Block, BlockBody, BlockHeader), Vec<TransparentInput>) {
            lustration_chain_with_inputs(2, status, announcements)
        }

        /// A status under which every input of the lustration chain must
        /// lustrate.
        fn lustrating_status(counter: NativeCurrencyAmount) -> LustrationStatus {
            LustrationStatus {
                counter,
                max_lustrating_aocl_leaf_index: u64::MAX / 2,
            }
        }

        fn all_lustrations(inputs: &[TransparentInput]) -> Vec<Announcement> {
            Announcement::lustration_announcements(
                lustrating_status(NativeCurrencyAmount::zero()),
                inputs,
            )
        }

        #[test]
        fn prev_block_lustrating_its_inputs_passes() {
            let initial = lustration_counter_initial();
            let ((prev_block, next_body, next_header), inputs) =
                lustration_chain(lustrating_status(initial), |inputs| {
                    [
                        vec![Announcement::new(vec![LUSTRATION_FLAG, bfe!(3)])],
                        all_lustrations(inputs),
                        all_lustrations(inputs),
                    ]
                    .concat()
                });
            let lustrated: NativeCurrencyAmount = inputs
                .iter()
                .map(|input| input.utxo.get_native_currency_amount())
                .sum();
            assert!(!lustrated.is_zero());
            assert_eq!(
                initial.checked_sub(&lustrated).unwrap(),
                prev_block.header().pow.lustration_status().unwrap().counter
            );

            assert_accepts(&skipping(), &prev_block, &next_body, &next_header);
        }

        #[test]
        fn prev_block_missing_a_lustration_announcement_fails() {
            let ((prev_block, next_body, next_header), _) =
                lustration_chain(lustrating_status(lustration_counter_initial()), |inputs| {
                    all_lustrations(inputs)[1..].to_vec()
                });

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::MissingLustrationAnnouncement.error_id(),
            );
        }

        #[test]
        fn prev_block_with_undecodable_lustration_announcement_fails() {
            let ((prev_block, next_body, next_header), _) =
                lustration_chain(lustrating_status(lustration_counter_initial()), |inputs| {
                    let mut announcements = all_lustrations(inputs);
                    announcements[0].message.pop();
                    announcements
                });

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::MissingLustrationAnnouncement.error_id(),
            );
        }

        #[test]
        fn prev_block_lustrating_more_than_the_counter_fails() {
            let ((prev_block, next_body, next_header), _) = lustration_chain(
                lustrating_status(NativeCurrencyAmount::one_nau()),
                all_lustrations,
            );

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::NegativeLustrationCounter.error_id(),
            );
        }

        /// An input whose AOCL range starts at or below the threshold must
        /// lustrate, but its amount only counts if its AOCL leaf index is at
        /// or below the threshold.
        #[test]
        fn prev_block_with_input_at_the_barrier_lustrates_without_counting() {
            let initial = lustration_counter_initial();
            let (_, inputs) = lustration_chain(lustrating_status(initial), all_lustrations);
            let input = &inputs[0];
            let (range_start, _) = input.absolute_index_set().aocl_range().unwrap();
            assert!(range_start < input.aocl_leaf_index);
            let status = LustrationStatus {
                counter: initial,
                max_lustrating_aocl_leaf_index: input.aocl_leaf_index - 1,
            };
            assert!(inputs[1..].iter().all(|other| {
                other.absolute_index_set().aocl_range().unwrap().0
                    > status.max_lustrating_aocl_leaf_index
            }));

            let ((prev_block, next_body, next_header), _) =
                lustration_chain(status, all_lustrations);
            assert_eq!(
                initial,
                prev_block.header().pow.lustration_status().unwrap().counter
            );
            assert_accepts(&skipping(), &prev_block, &next_body, &next_header);

            let ((prev_block, next_body, next_header), _) =
                lustration_chain(status, |inputs| all_lustrations(inputs)[1..].to_vec());
            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::MissingLustrationAnnouncement.error_id(),
            );
        }

        #[test]
        fn prev_block_with_lustration_counter_at_its_initial_value_passes() {
            let status = LustrationStatus {
                counter: lustration_counter_initial(),
                max_lustrating_aocl_leaf_index: 0,
            };
            let ((prev_block, next_body, next_header), _) = lustration_chain(status, |_| vec![]);

            assert_accepts(&skipping(), &prev_block, &next_body, &next_header);
        }

        #[test]
        fn prev_block_with_lustration_counter_above_its_initial_value_fails() {
            let status = LustrationStatus {
                counter: lustration_counter_initial() + NativeCurrencyAmount::one_nau(),
                max_lustrating_aocl_leaf_index: 0,
            };
            let ((prev_block, next_body, next_header), _) = lustration_chain(status, |_| vec![]);

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::LustrationCounterExceedsInitialValue.error_id(),
            );
        }

        /// The rows of every table, as signed numbers, so that profiles can
        /// be subtracted.
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
        struct Rows {
            processor: i64,
            op_stack: i64,
            ram: i64,
            hash: i64,
            u32: i64,
        }

        impl From<VMTableHeights> for Rows {
            fn from(heights: VMTableHeights) -> Self {
                Self {
                    processor: heights.processor.into(),
                    op_stack: heights.op_stack.into(),
                    ram: heights.ram.into(),
                    hash: heights.hash.into(),
                    u32: heights.u32.into(),
                }
            }
        }

        impl Rows {
            fn zip(self, other: Self, f: impl Fn(i64, i64) -> i64) -> Self {
                Self {
                    processor: f(self.processor, other.processor),
                    op_stack: f(self.op_stack, other.op_stack),
                    ram: f(self.ram, other.ram),
                    hash: f(self.hash, other.hash),
                    u32: f(self.u32, other.u32),
                }
            }

            fn add(self, other: Self) -> Self {
                self.zip(other, |a, b| a + b)
            }

            fn sub(self, other: Self) -> Self {
                self.zip(other, |a, b| a - b)
            }

            fn div(self, divisor: i64) -> Self {
                self.zip(Self::default(), |a, _| a / divisor)
            }
        }

        /// The rows each check of the program adds to every table, in
        /// program order: the spans of the subroutines the program calls
        /// directly, and, within the epoch section, of the checks it calls.
        /// The rows outside those spans are listed as glue. The u32 table
        /// counts distinct entries only, so its rows do not add up across
        /// checks.
        struct CheckCosts {
            /// A row per check, indented for the checks of the epoch section,
            /// and twice for the rules inside the mutator set update.
            rows: Vec<(String, Rows)>,
            total: Rows,
            padded_height: usize,
            /// The program table's height: the program's padded length.
            program: u32,
        }

        impl CheckCosts {
            const EPOCH_SECTION: &str = "predecessor_is_valid_prev_block_epoch_rules";
            const MUTATOR_SET_UPDATE: &str = "predecessor_is_valid_mutator_set_update_prev";
            /// The checks inside the mutator set update, by label.
            const MUTATOR_SET_UPDATE_RULES: [&str; 3] = [
                "neptune_consensus_block_removal_index_commitment",
                "predecessor_is_valid_find_swbf_claim",
                "neptune_consensus_block_mutator_set_update_from_state_hash_rule_2e",
            ];

            fn new(profile: &ExecutionTraceProfile) -> Self {
                let mut rows: Vec<(String, Rows)> = vec![];
                let mut add = |label: String, rows_of_span: Rows| match rows
                    .iter_mut()
                    .find(|(existing, _)| *existing == label)
                {
                    Some((_, existing)) => *existing = existing.add(rows_of_span),
                    None => rows.push((label, rows_of_span)),
                };

                let mut parent = String::new();
                for line in &profile.profile {
                    let contribution =
                        Rows::from(line.table_heights_stop).sub(line.table_heights_start.into());
                    if line.call_depth == 0 {
                        parent.clone_from(&line.label);
                        add(line.label.clone(), contribution);
                    } else if line.call_depth == 1 && parent == Self::EPOCH_SECTION {
                        add(format!("  {}", line.label), contribution);
                    } else if Self::MUTATOR_SET_UPDATE_RULES.contains(&line.label.as_str()) {
                        add(format!("    {}", line.label), contribution);
                    }
                }

                let mutator_set_update = rows
                    .iter()
                    .find(|(label, _)| label.trim_start() == Self::MUTATOR_SET_UPDATE)
                    .map(|(_, rows)| *rows);
                if let Some(mutator_set_update) = mutator_set_update {
                    let in_rules = rows
                        .iter()
                        .filter(|(label, _)| label.starts_with("    "))
                        .fold(Rows::default(), |sum, (_, rows)| sum.add(*rows));
                    let last_rule = rows
                        .iter()
                        .rposition(|(label, _)| label.starts_with("    "))
                        .expect("the update has rules");
                    rows.insert(
                        last_rule + 1,
                        (
                            "    (glue of the mutator set update)".to_string(),
                            mutator_set_update.sub(in_rules),
                        ),
                    );
                }

                let total = Rows::from(profile.total);
                let epoch_section = rows
                    .iter()
                    .find(|(label, _)| label == Self::EPOCH_SECTION)
                    .map(|(_, rows)| *rows);
                if let Some(epoch_section) = epoch_section {
                    let in_checks = rows
                        .iter()
                        .filter(|(label, _)| label.starts_with(' ') && !label.starts_with("    "))
                        .fold(Rows::default(), |sum, (_, rows)| sum.add(*rows));
                    rows.push((
                        "  (glue of the epoch section)".to_string(),
                        epoch_section.sub(in_checks),
                    ));
                }
                let in_spans = rows
                    .iter()
                    .filter(|(label, _)| !label.starts_with(' '))
                    .fold(Rows::default(), |sum, (_, rows)| sum.add(*rows));
                rows.push((
                    "(glue of the main program)".to_string(),
                    total.sub(in_spans),
                ));

                Self {
                    rows,
                    total,
                    padded_height: profile.padded_height,
                    program: profile.total.program,
                }
            }

            /// The rows of each check, less those of the same check in the
            /// other profile, divided by the count.
            fn per_unit(&self, other: &Self, count: i64) -> Vec<(String, Rows)> {
                self.rows
                    .iter()
                    .map(|(label, rows)| {
                        let other_rows = other
                            .rows
                            .iter()
                            .find(|(other_label, _)| other_label == label)
                            .map_or(Rows::default(), |(_, rows)| *rows);
                        (label.clone(), rows.sub(other_rows).div(count))
                    })
                    .collect()
            }

            /// The processor rows of the check with this label.
            fn processor_rows_of(&self, label: &str) -> i64 {
                self.rows
                    .iter()
                    .find(|(existing, _)| existing.trim_start() == label)
                    .map_or(0, |(_, rows)| rows.processor)
            }

            /// The hash rows outside every span: program attestation.
            fn program_attestation_hash_rows(&self) -> i64 {
                self.rows
                    .iter()
                    .find(|(label, _)| label == "(glue of the main program)")
                    .map_or(0, |(_, rows)| rows.hash)
            }

            /// The readable name of the check with this subroutine label.
            fn describe_check(label: &str) -> &str {
                let label = label.strip_prefix("predecessor_is_valid_").unwrap_or(label);
                match label {
                    "tasmlib_verifier_own_program_digest" => "own program digest",
                    _ if label.starts_with("tasmlib_structure_verify_nd_si_integrity") => {
                        "witness audit"
                    }
                    "authenticate_next_block_mmr_accumulator" => {
                        "authenticate next block's MMR accumulator (leaf for 0.a, 0.c)"
                    }
                    "hash_prev_block_body" => "hash previous block's body and transaction kernel",
                    "prev_block_hash" => "previous block's hash (header MAST, appendix, proof)",
                    "rule_0a" => "0.a height",
                    "rule_0c" => "0.c block MMR update",
                    "rule_1f_prev" => "1.f version in PoW",
                    "proof_of_work_prev" => "proof of work (minimum difficulty, hash under target)",
                    "rule_1b_prev" => "1.b appendix size",
                    "rule_1e_prev" => "1.e block size",
                    "rule_1c_prev" => "1.c single proof",
                    "rule_1d_prev" => "1.d block proof verification",
                    "rule_1a_prev" => "1.a transaction claim in appendix",
                    "rule_2g_prev" => "2.g coinbase within subsidy",
                    "rule_2h_prev" => "2.h coinbase non-negative",
                    "rule_2i_prev" => "2.i fee non-negative",
                    "rule_2c_prev" => "2.c inputs unique",
                    "mutator_set_after_prev_block" => {
                        "mutator set after previous block (guesser fee; claim output)"
                    }
                    "rules_2o_2u_announcements_prev" => "2.o/2.u announcement scan",
                    "rule_2m_prev" => "2.m lustration status parses",
                    "read_epoch_table" => "read epoch table",
                    "tasmlib_arithmetic_u64_lt" => "activation height comparison",
                    "prev_block_epoch_rules" => "**epoch section (sum of the indented rows)**",
                    "epoch_in_force" => "epoch in force",
                    "find_own_claim" => "find own claim in appendix",
                    "rule_0b_prev" => "0.b parent digest",
                    "rule_0d_prev" => "0.d minimum block time",
                    "rule_0e_prev" => "0.e difficulty",
                    "rule_0f_prev" => "0.f cumulative PoW",
                    "rule_2t_prev" => "2.t transaction and witness mutator set hashes",
                    "mutator_set_update_prev" => {
                        "2.a to 2.e mutator set update (sum of the indented rows)"
                    }
                    "neptune_consensus_block_removal_index_commitment" => {
                        "MMR peaks over the inputs' index sets"
                    }
                    "find_swbf_claim" => "find SWBF update claim in appendix",
                    "neptune_consensus_block_mutator_set_update_from_state_hash_rule_2e" => {
                        "2.e window, peaks, additions and comparison"
                    }
                    "rule_2q_prev" => "2.q lustration threshold",
                    "rules_2o_2p_2r_prev" => "2.o/2.p/2.r lustration amount and counter",
                    "lustration_reset_prev" => "2.p/2.q lustration reset",
                    "lustration_update_prev" => "2.o to 2.r lustration update",
                    "rule_2f_prev" => "2.f transaction timestamp",
                    "rule_2j_prev" => "2.j max inputs",
                    "rule_2k_prev" => "2.k max outputs",
                    "rule_2l_prev" => "2.l max announcements",
                    "rule_2s_prev" => "2.s counter below initial value",
                    "write_output" => "write claim output",
                    "(glue of the main program)" => {
                        "(glue of the main program; program attestation in the hash table)"
                    }
                    "total" => "**total**",
                    other => other,
                }
            }

            /// A markdown table of these rows, omitting rows that are zero
            /// throughout if asked.
            fn markdown_table(rows: &[(String, Rows)], omit_zero_rows: bool) -> String {
                let mut table = String::from(
                    "| check | processor | op_stack | ram | hash | u32 |\n\
                     |---|---:|---:|---:|---:|---:|\n",
                );
                for (label, rows) in rows {
                    if omit_zero_rows && *rows == Rows::default() {
                        continue;
                    }
                    let (indent, label) =
                        match (label.strip_prefix("    "), label.strip_prefix("  ")) {
                            (Some(label), _) => {
                                ("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;", label)
                            }
                            (None, Some(label)) => ("&nbsp;&nbsp;&nbsp;&nbsp;", label),
                            (None, None) => ("", label.as_str()),
                        };
                    table += &format!(
                        "| {indent}{} | {} | {} | {} | {} | {} |\n",
                        Self::describe_check(label),
                        with_separators(rows.processor),
                        with_separators(rows.op_stack),
                        with_separators(rows.ram),
                        with_separators(rows.hash),
                        with_separators(rows.u32),
                    );
                }
                table
            }

            /// A markdown section with the full profile.
            fn markdown(&self, title: &str, description: &str) -> String {
                let mut rows = self.rows.clone();
                rows.push(("total".to_string(), self.total));
                format!(
                    "### {title}\n\n{description}. Padded height 2^{} ({}); program table \
                     height {}.\n\n{}",
                    self.padded_height.ilog2(),
                    with_separators(self.padded_height as i64),
                    with_separators(self.program.into()),
                    Self::markdown_table(&rows, false),
                )
            }
        }

        /// The number with thousands separators.
        fn with_separators(n: i64) -> String {
            let digits = n.abs().to_string();
            let mut grouped = String::new();
            for (i, digit) in digits.chars().enumerate() {
                if i > 0 && (digits.len() - i).is_multiple_of(3) {
                    grouped.push(',');
                }
                grouped.push(digit);
            }
            if n < 0 {
                grouped.insert(0, '-');
            }
            grouped
        }

        /// The rows every table gets from each check of the skipping
        /// program, for this chain.
        fn profile_checks(
            (prev_block, next_body, next_header): &(Block, BlockBody, BlockHeader),
        ) -> CheckCosts {
            let program = skipping();
            let (claim, nondeterminism) =
                claim_and_nondeterminism(&program, prev_block, next_body, next_header, &epochs());
            let (output, profile) = VM::profile(
                program.program(),
                PublicInput::new(claim.input),
                nondeterminism,
            )
            .unwrap();
            assert_eq!(claim.output, output);

            CheckCosts::new(&profile)
        }

        /// The number of chunks the previous block's transaction's inputs
        /// need, in total and per input.
        fn describe_chunks(prev_block: &Block) -> (usize, usize) {
            let kernel = &prev_block.body().transaction_kernel;
            let num_chunks = ChunkWitness::chunks(&kernel.inputs).len();
            (num_chunks, num_chunks / kernel.inputs.len().max(1))
        }

        /// The shape of the previous block's transaction, in one line.
        fn describe_chain((prev_block, _, _): &(Block, BlockBody, BlockHeader)) -> String {
            let kernel = &prev_block.body().transaction_kernel;
            let mutator_set = transaction_mutator_set(prev_block);
            let window_start =
                u128::from(mutator_set.swbf_inactive.num_leafs()) << CHUNK_SIZE.ilog2();
            let inputs = &kernel.inputs;
            let indices_in_window = inputs
                .iter()
                .flat_map(|record| record.absolute_indices.to_array())
                .filter(|&index| index >= window_start)
                .count();
            let announcement_words = kernel
                .announcements
                .iter()
                .map(|announcement| announcement.message.len())
                .sum::<usize>();
            format!(
                "Previous block of {} words: {} inputs with {} packed chunks and {} of {} indices \
                 in the active window, {} outputs, {} announcements of {} words in total",
                prev_block.size(),
                inputs.len(),
                describe_chunks(prev_block).0,
                indices_in_window,
                inputs.len() * NUM_TRIALS as usize,
                kernel.outputs.len(),
                kernel.announcements.len(),
                announcement_words,
            )
        }

        /// Where the profile of the checks is written: next to the workspace
        /// manifest.
        const COST_PROFILE_PATH: &str = "../predecessor-is-valid-cost-profile.md";

        /// Writes the rows each check of the skipping program adds to the
        /// tables that decide the padded height, for previous blocks whose
        /// transactions differ in shape, and then the difference per input,
        /// per output, per announcement and per lustrating input, to the
        /// markdown document at [COST_PROFILE_PATH], and prints it. Built
        /// without any proof. Run this test after changing the program to
        /// regenerate the document.
        #[test]
        #[ignore = "regenerates the cost profile document"]
        fn profile_skipping_program_by_transaction_shape() {
            const FEW_INPUTS: usize = 2;
            const MANY_INPUTS: usize = 20;
            const EXTRA_OUTPUTS: usize = 18;
            const NUM_ANNOUNCEMENTS: usize = 10;
            const ANNOUNCEMENT_LEN: usize = 100;

            let plain = |num_inputs| {
                chain_with_inputs(num_inputs, unproven_fixture_grandparent, |_, kernel| kernel).0
            };
            let with_outputs =
                chain_with_inputs(FEW_INPUTS, unproven_fixture_grandparent, |_, kernel| {
                    let mut rng = StdRng::seed_from_u64(0);
                    let extra = (0..EXTRA_OUTPUTS).map(|_| AdditionRecord::new(rng.random()));
                    let outputs = kernel.outputs.iter().copied().chain(extra).collect();
                    TransactionKernelModifier::default()
                        .outputs(outputs)
                        .modify(kernel)
                })
                .0;
            let with_announcements =
                chain_with_inputs(FEW_INPUTS, unproven_fixture_grandparent, |_, kernel| {
                    let announcement = Announcement::new(vec![bfe!(1); ANNOUNCEMENT_LEN]);
                    let announcements = kernel
                        .announcements
                        .iter()
                        .cloned()
                        .chain(std::iter::repeat_n(announcement, NUM_ANNOUNCEMENTS))
                        .collect();
                    TransactionKernelModifier::default()
                        .announcements(announcements)
                        .modify(kernel)
                })
                .0;
            let lustrating = |num_inputs| {
                lustration_chain_with_inputs(
                    num_inputs,
                    lustrating_status(lustration_counter_initial()),
                    all_lustrations,
                )
                .0
            };

            let few = plain(FEW_INPUTS);
            let many = plain(MANY_INPUTS);
            let few_chunkless = without_chunk_data(plain(FEW_INPUTS));
            let many_chunkless = without_chunk_data(plain(MANY_INPUTS));
            let few_lustrating = lustrating(FEW_INPUTS);
            let many_lustrating = lustrating(MANY_INPUTS);
            let lustration_words = few_lustrating
                .0
                .body()
                .transaction_kernel
                .announcements
                .iter()
                .map(|announcement| announcement.message.len())
                .max()
                .unwrap();
            let chains = [
                (format!("{FEW_INPUTS} inputs"), &few),
                (format!("{MANY_INPUTS} inputs"), &many),
                (format!("{FEW_INPUTS} chunkless inputs"), &few_chunkless),
                (format!("{MANY_INPUTS} chunkless inputs"), &many_chunkless),
                (format!("{FEW_INPUTS} inputs, {EXTRA_OUTPUTS} extra outputs"), &with_outputs),
                (
                    format!("{FEW_INPUTS} inputs, {NUM_ANNOUNCEMENTS} announcements of {ANNOUNCEMENT_LEN} words"),
                    &with_announcements,
                ),
                (format!("{FEW_INPUTS} lustrating inputs"), &few_lustrating),
                (format!("{MANY_INPUTS} lustrating inputs"), &many_lustrating),
            ];
            let profiles = chains.each_ref().map(|(_, chain)| profile_checks(chain));
            let full_profiles = chains
                .iter()
                .zip(&profiles)
                .map(|((name, chain), profile)| profile.markdown(name, &describe_chain(chain)))
                .join("\n");
            let [few, many, few_chunkless, many_chunkless, with_outputs, with_announcements, few_lustrating, many_lustrating] =
                &profiles;

            let extra_inputs = (MANY_INPUTS - FEW_INPUTS) as i64;
            let per_input = many.per_unit(few, extra_inputs);
            let per_chunkless_input = many_chunkless.per_unit(few_chunkless, extra_inputs);
            let per_output = with_outputs.per_unit(few, EXTRA_OUTPUTS as i64);
            let per_announcement = with_announcements.per_unit(few, NUM_ANNOUNCEMENTS as i64);
            let lustration = few_lustrating.per_unit(few, 1);
            let per_lustrating_input = many_lustrating
                .per_unit(few_lustrating, extra_inputs)
                .into_iter()
                .zip(many.per_unit(few, extra_inputs))
                .map(|((label, lustrating), (_, plain))| (label, lustrating.sub(plain)))
                .collect_vec();
            let table = |rows: &[(String, Rows)]| CheckCosts::markdown_table(rows, true);

            let mutator_set_share = |profile: &CheckCosts| {
                let mutator_set_rules =
                    profile.processor_rows_of("predecessor_is_valid_mutator_set_update_prev");
                100 * mutator_set_rules / profile.total.processor
            };
            let (_, chunks_per_input) = describe_chunks(&chains[0].1 .0);
            let chunks_per_input = chunks_per_input as i64;

            let document = format!(
                "# Cost profile of `PredecessorIsValid`

Rows each check of `PredecessorIsValid` adds to the tables of the Triton VM
execution trace, for the program that skips the verification of the previous
block's proof (rule 1.d). A STARK verification is a few hundred thousand rows
and is not profiled here.

Generated by the test `profile_skipping_program_by_transaction_shape` in
`neptune-consensus/src/block/validity/predecessor_is_valid.rs`. Regenerate it
after changing the program:

```
cargo nextest run -p neptune-consensus --run-ignored ignored-only \\
    -E 'test(profile_skipping_program_by_transaction_shape)'
```

## Method

Every check is a labelled subroutine, so Triton VM's execution-trace profiler
(`VM::profile`) attributes the rows of every table to it, callees included.
The test builds eight previous blocks from the deterministic block primitive
witness generator, profiles each, and computes the differences.

The padded height is the next power of two above the tallest table. The u32
table counts distinct entries only, so its rows do not add up across checks.

The fixture transaction spends inputs whose {NUM_TRIALS} indices all lie in
the inactive SWBF, needing about {chunks_per_input} chunks per input. An
input whose indices lie in the active window needs no chunks and is much
cheaper. The chunkless chains strip the chunk dictionaries from the previous
block's inputs after its claims are built, leaving the index sets only, as
blocks carry inputs under e1; `PredecessorIsValid` reads no chunk data, so
their difference to the plain chains is the cost of carrying it. The
generator's transaction has no outputs; outputs and announcements are added on
top of it.

## Deltas per unit

Each row is the difference between two profiles divided by the number of units
added. Rows that are zero throughout are omitted. The epoch section is the sum
of the checks that run only when the previous block is at or past the
activation height.

### Per input ({MANY_INPUTS} inputs against {FEW_INPUTS})

{}

### Per input without chunk data ({MANY_INPUTS} chunkless inputs against {FEW_INPUTS})

{}

### Per output ({EXTRA_OUTPUTS} extra outputs against none)

{}
### Per announcement of {ANNOUNCEMENT_LEN} words ({NUM_ANNOUNCEMENTS} against none)

{}
### Lustration

{FEW_INPUTS} inputs that must lustrate, each with its {lustration_words}-word
lustration announcement, against the same inputs without lustration:

{}
Per lustrating input, over an input that does not lustrate ({MANY_INPUTS} and
{FEW_INPUTS} lustrating inputs against {MANY_INPUTS} and {FEW_INPUTS} plain
ones):

{}
## Full profiles

{}
## Observations

- The mutator-set rules 2.a and 2.e are {}% of the processor rows with
  {FEW_INPUTS} inputs and {}% with {MANY_INPUTS}.
- The base cost that scales with block size rather than with inputs is hashing
  the body and auditing the witness.
- The hash rows in the main program's glue, {}, are program attestation. The
  program table's height, {}, includes the STARK verifier, which is linked
  even when rule 1.d is not called.
",
                table(&per_input),
                table(&per_chunkless_input),
                table(&per_output),
                table(&per_announcement),
                table(&lustration),
                table(&per_lustrating_input),
                full_profiles,
                mutator_set_share(few),
                mutator_set_share(many),
                with_separators(few.program_attestation_hash_rows()),
                with_separators(few.program.into()),
            );

            println!("{document}");
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(COST_PROFILE_PATH);
            std::fs::write(&path, document).unwrap();
            println!("written to {}", path.display());
        }

        /// Prints how the skipping program's cycles distribute over subroutines,
        /// for a small previous block and for one of maximum size.
        #[test]
        #[ignore = "prints a profile"]
        fn profile_skipping_program() {
            let program = skipping();
            let max_block_size = max_block_size();
            for (name, (prev_block, next_body, next_header)) in [
                ("small", unproven_prev_block_and_next_body_and_header(0)),
                ("max size", prev_block_of_size(max_block_size)),
            ] {
                let (claim, nondeterminism) = claim_and_nondeterminism(
                    &program,
                    &prev_block,
                    &next_body,
                    &next_header,
                    &epochs(),
                );
                let profile = tasm_lib::generate_full_profile(
                    name,
                    program.program(),
                    &PublicInput::new(claim.input),
                    &nondeterminism,
                );
                println!("previous block size: {}\n{profile}", prev_block.size());
            }
        }

        #[test]
        fn witness_memory_size_agrees_with_block_size() {
            for prev_block in [
                random_unproven_block(0),
                unproven_prev_block_and_next_body_and_header(1).0,
                prev_block_of_size(500_000).0,
            ] {
                let (next_body, _) = next_body_and_header(&prev_block, 0);
                let witness = PredecessorIsValidWitness::new(
                    &prev_block,
                    &next_body,
                    transaction_mutator_set(&prev_block),
                );
                let memory = PredecessorIsValidWitnessMemory::from(&witness);
                assert_eq!(prev_block.size(), memory.prev_block_size());
            }
        }

        #[test]
        fn prev_block_at_max_size_passes() {
            let max_block_size = max_block_size();
            let (prev_block, next_body, next_header) = prev_block_of_size(max_block_size);
            assert_eq!(max_block_size, prev_block.size());

            assert_accepts(&skipping(), &prev_block, &next_body, &next_header);
        }

        /// The activation epoch's maximum block size.
        fn max_block_size() -> usize {
            usize::try_from(activation_epoch().max_block_size.value()).unwrap()
        }

        #[test]
        fn prev_block_size_is_bounded_by_epoch() {
            let transaction_kernel = transaction_kernel_and_proof().0.clone();
            let limits = |max_block_size| {
                EpochTable::new(&[Epoch {
                    max_block_size: bfe!(max_block_size),
                    ..activation_epoch()
                }])
            };

            let (prev_block, ..) =
                prev_block_with_transaction_kernel(transaction_kernel.clone(), &epochs());
            let size = u64::try_from(prev_block.size()).unwrap();

            let epochs = limits(size);
            let (prev_block, next_body, next_header) =
                prev_block_with_transaction_kernel(transaction_kernel.clone(), &epochs);
            assert_eq!(size, u64::try_from(prev_block.size()).unwrap());
            assert_accepts_with_epochs(&skipping(), &prev_block, &next_body, &next_header, &epochs);

            let epochs = limits(size - 1);
            let (prev_block, next_body, next_header) =
                prev_block_with_transaction_kernel(transaction_kernel, &epochs);
            assert_rejects_with_epochs(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                &epochs,
                BlockValidationRule::MaxSize.error_id(),
            );
        }

        #[test]
        fn transaction_claim_is_about_the_epochs_single_proof_program() {
            let transaction_kernel = transaction_kernel_and_proof().0.clone();
            let epochs = EpochTable::new(&[Epoch {
                single_proof_digest: Digest::default(),
                ..activation_epoch()
            }]);
            let (prev_block, next_body, next_header) =
                prev_block_with_transaction_kernel(transaction_kernel, &epochs);
            assert_rejects_with_epochs(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                &epochs,
                BlockValidationRule::AppendixMissingClaim.error_id(),
            );
        }

        #[test]
        fn swbf_update_claim_is_about_the_right_aggregation_program() {
            let transaction_kernel = transaction_kernel_and_proof().0.clone();
            let epochs = EpochTable::new(&[Epoch {
                swbf_aggregation_digest: Digest::default(),
                ..activation_epoch()
            }]);
            let (prev_block, next_body, next_header) =
                prev_block_with_transaction_kernel(transaction_kernel, &epochs);
            assert_rejects_with_epochs(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                &epochs,
                BlockValidationRule::AppendixMissingClaim.error_id(),
            );
        }

        #[test]
        fn prev_block_above_max_size_fails() {
            let max_block_size = max_block_size();
            let (prev_block, next_body, next_header) = prev_block_of_size(max_block_size + 1);

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::MaxSize.error_id(),
            );
        }

        #[test]
        fn prev_block_with_too_many_claims_fails() {
            let mut rng = StdRng::seed_from_u64(0);
            let prev_prev_block = random_unproven_block(0);
            let (body, header) = next_body_and_header(&prev_prev_block, 0);
            let claims = (0..=MAX_NUM_CLAIMS)
                .map(|_| Claim::new(rng.random()))
                .collect();
            let prev_block = block(
                header,
                body,
                BlockAppendix::new(claims),
                BlockProof::Invalid,
            );
            let (next_body, next_header) = next_body_and_header(&prev_block, 0);

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::AppendixTooLarge.error_id(),
            );
        }

        #[test]
        fn prev_block_without_single_proof_fails() {
            let (prev_block, next_body, next_header) =
                unproven_prev_block_and_next_body_and_header(0);

            assert_rejects(
                &PredecessorIsValid::new(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::ProofQuality.error_id(),
            );
        }

        /// A genesis parent, unmined and without claims or proof, passes
        /// no rule but the named hash.
        #[test]
        fn genesis_parent_passes_by_the_named_hash_alone() {
            let kernel = TransactionKernelModifier::default()
                .inputs(vec![])
                .outputs(vec![])
                .modify(transaction_kernel_and_proof().0.clone());
            let next = |genesis: &Block| {
                let mutator_set = &genesis.body().mutator_set_accumulator;
                next_body_and_header_with_transaction(genesis, 0, &kernel, mutator_set)
            };
            let genesis = fixture_genesis();
            let (next_body, next_header) = next(&genesis);
            for program in [PredecessorIsValid::new(), skipping()] {
                assert_accepts(&program, &genesis, &next_body, &next_header);
            }

            let other_genesis = Block::genesis(Network::TestnetMock);
            let (next_body, next_header) = next(&other_genesis);
            for program in [PredecessorIsValid::new(), skipping()] {
                assert_rejects(
                    &program,
                    &other_genesis,
                    &next_body,
                    &next_header,
                    BlockValidationRule::GenesisHash.error_id(),
                );
            }
        }

        #[test]
        fn prev_block_with_tampered_proof_fails() {
            let (mut prev_block, next_body, next_header) =
                unproven_prev_block_and_next_body_and_header(0);
            prev_block.set_proof(BlockProof::Genesis);

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::BlockMmrUpdate.error_id(),
            );
        }

        #[test]
        fn prev_block_height_not_one_less_than_next_block_height_fails() {
            let (prev_block, next_body, next_header) =
                unproven_prev_block_and_next_body_and_header(0);
            let mut prev_block_header = *prev_block.header();
            prev_block_header.height = prev_block_header.height.next();
            let prev_block = Block::new(
                prev_block_header,
                prev_block.body().clone(),
                prev_block.appendix().clone(),
                BlockProof::Invalid,
            );

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::BlockHeight.error_id(),
            );
        }

        #[test]
        fn next_block_mmr_with_wrong_leaf_count_fails() {
            let (prev_block, next_body, next_header) =
                unproven_prev_block_and_next_body_and_header(0);
            let next_body = BlockBody::new(
                next_body.transaction_kernel.clone(),
                next_body.mutator_set_accumulator.clone(),
                next_body.lock_free_mmr_accumulator.clone(),
                block_mmra_with_num_leafs(
                    next_body.block_mmr_accumulator.num_leafs() + 1,
                    next_body.block_mmr_accumulator.peaks(),
                ),
            );

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::BlockHeight.error_id(),
            );
        }

        /// An unproven previous block with the given timestamp, on top of a
        /// random block, and a next body and header for it.
        fn prev_block_with_timestamp(
            prev_prev_block: &Block,
            timestamp: Timestamp,
            epochs: &EpochTable,
        ) -> (Block, BlockBody, BlockHeader) {
            let (body, mut header) = next_body_and_header(prev_prev_block, 0);
            header.timestamp = timestamp;
            set_difficulty_fields(&mut header, prev_prev_block);
            // The shared transaction, dated to the block and built on the
            // block's predecessor, whatever its height and timestamp.
            let transaction_kernel = TransactionKernelModifier::default()
                .timestamp(timestamp)
                .mutator_set_hash(mutator_set_hash_after(prev_prev_block))
                .modify(body.transaction_kernel.clone());
            let body = BlockBody::new(
                transaction_kernel,
                body.mutator_set_accumulator.clone(),
                body.lock_free_mmr_accumulator.clone(),
                body.block_mmr_accumulator.clone(),
            );
            let body = body_with_mutator_set_after_transaction(prev_prev_block, body);
            let prev_block =
                unproven_block_with_own_claim_with_epochs(prev_prev_block, body, header, 0, epochs);
            let (next_body, next_header) = next_body_and_header(&prev_block, 0);

            (prev_block, next_body, next_header)
        }

        #[test]
        fn prev_block_exactly_minimum_block_time_after_its_predecessor_passes() {
            let prev_prev_block = random_unproven_block(0);
            let timestamp = prev_prev_block.header().timestamp + minimum_block_time();
            let (prev_block, next_body, next_header) =
                prev_block_with_timestamp(&prev_prev_block, timestamp, &epochs());

            assert_accepts(&skipping(), &prev_block, &next_body, &next_header);
        }

        #[test]
        fn prev_block_less_than_minimum_block_time_after_its_predecessor_fails() {
            let prev_prev_block = random_unproven_block(0);
            let prev_prev_block_timestamp = prev_prev_block.header().timestamp;
            for timestamp in [
                prev_prev_block_timestamp + minimum_block_time() - Timestamp::millis(1),
                prev_prev_block_timestamp,
                prev_prev_block_timestamp - Timestamp::millis(1),
                Timestamp::zero(),
            ] {
                let (prev_block, next_body, next_header) =
                    prev_block_with_timestamp(&prev_prev_block, timestamp, &epochs());

                assert_rejects(
                    &skipping(),
                    &prev_block,
                    &next_body,
                    &next_header,
                    BlockValidationRule::MinimumBlockTime.error_id(),
                );
            }
        }

        /// `Block::validate` rejects when `prev + minimum > next`; the program
        /// rejects when `next < prev + minimum`. Check that they agree at the
        /// boundary.
        #[test]
        fn rule_0d_agrees_with_block_validate_at_the_boundary() {
            let prev_prev_block = random_unproven_block(0);
            let earliest_prev_block_timestamp =
                prev_prev_block.header().timestamp + minimum_block_time();
            let start = earliest_prev_block_timestamp - Timestamp::millis(2);
            for offset_millis in 0..5 {
                let timestamp = start + Timestamp::millis(offset_millis);
                let too_early = offset_millis < 2;
                let (prev_block, next_body, next_header) =
                    prev_block_with_timestamp(&prev_prev_block, timestamp, &epochs());

                let host_rejects_on_0d = tokio_runtime().block_on(prev_block.validate(
                    &prev_prev_block,
                    Timestamp::now(),
                    Network::Main,
                )) == Err(BlockValidationError::MinimumBlockTime);

                let (claim, nondeterminism) = claim_and_nondeterminism(
                    &skipping(),
                    &prev_block,
                    &next_body,
                    &next_header,
                    &epochs(),
                );
                let program_rejects_on_0d = skipping()
                    .test_assertion_failure(
                        PublicInput::new(claim.input),
                        nondeterminism,
                        &[BlockValidationRule::MinimumBlockTime.error_id()],
                    )
                    .is_ok();

                assert_eq!(too_early, host_rejects_on_0d, "offset {offset_millis} ms");
                assert_eq!(
                    too_early, program_rejects_on_0d,
                    "offset {offset_millis} ms"
                );
            }
        }

        #[test]
        fn prev_block_whose_header_points_to_another_block_fails() {
            let prev_prev_block = random_unproven_block(0);
            let (body, mut header) = next_body_and_header(&prev_prev_block, 0);
            let own_claim = own_claim(&skipping(), &prev_prev_block, &body, &header);
            header.prev_block_digest = StdRng::seed_from_u64(0).random();
            let prev_block = unproven_block(header, body, vec![own_claim]);
            let (next_body, next_header) = next_body_and_header(&prev_block, 0);

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::PrevBlockDigest.error_id(),
            );
        }

        #[test]
        fn prev_block_with_wrong_difficulty_fails() {
            let prev_prev_block = random_unproven_block(0);
            let (body, mut header) = next_body_and_header(&prev_prev_block, 0);
            header.difficulty =
                Difficulty::from_biguint(BigUint::from(header.difficulty) + 1u32).unwrap();
            let prev_block = unproven_block_with_own_claim(&prev_prev_block, body, header, 0);
            let (next_body, next_header) = next_body_and_header(&prev_block, 0);

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::Difficulty.error_id(),
            );
        }

        #[test]
        fn prev_block_with_wrong_cumulative_proof_of_work_fails() {
            let prev_prev_block = random_unproven_block(0);
            let (body, mut header) = next_body_and_header(&prev_prev_block, 0);
            header.cumulative_proof_of_work = header.cumulative_proof_of_work + Difficulty::MINIMUM;
            let prev_block = unproven_block_with_own_claim(&prev_prev_block, body, header, 0);
            let (next_body, next_header) = next_body_and_header(&prev_block, 0);

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::CumulativeProofOfWork.error_id(),
            );
        }

        /// A claim of this program about some other block says nothing about
        /// this chain, even if it sits first in the appendix.
        #[test]
        fn decoy_claim_of_this_program_about_another_block_is_ignored() {
            let prev_prev_block = random_unproven_block(0);
            let (body, header) = next_body_and_header(&prev_prev_block, 0);

            // The decoy is about a block far in the future, so believing it would
            // violate rule 0.d.
            let (decoy_prev_header, decoy_prev_body) = random_header_and_body(
                1,
                height_below_activation(),
                header.timestamp + Timestamp::days(1),
            );
            let decoy_prev_block = unproven_block(decoy_prev_header, decoy_prev_body, vec![]);
            let (decoy_body, decoy_header) = next_body_and_header(&decoy_prev_block, 1);
            let decoy = own_claim(&skipping(), &decoy_prev_block, &decoy_body, &decoy_header);

            let own_claim = own_claim(&skipping(), &prev_prev_block, &body, &header);
            let prev_block = unproven_block(header, body, vec![decoy, own_claim]);
            let (next_body, next_header) = next_body_and_header(&prev_block, 0);

            assert_accepts(&skipping(), &prev_block, &next_body, &next_header);
        }

        /// An epoch starting right after activation, with this minimum block time.
        fn epoch_after_activation(minimum_block_time: Timestamp) -> Epoch {
            Epoch {
                height: activation_height().next().into(),
                minimum_block_time,
                ..activation_epoch()
            }
        }

        /// The previous block at the height after activation, its timestamp this
        /// long after its predecessor's, with its own claim under these epochs,
        /// and a next body and header for it.
        fn prev_block_after_activation(
            block_time: Timestamp,
            epochs: &EpochTable,
        ) -> (Block, BlockBody, BlockHeader) {
            let prev_prev_block = random_unproven_block_at_height(0, activation_height().value());
            let timestamp = prev_prev_block.header().timestamp + block_time;
            prev_block_with_timestamp(&prev_prev_block, timestamp, epochs)
        }

        #[test]
        fn epochs_may_be_appended_after_the_prev_block() {
            let (prev_block, next_body, next_header) =
                unproven_prev_block_and_next_body_and_header(0);
            let future_epoch = Epoch {
                height: prev_block.header().height.next().into(),
                ..activation_epoch()
            };
            let with_future_epoch = EpochTable::new(&[activation_epoch(), future_epoch]);
            assert_accepts_with_epochs(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                &with_future_epoch,
            );
        }

        #[test]
        fn prev_block_claiming_an_unknown_epoch_fails() {
            let prev_prev_block = random_unproven_block(0);
            let (body, header) = next_body_and_header(&prev_prev_block, 0);
            let unknown_epoch = Epoch {
                height: header.height.next().into(),
                ..activation_epoch()
            };
            let with_unknown_epoch = EpochTable::new(&[activation_epoch(), unknown_epoch]);
            let prev_block = unproven_block_with_own_claim_with_epochs(
                &prev_prev_block,
                body,
                header,
                0,
                &with_unknown_epoch,
            );
            let (next_body, next_header) = next_body_and_header(&prev_block, 0);

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::AppendixMissingClaim.error_id(),
            );
        }

        #[test]
        fn revised_epoch_at_the_same_height_takes_precedence() {
            let doubled_minimum_block_time =
                Timestamp::millis(2 * minimum_block_time().to_millis());
            let epochs_with_revision = EpochTable::new(&[
                activation_epoch(),
                epoch_after_activation(doubled_minimum_block_time),
                epoch_after_activation(minimum_block_time()),
            ]);

            let (prev_block, next_body, next_header) =
                prev_block_after_activation(minimum_block_time(), &epochs_with_revision);
            assert_accepts_with_epochs(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                &epochs_with_revision,
            );
        }

        #[test]
        fn epoch_started_by_prev_block_must_be_in_its_own_claim() {
            let epochs_with_second = EpochTable::new(&[
                activation_epoch(),
                epoch_after_activation(minimum_block_time()),
            ]);

            let (prev_block, next_body, next_header) =
                prev_block_after_activation(minimum_block_time(), &epochs_with_second);
            assert_accepts_with_epochs(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                &epochs_with_second,
            );

            let (prev_block, next_body, next_header) =
                prev_block_after_activation(minimum_block_time(), &epochs());
            assert_rejects_with_epochs(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                &epochs_with_second,
                BlockValidationRule::AppendixMissingClaim.error_id(),
            );
        }

        /// Like [block], but solving the proof of work by nonce search, for
        /// bodies the guessing puzzle rejects, such as one with a negative fee.
        fn block_solved_by_nonce_search(
            header: BlockHeader,
            body: BlockBody,
            appendix: BlockAppendix,
            proof: BlockProof,
        ) -> Block {
            let mut rng = StdRng::seed_from_u64(0);
            let mut block = Block::new(header, body, appendix, proof);
            let mut pow = block.header().pow;
            pow.set_version_in_pow(block.header().version);
            loop {
                pow.nonce = rng.random();
                block.set_header_pow(pow);
                if block.hash() <= Difficulty::MINIMUM.target() {
                    return block;
                }
            }
        }

        /// The previous block with this transaction kernel and its own claim
        /// under these epochs, and a next body and header for it.
        fn prev_block_with_transaction_kernel(
            transaction_kernel: TransactionKernel,
            epochs: &EpochTable,
        ) -> (Block, BlockBody, BlockHeader) {
            prev_block_with_transaction_kernel_at_height(
                transaction_kernel,
                epochs,
                activation_height().value(),
            )
        }

        /// As [prev_block_with_transaction_kernel], at this height.
        fn prev_block_with_transaction_kernel_at_height(
            transaction_kernel: TransactionKernel,
            epochs: &EpochTable,
            height: u64,
        ) -> (Block, BlockBody, BlockHeader) {
            let prev_prev_block = random_unproven_block_at_height(0, height - 1);
            let transaction_kernel = TransactionKernelModifier::default()
                .mutator_set_hash(mutator_set_hash_after(&prev_prev_block))
                .modify(transaction_kernel);
            prev_block_on(&prev_prev_block, transaction_kernel, epochs)
        }

        /// A successor of the block with this transaction kernel, carrying
        /// the transaction claim and the skipping program's claim, and a next
        /// body and header for it.
        fn prev_block_on(
            prev_prev_block: &Block,
            transaction_kernel: TransactionKernel,
            epochs: &EpochTable,
        ) -> (Block, BlockBody, BlockHeader) {
            let (body, _) = next_body_and_header(prev_prev_block, 0);
            let body = BlockBody::new(
                transaction_kernel,
                body.mutator_set_accumulator.clone(),
                body.lock_free_mmr_accumulator.clone(),
                body.block_mmr_accumulator.clone(),
            );
            let body = body_with_mutator_set_after_transaction(prev_prev_block, body);
            prev_block_with_body(prev_prev_block, body, epochs)
        }

        /// The previous block with this body and its own claim under these
        /// epochs, and a next body and header for it.
        fn prev_block_with_body(
            prev_prev_block: &Block,
            body: BlockBody,
            epochs: &EpochTable,
        ) -> (Block, BlockBody, BlockHeader) {
            let (_, header) = next_body_and_header(prev_prev_block, 0);
            let transaction_claim = single_proof_claim(
                body.transaction_kernel.mast_hash(),
                ConsensusRuleSet::HardforkDelta,
            );
            let own_claim =
                own_claim_with_epochs(&skipping(), prev_prev_block, &body, &header, epochs);
            let swbf_claim = swbf_update_claim(&header, &body);
            let claims = [
                vec![transaction_claim],
                swbf_claim.into_iter().collect(),
                vec![own_claim],
                main_host_claims(&header, &body),
            ]
            .concat();
            let prev_block = block_solved_by_nonce_search(
                header,
                body,
                BlockAppendix::new(claims),
                BlockProof::Invalid,
            );
            let (next_body, next_header) = next_body_and_header(&prev_block, 0);

            (prev_block, next_body, next_header)
        }

        mod mutator_set_reveals {
            use neptune_mutator_set::addition_record::AdditionRecord;
            use neptune_mutator_set::shared::BATCH_SIZE;

            use super::*;
            use crate::block::validity::knows_mutator_set::tests::ArchivalSwbfi;
            use crate::block::validity::swbfi_reveal::guesser_node_index;

            fn epochs_requiring_mutator_set_reveals() -> EpochTable {
                EpochTable::new(&[Epoch {
                    requires_mutator_set_reveals: bfe!(1),
                    ..activation_epoch()
                }])
            }

            /// A mutator set whose inactive SWBF this is, with an AOCL that
            /// one block's output and guesser fee records do not slide the
            /// window past.
            fn mutator_set_with_swbfi(
                rng: &mut StdRng,
                swbfi: &ArchivalSwbfi,
            ) -> MutatorSetAccumulator {
                let num_aocl_leafs = u64::from(BATCH_SIZE) * swbfi.num_leafs() + 1;
                let aocl_leafs = (0..num_aocl_leafs).map(|_| rng.random()).collect();
                MutatorSetAccumulator {
                    aocl: MmrAccumulator::new_from_leafs(aocl_leafs),
                    swbf_inactive: swbfi.accumulator(),
                    ..Default::default()
                }
            }

            /// The leaf this header's guesser must reveal and its path.
            fn reveal(header: &BlockHeader, swbfi: &ArchivalSwbfi) -> (u64, Digest, Vec<Digest>) {
                let (index, _) = guesser_node_index(
                    header.prev_block_digest,
                    &header.guesser_receiver_data,
                    swbfi.num_leafs(),
                )
                .unwrap();
                (index, Tip5::hash(swbfi.chunk(index)), swbfi.path(index))
            }

            fn revealing(
                swbfi: &ArchivalSwbfi,
            ) -> impl FnOnce(&BlockBody, BlockHeader) -> BlockHeader + '_ {
                move |_, mut header| {
                    let (_, leaf, path) = reveal(&header, swbfi);
                    header.pow.set_swbfi_reveal(leaf, &path);
                    header
                }
            }

            /// The mutator set after this header's parent, which the block's
            /// transaction is built on.
            fn parent_mutator_set(header: &BlockHeader) -> MutatorSetAccumulator {
                predecessor_by_hash(header.prev_block_digest)
                    .unwrap()
                    .mutator_set_accumulator_after()
                    .unwrap()
            }

            /// A previous block at the activation height on a parent whose
            /// inactive SWBF this is, carrying a transaction with one output
            /// and no inputs with its claims and the skipping program's
            /// claim, with its header edited given its body and header, and
            /// a next body and header for it.
            fn prev_block_with_swbfi(
                swbfi: &ArchivalSwbfi,
                epochs: &EpochTable,
                edit_header: impl FnOnce(&BlockBody, BlockHeader) -> BlockHeader,
            ) -> (Block, BlockBody, BlockHeader) {
                let mut rng = StdRng::seed_from_u64(0);
                let height = activation_height().value() - 1;
                let (header, body) = random_header_and_body(0, height, random_timestamp(0));
                let body = body_with_mutator_set(body, mutator_set_with_swbfi(&mut rng, swbfi));
                let prev_prev_block = unproven_block(header, body, vec![]);
                let kernel = TransactionKernelModifier::default()
                    .inputs(vec![])
                    .outputs(vec![AdditionRecord::new(rng.random())])
                    .mutator_set_hash(mutator_set_hash_after(&prev_prev_block))
                    .modify(transaction_kernel_and_proof().0.clone());
                let mutator_set = &prev_prev_block.body().mutator_set_accumulator;
                let (body, header) = next_body_and_header_with_transaction(
                    &prev_prev_block,
                    0,
                    &kernel,
                    mutator_set,
                );
                let header = edit_header(&body, header);
                let transaction_claim =
                    single_proof_claim(kernel.mast_hash(), ConsensusRuleSet::HardforkDelta);
                let own_claim =
                    own_claim_with_epochs(&skipping(), &prev_prev_block, &body, &header, epochs);
                let claims = [
                    vec![transaction_claim],
                    swbf_update_claim(&header, &body).into_iter().collect(),
                    vec![own_claim],
                ]
                .concat();
                let prev_block = block_solved_by_nonce_search(
                    header,
                    body,
                    BlockAppendix::new(claims),
                    BlockProof::Invalid,
                );
                let (next_body, next_header) =
                    next_body_and_header_with_transaction(&prev_block, 0, &kernel, mutator_set);
                (prev_block, next_body, next_header)
            }

            #[test]
            fn prev_block_revealing_its_swbfi_is_accepted() {
                let mut rng = StdRng::seed_from_u64(1);
                let epochs = epochs_requiring_mutator_set_reveals();
                for num_leafs in [1, 2, 3, 35, 64] {
                    let swbfi = ArchivalSwbfi::random(&mut rng, num_leafs);
                    let (prev_block, next_body, next_header) =
                        prev_block_with_swbfi(&swbfi, &epochs, revealing(&swbfi));
                    let parent_mutator_set = parent_mutator_set(prev_block.header());
                    assert_eq!(
                        swbfi.accumulator().peaks(),
                        parent_mutator_set.swbf_inactive.peaks()
                    );
                    assert_ne!(
                        parent_mutator_set.hash(),
                        prev_block.body().mutator_set_accumulator.hash()
                    );
                    assert_accepts_with_epochs(
                        &skipping(),
                        &prev_block,
                        &next_body,
                        &next_header,
                        &epochs,
                    );
                }
            }

            #[test]
            fn empty_swbfi_needs_no_guesser_reveal() {
                let mut rng = StdRng::seed_from_u64(2);
                let epochs = epochs_requiring_mutator_set_reveals();
                let swbfi = ArchivalSwbfi::random(&mut rng, 0);
                let (prev_block, next_body, next_header) =
                    prev_block_with_swbfi(&swbfi, &epochs, |_, header| header);
                assert_accepts_with_epochs(
                    &skipping(),
                    &prev_block,
                    &next_body,
                    &next_header,
                    &epochs,
                );
            }

            #[test]
            fn prev_block_without_guesser_reveal_fails() {
                let mut rng = StdRng::seed_from_u64(3);
                let epochs = epochs_requiring_mutator_set_reveals();
                let swbfi = ArchivalSwbfi::random(&mut rng, 35);
                let (prev_block, next_body, next_header) =
                    prev_block_with_swbfi(&swbfi, &epochs, |_, header| header);
                assert_rejects_with_epochs(
                    &skipping(),
                    &prev_block,
                    &next_body,
                    &next_header,
                    &epochs,
                    BlockValidationRule::GuesserSwbfiReveal.error_id(),
                );
            }

            #[test]
            fn guesser_reveal_of_another_leaf_fails() {
                let mut rng = StdRng::seed_from_u64(4);
                let epochs = epochs_requiring_mutator_set_reveals();
                let swbfi = ArchivalSwbfi::random(&mut rng, 35);
                let revealing_neighbour = |_: &BlockBody, mut header: BlockHeader| {
                    let (index, _, _) = reveal(&header, &swbfi);
                    let neighbour = index ^ 1;
                    let leaf = Tip5::hash(swbfi.chunk(neighbour));
                    header.pow.set_swbfi_reveal(leaf, &swbfi.path(neighbour));
                    header
                };
                let (prev_block, next_body, next_header) =
                    prev_block_with_swbfi(&swbfi, &epochs, revealing_neighbour);
                assert_rejects_with_epochs(
                    &skipping(),
                    &prev_block,
                    &next_body,
                    &next_header,
                    &epochs,
                    BlockValidationRule::GuesserSwbfiReveal.error_id(),
                );
            }

            #[test]
            fn epoch_without_reveals_requires_none() {
                let mut rng = StdRng::seed_from_u64(7);
                let swbfi = ArchivalSwbfi::random(&mut rng, 35);
                let (prev_block, next_body, next_header) =
                    prev_block_with_swbfi(&swbfi, &epochs(), |_, header| header);
                assert_accepts(&skipping(), &prev_block, &next_body, &next_header);
                let (prev_block, next_body, next_header) = prev_block_with_swbfi(
                    &swbfi,
                    &epochs_requiring_mutator_set_reveals(),
                    |_, header| header,
                );
                assert_rejects_with_epochs(
                    &skipping(),
                    &prev_block,
                    &next_body,
                    &next_header,
                    &epochs_requiring_mutator_set_reveals(),
                    BlockValidationRule::GuesserSwbfiReveal.error_id(),
                );
            }
        }

        /// The epoch table whose activation epoch allows this many outputs
        /// and announcements.
        fn epochs_with_limits(max_num_outputs: u64, max_num_announcements: u64) -> EpochTable {
            EpochTable::new(&[Epoch {
                max_num_outputs: bfe!(max_num_outputs),
                max_num_announcements: bfe!(max_num_announcements),
                ..activation_epoch()
            }])
        }

        /// The previous block at this height with this coinbase, and a next
        /// body and header for it.
        fn prev_block_with_coinbase_at_height(
            coinbase: Option<NativeCurrencyAmount>,
            height: u64,
        ) -> (Block, BlockBody, BlockHeader) {
            let transaction_kernel = TransactionKernelModifier::default()
                .coinbase(coinbase)
                .modify(transaction_kernel_and_proof().0.clone());
            prev_block_with_transaction_kernel_at_height(transaction_kernel, &epochs(), height)
        }

        #[test]
        fn prev_block_with_coinbase_up_to_its_subsidy_passes() {
            let heights = [
                activation_height().value(),
                BLOCKS_PER_GENERATION,
                4 * BLOCKS_PER_GENERATION,
                (1 << 32) + 7,
            ];
            let subsidies = heights.map(|height| Block::block_subsidy(height.into()));
            assert!(subsidies[0] > subsidies[1]);
            assert!(subsidies[1] > subsidies[2]);
            assert!(subsidies[3].is_zero());

            for (height, subsidy) in heights.into_iter().zip(subsidies) {
                for coinbase in [None, Some(subsidy)] {
                    let (prev_block, next_body, next_header) =
                        prev_block_with_coinbase_at_height(coinbase, height);
                    assert_accepts(&skipping(), &prev_block, &next_body, &next_header);
                }

                for excess in [
                    NativeCurrencyAmount::one_nau(),
                    NativeCurrencyAmount::coins(1),
                ] {
                    let (prev_block, next_body, next_header) =
                        prev_block_with_coinbase_at_height(Some(subsidy + excess), height);
                    assert_rejects(
                        &skipping(),
                        &prev_block,
                        &next_body,
                        &next_header,
                        BlockValidationRule::CoinbaseTooBig.error_id(),
                    );
                }
            }
        }

        #[test]
        fn prev_block_with_negative_coinbase_fails() {
            let transaction_kernel = TransactionKernelModifier::default()
                .coinbase(Some(-NativeCurrencyAmount::coins(1)))
                .modify(transaction_kernel_and_proof().0.clone());
            let (prev_block, next_body, next_header) =
                prev_block_with_transaction_kernel(transaction_kernel, &epochs());

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::NegativeCoinbase.error_id(),
            );
        }

        /// The previous block on the shared grandparent, carrying this SWBF
        /// update claim in place of the one its transaction calls for.
        fn prev_block_with_swbf_claim(
            swbf_claim: Option<Claim>,
        ) -> (Block, BlockBody, BlockHeader) {
            prev_block_with_swbf_claim_under(swbf_claim, &epochs())
        }

        /// As [prev_block_with_swbf_claim], with its own claim under these
        /// epochs.
        fn prev_block_with_swbf_claim_under(
            swbf_claim: Option<Claim>,
            epochs: &EpochTable,
        ) -> (Block, BlockBody, BlockHeader) {
            let grandparent = fixture_grandparent();
            let (body, header) = next_body_and_header(&grandparent, 0);
            let own_claim =
                own_claim_with_epochs(&skipping(), &grandparent, &body, &header, epochs);
            let prev_block =
                unproven_block_with_swbf_claim(header, body, vec![own_claim], swbf_claim);
            let (next_body, next_header) = next_body_and_header(&prev_block, 0);

            (prev_block, next_body, next_header)
        }

        /// The aggregated SWBF update claim the shared transaction calls for
        /// on the shared grandparent, over leaf proofs of these padded
        /// heights.
        fn fixture_swbf_claim_over(log2_padded_heights: [u32; 2]) -> Claim {
            let (kernel, _) = transaction_kernel_and_proof();
            let mutator_set = fixture_grandparent()
                .mutator_set_accumulator_after()
                .unwrap();
            claim_over_halves(&kernel.inputs, &mutator_set, log2_padded_heights)
        }

        /// As [fixture_swbf_claim_over], with leaf proofs that reach the
        /// fixture epoch's floor exactly.
        fn fixture_swbf_claim() -> Claim {
            fixture_swbf_claim_over([FIXTURE_LEAF_LOG2_PADDED_HEIGHT; 2])
        }

        #[test]
        fn prev_block_with_its_swbf_claim_passes() {
            let (prev_block, next_body, next_header) =
                prev_block_with_swbf_claim(Some(fixture_swbf_claim()));
            assert_accepts(&skipping(), &prev_block, &next_body, &next_header);
        }

        #[test]
        fn prev_block_with_swbf_leaf_proofs_above_the_floor_passes() {
            let claim = fixture_swbf_claim_over([FIXTURE_LEAF_LOG2_PADDED_HEIGHT + 1, 8]);
            let (prev_block, next_body, next_header) = prev_block_with_swbf_claim(Some(claim));
            assert_accepts(&skipping(), &prev_block, &next_body, &next_header);
        }

        #[test]
        fn prev_block_with_swbf_leaf_proofs_below_the_floor_fails() {
            let claim = fixture_swbf_claim_over([
                FIXTURE_LEAF_LOG2_PADDED_HEIGHT,
                FIXTURE_LEAF_LOG2_PADDED_HEIGHT - 1,
            ]);
            let (prev_block, next_body, next_header) = prev_block_with_swbf_claim(Some(claim));
            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::SwbfUpdateBelowWorkFloor.error_id(),
            );
        }

        #[test]
        fn epoch_without_a_floor_accepts_any_swbf_leaf_proofs() {
            let claim = fixture_swbf_claim_over([8, 8]);
            let (prev_block, next_body, next_header) =
                prev_block_with_swbf_claim(Some(claim.clone()));
            let without_floor = EpochTable::new(&[Epoch {
                min_swbf_padded_rows: bfe!(0),
                ..activation_epoch()
            }]);
            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::SwbfUpdateBelowWorkFloor.error_id(),
            );
            let (prev_block, next_body, next_header) =
                prev_block_with_swbf_claim_under(Some(claim), &without_floor);
            assert_accepts_with_epochs(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                &without_floor,
            );
        }

        #[test]
        fn prev_block_with_a_leaf_as_swbf_root_fails() {
            let (kernel, _) = transaction_kernel_and_proof();
            let mutator_set = fixture_grandparent()
                .mutator_set_accumulator_after()
                .unwrap();
            let claim = CorrectSwbfUpdate::claim(&kernel.inputs, &mutator_set);
            let (prev_block, next_body, next_header) = prev_block_with_swbf_claim(Some(claim));
            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::AppendixMissingClaim.error_id(),
            );
        }

        #[test]
        fn prev_block_without_swbf_claim_fails() {
            let (prev_block, next_body, next_header) = prev_block_with_swbf_claim(None);
            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::AppendixMissingClaim.error_id(),
            );
        }

        #[test]
        fn prev_block_with_swbf_claim_with_longer_input_fails() {
            let mut claim = fixture_swbf_claim();
            claim.input.push(bfe!(0));
            let (prev_block, next_body, next_header) = prev_block_with_swbf_claim(Some(claim));
            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::AppendixMissingClaim.error_id(),
            );
        }

        #[test]
        fn prev_block_with_swbf_claim_of_other_version_fails() {
            let mut claim = fixture_swbf_claim();
            claim.version += 1;
            let (prev_block, next_body, next_header) = prev_block_with_swbf_claim(Some(claim));
            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::AppendixMissingClaim.error_id(),
            );
        }

        #[test]
        fn prev_block_whose_own_claim_has_other_version_fails() {
            let prev_prev_block = random_unproven_block(0);
            let (body, header) = next_body_and_header(&prev_prev_block, 0);
            let mut own_claim = own_claim(&skipping(), &prev_prev_block, &body, &header);
            own_claim.version += 1;
            let prev_block = unproven_block(header, body, vec![own_claim]);
            let (next_body, next_header) = next_body_and_header(&prev_block, 0);

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::AppendixMissingClaim.error_id(),
            );
        }

        #[test]
        fn prev_block_with_swbf_claim_not_starting_at_the_first_leaf_fails() {
            let mut claim = fixture_swbf_claim();
            claim.input[INPUT_FIRST_LEAF_INDEX] += bfe!(1);
            let (prev_block, next_body, next_header) = prev_block_with_swbf_claim(Some(claim));
            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::AppendixMissingClaim.error_id(),
            );
        }

        #[test]
        fn prev_block_with_swbf_claim_on_other_mutator_set_fails() {
            let mut claim = fixture_swbf_claim();
            claim.input[0] += bfe!(1);
            let (prev_block, next_body, next_header) = prev_block_with_swbf_claim(Some(claim));
            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::AppendixMissingClaim.error_id(),
            );
        }

        #[test]
        fn prev_block_with_swbf_claim_outputting_other_state_fails() {
            let mut claim = fixture_swbf_claim();
            claim.output[OUTPUT_MUTATOR_SET_HASH] += bfe!(1);
            let (prev_block, next_body, next_header) = prev_block_with_swbf_claim(Some(claim));
            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::MutatorSetUpdateIntegrity.error_id(),
            );
        }

        #[test]
        fn prev_block_with_swbf_claim_with_other_peaks_fails() {
            let mut claim = fixture_swbf_claim();
            claim.output[OUTPUT_PEAKS] += bfe!(1);
            let (prev_block, next_body, next_header) = prev_block_with_swbf_claim(Some(claim));
            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::RemovalIndexCommitmentMismatch.error_id(),
            );
        }

        #[test]
        fn prev_block_with_swbf_claim_counting_other_index_sets_fails() {
            let mut claim = fixture_swbf_claim();
            claim.output[OUTPUT_COUNT] += bfe!(1);
            let (prev_block, next_body, next_header) = prev_block_with_swbf_claim(Some(claim));
            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::RemovalIndexCommitmentMismatch.error_id(),
            );
        }

        #[test]
        fn prev_block_with_malformed_swbf_claim_output_fails() {
            let mut claim = fixture_swbf_claim();
            claim.output.push(bfe!(0));
            let (prev_block, next_body, next_header) = prev_block_with_swbf_claim(Some(claim));
            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::MutatorSetUpdateIntegrity.error_id(),
            );
        }

        #[test]
        fn prev_block_with_body_swbfi_with_other_peaks_fails() {
            let mut mutator_set = fixture_mutator_set_after_transaction();
            let mut peaks = mutator_set.swbf_inactive.peaks();
            peaks[0] = StdRng::seed_from_u64(0).random();
            mutator_set.swbf_inactive =
                MmrAccumulator::init(peaks, mutator_set.swbf_inactive.num_leafs());
            assert_body_mutator_set_rejected(mutator_set);
        }

        /// The shared transaction's mutator set after the fixture grandparent,
        /// as the previous block's body must carry it.
        fn fixture_mutator_set_after_transaction() -> MutatorSetAccumulator {
            let (kernel, _) = transaction_kernel_and_proof();
            mutator_set_after_transaction(&fixture_grandparent(), kernel)
                .expect("the shared transaction applies after the fixture grandparent")
        }

        fn assert_body_mutator_set_rejected(mutator_set: MutatorSetAccumulator) {
            let grandparent = fixture_grandparent();
            let (body, _) = next_body_and_header(&grandparent, 0);
            let body = body_with_mutator_set(body, mutator_set);
            let (prev_block, next_body, next_header) =
                prev_block_with_body(&grandparent, body, &epochs());

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::MutatorSetUpdateIntegrity.error_id(),
            );
        }

        #[test]
        fn fixture_transaction_adds_to_the_aocl() {
            let before = fixture_grandparent()
                .mutator_set_accumulator_after()
                .unwrap();
            let after = fixture_mutator_set_after_transaction();
            assert!(after.aocl.num_leafs() > before.aocl.num_leafs());
            assert_ne!(after.aocl.peaks(), before.aocl.peaks());
        }

        /// The shared transaction's inputs with a record whose indices all
        /// lie in the active window and are unset there. It spends nothing
        /// real; the skipping program does not check the transaction's
        /// proof.
        fn inputs_with_record_in_the_window() -> Vec<RemovalRecord> {
            let (kernel, _) = transaction_kernel_and_proof();
            let mutator_set = fixture_grandparent()
                .mutator_set_accumulator_after()
                .unwrap();
            let window_start =
                u128::from(mutator_set.swbf_inactive.num_leafs()) << CHUNK_SIZE.ilog2();
            let mut rng = StdRng::seed_from_u64(0);
            let indices = core::array::from_fn(|_| loop {
                let relative = rng.random_range(0..WINDOW_SIZE);
                if !mutator_set.swbf_active.contains(relative) {
                    return window_start + u128::from(relative);
                }
            });
            let record = RemovalRecord {
                absolute_indices: AbsoluteIndexSet::new(indices),
                target_chunks: ChunkDictionary::default(),
            };
            let mut inputs = RemovalRecordList::try_unpack(kernel.inputs.clone(), true).unwrap();
            inputs.push(record);
            RemovalRecordList::pack(inputs, true)
        }

        #[test]
        fn prev_block_with_input_in_the_window_passes_and_sets_its_indices() {
            let (kernel, _) = transaction_kernel_and_proof();
            let transaction_kernel = TransactionKernelModifier::default()
                .inputs(inputs_with_record_in_the_window())
                .modify(kernel.clone());
            let grandparent = fixture_grandparent();
            let before = grandparent.mutator_set_accumulator_after().unwrap();
            let after = mutator_set_after_transaction(&grandparent, &transaction_kernel).unwrap();
            assert_eq!(
                before.swbf_active.sbf.len() + NUM_TRIALS as usize,
                after.swbf_active.sbf.len(),
                "the record's indices must be set in the window"
            );

            let (prev_block, next_body, next_header) =
                prev_block_with_transaction_kernel(transaction_kernel.clone(), &epochs());
            assert_accepts(&skipping(), &prev_block, &next_body, &next_header);

            // With one of its indices left out of the body's window.
            let mut mutator_set = after;
            let index = transaction_kernel
                .inputs
                .last()
                .unwrap()
                .absolute_indices
                .to_array()[0];
            let window_start = u128::from(before.swbf_inactive.num_leafs()) << CHUNK_SIZE.ilog2();
            mutator_set
                .swbf_active
                .remove((index - window_start) as u32);
            let (body, _) = next_body_and_header(&grandparent, 0);
            let body = BlockBody::new(
                transaction_kernel,
                mutator_set,
                body.lock_free_mmr_accumulator.clone(),
                body.block_mmr_accumulator.clone(),
            );
            let (prev_block, next_body, next_header) =
                prev_block_with_body(&grandparent, body, &epochs());
            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::MutatorSetUpdateIntegrity.error_id(),
            );
        }

        #[test]
        fn prev_block_with_body_window_missing_an_index_fails() {
            let mut mutator_set = fixture_mutator_set_after_transaction();
            mutator_set.swbf_active.sbf.pop();
            assert_body_mutator_set_rejected(mutator_set);
        }

        #[test]
        fn prev_block_with_body_window_with_an_extra_index_fails() {
            let mut mutator_set = fixture_mutator_set_after_transaction();
            mutator_set.swbf_active.insert(12_345);
            assert_body_mutator_set_rejected(mutator_set);
        }

        #[test]
        fn prev_block_with_body_aocl_with_an_extra_leaf_fails() {
            let mut mutator_set = fixture_mutator_set_after_transaction();
            mutator_set.aocl.append(Digest::default());
            assert_body_mutator_set_rejected(mutator_set);
        }

        #[test]
        fn prev_block_with_body_aocl_with_other_peaks_fails() {
            let mut mutator_set = fixture_mutator_set_after_transaction();
            let leaf_count = mutator_set.aocl.num_leafs();
            let mut peaks = mutator_set.aocl.peaks();
            peaks[0] = Digest::default();
            mutator_set.aocl = MmrAccumulator::init(peaks, leaf_count);
            assert_body_mutator_set_rejected(mutator_set);
        }

        #[test]
        fn prev_block_with_body_swbfi_with_an_extra_leaf_fails() {
            // A leaf count that does not fit the peaks is caught when the
            // accumulator is hashed, so a leaf is appended instead.
            let mut mutator_set = fixture_mutator_set_after_transaction();
            mutator_set.swbf_inactive.append(Digest::default());
            assert_body_mutator_set_rejected(mutator_set);
        }

        #[test]
        fn prev_block_with_many_outputs_slides_the_window_and_passes() {
            let (kernel, _) = transaction_kernel_and_proof();
            let mut rng = StdRng::seed_from_u64(0);
            let outputs = (0..20)
                .map(|_| AdditionRecord::new(rng.random()))
                .collect::<Vec<_>>();
            let transaction_kernel = TransactionKernelModifier::default()
                .outputs(outputs)
                .modify(kernel.clone());
            let grandparent = fixture_grandparent();
            let before = grandparent.mutator_set_accumulator_after().unwrap();
            let after = mutator_set_after_transaction(&grandparent, &transaction_kernel).unwrap();
            assert!(
                after.swbf_inactive.num_leafs() > before.swbf_inactive.num_leafs(),
                "the outputs must slide the window"
            );

            let (prev_block, next_body, next_header) =
                prev_block_with_transaction_kernel(transaction_kernel, &epochs());
            assert_accepts(&skipping(), &prev_block, &next_body, &next_header);
        }

        #[test]
        fn prev_block_without_outputs_passes() {
            let (kernel, _) = transaction_kernel_and_proof();
            let transaction_kernel = TransactionKernelModifier::default()
                .outputs(vec![])
                .modify(kernel.clone());
            let (prev_block, next_body, next_header) =
                prev_block_with_transaction_kernel(transaction_kernel, &epochs());
            assert_accepts(&skipping(), &prev_block, &next_body, &next_header);
        }

        #[test]
        fn witness_with_other_mutator_set_fails() {
            let (prev_block, next_body, next_header) =
                unproven_prev_block_and_next_body_and_header(0);
            let program = skipping();
            let claim = own_claim(&program, &prev_block, &next_body, &next_header);
            let mut other_mutator_set = transaction_mutator_set(&prev_block);
            other_mutator_set.swbf_active.insert(1);
            let witness =
                PredecessorIsValidWitness::new(&prev_block, &next_body, other_mutator_set);

            program
                .test_assertion_failure(
                    PublicInput::new(claim.input),
                    witness.nondeterminism_under(&program, &epochs()),
                    &[BlockValidationRule::TransactionMutatorSetMismatch.error_id()],
                )
                .unwrap();
        }

        #[test]
        fn prev_block_with_transaction_on_other_mutator_set_fails() {
            let prev_prev_block =
                random_unproven_block_at_height(0, activation_height().value() - 1);
            let (kernel, _) = transaction_kernel_and_proof();
            let transaction_kernel = TransactionKernelModifier::default()
                .mutator_set_hash(StdRng::seed_from_u64(7).random())
                .modify(kernel.clone());
            let (prev_block, next_body, next_header) =
                prev_block_on(&prev_prev_block, transaction_kernel, &epochs());

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::TransactionMutatorSetMismatch.error_id(),
            );
        }

        #[test]
        fn claim_output_ends_with_mutator_set_after_prev_block() {
            let (prev_block, next_body, next_header) =
                unproven_prev_block_and_next_body_and_header(0);
            let claim = own_claim(&skipping(), &prev_block, &next_body, &next_header);
            let offset = PredecessorIsValid::output_mutator_set_offset();
            assert_eq!(offset + Digest::LEN, claim.output.len());
            assert_eq!(
                prev_block
                    .mutator_set_accumulator_after()
                    .unwrap()
                    .hash()
                    .values(),
                claim.output[offset..]
            );
        }

        #[test]
        fn prev_block_with_duplicate_input_fails() {
            let (kernel, _) = transaction_kernel_and_proof();
            let mut inputs = kernel.inputs.clone();
            inputs.push(inputs[0].clone());
            let transaction_kernel = TransactionKernelModifier::default()
                .inputs(inputs)
                .modify(kernel.clone());
            let (prev_block, next_body, next_header) =
                prev_block_with_transaction_kernel(transaction_kernel, &epochs());

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::RemovalRecordsUniqueness.error_id(),
            );
        }

        #[test]
        fn prev_block_without_coinbase_passes() {
            let transaction_kernel = TransactionKernelModifier::default()
                .coinbase(None)
                .modify(transaction_kernel_and_proof().0.clone());
            let (prev_block, next_body, next_header) =
                prev_block_with_transaction_kernel(transaction_kernel, &epochs());

            assert_accepts(&skipping(), &prev_block, &next_body, &next_header);
        }

        #[test]
        fn prev_block_with_negative_fee_fails() {
            let transaction_kernel = TransactionKernelModifier::default()
                .fee(-NativeCurrencyAmount::coins(1))
                .modify(transaction_kernel_and_proof().0.clone());
            let (prev_block, next_body, next_header) =
                prev_block_with_transaction_kernel(transaction_kernel, &epochs());

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::NegativeFee.error_id(),
            );
        }

        #[test]
        fn prev_block_with_large_fee_passes() {
            let transaction_kernel = TransactionKernelModifier::default()
                .fee(NativeCurrencyAmount::coins(1_000_000))
                .modify(transaction_kernel_and_proof().0.clone());
            let (prev_block, next_body, next_header) =
                prev_block_with_transaction_kernel(transaction_kernel, &epochs());

            assert_accepts(&skipping(), &prev_block, &next_body, &next_header);
        }

        /// The timestamp `prev_block_with_transaction_kernel` gives the
        /// previous block's header.
        fn prev_block_timestamp() -> Timestamp {
            next_body_and_header(&random_unproven_block(0), 0)
                .1
                .timestamp
        }

        fn prev_block_with_transaction_timestamp(
            timestamp: Timestamp,
        ) -> (Block, BlockBody, BlockHeader) {
            let transaction_kernel = TransactionKernelModifier::default()
                .timestamp(timestamp)
                .modify(transaction_kernel_and_proof().0.clone());
            prev_block_with_transaction_kernel(transaction_kernel, &epochs())
        }

        #[test]
        fn prev_block_with_transaction_from_its_future_fails() {
            let (prev_block, next_body, next_header) = prev_block_with_transaction_timestamp(
                prev_block_timestamp() + Timestamp::millis(1),
            );

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::TransactionTimestamp.error_id(),
            );
        }

        #[test]
        fn prev_block_with_transaction_from_its_own_time_passes() {
            let (prev_block, next_body, next_header) =
                prev_block_with_transaction_timestamp(prev_block_timestamp());

            assert_accepts(&skipping(), &prev_block, &next_body, &next_header);
        }

        #[test]
        fn prev_block_with_transaction_backdated_to_the_threshold_passes() {
            let threshold = activation_epoch().transaction_backdating_threshold;
            let (prev_block, next_body, next_header) =
                prev_block_with_transaction_timestamp(prev_block_timestamp() - threshold);

            assert_accepts(&skipping(), &prev_block, &next_body, &next_header);
        }

        #[test]
        fn prev_block_with_transaction_backdated_beyond_the_threshold_fails() {
            let threshold = activation_epoch().transaction_backdating_threshold;
            let (prev_block, next_body, next_header) = prev_block_with_transaction_timestamp(
                prev_block_timestamp() - threshold - Timestamp::millis(1),
            );

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::TransactionTimestamp.error_id(),
            );
        }

        #[test]
        fn announcement_list_encoding_has_the_layout_the_program_reads() {
            let retirement = Timestamp::millis(7);
            let announcements = vec![Announcement::retirement(retirement)];
            let expected = [
                bfe!(1),
                bfe!(5),
                bfe!(4),
                bfe!(3),
                RETIREMENT_FLAG[0],
                RETIREMENT_FLAG[1],
                retirement.0,
            ];
            assert_eq!(expected.to_vec(), announcements.encode());
        }

        fn prev_block_with_announcements(
            announcements: Vec<Announcement>,
        ) -> (Block, BlockBody, BlockHeader) {
            let transaction_kernel = TransactionKernelModifier::default()
                .announcements(announcements)
                .modify(transaction_kernel_and_proof().0.clone());
            prev_block_with_transaction_kernel(transaction_kernel, &epochs())
        }

        #[test]
        fn prev_block_with_transaction_retiring_at_its_own_time_passes() {
            let (prev_block, next_body, next_header) = prev_block_with_announcements(vec![
                Announcement::new(vec![RETIREMENT_FLAG[0], RETIREMENT_FLAG[1]]),
                Announcement::new(vec![
                    RETIREMENT_FLAG[0],
                    RETIREMENT_FLAG[1],
                    bfe!(0),
                    bfe!(0),
                ]),
                Announcement::retirement(prev_block_timestamp()),
            ]);

            assert_accepts(&skipping(), &prev_block, &next_body, &next_header);
        }

        #[test]
        fn prev_block_with_retired_transaction_fails() {
            let (prev_block, next_body, next_header) = prev_block_with_announcements(vec![
                Announcement::new(vec![bfe!(1), bfe!(2), bfe!(3)]),
                Announcement::retirement(prev_block_timestamp() - Timestamp::millis(1)),
            ]);

            assert_rejects(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::TransactionRetired.error_id(),
            );
        }

        #[test]
        fn prev_block_with_too_many_inputs_fails() {
            let transaction_kernel = transaction_kernel_and_proof().0.clone();
            let num_inputs = u64::try_from(transaction_kernel.inputs.len()).unwrap();
            assert!(num_inputs > 0, "fixture transaction must have inputs");
            let limits = |max_num_inputs| {
                EpochTable::new(&[Epoch {
                    max_num_inputs: bfe!(max_num_inputs),
                    ..activation_epoch()
                }])
            };

            let epochs = limits(num_inputs);
            let (prev_block, next_body, next_header) =
                prev_block_with_transaction_kernel(transaction_kernel.clone(), &epochs);
            assert_accepts_with_epochs(&skipping(), &prev_block, &next_body, &next_header, &epochs);

            let epochs = limits(num_inputs - 1);
            let (prev_block, next_body, next_header) =
                prev_block_with_transaction_kernel(transaction_kernel, &epochs);
            assert_rejects_with_epochs(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                &epochs,
                BlockValidationRule::TooManyInputs.error_id(),
            );
        }

        #[test]
        fn prev_block_with_too_many_outputs_fails() {
            let mut rng = StdRng::seed_from_u64(0);
            let outputs = (0..3).map(|_| rng.random()).collect::<Vec<_>>();
            let transaction_kernel = TransactionKernelModifier::default()
                .outputs(outputs)
                .modify(transaction_kernel_and_proof().0.clone());
            let max_num_announcements = activation_epoch().max_num_announcements.value();

            let epochs = epochs_with_limits(3, max_num_announcements);
            let (prev_block, next_body, next_header) =
                prev_block_with_transaction_kernel(transaction_kernel.clone(), &epochs);
            assert_accepts_with_epochs(&skipping(), &prev_block, &next_body, &next_header, &epochs);

            let epochs = epochs_with_limits(2, max_num_announcements);
            let (prev_block, next_body, next_header) =
                prev_block_with_transaction_kernel(transaction_kernel, &epochs);
            assert_rejects_with_epochs(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                &epochs,
                BlockValidationRule::TooManyOutputs.error_id(),
            );
        }

        #[test]
        fn prev_block_with_too_many_announcements_fails() {
            let announcements = (0..3)
                .map(|i| Announcement::new(vec![bfe!(i)]))
                .collect::<Vec<_>>();
            let transaction_kernel = TransactionKernelModifier::default()
                .announcements(announcements)
                .modify(transaction_kernel_and_proof().0.clone());
            let max_num_outputs = activation_epoch().max_num_outputs.value();

            let epochs = epochs_with_limits(max_num_outputs, 3);
            let (prev_block, next_body, next_header) =
                prev_block_with_transaction_kernel(transaction_kernel.clone(), &epochs);
            assert_accepts_with_epochs(&skipping(), &prev_block, &next_body, &next_header, &epochs);

            let epochs = epochs_with_limits(max_num_outputs, 2);
            let (prev_block, next_body, next_header) =
                prev_block_with_transaction_kernel(transaction_kernel, &epochs);
            assert_rejects_with_epochs(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                &epochs,
                BlockValidationRule::TooManyAnnouncements.error_id(),
            );
        }

        #[test]
        fn prev_block_is_judged_under_the_last_epoch_started_by_its_height() {
            let doubled_minimum_block_time =
                Timestamp::millis(2 * minimum_block_time().to_millis());
            let epochs_with_second = EpochTable::new(&[
                activation_epoch(),
                epoch_after_activation(doubled_minimum_block_time),
            ]);

            let (prev_block, next_body, next_header) =
                prev_block_after_activation(minimum_block_time(), &epochs_with_second);
            assert_rejects_with_epochs(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                &epochs_with_second,
                BlockValidationRule::MinimumBlockTime.error_id(),
            );

            let (prev_block, next_body, next_header) =
                prev_block_after_activation(doubled_minimum_block_time, &epochs_with_second);
            assert_accepts_with_epochs(
                &skipping(),
                &prev_block,
                &next_body,
                &next_header,
                &epochs_with_second,
            );
        }
    }
}
