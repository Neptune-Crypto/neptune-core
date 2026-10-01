use std::sync::OnceLock;

use get_size2::GetSize;
use neptune_primitives::difficulty_control::Difficulty;
use neptune_primitives::difficulty_control::ProofOfWork;
use neptune_primitives::mast_hash::MastHash;
use neptune_primitives::timestamp::Timestamp;
use num_bigint::BigUint;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::arithmetic::u160::lt::Lt as U160Lt;
use tasm_lib::arithmetic::u192::safe_add::SafeAdd as U192SafeAdd;
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
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::verifier::own_program_digest::OwnProgramDigest;
use tasm_lib::verifier::stark_verify::StarkVerify;

use super::block_program::BlockProgram;
use super::difficulty_control::DifficultyControl;
use super::epoch_table::Epoch;
use super::epoch_table::EpochTable;
use super::epoch_table::NUM_EPOCHS;
use super::meets_threshold::MeetsThreshold;
use crate::block::block_appendix::BlockAppendix;
use crate::block::block_appendix::MAX_NUM_CLAIMS;
use crate::block::block_body::BlockBody;
use crate::block::block_body::BlockBodyField;
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
use crate::transaction::transaction_kernel::TransactionKernel;
use crate::transaction::validity::single_proof::single_proof_claim;
use crate::transaction::validity::single_proof::SingleProof;
use crate::transaction::validity::tasm::claims::generate_single_proof_claim::GenerateSingleProofClaim;
use crate::transaction::validity::tasm::claims::new_claim::NewClaim;

/// The witness for [`PredecessorIsValid`]: the previous block and the next
/// block's body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PredecessorIsValidWitness {
    prev_block: Block,
    next_block_body: BlockBody,
}

impl PredecessorIsValidWitness {
    pub fn new(prev_block: &Block, next_block_body: &BlockBody) -> Self {
        Self {
            prev_block: prev_block.clone(),
            next_block_body: next_block_body.clone(),
        }
    }

    pub fn nondeterminism(
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

        let prev_block_height = self.prev_block.header().height;
        if prev_block_height >= epochs.activation_height() {
            // 0.e)
            nondeterminism
                .individual_tokens
                .extend(DifficultyControl::divined_tokens(
                    epochs.in_force_at(prev_block_height).target_block_interval,
                    prev_block_height.previous().unwrap(),
                ));
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

    /// Number of words in the claim's standard-in stream.
    ///
    /// Same number as the number of words read from standard-in in this
    /// program.
    fn input_len() -> usize {
        // - Next block body MAST hash (5 words)
        // - Next block height (1)
        // - epoch table
        Digest::LEN + 1 + EpochTable::static_length().unwrap()
    }

    /// The claim for this program execution.
    pub fn claim(
        &self,
        next_block_body_mh: Digest,
        next_header: &BlockHeader,
        prev_block: &Block,
        epochs: &EpochTable,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Claim {
        let prev_block_header = prev_block.header();
        let input = [
            next_block_body_mh.reversed().values().to_vec(),
            vec![next_header.height.into()],
            epochs.encode(),
        ]
        .concat();

        let prev_lustration_status = prev_block_header
            .pow
            .lustration_status()
            .map(|status| status.encode())
            .unwrap_or_default();
        let output = [
            next_header.prev_block_digest.values().to_vec(),
            prev_lustration_status,
            vec![prev_block_header.timestamp.0],
            prev_block_header.cumulative_proof_of_work.encode(),
            prev_block_header.difficulty.encode(),
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
        let u160_lt = library.import(Box::new(U160Lt));
        let u64_lt = library.import(Box::new(U64Lt));
        let u192_safe_add = library.import(Box::new(U192SafeAdd));
        let difficulty_control = library.import(Box::new(DifficultyControl));
        let new_claim = library.import(Box::new(NewClaim::new(ConsensusRuleSet::HardforkDelta)));
        let generate_single_proof_claim = library.import(Box::new(GenerateSingleProofClaim::new(
            ConsensusRuleSet::HardforkDelta,
        )));
        let push_single_proof_digest = SingleProof::new(ConsensusRuleSet::HardforkDelta)
            .hash()
            .values()
            .into_iter()
            .rev()
            .flat_map(|word| triton_asm!(push { word }))
            .collect::<Vec<_>>();
        let transaction_claim_size =
            single_proof_claim(Digest::default(), ConsensusRuleSet::HardforkDelta)
                .encode()
                .len();
        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));
        let push_block_program_digest = BlockProgram
            .hash()
            .values()
            .into_iter()
            .rev()
            .flat_map(|word| triton_asm!(push { word }))
            .collect::<Vec<_>>();
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

        let epoch_size = Epoch::static_length().unwrap();
        let epoch_type = DataType::Tuple(vec![DataType::Bfe; epoch_size]);

        // BEFORE: _ *epoch_last_word
        // AFTER:  _ [epoch]
        let read_epoch = epoch_type.read_value_from_memory_pop_pointer();

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

                dup 4 addi {epoch_size - 1} {&read_epoch}
                dup {epoch_size + 2} addi {epoch_size - 1} {&read_epoch}
                {&epoch_type.compare()}
                // _ *claim_epoch[i] height *epoch[i] tables_agree i epochs_are_equal

                dup 5 addi {epoch_size - 1} {&read_epoch}
                {&vec![triton_asm!(push 0); epoch_size].concat()}
                {&epoch_type.compare()}
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

                dup 2 addi {Digest::LEN + 2}
                call {epoch_tables_agree}
                // _ *input body_mh_matches height_matches tables_agree

                mul mul
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
                // _ *claim[i]_si num_claims i program_matches

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

        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
        // BEFORE: _ *w [prev_block_hash]
        // AFTER:  _ *w [prev_block_hash]
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

        let prev_block_epoch_rules = "predecessor_is_valid_prev_block_epoch_rules".to_string();
        let prev_block_epoch_rules_code = triton_asm!(
            // BEFORE: _ *w [prev_block_hash]
            // AFTER:  _ *w [prev_block_hash]
            {prev_block_epoch_rules}:
                dup 5 {&read_prev_block_height}

                /* Get pointer to the epoch in force for previous block,
                   dictated by epoch from std-in, not by previous block. */
                call {epoch_in_force}
                // _ *w [prev_block_hash] *epoch

                dup 0 push {prev_epoch_alloc.write_address()} write_mem 1 pop 1
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

                pop 1
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
        // STDIN:  [epoch_table]
        let prev_block_epoch_rules_if_activated = triton_asm!(
            call {read_epoch_table}
            // _ *w [prev_block_hash]

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

            {&push_block_program_digest}
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
            {&push_single_proof_digest}
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
        // timestamp, cumulative proof-of-work and difficulty.
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
        let (prev_block_pow, prev_block_pow_code) =
            subroutine("proof_of_work_prev", prev_block_pow);
        let (rule_1b_prev, rule_1b_prev_code) = subroutine("rule_1b_prev", rule_1b_prev);
        let (rule_1a_txproof_prev, rule_1a_txproof_prev_code) =
            subroutine("rule_1a_prev", rule_1a_txproof_prev);
        let (write_output, write_output_code) = subroutine("write_output", write_output);

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

            call {prev_block_pow}
            // _ [next_block_body_mh] *w [prev_block_hash]

            call {rule_1b_prev}
            // _ [next_block_body_mh] *w [prev_block_hash]

            {&verify_prev_block_proof}
            // _ [next_block_body_mh] *w [prev_block_hash]

            call {rule_1a_txproof_prev}
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
            {&epoch_has_started_code}
            {&epoch_in_force_code}
            {&epoch_tables_agree_code}
            {&own_claim_input_matches_code}
            {&find_own_claim_code}
            {&prev_block_epoch_rules_code}
            {&authenticate_next_block_mmr_accumulator_code}
            {&hash_prev_block_body_code}
            {&prev_block_hash_code}
            {&rule_0a_code}
            {&rule_0c_code}
            {&prev_block_pow_code}
            {&rule_1b_prev_code}
            {&verify_prev_block_proof_code}
            {&rule_1a_txproof_prev_code}
            {&read_epoch_table_code}
            {&rule_0b_prev_code}
            {&rule_0d_prev_code}
            {&rule_0e_prev_code}
            {&rule_0f_prev_code}
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

    use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
    use neptune_mutator_set::removal_record::removal_record_list::RemovalRecordList;
    use neptune_primitives::block_height::BlockHeight;
    use neptune_primitives::difficulty_control::difficulty_control;
    use neptune_primitives::network::Network;
    use num_traits::Zero;
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::twenty_first::prelude::Mmr;

    use super::*;
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
    use crate::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::transaction::validity::neptune_proof::Proof as NeptuneProof;
    use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

    impl TritonProgramSpecification for PredecessorIsValid {
        fn source(&self) {
            let own_program_digest = tasm::own_program_digest();
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
                let prev_block_claim = Claim::new(BlockProgram.hash())
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
            let transaction_claim =
                single_proof_claim(prev_block_txk_mh, ConsensusRuleSet::HardforkDelta);
            assert!(witness.prev_block_appendix.contains(&transaction_claim));

            // The header rules, for the previous block. Its predecessor's
            // values come from the previous block's copy of the claim for this
            // program execution.
            let epoch_table_words = (0..EpochTable::static_length().unwrap())
                .map(|_| tasm::tasmlib_io_read_stdin___bfe())
                .collect::<Vec<_>>();
            let epochs = *EpochTable::decode(&epoch_table_words).unwrap();
            let cumulative_pow_size = ProofOfWork::static_length().unwrap();
            let prev_block_height = witness.prev_block_header.height;
            if prev_block_height >= epochs.activation_height() {
                let prev_epoch = epochs.in_force_at(prev_block_height);
                let prev_minimum_block_time = prev_epoch.minimum_block_time;
                let prev_target_block_interval = prev_epoch.target_block_interval;

                let expected_input_start = [
                    prev_block_body_mh.reversed().values().to_vec(),
                    vec![prev_block_height.into()],
                ]
                .concat();
                let parent_claim = witness
                    .prev_block_appendix
                    .iter()
                    .find(|claim| {
                        claim.program_digest == own_program_digest
                            && claim.input.len() == Self::input_len()
                            && claim.input.starts_with(&expected_input_start)
                            && EpochTable::decode(&claim.input[expected_input_start.len()..])
                                .unwrap()
                                .is_prefix_of_up_to(&epochs, prev_block_height)
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
            }

            tasm::tasmlib_io_write_to_stdout___digest(prev_block_hash);

            // The lustration status's words, as they sit in the PoW field; see
            // `Pow::lustration_status`.
            let pow = &witness.prev_block_header.pow;
            let [e0, e1, e2, e3, e4] = pow.path_a[POW_MEMORY_TREE_HEIGHT - 2].values();
            let e5 = pow.path_a[POW_MEMORY_TREE_HEIGHT - 1].values()[0];
            for word in [e0, e1, e2, e3, e4, e5] {
                tasm::tasmlib_io_write_to_stdout___bfe(word);
            }
            tasm::tasmlib_io_write_to_stdout___bfe(witness.prev_block_header.timestamp.0);
            tasm::tasmlib_io_write_to_stdout___encoding(
                witness.prev_block_header.cumulative_proof_of_work,
            );
            tasm::tasmlib_io_write_to_stdout___encoding(witness.prev_block_header.difficulty);
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
        }
    }

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
        predecessors()
            .lock()
            .unwrap()
            .get(&block.header().prev_block_digest)
            .cloned()
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
        let transaction_claim = single_proof_claim(
            body.transaction_kernel.mast_hash(),
            ConsensusRuleSet::HardforkDelta,
        );
        let claims = [vec![transaction_claim], claims].concat();

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
            epochs,
            ConsensusRuleSet::HardforkDelta,
        )
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
        let witness = PredecessorIsValidWitness::new(prev_block, next_body);

        (claim, witness.nondeterminism(program, epochs))
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
                .validate_without_proof(&predecessor, prev_block.header().timestamp, Network::Main)
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
            let claims = [vec![transaction_claim_and_proof_for(&body)], claims].concat();
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
            let witness = PredecessorIsValidWitness::new(prev_block, next_body);
            let proof = load_proof_or_produce_and_save(
                &claim,
                program.program(),
                witness.nondeterminism(&program, &epochs()),
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
