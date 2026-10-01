use std::sync::OnceLock;

use get_size2::GetSize;
use neptune_primitives::difficulty_control::Difficulty;
use neptune_primitives::mast_hash::MastHash;
use serde::Deserialize;
use serde::Serialize;
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
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

use crate::block::block_appendix::BlockAppendix;
use crate::block::block_body::BlockBody;
use crate::block::block_body::BlockBodyField;
use crate::block::block_header::BlockHeader;
use crate::block::block_header::BlockPow;
use crate::block::block_validation_error::BlockValidationRule;
use crate::block::pow::POW_MEMORY_TREE_HEIGHT;
use crate::block::Block;
use crate::consensus_rule_set::ConsensusRuleSet;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::transaction::transaction_kernel::TransactionKernel;

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

    pub fn nondeterminism(&self) -> NonDeterminism {
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

    /// As [Self::prev_block_header].
    prev_block_body: BlockBody,

    /// As [Self::prev_block_header].
    prev_block_appendix: BlockAppendix,

    /// The encoding of the previous block's `BlockProof`. As
    /// [Self::prev_block_header].
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
///
/// Output:
///  - previous block's hash
///  - previous block's lustration status
///  - previous block's timestamp
///  - previous block's cumulative proof-of-work
///  - previous block's difficulty
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, GetSize, BFieldCodec)]
pub struct PredecessorIsValid;

impl PredecessorIsValid {
    /// The claim for this program execution.
    pub fn claim(
        &self,
        next_block_body_mh: Digest,
        next_header: &BlockHeader,
        prev_block: &Block,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Claim {
        let prev_block_header = prev_block.header();
        let input = [
            next_block_body_mh.reversed().values().to_vec(),
            vec![next_header.height.into()],
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

        let prev_block_body_mh_alloc = library.kmalloc(Digest::LEN as u32);

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
        // The `BlockProof`'s encoding lies inside the `Vec` field, after the
        // `Vec`'s own length word.
        let prev_block_proof_encoding = triton_asm!(
            {&field_with_size!(PredecessorIsValidWitnessMemory::prev_block_proof)}
            // _ *vec vec_size
            addi -1 pick 1 addi 1 pick 1
            // _ *block_proof block_proof_size
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

        // Hash the previous block's body, and keep its MAST hash in static
        // memory.
        // BEFORE: _ *w
        // AFTER:  _ *w
        let hash_prev_block_body = triton_asm!(
            dup 0 {&field!(PredecessorIsValidWitnessMemory::prev_block_body)}
            // _ *w *body

            call {new_list}
            // _ *w *body *leafs

            dup 1 {&field!(BlockBody::transaction_kernel)}
            call {transaction_kernel_mast_hash}
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
        let (write_output, write_output_code) = subroutine("write_output", write_output);

        let code = triton_asm!(
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
            reconstructing the MAST hash construction. Along with rule 0.c, this
            establishes that the ND memory for the previous block is authentic. */
            call {prev_block_hash}
            // _ [next_block_body_mh] *w [prev_block_hash]

            call {rule_0a}
            // _ [next_block_body_mh] *w [prev_block_hash]

            call {rule_0c}
            // _ [next_block_body_mh] *w [prev_block_hash]

            call {write_output}
            // _ [next_block_body_mh]

            pop {Digest::LEN}
            halt

            {&header_mast_hash_code}
            {&transaction_kernel_mast_hash_code}
            {&authenticate_next_block_mmr_accumulator_code}
            {&hash_prev_block_body_code}
            {&prev_block_hash_code}
            {&rule_0a_code}
            {&rule_0c_code}
            {&write_output_code}
            {&library.all_imports()}
        );

        (library, code)
    }

    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
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
    use neptune_primitives::timestamp::Timestamp;
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::triton_vm::stark::Stark;
    use tasm_lib::twenty_first::prelude::Mmr;

    use super::*;
    use crate::block::mutator_set_update::MutatorSetUpdate;
    use crate::block::pow::LustrationStatus;
    use crate::block::test_helpers::block_mmra_with_num_leafs;
    use crate::block::validity::block_primitive_witness::deterministic_block_primitive_witness;
    use crate::block::validity::block_primitive_witness::BlockPrimitiveWitness;
    use crate::block::validity::block_program::BlockProgram;
    use crate::block::validity::block_proof_witness::BlockProofWitness;
    use crate::block::BlockProof;
    use crate::proof_abstractions::tasm::builtins as tasm;
    use crate::proof_abstractions::tasm::program::proof_cache::load_proof_or_produce_and_save;
    use crate::proof_abstractions::tasm::program::spec::TritonProgramSpecification;
    use crate::transaction::validity::neptune_proof::Proof as NeptuneProof;
    use crate::transaction::validity::single_proof::single_proof_claim;
    use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

    impl TritonProgramSpecification for PredecessorIsValid {
        fn source(&self) {
            let next_block_body_mh: Digest = tasm::tasmlib_io_read_stdin___digest();
            let witness: PredecessorIsValidWitnessMemory =
                tasm::decode_from_memory(FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS);

            tasm::tasmlib_hashing_merkle_verify(
                next_block_body_mh,
                BlockBodyField::BlockMmrAccumulator as u32,
                Tip5::hash_varlen(&witness.next_block_mmr_accumulator.encode()),
                BlockBody::MAST_HEIGHT as u32,
            );
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
        program.claim(
            next_body.mast_hash(),
            next_header,
            prev_block,
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
    /// appendix holds this program's claim among fillers, without a
    /// proof.
    fn unproven_block_with_own_claim(
        prev_block: &Block,
        body: BlockBody,
        header: BlockHeader,
        seed: u64,
    ) -> Block {
        let own_claim = own_claim(&PredecessorIsValid, prev_block, &body, &header);
        let mut claims = vec![halt_claim_and_proof().0, halt_claim_and_proof().0];
        claims.insert(own_claim_position(seed), own_claim);

        unproven_block(header, body, claims)
    }

    /// An unproven previous block that carries this program's claim,
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
    ) -> (Claim, NonDeterminism) {
        let claim = own_claim(program, prev_block, next_body, next_header);
        let witness = PredecessorIsValidWitness::new(prev_block, next_body);

        (claim, witness.nondeterminism())
    }

    /// Run the program in Rust and in Triton VM, and check that both agree
    /// with the claim.
    fn assert_accepts(
        program: &PredecessorIsValid,
        prev_block: &Block,
        next_body: &BlockBody,
        next_header: &BlockHeader,
    ) {
        let (claim, nondeterminism) =
            claim_and_nondeterminism(program, prev_block, next_body, next_header);
        let input = PublicInput::new(claim.input);

        let rust_output = program.run_rust(&input, nondeterminism.clone()).unwrap();
        let tasm_output = program.run_tasm(&input, nondeterminism).unwrap();
        assert_eq!(rust_output, tasm_output);
        assert_eq!(claim.output, tasm_output);

        if prev_block.header().height >= activation_height() {
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
        let (claim, nondeterminism) =
            claim_and_nondeterminism(program, prev_block, next_body, next_header);
        program
            .test_assertion_failure(PublicInput::new(claim.input), nondeterminism, &[error_id])
            .unwrap();
    }

    /// The tests on blocks without proofs.
    mod proof_free {
        use super::*;

        #[test]
        fn rust_and_tasm_agree_and_output_is_the_prev_block_hash() {
            for seed in 0..3 {
                let (prev_block, next_body, next_header) =
                    unproven_prev_block_and_next_body_and_header(seed);
                assert_accepts(&PredecessorIsValid, &prev_block, &next_body, &next_header);
            }
        }

        #[test]
        fn prev_block_with_tampered_proof_fails() {
            let (mut prev_block, next_body, next_header) =
                unproven_prev_block_and_next_body_and_header(0);
            prev_block.set_proof(BlockProof::Genesis);

            assert_rejects(
                &PredecessorIsValid,
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
                &PredecessorIsValid,
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
                &PredecessorIsValid,
                &prev_block,
                &next_body,
                &next_header,
                BlockValidationRule::BlockHeight.error_id(),
            );
        }
    }
}
