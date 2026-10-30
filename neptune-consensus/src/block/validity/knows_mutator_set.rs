//! The composer's proof that it holds the mutator set: one leaf of every
//! Merkle tree of the inactive SWBF, a chunk, and of the AOCL, the ones the
//! parent's hash samples, with their membership in the mutator set after
//! the parent block, which the block's transaction is built on. A block's
//! appendix contains the claim; its input binds the parent and the mutator
//! set, so the composer cannot pick the samples, and it can prove the claim
//! as soon as the parent lands.
//!
//! The claim is self-recursive: from the activation height on, the parent's
//! appendix must contain the claim about its own parent. The program checks
//! presence only, the parent's block proof having settled the claim's
//! truth, so by induction every block from the activation height on
//! contains it.

use std::sync::OnceLock;

use get_size2::GetSize;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_mutator_set::removal_record::chunk::Chunk;
use neptune_primitives::block_height::BlockHeight;
use neptune_primitives::mast_hash::HasDiscriminant;
use neptune_primitives::mast_hash::MastHash;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::arithmetic::u64::add::Add as U64Add;
use tasm_lib::arithmetic::u64::and::And as U64And;
use tasm_lib::arithmetic::u64::log_2_floor::Log2Floor;
use tasm_lib::arithmetic::u64::lt::Lt as U64Lt;
use tasm_lib::arithmetic::u64::popcount::PopCount;
use tasm_lib::arithmetic::u64::pow2::Pow2;
use tasm_lib::arithmetic::u64::sub::Sub as U64Sub;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::hashing::hash_from_stack::HashFromStack;
use tasm_lib::hashing::merkle_root::MerkleRoot;
use tasm_lib::hashing::merkle_step_u64_index::MerkleStepU64Index;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::list::new::New;
use tasm_lib::list::push::Push;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::*;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::verifier::own_program_digest::OwnProgramDigest;

use super::mutator_set_hash::MutatorSetHash;
use crate::block::block_appendix::BlockAppendix;
use crate::block::block_body::BlockBody;
use crate::block::block_body::BlockBodyField;
use crate::block::block_header::BlockHeader;
use crate::block::block_validation_error::BlockValidationRule;
use crate::block::Block;
use crate::block::BlockField;
use crate::consensus_rule_set::ConsensusRuleSet;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::proof_abstractions::SecretWitness;
use crate::transaction::transaction_kernel::TransactionKernel;
use crate::transaction::transaction_kernel::TransactionKernelField;

/// The leaf of each Merkle tree of an MMR with this many leafs that a parent
/// with this hash samples, as leaf indices from the tallest tree down: the
/// low bits of the hash's first word pick the leaf within the tree. Empty
/// for an empty MMR.
pub fn sampled_leafs(prev_block_digest: Digest, leaf_count: u64) -> Vec<u64> {
    let word = prev_block_digest.values()[0].value();
    let mut first_leaf = 0;
    (0..u64::BITS)
        .rev()
        .filter(|height| leaf_count & (1 << height) != 0)
        .map(|height| {
            let tree_size = 1 << height;
            let leaf_index = first_leaf + (word & (tree_size - 1));
            first_leaf += tree_size;
            leaf_index
        })
        .collect()
}

/// Witness data to prove that the composer knows the archival mutator set.
///
/// In the general case, this requires the archival mutator set to derived.
#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize, TasmObject)]
pub struct KnowsMutatorSetWitness {
    prev_block_digest: Digest,
    mutator_set: MutatorSetAccumulator,
    activation_height: BlockHeight,
    /// The sampled chunk of each Merkle tree of the inactive SWBF, from the
    /// tallest tree down.
    chunks: Vec<Chunk>,
    /// The sampled leaf of each Merkle tree of the AOCL, from the tallest
    /// tree down.
    aocl_leafs: Vec<Digest>,

    /// The parent block's parts the presence check reads: its header, body
    /// hash, appendix and the hash of its proof, and its transaction
    /// kernel's hash and mutator set hash.
    prev_block_header: BlockHeader,
    prev_block_body_mast_hash: Digest,
    prev_block_appendix: BlockAppendix,
    prev_block_proof_leaf: Digest,
    prev_block_txk_mast_hash: Digest,
    prev_block_txk_mutator_set_hash: Digest,

    /// The authentication paths of the chunks and of the AOCL leafs, then,
    /// for a parent at or past the activation height, of the transaction
    /// kernel in the parent's body and of the mutator set hash in that
    /// kernel.
    paths: Vec<Vec<Digest>>,
}

impl KnowsMutatorSetWitness {
    /// For the chunks and AOCL leafs [`sampled_leafs`] picks in this mutator
    /// set after the parent, with their authentication paths.
    pub fn new(
        prev_block: &Block,
        mutator_set: &MutatorSetAccumulator,
        activation_height: BlockHeight,
        chunks: Vec<Chunk>,
        chunk_paths: Vec<Vec<Digest>>,
        aocl_leafs: Vec<Digest>,
        aocl_paths: Vec<Vec<Digest>>,
    ) -> Self {
        let body = prev_block.body();
        let kernel = &body.transaction_kernel;
        let mut paths = [chunk_paths, aocl_paths].concat();
        if prev_block.header().height >= activation_height {
            paths.push(body.mast_path(BlockBodyField::TransactionKernel));
            paths.push(kernel.mast_path(TransactionKernelField::MutatorSetHash));
        }
        Self {
            prev_block_digest: prev_block.hash(),
            mutator_set: mutator_set.clone(),
            activation_height,
            chunks,
            aocl_leafs,
            prev_block_header: *prev_block.header(),
            prev_block_body_mast_hash: body.mast_hash(),
            prev_block_appendix: prev_block.appendix().clone(),
            prev_block_proof_leaf: prev_block.mast_path(BlockField::Kernel)[0],
            prev_block_txk_mast_hash: kernel.mast_hash(),
            prev_block_txk_mutator_set_hash: kernel.mutator_set_hash,
            paths,
        }
    }
}

impl SecretWitness for KnowsMutatorSetWitness {
    fn standard_input(&self) -> PublicInput {
        PublicInput::new(KnowsMutatorSet::claim_input(
            self.prev_block_digest,
            self.mutator_set.hash(),
            self.activation_height,
        ))
    }

    fn output(&self) -> Vec<BFieldElement> {
        vec![]
    }

    fn program(&self) -> Program {
        KnowsMutatorSet.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        let mut nondeterminism = NonDeterminism::default();
        encode_to_memory(
            &mut nondeterminism.ram,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self,
        );
        nondeterminism.digests = self.paths.concat();
        nondeterminism
    }
}

/// Input:
/// - the parent block's hash (5 words)
/// - the hash of the mutator set after the parent (5 words)
/// - the activation height: the first height at which a block must contain
///   the claim (1 word)
///
/// Output: none.
///
/// Divines the mutator set, which must hash to the input, one chunk per
/// Merkle tree of the inactive SWBF and one leaf per Merkle tree of the
/// AOCL, at the indices the parent's hash samples, with their authentication
/// paths. For a parent at or past the activation height, divines the
/// parent's parts, which must hash to its hash, and finds this program's
/// claim about the parent's parent and transaction mutator set in its
/// appendix.
#[derive(
    Debug, Clone, Copy, Default, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize,
)]
pub struct KnowsMutatorSet;

impl KnowsMutatorSet {
    const MUTATOR_SET_MISMATCH_ERROR_ID: i128 = 1_000_610;
    const WRONG_LEAF_ERROR_ID: i128 = 1_000_611;
    const PARENT_MISMATCH_ERROR_ID: i128 = 1_000_612;
    const LEAF_COUNT_MISMATCH_ERROR_ID: i128 = 1_000_613;

    const INPUT_LEN: usize = 2 * Digest::LEN + 1;

    pub fn claim_input(
        prev_block_digest: Digest,
        mutator_set_hash: Digest,
        activation_height: BlockHeight,
    ) -> Vec<BFieldElement> {
        [
            prev_block_digest.reversed().values().to_vec(),
            mutator_set_hash.reversed().values().to_vec(),
            vec![activation_height.into()],
        ]
        .concat()
    }

    /// The claim a block whose parent has this hash, and this mutator set
    /// after it, must contain from the activation height on.
    pub fn claim(
        prev_block_digest: Digest,
        mutator_set: &MutatorSetAccumulator,
        activation_height: BlockHeight,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Claim {
        Self::claim_about_hash(
            prev_block_digest,
            mutator_set.hash(),
            activation_height,
            consensus_rule_set,
        )
    }

    /// [`Self::claim`] given the mutator set's hash.
    pub fn claim_about_hash(
        prev_block_digest: Digest,
        mutator_set_hash: Digest,
        activation_height: BlockHeight,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Claim {
        Claim::new(Self.hash())
            .with_input(Self::claim_input(
                prev_block_digest,
                mutator_set_hash,
                activation_height,
            ))
            .about_version(consensus_rule_set.triton_proof_version().version())
    }
}

impl TritonProgram for KnowsMutatorSet {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        let mut library = Library::new();
        let audit_witness = library.import(Box::new(
            VerifyNdSiIntegrity::<KnowsMutatorSetWitness>::default(),
        ));
        let own_program_digest = library.import(Box::new(OwnProgramDigest));
        let mutator_set_hash = library.import(Box::new(MutatorSetHash));
        let hash_varlen = library.import(Box::new(HashVarlen));
        let hash_digest = library.import(Box::new(HashFromStack::new(DataType::Digest)));
        let new_list = library.import(Box::new(New));
        let push_digest = library.import(Box::new(Push::new(DataType::Digest)));
        let merkle_root = library.import(Box::new(MerkleRoot));
        let merkle_verify = library.import(Box::new(MerkleVerify));
        let u64_lt = library.import(Box::new(U64Lt));
        let u64_add = library.import(Box::new(U64Add));
        let u64_sub = library.import(Box::new(U64Sub));
        let u64_and = library.import(Box::new(U64And));
        let log2_floor = library.import(Box::new(Log2Floor));
        let pow2 = library.import(Box::new(Pow2));
        let popcount = library.import(Box::new(PopCount));
        let merkle_step = library.import(Box::new(MerkleStepU64Index));
        // The first word of the parent's hash, which samples the leafs.
        let sample_alloc = library.kmalloc(2);
        let prev_block_digest_alloc = library.kmalloc(Digest::LEN as u32);
        let activation_height_alloc = library.kmalloc(1);
        let own_program_digest_alloc = library.kmalloc(Digest::LEN as u32);
        // The parent's parent's hash and the parent's transaction mutator set
        // hash: the input of the claim the parent must contain.
        let expected_input_alloc = library.kmalloc(2 * Digest::LEN as u32);

        let version = ConsensusRuleSet::HardforkDelta
            .triton_proof_version()
            .version();
        let read_digest = triton_asm!(addi {Digest::LEN - 1} read_mem {Digest::LEN} pop 1);
        let read_leaf_count = triton_asm!(
            {&field!(MmrAccumulator::leaf_count)} addi 1 read_mem 2 pop 1
        );
        let digests_are_equal = DataType::Digest.compare();
        // Hash a field of the object, and append it to the list of all leafs.
        // BEFORE: _ *object *leafs
        // AFTER:  _ *object *leafs
        let push_leaf = |field_with_size: Vec<LabelledInstruction>| {
            triton_asm!(
                dup 1 {&field_with_size}
                call {hash_varlen}
                // _ *object *leafs [leaf]
                dup 5 place 5
                call {push_digest}
            )
        };
        let hash_chunks = "knows_mutator_set_hash_chunks".to_string();
        let hash_chunks_loop = "knows_mutator_set_hash_chunks_loop".to_string();
        let verify_trees = "knows_mutator_set_verify_trees".to_string();
        let verify_trees_loop = "knows_mutator_set_verify_trees_loop".to_string();
        let climb = "knows_mutator_set_climb".to_string();
        let parent_contains_claim = "knows_mutator_set_parent_contains_claim".to_string();
        let header_mast_hash = "knows_mutator_set_header_mast_hash".to_string();
        let find_own_claim = "knows_mutator_set_find_own_claim".to_string();
        let input_matches = "knows_mutator_set_input_matches".to_string();
        let code = triton_asm!(
            // _
            call {own_program_digest}
            // _ [own_program_digest]

            push {own_program_digest_alloc.write_address()} write_mem {Digest::LEN} pop 1
            // _

            read_io {Digest::LEN}
            // _ [prev_block_digest]

            dup 0 split
            push {sample_alloc.write_address()} write_mem 2 pop 1
            push {prev_block_digest_alloc.write_address()} write_mem {Digest::LEN} pop 1
            // _

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            hint witness = stack[0]
            dup 0 call {audit_witness} pop 1
            // _ *w

            read_io {Digest::LEN}
            // _ *w [mutator_set_hash]

            /* Assert that input is a commitment to the mutator set loaded from memory */
            dup 5 {&field!(KnowsMutatorSetWitness::mutator_set)}
            call {mutator_set_hash}
            // _ *w [mutator_set_hash] [witness_mutator_set_hash]
            assert_vector error_id {Self::MUTATOR_SET_MISMATCH_ERROR_ID}

            pop 5
            // _ *w

            read_io 1
            // _ *w activation_height

            push {activation_height_alloc.write_address()} write_mem 1 pop 1
            // _ *w

            dup 0 {&field!(KnowsMutatorSetWitness::mutator_set)}
            {&field!(MutatorSetAccumulator::swbf_inactive)}
            dup 0 {&field!(MmrAccumulator::peaks)}
            dup 2 {&field!(KnowsMutatorSetWitness::chunks)} call {hash_chunks}
            // _ *w *swbfi *peaks *leafs

            pick 2 {&read_leaf_count}
            // _ *w *peaks *leafs [leaf_count]

            call {verify_trees}
            // _ *w

            dup 0 {&field!(KnowsMutatorSetWitness::mutator_set)}
            {&field!(MutatorSetAccumulator::aocl)}
            dup 0 {&field!(MmrAccumulator::peaks)}
            dup 2 {&field!(KnowsMutatorSetWitness::aocl_leafs)}
            // _ *w *aocl *peaks *leafs

            pick 2 {&read_leaf_count}
            call {verify_trees}
            // _ *w

            push {activation_height_alloc.read_address()} read_mem 1 pop 1 split
            dup 2 {&field!(KnowsMutatorSetWitness::prev_block_header)}
            {&field!(BlockHeader::height)} read_mem 1 pop 1 split
            // _ *w [activation_height] [prev_block_height]
            call {u64_lt}
            push 0 eq
            // _ *w (prev_block_height >= activation_height)
            skiz call {parent_contains_claim}

            pop 1
            halt

            // The hashes of the chunks, as a list of the trees' leafs.
            // BEFORE: _ *chunks
            // AFTER:  _ *leafs
            {hash_chunks}:
                call {new_list}
                pick 1 read_mem 1 addi 2 place 1 push 0
                // _ *leafs *chunk[0]_si num_chunks 0

                call {hash_chunks_loop}
                pop 3
                return

            // INVARIANT: _ *leafs *chunk[i]_si num_chunks i
            {hash_chunks_loop}:
                dup 1 dup 1 eq skiz return
                dup 2 read_mem 1
                // _ *leafs *chunk[i]_si num_chunks i chunk_size (*chunk[i]_si - 1)

                // Crashes unless the size is a u32.
                dup 1 pop_count pop 1
                addi 2 dup 1 call {hash_varlen}
                // _ *leafs *chunk[i]_si num_chunks i chunk_size [leaf]

                dup 9 place 5 call {push_digest}
                // _ *leafs *chunk[i]_si num_chunks i chunk_size

                pick 3 add addi 1 place 2 addi 1
                // _ *leafs *chunk[i + 1]_si num_chunks (i + 1)

                recurse

            // The list holds one leaf per tree of the MMR, and each tree, from
            // the tallest down, holds the next leaf at the index the sample
            // picks within the tree.
            // BEFORE: _ *peaks *leafs [leaf_count: u64]
            // AFTER:  _
            {verify_trees}:
                dup 1 dup 1 call {popcount}
                dup 3 read_mem 1 pop 1 eq
                assert error_id {Self::LEAF_COUNT_MISMATCH_ERROR_ID}
                // _ *peaks *leafs [leaf_count]

                push 0
                call {verify_trees_loop}
                // _ *peaks *leafs 0 0 num_trees

                pop 5
                return

            // INVARIANT: _ *peaks *leafs [remaining_leafs: u64] i
            {verify_trees_loop}:
                dup 2 dup 2 push 0 push 0 {&DataType::U64.compare()}
                skiz return
                // _ *peaks *leafs [remaining_leafs] i

                dup 2 dup 2 call {log2_floor} call {pow2}
                // _ *peaks *leafs [remaining_leafs] i [tree_size]

                dup 1 dup 1 pick 6 pick 6 call {u64_sub}
                place 4 place 4
                // _ *peaks *leafs [remaining_leafs - tree_size] i [tree_size]

                push 0 push 1 dup 3 dup 3 call {u64_sub}
                push {sample_alloc.read_address()} read_mem 2 pop 1
                call {u64_and}
                call {u64_add}
                // _ *peaks *leafs [remaining_leafs'] i [tree_size + (sample % tree_size)]

                dup 5 dup 3 push {Digest::LEN} mul add addi 1 {&read_digest}
                // _ *peaks *leafs [remaining_leafs'] i [mt_index] [leaf]

                call {climb}
                // _ *peaks *leafs [remaining_leafs'] i 0 1 [root]

                dup 11 dup 8 push {Digest::LEN} mul add addi 1 {&read_digest}
                // _ *peaks *leafs [remaining_leafs'] i 0 1 [root] [peak]

                assert_vector error_id {Self::WRONG_LEAF_ERROR_ID}
                pop 5 pop 2 addi 1
                // _ *peaks *leafs [remaining_leafs'] (i + 1)

                recurse

            // INVARIANT: _ [mt_index] [node]
            {climb}:
                dup 6 dup 6 push 0 push 1 {&DataType::U64.compare()}
                skiz return
                call {merkle_step}
                recurse

            // The parent's parts must hash to its hash, and its appendix must
            // contain this program's claim about its parent and transaction
            // mutator set. The parent mutator set hash is committed to in the
            // parent's transaction kernel MAST hash.
            // BEFORE: _ *w
            // AFTER:  _ *w
            {parent_contains_claim}:
                /* Verify correct witness data for parent block */
                dup 0 {&field!(KnowsMutatorSetWitness::prev_block_proof_leaf)} {&read_digest}
                push 0 push 0 push 0 push 0 push 0
                // _ *w [proof_leaf] [zero]

                dup 10 {&field_with_size!(KnowsMutatorSetWitness::prev_block_appendix)}
                call {hash_varlen}
                // _ *w [proof_leaf] [zero] [appendix_leaf]

                hash
                // _ *w [proof_leaf] [right_node]

                dup 10 {&field!(KnowsMutatorSetWitness::prev_block_body_mast_hash)} {&read_digest}
                call {hash_digest}
                // _ *w [proof_leaf] [right_node] [body_leaf]

                dup 15 {&field!(KnowsMutatorSetWitness::prev_block_header)}
                call {header_mast_hash}
                call {hash_digest}
                // _ *w [proof_leaf] [right_node] [body_leaf] [header_leaf]

                hash
                hash
                // _ *w [proof_leaf] [kernel_mast_hash]

                call {hash_digest}
                hash
                // _ *w [prev_block_hash]

                push {prev_block_digest_alloc.read_address()} read_mem {Digest::LEN} pop 1
                assert_vector error_id {Self::PARENT_MISMATCH_ERROR_ID}
                pop 5
                // _ *w

                /* Verify correct parent tx-kernel MAST hash */
                dup 0 {&field!(KnowsMutatorSetWitness::prev_block_body_mast_hash)} {&read_digest}
                push {BlockBody::MAST_HEIGHT}
                push {BlockBodyField::TransactionKernel.discriminant()}
                dup 7 {&field!(KnowsMutatorSetWitness::prev_block_txk_mast_hash)} {&read_digest}
                call {hash_digest}
                // _ *w [body_mast_hash] height leaf_index [txk_leaf]

                call {merkle_verify}
                // _ *w


                /* Verify correct parent mutator set hash */
                dup 0 {&field!(KnowsMutatorSetWitness::prev_block_txk_mast_hash)} {&read_digest}
                push {TransactionKernel::MAST_HEIGHT}
                push {TransactionKernelField::MutatorSetHash.discriminant()}
                dup 7 {&field!(KnowsMutatorSetWitness::prev_block_txk_mutator_set_hash)} {&read_digest}
                call {hash_digest}
                // _ *w [txk_mast_hash] height leaf_index [mutator_set_hash_leaf]

                call {merkle_verify}
                // _ *w

                /* Construct expected input of own claim in parent block */
                dup 0 {&field!(KnowsMutatorSetWitness::prev_block_header)}
                {&field!(BlockHeader::prev_block_digest)} {&read_digest}
                // _ *w [prev_block_digest]

                push {expected_input_alloc.write_address()} write_mem {Digest::LEN} pop 1
                // _ *w

                dup 0 {&field!(KnowsMutatorSetWitness::prev_block_txk_mutator_set_hash)} {&read_digest}
                push {expected_input_alloc.write_address()} addi {Digest::LEN}
                write_mem {Digest::LEN} pop 1

                // _ *w
                dup 0 {&field!(KnowsMutatorSetWitness::prev_block_appendix)}
                {&field!(BlockAppendix::claims)}
                read_mem 1 addi 2 place 1 push 0
                // _ *w *claim[0]_si num_claims 0

                /* Verify own claim was present in parent */
                call {find_own_claim}
                pop 3

                return

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
                pick 1 pop 1
                call {merkle_root}
                return

            // INVARIANT: _ *claim[i]_si num_claims i
            {find_own_claim}:
                dup 1 dup 1 eq
                push 0 eq assert error_id {BlockValidationRule::AppendixMissingClaim.error_id()}
                // _ *claim[i]_si num_claims i
                dup 2 addi 1 {&field!(Claim::program_digest)} {&read_digest}
                push {own_program_digest_alloc.read_address()} read_mem {Digest::LEN} pop 1
                {&digests_are_equal}
                dup 3 addi 1 {&field!(Claim::version)} read_mem 1 pop 1
                push {version} eq mul
                // _ *claim[i]_si num_claims i program_and_version_match
                dup 3 addi 1 {&field_with_size!(Claim::input)}
                // _ *claim[i]_si num_claims i program_and_version_match *input input_size
                // The size counts the length word the pointer points at.
                push {1 + Self::INPUT_LEN} eq
                pick 2 mul
                // _ *claim[i]_si num_claims i *input shape_matches
                dup 0 skiz call {input_matches}
                place 1 pop 1
                // _ *claim[i]_si num_claims i is_own_claim_about_parent
                skiz return
                pick 2 read_mem 1
                // _ num_claims i claim_size (*claim[i]_si - 1)
                // Crashes unless the size is a u32.
                dup 1 pop_count pop 1
                addi 2 add
                place 2 addi 1
                // _ *claim[i + 1]_si num_claims (i + 1)
                recurse

            // Whether the input of a claim of this program binds the
            // parent's parent, transaction mutator set and activation height.
            // BEFORE: _ *input 1
            // AFTER:  _ *input input_matches
            {input_matches}:
                pop 1
                dup 0 addi {Digest::LEN} read_mem {Digest::LEN} pop 1
                swap 4 swap 1 swap 3 swap 1
                // _ *input [prev_prev_block_digest_in_input]
                push {expected_input_alloc.write_address()} {&read_digest}
                {&digests_are_equal}
                // _ *input parent_matches
                dup 1 addi {2 * Digest::LEN} read_mem {Digest::LEN} pop 1
                swap 4 swap 1 swap 3 swap 1
                // _ *input parent_matches [mutator_set_hash_in_input]
                push {expected_input_alloc.write_address()} addi {Digest::LEN} {&read_digest}
                {&digests_are_equal}
                mul
                // _ *input parent_and_mutator_set_match
                dup 1 addi {Self::INPUT_LEN} read_mem 1 pop 1
                push {activation_height_alloc.read_address()} read_mem 1 pop 1
                eq mul
                // _ *input input_matches
                return

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
pub(super) mod tests {
    use neptune_mutator_set::shared::CHUNK_SIZE;
    use neptune_primitives::network::Network;
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::twenty_first::prelude::MerkleTree;
    use tasm_lib::twenty_first::prelude::Mmr;

    use super::*;
    use crate::proof_abstractions::tasm::builtins as tasm;
    use crate::proof_abstractions::tasm::program::spec::TritonProgramSpecification;
    use crate::proof_abstractions::tasm::program::tests::test_program_snapshot;

    impl TritonProgramSpecification for KnowsMutatorSet {
        fn source(&self) {
            let own_program_digest = tasm::own_program_digest();
            let prev_block_digest = tasm::tasmlib_io_read_stdin___digest();
            let witness: KnowsMutatorSetWitness =
                tasm::decode_from_memory(FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS);
            let mutator_set_hash = tasm::tasmlib_io_read_stdin___digest();
            assert_eq!(mutator_set_hash, witness.mutator_set.hash());
            let activation_height: BlockHeight = tasm::tasmlib_io_read_stdin___bfe().into();
            let chunk_leafs = witness.chunks.iter().map(Tip5::hash).collect();
            let mmrs = [
                (&witness.mutator_set.swbf_inactive, chunk_leafs),
                (&witness.mutator_set.aocl, witness.aocl_leafs.clone()),
            ];

            // For each MMR ...
            for (mmr, leafs) in mmrs {
                let leaf_indices = sampled_leafs(prev_block_digest, mmr.num_leafs());
                assert_eq!(leaf_indices.len(), leafs.len());

                // ... open a leaf in each Merkle tree.
                for (leaf_index, leaf) in leaf_indices.iter().zip(&leafs) {
                    assert!(tasm::mmr_verify_from_secret_in_leaf_index_on_stack(
                        &mmr.peaks(),
                        mmr.num_leafs(),
                        *leaf_index,
                        *leaf,
                    ));
                }
            }

            // Self-recursion: Verify presence of own claim in parent block.
            if witness.prev_block_header.height >= activation_height {
                let header_leaf = Tip5::hash(&witness.prev_block_header.mast_hash());
                let body_leaf = Tip5::hash(&witness.prev_block_body_mast_hash);
                let appendix_leaf = Tip5::hash_varlen(&witness.prev_block_appendix.encode());
                let kernel_mast_hash = Tip5::hash_pair(
                    Tip5::hash_pair(header_leaf, body_leaf),
                    Tip5::hash_pair(appendix_leaf, Digest::default()),
                );
                let prev_block_hash =
                    Tip5::hash_pair(Tip5::hash(&kernel_mast_hash), witness.prev_block_proof_leaf);
                assert_eq!(prev_block_digest, prev_block_hash);
                tasm::tasmlib_hashing_merkle_verify(
                    witness.prev_block_body_mast_hash,
                    BlockBodyField::TransactionKernel.discriminant() as u32,
                    Tip5::hash(&witness.prev_block_txk_mast_hash),
                    BlockBody::MAST_HEIGHT as u32,
                );
                tasm::tasmlib_hashing_merkle_verify(
                    witness.prev_block_txk_mast_hash,
                    TransactionKernelField::MutatorSetHash.discriminant() as u32,
                    Tip5::hash(&witness.prev_block_txk_mutator_set_hash),
                    TransactionKernel::MAST_HEIGHT as u32,
                );
                let version = ConsensusRuleSet::HardforkDelta
                    .triton_proof_version()
                    .version();
                let claim = Claim::new(own_program_digest)
                    .with_input(KnowsMutatorSet::claim_input(
                        witness.prev_block_header.prev_block_digest,
                        witness.prev_block_txk_mutator_set_hash,
                        activation_height,
                    ))
                    .about_version(version);
                assert!(witness.prev_block_appendix.contains(&claim));
            }
        }
    }

    /// An MMR held in full: one Merkle tree per peak over its leafs.
    pub(in crate::block::validity) struct KnownMmr {
        trees: Vec<MerkleTree>,
        pub(in crate::block::validity) leafs: Vec<Digest>,
    }

    impl KnownMmr {
        pub(in crate::block::validity) fn new(leafs: Vec<Digest>) -> Self {
            let num_leafs = leafs.len();
            let mut trees = vec![];
            let mut first_leaf = 0;
            for height in (0..64)
                .rev()
                .filter(|height| num_leafs & (1 << height) != 0)
            {
                let num_tree_leafs = 1 << height;
                let tree = MerkleTree::par_new(&leafs[first_leaf..first_leaf + num_tree_leafs]);
                trees.push(tree.unwrap());
                first_leaf += num_tree_leafs;
            }
            Self { trees, leafs }
        }

        pub(in crate::block::validity) fn random(rng: &mut StdRng, num_leafs: u64) -> Self {
            Self::new((0..num_leafs).map(|_| rng.random()).collect())
        }

        pub(in crate::block::validity) fn num_leafs(&self) -> u64 {
            u64::try_from(self.leafs.len()).unwrap()
        }

        pub(in crate::block::validity) fn accumulator(&self) -> MmrAccumulator {
            let peaks = self.trees.iter().map(MerkleTree::root).collect();
            MmrAccumulator::init(peaks, self.num_leafs())
        }

        /// The authentication path of this leaf, from the leaf up.
        pub(in crate::block::validity) fn path(&self, leaf_index: u64) -> Vec<Digest> {
            let mut local_index = usize::try_from(leaf_index).unwrap();
            for tree in &self.trees {
                if local_index < tree.num_leafs() {
                    let proof = tree.inclusion_proof_for_leaf_indices(&[local_index]);
                    return proof.unwrap().into_authentication_paths().unwrap()[0].clone();
                }
                local_index -= tree.num_leafs();
            }
            panic!("leaf index {leaf_index} is out of range");
        }
    }

    /// An inactive SWBF held in full, over random chunks.
    pub(in crate::block::validity) struct ArchivalSwbfi {
        pub(in crate::block::validity) mmr: KnownMmr,
        pub(in crate::block::validity) chunks: Vec<Chunk>,
    }

    impl ArchivalSwbfi {
        pub(in crate::block::validity) fn random(rng: &mut StdRng, num_leafs: u64) -> Self {
            let chunks = (0..num_leafs)
                .map(|_| {
                    let mut chunk = Chunk::empty_chunk();
                    for _ in 0..rng.random_range(0..20) {
                        chunk.insert(rng.random_range(0..CHUNK_SIZE));
                    }
                    chunk
                })
                .collect::<Vec<_>>();
            let mmr = KnownMmr::new(chunks.iter().map(Tip5::hash).collect());
            Self { mmr, chunks }
        }

        pub(in crate::block::validity) fn num_leafs(&self) -> u64 {
            self.mmr.num_leafs()
        }

        pub(in crate::block::validity) fn accumulator(&self) -> MmrAccumulator {
            self.mmr.accumulator()
        }

        pub(in crate::block::validity) fn chunk(&self, leaf_index: u64) -> &Chunk {
            &self.chunks[usize::try_from(leaf_index).unwrap()]
        }

        pub(in crate::block::validity) fn path(&self, leaf_index: u64) -> Vec<Digest> {
            self.mmr.path(leaf_index)
        }
    }

    const RULE_SET: ConsensusRuleSet = ConsensusRuleSet::HardforkDelta;

    /// A parent block at this height, distinct per seed, whose appendix
    /// contains these claims.
    fn parent(rng: &mut StdRng, height: u64, claims: Vec<Claim>) -> Block {
        let mut block = Block::genesis(Network::Main);
        block.kernel_mut().header.height = height.into();
        block.kernel_mut().header.prev_block_digest = rng.random();
        block.set_appendix(BlockAppendix::new(claims));
        block
    }

    /// The claim this parent must contain from the activation height on.
    fn claim_of(parent: &Block, activation_height: BlockHeight) -> Claim {
        KnowsMutatorSet::claim_about_hash(
            parent.header().prev_block_digest,
            parent.body().transaction_kernel.mutator_set_hash,
            activation_height,
            RULE_SET,
        )
    }

    /// A parent at this height containing its claim.
    fn parent_with_claim(rng: &mut StdRng, height: u64, activation_height: BlockHeight) -> Block {
        let mut block = parent(rng, height, vec![]);
        let claim = claim_of(&block, activation_height);
        block.set_appendix(BlockAppendix::new(vec![claim]));
        block
    }

    /// The witness a composer with this mutator set holds for a block on
    /// the parent.
    fn witness(
        prev_block: &Block,
        swbfi: &ArchivalSwbfi,
        aocl: &KnownMmr,
        activation_height: BlockHeight,
    ) -> KnowsMutatorSetWitness {
        let mutator_set = MutatorSetAccumulator {
            aocl: aocl.accumulator(),
            swbf_inactive: swbfi.accumulator(),
            ..Default::default()
        };
        let chunk_indices = sampled_leafs(prev_block.hash(), swbfi.num_leafs());
        let aocl_indices = sampled_leafs(prev_block.hash(), aocl.num_leafs());
        KnowsMutatorSetWitness::new(
            prev_block,
            &mutator_set,
            activation_height,
            chunk_indices
                .iter()
                .map(|&i| swbfi.chunk(i).clone())
                .collect(),
            chunk_indices.iter().map(|&i| swbfi.path(i)).collect(),
            aocl_indices
                .iter()
                .map(|&i| aocl.leafs[usize::try_from(i).unwrap()])
                .collect(),
            aocl_indices.iter().map(|&i| aocl.path(i)).collect(),
        )
    }

    /// A witness on a parent at height 5 that contains its claim, under an
    /// activation height the parent has reached.
    fn witness_on_activated_parent(rng: &mut StdRng) -> KnowsMutatorSetWitness {
        let swbfi = ArchivalSwbfi::random(rng, 35);
        let aocl = KnownMmr::random(rng, 100);
        let activation_height = BlockHeight::from(5u64);
        let prev_block = parent_with_claim(rng, 5, activation_height);
        witness(&prev_block, &swbfi, &aocl, activation_height)
    }

    fn assert_accepts(witness: &KnowsMutatorSetWitness) {
        let input = witness.standard_input();
        let rust_output = KnowsMutatorSet
            .run_rust(&input, witness.nondeterminism())
            .unwrap();
        let tasm_output = KnowsMutatorSet
            .run_tasm(&input, witness.nondeterminism())
            .unwrap();
        assert!(rust_output.is_empty());
        assert_eq!(rust_output, tasm_output);
    }

    fn assert_rejects(witness: &KnowsMutatorSetWitness, error_id: i128) {
        KnowsMutatorSet
            .test_assertion_failure(
                witness.standard_input(),
                witness.nondeterminism(),
                &[error_id],
            )
            .unwrap();
    }

    #[test]
    fn num_sampled_leafs_matches_num_peaks() {
        for leaf_count in 0..22 {
            let leafs = sampled_leafs(Digest::default(), leaf_count);
            assert_eq!(leaf_count.count_ones() as usize, leafs.len());
        }
    }

    #[test]
    fn sampled_leafs_of_any_trees_are_accepted() {
        let mut rng = StdRng::seed_from_u64(0);
        let activation_height = BlockHeight::from(6u64);
        for swbfi_leafs in [0, 1, 2, 3, 7, 8, 35] {
            let swbfi = ArchivalSwbfi::random(&mut rng, swbfi_leafs);
            for aocl_leafs in [0, 1, 4, 100] {
                let aocl = KnownMmr::random(&mut rng, aocl_leafs);
                for _ in 0..2 {
                    let prev_block = parent(&mut rng, 5, vec![]);
                    assert_accepts(&witness(&prev_block, &swbfi, &aocl, activation_height));
                }
            }
        }
    }

    #[test]
    fn samples_pick_one_leaf_per_tree_and_cover_every_leaf() {
        let mut rng = StdRng::seed_from_u64(1);
        // Eleven leafs: trees of eight, two and one leafs.
        let mut sampled = [false; 11];
        for _ in 0..300 {
            let leaf_indices = sampled_leafs(rng.random(), 11);
            assert_eq!(3, leaf_indices.len());
            assert!(leaf_indices[0] < 8);
            assert!((8..10).contains(&leaf_indices[1]));
            assert_eq!(10, leaf_indices[2]);
            for leaf_index in leaf_indices {
                sampled[usize::try_from(leaf_index).unwrap()] = true;
            }
        }
        assert!(sampled.iter().all(|&leaf| leaf));
        assert!(sampled_leafs(rng.random(), 0).is_empty());
    }

    #[test]
    fn mutator_set_other_than_the_claim_binds_is_rejected() {
        let mut rng = StdRng::seed_from_u64(2);
        let witness = witness_on_activated_parent(&mut rng);
        let mut input = witness.standard_input();
        input.individual_tokens[Digest::LEN] += bfe!(1);
        KnowsMutatorSet
            .test_assertion_failure(
                input,
                witness.nondeterminism(),
                &[KnowsMutatorSet::MUTATOR_SET_MISMATCH_ERROR_ID],
            )
            .unwrap();
    }

    #[test]
    fn other_chunk_leaf_or_path_is_rejected() {
        let mut rng = StdRng::seed_from_u64(3);
        let activation_height = BlockHeight::from(6u64);
        for (swbfi_leafs, aocl_leafs) in [(1, 1), (2, 3), (35, 100)] {
            let swbfi = ArchivalSwbfi::random(&mut rng, swbfi_leafs);
            let aocl = KnownMmr::random(&mut rng, aocl_leafs);
            let prev_block = parent(&mut rng, 5, vec![]);
            let honest = witness(&prev_block, &swbfi, &aocl, activation_height);

            for chunk in 0..honest.chunks.len() {
                let mut other_chunk = honest.clone();
                other_chunk.chunks[chunk].insert(rng.random_range(0..CHUNK_SIZE));
                assert_rejects(&other_chunk, KnowsMutatorSet::WRONG_LEAF_ERROR_ID);
            }

            for leaf in 0..honest.aocl_leafs.len() {
                let mut other_aocl_leaf = honest.clone();
                other_aocl_leaf.aocl_leafs[leaf] = rng.random();
                assert_rejects(&other_aocl_leaf, KnowsMutatorSet::WRONG_LEAF_ERROR_ID);
            }

            let num_leafs = honest.chunks.len() + honest.aocl_leafs.len();
            for path in 0..num_leafs {
                if honest.paths[path].is_empty() {
                    continue;
                }
                let mut other_path = honest.clone();
                other_path.paths[path][0] = rng.random();
                assert_rejects(&other_path, KnowsMutatorSet::WRONG_LEAF_ERROR_ID);
            }

            let mut missing_chunk = honest.clone();
            missing_chunk.chunks.pop();
            assert_rejects(
                &missing_chunk,
                KnowsMutatorSet::LEAF_COUNT_MISMATCH_ERROR_ID,
            );

            let mut extra_aocl_leaf = honest.clone();
            extra_aocl_leaf.aocl_leafs.push(rng.random());
            assert_rejects(
                &extra_aocl_leaf,
                KnowsMutatorSet::LEAF_COUNT_MISMATCH_ERROR_ID,
            );
        }
    }

    #[test]
    fn leafs_sampled_by_another_parent_are_rejected() {
        let mut rng = StdRng::seed_from_u64(4);
        let swbfi = ArchivalSwbfi::random(&mut rng, 35);
        let aocl = KnownMmr::random(&mut rng, 100);
        let activation_height = BlockHeight::from(6u64);
        let honest = witness(
            &parent(&mut rng, 5, vec![]),
            &swbfi,
            &aocl,
            activation_height,
        );
        let other_parent: Digest = rng.random();
        assert_ne!(
            sampled_leafs(honest.prev_block_digest, 100),
            sampled_leafs(other_parent, 100)
        );
        let mut witness = honest;
        witness.prev_block_digest = other_parent;
        assert_rejects(&witness, KnowsMutatorSet::WRONG_LEAF_ERROR_ID);
    }

    #[test]
    fn parent_from_the_activation_height_on_must_contain_the_claim() {
        let mut rng = StdRng::seed_from_u64(5);
        let swbfi = ArchivalSwbfi::random(&mut rng, 35);
        let aocl = KnownMmr::random(&mut rng, 100);
        for (height, activation_height) in [(5, 5), (6, 5), (1 << 40, 0)] {
            let activation_height = BlockHeight::from(activation_height);
            let containing = parent_with_claim(&mut rng, height, activation_height);
            assert_accepts(&witness(&containing, &swbfi, &aocl, activation_height));
            let empty = parent(&mut rng, height, vec![]);
            assert_rejects(
                &witness(&empty, &swbfi, &aocl, activation_height),
                BlockValidationRule::AppendixMissingClaim.error_id(),
            );
        }
        let before = parent(&mut rng, 4, vec![]);
        assert_accepts(&witness(&before, &swbfi, &aocl, BlockHeight::from(5u64)));
    }

    #[test]
    fn claim_about_other_parent_mutator_set_or_activation_height_is_rejected() {
        let mut rng = StdRng::seed_from_u64(6);
        let swbfi = ArchivalSwbfi::random(&mut rng, 35);
        let aocl = KnownMmr::random(&mut rng, 100);
        let activation_height = BlockHeight::from(5u64);
        let honest = parent_with_claim(&mut rng, 5, activation_height);
        let claim = claim_of(&honest, activation_height);
        for word in [0, Digest::LEN, 2 * Digest::LEN] {
            let mut other = claim.clone();
            other.input[word] += bfe!(1);
            let mut prev_block = honest.clone();
            prev_block.set_appendix(BlockAppendix::new(vec![other]));
            assert_rejects(
                &witness(&prev_block, &swbfi, &aocl, activation_height),
                BlockValidationRule::AppendixMissingClaim.error_id(),
            );
        }
    }

    #[test]
    fn parent_parts_not_hashing_to_the_parent_are_rejected() {
        let mut rng = StdRng::seed_from_u64(7);
        let honest = witness_on_activated_parent(&mut rng);
        let mut other_header = honest.clone();
        other_header.prev_block_header.timestamp.0 += bfe!(1);
        let mut other_body = honest.clone();
        other_body.prev_block_body_mast_hash = rng.random();
        let mut other_appendix = honest.clone();
        other_appendix.prev_block_appendix = BlockAppendix::new(vec![]);
        let mut other_proof = honest.clone();
        other_proof.prev_block_proof_leaf = rng.random();
        for other in [other_header, other_body, other_appendix, other_proof] {
            assert_rejects(&other, KnowsMutatorSet::PARENT_MISMATCH_ERROR_ID);
        }
    }

    #[test]
    fn mast_paths_not_reaching_the_parent_are_rejected() {
        let mut rng = StdRng::seed_from_u64(8);
        let honest = witness_on_activated_parent(&mut rng);
        let mut other_kernel = honest.clone();
        other_kernel.prev_block_txk_mast_hash = rng.random();
        let mut other_mutator_set_hash = honest.clone();
        other_mutator_set_hash.prev_block_txk_mutator_set_hash = rng.random();
        let num_leafs = honest.chunks.len() + honest.aocl_leafs.len();
        let mut other_body_path = honest.clone();
        other_body_path.paths[num_leafs][0] = rng.random();
        let mut other_kernel_path = honest.clone();
        other_kernel_path.paths[num_leafs + 1][0] = rng.random();
        for other in [
            other_kernel,
            other_mutator_set_hash,
            other_body_path,
            other_kernel_path,
        ] {
            assert_rejects(&other, MerkleVerify::ROOT_MISMATCH_ERROR_ID);
        }
    }

    #[test]
    fn claim_is_the_witness_claim_with_the_proof_version() {
        let mut rng = StdRng::seed_from_u64(9);
        let witness = witness_on_activated_parent(&mut rng);
        let claim = KnowsMutatorSet::claim(
            witness.prev_block_digest,
            &witness.mutator_set,
            witness.activation_height,
            RULE_SET,
        );
        let expected = witness
            .claim()
            .about_version(RULE_SET.triton_proof_version().version());
        assert_eq!(expected, claim);
    }

    test_program_snapshot!(
        KnowsMutatorSet,
        "e832cc56aa9b4454c966eab1730a6d202890c2d7e2765328f55b5e121f4a2d8e704d6e274b0edc6d"
    );
}
