//! The composer's proof that it holds the parent block's extra data: for a
//! sample of the parent's inputs, the chunks of the inactive SWBF those
//! inputs' indices lie in, with their membership in the mutator set the
//! parent's transaction is built on. The parent's hash picks the sample, so
//! the composer cannot choose it. With the SWBF update claim, which binds
//! the chunk data of a block's own inputs, this binds it one block deeper.
//!
//! The claim is self-recursive: from the activation height on, the parent's
//! appendix must contain the claim about its own parent. The program checks
//! presence only, the parent's block proof having settled the claim's
//! truth.

use std::sync::OnceLock;

use get_size2::GetSize;
use itertools::Itertools;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_mutator_set::removal_record::chunk::Chunk;
use neptune_mutator_set::removal_record::removal_record_list::RemovalRecordList;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_primitives::block_height::BlockHeight;
use neptune_primitives::mast_hash::HasDiscriminant;
use neptune_primitives::mast_hash::MastHash;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::arithmetic::u64::lt::Lt as U64Lt;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::hashing::hash_from_stack::HashFromStack;
use tasm_lib::hashing::merkle_root::MerkleRoot;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::list::new::New;
use tasm_lib::list::push::Push;
use tasm_lib::memory::dyn_malloc::DynMalloc;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::memcpy::MemCpy;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::mmr::verify_from_secret_in_leaf_index_on_stack::MmrVerifyFromSecretInLeafIndexOnStack;
use tasm_lib::prelude::*;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;
use tasm_lib::verifier::own_program_digest::OwnProgramDigest;

use super::mutator_set_hash::MutatorSetHash;
use super::swbf_update::chunk_insertions::ChunkInsertions;
use super::swbf_update::divined_chunk_indices::DivinedChunkIndices;
use crate::block::block_appendix::BlockAppendix;
use crate::block::block_body::BlockBody;
use crate::block::block_body::BlockBodyField;
use crate::block::block_extra_data::BlockExtraData;
use crate::block::block_extra_data::BlockExtraDataError;
use crate::block::block_header::BlockHeader;
use crate::block::block_validation_error::BlockValidationRule;
use crate::block::Block;
use crate::block::BlockField;
use crate::consensus_rule_set::ConsensusRuleSet;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::proof_abstractions::SecretWitness;
use crate::transaction::transaction_kernel::TransactionKernel;
use crate::transaction::transaction_kernel::TransactionKernelField;

/// How many of the parent's inputs the claim samples, at most.
pub const NUM_SAMPLES: usize = 12;

/// The seed of sample `j`: the low 32 bits of the first word of the hash of
/// the parent's hash and `j`.
fn seed(prev_block_digest: Digest, j: usize) -> u64 {
    let preimage = [prev_block_digest.values().to_vec(), vec![bfe!(j as u64)]].concat();
    Tip5::hash_varlen(&preimage).values()[0].value() & u64::from(u32::MAX)
}

/// The positions of the inputs a parent with this hash and this many inputs
/// samples, ascending: all of them if there are at most [`NUM_SAMPLES`];
/// otherwise one per stretch of `num_inputs / NUM_SAMPLES` inputs, at an
/// offset the parent's hash picks.
pub fn sampled_inputs(prev_block_digest: Digest, num_inputs: usize) -> Vec<usize> {
    let stride = (num_inputs / NUM_SAMPLES).max(1);
    (0..num_inputs.min(NUM_SAMPLES))
        .map(|j| j * stride + (seed(prev_block_digest, j) % stride as u64) as usize)
        .collect()
}

/// The part of the witness the program reads from memory, audited.
#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize, TasmObject)]
pub struct KnowsBlockExtraDataMemory {
    /// The mutator set the parent's transaction is built on.
    mutator_set: MutatorSetAccumulator,

    /// The chunks of the inactive SWBF the sampled inputs' indices lie in,
    /// in ascending chunk index.
    chunks: Vec<Chunk>,

    /// The number of words of the encoding of the parent's transaction
    /// inputs, which follows this object in memory, unaudited: its hash
    /// binds it.
    prev_block_inputs_len: u32,

    /// The parent block's parts: its header, body hash, appendix and the
    /// hash of its proof, and its transaction kernel's hash.
    prev_block_header: BlockHeader,
    prev_block_body_mast_hash: Digest,
    prev_block_appendix: BlockAppendix,
    prev_block_proof_leaf: Digest,
    prev_block_txk_mast_hash: Digest,
}

/// Witness data to prove that the composer knows the parent's extra data.
#[derive(Debug, Clone)]
pub struct KnowsBlockExtraDataWitness {
    prev_block_digest: Digest,
    activation_height: BlockHeight,
    memory: KnowsBlockExtraDataMemory,

    /// The parent's transaction inputs exactly as its kernel commits to them:
    /// packed, and under zeta without chunk data. The program hashes them to
    /// authenticate them against the kernel and reads the sampled inputs'
    /// index sets from them.
    prev_block_inputs: Vec<RemovalRecord>,

    /// The authentication paths of the transaction kernel in the parent's
    /// body, of the inputs and the mutator set hash in that kernel, then of
    /// the chunks.
    digests: Vec<Digest>,

    /// The sampled chunk indices, then the chunk insertions' tokens.
    tokens: Vec<BFieldElement>,
}

impl KnowsBlockExtraDataWitness {
    /// For a block on the parent, whose inputs `full_inputs` are, with their
    /// chunk data, in the order of its kernel's inputs, synced to
    /// `mutator_set`: the parent's extra data rebuilt.
    pub fn new(
        prev_block: &Block,
        mutator_set: &MutatorSetAccumulator,
        full_inputs: &[RemovalRecord],
        activation_height: BlockHeight,
    ) -> Self {
        let body = prev_block.body();
        let kernel = &body.transaction_kernel;
        let positions = sampled_inputs(prev_block.hash(), kernel.inputs.len());
        let sampled = positions
            .iter()
            .map(|&i| kernel.inputs[i].clone())
            .collect_vec();
        let leaf_count = mutator_set.swbf_inactive.num_leafs();
        let chunk_indices = ChunkInsertions::chunk_indices_below(&sampled, leaf_count);
        Self::with_chunk_indices(
            prev_block,
            mutator_set,
            full_inputs,
            activation_height,
            &chunk_indices,
        )
    }

    /// Construct the witness from the parent bloc, and parent block extra data.
    pub fn from_extra_data(
        prev_block: &Block,
        mutator_set: &MutatorSetAccumulator,
        extra_data: &BlockExtraData,
        activation_height: BlockHeight,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Result<Self, BlockExtraDataError> {
        let inputs = RemovalRecordList::try_unpack(
            prev_block.body().transaction_kernel.inputs.clone(),
            consensus_rule_set.allow_big_chunks(),
        )?;
        let full_inputs =
            extra_data.try_rebuild_unsafe(&inputs, mutator_set, consensus_rule_set)?;

        Ok(Self::new(
            prev_block,
            mutator_set,
            &full_inputs,
            activation_height,
        ))
    }

    /// As [`Self::new`], with these chunk indices instead of the ones the
    /// sampled inputs' indices lie in.
    fn with_chunk_indices(
        prev_block: &Block,
        mutator_set: &MutatorSetAccumulator,
        full_inputs: &[RemovalRecord],
        activation_height: BlockHeight,
        chunk_indices: &[u64],
    ) -> Self {
        let body = prev_block.body();
        let kernel = &body.transaction_kernel;
        let positions = sampled_inputs(prev_block.hash(), kernel.inputs.len());
        let sampled = positions
            .iter()
            .map(|&i| kernel.inputs[i].clone())
            .collect_vec();
        let leaf_count = mutator_set.swbf_inactive.num_leafs();
        let authenticated_chunks = chunk_indices
            .iter()
            .map(|chunk_index| {
                positions
                    .iter()
                    .find_map(|&i| full_inputs[i].target_chunks.get(chunk_index))
                    .expect("full inputs must hold every chunk their indices lie in")
                    .clone()
            })
            .collect_vec();

        let digests = [
            body.mast_path(BlockBodyField::TransactionKernel),
            kernel.mast_path(TransactionKernelField::Inputs),
            kernel.mast_path(TransactionKernelField::MutatorSetHash),
        ]
        .into_iter()
        .chain(
            authenticated_chunks
                .iter()
                .map(|(path, _)| path.authentication_path.clone()),
        )
        .concat();
        let tokens = [
            DivinedChunkIndices::divined_tokens(chunk_indices),
            ChunkInsertions::divined_tokens(&sampled, chunk_indices, leaf_count),
        ]
        .concat();

        let memory = KnowsBlockExtraDataMemory {
            mutator_set: mutator_set.clone(),
            chunks: authenticated_chunks
                .into_iter()
                .map(|(_, chunk)| chunk)
                .collect(),
            prev_block_inputs_len: u32::try_from(kernel.inputs.encode().len())
                .expect("inputs encoding must fit in memory"),
            prev_block_header: *prev_block.header(),
            prev_block_body_mast_hash: body.mast_hash(),
            prev_block_appendix: prev_block.appendix().clone(),
            prev_block_proof_leaf: prev_block.mast_path(BlockField::Kernel)[0],
            prev_block_txk_mast_hash: kernel.mast_hash(),
        };
        Self {
            prev_block_digest: prev_block.hash(),
            activation_height,
            memory,
            prev_block_inputs: kernel.inputs.clone(),
            digests,
            tokens,
        }
    }
}

impl KnowsBlockExtraDataWitness {
    /// The number of chunks the sampled inputs' indices lie in.
    pub fn num_chunks(&self) -> usize {
        self.memory.chunks.len()
    }
}

impl SecretWitness for KnowsBlockExtraDataWitness {
    fn standard_input(&self) -> PublicInput {
        PublicInput::new(KnowsBlockExtraData::claim_input(
            self.prev_block_digest,
            self.activation_height,
        ))
    }

    fn output(&self) -> Vec<BFieldElement> {
        vec![]
    }

    fn program(&self) -> Program {
        KnowsBlockExtraData.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        let mut nondeterminism = NonDeterminism::default();
        let inputs_address = encode_to_memory(
            &mut nondeterminism.ram,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            &self.memory,
        );
        encode_to_memory(
            &mut nondeterminism.ram,
            inputs_address,
            &self.prev_block_inputs,
        );
        nondeterminism.digests = self.digests.clone();
        nondeterminism.individual_tokens = self.tokens.clone();
        nondeterminism
    }
}

/// Input:
/// - the parent block's hash (5 words)
/// - the activation height: the first height at which a block must contain
///   the claim (1 word)
///
/// Output: none.
///
/// Divines the parent's parts, which must hash to its hash, its transaction
/// kernel's inputs and the mutator set that kernel is built on. Samples
/// [`NUM_SAMPLES`] of the inputs, at the positions [`sampled_inputs`] gives,
/// and divines the chunks of the inactive SWBF their indices lie in, which
/// must be members of the mutator set's inactive SWBF. For a parent at or
/// past the activation height, finds this program's claim about the
/// parent's parent in the parent's appendix.
#[derive(
    Debug, Clone, Copy, Default, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize,
)]
pub struct KnowsBlockExtraData;

impl KnowsBlockExtraData {
    const PARENT_MISMATCH_ERROR_ID: i128 = 1_000_620;

    const INPUT_LEN: usize = Digest::LEN + 1;

    pub fn claim_input(
        prev_block_digest: Digest,
        activation_height: BlockHeight,
    ) -> Vec<BFieldElement> {
        [
            prev_block_digest.reversed().values().to_vec(),
            vec![activation_height.into()],
        ]
        .concat()
    }

    /// The claim a block whose parent has this hash must contain from the
    /// activation height on.
    pub fn claim(
        prev_block_digest: Digest,
        activation_height: BlockHeight,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Claim {
        Claim::new(Self.hash())
            .with_input(Self::claim_input(prev_block_digest, activation_height))
            .about_version(consensus_rule_set.triton_proof_version().version())
    }
}

impl TritonProgram for KnowsBlockExtraData {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        let mut library = Library::new();
        let audit_memory = library.import(Box::new(
            VerifyNdSiIntegrity::<KnowsBlockExtraDataMemory>::default(),
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
        let dyn_malloc = library.import(Box::new(DynMalloc));
        let memcpy = library.import(Box::new(MemCpy));
        let divined_chunk_indices = library.import(Box::new(DivinedChunkIndices));
        let chunk_insertions = library.import(Box::new(ChunkInsertions));
        let mmr_verify = library.import(Box::new(MmrVerifyFromSecretInLeafIndexOnStack));

        let prev_block_digest_alloc = library.kmalloc(Digest::LEN as u32);
        // The parent's hash and a sample's number: the preimage of the
        // sample's seed.
        let seed_alloc = library.kmalloc(Digest::LEN as u32 + 1);
        let activation_height_alloc = library.kmalloc(1);
        let own_program_digest_alloc = library.kmalloc(Digest::LEN as u32);
        let inputs_alloc = library.kmalloc(1);
        let stride_alloc = library.kmalloc(1);
        let chunk_indices_alloc = library.kmalloc(1);
        let leaf_count_alloc = library.kmalloc(2);
        // The parent's parent's hash: the input of the claim the parent must
        // contain, with the activation height.
        let expected_input_alloc = library.kmalloc(Digest::LEN as u32);

        let version = ConsensusRuleSet::HardforkDelta
            .triton_proof_version()
            .version();
        let read_digest = triton_asm!(addi {Digest::LEN - 1} read_mem {Digest::LEN} pop 1);
        let read_word = |alloc: &tasm_lib::library::StaticAllocation| triton_asm!(push {alloc.read_address()} read_mem 1 pop 1);
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

        let label = |name: &str| format!("knows_block_extra_data_{name}");
        let authenticate_parent = label("authenticate_parent");
        let authenticate_kernel = label("authenticate_kernel");
        let header_mast_hash = label("header_mast_hash");
        let sample_inputs = label("sample_inputs");
        let samples_loop = label("samples_loop");
        let seed = label("seed");
        let advance = label("advance");
        let verify_chunks_loop = label("verify_chunks_loop");
        let parent_contains_claim = label("parent_contains_claim");
        let find_own_claim = label("find_own_claim");
        let input_matches = label("input_matches");

        let code = triton_asm!(
            // _
            call {own_program_digest}
            push {own_program_digest_alloc.write_address()} write_mem {Digest::LEN} pop 1

            read_io {Digest::LEN}
            // _ [prev_block_digest]
            dup 4 dup 4 dup 4 dup 4 dup 4
            push {seed_alloc.write_address()} write_mem {Digest::LEN} pop 1
            push {prev_block_digest_alloc.write_address()} write_mem {Digest::LEN} pop 1
            // _

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            hint memory = stack[0]
            dup 0 call {audit_memory}
            // _ *m memory_size

            // The parent's inputs follow the audited memory.
            dup 1 add
            push {inputs_alloc.write_address()} write_mem 1 pop 1
            // _ *m

            read_io 1
            push {activation_height_alloc.write_address()} write_mem 1 pop 1
            // _ *m

            call {authenticate_parent}
            call {authenticate_kernel}
            // _ *m

            call {sample_inputs}
            // _ *m *records

            dup 1 {&field!(KnowsBlockExtraDataMemory::chunks)} read_mem 1 pop 1
            call {divined_chunk_indices}
            // _ *m *records *chunk_indices

            dup 0 push {chunk_indices_alloc.write_address()} write_mem 1 pop 1
            dup 2 {&field!(KnowsBlockExtraDataMemory::mutator_set)}
            {&field!(MutatorSetAccumulator::swbf_inactive)}
            {&field!(MmrAccumulator::leaf_count)} addi 1 read_mem 2 pop 1
            // _ *m *records *chunk_indices [leaf_count]

            dup 1 dup 1 push {leaf_count_alloc.write_address()} write_mem 2 pop 1
            call {chunk_insertions}
            pop 1
            // _ *m

            dup 0 {&field!(KnowsBlockExtraDataMemory::mutator_set)}
            {&field!(MutatorSetAccumulator::swbf_inactive)}
            {&field!(MmrAccumulator::peaks)}
            {&read_word(&chunk_indices_alloc)} addi 1
            dup 2 {&field!(KnowsBlockExtraDataMemory::chunks)}
            read_mem 1 addi 2 swap 1
            // _ *m *peaks *chunk_index[0] *chunk[0]_si num_chunks

            call {verify_chunks_loop}
            pop 4
            // _ *m

            {&read_word(&activation_height_alloc)} split
            dup 2 {&field!(KnowsBlockExtraDataMemory::prev_block_header)}
            {&field!(BlockHeader::height)} read_mem 1 pop 1 split
            // _ *m [activation_height] [prev_block_height]
            call {u64_lt}
            push 0 eq
            // _ *m (prev_block_height >= activation_height)
            skiz call {parent_contains_claim}

            pop 1
            halt

            // The parent's parts must hash to its hash.
            // BEFORE: _ *m
            // AFTER:  _ *m
            {authenticate_parent}:
                dup 0 {&field!(KnowsBlockExtraDataMemory::prev_block_proof_leaf)} {&read_digest}
                push 0 push 0 push 0 push 0 push 0
                // _ *m [proof_leaf] [zero]

                dup 10 {&field_with_size!(KnowsBlockExtraDataMemory::prev_block_appendix)}
                call {hash_varlen}
                hash
                // _ *m [proof_leaf] [right_node]

                dup 10 {&field!(KnowsBlockExtraDataMemory::prev_block_body_mast_hash)} {&read_digest}
                call {hash_digest}
                // _ *m [proof_leaf] [right_node] [body_leaf]

                dup 15 {&field!(KnowsBlockExtraDataMemory::prev_block_header)}
                call {header_mast_hash}
                call {hash_digest}
                // _ *m [proof_leaf] [right_node] [body_leaf] [header_leaf]

                hash
                hash
                // _ *m [proof_leaf] [kernel_mast_hash]

                call {hash_digest}
                hash
                // _ *m [prev_block_hash]

                push {prev_block_digest_alloc.read_address()} read_mem {Digest::LEN} pop 1
                assert_vector error_id {Self::PARENT_MISMATCH_ERROR_ID}
                pop 5
                return

            // The parent's transaction kernel must be in its body, and the
            // divined inputs and mutator set must be in that kernel.
            // BEFORE: _ *m
            // AFTER:  _ *m
            {authenticate_kernel}:
                dup 0 {&field!(KnowsBlockExtraDataMemory::prev_block_body_mast_hash)} {&read_digest}
                push {BlockBody::MAST_HEIGHT}
                push {BlockBodyField::TransactionKernel.discriminant()}
                dup 7 {&field!(KnowsBlockExtraDataMemory::prev_block_txk_mast_hash)} {&read_digest}
                call {hash_digest}
                call {merkle_verify}
                // _ *m

                dup 0 {&field!(KnowsBlockExtraDataMemory::prev_block_txk_mast_hash)} {&read_digest}
                push {TransactionKernel::MAST_HEIGHT}
                push {TransactionKernelField::Inputs.discriminant()}
                {&read_word(&inputs_alloc)}
                dup 8 {&field!(KnowsBlockExtraDataMemory::prev_block_inputs_len)} read_mem 1 pop 1
                call {hash_varlen}
                call {merkle_verify}
                // _ *m

                dup 0 {&field!(KnowsBlockExtraDataMemory::prev_block_txk_mast_hash)} {&read_digest}
                push {TransactionKernel::MAST_HEIGHT}
                push {TransactionKernelField::MutatorSetHash.discriminant()}
                dup 7 {&field!(KnowsBlockExtraDataMemory::mutator_set)}
                call {mutator_set_hash}
                call {hash_digest}
                call {merkle_verify}
                // _ *m
                return

            // BEFORE: _ *header
            // AFTER:  _ [header_mast_hash]
            {header_mast_hash}:
                call {new_list}
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

            // A list of copies of the sampled inputs, in the order of their
            // positions.
            // BEFORE: _
            // AFTER:  _ *records
            {sample_inputs}:
                {&read_word(&inputs_alloc)}
                read_mem 1 addi 2 swap 1
                // _ *record[0]_si num_inputs

                // The stride: num_inputs / NUM_SAMPLES, at least 1.
                dup 0 push {NUM_SAMPLES} swap 1 div_mod pop 1
                dup 0 push 0 eq add
                push {stride_alloc.write_address()} write_mem 1 pop 1
                // _ *record[0]_si num_inputs

                // The number of samples: min(num_inputs, NUM_SAMPLES).
                push {NUM_SAMPLES} dup 1 lt
                dup 0 push -1 mul addi 1 push {NUM_SAMPLES} mul
                place 2 mul add
                // _ *record[0]_si num_samples

                call {dyn_malloc}
                dup 1 dup 1 write_mem 1
                // _ *record[0]_si num_samples *records *free

                pick 3 pick 3 push 0 push 0 pick 2
                // _ *records *free *record[0]_si 0 0 num_samples
                call {samples_loop}
                pop 5
                // _ *records
                return

            // INVARIANT: _ *records *free *record[i]_si i j num_samples
            {samples_loop}:
                dup 1 dup 1 eq skiz return

                dup 1 call {seed}
                {&read_word(&stride_alloc)} swap 1 div_mod swap 1 pop 1
                dup 2 {&read_word(&stride_alloc)} mul add
                // _ *records *free *record[i]_si i j num_samples position

                pick 4 pick 4
                call {advance}
                pop 1
                // _ *records *free j num_samples position *record[position]_si

                dup 0 read_mem 1 pop 1 addi 1
                dup 1 dup 6 dup 2
                call {memcpy}
                // _ *records *free j num_samples position *record_si num_words

                pick 5 add place 4
                // _ *records *free' j num_samples position *record_si

                place 3 place 2
                pick 1 addi 1 place 1
                // _ *records *free' *record_si position (j + 1) num_samples
                recurse

            // The seed of sample j.
            // BEFORE: _ j
            // AFTER:  _ seed
            {seed}:
                push {seed_alloc.write_address() + bfe!(Digest::LEN as u64)}
                write_mem 1 pop 1
                push {seed_alloc.write_address()} push {Digest::LEN + 1}
                call {hash_varlen}
                swap 4 pop 4
                split swap 1 pop 1
                return

            // INVARIANT: _ position *record[i]_si i
            {advance}:
                dup 0 dup 3 eq skiz return
                pick 1 read_mem 1 addi 2 add
                place 1 addi 1
                recurse

            // INVARIANT: _ *peaks *chunk_index[k] *chunk[k]_si remaining
            {verify_chunks_loop}:
                dup 0 push 0 eq skiz return
                dup 1 read_mem 1
                // _ *peaks *chunk_index[k] *chunk[k]_si remaining chunk_size (*chunk[k]_si - 1)

                // Crashes unless the size is a u32.
                dup 1 pop_count pop 1
                addi 2 dup 1 call {hash_varlen}
                // _ *peaks *chunk_index[k] *chunk[k]_si remaining chunk_size [leaf]

                dup 9 place 5
                push {leaf_count_alloc.read_address()} read_mem 2 pop 1
                dup 11 addi 1 read_mem 2 pop 1
                // _ *peaks *chunk_index[k] *chunk[k]_si remaining chunk_size
                //   *peaks [leaf] [leaf_count] [chunk_index]
                call {mmr_verify}
                // _ *peaks *chunk_index[k] *chunk[k]_si remaining chunk_size

                pick 2 add addi 1
                swap 1 addi -1
                pick 2 addi 2 place 2
                // _ *peaks *chunk_index[k + 1] *chunk[k + 1]_si (remaining - 1)
                recurse

            // The parent's appendix must contain this program's claim about
            // its parent.
            // BEFORE: _ *m
            // AFTER:  _ *m
            {parent_contains_claim}:
                dup 0 {&field!(KnowsBlockExtraDataMemory::prev_block_header)}
                {&field!(BlockHeader::prev_block_digest)} {&read_digest}
                push {expected_input_alloc.write_address()} write_mem {Digest::LEN} pop 1

                dup 0 {&field!(KnowsBlockExtraDataMemory::prev_block_appendix)}
                {&field!(BlockAppendix::claims)}
                read_mem 1 addi 2 place 1 push 0
                // _ *m *claim[0]_si num_claims 0

                call {find_own_claim}
                pop 3
                return

            // INVARIANT: _ *claim[i]_si num_claims i
            {find_own_claim}:
                dup 1 dup 1 eq
                push 0 eq assert error_id {BlockValidationRule::AppendixMissingClaim.error_id()}
                dup 2 addi 1 {&field!(Claim::program_digest)} {&read_digest}
                push {own_program_digest_alloc.read_address()} read_mem {Digest::LEN} pop 1
                {&digests_are_equal}
                dup 3 addi 1 {&field!(Claim::version)} read_mem 1 pop 1
                push {version} eq mul
                // _ *claim[i]_si num_claims i program_and_version_match

                dup 3 addi 1 {&field_with_size!(Claim::input)}
                // The size counts the length word the pointer points at.
                push {1 + Self::INPUT_LEN} eq
                // _ *claim[i]_si num_claims i program_and_version_match *input input_size_matches

                // The output is empty: its size is the length word alone.
                dup 5 addi 1 {&field_with_size!(Claim::output)}
                push 1 eq
                place 1 pop 1 mul
                pick 2 mul
                // _ *claim[i]_si num_claims i *input shape_matches

                dup 0 skiz call {input_matches}
                place 1 pop 1
                // _ *claim[i]_si num_claims i is_own_claim_about_parent
                skiz return

                pick 2 read_mem 1
                // Crashes unless the size is a u32.
                dup 1 pop_count pop 1
                addi 2 add
                place 2 addi 1
                // _ *claim[i + 1]_si num_claims (i + 1)
                recurse

            // Whether the input of a claim of this program binds the
            // parent's parent and the activation height.
            // BEFORE: _ *input 1
            // AFTER:  _ *input input_matches
            {input_matches}:
                pop 1
                dup 0 addi {Digest::LEN} read_mem {Digest::LEN} pop 1
                swap 4 swap 1 swap 3 swap 1
                // _ *input [prev_prev_block_digest_in_input]
                push {expected_input_alloc.read_address()} read_mem {Digest::LEN} pop 1
                {&digests_are_equal}
                // _ *input parent_matches
                dup 1 addi {Self::INPUT_LEN} read_mem 1 pop 1
                {&read_word(&activation_height_alloc)}
                eq mul
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
mod tests {
    use neptune_mutator_set::msa_and_records::MsaAndRecords;
    use neptune_mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
    use neptune_mutator_set::removal_record::removal_record_list::RemovalRecordList;
    use neptune_primitives::network::Network;
    use proptest::prelude::Arbitrary;
    use proptest::strategy::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;

    use super::*;
    use crate::proof_abstractions::tasm::builtins as tasm;
    use crate::proof_abstractions::tasm::program::spec::TritonProgramSpecification;
    use crate::transaction::transaction_kernel::TransactionKernelModifier;

    impl TritonProgramSpecification for KnowsBlockExtraData {
        fn source(&self) {
            let own_program_digest = tasm::own_program_digest();
            let prev_block_digest = tasm::tasmlib_io_read_stdin___digest();
            let memory: KnowsBlockExtraDataMemory =
                tasm::decode_from_memory(FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS);
            let activation_height: BlockHeight = tasm::tasmlib_io_read_stdin___bfe().into();

            let header_leaf = Tip5::hash(&memory.prev_block_header.mast_hash());
            let body_leaf = Tip5::hash(&memory.prev_block_body_mast_hash);
            let appendix_leaf = Tip5::hash_varlen(&memory.prev_block_appendix.encode());
            let kernel_mast_hash = Tip5::hash_pair(
                Tip5::hash_pair(header_leaf, body_leaf),
                Tip5::hash_pair(appendix_leaf, Digest::default()),
            );
            let prev_block_hash =
                Tip5::hash_pair(Tip5::hash(&kernel_mast_hash), memory.prev_block_proof_leaf);
            assert_eq!(prev_block_digest, prev_block_hash);

            tasm::tasmlib_hashing_merkle_verify(
                memory.prev_block_body_mast_hash,
                BlockBodyField::TransactionKernel.discriminant() as u32,
                Tip5::hash(&memory.prev_block_txk_mast_hash),
                BlockBody::MAST_HEIGHT as u32,
            );
            let inputs_address = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS
                + bfe!(memory.encode().len() as u64);
            let inputs: Vec<RemovalRecord> = tasm::decode_from_memory(inputs_address);
            assert_eq!(inputs.encode().len(), memory.prev_block_inputs_len as usize);
            tasm::tasmlib_hashing_merkle_verify(
                memory.prev_block_txk_mast_hash,
                TransactionKernelField::Inputs.discriminant() as u32,
                Tip5::hash(&inputs),
                TransactionKernel::MAST_HEIGHT as u32,
            );
            tasm::tasmlib_hashing_merkle_verify(
                memory.prev_block_txk_mast_hash,
                TransactionKernelField::MutatorSetHash.discriminant() as u32,
                Tip5::hash(&memory.mutator_set.hash()),
                TransactionKernel::MAST_HEIGHT as u32,
            );

            let sampled = sampled_inputs(prev_block_digest, inputs.len())
                .into_iter()
                .map(|i| inputs[i].clone())
                .collect_vec();
            let swbfi = &memory.mutator_set.swbf_inactive;
            let leaf_count = swbfi.num_leafs();
            let chunk_indices = (0..memory.chunks.len())
                .map(|_| {
                    let hi = tasm::tasmlib_io_read_secin___bfe().value();
                    let lo = tasm::tasmlib_io_read_secin___bfe().value();
                    assert!(hi <= u64::from(u32::MAX) && lo <= u64::from(u32::MAX));
                    (hi << 32) | lo
                })
                .collect_vec();
            assert!(chunk_indices.is_sorted_by(|a, b| a < b));
            let tokens = ChunkInsertions::divined_tokens(&sampled, &chunk_indices, leaf_count);
            for _ in tokens {
                tasm::tasmlib_io_read_secin___bfe();
            }
            let required = ChunkInsertions::chunk_indices_below(&sampled, leaf_count);
            assert!(required.iter().all(|index| chunk_indices.contains(index)));
            for (&chunk_index, chunk) in chunk_indices.iter().zip(&memory.chunks) {
                assert!(tasm::mmr_verify_from_secret_in_leaf_index_on_stack(
                    &swbfi.peaks(),
                    leaf_count,
                    chunk_index,
                    Tip5::hash(chunk),
                ));
            }

            if memory.prev_block_header.height >= activation_height {
                let version = ConsensusRuleSet::HardforkDelta
                    .triton_proof_version()
                    .version();
                let claim = Claim::new(own_program_digest)
                    .with_input(KnowsBlockExtraData::claim_input(
                        memory.prev_block_header.prev_block_digest,
                        activation_height,
                    ))
                    .about_version(version);
                assert!(memory.prev_block_appendix.contains(&claim));
            }
        }
    }

    const RULE_SET: ConsensusRuleSet = ConsensusRuleSet::HardforkDelta;

    /// A mutator set and full removal records synced to it, with this many
    /// records and AOCL leafs.
    fn msa_and_records(seed: u64, num_records: usize, aocl_size: u64) -> MsaAndRecords {
        let mut rng = StdRng::seed_from_u64(seed);
        let removables = (0..num_records)
            .map(|_| (rng.random(), rng.random(), rng.random()))
            .collect_vec();
        let mut runner = TestRunner::deterministic();
        MsaAndRecords::arbitrary_with((removables, aocl_size))
            .new_tree(&mut runner)
            .unwrap()
            .current()
    }

    /// A parent block at this height whose transaction spends these records,
    /// stripped of their chunk data and packed, against this mutator set, and
    /// whose appendix contains these claims.
    fn parent(
        rng: &mut StdRng,
        height: u64,
        msa_and_records: &MsaAndRecords,
        claims: Vec<Claim>,
    ) -> Block {
        let stripped = msa_and_records
            .unpacked_removal_records()
            .into_iter()
            .map(|record| RemovalRecord {
                absolute_indices: record.absolute_indices,
                target_chunks: ChunkDictionary::empty(),
            })
            .collect_vec();
        let mut block = Block::genesis(Network::Main);
        let kernel = TransactionKernelModifier::default()
            .inputs(RemovalRecordList::pack(stripped, true))
            .mutator_set_hash(msa_and_records.mutator_set_accumulator.hash())
            .modify(block.body().transaction_kernel.clone());
        block.set_transaction_kernel(kernel);
        block.kernel_mut().header.height = height.into();
        block.kernel_mut().header.prev_block_digest = rng.random();
        block.set_appendix(BlockAppendix::new(claims));
        block
    }

    /// A parent at this height containing its claim.
    fn parent_with_claim(
        rng: &mut StdRng,
        height: u64,
        msa_and_records: &MsaAndRecords,
        activation_height: BlockHeight,
    ) -> Block {
        let block = parent(rng, height, msa_and_records, vec![]);
        let claim = KnowsBlockExtraData::claim(
            block.header().prev_block_digest,
            activation_height,
            RULE_SET,
        );
        let mut block = block;
        block.set_appendix(BlockAppendix::new(vec![claim]));
        block
    }

    fn witness(
        prev_block: &Block,
        msa_and_records: &MsaAndRecords,
        activation_height: BlockHeight,
    ) -> KnowsBlockExtraDataWitness {
        KnowsBlockExtraDataWitness::new(
            prev_block,
            &msa_and_records.mutator_set_accumulator,
            &msa_and_records.unpacked_removal_records(),
            activation_height,
        )
    }

    fn assert_accepts(witness: &KnowsBlockExtraDataWitness) {
        let input = witness.standard_input();
        let rust_output = KnowsBlockExtraData
            .run_rust(&input, witness.nondeterminism())
            .unwrap();
        let tasm_output = KnowsBlockExtraData
            .run_tasm(&input, witness.nondeterminism())
            .unwrap();
        assert!(rust_output.is_empty());
        assert_eq!(rust_output, tasm_output);
    }

    fn assert_rejects(witness: &KnowsBlockExtraDataWitness, error_ids: &[i128]) {
        KnowsBlockExtraData
            .test_assertion_failure(
                witness.standard_input(),
                witness.nondeterminism(),
                error_ids,
            )
            .unwrap();
    }

    /// A parent at the activation height, containing its claim, whose
    /// sampled inputs have inactive chunks.
    fn activated_parent(rng: &mut StdRng) -> (Block, MsaAndRecords, BlockHeight) {
        let msa_and_records = msa_and_records(30, 30, 3_000);
        let activation_height = BlockHeight::from(5u64);
        let prev_block = parent_with_claim(rng, 5, &msa_and_records, activation_height);
        (prev_block, msa_and_records, activation_height)
    }

    #[test]
    fn other_chunk_is_rejected() {
        let mut rng = StdRng::seed_from_u64(1);
        let (prev_block, msa_and_records, activation_height) = activated_parent(&mut rng);
        let mut witness = witness(&prev_block, &msa_and_records, activation_height);
        assert!(!witness.memory.chunks.is_empty());
        let chunk = &mut witness.memory.chunks[0];
        let absent = (0..).find(|&index| !chunk.contains(index)).unwrap();
        chunk.insert(absent);
        assert_rejects(&witness, &[10]);
    }

    #[test]
    fn missing_chunk_is_rejected() {
        let mut rng = StdRng::seed_from_u64(2);
        let (prev_block, msa_and_records, activation_height) = activated_parent(&mut rng);
        let honest = witness(&prev_block, &msa_and_records, activation_height);
        let kernel = &prev_block.body().transaction_kernel;
        let sampled = sampled_inputs(prev_block.hash(), kernel.inputs.len())
            .into_iter()
            .map(|i| kernel.inputs[i].clone())
            .collect_vec();
        let leaf_count = msa_and_records
            .mutator_set_accumulator
            .swbf_inactive
            .num_leafs();
        let chunk_indices = ChunkInsertions::chunk_indices_below(&sampled, leaf_count);
        assert!(!chunk_indices.is_empty());
        let witness = KnowsBlockExtraDataWitness::with_chunk_indices(
            &prev_block,
            &msa_and_records.mutator_set_accumulator,
            &msa_and_records.unpacked_removal_records(),
            activation_height,
            &chunk_indices[1..],
        );
        assert_eq!(honest.memory.chunks.len() - 1, witness.memory.chunks.len());
        assert_rejects(
            &witness,
            &[BlockValidationRule::RemovalRecordsValidity.error_id()],
        );
    }

    #[test]
    fn parent_without_its_claim_is_rejected() {
        let mut rng = StdRng::seed_from_u64(3);
        let (_, msa_and_records, activation_height) = activated_parent(&mut rng);
        let prev_block = parent(&mut rng, 5, &msa_and_records, vec![]);
        let witness = witness(&prev_block, &msa_and_records, activation_height);
        assert_rejects(
            &witness,
            &[BlockValidationRule::AppendixMissingClaim.error_id()],
        );
    }

    #[test]
    fn other_parent_is_rejected() {
        let mut rng = StdRng::seed_from_u64(4);
        let (prev_block, msa_and_records, activation_height) = activated_parent(&mut rng);
        let mut witness = witness(&prev_block, &msa_and_records, activation_height);
        witness.prev_block_digest = rng.random();
        assert_rejects(&witness, &[KnowsBlockExtraData::PARENT_MISMATCH_ERROR_ID]);
    }

    #[test]
    fn other_inputs_or_mutator_set_are_rejected() {
        let mut rng = StdRng::seed_from_u64(5);
        let (prev_block, msa_and_records, activation_height) = activated_parent(&mut rng);
        let honest = witness(&prev_block, &msa_and_records, activation_height);

        let mut witness = honest.clone();
        witness.prev_block_inputs.pop();
        witness.memory.prev_block_inputs_len =
            u32::try_from(witness.prev_block_inputs.encode().len()).unwrap();
        assert_rejects(&witness, &[MerkleVerify::ROOT_MISMATCH_ERROR_ID]);

        let mut witness = honest;
        witness.memory.mutator_set = self::msa_and_records(6, 3, 100).mutator_set_accumulator;
        assert_rejects(&witness, &[MerkleVerify::ROOT_MISMATCH_ERROR_ID]);
    }

    #[test]
    fn witness_from_extra_data_is_accepted() {
        let mut rng = StdRng::seed_from_u64(7);
        let (prev_block, msa_and_records, activation_height) = activated_parent(&mut rng);
        let mutator_set = &msa_and_records.mutator_set_accumulator;
        let rule_set = ConsensusRuleSet::HardforkZeta;
        let extra_data = BlockExtraData::new(
            msa_and_records.unpacked_removal_records(),
            mutator_set,
            rule_set,
        );
        let witness = KnowsBlockExtraDataWitness::from_extra_data(
            &prev_block,
            mutator_set,
            &extra_data,
            activation_height,
            rule_set,
        )
        .unwrap();
        assert!(witness.num_chunks() > 0);
        assert_accepts(&witness);
    }

    #[test]
    fn samples_are_ascending_distinct_and_in_range() {
        for num_inputs in [0, 1, 5, 12, 13, 24, 25, 100, 16_384] {
            for seed in 0..4u64 {
                let digest = Tip5::hash(&seed);
                let positions = sampled_inputs(digest, num_inputs);
                assert_eq!(num_inputs.min(NUM_SAMPLES), positions.len());
                assert!(positions.is_sorted_by(|a, b| a < b));
                assert!(positions.iter().all(|&position| position < num_inputs));
            }
        }
    }

    #[test]
    fn honest_witness_is_accepted() {
        let mut rng = StdRng::seed_from_u64(0);
        let activation_height = BlockHeight::from(5u64);
        for (num_records, aocl_size) in [(0, 100), (3, 100), (30, 3_000), (40, 1 << 14)] {
            let msa_and_records = msa_and_records(num_records as u64, num_records, aocl_size);

            // A parent below the activation height needs no claim.
            let prev_block = parent(&mut rng, 4, &msa_and_records, vec![]);
            assert_accepts(&witness(&prev_block, &msa_and_records, activation_height));

            let prev_block = parent_with_claim(&mut rng, 5, &msa_and_records, activation_height);
            assert_accepts(&witness(&prev_block, &msa_and_records, activation_height));
        }
    }
}
