//! Rule 2.e for the current block, restricted to the removals: from the
//! mutator set the block's transaction is built on, setting the indices of
//! its inputs yields the mutator set with this hash. Rules 2.a, 2.b and 2.d
//! come along: the chunks the witness supplies match the state of the
//! mutator set before applying the input/output set of the transaction.
//!
//! The claim goes in the block's appendix, so its proof is verified by the
//! block proof. Its public input binds the mutator set by hash and its
//! output the inputs by a commitment to their index sets, so that a verifier
//! that holds neither the chunks nor the mutator set can still tell what was
//! proven. The input also carries the leaf's position among the block's
//! leaves, so that no two leaves of one block share a claim, and no proof
//! can stand in for two leaves. Light nodes check the tip's update from it
//! on the host machine, and `PredecessorIsValid` checks the predecessor's
//! from the predecessor's copy. It is a leaf of the SWBF aggregation tree,
//! which reads the padded height of its proof, and sums these for all leaf
//! programs verified in the aggregation tree. This sum is calculated to
//! remove the incentive to mine empty blocks.

use std::sync::OnceLock;
use std::time::Instant;

use get_size2::GetSize;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_mutator_set::removal_record::chunk::Chunk;
use neptune_mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
use neptune_mutator_set::removal_record::removal_record_list::RemovalRecordList;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_mutator_set::shared::CHUNK_SIZE;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::field;
use tasm_lib::library::Library;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::triton_vm::vm::VM;
use tasm_lib::twenty_first::prelude::Mmr;
use tasm_lib::twenty_first::prelude::MmrMembershipProof;
use tracing::debug;

use super::chunk_insertions::ChunkInsertions;
use super::chunk_witness::ChunkWitness;
use super::hash_blocks::HashBlocks;
use super::mutate_swbfi_peaks::MutateSwbfiPeaks;
use super::mutator_set_hash_after_removals::MutatorSetHashAfterRemovals;
use super::removal_index_commitment::RemovalIndexCommitment;
use super::swbfi_peaks_after_removals::SwbfiPeaksAfterRemovals;
use super::update_tree_leaf::UpdateTreeLeaf;
use super::witness_lists::WitnessLists;
use super::ClaimOutput;
use crate::block::block_validation_error::BlockValidationRule;
use crate::block::mutator_set_update::MutatorSetUpdate;
use crate::block::validity::mutator_set_hash::MutatorSetHash;
use crate::consensus_rule_set::ConsensusRuleSet;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::proof_abstractions::SecretWitness;

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize, TasmObject)]
pub struct CorrectSwbfUpdateWitness {
    /// The block transaction's inputs with their chunk dictionaries left
    /// out: only their index sets are read.
    inputs: Vec<RemovalRecord>,

    /// The mutator set the transaction is built on.
    mutator_set: MutatorSetAccumulator,

    /// The chunks of the inactive SWBF the inputs' indices fall in, in
    /// ascending chunk index, each in the storage
    /// [`HashBlocks::chunk_storage`] describes.
    chunks: Vec<Vec<BFieldElement>>,

    /// The heights of the trees of the inactive SWBF the chunks lie in,
    /// strictly increasing: the trees of the smallest inactive SWBF that
    /// explains the chunks.
    tree_heights: Vec<u32>,

    /// Per tree in the same order, its chunks' authentication paths back
    /// to back, each against the tree after the chunks before it have
    /// changed.
    tree_paths: Vec<Vec<Digest>>,

    /// How many loop iterations of idle spinning to do after the work. This is
    /// done to meet requirements of minimum padded heights. Not part of the
    /// claim since verifiers read the padded height from the proof.
    /// See [`Self::with_padded_height`].
    idle_iterations: BFieldElement,

    /// The leaf's position among the block's leaves, counted from
    /// [`CorrectSwbfUpdate::FIRST_LEAF_INDEX`] along the chain of segments.
    /// Part of the claim's public input, not read from memory.
    ///
    /// Exists to prevent the same leaf from being used twice to save work on
    /// input aggregation.
    leaf_index: BFieldElement,
}

impl CorrectSwbfUpdateWitness {
    /// The witness for these packed inputs.
    pub fn new(inputs: Vec<RemovalRecord>, mutator_set: MutatorSetAccumulator) -> Self {
        let allow_big_chunks = ConsensusRuleSet::HardforkDelta.allow_big_chunks();
        let mut inputs = ChunkWitness::with_unpacked_chunks(inputs, allow_big_chunks);
        let chunks = ChunkWitness::chunks(&inputs);
        let tree_heights = ChunkWitness::tree_heights(&inputs);
        let (chunk_indices, insertions) =
            SwbfiPeaksAfterRemovals::chunk_indices_and_insertions(&inputs, &mutator_set);
        let tree_paths = MutateSwbfiPeaks::tree_paths(
            WitnessLists::swbfi_leaf_count_estimate(&tree_heights),
            &chunk_indices,
            &chunks,
            &insertions,
            &ChunkWitness::tree_paths(&inputs),
        );
        for input in &mut inputs {
            input.target_chunks = ChunkDictionary::empty();
        }
        let chunks = chunks
            .iter()
            .map(|chunk| HashBlocks::chunk_storage(chunk))
            .collect();
        Self {
            inputs,
            mutator_set,
            chunks,
            tree_heights,
            tree_paths,
            idle_iterations: bfe!(0),
            leaf_index: bfe!(CorrectSwbfUpdate::FIRST_LEAF_INDEX),
        }
    }

    /// The witnesses of consecutive segments of these inputs, of these
    /// sizes, each built on the mutator set after the segments before it.
    pub fn segments(
        inputs: &[RemovalRecord],
        mutator_set: &MutatorSetAccumulator,
        segment_sizes: &[usize],
    ) -> Vec<Self> {
        let allow_big_chunks = ConsensusRuleSet::HardforkDelta.allow_big_chunks();
        let mut rest = RemovalRecordList::try_unpack(inputs.to_vec(), allow_big_chunks)
            .expect("inputs must unpack");
        let mut mutator_set = mutator_set.clone();
        segment_sizes
            .iter()
            .enumerate()
            .map(|(position, &size)| {
                let segment = rest.drain(..size).collect::<Vec<_>>();
                let witness = Self::new(
                    RemovalRecordList::pack(segment.clone(), allow_big_chunks),
                    mutator_set.clone(),
                );
                MutatorSetUpdate::new(segment, vec![])
                    .apply_to_accumulator_and_records(
                        &mut mutator_set,
                        &mut rest.iter_mut().collect::<Vec<_>>(),
                        &mut [],
                    )
                    .expect("segment must be removable");
                witness.with_leaf_index(CorrectSwbfUpdate::FIRST_LEAF_INDEX + position as u64)
            })
            .collect()
    }

    pub fn inputs(&self) -> &[RemovalRecord] {
        &self.inputs
    }

    /// The chunks' lists of set indices, out of their storage.
    fn chunk_lists(&self) -> Vec<Vec<u32>> {
        self.chunks
            .iter()
            .map(|storage| HashBlocks::chunk(storage))
            .collect()
    }

    /// The inputs in the packed list's form, which the host-side update
    /// takes.
    pub fn packed_inputs(&self) -> Vec<RemovalRecord> {
        RemovalRecordList::pack(
            self.unpacked_records(),
            ConsensusRuleSet::HardforkDelta.allow_big_chunks(),
        )
    }

    /// The inputs as the archival update takes them: each with the chunks
    /// its indices need and their membership proofs in the inactive SWBF.
    pub(in crate::block::validity) fn unpacked_records(&self) -> Vec<RemovalRecord> {
        let swbfi_leaf_count = self.mutator_set.swbf_inactive.num_leafs();
        let chunk_indices = ChunkInsertions::chunk_indices_below(&self.inputs, swbfi_leaf_count);
        let (_, insertions) =
            SwbfiPeaksAfterRemovals::chunk_indices_and_insertions(&self.inputs, &self.mutator_set);
        let estimate = WitnessLists::swbfi_leaf_count_estimate(&self.tree_heights);

        // Each chunk's path in its tree, from the tree's sequential paths:
        // the runs come from the highest tree down, the path lists in
        // ascending height.
        let chunks = self.chunk_lists();
        let mut paths_of_chunk = vec![vec![]; chunks.len()];
        let mut next_chunk = 0;
        for ((height, old_leafs, _), paths) in
            MutateSwbfiPeaks::runs(estimate, &chunk_indices, &chunks, &insertions)
                .into_iter()
                .zip(self.tree_paths.iter().rev())
        {
            let nodes = UpdateTreeLeaf::old_nodes(height, paths, &old_leafs);
            for (leaf_index, _) in &old_leafs {
                paths_of_chunk[next_chunk] = UpdateTreeLeaf::path_in(&nodes, height, *leaf_index);
                next_chunk += 1;
            }
        }

        let window_start = SwbfiPeaksAfterRemovals::window_start(&self.mutator_set);
        self.inputs
            .iter()
            .map(|input| {
                let mut entries = input
                    .absolute_indices
                    .to_array()
                    .into_iter()
                    .filter(|&index| index < window_start)
                    .map(|index| (index >> CHUNK_SIZE.ilog2()) as u64)
                    .collect::<Vec<_>>();
                entries.sort_unstable();
                entries.dedup();
                let dictionary = entries
                    .into_iter()
                    .map(|chunk_index| {
                        let position = chunk_indices
                            .binary_search(&chunk_index)
                            .expect("the witness holds the chunk");
                        let chunk = Chunk {
                            relative_indices: chunks[position].clone(),
                        };
                        let proof = MmrMembershipProof::new(paths_of_chunk[position].clone());
                        (chunk_index, (proof, chunk))
                    })
                    .collect();
                RemovalRecord {
                    absolute_indices: input.absolute_indices,
                    target_chunks: ChunkDictionary::new(dictionary),
                }
            })
            .collect()
    }

    pub fn mutator_set(&self) -> &MutatorSetAccumulator {
        &self.mutator_set
    }

    /// The claim about this witness, as a block's appendix carries it.
    pub fn versioned_claim(&self) -> Claim {
        self.claim().about_version(
            ConsensusRuleSet::HardforkDelta
                .triton_proof_version()
                .version(),
        )
    }

    /// # Panics
    ///
    /// If the iterations exceed [`CorrectSwbfUpdate::MAX_IDLE_ITERATIONS`].
    pub fn with_idle_iterations(mut self, idle_iterations: u64) -> Self {
        assert!(
            idle_iterations <= CorrectSwbfUpdate::MAX_IDLE_ITERATIONS,
            "idle iterations exceed the cap"
        );
        self.idle_iterations = bfe!(idle_iterations);
        self
    }

    pub fn with_leaf_index(mut self, leaf_index: u64) -> Self {
        self.leaf_index = bfe!(leaf_index);
        self
    }

    pub fn leaf_index(&self) -> BFieldElement {
        self.leaf_index
    }

    /// Set enough idle iterations to increase the proof of this program
    /// execution to the supplied padded height. A program execution below the
    /// padded height value idles it up to the required height. A program
    /// execution that has already met this requirement does nothing.
    ///
    /// # Panics
    ///
    /// If the leaf's work alone exceeds the height.
    pub fn with_padded_height(self, log2_padded_height: u32) -> Self {
        let witness = self.with_idle_iterations(0);

        let tick = Instant::now();
        let (aet, _) = VM::trace_execution(
            witness.program(),
            witness.standard_input(),
            witness.nondeterminism(),
        )
        .expect("witness must run");
        let trace_execution_time = tick.elapsed();
        debug!(
            "Trace execution to measure required spin took: {}ms",
            trace_execution_time.as_millis()
        );

        let target = 1 << log2_padded_height;
        if aet.padded_height() >= target {
            assert_eq!(
                target,
                aet.padded_height(),
                "leaf exceeds the padded height"
            );
            return witness;
        }

        // No table exceeds half the target. So grow by idling. Idling mainly
        // grows the processor table, so that table will decide the padded
        // height after idling.
        let rows_short = target / 2 - aet.processor_trace.nrows();
        let idle_iterations = rows_short / CorrectSwbfUpdate::IDLE_ROWS_PER_ITERATION + 1;
        witness.with_idle_iterations(idle_iterations as u64)
    }
}

impl SecretWitness for CorrectSwbfUpdateWitness {
    fn standard_input(&self) -> PublicInput {
        // - mutator set hash the leaf starts from: the one in the transaction
        //   kernel for the block's first leaf, the one the preceding leaf
        //   ends on otherwise (5 words)
        // - leaf index: this leaf's position among the block's leaves (1 word)
        //   all n leafs must be enumerated 1..n for the proof tree to be
        //   accepted during block verification.
        PublicInput::new(CorrectSwbfUpdate::claim_input(
            &self.mutator_set,
            self.leaf_index,
        ))
    }

    fn output(&self) -> Vec<BFieldElement> {
        // - 0: padded row count in proof below leaf. Zero since there are no
        //      proofs in the proof tree below the leaf. (1 word)
        // - number of inputs applied to the mutator set in this leaf (1 word)
        // - mutator set hash after application of all removals in this leaf
        //   (5 words)
        // - last leaf index in this proof: this leaf's index from the claim
        //   input, since it is a leaf (1 word)
        // - number of peaks in the MMR of the absolute index sets in this leaf
        //   (1 word)
        // - those peaks (5 words each)
        let mutator_set_after =
            SwbfiPeaksAfterRemovals::apply_removals(&self.packed_inputs(), &self.mutator_set);
        ClaimOutput {
            padded_rows: bfe!(CorrectSwbfUpdate::ATTESTED_PADDED_ROWS),
            count: self.inputs.len(),
            mutator_set_hash: mutator_set_after.hash(),
            last_leaf_index: self.leaf_index,
            peaks: RemovalIndexCommitment::peaks(&self.inputs),
        }
        .encode()
    }

    fn program(&self) -> Program {
        CorrectSwbfUpdate.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        let mut nondeterminism = NonDeterminism::default();
        encode_to_memory(
            &mut nondeterminism.ram,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self,
        );
        nondeterminism.individual_tokens = MutatorSetHashAfterRemovals::divined_tokens(
            &self.inputs,
            &self.mutator_set,
            &self.chunk_lists(),
            &self.tree_heights,
        );

        nondeterminism
    }
}

/// Input:
/// - the hash of the mutator set the leaf starts from: the one the block's
///   transaction is built on for the first leaf, the one the preceding leaf
///   ends on for any other (5 words)
/// - the leaf's index: its position among the block's leaves, counted from
///   [`Self::FIRST_LEAF_INDEX`] (1 word)
///
/// Output:
/// - the attested padded rows: zero, see [`Self::ATTESTED_PADDED_ROWS`]
///   (1 word)
/// - the number of inputs removed, which the index-set peaks below commit to
///   (1 word)
/// - the hash of the mutator set after the removals (5 words)
/// - the last leaf index: the leaf's own, echoed from the input (1 word)
/// - the number of peaks of the MMR over the inputs' index sets (1 word)
/// - those peaks (5 words each)
///
/// Aggregations of leaves keep this layout, with the first word summing the
/// leaf proofs' padded heights beneath them and the leaf indices spanning
/// their leaves.
#[derive(
    Debug, Clone, Copy, Default, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize,
)]
pub struct CorrectSwbfUpdate;

impl CorrectSwbfUpdate {
    /// The first output word: the padded rows of the leaf proofs a claim
    /// attests, which an aggregation sums over its children. A leaf cannot
    /// attest its own proof's height, so it writes zero; the aggregation
    /// reads the height from the proof instead.
    pub const ATTESTED_PADDED_ROWS: u64 = 0;

    /// Processor rows one idle iteration costs; see
    /// [`CorrectSwbfUpdateWitness::with_padded_height`].
    pub const IDLE_ROWS_PER_ITERATION: usize = 4;

    /// The index of a block's first leaf; the others follow in order of
    /// their segments.
    pub const FIRST_LEAF_INDEX: u64 = 1;

    /// The most idle iterations a leaf takes: idling alone then stays under
    /// 2^29 processor rows, the tallest trace the verifier accepts. The
    /// program rejects a witness above it.
    pub const MAX_IDLE_ITERATIONS: u64 = 1 << 27;

    /// The claim for a block's inputs on this mutator set as its only leaf,
    /// as its appendix carries it.
    pub fn claim(inputs: &[RemovalRecord], mutator_set: &MutatorSetAccumulator) -> Claim {
        CorrectSwbfUpdateWitness::new(inputs.to_vec(), mutator_set.clone()).versioned_claim()
    }

    /// The claim's input for a leaf with this index starting from this
    /// mutator set: what a block binds, without computing the output.
    pub fn claim_input(
        mutator_set: &MutatorSetAccumulator,
        leaf_index: BFieldElement,
    ) -> Vec<BFieldElement> {
        [
            mutator_set.hash().reversed().values().to_vec(),
            vec![leaf_index],
        ]
        .concat()
    }
}

impl TritonProgram for CorrectSwbfUpdate {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        let mut library = Library::new();
        let audit_witness = library.import(Box::new(
            VerifyNdSiIntegrity::<CorrectSwbfUpdateWitness>::default(),
        ));
        let mutator_set_hash = library.import(Box::new(MutatorSetHash));
        let hash_after_removals = library.import(Box::new(MutatorSetHashAfterRemovals));
        let commitment = library.import(Box::new(RemovalIndexCommitment));

        let write_peaks = "correct_swbf_update_write_peaks".to_string();
        let idle = "correct_swbf_update_idle".to_string();
        let idle_loop = format!("{idle}_loop");

        let code = triton_asm!(
            read_io {Digest::LEN}
            // _ [mutator_set_hash]

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            hint witness = stack[0]
            dup 0 call {audit_witness} pop 1
            // _ [mutator_set_hash] *w

            dup 0 {&field!(CorrectSwbfUpdateWitness::mutator_set)}
            call {mutator_set_hash}
            // _ [mutator_set_hash] *w [witness_mutator_set_hash]

            pick 10 pick 10 pick 10 pick 10 pick 10
            // _ *w [witness_mutator_set_hash] [mutator_set_hash]

            assert_vector error_id {BlockValidationRule::TransactionMutatorSetMismatch.error_id()}
            pop {Digest::LEN}
            // _ *w

            dup 0 {&field!(CorrectSwbfUpdateWitness::inputs)}
            call {commitment}
            place 1
            // _ *peaks *w

            dup 0 {&field!(CorrectSwbfUpdateWitness::inputs)}
            dup 1 {&field!(CorrectSwbfUpdateWitness::mutator_set)}
            dup 2 {&field!(CorrectSwbfUpdateWitness::chunks)}
            dup 3 {&field!(CorrectSwbfUpdateWitness::tree_heights)}
            dup 4 {&field!(CorrectSwbfUpdateWitness::tree_paths)}
            call {hash_after_removals}
            // _ *peaks *w [mutator_set_after_removals_hash]

            push {Self::ATTESTED_PADDED_ROWS} write_io 1
            dup 5 {&field!(CorrectSwbfUpdateWitness::inputs)} read_mem 1 pop 1 write_io 1
            write_io {Digest::LEN}
            pop 1
            // _ *peaks

            // The leaf index, which only the claim reads: the last leaf index
            // of a leaf is its own.
            read_io 1 write_io 1

            dup 0 read_mem 1 pop 1
            dup 0 write_io 1
            push {Digest::LEN} mul dup 1 add
            // _ *peaks *peaks_end

            swap 1 call {write_peaks}
            // _ *peaks_end *peaks_end

            pop 2
            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            {&field!(CorrectSwbfUpdateWitness::idle_iterations)} read_mem 1 pop 1
            // _ idle_iterations

            // Crashes unless the count is a u32 at or below the cap.
            push {Self::MAX_IDLE_ITERATIONS + 1} dup 1 lt assert
            // _ idle_iterations

            dup 0 skiz call {idle}
            pop 1
            halt

            // BEFORE: _ n     (n > 0)
            // AFTER:  _ 0
            {idle}:
                push 0 push 0 push 0 push 0 push 0 push 0
                call {idle_loop}
                pop 5 pop 1
                return

            // `IDLE_ROWS_PER_ITERATION` processor rows per iteration.
            // INVARIANT: _ n 0 0 0 0 0 0
            {idle_loop}:
                pick 6 addi -1 place 6
                recurse_or_return

            // INVARIANT: _ *end *peak[i]_previous_word
            {write_peaks}:
                dup 1 dup 1 eq skiz return
                addi {Digest::LEN} read_mem {Digest::LEN}
                // _ *end [peak[i]] *peak[i]_previous_word

                addi {Digest::LEN} place {Digest::LEN}
                // _ *end *peak[i + 1]_previous_word [peak[i]]

                write_io {Digest::LEN}
                recurse

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
    use neptune_mutator_set::active_window::ActiveWindow;
    use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
    use neptune_mutator_set::shared::WINDOW_SIZE;
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::twenty_first::prelude::Mmr;
    use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

    use super::super::chunk_witness::tests::random_msa_and_records;
    use super::super::window_after_removals::WindowAfterRemovals;
    use super::*;
    use crate::proof_abstractions::tasm::builtins as tasm;
    use crate::proof_abstractions::tasm::program::spec::TritonProgramSpecification;

    impl CorrectSwbfUpdateWitness {
        pub(in crate::block::validity) fn chunks(&self) -> Vec<Vec<u32>> {
            self.chunk_lists()
        }

        /// Replaces the chunk at the position.
        fn set_chunk(&mut self, position: usize, chunk: &[u32]) {
            self.chunks[position] = HashBlocks::chunk_storage(chunk);
        }

        pub(in crate::block::validity) fn tree_heights(&self) -> &[u32] {
            &self.tree_heights
        }

        pub(in crate::block::validity) fn tree_paths(&self) -> &[Vec<Digest>] {
            &self.tree_paths
        }
    }

    impl TritonProgramSpecification for CorrectSwbfUpdate {
        fn source(&self) {
            let mutator_set_hash = tasm::tasmlib_io_read_stdin___digest();
            let witness: CorrectSwbfUpdateWitness =
                tasm::decode_from_memory(FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS);

            assert_eq!(mutator_set_hash, witness.mutator_set.hash());
            let index_set_peaks = RemovalIndexCommitment::peaks(&witness.inputs);

            let peaks = SwbfiPeaksAfterRemovals::verify(
                &witness.inputs,
                &witness.mutator_set,
                &witness.chunk_lists(),
                &witness.tree_heights,
                &witness.tree_paths,
            );
            let window = WindowAfterRemovals::verify(&witness.inputs, &witness.mutator_set);
            let mut mutator_set_after = witness.mutator_set.clone();
            mutator_set_after.swbf_inactive =
                MmrAccumulator::init(peaks, witness.mutator_set.swbf_inactive.num_leafs());
            mutator_set_after.swbf_active = window;

            let output = ClaimOutput {
                padded_rows: bfe!(Self::ATTESTED_PADDED_ROWS),
                count: witness.inputs.len(),
                mutator_set_hash: mutator_set_after.hash(),
                last_leaf_index: tasm::tasmlib_io_read_stdin___bfe(),
                peaks: index_set_peaks,
            };
            for word in output.encode() {
                tasm::tasmlib_io_write_to_stdout___bfe(word);
            }
        }
    }

    /// A witness with this many packed inputs, and the mutator set they
    /// remove from. The fixture's active window is random; the mutator set
    /// produces a sorted multiset of indices inside the window, so it is
    /// made one.
    pub(in crate::block::validity) fn witness(
        num_inputs: usize,
        seed: u64,
    ) -> CorrectSwbfUpdateWitness {
        witness_on_aocl(num_inputs, seed, 1 << 20)
    }

    /// [witness] on an AOCL of this size: a small one keeps the inputs'
    /// index windows near the active window.
    fn witness_on_aocl(num_inputs: usize, seed: u64, aocl_size: u64) -> CorrectSwbfUpdateWitness {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut msa_and_records = random_msa_and_records(&mut rng, num_inputs, aocl_size);
        let inputs = RemovalRecordList::pack(
            msa_and_records.unpacked_removal_records(),
            ConsensusRuleSet::HardforkDelta.allow_big_chunks(),
        );
        let window = &mut msa_and_records.mutator_set_accumulator.swbf_active;
        let mut sbf = window
            .sbf
            .iter()
            .map(|index| index % WINDOW_SIZE)
            .collect::<Vec<_>>();
        sbf.sort_unstable();
        *window = ActiveWindow::from_vec_u32(sbf);

        // The archival rules 2.a and 2.b must hold for the fixture.
        let mutator_set = msa_and_records.mutator_set_accumulator;
        let unpacked = RemovalRecordList::try_unpack(
            inputs.clone(),
            ConsensusRuleSet::HardforkDelta.allow_big_chunks(),
        )
        .expect("fixture inputs must unpack");
        assert!(
            unpacked.iter().all(|record| mutator_set.can_remove(record)),
            "fixture inputs must be removable"
        );

        CorrectSwbfUpdateWitness::new(inputs, mutator_set)
    }

    /// [witness] with every chunk emptied, and the inactive SWBF's peaks
    /// and the trees' paths recomputed for the empty chunks: the cost of
    /// the list form at a chunk density of zero.
    pub(in crate::block::validity) fn witness_with_empty_chunks(
        num_inputs: usize,
        seed: u64,
    ) -> CorrectSwbfUpdateWitness {
        let mut witness = witness(num_inputs, seed);
        let (chunk_indices, insertions) = SwbfiPeaksAfterRemovals::chunk_indices_and_insertions(
            &witness.inputs,
            &witness.mutator_set,
        );
        let estimate = WitnessLists::swbfi_leaf_count_estimate(&witness.tree_heights);
        let leaf_count = witness.mutator_set.swbf_inactive.num_leafs();
        let auth_structs = MutateSwbfiPeaks::tree_auth_structs(
            estimate,
            &chunk_indices,
            &witness.chunk_lists(),
            &insertions,
            &witness.tree_paths,
        );
        let empty_chunks = vec![vec![]; witness.chunks.len()];
        let runs = MutateSwbfiPeaks::runs(estimate, &chunk_indices, &empty_chunks, &insertions);
        let mut peaks = witness.mutator_set.swbf_inactive.peaks();
        let mut tree_paths = vec![];
        for ((height, old, new), auth_struct) in runs.iter().rev().zip(&auth_structs) {
            let paths = UpdateTreeLeaf::sequential_paths(*height, auth_struct, old, new);
            if !old.is_empty() {
                let (root, _) = UpdateTreeLeaf::try_roots(*height, &paths, old, new).unwrap();
                peaks[(leaf_count >> (height + 1)).count_ones() as usize] = root;
            }
            tree_paths.push(paths);
        }
        for position in 0..witness.chunks.len() {
            witness.set_chunk(position, &[]);
        }
        witness.tree_paths = tree_paths;
        witness.mutator_set.swbf_inactive = MmrAccumulator::init(peaks, leaf_count);
        witness
    }

    /// The witnesses of consecutive segments of these sizes of one block's
    /// inputs, each built on the mutator set after the segments before it.
    pub(in crate::block::validity) fn chained_witnesses(
        segment_sizes: &[usize],
        seed: u64,
    ) -> Vec<CorrectSwbfUpdateWitness> {
        let all = witness(segment_sizes.iter().sum(), seed);
        CorrectSwbfUpdateWitness::segments(&all.packed_inputs(), &all.mutator_set, segment_sizes)
    }

    /// The mutator set the archival update computes for the witness's
    /// inputs.
    pub(in crate::block::validity) fn archival_mutator_set_after(
        witness: &CorrectSwbfUpdateWitness,
    ) -> MutatorSetAccumulator {
        let mut mutator_set = witness.mutator_set.clone();
        MutatorSetUpdate::new(witness.unpacked_records(), vec![])
            .apply_to_accumulator(&mut mutator_set)
            .expect("archival update must apply");
        mutator_set
    }

    #[test]
    fn honest_witness_is_accepted_and_outputs_the_mutator_set_hash() {
        for (num_inputs, seed) in [(1, 0), (2, 1), (5, 2)] {
            let witness = witness(num_inputs, seed);
            let input = witness.standard_input();
            let nondeterminism = witness.nondeterminism();

            let rust_output = CorrectSwbfUpdate
                .run_rust(&input, nondeterminism.clone())
                .unwrap();
            let tasm_output = CorrectSwbfUpdate.run_tasm(&input, nondeterminism).unwrap();
            assert_eq!(rust_output, tasm_output, "{num_inputs} inputs");
            assert_eq!(witness.output(), tasm_output, "{num_inputs} inputs");

            // The hash is that of the mutator set the archival update
            // computes.
            let expected_hash = archival_mutator_set_after(&witness).hash().values();
            assert_eq!(expected_hash, tasm_output[2..7], "{num_inputs} inputs");
        }
    }

    #[test]
    fn leaf_index_is_echoed_and_changes_nothing_else() {
        let first = witness(2, 3);
        let third = first.clone().with_leaf_index(3);
        assert_ne!(first.versioned_claim(), third.versioned_claim());
        for leaf in [&first, &third] {
            let output = CorrectSwbfUpdate
                .run_tasm(&leaf.standard_input(), leaf.nondeterminism())
                .unwrap();
            assert_eq!(leaf.output(), output);
            assert_eq!(leaf.leaf_index(), output[2 + Digest::LEN]);
        }
        let (first, third) = (first.output(), third.output());
        assert_eq!(first[..2 + Digest::LEN], third[..2 + Digest::LEN]);
        assert_eq!(first[3 + Digest::LEN..], third[3 + Digest::LEN..]);
    }

    #[test]
    fn segments_are_numbered_from_the_first_leaf_index() {
        let witnesses = chained_witnesses(&[1, 0, 2], 7);
        let indices = witnesses
            .iter()
            .map(|witness| witness.leaf_index().value())
            .collect::<Vec<_>>();
        let first = CorrectSwbfUpdate::FIRST_LEAF_INDEX;
        assert_eq!(vec![first, first + 1, first + 2], indices);
    }

    #[test]
    fn chained_witnesses_are_accepted_and_chain_the_mutator_set() {
        let witnesses = chained_witnesses(&[2, 3], 7);
        let [left, right] = witnesses.as_slice() else {
            unreachable!()
        };
        let all = witness(5, 7);
        assert_eq!(all.mutator_set, left.mutator_set);
        assert_eq!(archival_mutator_set_after(left), right.mutator_set);
        assert_eq!(
            archival_mutator_set_after(&all),
            archival_mutator_set_after(right)
        );
        for witness in &witnesses {
            let input = witness.standard_input();
            let nondeterminism = witness.nondeterminism();
            let tasm_output = CorrectSwbfUpdate.run_tasm(&input, nondeterminism).unwrap();
            assert_eq!(witness.output(), tasm_output);
        }
    }

    #[test]
    fn peaks_change_unless_no_index_lies_in_the_inactive_swbf() {
        let witness = witness(5, 3);
        let before = witness.mutator_set.swbf_inactive.peaks();
        let after =
            SwbfiPeaksAfterRemovals::apply_removals(&witness.packed_inputs(), &witness.mutator_set)
                .swbf_inactive
                .peaks();
        assert_ne!(before, after, "the fixture must touch the inactive SWBF");
    }

    #[test]
    fn other_mutator_set_hash_is_rejected() {
        let witness = witness(2, 4);
        let mut input = witness.standard_input();
        input.individual_tokens[0] += bfe!(1);

        CorrectSwbfUpdate
            .test_assertion_failure(
                input,
                witness.nondeterminism(),
                &[BlockValidationRule::TransactionMutatorSetMismatch.error_id()],
            )
            .unwrap();
    }

    fn assert_rejects(witness: &CorrectSwbfUpdateWitness, error_id: i128) {
        CorrectSwbfUpdate
            .test_assertion_failure(
                witness.standard_input(),
                witness.nondeterminism(),
                &[error_id],
            )
            .unwrap();
    }

    /// A witness that holds chunks of the inactive SWBF.
    fn witness_with_chunks() -> CorrectSwbfUpdateWitness {
        let witness = witness(3, 7);
        assert!(
            !witness.chunks.is_empty(),
            "the test data must exercise the rules on chunks"
        );
        witness
    }

    #[test]
    fn input_carrying_a_tampered_chunk_is_rejected() {
        let mut witness = witness_with_chunks();
        let mut chunk = witness.chunks()[0].clone();
        chunk.insert(0, 0);
        witness.set_chunk(0, &chunk);
        assert_rejects(
            &witness,
            BlockValidationRule::RemovalRecordsValidity.error_id(),
        );
    }

    /// At most this many of the items, spread evenly, first and last
    /// included.
    fn spread<T: Clone>(items: Vec<T>, at_most: usize) -> Vec<T> {
        if items.len() <= at_most {
            return items;
        }
        (0..at_most)
            .map(|i| items[i * (items.len() - 1) / (at_most - 1)].clone())
            .collect()
    }

    /// A tree's height is load-bearing: one higher or one lower, the tree
    /// is not a tree of the inactive SWBF, or the heights are out of
    /// order, or the estimate of the SWBF's shape is off. Rule 2.a or 2.b
    /// rejects, whichever comes first.
    #[test]
    fn every_tree_height_is_checked() {
        let honest = witness_with_chunks();
        assert!(
            !honest.tree_heights.is_empty(),
            "the test data must hold trees"
        );
        let mut checked = 0;
        for tree in 0..honest.tree_heights.len() {
            let height = honest.tree_heights[tree];
            for other in [height.checked_sub(1), Some(height + 1)]
                .into_iter()
                .flatten()
            {
                let mut witness = honest.clone();
                witness.tree_heights[tree] = other;
                CorrectSwbfUpdate
                    .test_assertion_failure(
                        witness.standard_input(),
                        witness.nondeterminism(),
                        &[
                            BlockValidationRule::RemovalRecordsUnpackFailure.error_id(),
                            BlockValidationRule::RemovalRecordsValidity.error_id(),
                        ],
                    )
                    .unwrap_or_else(|error| panic!("height {height} -> {other}: {error:?}"));
                checked += 1;
            }
        }
        assert!(checked > 0);
    }

    /// Path digests are load-bearing in every word: a spread of digests
    /// over every tree's path list, at every word each. The snippet's own
    /// test covers every digest.
    #[test]
    fn every_word_of_spread_path_digests_is_rejected() {
        let honest = witness_with_chunks();
        let digests = (0..honest.tree_paths.len())
            .flat_map(|tree| (0..honest.tree_paths[tree].len()).map(move |digest| (tree, digest)))
            .collect::<Vec<_>>();
        assert!(!digests.is_empty(), "the test data must hold paths");
        for (tree, digest) in spread(digests, 12) {
            for word in 0..Digest::LEN {
                let mut witness = honest.clone();
                witness.tree_paths[tree][digest].0[word] += bfe!(1);
                assert_rejects(
                    &witness,
                    BlockValidationRule::RemovalRecordsValidity.error_id(),
                );
            }
        }
    }

    /// Every word of every inactive-SWBF peak whose tree holds chunks is
    /// load-bearing.
    #[test]
    fn every_word_of_every_peak_with_chunks_is_rejected() {
        let honest = witness_with_chunks();
        let inputs = &honest.inputs;
        let mutator_set = &honest.mutator_set;
        let swbfi_leaf_count = mutator_set.swbf_inactive.num_leafs();
        let chunk_indices = ChunkInsertions::chunk_indices_below(inputs, swbfi_leaf_count);
        let insertions = ChunkInsertions::insertions(
            inputs,
            &chunk_indices,
            SwbfiPeaksAfterRemovals::window_start(mutator_set),
        );
        let peaks_with_chunks = MutateSwbfiPeaks::runs(
            swbfi_leaf_count,
            &chunk_indices,
            &honest.chunks(),
            &insertions,
        )
        .into_iter()
        .enumerate()
        .filter(|(_, (_, old_leafs, _))| !old_leafs.is_empty())
        .map(|(peak, _)| peak)
        .collect::<Vec<_>>();
        assert!(
            !peaks_with_chunks.is_empty(),
            "the test data must hold chunks"
        );
        for (peak, word) in peaks_with_chunks
            .into_iter()
            .flat_map(|p| (0..Digest::LEN).map(move |w| (p, w)))
        {
            let mut witness = honest.clone();
            let swbfi = &witness.mutator_set.swbf_inactive;
            let mut peaks = swbfi.peaks();
            peaks[peak].0[word] += bfe!(1);
            witness.mutator_set.swbf_inactive = MmrAccumulator::init(peaks, swbfi.num_leafs());
            assert_rejects(
                &witness,
                BlockValidationRule::RemovalRecordsValidity.error_id(),
            );
        }
    }

    /// Chunk contents are load-bearing: for a spread of chunks, an entry
    /// added, and for a spread of their entries, one changed and one
    /// removed. The peak mutation's own test covers every entry.
    #[test]
    fn every_change_to_spread_chunks_is_rejected() {
        let honest = witness_with_chunks();
        let chunks = spread((0..honest.chunks.len()).collect(), 8);
        assert!(!chunks.is_empty(), "the test data must hold chunks");
        let rejects = |witness: &CorrectSwbfUpdateWitness| {
            assert_rejects(
                witness,
                BlockValidationRule::RemovalRecordsValidity.error_id(),
            );
        };
        let lists = honest.chunks();
        for chunk in chunks {
            let mut witness = honest.clone();
            let mut list = lists[chunk].clone();
            list.insert(0, 0);
            witness.set_chunk(chunk, &list);
            rejects(&witness);
            for index in spread((0..lists[chunk].len()).collect(), 3) {
                let mut witness = honest.clone();
                let mut list = lists[chunk].clone();
                list[index] = if list[index] == 0 { 1 } else { list[index] - 1 };
                witness.set_chunk(chunk, &list);
                rejects(&witness);
                let mut witness = honest.clone();
                let mut list = lists[chunk].clone();
                list.remove(index);
                witness.set_chunk(chunk, &list);
                rejects(&witness);
            }
        }
    }

    /// The first tree with paths.
    fn tree_with_paths(witness: &CorrectSwbfUpdateWitness) -> usize {
        (0..witness.tree_paths.len())
            .find(|&tree| !witness.tree_paths[tree].is_empty())
            .expect("the test data must hold paths")
    }

    #[test]
    fn input_carrying_a_tampered_path_is_rejected() {
        let mut witness = witness_with_chunks();
        let tree = tree_with_paths(&witness);
        witness.tree_paths[tree][0] = StdRng::seed_from_u64(0).random();
        assert_rejects(
            &witness,
            BlockValidationRule::RemovalRecordsValidity.error_id(),
        );
    }

    #[test]
    fn input_missing_a_chunk_is_rejected() {
        // The chunk goes; its tree's paths stay.
        let mut witness = witness_with_chunks();
        witness.chunks.remove(0);
        assert_rejects(
            &witness,
            BlockValidationRule::RemovalRecordsValidity.error_id(),
        );
    }

    #[test]
    fn input_carrying_a_superfluous_chunk_is_rejected() {
        let mut witness = witness_with_chunks();
        witness.chunks.push(HashBlocks::chunk_storage(&[]));
        assert_rejects(
            &witness,
            BlockValidationRule::RemovalRecordsUnpackFailure.error_id(),
        );
    }

    #[test]
    fn input_trees_not_increasing_is_rejected() {
        // A tree repeated: the heights no longer strictly increase.
        let mut witness = witness_with_chunks();
        witness.tree_heights.insert(1, witness.tree_heights[0]);
        witness.tree_paths.insert(1, witness.tree_paths[0].clone());
        assert_rejects(
            &witness,
            BlockValidationRule::RemovalRecordsUnpackFailure.error_id(),
        );
    }

    /// The witness with one input's indices set in its chunks: that input is
    /// The witness's tokens with the one at this position changed.
    fn tampered_tokens(witness: &CorrectSwbfUpdateWitness, position: usize) -> NonDeterminism {
        let mut nondeterminism = witness.nondeterminism();
        nondeterminism.individual_tokens[position] += bfe!(1);
        nondeterminism
    }

    fn assert_rejects_tokens(witness: &CorrectSwbfUpdateWitness, nondeterminism: NonDeterminism) {
        assert!(CorrectSwbfUpdate
            .run_tasm(&witness.standard_input(), nondeterminism)
            .is_err());
    }

    /// The number of tokens the window insertion reads, at the end of the
    /// witness's tokens, and the number the peak mutation reads before them.
    fn window_and_mutation_token_counts(witness: &CorrectSwbfUpdateWitness) -> (usize, usize) {
        let inputs = &witness.inputs;
        let mutator_set = &witness.mutator_set;
        let window = WindowAfterRemovals::divined_tokens(inputs, mutator_set).len();
        let estimate = WitnessLists::swbfi_leaf_count_estimate(&witness.tree_heights);
        let (chunk_indices, insertions) =
            SwbfiPeaksAfterRemovals::chunk_indices_and_insertions(inputs, mutator_set);
        let mutation = MutateSwbfiPeaks::divined_tokens(
            estimate,
            &chunk_indices,
            &witness.chunks(),
            &insertions,
        )
        .len();
        (window, mutation)
    }

    #[test]
    fn tampered_tokens_are_rejected() {
        let witness = witness_with_chunks();
        let total = witness.nondeterminism().individual_tokens.len();
        let (window, mutation) = window_and_mutation_token_counts(&witness);
        for position in [
            0,                            // the first chunk index
            total - window - mutation,    // the first insertion position
            total - window - 1,           // the last word of the root tokens
            total - window - Digest::LEN, // a word of the root pair's digests
            total - 1,                    // the last window insertion position
        ] {
            assert_rejects_tokens(&witness, tampered_tokens(&witness, position));
        }
    }

    #[test]
    fn insertion_position_out_of_place_is_rejected() {
        let witness = witness_with_chunks();
        let total = witness.nondeterminism().individual_tokens.len();
        let (window, mutation) = window_and_mutation_token_counts(&witness);
        let mut nondeterminism = witness.nondeterminism();
        // The first chunk's first insertion position moved past the chunk's
        // length. The Rust shadow reads past these tokens, so only the
        // program can reject.
        nondeterminism.individual_tokens[total - window - mutation] = bfe!(1 << 20);
        let error = CorrectSwbfUpdate
            .run_tasm(&witness.standard_input(), nondeterminism)
            .unwrap_err();
        assert!(format!("{error:?}").contains(
            &BlockValidationRule::MutatorSetUpdateIntegrity
                .error_id()
                .to_string()
        ));
    }

    #[test]
    fn input_carrying_a_tampered_path_end_is_rejected() {
        let mut witness = witness_with_chunks();
        let tree = tree_with_paths(&witness);
        let last = witness.tree_paths[tree].len() - 1;
        witness.tree_paths[tree][last] = StdRng::seed_from_u64(1).random();
        assert_rejects(
            &witness,
            BlockValidationRule::RemovalRecordsValidity.error_id(),
        );
    }

    #[test]
    fn input_carrying_a_chunk_with_an_index_removed_is_rejected() {
        let mut witness = witness_with_chunks();
        let lists = witness.chunks();
        let chunk = (0..lists.len())
            .find(|&chunk| !lists[chunk].is_empty())
            .expect("the test data must hold a chunk with indices");
        witness.set_chunk(chunk, &lists[chunk][..lists[chunk].len() - 1]);
        assert_rejects(
            &witness,
            BlockValidationRule::RemovalRecordsValidity.error_id(),
        );
    }

    #[test]
    fn mutator_set_with_a_tampered_swbfi_peak_is_rejected() {
        let mut witness = witness_with_chunks();
        let swbfi = &witness.mutator_set.swbf_inactive;
        let mut peaks = swbfi.peaks();
        peaks[0] = StdRng::seed_from_u64(2).random();
        witness.mutator_set.swbf_inactive = MmrAccumulator::init(peaks, swbfi.num_leafs());
        // The claim input follows the tampered set, so the chunks are what
        // fails to authenticate.
        assert_rejects(
            &witness,
            BlockValidationRule::RemovalRecordsValidity.error_id(),
        );
    }

    /// An index moved into a chunk the witness does not hold.
    #[test]
    fn index_moved_to_a_chunk_the_witness_lacks_is_rejected() {
        let mut witness = witness_with_chunks();
        let swbfi_leaf_count = witness.mutator_set.swbf_inactive.num_leafs();
        let present = ChunkInsertions::chunk_indices_below(&witness.inputs, swbfi_leaf_count);
        let window_start = SwbfiPeaksAfterRemovals::window_start(&witness.mutator_set);
        let mut indices = witness.inputs[0].absolute_indices.to_array();
        let position = indices
            .iter()
            .position(|&index| index < window_start)
            .expect("some index must lie in the inactive SWBF");
        // A chunk within the index set's window, so that the set still
        // encodes, that the witness does not hold.
        let chunk_of = |index: u128| (index >> CHUNK_SIZE.ilog2()) as u64;
        let lowest = chunk_of(*indices.iter().min().unwrap());
        let absent = (lowest..lowest + u64::from(WINDOW_SIZE / CHUNK_SIZE))
            .filter(|chunk_index| *chunk_index < swbfi_leaf_count)
            .find(|chunk_index| !present.contains(chunk_index))
            .expect("the window must have a chunk the witness lacks");
        indices[position] = u128::from(absent) * u128::from(CHUNK_SIZE)
            + indices[position] % u128::from(CHUNK_SIZE);
        witness.inputs[0].absolute_indices = AbsoluteIndexSet::new(indices);
        assert_rejects(
            &witness,
            BlockValidationRule::RemovalRecordsValidity.error_id(),
        );
    }

    /// An index moved within its chunk is a different transaction the leaf
    /// cannot tell from the honest one: it passes, and only the commitment
    /// in its output tells them apart, which is what binds it upstream.
    /// An index moved to either edge of its chunk stays in it and the update
    /// goes through, with another commitment; one step further it lies in
    /// the neighbouring chunk, and goes through if the witness holds that
    /// chunk and is rejected if not.
    /// The chunks the mutator set hands out are sorted, and stay sorted
    /// when other records' removals are applied to them: what the gap proof
    /// of the unspent check and the insertion hash rely on.
    #[test]
    fn mutator_set_keeps_its_chunks_sorted() {
        for (seed, num_records, aocl_size) in [(0, 2, 100), (1, 4, 1 << 12), (2, 3, 1 << 20)] {
            let mut rng = StdRng::seed_from_u64(seed);
            let msa_and_records = random_msa_and_records(&mut rng, num_records, aocl_size);
            let mut records = msa_and_records.unpacked_removal_records();
            let chunks_of = |records: &[RemovalRecord]| {
                records
                    .iter()
                    .flat_map(|record| record.target_chunks.indices_and_chunks())
                    .map(|(_, chunk)| chunk.relative_indices)
                    .collect::<Vec<_>>()
            };
            let chunks = chunks_of(&records);
            assert!(chunks.iter().all(|chunk| chunk.is_sorted()), "seed {seed}");

            // The first record removed, the others' chunks updated.
            let mut mutator_set = msa_and_records.mutator_set_accumulator.clone();
            let removed = records.remove(0);
            MutatorSetUpdate::new(vec![removed], vec![])
                .apply_to_accumulator_and_records(
                    &mut mutator_set,
                    &mut records.iter_mut().collect::<Vec<_>>(),
                    &mut [],
                )
                .expect("removal must apply");
            let updated = chunks_of(&records);
            assert!(updated.iter().all(|chunk| chunk.is_sorted()), "seed {seed}");
            assert!(
                chunks.iter().any(|chunk| !chunk.is_empty())
                    || updated.iter().any(|chunk| !chunk.is_empty()),
                "seed {seed}: the fixture must hold chunks"
            );
        }
    }

    #[test]
    fn index_moved_to_a_chunk_edge_and_across_it() {
        let honest = witness_with_chunks();
        let honest_output = CorrectSwbfUpdate
            .run_tasm(&honest.standard_input(), honest.nondeterminism())
            .unwrap();
        let window_start = SwbfiPeaksAfterRemovals::window_start(&honest.mutator_set);
        let leaf_count = honest.mutator_set.swbf_inactive.num_leafs();
        let present = ChunkInsertions::chunk_indices_below(&honest.inputs, leaf_count);
        let chunk_size = u128::from(CHUNK_SIZE);
        let (mut seen_present, mut seen_absent) = (false, false);
        for input in 0..honest.inputs.len() {
            let indices = honest.inputs[input].absolute_indices.to_array();
            let Some(position) = indices.iter().position(|&index| index < window_start) else {
                continue;
            };
            let chunk_start = indices[position] - indices[position] % chunk_size;
            for target in [
                chunk_start,
                chunk_start + chunk_size - 1,
                chunk_start.wrapping_sub(1),
                chunk_start + chunk_size,
            ] {
                let mut moved = indices;
                moved[position] = target;
                let spread = moved.iter().max().unwrap() - moved.iter().min().unwrap();
                if target == indices[position]
                    || target >= window_start
                    || spread >= u128::from(WINDOW_SIZE)
                {
                    continue;
                }
                let mut witness = honest.clone();
                witness.inputs[input].absolute_indices = AbsoluteIndexSet::new(moved);
                if present.contains(&((target / chunk_size) as u64)) {
                    // The paths follow the insertions, so an honest prover
                    // recomputes them.
                    let witness =
                        CorrectSwbfUpdateWitness::new(witness.packed_inputs(), witness.mutator_set);
                    let output = CorrectSwbfUpdate
                        .run_tasm(&witness.standard_input(), witness.nondeterminism())
                        .unwrap();
                    assert_eq!(honest_output[..2], output[..2]);
                    assert_ne!(honest_output[2..], output[2..]);
                    seen_present = true;
                } else {
                    assert_rejects(
                        &witness,
                        BlockValidationRule::RemovalRecordsValidity.error_id(),
                    );
                    seen_absent = true;
                }
            }
        }
        assert!(
            seen_present && seen_absent,
            "the test data must hit both cases"
        );
    }

    /// An index moved to the window start enters the active window and the
    /// update goes through, with another window; moved just below it, it
    /// needs the last chunk, which the witness holds or not.
    #[test]
    fn index_moved_to_the_window_start_and_just_below_it() {
        let chunk_of = |index: u128| (index >> CHUNK_SIZE.ilog2()) as u64;
        // A witness on a small AOCL, so that an input's index window reaches
        // the window start: an inactive index of it, whose chunk another
        // index of the record shares so the chunk stays needed when it moves
        // away, can move to the window start.
        let (honest, input, position) = (0..64)
            .map(|seed| witness_on_aocl(3, seed, 4_000))
            .find_map(|witness| {
                let window_start = SwbfiPeaksAfterRemovals::window_start(&witness.mutator_set);
                let target = (0..witness.inputs.len()).find_map(|input| {
                    let indices = witness.inputs[input].absolute_indices.to_array();
                    let minimum = *indices.iter().min().unwrap();
                    (0..indices.len())
                        .find(|&p| {
                            indices[p] < window_start
                                && window_start - minimum < u128::from(WINDOW_SIZE)
                                && indices.iter().enumerate().any(|(q, &other)| {
                                    q != p && chunk_of(other) == chunk_of(indices[p])
                                })
                        })
                        .map(|position| (input, position))
                })?;
                Some((witness, target.0, target.1))
            })
            .expect("some seed must give an input reaching the window start");
        let honest_output = CorrectSwbfUpdate
            .run_tasm(&honest.standard_input(), honest.nondeterminism())
            .unwrap();
        let window_start = SwbfiPeaksAfterRemovals::window_start(&honest.mutator_set);
        let leaf_count = honest.mutator_set.swbf_inactive.num_leafs();
        let present = ChunkInsertions::chunk_indices_below(&honest.inputs, leaf_count);
        let indices = honest.inputs[input].absolute_indices.to_array();

        for target in [window_start, window_start - 1] {
            let mut moved = indices;
            moved[position] = target;
            let mut witness = honest.clone();
            witness.inputs[input].absolute_indices = AbsoluteIndexSet::new(moved);
            if target >= window_start || present.contains(&chunk_of(target)) {
                // The paths follow the insertions, so an honest prover
                // recomputes them.
                let witness =
                    CorrectSwbfUpdateWitness::new(witness.packed_inputs(), witness.mutator_set);
                let output = CorrectSwbfUpdate
                    .run_tasm(&witness.standard_input(), witness.nondeterminism())
                    .unwrap();
                assert_eq!(honest_output[..2], output[..2]);
                assert_ne!(honest_output[2..], output[2..]);
            } else {
                assert_rejects(
                    &witness,
                    BlockValidationRule::RemovalRecordsValidity.error_id(),
                );
            }
        }
    }

    #[test]
    fn index_moved_within_its_chunk_changes_the_commitment_only() {
        let honest = witness_with_chunks();
        let honest_output = CorrectSwbfUpdate
            .run_tasm(&honest.standard_input(), honest.nondeterminism())
            .unwrap();

        let mut witness = honest.clone();
        let window_start = SwbfiPeaksAfterRemovals::window_start(&witness.mutator_set);
        let mut indices = witness.inputs[0].absolute_indices.to_array();
        let position = indices
            .iter()
            .position(|&index| index < window_start && index % u128::from(CHUNK_SIZE) > 0)
            .expect("some inactive index must not start its chunk");
        indices[position] -= 1;
        witness.inputs[0].absolute_indices = AbsoluteIndexSet::new(indices);
        // The paths follow the insertions, so an honest prover recomputes them.
        let witness = CorrectSwbfUpdateWitness::new(witness.packed_inputs(), witness.mutator_set);
        let output = CorrectSwbfUpdate
            .run_tasm(&witness.standard_input(), witness.nondeterminism())
            .unwrap();

        // Same attested rows and input count, other mutator set and peaks.
        assert_eq!(honest_output[..2], output[..2]);
        assert_ne!(
            honest_output[2..2 + Digest::LEN],
            output[2..2 + Digest::LEN]
        );
        assert_ne!(honest_output[2 + Digest::LEN..], output[2 + Digest::LEN..]);
    }

    /// The witness with one input's indices set in its chunks: that input is
    /// spent. The chunks are not yet authenticated, so the unspent rule
    /// alone must catch this.
    fn witness_with_a_spent_input() -> CorrectSwbfUpdateWitness {
        let mut witness = witness_with_chunks();
        let swbfi_leaf_count = witness.mutator_set.swbf_inactive.num_leafs();
        let window_start = u128::from(swbfi_leaf_count) << CHUNK_SIZE.ilog2();
        let chunk_indices = ChunkInsertions::chunk_indices_below(&witness.inputs, swbfi_leaf_count);
        let indices = witness
            .inputs
            .iter()
            .map(|input| input.absolute_indices.to_array())
            .find(|indices| indices.iter().all(|index| *index < window_start))
            .expect("some input must lie in the inactive SWBF");
        let mut lists = witness.chunks();
        for index in indices {
            let chunk_index = (index >> CHUNK_SIZE.ilog2()) as u64;
            let position = chunk_indices.binary_search(&chunk_index).unwrap();
            let relative_index = (index % u128::from(CHUNK_SIZE)) as u32;
            let chunk = &mut lists[position];
            let at = chunk.partition_point(|&set| set < relative_index);
            chunk.insert(at, relative_index);
        }
        for (position, list) in lists.iter().enumerate() {
            witness.set_chunk(position, list);
        }
        witness
    }

    #[test]
    fn spent_input_is_rejected() {
        assert_rejects(
            &witness_with_a_spent_input(),
            BlockValidationRule::RemovalRecordsValidity.error_id(),
        );
    }

    /// Prints how the program's cycles and table rows distribute over its
    /// subroutines, at the input counts a leaf of the aggregation tree is
    /// sized for.
    fn processor_rows_and_padded_height(witness: &CorrectSwbfUpdateWitness) -> (usize, usize) {
        let (aet, _) = VM::trace_execution(
            witness.program(),
            witness.standard_input(),
            witness.nondeterminism(),
        )
        .unwrap();
        (aet.processor_trace.nrows(), aet.padded_height())
    }

    #[test]
    fn idling_costs_the_rows_per_iteration_and_changes_nothing_else() {
        let witness = witness(2, 0);
        let idle = witness.clone().with_idle_iterations(1_000);
        assert_eq!(witness.versioned_claim(), idle.versioned_claim());
        let output = CorrectSwbfUpdate
            .run_tasm(&idle.standard_input(), idle.nondeterminism())
            .unwrap();
        assert_eq!(idle.output(), output);

        let (rows, _) = processor_rows_and_padded_height(&witness);
        let (idle_rows, _) = processor_rows_and_padded_height(&idle);
        let per_iteration = CorrectSwbfUpdate::IDLE_ROWS_PER_ITERATION;
        assert!(idle_rows - rows >= 1_000 * per_iteration);
        assert!(idle_rows - rows < 1_000 * per_iteration + 32);
    }

    #[test]
    #[should_panic(expected = "idle iterations exceed the cap")]
    fn idle_iterations_are_capped() {
        witness(1, 0).with_idle_iterations(CorrectSwbfUpdate::MAX_IDLE_ITERATIONS + 1);
    }

    #[test]
    fn program_rejects_idle_iterations_above_the_cap_or_beyond_u32() {
        for idle_iterations in [CorrectSwbfUpdate::MAX_IDLE_ITERATIONS + 1, 1 << 40] {
            let mut witness = witness(1, 0);
            witness.idle_iterations = bfe!(idle_iterations);
            let result =
                CorrectSwbfUpdate.run_tasm(&witness.standard_input(), witness.nondeterminism());
            assert!(result.is_err(), "{idle_iterations} iterations");
        }
    }

    #[test]
    fn idling_lifts_the_padded_height_to_the_target() {
        let witness = witness(2, 0);
        let (_, natural) = processor_rows_and_padded_height(&witness);
        let natural_log2 = natural.ilog2();
        assert_eq!(
            bfe!(0),
            witness
                .clone()
                .with_padded_height(natural_log2)
                .idle_iterations
        );
        for log2 in [natural_log2 + 1, natural_log2 + 2] {
            let lifted = witness.clone().with_padded_height(log2);
            let (rows, padded) = processor_rows_and_padded_height(&lifted);
            assert_eq!(1 << log2, padded, "target 2^{log2}");
            assert!(rows > padded / 2);
        }
    }

    #[test]
    #[should_panic(expected = "exceeds the padded height")]
    fn leaf_above_the_target_height_cannot_be_lowered() {
        let witness = witness(2, 0);
        let (_, natural) = processor_rows_and_padded_height(&witness);
        witness.with_padded_height(natural.ilog2() - 1);
    }

    #[test]
    #[ignore = "prints a profile"]
    fn profile_leaf() {
        for num_inputs in [8, 16] {
            let witness = witness(num_inputs, 6);
            let profile = tasm_lib::generate_full_profile(
                &format!("{num_inputs} inputs"),
                CorrectSwbfUpdate.program(),
                &witness.standard_input(),
                &witness.nondeterminism(),
            );
            println!("{profile}");
        }
    }
}
