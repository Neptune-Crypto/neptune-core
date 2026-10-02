use itertools::Itertools;
use neptune_mutator_set::removal_record::chunk::Chunk;
use tasm_lib::arithmetic::u64::add::Add as U64Add;
use tasm_lib::arithmetic::u64::log_2_floor::Log2Floor;
use tasm_lib::arithmetic::u64::lt::Lt as U64Lt;
use tasm_lib::arithmetic::u64::popcount::PopCount;
use tasm_lib::arithmetic::u64::pow2::Pow2;
use tasm_lib::arithmetic::u64::shift_right::ShiftRight as U64ShiftRight;
use tasm_lib::arithmetic::u64::sub::Sub as U64Sub;
use tasm_lib::list::get::Get;
use tasm_lib::list::set::Set;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use super::hash_chunk_with_insertions::HashChunkWithInsertions;
use super::hash_words::HashWords;
use super::insert_into_window::InsertIntoWindow;
use super::update_tree_leaf::UpdateTreeLeaf;
use crate::block::block_validation_error::BlockValidationRule;

/// Applies the mutations of a list of chunks to the peaks of the inactive
/// SWBF they lie in, in place: each tree's peak is recomputed from the
/// chunks' authentication paths with the chunks' hashes before and after
/// the insertions, as the removal of the records changes it.
///
/// ```text
/// BEFORE: _ *chunk_indices *chunks *insertions *tree_paths *swbfi_peaks [swbfi_leaf_count_estimate: u64] [swbfi_leaf_count: u64]
/// AFTER:  _
/// ```
///
/// `*chunk_indices` lists the chunks' leaf indices in ascending order,
/// `*chunks` and `*insertions` pointers to the unpacked chunks, each
/// preceded by the word that begins its encoding, and to the sorted indices
/// inserted into each, in the same order. `*tree_paths` lists a pointer to
/// the path list of each tree of an inactive SWBF with the estimated leaf
/// count, in ascending tree height, the way the witness describes it: the
/// authentication paths of the tree's chunks back to back, each against
/// the tree after the chunks before it have changed.
///
/// The trees of the estimate are walked from the highest down, each taking
/// the run of chunks that lie in it. A tree with chunks must be a tree of
/// the true inactive SWBF and its paths must reproduce the true peak from
/// the chunks' hashes, as the archival validity check of the records'
/// membership proofs demands. The peak is then replaced by the root over
/// the mutated chunks. Digests in a path list beyond what its run needs
/// are witness data nobody reads, and pass.
///
/// Crashes with the error ID of rule 2.a if a chunk lies in no tree of the
/// estimate, and with the error ID of rule 2.b if a tree with chunks is not
/// a tree of the true inactive SWBF or its paths do not reproduce the peak.
#[derive(Debug, Copy, Clone)]
pub(super) struct MutateSwbfiPeaks;

/// A tree's height and its chunks' leaf indices and hashes before and after
/// the insertions.
pub(super) type TreeRun = (u32, Vec<(u64, Digest)>, Vec<(u64, Digest)>);

impl MutateSwbfiPeaks {
    fn unpack_error_id() -> i128 {
        BlockValidationRule::RemovalRecordsUnpackFailure.error_id()
    }

    fn validity_error_id() -> i128 {
        BlockValidationRule::RemovalRecordsValidity.error_id()
    }

    /// The chunk after the insertions, as the mutator set produces it.
    pub(crate) fn mutated(chunk: &[u32], insertions: &[u32]) -> Vec<u32> {
        let mut mutated = [chunk, insertions].concat();
        mutated.sort_unstable();
        mutated
    }

    fn leaf_hash(chunk: &[u32]) -> Digest {
        Tip5::hash(&Chunk {
            relative_indices: chunk.to_vec(),
        })
    }

    /// The trees of an inactive SWBF with this leaf count, from the highest
    /// down, as the height and the index of the first leaf.
    fn trees(leaf_count: u64) -> Vec<(u32, u64)> {
        let mut trees = vec![];
        let mut start = 0;
        for height in (0..u64::BITS).rev() {
            if leaf_count & (1 << height) != 0 {
                trees.push((height, start));
                start += 1 << height;
            }
        }
        trees
    }

    /// The runs of chunks in the trees of an inactive SWBF with this leaf
    /// count, from the highest tree down: each tree's height with its
    /// chunks' leaf indices and hashes before and after the insertions.
    pub(super) fn runs(
        swbfi_leaf_count: u64,
        chunk_indices: &[u64],
        chunks: &[Vec<u32>],
        insertions: &[Vec<u32>],
    ) -> Vec<TreeRun> {
        let mut next_chunk = 0;
        Self::trees(swbfi_leaf_count)
            .into_iter()
            .map(|(height, start)| {
                let end = start + (1 << height);
                let run = next_chunk
                    + chunk_indices[next_chunk..]
                        .iter()
                        .take_while(|&&chunk_index| chunk_index < end)
                        .count();
                let leafs = |mutate: bool| {
                    (next_chunk..run)
                        .map(|position| {
                            let chunk = if mutate {
                                Self::mutated(&chunks[position], &insertions[position])
                            } else {
                                chunks[position].clone()
                            };
                            (chunk_indices[position] - start, Self::leaf_hash(&chunk))
                        })
                        .collect_vec()
                };
                let tree = (height, leafs(false), leafs(true));
                next_chunk = run;
                tree
            })
            .collect()
    }

    /// The tokens the prover supplies: for each tree of the estimate with
    /// chunks, from the highest down, the insertion's tokens for each chunk
    /// of the run.
    pub(crate) fn divined_tokens(
        swbfi_leaf_count_estimate: u64,
        chunk_indices: &[u64],
        chunks: &[Vec<u32>],
        insertions: &[Vec<u32>],
    ) -> Vec<BFieldElement> {
        let mut tokens = vec![];
        let mut next_chunk = 0;
        for (_, old_leafs, _) in
            Self::runs(swbfi_leaf_count_estimate, chunk_indices, chunks, insertions)
        {
            for position in next_chunk..next_chunk + old_leafs.len() {
                tokens.extend(InsertIntoWindow::divined_tokens(
                    &chunks[position],
                    &insertions[position],
                ));
            }
            next_chunk += old_leafs.len();
        }
        tokens
    }

    /// The path lists the witness holds, in ascending tree height, from the
    /// trees' authentication structures for the chunks in the same order.
    pub(crate) fn tree_paths(
        swbfi_leaf_count: u64,
        chunk_indices: &[u64],
        chunks: &[Vec<u32>],
        insertions: &[Vec<u32>],
        auth_structs: &[Vec<Digest>],
    ) -> Vec<Vec<Digest>> {
        Self::runs(swbfi_leaf_count, chunk_indices, chunks, insertions)
            .into_iter()
            .rev()
            .zip(auth_structs)
            .map(|((height, old_leafs, new_leafs), auth_struct)| {
                UpdateTreeLeaf::sequential_paths(height, auth_struct, &old_leafs, &new_leafs)
            })
            .collect()
    }

    /// The inverse of [`Self::tree_paths`]: the trees' authentication
    /// structures from the witness's path lists.
    pub(crate) fn tree_auth_structs(
        swbfi_leaf_count: u64,
        chunk_indices: &[u64],
        chunks: &[Vec<u32>],
        insertions: &[Vec<u32>],
        tree_paths: &[Vec<Digest>],
    ) -> Vec<Vec<Digest>> {
        Self::runs(swbfi_leaf_count, chunk_indices, chunks, insertions)
            .into_iter()
            .rev()
            .zip(tree_paths)
            .map(|((height, old_leafs, _), paths)| {
                UpdateTreeLeaf::auth_struct_from_paths(height, paths, &old_leafs)
            })
            .collect()
    }
}

impl BasicSnippet for MutateSwbfiPeaks {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (
                DataType::List(Box::new(DataType::U64)),
                "*chunk_indices".to_string(),
            ),
            (
                DataType::List(Box::new(DataType::Bfe)),
                "*chunks".to_string(),
            ),
            (
                DataType::List(Box::new(DataType::Bfe)),
                "*insertions".to_string(),
            ),
            (
                DataType::List(Box::new(DataType::Bfe)),
                "*tree_paths".to_string(),
            ),
            (
                DataType::List(Box::new(DataType::Digest)),
                "*swbfi_peaks".to_string(),
            ),
            (DataType::U64, "swbfi_leaf_count_estimate".to_string()),
            (DataType::U64, "swbfi_leaf_count".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_mutate_swbfi_peaks".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let get_pointer = library.import(Box::new(Get::new(DataType::Bfe)));
        let get_digest = library.import(Box::new(Get::new(DataType::Digest)));
        let set_digest = library.import(Box::new(Set::new(DataType::Digest)));
        let hash_words = library.import(Box::new(HashWords));
        let log_2_floor = library.import(Box::new(Log2Floor));
        let pow2 = library.import(Box::new(Pow2));
        let popcount = library.import(Box::new(PopCount));
        let u64_add = library.import(Box::new(U64Add));
        let u64_sub = library.import(Box::new(U64Sub));
        let u64_lt = library.import(Box::new(U64Lt));
        let u64_shift_right = library.import(Box::new(U64ShiftRight));
        let hash_chunk_with_insertions = library.import(Box::new(HashChunkWithInsertions));
        let update_tree_leaf = library.import(Box::new(UpdateTreeLeaf));

        let chunk_indices_alloc = library.kmalloc(1);
        let chunks_alloc = library.kmalloc(1);
        let insertions_alloc = library.kmalloc(1);
        let tree_paths_alloc = library.kmalloc(1);
        let peaks_alloc = library.kmalloc(1);
        let estimate_alloc = library.kmalloc(2);
        let leaf_count_alloc = library.kmalloc(2);
        // The trees of the estimate not walked yet, as a leaf count.
        let remaining_alloc = library.kmalloc(2);
        // The current tree's height, first leaf and end.
        let height_alloc = library.kmalloc(1);
        let tree_start_alloc = library.kmalloc(2);
        let tree_end_alloc = library.kmalloc(2);
        // What a chunk index in the current tree adds up to its node index
        // with the high limb raised, as the leaf update takes it: the tree's
        // leaf count less its first leaf, limb by limb, plus one up high.
        let node_offset_alloc = library.kmalloc(2);
        // The current tree's root, before and after each chunk.
        let running_alloc = library.kmalloc(Digest::LEN as u32);
        // The next chunk to place in a tree, and the position of the current
        // tree's path list.
        let next_chunk_alloc = library.kmalloc(1);
        let paths_position_alloc = library.kmalloc(1);

        let entrypoint = self.entrypoint();
        let trees_loop = format!("{entrypoint}_trees_loop");
        let run_loop = format!("{entrypoint}_run_loop");
        let mutate_tree = format!("{entrypoint}_mutate_tree");
        let chunks = format!("{entrypoint}_chunks");
        let chunks_loop = format!("{entrypoint}_chunks_loop");
        let single_leaf_tree = format!("{entrypoint}_single_leaf_tree");
        let chunk_hashes = format!("{entrypoint}_chunk_hashes");
        let unpack_error_id = Self::unpack_error_id();
        let validity_error_id = Self::validity_error_id();

        let read_remaining = triton_asm!(push {remaining_alloc.read_address()} read_mem 2 pop 1);
        let read_leaf_count = triton_asm!(push {leaf_count_alloc.read_address()} read_mem 2 pop 1);
        let read_estimate = triton_asm!(push {estimate_alloc.read_address()} read_mem 2 pop 1);
        let read_tree_start = triton_asm!(push {tree_start_alloc.read_address()} read_mem 2 pop 1);
        let read_tree_end = triton_asm!(push {tree_end_alloc.read_address()} read_mem 2 pop 1);
        let read_height = triton_asm!(push {height_alloc.read_address()} read_mem 1 pop 1);
        let read_next_chunk = triton_asm!(push {next_chunk_alloc.read_address()} read_mem 1 pop 1);
        let read_chunk_indices =
            triton_asm!(push {chunk_indices_alloc.read_address()} read_mem 1 pop 1);
        let read_peaks = triton_asm!(push {peaks_alloc.read_address()} read_mem 1 pop 1);
        let read_paths_position =
            triton_asm!(push {paths_position_alloc.read_address()} read_mem 1 pop 1);

        triton_asm!(
            {entrypoint}:
                // _ *chunk_indices *chunks *insertions *tree_paths *swbfi_peaks [estimate] [leaf_count]
                push {leaf_count_alloc.write_address()} write_mem 2 pop 1
                dup 1 dup 1 push {estimate_alloc.write_address()} write_mem 2 pop 1
                push {remaining_alloc.write_address()} write_mem 2 pop 1
                push {peaks_alloc.write_address()} write_mem 1 pop 1
                push {tree_paths_alloc.write_address()} write_mem 1 pop 1
                push {insertions_alloc.write_address()} write_mem 1 pop 1
                push {chunks_alloc.write_address()} write_mem 1 pop 1
                push {chunk_indices_alloc.write_address()} write_mem 1 pop 1
                // _

                push 0 push 0 push {tree_start_alloc.write_address()} write_mem 2 pop 1
                push 0 push {next_chunk_alloc.write_address()} write_mem 1 pop 1
                // The path lists come in ascending height: the highest tree's
                // is the last.
                {&read_estimate} call {popcount}
                push {paths_position_alloc.write_address()} write_mem 1 pop 1
                // _

                call {trees_loop}
                // _

                // Every chunk lies in a tree of the estimate.
                {&read_next_chunk}
                {&read_chunk_indices} read_mem 1 pop 1
                eq assert error_id {unpack_error_id}
                // _

                return

            // Walks the trees of the estimate from the highest down.
            // INVARIANT: _
            {trees_loop}:
                {&read_remaining} add push 0 eq skiz return
                // _

                {&read_remaining} call {log_2_floor}
                dup 0 push {height_alloc.write_address()} write_mem 1 pop 1
                // _ height

                dup 0 call {pow2} {&read_remaining} call {u64_sub}
                push {remaining_alloc.write_address()} write_mem 2 pop 1
                // _ height

                call {pow2} dup 1 dup 1 {&read_tree_start}
                push -1 mul pick 2 add place 2 push -1 mul add addi 1 swap 1
                push {node_offset_alloc.write_address()} write_mem 2 pop 1
                {&read_tree_start} call {u64_add}
                push {tree_end_alloc.write_address()} write_mem 2 pop 1
                // _

                {&read_paths_position} addi -1
                push {paths_position_alloc.write_address()} write_mem 1 pop 1
                // _

                // The run of chunks in this tree.
                {&read_next_chunk}
                call {run_loop}
                // _ next_chunk'

                {&read_next_chunk} dup 1 push {next_chunk_alloc.write_address()} write_mem 1 pop 1
                push -1 mul add
                // _ run_length

                push {tree_paths_alloc.read_address()} read_mem 1 pop 1
                {&read_paths_position} call {get_pointer}
                // _ run_length *paths

                swap 1 dup 0 push 0 eq push 0 eq
                // _ *paths run_length (run_length != 0)

                skiz call {mutate_tree}
                pop 2
                // _

                {&read_tree_end} push {tree_start_alloc.write_address()} write_mem 2 pop 1
                recurse

            // Counts the chunks, from the next one on, that lie in this tree.
            // INVARIANT: _ next_chunk
            {run_loop}:
                {&read_chunk_indices} read_mem 1 pop 1 dup 1 eq skiz return
                {&read_chunk_indices} dup 1 push 2 mul add addi 2 read_mem 2 pop 1
                {&read_tree_end} dup 3 dup 3 call {u64_lt}
                // _ next_chunk [chunk_index] (chunk_index < tree_end)

                place 2 pop 2
                push 0 eq skiz return
                addi 1
                recurse

            // A tree with chunks: it is a tree of the true inactive SWBF, its
            // paths reproduce the peak, and the peak becomes the root over
            // the mutated chunks.
            // BEFORE: _ *paths run_length
            // AFTER:  _ *paths run_length
            {mutate_tree}:
                {&read_height} addi 1
                // _ *paths run_length (height + 1)

                {&read_leaf_count} dup 2 call {u64_shift_right}
                {&read_estimate} dup 4 call {u64_shift_right}
                {&DataType::U64.compare()} assert error_id {validity_error_id}
                // _ *paths run_length (height + 1)

                {&read_leaf_count} dup 2 addi -1 call {u64_shift_right}
                swap 1 pop 1 push 2 swap 1 div_mod pick 1 pop 1
                assert error_id {validity_error_id}
                // _ *paths run_length (height + 1)

                {&read_leaf_count} pick 2 call {u64_shift_right} call {popcount}
                // _ *paths run_length peak_index

                {&read_peaks} dup 1 call {get_digest}
                push {running_alloc.write_address()} write_mem {Digest::LEN} pop 1
                {&read_next_chunk} dup 2 push -1 mul add
                // _ *paths run_length peak_index first

                {&read_height} push 0 eq skiz call {single_leaf_tree}
                {&read_height} push 0 eq push 0 eq skiz call {chunks}
                // _ *paths run_length peak_index first

                push {running_alloc.read_address()} read_mem {Digest::LEN} pop 1
                {&read_peaks} dup 7 call {set_digest}
                pop 2
                // _ *paths run_length

                return

            // A tree of one leaf: the chunk is the peak.
            // BEFORE: _ *paths run_length peak_index first
            // AFTER:  _ *paths run_length peak_index first
            {single_leaf_tree}:
                dup 0 call {chunk_hashes}
                push {running_alloc.read_address()} read_mem {Digest::LEN} pop 1
                pick 14 pick 14 pick 14 pick 14 pick 14
                // _ *paths run_length peak_index first [new] [running] [old]

                assert_vector error_id {validity_error_id}
                pop 5
                push {running_alloc.write_address()} write_mem {Digest::LEN} pop 1
                return

            // BEFORE: _ *paths run_length peak_index first
            // AFTER:  _ *paths run_length peak_index first
            {chunks}:
                pick 2 push 0
                call {chunks_loop}
                // _ *paths peak_index first run_length run_length

                pop 1 place 2
                return

            // Each chunk of the run in turn: its hash before and after the
            // insertions walked up its path, the first to the running root,
            // the second to the root the tree then has.
            // INVARIANT: _ *paths peak_index first run_length t
            {chunks_loop}:
                dup 1 dup 1 eq skiz return
                push {running_alloc.write_address()}
                {&read_height} push {Digest::LEN} mul dup 2 mul addi 1 dup 6 add
                // _ *paths peak_index first run_length t *running *path

                dup 4 dup 3 add
                {&read_chunk_indices} dup 1 push 2 mul add addi 2 read_mem 2 pop 1
                // _ ... t *running *path p [chunk_index]

                // The chunk lies in the tree, so neither limb borrows or
                // carries.
                push {node_offset_alloc.read_address()} read_mem 2 pop 1
                pick 2 add place 2 add swap 1
                pick 2 dup 3 dup 3 dup 3 pick 3
                // _ ... t *running *path (hi + 1) lo *path (hi + 1) lo p

                call {chunk_hashes}
                call {update_tree_leaf}
                // _ *paths peak_index first run_length t

                addi 1
                recurse

            // The hash of the chunk at a position before and after its
            // insertions. The chunk is sorted, as every chunk that hashes to
            // a leaf of the inactive SWBF is, so the insertion hashes the
            // sorted union the mutator set produces.
            // BEFORE: _ p
            // AFTER:  _ [old] [new]
            {chunk_hashes}:
                push {chunks_alloc.read_address()} read_mem 1 pop 1 dup 1 add addi 1 read_mem 1 pop 1
                addi -1
                // _ p *encoding

                dup 0 dup 0 read_mem 1 pop 1 addi 1 call {hash_words}
                // _ p *encoding [old]

                dup 5
                push {insertions_alloc.read_address()} read_mem 1 pop 1 dup 8 add addi 1 read_mem 1 pop 1
                call {hash_chunk_with_insertions}
                // _ p *encoding [old] [new]

                pick 11 pop 1 pick 10 pop 1
                return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;

    use neptune_mutator_set::shared::CHUNK_SIZE;
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::triton_vm::isa::instruction::AssertionError;
    use tasm_lib::triton_vm::isa::instruction::InstructionError;
    use tasm_lib::triton_vm::vm::VMState;
    use tasm_lib::triton_vm::vm::VM;
    use tasm_lib::twenty_first::util_types::merkle_tree::MerkleTree;

    use super::super::update_tree_leaf::UpdateTreeLeaf;
    use super::*;

    /// An inactive SWBF of chunks, with some chunks chosen for mutation.
    struct Fixture {
        leaf_count: u64,
        estimate: u64,
        chunks_by_leaf: Vec<Vec<u32>>,
        chunk_indices: Vec<u64>,
        /// The witness's chunks: those at the chunk indices, unless a test
        /// tampers with them.
        chunks: Vec<Vec<u32>>,
        insertions: Vec<Vec<u32>>,
        tree_paths: Vec<Vec<Digest>>,
        peaks: Vec<Digest>,
    }

    /// A chunk or an insertion list with this many random indices.
    fn sorted_indices(rng: &mut StdRng, length: usize) -> Vec<u32> {
        let mut entries = (0..length)
            .map(|_| rng.random_range(0..CHUNK_SIZE))
            .collect_vec();
        entries.sort_unstable();
        entries
    }

    impl Fixture {
        fn new(rng: &mut StdRng, leaf_count: u64, chunk_indices: Vec<u64>, estimate: u64) -> Self {
            let chunks_by_leaf = (0..leaf_count)
                .map(|_| {
                    let length = rng.random_range(0..20);
                    sorted_indices(rng, length)
                })
                .collect_vec();
            let insertions = chunk_indices
                .iter()
                .map(|_| {
                    let length = rng.random_range(0..10);
                    sorted_indices(rng, length)
                })
                .collect_vec();
            let chunks = chunk_indices
                .iter()
                .map(|&chunk_index| chunks_by_leaf[chunk_index as usize].clone())
                .collect();
            let mut fixture = Self {
                leaf_count,
                estimate,
                chunks_by_leaf,
                chunk_indices,
                chunks,
                insertions,
                tree_paths: vec![],
                peaks: vec![],
            };
            fixture.tree_paths = fixture.tree_paths();
            fixture.peaks = fixture.peaks_of(&fixture.chunks_by_leaf);
            fixture
        }

        fn chunks(&self) -> Vec<Vec<u32>> {
            self.chunks.clone()
        }

        fn tree(&self, height: u32, start: u64, chunks_by_leaf: &[Vec<u32>]) -> MerkleTree {
            let leafs = (start..start + (1 << height))
                .map(|leaf| MutateSwbfiPeaks::leaf_hash(&chunks_by_leaf[leaf as usize]))
                .collect_vec();
            MerkleTree::par_new(&leafs).unwrap()
        }

        fn peaks_of(&self, chunks_by_leaf: &[Vec<u32>]) -> Vec<Digest> {
            MutateSwbfiPeaks::trees(self.leaf_count)
                .into_iter()
                .map(|(height, start)| self.tree(height, start, chunks_by_leaf).root())
                .collect()
        }

        fn expected_peaks(&self) -> Vec<Digest> {
            let mut chunks_by_leaf = self.chunks_by_leaf.clone();
            for (chunk_index, insertions) in self.chunk_indices.iter().zip(&self.insertions) {
                let chunk = &mut chunks_by_leaf[*chunk_index as usize];
                *chunk = MutateSwbfiPeaks::mutated(chunk, insertions);
            }
            self.peaks_of(&chunks_by_leaf)
        }

        /// The path lists of the estimate's trees, in ascending height, from
        /// the true trees' authentication structures.
        fn tree_paths(&self) -> Vec<Vec<Digest>> {
            let auth_structs = MutateSwbfiPeaks::trees(self.estimate)
                .into_iter()
                .rev()
                .map(|(height, start)| {
                    let leaf_indices = self
                        .chunk_indices
                        .iter()
                        .filter(|&&chunk_index| {
                            (start..start + (1 << height)).contains(&chunk_index)
                        })
                        .map(|chunk_index| (chunk_index - start) as usize)
                        .collect_vec();
                    self.tree(height, start, &self.chunks_by_leaf)
                        .authentication_structure(&leaf_indices)
                        .unwrap()
                })
                .collect_vec();
            MutateSwbfiPeaks::tree_paths(
                self.estimate,
                &self.chunk_indices,
                &self.chunks,
                &self.insertions,
                &auth_structs,
            )
        }

        fn tokens(&self) -> Vec<BFieldElement> {
            MutateSwbfiPeaks::divined_tokens(
                self.estimate,
                &self.chunk_indices,
                &self.chunks(),
                &self.insertions,
            )
        }

        fn program_and_nondeterminism(
            &self,
            tokens: Vec<BFieldElement>,
        ) -> (Program, NonDeterminism, BFieldElement) {
            let mut library = Library::new();
            let snippet = library.import(Box::new(MutateSwbfiPeaks));
            let push_u64 = |value: u64| {
                value
                    .encode()
                    .into_iter()
                    .rev()
                    .flat_map(|limb| triton_asm!(push { limb }))
                    .collect_vec()
            };
            let pointer = |i: u64| bfe!(1 << (20 + i));
            let program = Program::new(&triton_asm!(
                push {pointer(0)} push {pointer(1)} push {pointer(2)} push {pointer(3)}
                push {pointer(4)}
                {&push_u64(self.estimate)}
                {&push_u64(self.leaf_count)}
                call {snippet}
                halt
                {&library.all_imports()}
            ));

            let mut ram = HashMap::new();
            encode_to_memory(&mut ram, pointer(0), &self.chunk_indices);
            let mut next = pointer(5);
            // The chunks lie in their encodings, a word past the length.
            let chunks = self
                .chunks()
                .into_iter()
                .map(|relative_indices| Chunk { relative_indices })
                .collect_vec();
            let chunks = lists_of_lists(&mut ram, &mut next, &chunks)
                .into_iter()
                .map(|encoding| encoding + bfe!(1))
                .collect_vec();
            encode_to_memory(&mut ram, pointer(1), &chunks);
            let insertions = lists_of_lists(&mut ram, &mut next, &self.insertions);
            encode_to_memory(&mut ram, pointer(2), &insertions);
            let tree_paths = lists_of_lists(&mut ram, &mut next, &self.tree_paths);
            encode_to_memory(&mut ram, pointer(3), &tree_paths);
            encode_to_memory(&mut ram, pointer(4), &self.peaks);

            let nondeterminism = NonDeterminism::new(tokens).with_ram(ram);
            (program, nondeterminism, pointer(4))
        }

        fn run(&self, tokens: Vec<BFieldElement>) -> Result<Vec<Digest>, InstructionError> {
            let (program, nondeterminism, peaks) = self.program_and_nondeterminism(tokens);
            let mut state = VMState::new(program, PublicInput::default(), nondeterminism);
            state.run()?;
            let num_peaks = state.ram[&peaks].value();
            Ok((0..num_peaks)
                .map(|i| {
                    let words = (0..Digest::LEN)
                        .map(|w| state.ram[&(peaks + bfe!(1 + i * 5 + w as u64))])
                        .collect_vec();
                    Digest::new(words.try_into().unwrap())
                })
                .collect())
        }

        fn assert_agrees(&self) {
            assert_eq!(self.expected_peaks(), self.run(self.tokens()).unwrap());
        }

        fn assert_rejects(&self, error_id: i128) {
            let Err(
                InstructionError::AssertionFailed(AssertionError { id, .. })
                | InstructionError::VectorAssertionFailed(_, AssertionError { id, .. }),
            ) = self.run(self.tokens())
            else {
                panic!("must fail");
            };
            assert_eq!(Some(error_id), id);
        }
    }

    /// Writes each value at its own address, and returns those addresses.
    fn lists_of_lists<T: BFieldCodec>(
        ram: &mut HashMap<BFieldElement, BFieldElement>,
        next: &mut BFieldElement,
        values: &[T],
    ) -> Vec<BFieldElement> {
        let mut pointers = vec![];
        for value in values {
            encode_to_memory(ram, *next, value);
            pointers.push(*next);
            *next += bfe!(1 << 16);
        }
        pointers
    }

    /// Prints how the cycles distribute over subroutines for a transaction
    /// with many large chunks in a main-net-sized inactive SWBF, for chunks
    /// scattered over the tree and for chunks clustered the way the inputs
    /// of a transaction cluster them. The tree around the chunks is all
    /// zeros, and the peak whatever that implies.
    #[test]
    #[ignore = "prints a profile"]
    fn profile_many_large_chunks() {
        let mut rng = StdRng::seed_from_u64(9);
        let height = 59;
        let leaf_count = (1 << height) + 5;
        for (num_clusters, chunks_per_cluster) in [(84, 1), (2, 42)] {
            let chunk_indices = (0..num_clusters)
                .flat_map(|_| {
                    let start = rng.random_range(0..(1 << height) - 256);
                    (0..chunks_per_cluster)
                        .map(|_| start + rng.random_range(0..256))
                        .collect_vec()
                })
                .sorted_unstable()
                .dedup()
                .collect_vec();
            let chunks = chunk_indices
                .iter()
                .map(|_| sorted_indices(&mut rng, 410))
                .collect_vec();
            let insertions = chunk_indices
                .iter()
                .map(|_| sorted_indices(&mut rng, 5))
                .collect_vec();
            let leafs = |mutate: bool| {
                chunk_indices
                    .iter()
                    .zip(&chunks)
                    .zip(&insertions)
                    .map(|((&chunk_index, chunk), insertion)| {
                        let chunk = if mutate {
                            MutateSwbfiPeaks::mutated(chunk, insertion)
                        } else {
                            chunk.clone()
                        };
                        (chunk_index, MutateSwbfiPeaks::leaf_hash(&chunk))
                    })
                    .collect_vec()
            };
            // Paths through a tree of zero digests around the chunks.
            let paths = UpdateTreeLeaf::sequential_paths(height, &[], &leafs(false), &leafs(true));
            let (old_root, _) =
                UpdateTreeLeaf::try_roots(height, &paths, &leafs(false), &leafs(true)).unwrap();
            let peaks = vec![old_root, rng.random(), rng.random()];
            let fixture = Fixture {
                leaf_count,
                estimate: leaf_count,
                chunks_by_leaf: vec![],
                chunk_indices,
                chunks,
                insertions,
                tree_paths: vec![vec![], vec![], paths],
                peaks,
            };

            let (program, nondeterminism, _) = fixture.program_and_nondeterminism(fixture.tokens());
            let (_, profile) =
                VM::profile(program, PublicInput::default(), nondeterminism).unwrap();
            println!(
                "{} chunks in {num_clusters} clusters:\n{profile}",
                fixture.chunk_indices.len(),
            );
        }
    }

    #[test]
    fn mutated_peaks_agree_with_rebuilt_trees() {
        let mut rng = StdRng::seed_from_u64(0);
        for (leaf_count, chunk_indices) in [
            (1, vec![0]),
            (2, vec![0, 1]),
            (13, vec![1, 2, 5, 9, 12]),
            (13, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
            (16, vec![7]),
            (37, vec![0, 31, 32, 35, 36]),
        ] {
            Fixture::new(&mut rng, leaf_count, chunk_indices, leaf_count).assert_agrees();
        }
    }

    #[test]
    fn chunks_in_no_tree_leave_the_peaks() {
        let mut rng = StdRng::seed_from_u64(1);
        let fixture = Fixture::new(&mut rng, 13, vec![], 13);
        assert_eq!(fixture.peaks, fixture.run(fixture.tokens()).unwrap());
    }

    #[test]
    fn smaller_estimate_with_the_same_trees_agrees() {
        let mut rng = StdRng::seed_from_u64(2);
        Fixture::new(&mut rng, 13, vec![1, 9, 11], 12).assert_agrees();
        Fixture::new(&mut rng, 13, vec![1, 5], 8).assert_agrees();
    }

    #[test]
    fn estimate_with_another_tree_fails() {
        let mut rng = StdRng::seed_from_u64(3);
        Fixture::new(&mut rng, 13, vec![1, 5], 4)
            .assert_rejects(MutateSwbfiPeaks::validity_error_id());
        Fixture::new(&mut rng, 6, vec![0], 2).assert_rejects(MutateSwbfiPeaks::validity_error_id());
    }

    #[test]
    fn chunk_beyond_the_estimate_fails() {
        let mut rng = StdRng::seed_from_u64(4);
        Fixture::new(&mut rng, 13, vec![1, 12], 8)
            .assert_rejects(MutateSwbfiPeaks::unpack_error_id());
    }

    #[test]
    fn tampered_chunk_fails() {
        let mut rng = StdRng::seed_from_u64(5);
        let mut fixture = Fixture::new(&mut rng, 13, vec![1, 2, 5, 9, 12], 13);
        fixture.chunks[2].insert(0, 0);
        fixture.assert_rejects(MutateSwbfiPeaks::validity_error_id());
    }

    #[test]
    fn every_word_of_every_path_digest_is_checked() {
        let mut rng = StdRng::seed_from_u64(6);
        let fixture = Fixture::new(&mut rng, 13, vec![1, 2, 5, 9], 13);
        for (tree, position, word) in fixture
            .tree_paths
            .iter()
            .enumerate()
            .flat_map(|(t, paths)| (0..paths.len()).map(move |p| (t, p)))
            .flat_map(|(t, p)| (0..Digest::LEN).map(move |w| (t, p, w)))
        {
            let mut tampered =
                Fixture::new(&mut StdRng::seed_from_u64(6), 13, vec![1, 2, 5, 9], 13);
            tampered.tree_paths[tree][position].0[word] += bfe!(1);
            tampered.assert_rejects(MutateSwbfiPeaks::validity_error_id());
        }
    }

    #[test]
    fn every_word_of_every_peak_with_chunks_is_checked() {
        let mut rng = StdRng::seed_from_u64(11);
        let fixture = Fixture::new(&mut rng, 13, vec![1, 2, 5, 9, 12], 13);
        let peaks_with_chunks = MutateSwbfiPeaks::runs(
            fixture.leaf_count,
            &fixture.chunk_indices,
            &fixture.chunks,
            &fixture.insertions,
        )
        .into_iter()
        .enumerate()
        .filter(|(_, (_, old_leafs, _))| !old_leafs.is_empty())
        .map(|(peak, _)| peak)
        .collect_vec();
        assert_eq!(vec![0, 1, 2], peaks_with_chunks);
        for (peak, word) in peaks_with_chunks
            .into_iter()
            .flat_map(|p| (0..Digest::LEN).map(move |w| (p, w)))
        {
            let mut tampered =
                Fixture::new(&mut StdRng::seed_from_u64(11), 13, vec![1, 2, 5, 9, 12], 13);
            tampered.peaks[peak].0[word] += bfe!(1);
            tampered.assert_rejects(MutateSwbfiPeaks::validity_error_id());
        }
    }

    #[test]
    fn every_entry_of_every_chunk_is_checked() {
        let mut rng = StdRng::seed_from_u64(12);
        let fixture = Fixture::new(&mut rng, 13, vec![1, 2, 5, 9, 12], 13);
        assert!(fixture.chunks.iter().any(|chunk| !chunk.is_empty()));
        for (chunk, entry) in (0..fixture.chunks.len())
            .flat_map(|c| (0..fixture.chunks[c].len()).map(move |e| (c, e)))
        {
            let fresh =
                || Fixture::new(&mut StdRng::seed_from_u64(12), 13, vec![1, 2, 5, 9, 12], 13);
            let mut tampered = fresh();
            let value = tampered.chunks[chunk][entry];
            tampered.chunks[chunk][entry] = if value == 0 { 1 } else { value - 1 };
            tampered.assert_rejects(MutateSwbfiPeaks::validity_error_id());

            let mut tampered = fresh();
            tampered.chunks[chunk].remove(entry);
            tampered.assert_rejects(MutateSwbfiPeaks::validity_error_id());
        }
        for chunk in 0..fixture.chunks.len() {
            let mut tampered =
                Fixture::new(&mut StdRng::seed_from_u64(12), 13, vec![1, 2, 5, 9, 12], 13);
            tampered.chunks[chunk].insert(0, 0);
            tampered.assert_rejects(MutateSwbfiPeaks::validity_error_id());
        }
    }

    #[test]
    fn spare_path_digest_passes_and_missing_digest_fails() {
        // A digest in a path list nobody reads changes nothing.
        let mut rng = StdRng::seed_from_u64(7);
        let mut fixture = Fixture::new(&mut rng, 13, vec![1, 2, 5, 9], 13);
        for paths in &mut fixture.tree_paths {
            paths.push(rng.random());
        }
        fixture.assert_agrees();

        // A missing digest makes the last chunk's walk read past its list.
        let mut fixture = Fixture::new(&mut rng, 13, vec![1, 2, 5, 9], 13);
        let paths = fixture
            .tree_paths
            .iter_mut()
            .find(|paths| !paths.is_empty())
            .unwrap();
        paths.pop();
        fixture.assert_rejects(MutateSwbfiPeaks::validity_error_id());
    }
}
