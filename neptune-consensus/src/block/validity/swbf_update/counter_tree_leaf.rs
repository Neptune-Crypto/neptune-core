//! The leaf of the SWBF update tree in the counter-tree form of proposal
//! f): a chunk of the inactive SWBF is a Merkle tree over the counts of
//! its indices, so an insertion is a path update instead of a hash of the
//! whole chunk, and an index is unset if its count is zero. Built to
//! measure the leaf's cost per input in that form against the list
//! form's, on the list form's own fixture; no block uses it.

use std::collections::HashMap;

use get_size2::GetSize;
use neptune_mutator_set::active_window::ActiveWindow;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_mutator_set::shared::CHUNK_SIZE;
use neptune_mutator_set::shared::NUM_TRIALS;
use neptune_mutator_set::shared::WINDOW_SIZE;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::arithmetic::u128::lt::Lt as U128Lt;
use tasm_lib::arithmetic::u128::safe_add::SafeAdd as U128SafeAdd;
use tasm_lib::arithmetic::u128::shift_left_static::ShiftLeftStatic;
use tasm_lib::arithmetic::u128::sub::Sub as U128Sub;
use tasm_lib::field;
use tasm_lib::library::Library;
use tasm_lib::list::new::New;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::memcpy::MemCpy;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::prelude::Mmr;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

use super::counter_tree_removals::CounterTreeRemovals;
use super::counter_tree_root::counter_tree_root;
use super::counter_tree_root::CounterTree;
use super::leaf::CorrectSwbfUpdate;
use super::leaf::CorrectSwbfUpdateWitness;
use super::mutate_swbfi_peaks::MutateSwbfiPeaks;
use super::removal_index_commitment::RemovalIndexCommitment;
use super::removal_records_are_unspent::RemovalRecordsAreUnspent;
use super::swbfi_peaks_after_removals::SwbfiPeaksAfterRemovals;
use super::update_tree_leaf::UpdateTreeLeaf;
use super::window_after_removals::WindowAfterRemovals;
use super::witness_lists::WitnessLists;
use super::ClaimOutput;
use crate::block::block_validation_error::BlockValidationRule;
use crate::block::validity::mutator_set_hash::MutatorSetHash;
use crate::block::validity::mutator_set_hash::MutatorSetHashFromComponents;
use crate::proof_abstractions::tasm::program::TritonProgram;

const LOG2_CHUNK_SIZE: u8 = CHUNK_SIZE.ilog2() as u8;

/// [`RemovalRecordsAreUnspent`] in the counter form: the same check of
/// the active window, and for an index in the inactive part a count of
/// zero in the table `*chunks` points at, [`NUM_TRIALS`] words per record.
#[derive(Debug, Copy, Clone)]
struct CounterTreeUnspent;

impl BasicSnippet for CounterTreeUnspent {
    fn parameters(&self) -> Vec<(DataType, String)> {
        RemovalRecordsAreUnspent.parameters()
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_counter_tree_unspent".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let new_list = library.import(Box::new(New));
        let u128_lt = library.import(Box::new(U128Lt));
        let u128_sub = library.import(Box::new(U128Sub));
        let u128_safe_add = library.import(Box::new(U128SafeAdd));
        let to_window_start = library.import(Box::new(ShiftLeftStatic::<{ LOG2_CHUNK_SIZE }>));

        // The divined position of the record's index, kept for the table.
        let position_alloc = library.kmalloc(1);

        let entrypoint = self.entrypoint();
        let assert_sorted = format!("{entrypoint}_assert_sorted");
        let sorted_by_5 = format!("{entrypoint}_sorted_by_5");
        let sorted_by_1 = format!("{entrypoint}_sorted_by_1");
        let records_loop = format!("{entrypoint}_records_loop");
        let inactive = format!("{entrypoint}_inactive");
        let active = format!("{entrypoint}_active");
        let gap = format!("{entrypoint}_gap");
        let gap_left = format!("{entrypoint}_gap_left");
        let gap_right = format!("{entrypoint}_gap_right");

        let error_id = BlockValidationRule::RemovalRecordsValidity.error_id();
        let unsorted_window_error_id = RemovalRecordsAreUnspent::UNSORTED_WINDOW_ERROR_ID;
        let read_u128 = triton_asm!(addi 3 read_mem 4 pop 1);

        // Asserts y <= x, keeping the larger one.
        // BEFORE: _ x y
        // AFTER:  _ x
        let assert_below_keep_upper =
            triton_asm!(dup 1 lt push 0 eq assert error_id {unsorted_window_error_id});

        // Asserts y <= x, keeping the smaller one.
        // BEFORE: _ x y
        // AFTER:  _ y
        let assert_below_keep_lower = triton_asm!(
            dup 0 place 2 swap 1 lt push 0 eq assert error_id {unsorted_window_error_id}
        );

        // BEFORE: _ neg_index ... e (element - index) * ...
        // Folds one more element into the product.
        // The context: the chunk indices and their number, the chunks, the
        // active window's list, and the window start.
        let chunks_offset = 2;
        let window_offset = 3;
        let window_start_offset = 4;

        triton_asm!(
            {entrypoint}:
                // _ *removal_records *chunk_indices *chunks *active_window [swbfi_leaf_count]
                push 0 push 0 pick 3 pick 3 call {to_window_start}
                // _ *removal_records *chunk_indices *chunks *active_window [window_start]

                pick 4 {&field!(ActiveWindow::sbf)}
                dup 0 call {assert_sorted}
                // _ *removal_records *chunk_indices *chunks [window_start] *window

                pick 5 dup 6 read_mem 1 pop 1 pick 7
                // _ *removal_records [window_start] *window *chunks num_chunks *chunk_indices

                call {new_list}
                write_mem 5 write_mem 3 addi -8
                // _ *removal_records *context

                swap 1 read_mem 1 addi 2 place 1 push 0
                // _ *context *record[0]_si num_records 0

                call {records_loop}
                pop 4
                // _

                return

            // The window's list must be sorted, with every entry inside the
            // window, for the gap test to mean anything. The entries are
            // checked from the last one down, against the largest index in
            // the window first.
            // BEFORE: _ *list
            // AFTER:  _
            {assert_sorted}:
                read_mem 1 addi 1 dup 1 add
                // _ len *last

                push {WINDOW_SIZE - 1}
                // _ len *next prev

                call {sorted_by_5}
                call {sorted_by_1}
                // _ 0 *list prev

                pop 3
                return

            // INVARIANT: _ len *next prev
            {sorted_by_5}:
                push 5 dup 3 lt skiz return
                // _ len *next prev

                swap 1 read_mem 5 place 6
                // _ len (*next - 5) prev m[next] m[next - 1] m[next - 2] m[next - 3] m[next - 4]

                dup 0 place 6
                // _ len (*next - 5) m[next - 4] prev m[next] m[next - 1] m[next - 2] m[next - 3] m[next - 4]

                {&assert_below_keep_upper}
                {&assert_below_keep_upper}
                {&assert_below_keep_upper}
                {&assert_below_keep_upper}
                {&assert_below_keep_upper}
                // _ len (*next - 5) m[next - 4] prev

                pop 1
                pick 2 addi -5 place 2
                // _ (len - 5) (*next - 5) m[next - 4]

                recurse

            // INVARIANT: _ len *next prev
            {sorted_by_1}:
                dup 2 push 0 eq skiz return
                // _ len *next prev

                swap 1 read_mem 1 place 2
                // _ len (*next - 1) prev m[next]

                {&assert_below_keep_lower}
                // _ len (*next - 1) m[next]

                pick 2 addi -1 place 2
                // _ (len - 1) (*next - 1) m0

                recurse

            // INVARIANT: _ *context *record[i]_si num_records i
            {records_loop}:
                dup 1 dup 1 eq skiz return
                // _ *context *record[i]_si num_records i

                divine 1
                dup 0 push {NUM_TRIALS} swap 1 lt assert error_id {error_id}
                dup 0 push {position_alloc.write_address()} write_mem 1 pop 1
                // _ *context *record[i]_si num_records i position

                dup 3 addi 1 {&field!(RemovalRecord::absolute_indices)}
                // _ *context *record[i]_si num_records i position *index_set

                dup 0 {&field!(AbsoluteIndexSet::minimum)} {&read_u128}
                // _ *context *record[i]_si num_records i position *index_set [minimum]

                push 0 push 0 push 0
                pick 7 {&field!(AbsoluteIndexSet::distances)} pick 8 add read_mem 1 pop 1
                // _ *context *record[i]_si num_records i [minimum] 0 0 0 distance

                call {u128_safe_add}
                // _ *context *record[i]_si num_records i [index]

                dup 7 addi {window_start_offset + 3} read_mem 4 pop 1
                dup 7 dup 7 dup 7 dup 7
                call {u128_lt}
                // _ *context *record[i]_si num_records i [index] (index < window_start)

                dup 0 skiz call {inactive}
                push 0 eq skiz call {active}
                // _ *context *record[i]_si num_records i

                pick 2 read_mem 1
                // _ *context num_records i record_size (*record[i]_si - 1)

                // Crashes unless the size is a u32.
                dup 1 pop_count pop 1

                addi 2 add place 2 addi 1
                // _ *context *record[i + 1]_si num_records (i + 1)

                recurse

            // The index lies in a chunk of the inactive part: the count its
            // insertion found must be zero.
            // BEFORE: _ *context *record_si num_records i [index] 1
            // AFTER:  _ *context *record_si num_records i 1
            {inactive}:
                pop 5
                // _ *context *record_si num_records i

                dup 3 addi {chunks_offset} read_mem 1 pop 1
                dup 1 push {NUM_TRIALS} mul add
                push {position_alloc.read_address()} read_mem 1 pop 1 add
                read_mem 1 pop 1
                // _ *context *record_si num_records i count

                push 0 eq assert error_id {error_id}
                push 1
                return

            // The index lies in the active window.
            // BEFORE: _ *context *record_si num_records i [index]
            // AFTER:  _ *context *record_si num_records i
            {active}:
                dup 7 addi {window_start_offset + 3} read_mem 4 pop 1
                pick 7 pick 7 pick 7 pick 7
                call {u128_sub}
                // _ *context *record_si num_records i [index - window_start]

                // The difference must fit the window.
                place 3 add add push 0 eq assert error_id {error_id}
                dup 0 push {WINDOW_SIZE} swap 1 lt assert error_id {error_id}
                // _ *context *record_si num_records i relative_index

                dup 4 addi {window_offset} read_mem 1 pop 1
                swap 1 call {gap}
                // _ *context *record_si num_records i

                return

            // The index must lie strictly between the entries around the
            // divined gap position of the sorted list.
            // BEFORE: _ *list index
            // AFTER:  _
            {gap}:
                divine 1
                // _ *list index gap

                dup 2 read_mem 1 pop 1
                // _ *list index gap len

                dup 0 addi 1 dup 2 lt assert error_id {error_id}
                // _ *list index gap len

                dup 1 push 0 eq push 0 eq skiz call {gap_left}
                dup 1 dup 1 eq push 0 eq skiz call {gap_right}
                // _ *list index gap len

                pop 4
                return

            // BEFORE: _ *list index gap len
            // AFTER:  _ *list index gap len
            {gap_left}:
                dup 3 dup 2 add read_mem 1 pop 1
                // _ *list index gap len list[gap - 1]

                dup 3 swap 1 lt assert error_id {error_id}
                // _ *list index gap len

                return

            // BEFORE: _ *list index gap len
            // AFTER:  _ *list index gap len
            {gap_right}:
                dup 3 dup 2 add addi 1 read_mem 1 pop 1
                // _ *list index gap len list[gap]

                dup 3 lt assert error_id {error_id}
                // _ *list index gap len

                return
        )
    }
}

/// [`SwbfiPeaksAfterRemovals`] in the counter form: the records' indices
/// are counted in the forest in one pass, on a copy of the peaks, then the
/// records checked unspent from the counts.
///
/// ```text
/// BEFORE: _ *inputs *mutator_set *counter_paths
/// AFTER:  _ *swbfi_peaks_after
/// ```
#[derive(Debug, Copy, Clone)]
struct CounterTreePeaksAfterRemovals;

impl BasicSnippet for CounterTreePeaksAfterRemovals {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*inputs".to_string()),
            (DataType::VoidPointer, "*mutator_set".to_string()),
            (DataType::VoidPointer, "*counter_paths".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        SwbfiPeaksAfterRemovals.return_values()
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_counter_tree_peaks_after_removals".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let new_list = library.import(Box::new(New));
        let memcpy = library.import(Box::new(MemCpy));
        let removals = library.import(Box::new(CounterTreeRemovals));
        let unspent = library.import(Box::new(CounterTreeUnspent));

        // BEFORE: _ *mutator_set
        // AFTER:  _ [swbfi_leaf_count: u64]
        let swbfi_leaf_count = triton_asm!(
            {&field!(MutatorSetAccumulator::swbf_inactive)}
            {&field!(MmrAccumulator::leaf_count)} addi 1 read_mem 2 pop 1
        );

        // BEFORE: _ *list
        // AFTER:  _ *copy
        let copy_digest_list = triton_asm!(
            dup 0 read_mem 1 pop 1 push {Digest::LEN} mul addi 1
            call {new_list}
            place 1 dup 1 place 3
            call {memcpy}
        );

        triton_asm!(
            {self.entrypoint()}:
                // _ *inputs *mutator_set *counter_paths
                dup 1 {&field!(MutatorSetAccumulator::swbf_inactive)} {&field!(MmrAccumulator::peaks)}
                {&copy_digest_list}
                // _ *inputs *mutator_set *counter_paths *swbfi_peaks_after

                dup 3 dup 1 dup 3
                dup 5 {&swbfi_leaf_count}
                call {removals}
                // _ *inputs *mutator_set *counter_paths *swbfi_peaks_after *counts

                dup 4 push 0 pick 2
                dup 5 {&field!(MutatorSetAccumulator::swbf_active)}
                dup 6 {&swbfi_leaf_count}
                call {unspent}
                // _ *inputs *mutator_set *counter_paths *swbfi_peaks_after

                place 3 pop 3
                return
        )
    }
}

/// The hash of the mutator set after the removals, in the counter form.
///
/// ```text
/// BEFORE: _ *inputs *mutator_set *counter_paths
/// AFTER:  _ [mutator_set_hash_after_removals]
/// ```
#[derive(Debug, Copy, Clone)]
struct CounterTreeHashAfterRemovals;

impl BasicSnippet for CounterTreeHashAfterRemovals {
    fn parameters(&self) -> Vec<(DataType, String)> {
        CounterTreePeaksAfterRemovals.parameters()
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(DataType::Digest, "mutator_set_hash".to_string())]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_counter_tree_hash_after_removals".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let peaks_after_removals = library.import(Box::new(CounterTreePeaksAfterRemovals));
        let window_after_removals = library.import(Box::new(WindowAfterRemovals));
        let mutator_set_hash_from_components =
            library.import(Box::new(MutatorSetHashFromComponents));

        triton_asm!(
            {self.entrypoint()}:
                dup 2 dup 2 dup 2 call {peaks_after_removals}
                pick 1 pop 1
                // _ *inputs *mutator_set *swbfi_peaks'

                dup 2 dup 2 call {window_after_removals}
                // _ *inputs *mutator_set *swbfi_peaks' *window'

                dup 2 {&MutatorSetHash::read_components()}
                pick 5 pop 1
                pick 5 pop 1
                pick 6 place 5
                call {mutator_set_hash_from_components}
                // _ *inputs *mutator_set [mutator_set_hash_after_removals]

                pick 5 pop 1
                pick 5 pop 1
                return
        )
    }
}

/// The leaf's witness in the counter form.
#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize, TasmObject)]
struct CounterTreeLeafWitness {
    /// The inputs with their chunk dictionaries left out: only their index
    /// sets are read.
    inputs: Vec<RemovalRecord>,
    /// The mutator set the transaction is built on, with the inactive
    /// SWBF's peaks over the chunks' roots.
    mutator_set: MutatorSetAccumulator,
    /// The indices' authentication paths from their counts' leaves up to
    /// their peaks, in the order of the records and of their indices, back
    /// to back.
    counter_paths: Vec<Digest>,
    idle_iterations: BFieldElement,
    leaf_index: BFieldElement,
}

/// One tree of the forest over the chunks' roots, with the nodes the
/// paths need: an unknown node reads as zero, like the list form's
/// authentication structures treat it.
struct SparseTree {
    height: u32,
    nodes: HashMap<u64, Digest>,
    touched: bool,
}

impl SparseTree {
    fn new(height: u32) -> Self {
        Self {
            height,
            nodes: HashMap::new(),
            touched: false,
        }
    }

    /// Seeds the tree with its authentication structure for these leaves,
    /// and the leaves.
    fn seed(&mut self, auth_struct: &[Digest], leafs: &[(u64, Digest)]) {
        let leaf_indices = leafs.iter().map(|(index, _)| *index).collect::<Vec<_>>();
        self.nodes.extend(
            UpdateTreeLeaf::auth_struct_indices(self.height, &leaf_indices)
                .into_iter()
                .zip(auth_struct.iter().copied()),
        );
        for &(leaf_index, digest) in leafs {
            UpdateTreeLeaf::set_leaf(&mut self.nodes, self.height, leaf_index, digest);
        }
        self.touched |= !leafs.is_empty();
    }

    fn set_leaf(&mut self, leaf_index: u64, digest: Digest) {
        UpdateTreeLeaf::set_leaf(&mut self.nodes, self.height, leaf_index, digest);
        self.touched = true;
    }

    fn is_touched(&self) -> bool {
        self.touched
    }

    fn root(&self) -> Digest {
        self.nodes.get(&1).copied().unwrap_or_default()
    }

    /// The siblings on the way up from this leaf.
    fn path(&self, leaf_index: u64) -> Vec<Digest> {
        let mut node = leaf_index + (1 << self.height);
        let mut path = vec![];
        while node > 1 {
            path.push(self.nodes.get(&(node ^ 1)).copied().unwrap_or_default());
            node /= 2;
        }
        path
    }
}

/// A run of the counter-form leaf: the witness, the tokens, the input and
/// the output to expect, built from the list form's witness.
struct CounterTreeLeafCase {
    witness: CounterTreeLeafWitness,
    tokens: Vec<BFieldElement>,
    expected_output: Vec<BFieldElement>,
    /// The position of the first count among the tokens.
    first_count_token: usize,
}

impl CounterTreeLeafCase {
    fn from_list_form(list: &CorrectSwbfUpdateWitness) -> Self {
        let inputs = list.inputs();
        let mutator_set = list.mutator_set();
        let chunks = list.chunks();
        let (chunk_indices, insertions) =
            SwbfiPeaksAfterRemovals::chunk_indices_and_insertions(inputs, mutator_set);
        let estimate = WitnessLists::swbfi_leaf_count_estimate(list.tree_heights());
        let leaf_count = mutator_set.swbf_inactive.num_leafs();
        let window_start = SwbfiPeaksAfterRemovals::window_start(mutator_set);

        // The forest over the chunks' roots, from the list form's
        // authentication structures: the untouched siblings keep their
        // digests, which only the measurement cares about. One sparse tree
        // per tree of the inactive SWBF, from the highest down.
        let auth_structs = MutateSwbfiPeaks::tree_auth_structs(
            estimate,
            &chunk_indices,
            chunks,
            &insertions,
            list.tree_paths(),
        );
        let runs = MutateSwbfiPeaks::runs_with(
            estimate,
            &chunk_indices,
            chunks,
            &insertions,
            counter_tree_root,
        );
        let trees = CounterTreeRemovals::trees(leaf_count);
        let mut forest = trees
            .iter()
            .map(|&(height, _)| SparseTree::new(height))
            .collect::<Vec<_>>();
        let mut peaks = mutator_set.swbf_inactive.peaks();
        for ((height, old, _), auth_struct) in runs.iter().rev().zip(&auth_structs) {
            let tree = trees
                .iter()
                .position(|(tree_height, _)| tree_height == height)
                .expect("the estimate's trees are trees of the inactive SWBF");
            forest[tree].seed(auth_struct, old);
            if !old.is_empty() {
                peaks[Self::peak_position(leaf_count, *height)] = forest[tree].root();
            }
        }
        let mut counter_mutator_set = mutator_set.clone();
        counter_mutator_set.swbf_inactive = MmrAccumulator::init(peaks, leaf_count);

        // The paths and tokens, index by index.
        let mut chunk_trees = chunks
            .iter()
            .map(|chunk| CounterTree::new(chunk))
            .collect::<Vec<_>>();
        let mut counter_paths = vec![];
        let mut removal_tokens = vec![];
        for index in inputs
            .iter()
            .flat_map(|record| record.absolute_indices.to_array())
            .filter(|&index| index < window_start)
        {
            let chunk_index = (index >> CHUNK_SIZE.ilog2()) as u64;
            let chunk = chunk_indices
                .binary_search(&chunk_index)
                .expect("the chunk is listed");
            let relative = (index % u128::from(CHUNK_SIZE)) as u32;
            let tree = trees
                .iter()
                .rposition(|&(_, start)| start <= chunk_index)
                .expect("the chunk lies in a tree");
            let leaf = chunk_index - trees[tree].1;
            counter_paths.extend(chunk_trees[chunk].path(relative));
            counter_paths.extend(forest[tree].path(leaf));
            removal_tokens.push(bfe!(tree as u64));
            removal_tokens.push(bfe!(chunk_trees[chunk].increment(relative)));
            forest[tree].set_leaf(leaf, chunk_trees[chunk].root());
        }
        let mut peaks_after = counter_mutator_set.swbf_inactive.peaks();
        for (tree, &(height, _)) in trees.iter().enumerate() {
            if forest[tree].is_touched() {
                peaks_after[Self::peak_position(leaf_count, height)] = forest[tree].root();
            }
        }
        let first_count_token = 1;
        let tokens = [
            removal_tokens,
            Self::unspent_tokens(inputs, &chunk_indices, chunks, mutator_set),
            WindowAfterRemovals::divined_tokens(inputs, mutator_set),
        ]
        .concat();

        let list_after =
            SwbfiPeaksAfterRemovals::apply_removals(&list.packed_inputs(), mutator_set);
        let mut counter_mutator_set_after = counter_mutator_set.clone();
        counter_mutator_set_after.swbf_inactive = MmrAccumulator::init(peaks_after, leaf_count);
        counter_mutator_set_after.swbf_active = list_after.swbf_active;
        let expected_output = ClaimOutput {
            padded_rows: bfe!(CorrectSwbfUpdate::ATTESTED_PADDED_ROWS),
            count: inputs.len(),
            mutator_set_hash: counter_mutator_set_after.hash(),
            last_leaf_index: list.leaf_index(),
            peaks: RemovalIndexCommitment::peaks(inputs),
        }
        .encode();

        Self {
            witness: CounterTreeLeafWitness {
                inputs: inputs.to_vec(),
                mutator_set: counter_mutator_set,
                counter_paths,
                idle_iterations: bfe!(0),
                leaf_index: list.leaf_index(),
            },
            tokens,
            expected_output,
            first_count_token,
        }
    }

    /// The position of the peak of the tree of this height among the
    /// peaks of an inactive SWBF with this leaf count.
    fn peak_position(leaf_count: u64, height: u32) -> usize {
        (leaf_count >> (height + 1)).count_ones() as usize
    }

    /// The counter form's tokens for the unspent check: per record, the
    /// position of an unset index, then the gap in the window if the
    /// index lies there.
    fn unspent_tokens(
        inputs: &[RemovalRecord],
        chunk_indices: &[u64],
        chunks: &[Vec<u32>],
        mutator_set: &MutatorSetAccumulator,
    ) -> Vec<BFieldElement> {
        let window_start = SwbfiPeaksAfterRemovals::window_start(mutator_set);
        let window = &mutator_set.swbf_active.sbf;
        let mut tokens = vec![];
        for record in inputs {
            let indices = record.absolute_indices.to_array();
            let tokens_of = |position: usize| {
                let index = indices[position];
                if index < window_start {
                    let chunk_index = (index >> CHUNK_SIZE.ilog2()) as u64;
                    let chunk_position = chunk_indices
                        .binary_search(&chunk_index)
                        .expect("the chunk is listed");
                    let relative = (index % u128::from(CHUNK_SIZE)) as u32;
                    let is_unset = !chunks[chunk_position].contains(&relative);
                    (vec![bfe!(position as u64)], is_unset)
                } else {
                    let relative = (index - window_start) as u32;
                    let gap = window.partition_point(|&set| set < relative);
                    (
                        vec![bfe!(position as u64), bfe!(gap as u64)],
                        !window.contains(&relative),
                    )
                }
            };
            let (record_tokens, _) = (0..indices.len())
                .map(tokens_of)
                .find(|(_, is_unset)| *is_unset)
                .expect("the fixture's records are unspent");
            tokens.extend(record_tokens);
        }
        tokens
    }

    fn public_input(&self) -> PublicInput {
        PublicInput::new(CorrectSwbfUpdate::claim_input(
            &self.witness.mutator_set,
            self.witness.leaf_index,
        ))
    }

    fn nondeterminism(&self) -> NonDeterminism {
        let mut nondeterminism = NonDeterminism::default();
        encode_to_memory(
            &mut nondeterminism.ram,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            &self.witness,
        );
        nondeterminism.individual_tokens = self.tokens.clone();
        nondeterminism
    }
}

/// [`CorrectSwbfUpdate`] in the counter form: the same claim, with the
/// inactive SWBF's chunks as counter trees.
#[derive(Debug, Clone, Copy)]
struct CounterTreeLeaf;

impl TritonProgram for CounterTreeLeaf {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        let mut library = Library::new();
        let audit_witness = library.import(Box::new(
            VerifyNdSiIntegrity::<CounterTreeLeafWitness>::default(),
        ));
        let mutator_set_hash = library.import(Box::new(MutatorSetHash));
        let hash_after_removals = library.import(Box::new(CounterTreeHashAfterRemovals));
        let commitment = library.import(Box::new(RemovalIndexCommitment));
        let write_peaks = "counter_tree_leaf_write_peaks".to_string();
        let idle = "counter_tree_leaf_idle".to_string();
        let idle_loop = format!("{idle}_loop");

        let code = triton_asm!(
            read_io {Digest::LEN}
            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            hint witness = stack[0]
            dup 0 call {audit_witness} pop 1
            // _ [mutator_set_hash] *w

            dup 0 {&field!(CounterTreeLeafWitness::mutator_set)}
            call {mutator_set_hash}
            pick 10 pick 10 pick 10 pick 10 pick 10
            assert_vector error_id {BlockValidationRule::TransactionMutatorSetMismatch.error_id()}
            pop {Digest::LEN}
            // _ *w

            dup 0 {&field!(CounterTreeLeafWitness::inputs)}
            call {commitment}
            place 1
            // _ *peaks *w

            dup 0 {&field!(CounterTreeLeafWitness::inputs)}
            dup 1 {&field!(CounterTreeLeafWitness::mutator_set)}
            dup 2 {&field!(CounterTreeLeafWitness::counter_paths)} addi 1
            call {hash_after_removals}
            // _ *peaks *w [mutator_set_after_removals_hash]

            push {CorrectSwbfUpdate::ATTESTED_PADDED_ROWS} write_io 1
            dup 5 {&field!(CounterTreeLeafWitness::inputs)} read_mem 1 pop 1 write_io 1
            write_io {Digest::LEN}
            pop 1
            // _ *peaks

            read_io 1 write_io 1
            dup 0 read_mem 1 pop 1
            dup 0 write_io 1
            push {Digest::LEN} mul dup 1 add
            swap 1 call {write_peaks}
            pop 2

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            {&field!(CounterTreeLeafWitness::idle_iterations)} read_mem 1 pop 1
            push {CorrectSwbfUpdate::MAX_IDLE_ITERATIONS + 1} dup 1 lt assert
            dup 0 skiz call {idle}
            pop 1
            halt

            {idle}:
                push 0 push 0 push 0 push 0 push 0 push 0
                call {idle_loop}
                pop 5 pop 1
                return

            {idle_loop}:
                pick 6 addi -1 place 6
                recurse_or_return

            // INVARIANT: _ *end *peak[i]_previous_word
            {write_peaks}:
                dup 1 dup 1 eq skiz return
                addi {Digest::LEN} read_mem {Digest::LEN}
                addi {Digest::LEN} place {Digest::LEN}
                write_io {Digest::LEN}
                recurse

            {&library.all_imports()}
        );
        (library, code)
    }

    fn hash(&self) -> Digest {
        self.program().hash()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use tasm_lib::triton_vm::vm::VM;

    use super::super::leaf::tests::witness as list_witness;
    use super::super::leaf::tests::witness_with_empty_chunks;
    use super::*;
    use crate::proof_abstractions::SecretWitness;

    #[test]
    fn counter_form_agrees_with_the_host() {
        for (num_inputs, seed) in [(1, 0), (3, 1), (8, 6)] {
            let case = CounterTreeLeafCase::from_list_form(&list_witness(num_inputs, seed));
            let output = VM::run(
                CounterTreeLeaf.program(),
                case.public_input(),
                case.nondeterminism(),
            )
            .unwrap();
            assert_eq!(
                case.expected_output, output,
                "{num_inputs} inputs, seed {seed}"
            );
        }
    }

    /// The list form accepts the emptied fixture, so its cost at density
    /// zero is a cost of a valid leaf.
    #[test]
    fn list_form_accepts_the_emptied_fixture() {
        let empty = witness_with_empty_chunks(2, 0);
        let output = VM::run(
            CorrectSwbfUpdate.program(),
            empty.standard_input(),
            empty.nondeterminism(),
        )
        .unwrap();
        assert_eq!(empty.output(), output);
    }

    #[test]
    fn wrong_count_is_rejected() {
        let case = CounterTreeLeafCase::from_list_form(&list_witness(2, 0));
        let mut nondeterminism = case.nondeterminism();
        nondeterminism.individual_tokens[case.first_count_token] += bfe!(1);
        assert!(VM::run(
            CounterTreeLeaf.program(),
            case.public_input(),
            nondeterminism
        )
        .is_err());
    }

    /// Prints both forms' profiles on the list form's fixture, and the
    /// processor rows per input.
    #[test]
    #[ignore = "prints a profile"]
    fn profile_both_forms() {
        let total_line = |profile: &str| {
            profile
                .lines()
                .find(|line| line.starts_with("| Total"))
                .unwrap()
                .to_string()
        };
        let processor_rows = |line: &str| -> usize {
            let cell = line.split('|').nth(2).unwrap().trim();
            cell.split_whitespace().next().unwrap().parse().unwrap()
        };
        let mut rows = vec![];
        for num_inputs in [8, 16] {
            let list = list_witness(num_inputs, 6);
            let counter = CounterTreeLeafCase::from_list_form(&list);
            let list_profile = tasm_lib::generate_full_profile(
                &format!("list form, {num_inputs} inputs"),
                CorrectSwbfUpdate.program(),
                &list.standard_input(),
                &list.nondeterminism(),
            )
            .to_string();
            let empty = witness_with_empty_chunks(num_inputs, 6);
            let empty_total = total_line(
                &tasm_lib::generate_full_profile(
                    &format!("list form with empty chunks, {num_inputs} inputs"),
                    CorrectSwbfUpdate.program(),
                    &empty.standard_input(),
                    &empty.nondeterminism(),
                )
                .to_string(),
            );
            println!("list form with empty chunks, {num_inputs} inputs: {empty_total}");
            let counter_profile = tasm_lib::generate_full_profile(
                &format!("counter form, {num_inputs} inputs"),
                CounterTreeLeaf.program(),
                &counter.public_input(),
                &counter.nondeterminism(),
            )
            .to_string();
            println!("{list_profile}\n{counter_profile}");
            let list_total = total_line(&list_profile);
            let counter_total = total_line(&counter_profile);
            println!("list form, {num_inputs} inputs: {list_total}");
            println!("counter form, {num_inputs} inputs: {counter_total}");
            rows.push((
                processor_rows(&list_total),
                processor_rows(&empty_total),
                processor_rows(&counter_total),
            ));
        }
        let per_input = |a: usize, b: usize| (b - a) / 8;
        println!(
            "per input: list form {}, list form with empty chunks {}, counter form {}",
            per_input(rows[0].0, rows[1].0),
            per_input(rows[0].1, rows[1].1),
            per_input(rows[0].2, rows[1].2)
        );
    }
}
