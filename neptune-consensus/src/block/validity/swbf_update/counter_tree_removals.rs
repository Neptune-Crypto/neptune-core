//! Rules 2.b and 2.d and the inactive-SWBF half of 2.e in the counter-tree
//! form of proposal f), where the inactive SWBF is one Merkle forest down
//! to the counts of its indices: each index of each record that lies in
//! the inactive part is counted once more by two walks up its path, from
//! its count's leaf through its chunk's root to the peak of the tree it
//! lies in, with [`UpdateTreeLeaf`]. The peaks are updated in place; the
//! count each index found is what the unspent rule reads. No block uses
//! it.

use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_mutator_set::shared::CHUNK_SIZE;
use neptune_mutator_set::shared::NUM_TRIALS;
use neptune_mutator_set::shared::WINDOW_SIZE;
use tasm_lib::arithmetic::u128::lt::Lt as U128Lt;
use tasm_lib::arithmetic::u128::shift_left_static::ShiftLeftStatic;
use tasm_lib::arithmetic::u128::sub::Sub as U128Sub;
use tasm_lib::arithmetic::u64::add::Add as U64Add;
use tasm_lib::arithmetic::u64::log_2_floor::Log2Floor;
use tasm_lib::arithmetic::u64::lt::Lt as U64Lt;
use tasm_lib::arithmetic::u64::pow2::Pow2;
use tasm_lib::arithmetic::u64::shift_left::ShiftLeft as U64ShiftLeft;
use tasm_lib::arithmetic::u64::sub::Sub as U64Sub;
use tasm_lib::field;
use tasm_lib::list::new::New;
use tasm_lib::memory::dyn_malloc::DynMalloc;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use super::counter_tree_root::TREE_HEIGHT;
use super::update_tree_leaf::UpdateTreeLeaf;
use crate::block::block_validation_error::BlockValidationRule;

/// ```text
/// BEFORE: _ *removal_records *swbfi_peaks *counter_paths [swbfi_leaf_count: u64]
/// AFTER:  _ *counts
/// ```
///
/// `*swbfi_peaks` lists the inactive SWBF's peaks, replaced in place by
/// the peaks after the insertions. `*counter_paths` points at the first
/// index's authentication path, one digest per level from its count's
/// leaf up to the peak, each path against the forest after the insertions
/// before it, in the order of the records and of their indices, back to
/// back. `*counts` is a table of the count each index found,
/// [`NUM_TRIALS`] words per record, meaningful for the indices below the
/// window start.
///
/// The prover supplies, for each index below the window start, the
/// position of the tree it lies in among the trees from the highest down,
/// and the count it finds.
///
/// Crashes with the error ID of rule 2.b if an index does not lie in the
/// divined tree, or a count or path does not fit the tree's running peak.
#[derive(Debug, Copy, Clone)]
pub(super) struct CounterTreeRemovals;

impl CounterTreeRemovals {
    const LOG2_CHUNK_SIZE: u8 = CHUNK_SIZE.ilog2() as u8;

    /// The trees of an inactive SWBF with this leaf count, from the highest
    /// down, as the height and the index of the first leaf: the order the
    /// snippet's tree table has.
    pub(super) fn trees(swbfi_leaf_count: u64) -> Vec<(u32, u64)> {
        let mut trees = vec![];
        let mut start = 0;
        for height in (0..u64::BITS).rev() {
            if swbfi_leaf_count & (1 << height) != 0 {
                trees.push((height, start));
                start += 1 << height;
            }
        }
        trees
    }
}

impl BasicSnippet for CounterTreeRemovals {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*removal_records".to_string()),
            (
                DataType::List(Box::new(DataType::Digest)),
                "*swbfi_peaks".to_string(),
            ),
            (DataType::VoidPointer, "*counter_paths".to_string()),
            (DataType::U64, "swbfi_leaf_count".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "*counts".to_string())]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_counter_tree_removals".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let new_list = library.import(Box::new(New));
        let dyn_malloc = library.import(Box::new(DynMalloc));
        let u128_lt = library.import(Box::new(U128Lt));
        let u128_sub = library.import(Box::new(U128Sub));
        let to_window_start =
            library.import(Box::new(ShiftLeftStatic::<{ Self::LOG2_CHUNK_SIZE }>));
        let log2_floor = library.import(Box::new(Log2Floor));
        let pow2 = library.import(Box::new(Pow2));
        let u64_add = library.import(Box::new(U64Add));
        let u64_lt = library.import(Box::new(U64Lt));
        let u64_shift_left = library.import(Box::new(U64ShiftLeft));
        let u64_sub = library.import(Box::new(U64Sub));
        let update_tree_leaf = library.import(Box::new(UpdateTreeLeaf));

        let peaks_alloc = library.kmalloc(1);
        let counts_alloc = library.kmalloc(1);
        let cursor_alloc = library.kmalloc(1);
        // The tree table and its building: the trees not tabled yet as a
        // leaf count, the next tree's first leaf, its position and its
        // entry.
        let table_alloc = library.kmalloc(1);
        let num_trees_alloc = library.kmalloc(1);
        let remaining_alloc = library.kmalloc(2);
        let start_alloc = library.kmalloc(2);
        let position_alloc = library.kmalloc(1);
        let entry_alloc = library.kmalloc(1);

        let entrypoint = self.entrypoint();
        let table_loop = format!("{entrypoint}_table_loop");
        let records_loop = format!("{entrypoint}_records_loop");
        let indices_loop = format!("{entrypoint}_indices_loop");
        let insert = format!("{entrypoint}_insert");
        let mode_below = format!("{entrypoint}_mode_below");
        let mode_not_below = format!("{entrypoint}_mode_not_below");

        // The context, in memory: the window start, and, per record, how
        // its indices relate to it and the low limbs of its minimum.
        let window_start_offset = 0;
        let mode_offset = 4;
        let minimum_offset = 6;

        // A tree's table entry: its first absolute index and its leaf count
        // down to the counts, what an absolute index adds up to its node
        // index, the position of its peak, and the words of a path to it.
        let entry_first = 0;
        let entry_leafs = 2;
        let entry_offset = 4;
        let entry_peak = 6;
        let entry_path_words = 7;
        let entry_size = 8;

        let read_u64 = |alloc: &tasm_lib::library::StaticAllocation| triton_asm!(push {alloc.read_address()} read_mem 2 pop 1);
        let write_u64 = |alloc: &tasm_lib::library::StaticAllocation| triton_asm!(push {alloc.write_address()} write_mem 2 pop 1);
        let read_word = |alloc: &tasm_lib::library::StaticAllocation| triton_asm!(push {alloc.read_address()} read_mem 1 pop 1);
        let write_word = |alloc: &tasm_lib::library::StaticAllocation| triton_asm!(push {alloc.write_address()} write_mem 1 pop 1);

        // Whether an index of the record, given by its distance to the
        // record's minimum, lies below the window start.
        // BEFORE: _ ... distance
        // AFTER:  _ ... distance is_below
        let is_below = |context_depth: usize| {
            triton_asm!(
                dup {context_depth} addi {mode_offset} read_mem 1 pop 1
                dup 1 lt
                dup {context_depth + 1} addi {mode_offset + 1} read_mem 1 pop 1
                add
            )
        };

        triton_asm!(
            {entrypoint}:
                // _ *removal_records *swbfi_peaks *counter_paths [leaf_count]
                call {new_list}
                place 5
                pick 2 {&write_word(&cursor_alloc)}
                pick 2 {&write_word(&peaks_alloc)}
                // _ *context *removal_records [leaf_count]

                dup 1 dup 1 push 0 push 0 pick 3 pick 3 call {to_window_start}
                dup 7 addi {window_start_offset} write_mem 4 pop 1
                // _ *context *removal_records [leaf_count]

                // The tree table, from the highest tree down.
                {&write_u64(&remaining_alloc)}
                push 0 push 0 {&write_u64(&start_alloc)}
                push 0 {&write_word(&position_alloc)}
                call {dyn_malloc}
                dup 0 {&write_word(&table_alloc)}
                {&write_word(&entry_alloc)}
                call {table_loop}
                {&read_word(&position_alloc)} {&write_word(&num_trees_alloc)}
                call {dyn_malloc} {&write_word(&counts_alloc)}
                // _ *context *removal_records

                read_mem 1 addi 2 place 1 push 0
                call {records_loop}
                pop 4
                {&read_word(&counts_alloc)}
                // _ *counts

                return

            // INVARIANT: _
            {table_loop}:
                {&read_u64(&remaining_alloc)} add push 0 eq skiz return
                {&read_u64(&remaining_alloc)} call {log2_floor}
                // _ height

                {&read_u64(&start_alloc)} push {Self::LOG2_CHUNK_SIZE} call {u64_shift_left}
                dup 1 dup 1 {&read_word(&entry_alloc)} addi {entry_first} write_mem 2 pop 1
                dup 2 addi {Self::LOG2_CHUNK_SIZE} call {pow2}
                dup 1 dup 1 {&read_word(&entry_alloc)} addi {entry_leafs} write_mem 2 pop 1
                // _ height [first_index] [leaf_count]

                // What an absolute index adds up to its node index: the leaf
                // count less the first index, limb by limb. An index in the
                // tree adds up without a carry or a borrow, since the first
                // index is a multiple of the leaf count.
                pick 2 push -1 mul add
                place 2 swap 1 push -1 mul add
                swap 1
                {&read_word(&entry_alloc)} addi {entry_offset} write_mem 2 pop 1
                // _ height

                dup 0 call {pow2}
                dup 1 dup 1 {&read_u64(&start_alloc)} call {u64_add}
                {&write_u64(&start_alloc)}
                {&read_u64(&remaining_alloc)} call {u64_sub}
                {&write_u64(&remaining_alloc)}
                // _ height

                {&read_word(&position_alloc)}
                {&read_word(&entry_alloc)} addi {entry_peak} write_mem 1 pop 1
                addi {TREE_HEIGHT} push {Digest::LEN} mul
                {&read_word(&entry_alloc)} addi {entry_path_words} write_mem 1 pop 1
                // _

                {&read_word(&position_alloc)} addi 1 {&write_word(&position_alloc)}
                {&read_word(&entry_alloc)} addi {entry_size} {&write_word(&entry_alloc)}
                recurse

            // INVARIANT: _ *context *record[i]_si num_records i
            {records_loop}:
                dup 1 dup 1 eq skiz return
                dup 2 addi 1
                {&field!(RemovalRecord::absolute_indices)}
                {&field!(AbsoluteIndexSet::minimum)}
                // _ *context *record[i]_si num_records i *minimum

                // The record's mode: all its indices lie below the window
                // start, none do, or those at a distance below a bound do.
                dup 0 addi 3 read_mem 4 pop 1
                dup 8 addi {window_start_offset + 3} read_mem 4 pop 1
                dup 3 dup 3 dup 3 dup 3
                dup 11 dup 11 dup 11 dup 11
                call {u128_lt}
                dup 0 skiz call {mode_below}
                push 0 eq skiz call {mode_not_below}
                // _ *context *record[i]_si num_records i *minimum bound all

                swap 1 dup 6 addi {mode_offset} write_mem 2 pop 1
                dup 0 addi 1 read_mem 2 pop 1
                dup 6 addi {minimum_offset} write_mem 2 pop 1
                pop 1
                // _ *context *record[i]_si num_records i

                dup 2 addi 1
                {&field!(RemovalRecord::absolute_indices)}
                {&field!(AbsoluteIndexSet::distances)}
                push 0
                call {indices_loop}
                pop 2
                // _ *context *record[i]_si num_records i

                pick 2 read_mem 1
                // Crashes unless the size is a u32.
                dup 1 pop_count pop 1
                addi 2 add place 2 addi 1
                recurse

            // BEFORE: _ ... *minimum [minimum] [window_start] 1
            // AFTER:  _ ... *minimum bound all 1
            {mode_below}:
                pop 1
                call {u128_sub}
                place 3
                add add push 0 eq push 0 eq
                dup 1 push {WINDOW_SIZE} swap 1 lt push 0 eq
                add push 0 eq push 0 eq
                dup 0 push -1 mul addi 1 pick 2 mul
                swap 1 push 1
                return

            // BEFORE: _ ... *minimum [minimum] [window_start]
            // AFTER:  _ ... *minimum 0 0
            {mode_not_below}:
                pop 5 pop 3 push 0 push 0
                return

            // INVARIANT: _ *context *record_si num_records i *distance[k] k
            {indices_loop}:
                dup 0 push {NUM_TRIALS} eq skiz return
                dup 1 read_mem 1 pop 1
                {&is_below(6)}
                skiz call {insert}
                pop 1
                pick 1 addi 1 place 1 addi 1
                recurse

            // Counts the index once more: the divined count's leaf walks up
            // the path to the running peak of the divined tree, the count
            // plus one to the peak the tree then has.
            // BEFORE: _ *context *record_si num_records i *distance[k] k distance
            // AFTER:  _ *context *record_si num_records i *distance[k] k distance
            {insert}:
                // The index's low limbs: it lies below the window start,
                // so the high ones are zero.
                dup 6 addi {minimum_offset + 1} read_mem 2 pop 1
                push 0 dup 3 call {u64_add}
                // _ ... distance [index]

                divine 1
                {&read_word(&num_trees_alloc)} dup 1 lt assert error_id {BlockValidationRule::RemovalRecordsValidity.error_id()}
                push {entry_size} mul {&read_word(&table_alloc)} add
                // _ ... distance [index] *entry

                // The index lies in the tree: its distance to the tree's
                // first index, limb by limb, is below the tree's leaf count.
                // A limb that borrows is no u32 and crashes the comparison.
                dup 0 addi {entry_first + 1} read_mem 2 pop 1
                dup 4 dup 4
                pick 2 push -1 mul add
                place 2 swap 1 push -1 mul add
                swap 1
                // _ ... distance [index] *entry [distance_in_tree]

                dup 2 addi {entry_leafs + 1} read_mem 2 pop 1
                pick 3 pick 3 call {u64_lt}
                assert error_id {BlockValidationRule::RemovalRecordsValidity.error_id()}
                // _ ... distance [index] *entry

                dup 0 addi {entry_offset + 1} read_mem 2 pop 1
                // _ ... distance [index] *entry [offset]

                pick 3 add place 3 pick 2 add addi 1 pick 2
                // _ ... distance *entry (node_hi + 1) node_lo

                dup 2 addi {entry_peak} read_mem 1 pop 1
                push {Digest::LEN} mul addi 1 {&read_word(&peaks_alloc)} add
                {&read_word(&cursor_alloc)}
                // _ ... distance *entry (node_hi + 1) node_lo *running_peak *path

                dup 4 addi {entry_path_words} read_mem 1 pop 1
                dup 1 add {&write_word(&cursor_alloc)}
                divine 1
                // _ ... i *distance[k] k distance *entry (node_hi + 1) node_lo *running_peak *path count

                {&read_word(&counts_alloc)}
                dup 10 push {NUM_TRIALS} mul add dup 8 add
                dup 1 swap 1 write_mem 1 pop 1
                // _ ... distance *entry (node_hi + 1) node_lo *running_peak *path count

                pick 2 pick 2 pick 4 pick 4
                dup 2 dup 2 dup 2
                // _ ... distance *entry count *running_peak *path (node_hi + 1) node_lo *path (node_hi + 1) node_lo

                push 0 push 0 push 0 push 0 dup 11
                push 0 push 0 push 0 push 0 dup 4 addi 1
                call {update_tree_leaf}
                // _ ... distance *entry count

                pop 2
                return
        )
    }
}
