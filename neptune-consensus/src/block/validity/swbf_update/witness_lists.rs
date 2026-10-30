//! The leaf witness's lists of chunks and tree paths, read into the pointer
//! lists the rules on the inactive SWBF take.

use tasm_lib::arithmetic::u64::add::Add as U64Add;
use tasm_lib::arithmetic::u64::pow2::Pow2 as U64Pow2;
use tasm_lib::list::new::New;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use crate::block::block_validation_error::BlockValidationRule;

/// ```text
/// BEFORE: _ *chunks *tree_heights *tree_paths
/// AFTER:  _ *chunk_pointers *path_pointers [swbfi_leaf_count_estimate: u64]
/// ```
///
/// `*chunks` lists the chunks' storage in ascending chunk index (see
/// [`HashBlocks::chunk_storage`](super::hash_blocks::HashBlocks::chunk_storage)),
/// `*tree_heights` the heights of the trees of an inactive SWBF the chunks
/// lie in, strictly increasing, and `*tree_paths` one digest list per
/// tree in the same order. `*chunk_pointers` lists a pointer to each
/// chunk's list, a word past its storage's first word, `*path_pointers` a
/// pointer to each tree's digest list, and the estimate is the leaf count
/// of the smallest inactive SWBF with those trees.
///
/// Crashes with the error ID of rule 2.a unless the heights strictly
/// increase and come one per path list.
#[derive(Debug, Copy, Clone)]
pub(super) struct WitnessLists;

impl WitnessLists {
    /// The leaf count of the inactive SWBF with trees of these heights.
    pub(in crate::block::validity) fn swbfi_leaf_count_estimate(tree_heights: &[u32]) -> u64 {
        tree_heights
            .iter()
            .fold(0, |sum, &height| sum.wrapping_add(1 << height.min(63)))
    }
}

impl BasicSnippet for WitnessLists {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*chunks".to_string()),
            (
                DataType::List(Box::new(DataType::U32)),
                "*tree_heights".to_string(),
            ),
            (DataType::VoidPointer, "*tree_paths".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![
            (
                DataType::List(Box::new(DataType::VoidPointer)),
                "*chunk_pointers".to_string(),
            ),
            (
                DataType::List(Box::new(DataType::VoidPointer)),
                "*path_pointers".to_string(),
            ),
            (DataType::U64, "swbfi_leaf_count_estimate".to_string()),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_witness_lists".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let new_list = library.import(Box::new(New));
        let pow2 = library.import(Box::new(U64Pow2));
        let u64_add = library.import(Box::new(U64Add));

        let entrypoint = self.entrypoint();
        let pointers = format!("{entrypoint}_pointers");
        let pointers_loop = format!("{entrypoint}_pointers_loop");
        let estimate = format!("{entrypoint}_estimate");
        let estimate_loop = format!("{entrypoint}_estimate_loop");

        triton_asm!(
            {entrypoint}:
                // _ *chunks *tree_heights *tree_paths
                dup 1 read_mem 1 pop 1 dup 1 read_mem 1 pop 1
                eq assert error_id {BlockValidationRule::RemovalRecordsUnpackFailure.error_id()}
                // A chunk's list sits two words past its element: past
                // the element's own length and the storage's first word.
                pick 2 push 2 call {pointers}
                pick 1 push 0 call {pointers}
                // _ *tree_heights *chunk_pointers *path_pointers

                pick 2 call {estimate}
                // _ *chunk_pointers *path_pointers [estimate]

                return

            // Collects a pointer to each element of a list of dynamically
            // sized elements: to the word after the element's size, plus
            // the offset.
            // BEFORE: _ *list offset
            // AFTER:  _ *pointers
            {pointers}:
                swap 1 read_mem 1 addi 2
                call {new_list}
                dup 2 dup 1 write_mem 1 pop 1
                place 3 push 0
                // _ *pointers offset len *element[0]_si 0

                call {pointers_loop}
                pop 4
                return

            // INVARIANT: _ *pointers offset len *element[i]_si i
            {pointers_loop}:
                dup 2 dup 1 eq skiz return
                dup 1 addi 1 dup 4 add
                dup 5 dup 2 add addi 1
                write_mem 1 pop 1
                // _ *pointers offset len *element[i]_si i

                pick 1 read_mem 1
                // Crashes unless the size is a u32.
                dup 1 pop_count pop 1
                addi 2 add place 1 addi 1
                recurse

            // The sum of the trees' leaf counts, for strictly increasing
            // heights.
            // BEFORE: _ *tree_heights
            // AFTER:  _ [estimate]
            {estimate}:
                read_mem 1 addi 2 push 0 push 0 push 0
                // _ remaining *height estimate_hi estimate_lo next_height

                call {estimate_loop}
                pop 1 place 3 place 3 pop 2
                return

            // INVARIANT: _ remaining *height estimate_hi estimate_lo next_height
            {estimate_loop}:
                dup 4 push 0 eq skiz return
                dup 3 read_mem 1 pop 1
                // _ remaining *height [estimate] next_height height

                dup 1 dup 1 lt push 0 eq assert error_id {BlockValidationRule::RemovalRecordsUnpackFailure.error_id()}
                dup 0 addi 1 place 2 pick 1 pop 1
                // _ remaining *height [estimate] (height + 1) height

                call {pow2}
                dup 4 dup 4 call {u64_add}
                place 4 place 4 pick 2 pop 1 pick 1 pop 1
                // _ remaining *height [estimate'] (height + 1)

                pick 4 addi -1 place 4
                pick 3 addi 1 place 3
                recurse
        )
    }
}
