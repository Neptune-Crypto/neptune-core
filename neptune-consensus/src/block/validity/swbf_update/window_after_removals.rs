//! The active window after a transaction's removals: the indices that lie in
//! the window inserted into a copy of it. Needs no chunk data.

use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_mutator_set::shared::CHUNK_SIZE;
use tasm_lib::arithmetic::u128::shift_left_static::ShiftLeftStatic;
use tasm_lib::field;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

use super::insert_into_window::InsertIntoWindow;
use super::sorted_window_indices::SortedWindowIndices;
use super::swbfi_peaks_after_removals::SwbfiPeaksAfterRemovals;

/// ```text
/// BEFORE: _ *inputs *mutator_set
/// AFTER:  _ *window_after
/// ```
#[derive(Debug, Copy, Clone)]
pub(in crate::block::validity) struct WindowAfterRemovals;

impl WindowAfterRemovals {
    /// The tokens: the sorted indices in the active window and their
    /// positions in it.
    pub(in crate::block::validity) fn divined_tokens(
        inputs: &[RemovalRecord],
        mutator_set: &MutatorSetAccumulator,
    ) -> Vec<BFieldElement> {
        let window_start = SwbfiPeaksAfterRemovals::window_start(mutator_set);
        let sorted_window_indices =
            SortedWindowIndices::sorted_window_indices(inputs, window_start);

        [
            SortedWindowIndices::divined_tokens(inputs, window_start),
            InsertIntoWindow::divined_tokens(&mutator_set.swbf_active.sbf, &sorted_window_indices),
        ]
        .concat()
    }
}

impl BasicSnippet for WindowAfterRemovals {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*inputs".to_string()),
            (DataType::VoidPointer, "*mutator_set".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "*window_after".to_string())]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_window_after_removals".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let sorted_window_indices = library.import(Box::new(SortedWindowIndices));
        let insert_into_window = library.import(Box::new(InsertIntoWindow));
        let to_window_start =
            library.import(Box::new(ShiftLeftStatic::<{ CHUNK_SIZE.ilog2() as u8 }>));

        let entrypoint = self.entrypoint();
        let read_u64 = triton_asm!(addi 1 read_mem 2 pop 1);

        triton_asm!(
            // BEFORE: _ *inputs *mutator_set
            // AFTER:  _ *window_after
            {entrypoint}:
                dup 1
                dup 1 {&field!(MutatorSetAccumulator::swbf_inactive)}
                {&field!(MmrAccumulator::leaf_count)} {&read_u64}
                push 0 push 0 pick 3 pick 3 call {to_window_start}
                // _ *inputs *mutator_set *inputs [window_start]

                call {sorted_window_indices}
                // _ *inputs *mutator_set *sorted_indices

                dup 1 {&field!(MutatorSetAccumulator::swbf_active)}
                swap 1 call {insert_into_window}
                // _ *inputs *mutator_set *window_after

                place 2 pop 2
                return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(in crate::block::validity) mod tests {
    use neptune_mutator_set::active_window::ActiveWindow;

    use super::*;
    use crate::proof_abstractions::tasm::builtins as tasm;

    impl WindowAfterRemovals {
        /// The host shadow: reads the same divined tokens and computes the
        /// window after the removals directly.
        pub(in crate::block::validity) fn verify(
            inputs: &[RemovalRecord],
            mutator_set: &MutatorSetAccumulator,
        ) -> ActiveWindow {
            // The prover's sorted indices and positions are read and ignored.
            for _ in 0..Self::divined_tokens(inputs, mutator_set).len() {
                tasm::tasmlib_io_read_secin___bfe();
            }

            let window_start = SwbfiPeaksAfterRemovals::window_start(mutator_set);
            let mut window = mutator_set.swbf_active.clone();
            for index in inputs
                .iter()
                .flat_map(|record| record.absolute_indices.to_array())
                .filter(|&index| index >= window_start)
            {
                window.insert((index - window_start) as u32);
            }
            window
        }
    }
}
