//! The hash of the mutator set after a transaction's removals, from the
//! mutator set it is built on: the inactive SWBF's peaks and the active
//! window after the removals, hashed with the unchanged AOCL. The body of
//! the SWBFI update claims.

use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_mutator_set::removal_record::RemovalRecord;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use super::swbfi_peaks_after_removals::SwbfiPeaksAfterRemovals;
use super::window_after_removals::WindowAfterRemovals;
use crate::block::validity::mutator_set_hash::MutatorSetHash;
use crate::block::validity::mutator_set_hash::MutatorSetHashFromComponents;

/// ```text
/// BEFORE: _ *inputs *mutator_set
/// AFTER:  _ [mutator_set_hash_after_removals]
/// ```
#[derive(Debug, Copy, Clone)]
pub(super) struct MutatorSetHashAfterRemovals;

impl MutatorSetHashAfterRemovals {
    pub(super) fn divined_tokens(
        inputs: &[RemovalRecord],
        mutator_set: &MutatorSetAccumulator,
    ) -> Vec<BFieldElement> {
        [
            SwbfiPeaksAfterRemovals::divined_tokens(inputs, mutator_set),
            WindowAfterRemovals::divined_tokens(inputs, mutator_set),
        ]
        .concat()
    }
}

impl BasicSnippet for MutatorSetHashAfterRemovals {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*inputs".to_string()),
            (DataType::VoidPointer, "*mutator_set".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(
            DataType::Digest,
            "mutator_set_hash_after_removals".to_string(),
        )]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_mutator_set_hash_after_removals".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let swbfi_peaks_after_removals = library.import(Box::new(SwbfiPeaksAfterRemovals));
        let window_after_removals = library.import(Box::new(WindowAfterRemovals));
        let mutator_set_hash_from_components =
            library.import(Box::new(MutatorSetHashFromComponents));

        triton_asm!(
            // BEFORE: _ *inputs *mutator_set
            // AFTER:  _ [mutator_set_hash_after_removals]
            {self.entrypoint()}:
                dup 1 dup 1 call {swbfi_peaks_after_removals}
                // _ *inputs *mutator_set *swbfi_peaks'

                dup 2 dup 2 call {window_after_removals}
                // _ *inputs *mutator_set *swbfi_peaks' *window'

                dup 2 {&MutatorSetHash::read_components()}
                pick 5 pop 1
                pick 5 pop 1
                pick 6 place 5
                // _ *inputs *mutator_set *window' *swbfi_peaks' [swbfi_leaf_count] [aocl_leaf_count] *aocl_peaks

                call {mutator_set_hash_from_components}
                // _ *inputs *mutator_set [mutator_set_hash_after_removals]

                pick 5 pop 1
                pick 5 pop 1
                return
        )
    }
}
