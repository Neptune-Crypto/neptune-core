use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use super::apply_addition_record::ApplyAdditionRecord;

/// Adds each addition record in a list to a mutator set accumulator given
/// as its components, as [`ApplyAdditionRecord`] does for one.
///
/// ```text
/// BEFORE: _ *window_encoding *swbfi_peaks [swbfi_leaf_count: u64] [aocl_leaf_count: u64] *aocl_peaks *records
/// AFTER:  _ *window_encoding' *swbfi_peaks [swbfi_leaf_count'] [aocl_leaf_count + n] *aocl_peaks
/// ```
#[derive(Debug, Copy, Clone)]
pub(super) struct ApplyAdditionRecords;

impl BasicSnippet for ApplyAdditionRecords {
    fn parameters(&self) -> Vec<(DataType, String)> {
        let mut parameters = ApplyAdditionRecord.return_values();
        parameters.push((
            DataType::List(Box::new(DataType::Digest)),
            "*records".to_string(),
        ));
        parameters
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        ApplyAdditionRecord.return_values()
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_apply_addition_records".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let apply_addition_record = library.import(Box::new(ApplyAdditionRecord));

        let entrypoint = self.entrypoint();
        let each = format!("{entrypoint}_each");

        triton_asm!(
            // BEFORE: _ [components] *records
            // AFTER:  _ [components']
            {entrypoint}:
                dup 0 read_mem 1 pop 1 push {Digest::LEN} mul dup 1 add
                // _ [components] *records *records_end

                place 8 place 7
                // _ *records_end *records [components]

                call {each}
                // _ *records_end *records_end [components']

                pick 8 pop 1 pick 7 pop 1
                // _ [components']

                return

            // INVARIANT: _ *records_end *record[i]_previous_word [components]
            {each}:
                dup 8 dup 8 eq skiz return
                // _ *records_end *record[i]_previous_word [components]

                dup 7 addi {Digest::LEN} read_mem {Digest::LEN} pop 1
                // _ *records_end *record[i]_previous_word [components] [record[i]]

                call {apply_addition_record}
                // _ *records_end *record[i]_previous_word [components']

                pick 7 addi {Digest::LEN} place 7
                // _ *records_end *record[i + 1]_previous_word [components']

                recurse
        )
    }
}
