//! Absorbs blocks of ten words straight from memory, sixteen, four and one
//! at a time.

use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

/// ```text
/// BEFORE: _ *blocks num_blocks
/// AFTER:  _
/// ```
///
/// The sponge must be initialized.
#[derive(Debug, Copy, Clone)]
pub(super) struct AbsorbBlocks;

impl BasicSnippet for AbsorbBlocks {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*blocks".to_string()),
            (DataType::U32, "num_blocks".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_absorb_blocks".to_string()
    }

    fn code(&self, _: &mut Library) -> Vec<LabelledInstruction> {
        let entrypoint = self.entrypoint();
        let sixteens = format!("{entrypoint}_sixteens");
        let fours = format!("{entrypoint}_fours");
        let ones = format!("{entrypoint}_ones");

        triton_asm!(
            // BEFORE: _ *blocks num_blocks
            // AFTER:  _
            {entrypoint}:
                // The absorption overwrites four words below the pointer.
                push 0 push 0 push 0 push 0 pick 5
                // _ num_blocks 0 0 0 0 *blocks

                call {sixteens}
                call {fours}
                call {ones}
                pop 5 pop 1
                return

            // INVARIANT: _ remaining a b c d *blocks
            {sixteens}:
                dup 5 push 15 lt push 0 eq skiz return
                sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem
                sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem
                sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem
                sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem
                pick 5 addi -16 place 5
                recurse

            // INVARIANT: _ remaining a b c d *blocks
            {fours}:
                dup 5 push 3 lt push 0 eq skiz return
                sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem
                pick 5 addi -4 place 5
                recurse

            // INVARIANT: _ remaining a b c d *blocks
            {ones}:
                dup 5 push 0 eq skiz return
                sponge_absorb_mem
                pick 5 addi -1 place 5
                recurse
        )
    }
}
