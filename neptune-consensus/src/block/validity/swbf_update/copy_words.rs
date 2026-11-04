//! A word copy for long runs: twenty words per loop iteration, then the
//! tasm-lib copy for the rest.

use tasm_lib::memory::memcpy::MemCpy;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

/// ```text
/// BEFORE: _ *read *write num_words
/// AFTER:  _
/// ```
///
/// Copies the words at `*read` and up to `*write` and up.
#[derive(Debug, Copy, Clone)]
pub(super) struct CopyWords;

impl BasicSnippet for CopyWords {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*read".to_string()),
            (DataType::VoidPointer, "*write".to_string()),
            (DataType::U32, "num_words".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_copy_words".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let memcpy = library.import(Box::new(MemCpy));
        let entrypoint = self.entrypoint();
        let copy_twenty = format!("{entrypoint}_twenty");

        // Five words from the block whose last word the read pointer points
        // at, to the write pointer; both advance.
        // BEFORE: _ *read_last *write
        // AFTER:  _ *read_last' *write'
        let copy_five = triton_asm!(
            swap 1 read_mem 5 addi 10 place 6 pick 5 write_mem 5
        );

        triton_asm!(
            // BEFORE: _ *read *write num_words
            // AFTER:  _
            {entrypoint}:
                push 20 dup 1 div_mod
                // _ *read *write num_words blocks rest

                pick 1 push 20 mul dup 4 add addi 4
                // _ *read *write num_words rest *stop_last

                pick 4 addi 4 pick 4
                // _ num_words rest *stop_last *read_last *write

                call {copy_twenty}
                // _ num_words rest *stop_last *stop_last *write

                pick 1 addi -4 place 1 pick 2 pop 1 pick 2
                // _ num_words *read' *write' rest

                call {memcpy}
                pop 1
                return

            // INVARIANT: _ *stop_last *read_last *write
            {copy_twenty}:
                dup 2 dup 2 eq skiz return
                {&copy_five}
                {&copy_five}
                {&copy_five}
                {&copy_five}
                recurse
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;

    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::triton_vm::vm::VMState;

    use super::*;

    #[test]
    fn copies_like_the_host() {
        let mut rng = StdRng::seed_from_u64(0);
        for num_words in [0, 1, 4, 5, 19, 20, 21, 39, 40, 41, 100, 412, 413] {
            let words = (0..num_words)
                .map(|_| rng.random())
                .collect::<Vec<BFieldElement>>();
            let read = bfe!(1_000);
            let write = bfe!(10_000);
            let mut nondeterminism = NonDeterminism::default();
            for (i, &word) in words.iter().enumerate() {
                nondeterminism.ram.insert(read + bfe!(i as u64), word);
            }

            let program = Program::new(&CopyWords.link_for_isolated_run());
            let mut vm_state = VMState::new(program, PublicInput::default(), nondeterminism);
            vm_state.op_stack.stack = [
                CopyWords.init_stack_for_isolated_run(),
                vec![read, write, bfe!(num_words as u64)],
            ]
            .concat();
            vm_state.run().unwrap();

            let copied = (0..num_words)
                .map(|i| {
                    vm_state
                        .ram
                        .get(&(write + bfe!(i as u64)))
                        .copied()
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>();
            assert_eq!(words, copied, "{num_words} words");
            assert_eq!(
                CopyWords.init_stack_for_isolated_run(),
                vm_state.op_stack.stack,
                "{num_words} words"
            );
            let _ = HashMap::<u8, u8>::new();
        }
    }
}
