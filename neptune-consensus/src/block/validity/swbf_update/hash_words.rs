//! A variable-length hash for long inputs: a hundred and sixty words
//! absorbed per loop iteration, then forty, then ten, then the rest padded
//! in a staging block with two ten-word writes, so that the digest is that
//! of `Tip5::hash_varlen`.

use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

/// ```text
/// BEFORE: _ *words num_words
/// AFTER:  _ [digest]
/// ```
#[derive(Debug, Copy, Clone)]
pub(super) struct HashWords;

impl BasicSnippet for HashWords {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*words".to_string()),
            (DataType::U32, "num_words".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(DataType::Digest, "digest".to_string())]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_hash_words".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        // The last block: the words past the full blocks, a one, then zeros,
        // with nine words after it that the padding may write into.
        let stage = library.kmalloc(19).write_address();
        let entrypoint = self.entrypoint();
        let absorb_hundred_sixty = format!("{entrypoint}_hundred_sixty");
        let absorb_forty = format!("{entrypoint}_forty");
        let absorb_ten = format!("{entrypoint}_ten");
        let copy_tail = format!("{entrypoint}_copy_tail");
        let copy_eight = format!("{entrypoint}_copy_eight");
        let copy_four = format!("{entrypoint}_copy_four");
        let copy_two = format!("{entrypoint}_copy_two");
        let copy_one = format!("{entrypoint}_copy_one");

        triton_asm!(
            // BEFORE: _ *words num_words
            // AFTER:  _ [digest]
            {entrypoint}:
                sponge_init
                push 10 dup 1 div_mod place 1 pop 1
                // _ *words num_words rest

                dup 2 dup 2 add dup 1 push -1 mul add
                // _ *words num_words rest *stop_ten

                push 40 dup 3 div_mod pop 1 push 40 mul dup 4 add
                // _ *words num_words rest *stop_ten *stop_forty

                push 160 dup 4 div_mod pop 1 push 160 mul dup 5 add
                // _ *words num_words rest *stop_ten *stop_forty *stop_hundred_sixty

                push 0 push 0 push 0 push 0 pick 9
                call {absorb_hundred_sixty}
                pick 5 pop 1
                call {absorb_forty}
                pick 5 pop 1
                call {absorb_ten}
                // _ num_words rest *stop_ten e f g h *stop_ten

                place 4 pop 4 pick 1 pop 1 swap 1
                // _ num_words *tail rest

                push {stage} swap 1
                call {copy_tail}
                pop 1 swap 1 pop 1
                // _ num_words *next

                push 0 push 0 push 0 push 0 push 1 pick 5 write_mem 5
                push 0 push 0 push 0 push 0 push 0 pick 5 write_mem 5 pop 2
                push 0 push 0 push 0 push 0 push {stage} sponge_absorb_mem pop 5
                sponge_squeeze
                pick 9 pick 9 pick 9 pick 9 pick 9 pop 5
                return

            // INVARIANT: _ *stop a b c d *words
            {absorb_hundred_sixty}:
                dup 5 dup 1 eq skiz return
                sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem
                sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem
                sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem
                sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem
                recurse

            // INVARIANT: _ *stop a b c d *words
            {absorb_forty}:
                dup 5 dup 1 eq skiz return
                sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem
                recurse

            // INVARIANT: _ *stop a b c d *words
            {absorb_ten}:
                dup 5 dup 1 eq skiz return
                sponge_absorb_mem
                recurse

            // INVARIANT: _ *tail *next rest
            // The rest into the stage: eight, four, two and one words, as the
            // count's bits say.
            // BEFORE: _ *tail *next rest
            // AFTER:  _ *tail' *next' 0
            {copy_tail}:
                dup 0 push 7 lt skiz call {copy_eight}
                dup 0 push 3 lt skiz call {copy_four}
                dup 0 push 1 lt skiz call {copy_two}
                dup 0 skiz call {copy_one}
                return

            // BEFORE: _ *tail *next rest
            // AFTER:  _ *tail' *next' (rest - 8)
            {copy_eight}:
                pick 2 addi 4 read_mem 5 addi 6 place 7 pick 6 write_mem 5 place 1
                pick 2 addi 2 read_mem 3 addi 4 place 5 pick 4 write_mem 3 place 1
                addi -8
                return

            // BEFORE: _ *tail *next rest
            // AFTER:  _ *tail' *next' (rest - 4)
            {copy_four}:
                pick 2 addi 3 read_mem 4 addi 5 place 6 pick 5 write_mem 4 place 1
                addi -4
                return

            // BEFORE: _ *tail *next rest
            // AFTER:  _ *tail' *next' (rest - 2)
            {copy_two}:
                pick 2 addi 1 read_mem 2 addi 3 place 4 pick 3 write_mem 2 place 1
                addi -2
                return

            // BEFORE: _ *tail *next 1
            // AFTER:  _ *tail' *next' 0
            {copy_one}:
                pick 2 read_mem 1 addi 2 place 3 pick 2 write_mem 1 place 1
                addi -1
                return

        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::prelude::Tip5;
    use tasm_lib::triton_vm::vm::VMState;

    use super::*;

    #[test]
    fn hashes_like_the_host() {
        let mut rng = StdRng::seed_from_u64(0);
        for num_words in (0..=100).chain([159, 160, 161, 199, 200, 201, 412, 413, 4_096]) {
            let words = (0..num_words)
                .map(|_| rng.random())
                .collect::<Vec<BFieldElement>>();
            let pointer = bfe!(1_000);
            let mut nondeterminism = NonDeterminism::default();
            for (i, &word) in words.iter().enumerate() {
                nondeterminism.ram.insert(pointer + bfe!(i as u64), word);
            }

            let program = Program::new(&HashWords.link_for_isolated_run());
            let mut vm_state = VMState::new(program, PublicInput::default(), nondeterminism);
            vm_state.op_stack.stack = [
                HashWords.init_stack_for_isolated_run(),
                vec![pointer, bfe!(num_words as u64)],
            ]
            .concat();
            vm_state.run().unwrap();

            let stack = &vm_state.op_stack.stack;
            let mut digest = stack[stack.len() - Digest::LEN..].to_vec();
            digest.reverse();
            assert_eq!(
                Tip5::hash_varlen(&words),
                Digest::new(digest.try_into().unwrap()),
                "{num_words} words"
            );
        }
    }
}
