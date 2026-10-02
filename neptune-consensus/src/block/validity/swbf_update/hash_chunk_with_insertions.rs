//! The hash of a chunk with sorted indices inserted, without writing the
//! new chunk: the runs between insertions are absorbed straight from the old
//! chunk's memory, ten words per instruction, and only the words around an
//! insertion pass through a staging block. The digest is that of
//! `Tip5::hash` of the new chunk.

use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use crate::block::block_validation_error::BlockValidationRule;

/// ```text
/// BEFORE: _ *chunk_encoding *sorted_indices
/// AFTER:  _ [digest]
/// ```
///
/// The chunk is given by a pointer to its encoding, whose first word is the
/// length of the rest, followed by the list of set indices in ascending
/// order. The prover supplies for each index, in order, the position in the
/// chunk's list where it goes, as for
/// [`InsertIntoWindow`](super::insert_into_window::InsertIntoWindow), and
/// the same tokens serve. Positions must not decrease, and the entries
/// around a position must enclose the index, with repetitions allowed.
///
/// Crashes with the error ID of rule 2.e if a position is out of order or
/// its neighbours do not enclose the index.
#[derive(Debug, Copy, Clone)]
pub(super) struct HashChunkWithInsertions;

impl BasicSnippet for HashChunkWithInsertions {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*chunk_encoding".to_string()),
            (
                DataType::List(Box::new(DataType::U32)),
                "*sorted_indices".to_string(),
            ),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(DataType::Digest, "digest".to_string())]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_hash_chunk_with_insertions".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        // The block being filled, absorbed once it holds ten words, with nine
        // words after it that the padding may write into.
        let stage = library.kmalloc(19).write_address();
        let error_id = BlockValidationRule::MutatorSetUpdateIntegrity.error_id();

        let entrypoint = self.entrypoint();
        let insertions_loop = format!("{entrypoint}_insertions_loop");
        let check_before = format!("{entrypoint}_check_before");
        let check_at = format!("{entrypoint}_check_at");
        let emit_run = format!("{entrypoint}_emit_run");
        let copy_into_stage = format!("{entrypoint}_copy_into_stage");
        let copy_eight = format!("{entrypoint}_copy_eight");
        let copy_four = format!("{entrypoint}_copy_four");
        let copy_two = format!("{entrypoint}_copy_two");
        let copy_one = format!("{entrypoint}_copy_one");
        let absorb_hundred_sixties = format!("{entrypoint}_absorb_hundred_sixties");
        let absorb_forties = format!("{entrypoint}_absorb_forties");
        let absorb_tens = format!("{entrypoint}_absorb_tens");
        let stage_word = format!("{entrypoint}_stage_word");
        let flush = format!("{entrypoint}_flush");
        let finish = format!("{entrypoint}_finish");

        // BEFORE: _ a b
        // AFTER:  _ min(a, b)
        let min = triton_asm!(
            dup 0 dup 2 lt
            dup 2 dup 2 push -1 mul add mul add
            place 1 pop 1
        );

        // BEFORE: _
        // AFTER:  _
        let absorb_stage = triton_asm!(
            push 0 push 0 push 0 push 0 push {stage} sponge_absorb_mem pop 5
        );

        triton_asm!(
            // BEFORE: _ *chunk_encoding *sorted_indices
            // AFTER:  _ [digest]
            {entrypoint}:
                sponge_init
                dup 1 addi 1 read_mem 1 pop 1
                dup 1 read_mem 1 pop 1
                // _ *encoding *sorted n m

                dup 1 dup 1 add
                // _ *encoding *sorted n m (n + m)

                // The new encoding's two length words.
                dup 0 addi 1 push {stage} write_mem 2
                // _ *encoding *sorted n m f

                pick 4 addi 2
                // _ *sorted n m f *first

                dup 0 dup 4 add
                // _ *sorted n m f *first *stop

                pick 5 addi 1 dup 0 dup 5 add
                // _ n m f *first *stop *x *x_end

                place 1 pick 4 dup 4 place 1
                // _ n m *first *stop *x_end *x *first f

                pick 7 pop 1 pick 6 pop 1
                // _ *first *stop *x_end *x *first f

                call {insertions_loop}
                // _ *first *stop *x_end *x_end *old f

                pick 4 place 2
                // _ *first *x_end *x_end *stop *old f

                call {emit_run}
                // _ *first *x_end *x_end *stop f

                call {finish}
                pop 4
                sponge_squeeze
                pick 9 pick 9 pick 9 pick 9 pick 9 pop 5
                return

            // Each index at its divined position, after the run of the
            // chunk's entries up to there.
            // INVARIANT: _ *first *stop *x_end *x *old f
            {insertions_loop}:
                dup 3 dup 3 eq skiz return
                divine 1 dup 6 add
                // _ *first *stop *x_end *x *old f *target

                // Positions do not decrease, and do not exceed the chunk's
                // length.
                dup 2 dup 1 lt push 0 eq assert error_id {error_id}
                dup 0 dup 6 lt push 0 eq assert error_id {error_id}
                dup 3 read_mem 1 pop 1
                // _ *first *stop *x_end *x *old f *target x

                dup 1 dup 8 eq push 0 eq skiz call {check_before}
                dup 1 dup 7 eq push 0 eq skiz call {check_at}
                // _ *first *stop *x_end *x *old f *target x

                place 3 place 2
                // _ *first *stop *x_end *x x *target *old f

                call {emit_run}
                // _ *first *stop *x_end *x x *target f

                pick 2 swap 1 call {stage_word}
                // _ *first *stop *x_end *x *target f

                pick 2 addi 1 place 2
                recurse

            // The entry before the position must not exceed the index.
            // BEFORE: _ ... *target x
            // AFTER:  _ ... *target x
            {check_before}:
                dup 1 addi -1 read_mem 1 pop 1
                dup 1 lt push 0 eq assert error_id {error_id}
                return

            // The entry at the position must not fall below the index.
            // BEFORE: _ ... *target x
            // AFTER:  _ ... *target x
            {check_at}:
                dup 1 read_mem 1 pop 1
                dup 1 swap 1 lt push 0 eq assert error_id {error_id}
                return

            // The chunk's entries from the cursor up to the target absorbed:
            // into the stage until it fills and flushes, then a hundred and
            // sixty, forty and ten words at a time straight from memory, then
            // the rest into the stage.
            // BEFORE: _ *target *old f
            // AFTER:  _ *target f'
            {emit_run}:
                dup 2 dup 2 push -1 mul add
                push {stage + bfe!(10)} dup 2 push -1 mul add
                {&min}
                // _ *target *old f min(run, space)

                call {copy_into_stage}
                dup 0 push {stage + bfe!(10)} eq skiz call {flush}
                // _ *target *old f

                place 2 push 0 push 0 push 0 push 0 pick 4
                // _ f *target 0 0 0 0 *old

                call {absorb_hundred_sixties}
                call {absorb_forties}
                call {absorb_tens}
                place 4 pop 4 pick 2
                // _ *target *old f

                dup 2 dup 2 push -1 mul add
                call {copy_into_stage}
                pick 1 pop 1
                return

            // At most ten words from the cursor into the stage: eight, four,
            // two and one, as the count's bits say.
            // BEFORE: _ *old f n
            // AFTER:  _ *old' f'
            {copy_into_stage}:
                dup 0 push 7 lt skiz call {copy_eight}
                dup 0 push 3 lt skiz call {copy_four}
                dup 0 push 1 lt skiz call {copy_two}
                dup 0 skiz call {copy_one}
                pop 1
                return

            // BEFORE: _ *old f n
            // AFTER:  _ *old' f' (n - 8)
            {copy_eight}:
                pick 2 addi 4 read_mem 5 addi 6 place 7 pick 6 write_mem 5 place 1
                pick 2 addi 2 read_mem 3 addi 4 place 5 pick 4 write_mem 3 place 1
                addi -8
                return

            // BEFORE: _ *old f n
            // AFTER:  _ *old' f' (n - 4)
            {copy_four}:
                pick 2 addi 3 read_mem 4 addi 5 place 6 pick 5 write_mem 4 place 1
                addi -4
                return

            // BEFORE: _ *old f n
            // AFTER:  _ *old' f' (n - 2)
            {copy_two}:
                pick 2 addi 1 read_mem 2 addi 3 place 4 pick 3 write_mem 2 place 1
                addi -2
                return

            // BEFORE: _ *old f 1
            // AFTER:  _ *old' f' 0
            {copy_one}:
                pick 2 read_mem 1 addi 2 place 3 pick 2 write_mem 1 place 1
                addi -1
                return

            // INVARIANT: _ f *target a b c d *old
            {absorb_hundred_sixties}:
                dup 5 dup 1 push -1 mul add push 160 swap 1 lt skiz return
                sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem
                sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem
                sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem
                sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem
                recurse

            // INVARIANT: _ f *target a b c d *old
            {absorb_forties}:
                dup 5 dup 1 push -1 mul add push 40 swap 1 lt skiz return
                sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem sponge_absorb_mem
                recurse

            // INVARIANT: _ f *target a b c d *old
            {absorb_tens}:
                dup 5 dup 1 push -1 mul add push 10 swap 1 lt skiz return
                sponge_absorb_mem
                recurse

            // A word into the stage, absorbed when it fills. The fill is the
            // address of the next free word.
            // BEFORE: _ x f
            // AFTER:  _ f'
            {stage_word}:
                write_mem 1
                dup 0 push {stage + bfe!(10)} eq skiz call {flush}
                return

            // BEFORE: _ *stage_end
            // AFTER:  _ *stage
            {flush}:
                pop 1
                {&absorb_stage}
                push {stage}
                return

            // The last block: the staged words, a one, then zeros, written
            // ten at a time into the stage and the words after it.
            // BEFORE: _ f
            // AFTER:  _
            {finish}:
                push 0 push 0 push 0 push 0 push 1 pick 5 write_mem 5
                push 0 push 0 push 0 push 0 push 0 pick 5 write_mem 5 pop 1
                {&absorb_stage}
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
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::prelude::Tip5;
    use tasm_lib::triton_vm::vm::VMState;

    use super::super::insert_into_window::InsertIntoWindow;
    use super::super::mutate_swbfi_peaks::MutateSwbfiPeaks;
    use super::*;

    /// The digest the snippet computes, if it accepts the tokens.
    fn tasm_digest(
        chunk: &[u32],
        insertions: &[u32],
        tokens: Vec<BFieldElement>,
    ) -> Option<Digest> {
        let encoding_pointer = bfe!(1_000);
        let indices_pointer = bfe!(10_000);
        let mut nondeterminism = NonDeterminism::new(tokens);
        // The encoding: the length of the rest, then the list.
        let mut encoding = vec![bfe!(chunk.len() as u64 + 1), bfe!(chunk.len() as u64)];
        encoding.extend(chunk.iter().map(|&index| bfe!(index)));
        for (i, &word) in encoding.iter().enumerate() {
            nondeterminism
                .ram
                .insert(encoding_pointer + bfe!(i as u64), word);
        }
        encode_to_memory(
            &mut nondeterminism.ram,
            indices_pointer,
            &insertions.to_vec(),
        );

        let program = Program::new(&HashChunkWithInsertions.link_for_isolated_run());
        let mut vm_state = VMState::new(program, PublicInput::default(), nondeterminism);
        vm_state.op_stack.stack = [
            HashChunkWithInsertions.init_stack_for_isolated_run(),
            vec![encoding_pointer, indices_pointer],
        ]
        .concat();
        vm_state.run().ok()?;

        let stack = &vm_state.op_stack.stack;
        let init_stack = HashChunkWithInsertions.init_stack_for_isolated_run();
        assert_eq!(
            init_stack.len() + Digest::LEN,
            stack.len(),
            "stack must balance"
        );
        assert_eq!(
            init_stack[..],
            stack[..init_stack.len()],
            "stack must balance"
        );
        let mut digest = stack[stack.len() - Digest::LEN..].to_vec();
        digest.reverse();
        Some(Digest::new(digest.try_into().unwrap()))
    }

    fn sorted(rng: &mut StdRng, len: usize, bound: u32) -> Vec<u32> {
        let mut values = (0..len)
            .map(|_| rng.random_range(0..bound))
            .collect::<Vec<_>>();
        values.sort_unstable();
        values
    }

    #[test]
    fn hashes_the_chunk_with_insertions_like_the_host() {
        let mut rng = StdRng::seed_from_u64(0);
        for (chunk_len, num_insertions) in [
            (0, 0),
            (0, 1),
            (1, 0),
            (7, 1),
            (9, 1),
            (10, 1),
            (11, 3),
            (39, 2),
            (40, 1),
            (41, 5),
            (100, 0),
            (100, 7),
            (159, 2),
            (160, 1),
            (161, 1),
            (170, 1),
            (320, 2),
            (321, 3),
            (412, 1),
            (412, 3),
            (413, 45),
        ] {
            let chunk = sorted(&mut rng, chunk_len, 4096);
            let insertions = sorted(&mut rng, num_insertions, 4096);
            let expected = Tip5::hash(&neptune_mutator_set::removal_record::chunk::Chunk {
                relative_indices: MutateSwbfiPeaks::mutated(&chunk, &insertions),
            });
            let tokens = InsertIntoWindow::divined_tokens(&chunk, &insertions);
            assert_eq!(
                Some(expected),
                tasm_digest(&chunk, &insertions, tokens),
                "{chunk_len} entries, {num_insertions} insertions"
            );
        }
    }

    /// The positions of a sorted list at which an index may be inserted
    /// without breaking the order, repetitions allowed.
    fn enclosing_positions(sorted: &[u32], index: u32) -> Vec<usize> {
        (0..=sorted.len())
            .filter(|&p| {
                (p == 0 || sorted[p - 1] <= index) && (p == sorted.len() || index <= sorted[p])
            })
            .collect()
    }

    /// Whatever accepted positions the prover chooses, the digest is that of
    /// the sorted union: no accepted run yields an unsorted chunk. Small
    /// values force repetitions, where several positions are accepted.
    #[test]
    fn every_accepted_position_yields_the_sorted_union() {
        let mut rng = StdRng::seed_from_u64(3);
        let mut runs = 0;
        for _ in 0..6 {
            let chunk = sorted(&mut rng, 8, 6);
            let insertions = sorted(&mut rng, 2, 6);
            let expected = Tip5::hash(&neptune_mutator_set::removal_record::chunk::Chunk {
                relative_indices: MutateSwbfiPeaks::mutated(&chunk, &insertions),
            });
            for first in enclosing_positions(&chunk, insertions[0]) {
                for second in enclosing_positions(&chunk, insertions[1]) {
                    let tokens = vec![bfe!(first as u64), bfe!(second as u64)];
                    let digest = tasm_digest(&chunk, &insertions, tokens);
                    if second < first {
                        assert_eq!(None, digest, "positions must not decrease");
                    } else {
                        assert_eq!(
                            Some(expected),
                            digest,
                            "{chunk:?} + {insertions:?} at {first}, {second}"
                        );
                        runs += 1;
                    }
                }
            }
        }
        assert!(runs > 12, "the cases must offer several accepted positions");
    }

    #[test]
    fn insertions_at_the_ends_and_repeated_are_accepted() {
        let chunk = vec![5, 5, 9];
        for insertions in [vec![0], vec![5], vec![9], vec![12], vec![5, 5, 9, 9]] {
            let expected = Tip5::hash(&neptune_mutator_set::removal_record::chunk::Chunk {
                relative_indices: MutateSwbfiPeaks::mutated(&chunk, &insertions),
            });
            let tokens = InsertIntoWindow::divined_tokens(&chunk, &insertions);
            assert_eq!(Some(expected), tasm_digest(&chunk, &insertions, tokens));
        }
    }

    /// Every position of one insertion, and of two adjacent ones, in a
    /// chunk long enough to fill the stage, flush it, absorb in bulk and
    /// stage a tail.
    #[test]
    fn every_insertion_position_agrees() {
        let mut rng = StdRng::seed_from_u64(1);
        for chunk_len in [23, 51] {
            let chunk = (0..chunk_len as u32).map(|i| 3 * i).collect::<Vec<_>>();
            for position in 0..=chunk_len {
                let index = 3 * position as u32;
                for insertions in [vec![index], vec![index, index + 1]] {
                    let expected = Tip5::hash(&neptune_mutator_set::removal_record::chunk::Chunk {
                        relative_indices: MutateSwbfiPeaks::mutated(&chunk, &insertions),
                    });
                    let tokens = InsertIntoWindow::divined_tokens(&chunk, &insertions);
                    assert_eq!(
                        Some(expected),
                        tasm_digest(&chunk, &insertions, tokens),
                        "{chunk_len} entries, {insertions:?} at {position}"
                    );
                }
            }
            let _ = &mut rng;
        }
    }

    #[test]
    fn missing_and_oversized_position_tokens_are_rejected() {
        let chunk = vec![2, 4, 6, 8];
        let insertions = vec![3, 7];
        let honest = InsertIntoWindow::divined_tokens(&chunk, &insertions);
        assert_eq!(None, tasm_digest(&chunk, &insertions, vec![]));
        assert_eq!(None, tasm_digest(&chunk, &insertions, honest[..1].to_vec()));
        assert_eq!(
            None,
            tasm_digest(&chunk, &insertions, vec![bfe!(1), bfe!(1_u64 << 40)])
        );
        assert_eq!(
            None,
            tasm_digest(&chunk, &insertions, vec![-bfe!(1), bfe!(3)])
        );
    }

    #[test]
    fn positions_out_of_order_or_not_enclosing_are_rejected() {
        let chunk = vec![2, 4, 6, 8];
        let insertions = vec![3, 7];
        let honest = InsertIntoWindow::divined_tokens(&chunk, &insertions);
        assert_eq!(vec![bfe!(1), bfe!(3)], honest);
        for tokens in [
            vec![bfe!(3), bfe!(1)],
            vec![bfe!(0), bfe!(3)],
            vec![bfe!(2), bfe!(3)],
            vec![bfe!(1), bfe!(5)],
            vec![bfe!(1), bfe!(4)],
        ] {
            assert_eq!(
                None,
                tasm_digest(&chunk, &insertions, tokens.clone()),
                "{tokens:?}"
            );
        }
    }
}
