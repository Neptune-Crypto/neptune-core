//! The hash of a chunk with sorted indices inserted, without writing the
//! new chunk. With one insertion, the common case, the blocks of the new
//! encoding are those of the chunk's padded storage, before the insertion
//! as they are and after it at an offset of one word, and are absorbed
//! straight from memory; only the block with the insertion is assembled,
//! on the stack. With any other number, the runs between insertions are
//! absorbed straight from the old chunk's memory, ten words per
//! instruction, and only the words around an insertion pass through a
//! staging block. The digest is that of `Tip5::hash` of the new chunk.

use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use super::absorb_blocks::AbsorbBlocks;
use crate::block::block_validation_error::BlockValidationRule;

/// ```text
/// BEFORE: _ *chunk_storage *sorted_indices
/// AFTER:  _ [digest]
/// ```
///
/// The chunk is given by a pointer to its storage, its encoding padded for
/// the sponge (see [`HashBlocks::chunk_storage`](super::hash_blocks::HashBlocks::chunk_storage)):
/// the length of the rest, then the list of set indices in ascending
/// order. The prover supplies for each index, in order, the position in
/// the chunk's list where it goes, as for
/// [`InsertIntoWindow`](super::insert_into_window::InsertIntoWindow), and
/// the same tokens serve. Positions must not decrease, and the entries
/// around a position must enclose the index, with repetitions allowed.
///
/// With exactly one index to insert, the storage's two length words are
/// raised by one in place: the storage then no longer hashes to the old
/// chunk.
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
        let absorb_blocks = library.import(Box::new(AbsorbBlocks));
        // The block being filled, absorbed once it holds ten words, with nine
        // words after it that the padding may write into.
        let stage = library.kmalloc(19).write_address();
        // The single insertion's chunk, list and length, the block its
        // index lands in and its position in that block, and the blocks of
        // the old encoding.
        let chunk_alloc = library.kmalloc(1);
        let sorted_alloc = library.kmalloc(1);
        let length_alloc = library.kmalloc(1);
        let block_alloc = library.kmalloc(1);
        let rest_alloc = library.kmalloc(1);
        let old_blocks_alloc = library.kmalloc(1);
        let error_id = BlockValidationRule::MutatorSetUpdateIntegrity.error_id();

        let entrypoint = self.entrypoint();
        let general = format!("{entrypoint}_general");
        let single = format!("{entrypoint}_single");
        let single_before = format!("{entrypoint}_single_before");
        let single_at = format!("{entrypoint}_single_at");
        let final_block = format!("{entrypoint}_final_block");
        let read_run = format!("{entrypoint}_read_run");
        let take_five = format!("{entrypoint}_take_five");
        let take_four = format!("{entrypoint}_take_four");
        let take_three = format!("{entrypoint}_take_three");
        let take_two = format!("{entrypoint}_take_two");
        let take_one = format!("{entrypoint}_take_one");
        let read = |alloc: &tasm_lib::library::StaticAllocation| triton_asm!(push {alloc.read_address()} read_mem 1 pop 1);
        let write = |alloc: &tasm_lib::library::StaticAllocation| triton_asm!(push {alloc.write_address()} write_mem 1 pop 1);
        // Reads this many words of a run onto the stack, the first on top.
        // BEFORE: _ *last len
        // AFTER:  _ [words] (*last - n) (len - n)
        let take = |n: usize| {
            triton_asm!(
                swap 1 read_mem {n}
                pick {n + 1} addi {-(n as i64)}
                return
            )
        };
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
            // BEFORE: _ *chunk_storage *sorted_indices
            // AFTER:  _ [digest]
            {entrypoint}:
                dup 0 read_mem 1 pop 1 push 1 eq
                dup 0 skiz call {single}
                push 0 eq skiz call {general}
                return

            // The one index's block assembled, the others absorbed from the
            // storage, before it as they are and after it a word along.
            // BEFORE: _ *chunk_storage *sorted_indices 1
            // AFTER:  _ [digest] 1
            {single}:
                pop 1
                sponge_init
                dup 1 {&write(&chunk_alloc)}
                dup 0 {&write(&sorted_alloc)}
                dup 1 addi 1 read_mem 1 pop 1
                dup 0 {&write(&length_alloc)}
                // _ *chunk *sorted length

                divine 1
                // The position does not exceed the chunk's length, and its
                // neighbours enclose the index.
                dup 0 dup 2 lt push 0 eq assert error_id {error_id}
                dup 2 addi 1 read_mem 1 pop 1
                // _ *chunk *sorted length position index

                dup 1 push 0 eq push 0 eq skiz call {single_before}
                dup 1 dup 3 eq push 0 eq skiz call {single_at}
                pop 1
                // _ *chunk *sorted length position

                // The new encoding's length words, in place.
                dup 1 addi 1 dup 2 addi 2 dup 5 write_mem 2 pop 1
                // The index's position in the new encoding, as a block and
                // a rest; and the old encoding's blocks.
                addi 2 push 10 swap 1 div_mod
                dup 0 {&write(&rest_alloc)}
                dup 1 {&write(&block_alloc)}
                dup 2 addi 12 push 10 swap 1 div_mod pop 1 {&write(&old_blocks_alloc)}
                // _ *chunk *sorted length block rest

                // The blocks before the index's.
                pick 4 dup 2 call {absorb_blocks}
                pop 4
                // _

                // The index's block: the run after the index, the index,
                // then the run before it, so that the first word is on top.
                {&read(&chunk_alloc)} {&read(&block_alloc)} push 10 mul add
                dup 0 addi 8 push 9 {&read(&rest_alloc)} push -1 mul add
                pick 2 pop 1
                call {read_run}
                {&read(&sorted_alloc)} addi 1 read_mem 1 pop 1
                {&read(&chunk_alloc)} {&read(&block_alloc)} push 10 mul add
                {&read(&rest_alloc)} add addi -1
                {&read(&rest_alloc)}
                call {read_run}
                sponge_absorb
                // _

                // The blocks after the index's that the old encoding
                // covers, a word along; then, if the new encoding is a block
                // longer, the block of its padding, the one and nine zeros,
                // since the old encoding's one is then the last word of its
                // storage.
                {&read(&chunk_alloc)} {&read(&block_alloc)} addi 1 push 10 mul add addi -1
                {&read(&old_blocks_alloc)} {&read(&block_alloc)} push -1 mul add addi -1
                call {absorb_blocks}
                {&read(&length_alloc)} addi 3 push 10 swap 1 div_mod place 1 pop 1
                push 0 eq skiz call {final_block}
                sponge_squeeze
                pick 9 pick 9 pick 9 pick 9 pick 9 pop 5
                push 1
                return

            // The entry before the position must not exceed the index.
            // BEFORE: _ ... position index
            // AFTER:  _ ... position index
            {single_before}:
                {&read(&chunk_alloc)} dup 2 add addi 1 read_mem 1 pop 1
                dup 1 lt push 0 eq assert error_id {error_id}
                return

            // The entry at the position must not fall below the index.
            // BEFORE: _ ... position index
            // AFTER:  _ ... position index
            {single_at}:
                {&read(&chunk_alloc)} dup 2 add addi 2 read_mem 1 pop 1
                dup 1 swap 1 lt push 0 eq assert error_id {error_id}
                return

            // BEFORE: _
            // AFTER:  _
            {final_block}:
                push 0 push 0 push 0 push 0 push 0 push 0 push 0 push 0 push 0 push 1
                sponge_absorb
                return

            // Up to nine words of a run onto the stack, the first on top:
            // five, then as many as remain.
            // BEFORE: _ *last len
            // AFTER:  _ [words]
            {read_run}:
                dup 0 push 4 lt skiz call {take_five}
                dup 0 push 3 lt skiz call {take_four}
                dup 0 push 2 lt skiz call {take_three}
                dup 0 push 1 lt skiz call {take_two}
                dup 0 push 0 lt skiz call {take_one}
                pop 2
                return

            {take_five}:
                {&take(5)}
            {take_four}:
                {&take(4)}
            {take_three}:
                {&take(3)}
            {take_two}:
                {&take(2)}
            {take_one}:
                {&take(1)}

            // Any number of insertions, through the staging block.
            // BEFORE: _ *chunk_storage *sorted_indices
            // AFTER:  _ [digest]
            {general}:
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
    use tasm_lib::triton_vm::vm::VM;

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
        let storage = super::super::hash_blocks::HashBlocks::chunk_storage(chunk);
        for (i, &word) in storage.iter().enumerate() {
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

    /// The digests both snippets compute on one copy of the chunk's
    /// storage, the old chunk's first, as the peak mutation runs them.
    fn tasm_digests_on_storage(chunk: &[u32], insertions: &[u32]) -> Option<(Digest, Digest)> {
        use super::super::hash_blocks::HashBlocks;

        let storage_pointer = bfe!(1_000);
        let indices_pointer = bfe!(10_000);
        let storage = HashBlocks::chunk_storage(chunk);
        let mut library = Library::new();
        let hash_blocks = library.import(Box::new(HashBlocks));
        let with_insertions = library.import(Box::new(HashChunkWithInsertions));
        let program = Program::new(&triton_asm!(
            push {storage_pointer} push {storage.len() / 10} call {hash_blocks}
            push {storage_pointer} push {indices_pointer} call {with_insertions}
            write_io 5 write_io 5
            halt
            {&library.all_imports()}
        ));
        let mut nondeterminism =
            NonDeterminism::new(InsertIntoWindow::divined_tokens(chunk, insertions));
        for (i, &word) in storage.iter().enumerate() {
            nondeterminism
                .ram
                .insert(storage_pointer + bfe!(i as u64), word);
        }
        encode_to_memory(
            &mut nondeterminism.ram,
            indices_pointer,
            &insertions.to_vec(),
        );
        let output = VM::run(program, PublicInput::default(), nondeterminism).ok()?;
        let digest = |words: &[BFieldElement]| Digest::new(words.to_vec().try_into().unwrap());
        Some((digest(&output[5..]), digest(&output[..5])))
    }

    /// Every number of insertions from none to eleven, into chunks of
    /// every length modulo the block, so that the padding of the storage
    /// and of the new encoding fall every way they can around the
    /// insertions: the old hash and the new one both match the host.
    #[test]
    fn padding_holds_for_every_insertion_count_and_chunk_length() {
        let mut rng = StdRng::seed_from_u64(9);
        let chunk_lengths = (0..=25).chain(405..=415).collect::<Vec<usize>>();
        for chunk_len in chunk_lengths {
            for num_insertions in 0..=11 {
                let chunk = sorted(&mut rng, chunk_len, 4096);
                let insertions = sorted(&mut rng, num_insertions, 4096);
                let old = Tip5::hash(&neptune_mutator_set::removal_record::chunk::Chunk {
                    relative_indices: chunk.clone(),
                });
                let new = Tip5::hash(&neptune_mutator_set::removal_record::chunk::Chunk {
                    relative_indices: MutateSwbfiPeaks::mutated(&chunk, &insertions),
                });
                assert_eq!(
                    Some((old, new)),
                    tasm_digests_on_storage(&chunk, &insertions),
                    "{chunk_len} entries, {num_insertions} insertions"
                );
            }
        }
    }

    /// One insertion at every position of chunks whose padding sits every
    /// way around the last block, and at the ends.
    #[test]
    fn single_insertion_at_every_position_and_padding_boundary() {
        for chunk_len in [0, 1, 6, 7, 8, 9, 16, 17, 18, 27, 37, 47] {
            let chunk = (0..chunk_len as u32).map(|i| 3 * i + 1).collect::<Vec<_>>();
            for position in 0..=chunk_len {
                let index = 3 * position as u32;
                let old = Tip5::hash(&neptune_mutator_set::removal_record::chunk::Chunk {
                    relative_indices: chunk.clone(),
                });
                let new = Tip5::hash(&neptune_mutator_set::removal_record::chunk::Chunk {
                    relative_indices: MutateSwbfiPeaks::mutated(&chunk, &[index]),
                });
                assert_eq!(
                    Some((old, new)),
                    tasm_digests_on_storage(&chunk, &[index]),
                    "{chunk_len} entries, insertion at {position}"
                );
            }
        }
    }

    #[test]
    fn single_insertion_out_of_place_or_not_enclosed_is_rejected() {
        let chunk = vec![2, 4, 6, 8];
        for (insertion, position) in [(3, 0), (3, 2), (3, 5), (9, 3), (1, 1)] {
            assert_eq!(
                None,
                tasm_digest(&chunk, &[insertion], vec![bfe!(position)]),
                "{insertion} at {position}"
            );
        }
    }
}
