use std::collections::HashMap;

use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_mutator_set::shared::CHUNK_SIZE;
use neptune_mutator_set::shared::NUM_TRIALS;
use tasm_lib::arithmetic::u128::lt::Lt as U128Lt;
use tasm_lib::arithmetic::u128::sub::Sub as U128Sub;
use tasm_lib::field;
use tasm_lib::memory::dyn_malloc::DynMalloc;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use crate::block::block_validation_error::BlockValidationRule;

/// Collects, for each chunk of the inactive SWBF that a list of removal
/// records touches, the indices the records set in it, relative to the
/// chunk's start, as a sorted list.
///
/// ```text
/// BEFORE: _ *removal_records *chunk_indices [window_start: u128]
/// AFTER:  _ *insertions
/// ```
///
/// `*chunk_indices` lists the chunks' indices in ascending order, and
/// `*insertions` lists a pointer to the sorted list for each of them in the
/// same order. The lists hold exactly the records' indices below the window
/// start, each in the chunk it lies in, with repetitions.
///
/// The prover supplies each list's length and entries, then for every index
/// below the window start, in the order of the records and of their
/// indices, the position of its chunk and its position in that chunk's
/// list. Each position must hold that index and may be pointed at once,
/// and every position must be pointed at.
///
/// Crashes with the error ID of rule 2.e if the prover's lists are not the
/// sorted lists of the indices per chunk.
#[derive(Debug, Copy, Clone)]
pub(super) struct ChunkInsertions;

impl ChunkInsertions {
    fn error_id() -> i128 {
        BlockValidationRule::MutatorSetUpdateIntegrity.error_id()
    }

    fn chunk_index_of(index: u128) -> u64 {
        u64::try_from(index >> CHUNK_SIZE.ilog2()).expect("index below window start fits")
    }

    fn relative_index_of(index: u128) -> u32 {
        (index % u128::from(CHUNK_SIZE)) as u32
    }

    /// The records' indices below the window start, in the order of the
    /// records and of their indices.
    fn indices_below(removal_records: &[RemovalRecord], window_start: u128) -> Vec<u128> {
        removal_records
            .iter()
            .flat_map(|record| record.absolute_indices.to_array())
            .filter(|&index| index < window_start)
            .collect()
    }

    /// The sorted list of inserted indices per chunk: what the snippet
    /// returns. An index whose chunk is not listed is dropped; the snippet
    /// rejects it.
    pub(crate) fn insertions(
        removal_records: &[RemovalRecord],
        chunk_indices: &[u64],
        window_start: u128,
    ) -> Vec<Vec<u32>> {
        let mut insertions = vec![vec![]; chunk_indices.len()];
        for index in Self::indices_below(removal_records, window_start) {
            if let Some(position) = chunk_indices
                .iter()
                .position(|&chunk_index| chunk_index == Self::chunk_index_of(index))
            {
                insertions[position].push(Self::relative_index_of(index));
            }
        }
        for insertion in &mut insertions {
            insertion.sort_unstable();
        }
        insertions
    }

    /// The tokens the prover supplies: each chunk's list, then the positions
    /// of each index below the window start.
    pub(crate) fn divined_tokens(
        removal_records: &[RemovalRecord],
        chunk_indices: &[u64],
        window_start: u128,
    ) -> Vec<BFieldElement> {
        let insertions = Self::insertions(removal_records, chunk_indices, window_start);
        let lists: Vec<_> = insertions
            .iter()
            .flat_map(|insertion| {
                [bfe!(insertion.len() as u64)]
                    .into_iter()
                    .chain(insertion.iter().map(|&index| bfe!(index)))
            })
            .collect();

        let mut next_slot_of: HashMap<(usize, u32), usize> = HashMap::new();
        let positions: Vec<_> = Self::indices_below(removal_records, window_start)
            .into_iter()
            .flat_map(|index| {
                let chunk_position = chunk_indices
                    .iter()
                    .position(|&chunk_index| chunk_index == Self::chunk_index_of(index))
                    .unwrap_or_default();
                let relative_index = Self::relative_index_of(index);
                let slot = next_slot_of
                    .entry((chunk_position, relative_index))
                    .or_insert_with(|| {
                        insertions[chunk_position].partition_point(|&entry| entry < relative_index)
                    });
                *slot += 1;
                [bfe!(chunk_position as u64), bfe!(*slot as u64 - 1)]
            })
            .collect();

        [lists, positions].concat()
    }
}

impl BasicSnippet for ChunkInsertions {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*removal_records".to_string()),
            (
                DataType::List(Box::new(DataType::U64)),
                "*chunk_indices".to_string(),
            ),
            (DataType::U128, "window_start".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(
            DataType::List(Box::new(DataType::Bfe)),
            "*insertions".to_string(),
        )]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_chunk_insertions".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let dyn_malloc = library.import(Box::new(DynMalloc));
        let u128_lt = library.import(Box::new(U128Lt));
        let u128_sub = library.import(Box::new(U128Sub));

        let window_start_alloc = library.kmalloc(4);
        let chunk_indices_alloc = library.kmalloc(1);
        let insertions_alloc = library.kmalloc(1);
        let total_alloc = library.kmalloc(1);

        // The record at hand: an index lies below the window start if its
        // distance to the minimum is below the bound, or if all do. The
        // minimum's chunk index and offset in its chunk locate the others.
        // Layout: bound, all, chunk_lo, chunk_hi, offset.
        let record_alloc = library.kmalloc(5);
        let bound_address = record_alloc.write_address();
        let all_address = bound_address + bfe!(1);
        let offset_address = record_alloc.read_address();
        let chunks_per_limb = 1_u64 << (32 - CHUNK_SIZE.ilog2());

        let entrypoint = self.entrypoint();
        let chunks_loop = format!("{entrypoint}_chunks_loop");
        let read_loop = format!("{entrypoint}_read_loop");
        let records_loop = format!("{entrypoint}_records_loop");
        let indices_loop = format!("{entrypoint}_indices_loop");
        let process_index = format!("{entrypoint}_process_index");
        let mode_below = format!("{entrypoint}_mode_below");
        let mode_not_below = format!("{entrypoint}_mode_not_below");
        let error_id = Self::error_id();
        let read_u128 = triton_asm!(addi 3 read_mem 4 pop 1);

        triton_asm!(
            {entrypoint}:
                // _ *removal_records *chunk_indices [window_start]
                push {window_start_alloc.write_address()} write_mem 4 pop 1
                dup 0 push {chunk_indices_alloc.write_address()} write_mem 1 pop 1
                read_mem 1 pop 1
                // _ *removal_records num_chunks

                // One page holds the pointer list and, after it, every
                // chunk's sorted list with its taken flags.
                call {dyn_malloc}
                dup 1 dup 1 write_mem 1 pop 1
                dup 0 push {insertions_alloc.write_address()} write_mem 1 pop 1
                dup 0 dup 2 add addi 1
                push 0 push 0
                // _ *removal_records num_chunks *insertions *free 0 0

                call {chunks_loop}
                // _ *removal_records num_chunks *insertions *free total num_chunks

                pop 1 push {total_alloc.write_address()} write_mem 1 pop 1
                pop 3
                push 0 swap 1
                // _ 0 *removal_records

                read_mem 1 addi 2 place 1 push 0
                // _ consumed *record[0]_si num_records 0

                call {records_loop}
                pop 3
                // _ consumed

                push {total_alloc.read_address()} read_mem 1 pop 1
                eq assert error_id {error_id}
                push {insertions_alloc.read_address()} read_mem 1 pop 1
                // _ *insertions

                return

            // Reads each chunk's sorted list into the page's free words, and
            // reserves as many words again after it for its taken flags,
            // which start out zero.
            // INVARIANT: _ num_chunks *insertions *free total j
            {chunks_loop}:
                dup 4 dup 1 eq skiz return
                divine 1
                // Crashes unless the length is a u32.
                dup 0 pop_count pop 1
                // _ num_chunks *insertions *free total j length

                dup 0 dup 4 write_mem 1 pop 1
                dup 3 dup 5 dup 3 add addi 1 write_mem 1 pop 1
                // _ num_chunks *insertions *free total j length

                dup 3 dup 0 addi 1 push 0 push 0
                // _ num_chunks *insertions *free total j length *sorted *sorted[0] 0 0

                call {read_loop}
                pop 4
                // _ num_chunks *insertions *free total j length

                dup 0 push 2 mul addi 1 dup 4 add
                place 4 pick 3 pop 1
                // _ num_chunks *insertions *free' total j length

                pick 2 add place 1
                addi 1
                // _ num_chunks *insertions *free' (total + length) (j + 1)

                recurse

            // Reads a sorted list: each entry is at least the previous one
            // and inside the chunk.
            // INVARIANT: _ length *sorted *sorted[i] previous i
            {read_loop}:
                dup 4 dup 1 eq skiz return
                divine 1
                // _ length *sorted *sorted[i] previous i entry

                dup 2 dup 1 lt push 0 eq assert error_id {error_id}
                push {CHUNK_SIZE} dup 1 lt assert error_id {error_id}
                dup 0 pick 4 write_mem 1 place 3
                // _ length *sorted *sorted[i + 1] previous i entry

                place 2 pick 1 pop 1 addi 1
                // _ length *sorted *sorted[i + 1] entry (i + 1)

                recurse

            // INVARIANT: _ consumed *record[i]_si num_records i
            {records_loop}:
                dup 1 dup 1 eq skiz return
                dup 2 addi 1 {&field!(RemovalRecord::absolute_indices)}
                // _ *record[i]_si num_records i *index_set

                dup 0 {&field!(AbsoluteIndexSet::minimum)} {&read_u128}
                push {window_start_alloc.read_address()} read_mem 4 pop 1
                dup 7 dup 7 dup 7 dup 7
                call {u128_lt}
                // _ *record[i]_si num_records i *index_set [minimum] (minimum < window_start)

                dup 0 skiz call {mode_below}
                push 0 eq skiz call {mode_not_below}
                // _ *record[i]_si num_records i *index_set offset chunk_hi chunk_lo all bound

                push {bound_address} write_mem 5 pop 1
                {&field!(AbsoluteIndexSet::distances)} push 0
                // _ *record[i]_si num_records i *distances[0] 0

                call {indices_loop}
                pop 2
                // _ *record[i]_si num_records i

                pick 2 read_mem 1
                // _ num_records i record_size (*record[i]_si - 1)

                // Crashes unless the size is a u32.
                dup 1 pop_count pop 1

                addi 2 add place 2 addi 1
                // _ *record[i + 1]_si num_records (i + 1)

                recurse

            // A minimum below the window start lies below 2^76: its chunk
            // index is a u64. The window start is at least a limb beyond it
            // if the difference's higher limbs are not all zero.
            // BEFORE: _ [minimum] 1
            // AFTER:  _ offset chunk_hi chunk_lo all bound 1
            {mode_below}:
                pop 1
                // _ m3 m2 m1 m0

                dup 0 push {CHUNK_SIZE} swap 1 div_mod
                // _ m3 m2 m1 m0 q0 offset

                place 5
                dup 2 push {CHUNK_SIZE} swap 1 div_mod
                // _ offset m3 m2 m1 m0 q0 q1 r1

                push {chunks_per_limb} mul pick 2 add
                // _ offset m3 m2 m1 m0 q1 chunk_lo

                place 5
                dup 3 push {chunks_per_limb} mul add
                // _ offset chunk_lo m3 m2 m1 m0 chunk_hi

                place 5
                push {window_start_alloc.read_address()} read_mem 4 pop 1
                call {u128_sub}
                // _ offset chunk_hi chunk_lo d3 d2 d1 d0

                place 3 add add push 0 eq push 0 eq
                // _ offset chunk_hi chunk_lo d0 all

                dup 0 push -1 mul addi 1 pick 2 mul
                // _ offset chunk_hi chunk_lo all bound

                push 1
                return

            // A record whose minimum is not below the window start has no
            // index below it.
            // BEFORE: _ [minimum]
            // AFTER:  _ 0 0 0 0 0
            {mode_not_below}:
                pop 4 push 0 push 0 push 0 push 0 push 0
                return

            // INVARIANT: _ consumed *record_si num_records i *distances[k] k
            {indices_loop}:
                dup 0 push {NUM_TRIALS} eq skiz return
                dup 1 read_mem 1 pop 1
                // _ *distances[k] k distance

                push {all_address} read_mem 2 pop 1
                dup 2 lt add
                // _ *distances[k] k distance (distance < window_start - minimum)

                skiz call {process_index}
                pop 1
                // _ *distances[k] k

                pick 1 addi 1 place 1 addi 1
                // _ *distances[k + 1] (k + 1)

                recurse

            // An index below the window start: its divined chunk position
            // and slot must hold it, and the slot must be free. Counts it.
            // BEFORE: _ consumed *record_si num_records i *distances[k] k distance
            // AFTER:  _ (consumed + 1) *record_si num_records i *distances[k] k distance
            {process_index}:
                divine 2
                // _ distance j s

                push {offset_address} read_mem 3 pop 1
                // _ distance j s offset chunk_hi chunk_lo

                pick 2 dup 5 add push {CHUNK_SIZE} swap 1 div_mod
                // _ distance j s chunk_hi chunk_lo chunks_past relative_index

                place 3 add split place 2 add swap 1
                // _ distance j s relative_index [chunk_index]

                push {chunk_indices_alloc.read_address()} read_mem 1 pop 1
                dup 0 read_mem 1 pop 1 dup 6 lt assert error_id {error_id}
                // _ distance j s relative_index [chunk_index] *chunk_indices

                dup 5 push 2 mul add addi 2 read_mem 2 pop 1
                // _ distance j s relative_index [chunk_index] [listed_chunk_index]

                {&DataType::U64.compare()} assert error_id {error_id}
                // _ distance j s relative_index

                push {insertions_alloc.read_address()} read_mem 1 pop 1
                dup 3 add addi 1 read_mem 1 pop 1
                // _ distance j s relative_index *sorted

                dup 0 read_mem 1 pop 1 dup 3 lt assert error_id {error_id}
                dup 0 dup 3 add addi 1 read_mem 1 pop 1
                pick 2 eq assert error_id {error_id}
                // _ distance j s *sorted

                dup 0 read_mem 1 pop 1 add addi 1 dup 1 add
                // _ distance j s *taken[s]

                dup 0 read_mem 1 pop 1 push 0 eq assert error_id {error_id}
                push 1 swap 1 write_mem 1 pop 1
                pop 1
                // _ distance j

                pick 7 addi 1 place 7
                pop 1
                // _ distance

                return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;

    use neptune_mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
    use neptune_mutator_set::shared::WINDOW_SIZE;
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::triton_vm::isa::instruction::AssertionError;
    use tasm_lib::triton_vm::isa::instruction::InstructionError;
    use tasm_lib::triton_vm::vm::VMState;

    use super::*;

    const RECORDS_POINTER: BFieldElement = BFieldElement::new(1 << 20);
    const CHUNK_INDICES_POINTER: BFieldElement = BFieldElement::new(1 << 24);

    /// A record whose indices are the minimum plus random distances.
    fn record(rng: &mut StdRng, minimum: u128) -> RemovalRecord {
        let indices =
            core::array::from_fn(|_| minimum + u128::from(rng.random_range(0..WINDOW_SIZE)));
        RemovalRecord {
            absolute_indices: AbsoluteIndexSet::new(indices),
            target_chunks: ChunkDictionary::default(),
        }
    }

    /// The chunk indices the records' indices below the window start need.
    fn chunk_indices(records: &[RemovalRecord], window_start: u128) -> Vec<u64> {
        let mut chunk_indices = ChunkInsertions::indices_below(records, window_start)
            .into_iter()
            .map(ChunkInsertions::chunk_index_of)
            .collect::<Vec<_>>();
        chunk_indices.sort_unstable();
        chunk_indices.dedup();
        chunk_indices
    }

    fn run(
        records: &[RemovalRecord],
        chunk_indices: &[u64],
        window_start: u128,
        tokens: Vec<BFieldElement>,
    ) -> Result<Vec<Vec<u32>>, InstructionError> {
        let mut library = Library::new();
        let snippet = library.import(Box::new(ChunkInsertions));
        let push_window_start = window_start
            .encode()
            .into_iter()
            .rev()
            .flat_map(|limb| triton_asm!(push { limb }))
            .collect::<Vec<_>>();
        let program = Program::new(&triton_asm!(
            push {RECORDS_POINTER}
            push {CHUNK_INDICES_POINTER}
            {&push_window_start}
            call {snippet}
            halt
            {&library.all_imports()}
        ));

        let mut ram = HashMap::new();
        encode_to_memory(&mut ram, RECORDS_POINTER, &records.to_vec());
        encode_to_memory(&mut ram, CHUNK_INDICES_POINTER, &chunk_indices.to_vec());
        let nondeterminism = NonDeterminism::new(tokens).with_ram(ram);
        let mut state = VMState::new(program, PublicInput::default(), nondeterminism);
        state.run()?;

        let read = |pointer: BFieldElement| {
            let length = state.ram[&pointer].value();
            (0..length)
                .map(|i| state.ram[&(pointer + bfe!(1 + i))])
                .collect::<Vec<_>>()
        };
        let insertions = read(*state.op_stack.stack.last().unwrap());
        Ok(insertions
            .into_iter()
            .map(|pointer| {
                read(pointer)
                    .into_iter()
                    .map(|entry| u32::try_from(entry.value()).unwrap())
                    .collect()
            })
            .collect())
    }

    fn assert_agrees(records: &[RemovalRecord], window_start: u128) {
        let chunk_indices = chunk_indices(records, window_start);
        let tokens = ChunkInsertions::divined_tokens(records, &chunk_indices, window_start);
        let expected = ChunkInsertions::insertions(records, &chunk_indices, window_start);
        assert_eq!(
            expected,
            run(records, &chunk_indices, window_start, tokens).unwrap()
        );
    }

    fn assert_rejects(
        records: &[RemovalRecord],
        chunk_indices: &[u64],
        tokens: Vec<BFieldElement>,
    ) {
        let window_start = 1 << 40;
        let Err(InstructionError::AssertionFailed(AssertionError { id, .. })) =
            run(records, chunk_indices, window_start, tokens)
        else {
            panic!("must fail");
        };
        assert_eq!(Some(ChunkInsertions::error_id()), id);
    }

    #[test]
    fn insertions_agree_with_the_native_computation() {
        let mut rng = StdRng::seed_from_u64(0);
        let window_start = 1 << 40;
        for num_records in [0, 1, 2, 5] {
            let records = (0..num_records)
                .map(|_| {
                    let minimum = rng.random_range(0..window_start + u128::from(WINDOW_SIZE));
                    record(&mut rng, minimum)
                })
                .collect::<Vec<_>>();
            assert_agrees(&records, window_start);
        }
    }

    #[test]
    fn records_sharing_chunks_and_indices_agree() {
        let mut rng = StdRng::seed_from_u64(1);
        let window_start = 1 << 40;
        let shared = record(&mut rng, window_start - u128::from(WINDOW_SIZE));
        let records = vec![
            shared.clone(),
            record(&mut rng, window_start - 5000),
            shared,
        ];
        assert_agrees(&records, window_start);
    }

    /// A record whose minimum is exactly the given index.
    fn record_from(rng: &mut StdRng, minimum: u128) -> RemovalRecord {
        let mut record = record(rng, minimum);
        let mut indices = record.absolute_indices.to_array();
        indices[0] = minimum;
        record.absolute_indices = AbsoluteIndexSet::new(indices);
        record
    }

    #[test]
    fn records_below_window_starts_beyond_a_limb_agree() {
        let mut rng = StdRng::seed_from_u64(11);
        let largest_window_start = u128::from(u64::MAX) << CHUNK_SIZE.ilog2();
        for window_start in [1 << 44, 1 << 70, 1 << 75, largest_window_start] {
            let records = vec![
                record(&mut rng, window_start - u128::from(WINDOW_SIZE)),
                record(&mut rng, window_start - u128::from(2 * WINDOW_SIZE)),
                record(&mut rng, window_start - 1 - u128::from(u32::MAX)),
            ];
            assert_agrees(&records, window_start);
        }
    }

    #[test]
    fn minimums_at_the_edges_of_the_window_start_agree() {
        let mut rng = StdRng::seed_from_u64(12);
        let window_start = 1 << 40;
        for distance in [1, 2, u128::from(WINDOW_SIZE) - 1, u128::from(WINDOW_SIZE)] {
            let records = vec![record_from(&mut rng, window_start - distance)];
            assert_agrees(&records, window_start);
        }
        for distance in [1 << 32, (1 << 32) - 5, (1 << 32) + 5, 1 << 33] {
            let records = vec![record_from(&mut rng, window_start - distance)];
            let chunk_indices = chunk_indices(&records, window_start);
            assert_eq!(
                NUM_TRIALS as usize,
                ChunkInsertions::insertions(&records, &chunk_indices, window_start)
                    .iter()
                    .map(Vec::len)
                    .sum::<usize>()
            );
            assert_agrees(&records, window_start);
        }
    }

    /// A record with exactly these indices.
    fn record_with(indices: [u128; NUM_TRIALS as usize]) -> RemovalRecord {
        RemovalRecord {
            absolute_indices: AbsoluteIndexSet::new(indices),
            target_chunks: ChunkDictionary::default(),
        }
    }

    /// Indices around a chunk boundary: the last of a chunk, the first of
    /// the next, and the same a chunk further, with the minimum a chunk
    /// below. Boundaries at limb edges cross a limb of the index, of the
    /// chunk index, or both.
    fn indices_around(boundary: u128) -> [u128; NUM_TRIALS as usize] {
        let chunk_size = u128::from(CHUNK_SIZE);
        let mut indices = [boundary - 1; NUM_TRIALS as usize];
        indices[1] = boundary;
        indices[2] = boundary + chunk_size - 1;
        indices[3] = boundary + chunk_size;
        indices[4] = boundary - chunk_size;
        for (i, index) in indices.iter_mut().enumerate().skip(5) {
            *index = boundary - chunk_size + (i as u128 * 97) % (3 * chunk_size);
        }
        indices
    }

    #[test]
    fn indices_at_chunk_boundaries_go_to_their_own_chunks() {
        let chunk_size = u128::from(CHUNK_SIZE);
        for window_start in [1_u128 << 40, 1 << 70] {
            for boundary in [
                3 * chunk_size,
                window_start - 3 * chunk_size,
                1 << 32,
                1 << 44,
                1 << 64,
            ] {
                if boundary + 2 * chunk_size > window_start {
                    continue;
                }
                let records = vec![record_with(indices_around(boundary))];
                let chunk_indices = chunk_indices(&records, window_start);
                assert!(chunk_indices.len() >= 3, "boundary {boundary}");
                assert_agrees(&records, window_start);
            }
        }
    }

    /// Indices around the window start: the one just below it goes into
    /// the last chunk, the one at it and above go nowhere.
    fn indices_around_the_window_start(window_start: u128) -> [u128; NUM_TRIALS as usize] {
        let chunk_size = u128::from(CHUNK_SIZE);
        let mut indices = [window_start - 1; NUM_TRIALS as usize];
        indices[1] = window_start;
        indices[2] = window_start + 1;
        indices[3] = window_start - 2;
        indices[4] = window_start - chunk_size;
        for (i, index) in indices.iter_mut().enumerate().skip(5) {
            *index = window_start - chunk_size + (i as u128 * 97) % (2 * chunk_size);
        }
        indices
    }

    #[test]
    fn indices_at_the_window_start_are_split_between_chunks_and_window() {
        let chunk_size = u128::from(CHUNK_SIZE);
        for window_start in [2 * chunk_size, 1 << 40, 1 << 70] {
            let straddling = record_with(indices_around_the_window_start(window_start));
            let mut above = indices_around_the_window_start(window_start + chunk_size);
            above[3] = window_start;
            above[4] = window_start;
            let all_above = record_with(above);
            let mut one_below = [window_start; NUM_TRIALS as usize];
            one_below[0] = window_start - 1;
            let one_below = record_with(one_below);
            let records = vec![straddling, all_above, one_below];

            let chunk_indices = chunk_indices(&records, window_start);
            assert_eq!(
                vec![(window_start >> CHUNK_SIZE.ilog2()) as u64 - 1],
                chunk_indices,
                "only the chunk below the window start is needed"
            );
            let insertions = ChunkInsertions::insertions(&records, &chunk_indices, window_start);
            assert_eq!(
                2,
                insertions[0]
                    .iter()
                    .filter(|&&i| i == CHUNK_SIZE - 1)
                    .count()
            );
            assert_agrees(&records, window_start);
        }
    }

    #[test]
    fn index_assigned_to_a_neighbouring_chunk_fails() {
        let (records, chunk_indices, tokens) = record_below_the_window(13);
        let first_pair = num_list_tokens(&records, &chunk_indices);
        let honest_position = tokens[first_pair].value();
        let mut checked = 0;
        for other in [honest_position + 1, honest_position.wrapping_sub(1)] {
            if other >= chunk_indices.len() as u64 {
                continue;
            }
            let mut tampered = tokens.clone();
            tampered[first_pair] = bfe!(other);
            assert_rejects(&records, &chunk_indices, tampered);
            checked += 1;
        }
        assert!(checked > 0);
    }

    #[test]
    fn records_around_the_window_start_agree() {
        let mut rng = StdRng::seed_from_u64(2);
        for window_start in [0, u128::from(CHUNK_SIZE), 1 << 40] {
            let records = vec![
                record(
                    &mut rng,
                    window_start.saturating_sub(u128::from(WINDOW_SIZE) / 2),
                ),
                record(&mut rng, window_start),
            ];
            assert_agrees(&records, window_start);
        }
    }

    /// A record entirely below the window start, spread over several
    /// chunks, with its chunk indices and honest tokens.
    fn record_below_the_window(seed: u64) -> (Vec<RemovalRecord>, Vec<u64>, Vec<BFieldElement>) {
        let mut rng = StdRng::seed_from_u64(seed);
        let window_start = 1 << 40;
        let records = vec![record(&mut rng, window_start - 2 * u128::from(WINDOW_SIZE))];
        let chunk_indices = chunk_indices(&records, window_start);
        assert!(chunk_indices.len() > 1);
        let tokens = ChunkInsertions::divined_tokens(&records, &chunk_indices, window_start);
        (records, chunk_indices, tokens)
    }

    #[test]
    fn wrong_slot_fails() {
        let (records, chunk_indices, mut tokens) = record_below_the_window(3);
        let last_slot = tokens.last_mut().unwrap();
        *last_slot += bfe!(1);
        assert_rejects(&records, &chunk_indices, tokens);
    }

    #[test]
    fn extra_entry_in_a_list_fails() {
        let (records, chunk_indices, mut tokens) = record_below_the_window(4);
        tokens[0] += bfe!(1);
        tokens.insert(1, bfe!(0));
        assert_rejects(&records, &chunk_indices, tokens);
    }

    #[test]
    fn missing_chunk_fails() {
        let (records, chunk_indices, tokens) = record_below_the_window(5);
        assert_rejects(&records, &chunk_indices[1..], tokens);
    }

    /// The number of tokens holding the lists: the position pairs follow.
    fn num_list_tokens(records: &[RemovalRecord], chunk_indices: &[u64]) -> usize {
        ChunkInsertions::insertions(records, chunk_indices, 1 << 40)
            .iter()
            .map(|insertion| insertion.len() + 1)
            .sum()
    }

    #[test]
    fn slot_at_the_list_length_fails() {
        let (records, chunk_indices, mut tokens) = record_below_the_window(6);
        let insertions = ChunkInsertions::insertions(&records, &chunk_indices, 1 << 40);
        let first_pair = num_list_tokens(&records, &chunk_indices);
        let chunk_position = tokens[first_pair].value() as usize;
        tokens[first_pair + 1] = bfe!(insertions[chunk_position].len() as u64);
        assert_rejects(&records, &chunk_indices, tokens);
    }

    #[test]
    fn slot_reused_by_an_equal_index_fails() {
        let mut rng = StdRng::seed_from_u64(7);
        let window_start = 1 << 40;
        let shared = record(&mut rng, window_start - u128::from(WINDOW_SIZE));
        let records = vec![shared.clone(), shared];
        let chunk_indices = chunk_indices(&records, window_start);
        let mut tokens = ChunkInsertions::divined_tokens(&records, &chunk_indices, window_start);
        let first_pair = num_list_tokens(&records, &chunk_indices);
        let same_index_again = first_pair + 2 * NUM_TRIALS as usize;
        assert_eq!(tokens[first_pair], tokens[same_index_again]);
        assert_eq!(
            tokens[first_pair + 1] + bfe!(1),
            tokens[same_index_again + 1]
        );

        tokens[same_index_again + 1] = tokens[first_pair + 1];
        assert_rejects(&records, &chunk_indices, tokens);
    }

    #[test]
    fn entry_outside_the_chunk_fails() {
        let (records, chunk_indices, mut tokens) = record_below_the_window(8);
        assert_ne!(bfe!(0), tokens[0]);
        tokens[1] = bfe!(CHUNK_SIZE);
        assert_rejects(&records, &chunk_indices, tokens);
    }

    #[test]
    fn entries_out_of_order_fails() {
        let mut rng = StdRng::seed_from_u64(9);
        let window_start = 1 << 40;
        let shared = record(&mut rng, window_start - u128::from(WINDOW_SIZE));
        let records = vec![shared.clone(), shared];
        let chunk_indices = chunk_indices(&records, window_start);
        let mut tokens = ChunkInsertions::divined_tokens(&records, &chunk_indices, window_start);
        assert_eq!(tokens[1], tokens[2]);
        assert_ne!(bfe!(CHUNK_SIZE - 1), tokens[1]);
        tokens[1] += bfe!(1);
        assert_rejects(&records, &chunk_indices, tokens);
    }

    #[test]
    fn index_not_yet_consumed_fails() {
        let (records, chunk_indices, mut tokens) = record_below_the_window(10);
        let first_pair = num_list_tokens(&records, &chunk_indices);
        tokens.truncate(first_pair);
        let window_start = 1 << 40;
        assert!(run(&records, &chunk_indices, window_start, tokens).is_err());
    }
}
