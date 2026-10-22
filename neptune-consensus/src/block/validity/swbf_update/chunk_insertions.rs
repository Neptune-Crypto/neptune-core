//! Rule 2.b's chunks and the insertion lists of rule 2.e in one pass over
//! the records' indices: each index of each record that lies in the
//! inactive SWBF resolves to its chunk in the witness's list, and takes its
//! place in the chunk's sorted list of insertions.

use std::collections::HashMap;

use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_mutator_set::shared::CHUNK_SIZE;
use neptune_mutator_set::shared::NUM_TRIALS;
use neptune_mutator_set::shared::WINDOW_SIZE;
use tasm_lib::arithmetic::u128::lt::Lt as U128Lt;
use tasm_lib::arithmetic::u128::shift_left_static::ShiftLeftStatic;
use tasm_lib::arithmetic::u128::sub::Sub as U128Sub;
use tasm_lib::field;
use tasm_lib::memory::dyn_malloc::DynMalloc;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use crate::block::block_validation_error::BlockValidationRule;

/// Resolves every absolute index of every removal record that lies in the
/// inactive part of the sliding-window Bloom filter to its chunk, as the
/// archival validity check demands, and collects, for each chunk, the
/// indices the records set in it, relative to the chunk's start, as a
/// sorted list.
///
/// ```text
/// BEFORE: _ *removal_records *chunk_indices [swbfi_leaf_count: u64]
/// AFTER:  _ *insertions
/// ```
///
/// `*chunk_indices` lists the chunks' indices in ascending order, and
/// `*insertions` lists a pointer to the sorted list for each of them in the
/// same order. The lists hold exactly the records' indices below the
/// window start, each in the chunk it lies in, with repetitions. A chunk
/// no index lies in gets an empty list.
///
/// The prover supplies each list's length and entries, then for every index
/// below the window start, in the order of the records and of their
/// indices, the position of its chunk among the chunk indices and its
/// position in that chunk's list. Each list position must hold that index
/// and may be pointed at once, and every position must be pointed at.
///
/// Crashes with the error ID of rule 2.b if an index has no chunk at the
/// divined position, and with the error ID of rule 2.e if the prover's
/// lists are not the sorted lists of the indices per chunk.
#[derive(Debug, Copy, Clone)]
pub(super) struct ChunkInsertions;

impl ChunkInsertions {
    const LOG2_CHUNK_SIZE: u8 = CHUNK_SIZE.ilog2() as u8;

    fn no_chunk_error_id() -> i128 {
        BlockValidationRule::RemovalRecordsValidity.error_id()
    }

    fn lists_error_id() -> i128 {
        BlockValidationRule::MutatorSetUpdateIntegrity.error_id()
    }

    /// The first absolute index of the active window for this many leafs in
    /// the inactive SWBF.
    fn window_start(swbfi_leaf_count: u64) -> u128 {
        u128::from(swbfi_leaf_count) << Self::LOG2_CHUNK_SIZE
    }

    fn chunk_index_of(index: u128) -> u64 {
        u64::try_from(index >> Self::LOG2_CHUNK_SIZE).expect("index below window start fits")
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

    /// The distinct chunk indices of the indices below the window start,
    /// ascending: the chunks an honest witness carries.
    pub(crate) fn chunk_indices_below(
        removal_records: &[RemovalRecord],
        swbfi_leaf_count: u64,
    ) -> Vec<u64> {
        let mut chunk_indices =
            Self::indices_below(removal_records, Self::window_start(swbfi_leaf_count))
                .into_iter()
                .map(Self::chunk_index_of)
                .collect::<Vec<_>>();
        chunk_indices.sort_unstable();
        chunk_indices.dedup();
        chunk_indices
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

    /// The tokens the prover supplies: each chunk's list, then for each
    /// index below the window start the position of its chunk and its list
    /// position. An index whose chunk is missing gets the position where
    /// the chunk would be, which the snippet then rejects.
    pub(crate) fn divined_tokens(
        removal_records: &[RemovalRecord],
        chunk_indices: &[u64],
        swbfi_leaf_count: u64,
    ) -> Vec<BFieldElement> {
        let window_start = Self::window_start(swbfi_leaf_count);
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
                let chunk_index = Self::chunk_index_of(index);
                let chunk_position = chunk_indices
                    .binary_search(&chunk_index)
                    .unwrap_or_else(|insertion_point| insertion_point);
                let relative_index = Self::relative_index_of(index);
                let slot = next_slot_of
                    .entry((chunk_position, relative_index))
                    .or_insert_with(|| {
                        insertions.get(chunk_position).map_or(0, |list| {
                            list.partition_point(|&entry| entry < relative_index)
                        })
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
            (DataType::U64, "swbfi_leaf_count".to_string()),
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
        type Alloc = tasm_lib::library::StaticAllocation;

        let dyn_malloc = library.import(Box::new(DynMalloc));
        let u128_lt = library.import(Box::new(U128Lt));
        let u128_sub = library.import(Box::new(U128Sub));
        let to_window_start =
            library.import(Box::new(ShiftLeftStatic::<{ Self::LOG2_CHUNK_SIZE }>));

        // The chunk indices and their number, the insertion lists and the
        // number of their entries.
        let chunk_indices_alloc = library.kmalloc(1);
        let num_chunks_alloc = library.kmalloc(1);
        let insertions_alloc = library.kmalloc(1);
        let total_alloc = library.kmalloc(1);
        let window_start_alloc = library.kmalloc(4);
        // The record at hand: whether all of its indices lie below the
        // window start, none do, or those at a distance to the minimum
        // below a bound do; and the minimum's chunk index and offset in its
        // chunk, which locate the others.
        let mode_alloc = library.kmalloc(2);
        // The minimum's chunk index, low limb then high, and its offset in
        // its chunk.
        let base_alloc = library.kmalloc(3);

        let entrypoint = self.entrypoint();
        let chunks_loop = format!("{entrypoint}_chunks_loop");
        let read_loop = format!("{entrypoint}_read_loop");
        let records_loop = format!("{entrypoint}_records_loop");
        let indices_loop = format!("{entrypoint}_indices_loop");
        let resolve = format!("{entrypoint}_resolve");
        let mode_below = format!("{entrypoint}_mode_below");
        let mode_not_below = format!("{entrypoint}_mode_not_below");

        let chunk_size = CHUNK_SIZE;
        let chunks_per_limb = 1_u64 << (32 - Self::LOG2_CHUNK_SIZE);
        let no_chunk = Self::no_chunk_error_id();
        let lists_error = Self::lists_error_id();

        let read_word = |alloc: &Alloc| triton_asm!(push {alloc.read_address()} read_mem 1 pop 1);
        let write_word =
            |alloc: &Alloc| triton_asm!(push {alloc.write_address()} write_mem 1 pop 1);
        let read_u128 = |alloc: &Alloc| triton_asm!(push {alloc.read_address()} read_mem 4 pop 1);
        let write_u128 =
            |alloc: &Alloc| triton_asm!(push {alloc.write_address()} write_mem 4 pop 1);

        // Whether an index of the record, given by its distance to the
        // record's minimum, lies below the window start, by the record's
        // mode.
        // BEFORE: _ ... distance
        // AFTER:  _ ... distance is_below
        let is_below = triton_asm!(
            push {mode_alloc.write_address()} read_mem 1 pop 1
            dup 1 lt
            push {mode_alloc.read_address()} read_mem 1 pop 1
            add
        );

        // The record's mode, from the window start and the record's
        // minimum, written to the mode.
        // BEFORE: _ *minimum
        // AFTER:  _ *minimum
        let record_mode = triton_asm!(
            dup 0 addi 3 read_mem 4 pop 1
            {&read_u128(&window_start_alloc)}
            dup 3 dup 3 dup 3 dup 3
            dup 11 dup 11 dup 11 dup 11
            call {u128_lt}
            // _ *minimum [minimum] [window_start] (minimum < window_start)

            dup 0 skiz call {mode_below}
            push 0 eq skiz call {mode_not_below}
            // _ *minimum bound all

            swap 1 push {mode_alloc.write_address()} write_mem 2 pop 1
        );

        triton_asm!(
            {entrypoint}:
                // _ *removal_records *chunk_indices [leaf_count]
                push 0 push 0 pick 3 pick 3 call {to_window_start}
                {&write_u128(&window_start_alloc)}
                // _ *removal_records *chunk_indices

                dup 0 {&write_word(&chunk_indices_alloc)}
                read_mem 1 pop 1
                dup 0 {&write_word(&num_chunks_alloc)}
                // _ *removal_records num_chunks

                // One page holds the pointer list and, after it, every
                // chunk's sorted list with its taken flags.
                call {dyn_malloc}
                dup 1 dup 1 write_mem 1 pop 1
                dup 0 {&write_word(&insertions_alloc)}
                dup 0 dup 2 add addi 1
                push 0 push 0
                // _ *removal_records num_chunks *insertions *free 0 0

                call {chunks_loop}
                // _ *removal_records num_chunks *insertions *free total num_chunks

                pop 1 {&write_word(&total_alloc)}
                pop 3
                push 0 swap 1
                // _ 0 *removal_records

                read_mem 1 addi 2 place 1 push 0
                // _ consumed *record[0]_si num_records 0

                call {records_loop}
                pop 3
                // _ consumed

                {&read_word(&total_alloc)}
                eq assert error_id {lists_error}
                {&read_word(&insertions_alloc)}
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

                dup 2 dup 1 lt push 0 eq assert error_id {lists_error}
                push {chunk_size} dup 1 lt assert error_id {lists_error}
                dup 0 pick 4 write_mem 1 place 3
                // _ length *sorted *sorted[i + 1] previous i entry

                place 2 pick 1 pop 1 addi 1
                // _ length *sorted *sorted[i + 1] entry (i + 1)

                recurse

            // INVARIANT: _ consumed *record[i]_si num_records i
            {records_loop}:
                dup 1 dup 1 eq skiz return
                dup 2 addi 1
                {&field!(RemovalRecord::absolute_indices)}
                {&field!(AbsoluteIndexSet::minimum)}
                // _ consumed *record[i]_si num_records i *minimum

                {&record_mode}

                // The chunk index of the minimum and the minimum's offset
                // in its chunk. Only meaningful for a minimum below a window
                // start, which then lies far below 2^76.
                dup 0 addi 3 read_mem 4 pop 1
                // _ ... *minimum m3 m2 m1 m0

                push {chunk_size} swap 1 div_mod
                // _ ... *minimum m3 m2 m1 q0 r0

                pick 2 push {chunk_size} swap 1 div_mod
                // _ ... *minimum m3 m2 q0 r0 q1 r1

                push {chunks_per_limb} mul
                pick 3 add
                // _ ... *minimum m3 m2 r0 q1 base_chunk_lo

                pick 3 push {chunk_size} swap 1 div_mod swap 1 pop 1
                push {chunks_per_limb} mul
                pick 2 add
                // _ ... *minimum m3 r0 base_chunk_lo base_chunk_hi

                swap 1
                push {base_alloc.write_address()} write_mem 3 pop 1
                pop 2
                // _ consumed *record[i]_si num_records i

                dup 2 addi 1
                {&field!(RemovalRecord::absolute_indices)}
                {&field!(AbsoluteIndexSet::distances)}
                push 0
                // _ consumed *record[i]_si num_records i *distance[0] 0

                call {indices_loop}
                pop 2
                // _ consumed *record[i]_si num_records i

                pick 2 read_mem 1
                // _ consumed num_records i record_size (*record[i]_si - 1)
                // Crashes unless the size is a u32.
                dup 1 pop_count pop 1
                addi 2 add place 2 addi 1
                // _ consumed *record[i + 1]_si num_records (i + 1)

                recurse

            // Computes the bound and flag of a record whose minimum lies
            // below the window start: all of its indices do if the window
            // start is at least a window beyond the minimum.
            // BEFORE: _ ... *minimum [minimum] [window_start] 1
            // AFTER:  _ ... *minimum bound all 1
            {mode_below}:
                pop 1
                call {u128_sub}
                // _ ... *minimum [window_start - minimum]

                place 3
                // _ ... *minimum d0 d3 d2 d1

                add add push 0 eq push 0 eq
                // _ ... *minimum d0 (higher_limbs != 0)

                dup 1 push {WINDOW_SIZE} swap 1 lt push 0 eq
                add push 0 eq push 0 eq
                // _ ... *minimum d0 all

                dup 0 push -1 mul addi 1 pick 2 mul
                // _ ... *minimum all bound

                swap 1 push 1
                // _ ... *minimum bound all 1

                return

            // A record whose minimum is not below the window start has no
            // index below it.
            // BEFORE: _ ... *minimum [minimum] [window_start]
            // AFTER:  _ ... *minimum 0 0
            {mode_not_below}:
                pop 5 pop 3 push 0 push 0
                return

            // INVARIANT: _ consumed *record_si num_records i *distance[k] k
            {indices_loop}:
                dup 0 push {NUM_TRIALS} eq skiz return
                dup 1 read_mem 1 pop 1
                // _ consumed *record_si num_records i *distance[k] k distance

                {&is_below}
                skiz call {resolve}
                pop 1
                // _ consumed *record_si num_records i *distance[k] k

                pick 1 addi 1 place 1 addi 1
                // _ consumed *record_si num_records i *distance[k + 1] (k + 1)

                recurse

            // Resolves the index to its chunk at the divined position and
            // inserts it at its divined slot in the chunk's list: the slot
            // must hold it and must be free. Counts it.
            // BEFORE: _ consumed *record_si num_records i *distance[k] k distance
            // AFTER:  _ consumed *record_si num_records i *distance[k] k distance
            {resolve}:
                dup 0 push {chunk_size} swap 1 div_mod
                // _ ... distance q r

                {&read_word(&base_alloc)} add
                push {chunk_size} swap 1 div_mod
                // _ ... distance q carry relative_index

                place 2 add
                // _ ... distance relative_index chunks_past_base

                push {base_alloc.write_address() + bfe!(1)} read_mem 2 pop 1
                pick 2 add split place 2 add swap 1
                // _ ... distance relative_index [chunk_index]

                divine 1
                // _ ... distance relative_index [chunk_index] position

                {&read_word(&num_chunks_alloc)}
                dup 1 lt assert error_id {no_chunk}
                {&read_word(&chunk_indices_alloc)}
                dup 1 push 2 mul add addi 2 read_mem 2 pop 1
                // _ ... distance relative_index [chunk_index] position [listed_chunk_index]

                pick 3 eq
                place 2 pick 3 eq
                // _ ... distance relative_index lo_agree position hi_agree

                swap 1 place 2 mul assert error_id {no_chunk}
                // _ ... distance relative_index position

                divine 1
                {&read_word(&insertions_alloc)} dup 2 add addi 1 read_mem 1 pop 1
                // _ ... relative_index position slot *sorted

                dup 0 read_mem 1 pop 1 dup 2 lt assert error_id {lists_error}
                dup 0 dup 2 add addi 1 read_mem 1 pop 1
                dup 4 eq assert error_id {lists_error}
                // _ ... relative_index position slot *sorted

                dup 0 read_mem 1 pop 1 add addi 1 dup 1 add
                // _ ... relative_index position slot *taken[slot]

                dup 0 read_mem 1 pop 1 push 0 eq assert error_id {lists_error}
                push 1 swap 1 write_mem 1 pop 1
                pop 3
                // _ ... distance

                pick 6 addi 1 place 6
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

    /// The leaf count whose window starts at the index.
    fn leaf_count_of(window_start: u128) -> u64 {
        u64::try_from(window_start >> CHUNK_SIZE.ilog2()).unwrap()
    }

    fn run(
        records: &[RemovalRecord],
        chunk_indices: &[u64],
        leaf_count: u64,
        tokens: Vec<BFieldElement>,
    ) -> Result<Vec<Vec<u32>>, InstructionError> {
        let mut library = Library::new();
        let snippet = library.import(Box::new(ChunkInsertions));
        let push_u64 = |value: u64| {
            value
                .encode()
                .into_iter()
                .rev()
                .flat_map(|limb| triton_asm!(push { limb }))
                .collect::<Vec<_>>()
        };
        let program = Program::new(&triton_asm!(
            push {RECORDS_POINTER}
            push {CHUNK_INDICES_POINTER}
            {&push_u64(leaf_count)}
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

    /// The window start at the index.
    fn assert_agrees(records: &[RemovalRecord], window_start: u128) {
        let chunk_indices = chunk_indices(records, window_start);
        let leaf_count = leaf_count_of(window_start);
        let tokens = ChunkInsertions::divined_tokens(records, &chunk_indices, leaf_count);
        let expected = ChunkInsertions::insertions(records, &chunk_indices, window_start);
        assert_eq!(
            expected,
            run(records, &chunk_indices, leaf_count, tokens).unwrap()
        );
    }

    fn assert_rejects_with(
        records: &[RemovalRecord],
        chunk_indices: &[u64],
        leaf_count: u64,
        tokens: Vec<BFieldElement>,
        error_id: i128,
    ) {
        let Err(InstructionError::AssertionFailed(AssertionError { id, .. })) =
            run(records, chunk_indices, leaf_count, tokens)
        else {
            panic!("must fail");
        };
        assert_eq!(Some(error_id), id);
    }

    /// Rejection by the lists' rule, at the window start the fixtures use.
    fn assert_rejects(
        records: &[RemovalRecord],
        chunk_indices: &[u64],
        tokens: Vec<BFieldElement>,
    ) {
        let leaf_count = leaf_count_of(1 << 40);
        assert_rejects_with(
            records,
            chunk_indices,
            leaf_count,
            tokens,
            ChunkInsertions::lists_error_id(),
        );
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
            // The resolution rejects the chunk before the list is read.
            let mut tampered = tokens.clone();
            tampered[first_pair] = bfe!(other);
            let leaf_count = leaf_count_of(1 << 40);
            assert_rejects_with(
                &records,
                &chunk_indices,
                leaf_count,
                tampered,
                ChunkInsertions::no_chunk_error_id(),
            );
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
        let tokens =
            ChunkInsertions::divined_tokens(&records, &chunk_indices, leaf_count_of(window_start));
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
        let leaf_count = leaf_count_of(1 << 40);
        assert_rejects_with(
            &records,
            &chunk_indices[1..],
            leaf_count,
            tokens,
            ChunkInsertions::no_chunk_error_id(),
        );
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
        let mut tokens =
            ChunkInsertions::divined_tokens(&records, &chunk_indices, leaf_count_of(window_start));
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
        let mut tokens =
            ChunkInsertions::divined_tokens(&records, &chunk_indices, leaf_count_of(window_start));
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
        let leaf_count = leaf_count_of(1 << 40);
        assert!(run(&records, &chunk_indices, leaf_count, tokens).is_err());
    }

    /// Records with chunks in the inactive part, their chunk indices, and
    /// the leaf count of the inactive SWBF they lie in.
    fn fixture_with_chunks(seed: u64) -> (Vec<RemovalRecord>, Vec<u64>, u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let leaf_count = 1 << 28;
        let window_start = ChunkInsertions::window_start(leaf_count);
        // Three records well below the window start, and one across it.
        let mut records = (0..3)
            .map(|_| {
                let below = u128::from(rng.random_range(1_u64 << 21..1 << 30));
                record(&mut rng, window_start - below)
            })
            .collect::<Vec<_>>();
        records.push(record(&mut rng, window_start - 1000));
        let chunk_indices = chunk_indices(&records, window_start);
        assert!(!chunk_indices.is_empty(), "fixture must have chunks");
        (records, chunk_indices, leaf_count)
    }

    fn assert_accepts(records: &[RemovalRecord], chunk_indices: &[u64], leaf_count: u64) {
        let tokens = ChunkInsertions::divined_tokens(records, chunk_indices, leaf_count);
        let expected = ChunkInsertions::insertions(
            records,
            chunk_indices,
            ChunkInsertions::window_start(leaf_count),
        );
        assert_eq!(
            expected,
            run(records, chunk_indices, leaf_count, tokens).unwrap()
        );
    }

    fn assert_rejects_rule(
        records: &[RemovalRecord],
        chunk_indices: &[u64],
        leaf_count: u64,
        error_id: i128,
    ) {
        let tokens = ChunkInsertions::divined_tokens(records, chunk_indices, leaf_count);
        assert_rejects_with(records, chunk_indices, leaf_count, tokens, error_id);
    }

    #[test]
    fn missing_chunk_is_rejected_by_the_resolution() {
        let (records, chunk_indices, leaf_count) = fixture_with_chunks(1);
        for position in [0, chunk_indices.len() / 2, chunk_indices.len() - 1] {
            let mut fewer = chunk_indices.clone();
            fewer.remove(position);
            assert_rejects_rule(
                &records,
                &fewer,
                leaf_count,
                ChunkInsertions::no_chunk_error_id(),
            );
        }
        assert_rejects_rule(
            &records,
            &[],
            leaf_count,
            ChunkInsertions::no_chunk_error_id(),
        );
    }

    #[test]
    fn chunk_no_index_lies_in_gets_an_empty_list() {
        let (records, chunk_indices, leaf_count) = fixture_with_chunks(2);
        let unused = chunk_indices.iter().max().unwrap() + 1;
        let mut more = chunk_indices.clone();
        more.push(unused);
        assert_accepts(&records, &more, leaf_count);
    }

    #[test]
    fn chunk_index_off_by_one_is_rejected() {
        let (records, chunk_indices, leaf_count) = fixture_with_chunks(3);
        let mut shifted = chunk_indices.clone();
        shifted[0] += 1;
        if shifted.len() > 1 && shifted[0] == shifted[1] {
            return;
        }
        assert_rejects_rule(
            &records,
            &shifted,
            leaf_count,
            ChunkInsertions::no_chunk_error_id(),
        );
    }

    #[test]
    fn empty_list_with_no_chunks_is_accepted() {
        for leaf_count in [0, 1 << 40, 5] {
            assert_accepts(&[], &[], leaf_count);
        }
    }

    #[test]
    fn records_entirely_in_the_active_window_need_no_chunks() {
        let mut rng = StdRng::seed_from_u64(5);
        let records = (0..3).map(|_| record(&mut rng, 0)).collect::<Vec<_>>();
        assert_accepts(&records, &[], 0);
    }
}
