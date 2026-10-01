use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use neptune_mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
use neptune_mutator_set::removal_record::removal_record_list::RemovalRecordList;
use neptune_mutator_set::removal_record::RemovalRecord;
use tasm_lib::arithmetic::u64::add::Add as U64Add;
use tasm_lib::arithmetic::u64::pow2::Pow2 as U64Pow2;
use tasm_lib::field;
use tasm_lib::list::new::New;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use crate::block::block_validation_error::BlockValidationRule;

/// Reads the chunks and the trees' digest lists out of the chunk witness: a
/// packed list of removal records whose chunks are stored unpacked and
/// whose tree entries hold the paths of the tree's chunks, read the way
/// [`RemovalRecordList::try_unpack`] reads a packed list, without unpacking
/// the records.
///
/// The list stores its chunks and one digest list per tree of the inactive
/// SWBF in the chunk dictionaries of its records, as entries of a tree
/// height and a pair of a digest list and a chunk. A height below the
/// offset means both are used; a height offset by
/// [`RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET`] means only the digest
/// list; the delimiter [`RemovalRecordList::ENCODING_DELIMITER_IGNORE_TREE_HEIGHT`]
/// means only the chunk. In the witness's form a tree's digest list holds
/// its chunks' authentication paths back to back; in the packed list's form
/// it holds the tree's authentication structure.
///
/// ```text
/// BEFORE: _ *removal_records
/// AFTER:  _ *chunks *tree_paths [swbfi_leaf_count_estimate: u64]
/// ```
///
/// `*chunks` lists pointers to the chunks, in the order the list stores
/// them, which is ascending chunk index. `*tree_paths` lists pointers to
/// the trees' digest lists in ascending tree height. The heights are those
/// of the trees of an inactive SWBF with the returned leaf count: the list
/// describes the smallest inactive SWBF that explains its chunks, whose
/// trees are those of the true one that the chunks lie in, and the `i`th
/// digest list belongs to the tree of the `i`th lowest set bit.
///
/// Crashes unless the tree heights are strictly increasing.
#[derive(Debug, Copy, Clone)]
pub(super) struct ChunkWitness;

impl ChunkWitness {
    fn tree_heights_error_id() -> i128 {
        BlockValidationRule::RemovalRecordsUnpackFailure.error_id()
    }

    /// The tree heights and chunks the packed list's dictionaries hold, in
    /// order: the height of each tree entry, and whether each entry carries
    /// a chunk. Entries with a height that does not classify are skipped;
    /// the snippet rejects them.
    fn entries(removal_records: &[RemovalRecord]) -> Vec<(Option<u64>, bool)> {
        let offset = RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET;
        removal_records
            .iter()
            .flat_map(|record| record.target_chunks.iter())
            .filter_map(|(tree_height, _)| {
                if *tree_height < 2 * offset {
                    Some((Some(tree_height % offset), *tree_height < offset))
                } else if *tree_height == RemovalRecordList::ENCODING_DELIMITER_IGNORE_TREE_HEIGHT {
                    Some((None, true))
                } else {
                    None
                }
            })
            .collect()
    }

    /// The leaf count of the inactive SWBF the packed list describes: the
    /// sum over its trees.
    pub(crate) fn swbfi_leaf_count_estimate(removal_records: &[RemovalRecord]) -> u64 {
        Self::entries(removal_records)
            .into_iter()
            .filter_map(|(height, _)| height)
            .fold(0, |sum, height| sum.wrapping_add(1 << height.min(63)))
    }

    /// The number of chunks the packed list carries.
    pub(crate) fn num_chunks(removal_records: &[RemovalRecord]) -> usize {
        Self::chunks(removal_records).len()
    }

    /// A packed list with its chunks' contents unpacked, the form a witness
    /// holds; and the inverse.
    pub(super) fn with_unpacked_chunks(
        mut removal_records: Vec<RemovalRecord>,
        allow_big_chunks: bool,
    ) -> Vec<RemovalRecord> {
        for record in &mut removal_records {
            for (_, (_, chunk)) in record.target_chunks.iter_mut() {
                *chunk = chunk
                    .try_unpack(allow_big_chunks)
                    .expect("packed chunk must unpack");
            }
        }
        removal_records
    }

    pub(super) fn with_packed_chunks(
        mut removal_records: Vec<RemovalRecord>,
        allow_big_chunks: bool,
    ) -> Vec<RemovalRecord> {
        for record in &mut removal_records {
            for (_, (_, chunk)) in record.target_chunks.iter_mut() {
                *chunk = chunk.pack(allow_big_chunks);
            }
        }
        removal_records
    }

    /// The digest lists of the tree entries, in their order, which is
    /// ascending tree height: the trees' path lists in the witness's form,
    /// their authentication structures in the packed list's form.
    pub(crate) fn tree_paths(removal_records: &[RemovalRecord]) -> Vec<Vec<Digest>> {
        let offset = RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET;
        removal_records
            .iter()
            .flat_map(|record| record.target_chunks.iter())
            .filter(|(tree_height, _)| *tree_height < 2 * offset)
            .map(|(_, (membership_proof, _))| membership_proof.authentication_path.clone())
            .collect()
    }

    /// Replaces the tree entries' digest lists, in their order.
    pub(super) fn set_tree_paths(
        removal_records: &mut [RemovalRecord],
        tree_paths: Vec<Vec<Digest>>,
    ) {
        let offset = RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET;
        let mut tree_paths = tree_paths.into_iter();
        for record in removal_records {
            for (tree_height, (membership_proof, _)) in record.target_chunks.iter_mut() {
                if *tree_height < 2 * offset {
                    membership_proof.authentication_path =
                        tree_paths.next().expect("one digest list per tree entry");
                }
            }
        }
        assert!(
            tree_paths.next().is_none(),
            "one digest list per tree entry"
        );
    }

    /// The chunks the packed list carries, in its order.
    pub(crate) fn chunks(removal_records: &[RemovalRecord]) -> Vec<Vec<u32>> {
        let offset = RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET;
        removal_records
            .iter()
            .flat_map(|record| record.target_chunks.iter())
            .filter(|(tree_height, _)| {
                *tree_height < offset
                    || *tree_height == RemovalRecordList::ENCODING_DELIMITER_IGNORE_TREE_HEIGHT
            })
            .map(|(_, (_, chunk))| chunk.relative_indices.clone())
            .collect()
    }
}

impl BasicSnippet for ChunkWitness {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "*removal_records".to_string())]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![
            (
                DataType::List(Box::new(DataType::Bfe)),
                "*chunks".to_string(),
            ),
            (
                DataType::List(Box::new(DataType::Bfe)),
                "*tree_paths".to_string(),
            ),
            (DataType::U64, "swbfi_leaf_count_estimate".to_string()),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_chunk_witness".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let new_list = library.import(Box::new(New));
        // Appends the word to the list.
        // BEFORE: _ word *list
        // AFTER:  _
        let append = triton_asm!(
            dup 0 read_mem 1 pop 1
            dup 0 addi 1 dup 2 write_mem 1 pop 1
            add addi 1 write_mem 1 pop 1
        );
        let pow2 = library.import(Box::new(U64Pow2));
        let u64_add = library.import(Box::new(U64Add));

        let entrypoint = self.entrypoint();
        let records_loop = format!("{entrypoint}_records_loop");
        let entries_loop = format!("{entrypoint}_entries_loop");
        let check_entry = format!("{entrypoint}_check_entry");
        let process_entry = format!("{entrypoint}_process_entry");
        let process_tree = format!("{entrypoint}_process_tree");
        let process_chunk = format!("{entrypoint}_process_chunk");

        let offset = RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET;
        let error_id = Self::tree_heights_error_id();

        // The context: the pointers to the two lists, the leaf count the
        // tree heights seen so far add up to, and the height after the last
        // tree's, or zero before any tree.
        let tree_paths_offset = 0;
        let chunks_offset = 1;
        let leaf_count_offset = 2;
        let next_height_offset = 4;
        // Where the current record's dictionary must end.
        let dictionary_end_offset = 5;
        let index_set_size = AbsoluteIndexSet::static_length().expect("index sets are static");

        triton_asm!(
            {entrypoint}:
                // _ *removal_records
                call {new_list}
                call {new_list}
                call {new_list}
                // _ *removal_records *chunks *tree_paths *context

                push 0 push 0 push 0
                pick 5 pick 5 pick 5
                // _ *removal_records 0 0 0 *chunks *tree_paths *context

                write_mem 5 addi -5
                // _ *removal_records *context

                swap 1 read_mem 1 addi 2 place 1 push 0
                // Crashes unless the number of records is a u32.
                dup 1 pop_count pop 1
                // _ *context *record[0]_si num_records 0

                call {records_loop}
                pop 3
                // _ *context

                dup 0 addi {chunks_offset} read_mem 2 pop 1
                // _ *context *chunks *tree_paths

                pick 2 addi {leaf_count_offset + 1} read_mem 2 pop 1
                // _ *chunks *tree_paths [swbfi_leaf_count_estimate]

                return

            // INVARIANT: _ *context *record[i]_si num_records i
            {records_loop}:
                dup 1 dup 1 eq skiz return
                // _ *context *record[i]_si num_records i

                dup 2 addi 1
                {&field!(RemovalRecord::target_chunks)}
                {&field!(ChunkDictionary::dictionary)}
                // _ *context *record[i]_si num_records i *dictionary

                // The dictionary's size says where its entries end, and the
                // record's size holds the dictionary and the index set.
                dup 0 addi -1 read_mem 1 pop 1
                // Crashes unless the dictionary's size is a u32.
                dup 0 pop_count pop 1
                dup 1 dup 1 add dup 6 addi {dictionary_end_offset} write_mem 1 pop 1
                addi {index_set_size + 2} dup 4 read_mem 1 pop 1 eq assert error_id {error_id}
                // _ *context *record[i]_si num_records i *dictionary

                read_mem 1 addi 2 place 1 push 0
                // _ *context *record[i]_si num_records i *entry[0]_si num_entries 0

                call {entries_loop}
                // _ *context *record[i]_si num_records i *entry[end]_si num_entries num_entries

                dup 6 addi {dictionary_end_offset} read_mem 1 pop 1 dup 3 eq assert error_id {error_id}
                pop 3
                // _ *context *record[i]_si num_records i

                pick 2 read_mem 1
                // _ *context num_records i record_size (*record[i]_si - 1)

                // Crashes unless the size is a u32.
                dup 1 pop_count pop 1

                addi 2 add place 2 addi 1
                // _ *context *record[i + 1]_si num_records (i + 1)

                recurse

            // INVARIANT: _ *context *record_si num_records i *entry[j]_si num_entries j
            {entries_loop}:
                dup 1 dup 1 eq skiz return
                // _ *context *record_si num_records i *entry[j]_si num_entries j

                dup 2 addi 1
                call {check_entry}
                // _ ... *entry[j]_si num_entries j *entry

                // The tree height follows the inner pair of digest list and
                // chunk.
                dup 0 read_mem 1 pop 1
                dup 1 add addi 2 read_mem 2 pop 1
                // _ ... *entry[j]_si num_entries j *entry [tree_height]

                call {process_entry}
                pop 1
                // _ ... *entry[j]_si num_entries j

                pick 2 read_mem 1
                // _ ... num_entries j entry_size (*entry[j]_si - 1)

                // Crashes unless the size is a u32.
                dup 1 pop_count pop 1

                addi 2 add place 2 addi 1
                // _ ... *entry[j + 1]_si num_entries (j + 1)

                recurse

            // The entry's sizes: the inner pair holds the chunk's and the
            // digest list's encodings, the entry the pair and the tree height.
            // BEFORE: _ ... *entry[j]_si num_entries j *entry
            // AFTER:  _ ... *entry[j]_si num_entries j *entry
            {check_entry}:
                dup 3 read_mem 1 pop 1
                dup 1 read_mem 1 pop 1
                // _ ... *entry entry_size pair_size

                dup 0 addi 3 pick 2 eq assert error_id {error_id}
                // _ ... *entry pair_size

                dup 1 addi 1 read_mem 1 pop 1
                // Crashes unless the chunk's size is a u32.
                dup 0 pop_count pop 1
                dup 2 addi 2 read_mem 1 pop 1
                // Crashes unless the chunk's length is a u32.
                dup 0 pop_count pop 1
                addi 1 dup 1 eq assert error_id {error_id}
                // _ ... *entry pair_size chunk_size

                dup 2 dup 1 add addi 2 read_mem 1 pop 1
                // Crashes unless the digest list's size is a u32.
                dup 0 pop_count pop 1
                add addi 2 eq assert error_id {error_id}
                // _ ... *entry

                return

            // Classifies the entry by its tree height and handles its parts.
            // BEFORE: _ ... *entry [tree_height]
            // AFTER:  _ ... *entry
            {process_entry}:
                dup 1 push 0 eq
                dup 1 push {2 * offset} swap 1 lt
                mul
                // _ ... *entry [tree_height] is_tree

                dup 2 push {u32::MAX} eq
                dup 2 push {u32::MAX} eq
                mul
                // _ ... *entry [tree_height] is_tree is_chunk_only

                dup 1 dup 1 add assert error_id {error_id}
                // _ ... *entry [tree_height] is_tree is_chunk_only

                swap 1 skiz call {process_tree}
                dup 0 skiz call {process_chunk}
                // _ ... *entry [tree_height] is_chunk_only

                pop 3
                // _ ... *entry

                return

            // Appends the entry's digest list, for a tree
            // higher than the last one, and its chunk if the tree height
            // says so.
            // BEFORE: _ ... *entry tree_height_hi tree_height_lo is_chunk_only
            // AFTER:  _ ... *entry tree_height_hi tree_height_lo is_chunk_only
            {process_tree}:
                dup 1
                dup 0 push {offset} swap 1 lt
                // _ ... *entry [tree_height] is_chunk_only tree_height_lo has_chunk

                dup 0 push {-(offset as i64)} mul addi {offset} push -1 mul
                pick 2 add
                // _ ... *entry [tree_height] is_chunk_only has_chunk height

                // Strictly higher than the last tree.
                dup 12 addi {next_height_offset} read_mem 1 pop 1
                dup 1 lt push 0 eq assert error_id {error_id}
                // _ ... *entry [tree_height] is_chunk_only has_chunk height

                dup 0 addi 1 dup 13 addi {next_height_offset} write_mem 1 pop 1
                // _ ... *entry [tree_height] is_chunk_only has_chunk height

                call {pow2}
                dup 13 addi {leaf_count_offset + 1} read_mem 2 pop 1
                call {u64_add}
                dup 13 addi {leaf_count_offset} write_mem 2 pop 1
                // _ ... *entry [tree_height] is_chunk_only has_chunk

                // The digest list follows the chunk in the inner pair.
                dup 4 addi 1 read_mem 1 pop 1
                dup 5 add addi 4
                // _ ... *entry [tree_height] is_chunk_only has_chunk *tree_paths

                dup 12 addi {tree_paths_offset} read_mem 1 pop 1
                {&append}
                // _ ... *entry [tree_height] is_chunk_only has_chunk

                skiz call {process_chunk}
                // _ ... *entry [tree_height] is_chunk_only

                return

            // Appends the entry's chunk: its list of relative indices, which
            // the word before it precedes with the length of its encoding.
            // BEFORE: _ ... *entry tree_height_hi tree_height_lo is_chunk_only
            // AFTER:  _ ... *entry tree_height_hi tree_height_lo is_chunk_only
            {process_chunk}:
                dup 3 addi 3
                // _ ... *entry [tree_height] is_chunk_only *chunk

                dup 11 addi {chunks_offset} read_mem 1 pop 1
                {&append}
                // _ ... *entry [tree_height] is_chunk_only

                return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) mod tests {
    use std::collections::HashMap;

    use itertools::Itertools;
    use neptune_mutator_set::msa_and_records::MsaAndRecords;
    use neptune_mutator_set::removal_record::chunk::Chunk;
    use neptune_mutator_set::removal_record::removal_record_list::RemovalRecordList;
    use proptest::arbitrary::Arbitrary;
    use proptest::strategy::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::rust_shadowing_helper_functions::dyn_malloc::dynamic_allocator;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::structure::tasm_object::TasmObject;
    use tasm_lib::test_helpers::test_assertion_failure;
    use tasm_lib::test_helpers::test_rust_equivalence_given_execution_state;
    use tasm_lib::traits::procedure::Procedure;
    use tasm_lib::traits::procedure::ProcedureInitialState;
    use tasm_lib::traits::procedure::ShadowedProcedure;
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tasm_lib::traits::rust_shadow::RustShadowError;
    use tasm_lib::triton_vm::isa::instruction::AssertionError;
    use tasm_lib::triton_vm::isa::instruction::InstructionError;
    use tasm_lib::triton_vm::vm::VMState;
    use tasm_lib::twenty_first::prelude::Mmr;
    use tasm_lib::twenty_first::prelude::MmrMembershipProof;

    use super::*;

    pub(in crate::block::validity) const RECORDS_POINTER: BFieldElement =
        BFieldElement::new(1 << 20);

    /// A mutator set accumulator with this many removable items among this
    /// many AOCL leafs, and the records that remove them.
    pub(in crate::block::validity) fn random_msa_and_records(
        rng: &mut StdRng,
        num_records: usize,
        aocl_size: u64,
    ) -> MsaAndRecords {
        let removables = (0..num_records)
            .map(|_| (rng.random(), rng.random(), rng.random()))
            .collect::<Vec<(Digest, Digest, Digest)>>();
        let mut runner = TestRunner::deterministic();
        MsaAndRecords::arbitrary_with((removables, aocl_size))
            .new_tree(&mut runner)
            .unwrap()
            .current()
    }

    /// An entry of a packed chunk dictionary, as the tasm reads it.
    pub(in crate::block::validity) enum PackedEntry {
        Tree {
            height: u32,
            tree_paths: Vec<Digest>,
            chunk: Option<Vec<u32>>,
        },
        ChunkOnly,
    }

    /// The entries of the packed list's chunk dictionaries in order, or the
    /// tree height that does not classify.
    pub(in crate::block::validity) fn packed_entries(
        removal_records: &[RemovalRecord],
    ) -> Result<Vec<PackedEntry>, u64> {
        let offset = RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET;
        let mut entries = vec![];
        for record in removal_records {
            for (tree_height, (proof, chunk)) in record.target_chunks.iter() {
                let entry = if *tree_height < 2 * offset {
                    let has_chunk = *tree_height < offset;
                    PackedEntry::Tree {
                        height: (*tree_height % offset) as u32,
                        tree_paths: proof.authentication_path.clone(),
                        chunk: has_chunk.then(|| chunk.relative_indices.clone()),
                    }
                } else if *tree_height == RemovalRecordList::ENCODING_DELIMITER_IGNORE_TREE_HEIGHT {
                    PackedEntry::ChunkOnly
                } else {
                    return Err(*tree_height);
                };
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    /// The snippet's memory effects and result, as a Rust computation.
    fn mirror(
        removal_records: &[RemovalRecord],
        memory: &mut HashMap<BFieldElement, BFieldElement>,
    ) -> Result<(BFieldElement, BFieldElement, u64), RustShadowError> {
        let fail = || RustShadowError::AssertionError(ChunkWitness::tree_heights_error_id());
        let chunks = dynamic_allocator(memory);
        let tree_paths = dynamic_allocator(memory);
        let context = dynamic_allocator(memory);
        memory.insert(chunks, bfe!(0));
        memory.insert(tree_paths, bfe!(0));
        let write_context = |memory: &mut HashMap<_, _>, leaf_count: u64, next_height: u32| {
            for (i, word) in [
                tree_paths,
                chunks,
                bfe!(leaf_count & u64::from(u32::MAX)),
                bfe!(leaf_count >> 32),
                bfe!(next_height),
            ]
            .into_iter()
            .enumerate()
            {
                memory.insert(context + bfe!(i as u64), word);
            }
        };
        write_context(memory, 0, 0);

        // Where the last record's dictionary ends, as the snippet notes it.
        let mut record_si = RECORDS_POINTER + bfe!(1);
        for record in removal_records {
            let dictionary_end =
                record_si + bfe!(1) + bfe!(record.target_chunks.encode().len() as u64 + 1);
            memory.insert(context + bfe!(5), dictionary_end);
            record_si += bfe!(record.encode().len() as u64 + 1);
        }

        let push = |list: BFieldElement, pointer: BFieldElement, memory: &mut HashMap<_, _>| {
            let length = memory[&list];
            memory.insert(list + bfe!(1) + length, pointer);
            memory.insert(list, length + bfe!(1));
        };
        let mut leaf_count = 0_u64;
        let mut next_height = 0_u32;
        let entries = packed_entries(removal_records).map_err(|_| fail())?;
        let (tree_paths_pointers, chunk_pointers) = entry_pointers(removal_records);
        let mut tree_paths_pointers = tree_paths_pointers.into_iter();
        let mut chunk_pointers = chunk_pointers.into_iter();
        for entry in entries {
            match entry {
                PackedEntry::ChunkOnly => {
                    push(chunks, chunk_pointers.next().unwrap(), memory);
                }
                PackedEntry::Tree {
                    height,
                    tree_paths: _,
                    chunk,
                } => {
                    if height < next_height {
                        return Err(fail());
                    }
                    next_height = height + 1;
                    leaf_count += 1 << height;
                    write_context(memory, leaf_count, next_height);
                    push(tree_paths, tree_paths_pointers.next().unwrap(), memory);
                    if chunk.is_some() {
                        push(chunks, chunk_pointers.next().unwrap(), memory);
                    }
                }
            }
        }
        Ok((chunks, tree_paths, leaf_count))
    }

    /// The pointers to the digest lists of the tree
    /// entries and to the chunk lists of the entries that carry a chunk, in
    /// order, when the records are encoded at the records pointer.
    fn entry_pointers(
        removal_records: &[RemovalRecord],
    ) -> (Vec<BFieldElement>, Vec<BFieldElement>) {
        let offset = RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET;
        let mut tree_paths_pointers = vec![];
        let mut chunk_pointers = vec![];
        let mut record_pointer = RECORDS_POINTER + bfe!(1);
        for record in removal_records {
            // The record starts past its size indicator with its chunk
            // dictionary, which fields encode in reverse: the dictionary's
            // size, its list's size and its length precede the entries.
            let record_start = record_pointer + bfe!(1);
            let mut entry_pointer = record_start + bfe!(3);
            for (tree_height, (proof, chunk)) in record.target_chunks.iter() {
                let entry_start = entry_pointer + bfe!(1);
                let chunk_size = chunk.encode().len() as u64;
                if *tree_height < 2 * offset {
                    tree_paths_pointers.push(entry_start + bfe!(2 + chunk_size + 2));
                }
                if *tree_height < offset
                    || *tree_height == RemovalRecordList::ENCODING_DELIMITER_IGNORE_TREE_HEIGHT
                {
                    chunk_pointers.push(entry_start + bfe!(3));
                }
                let entry_size = (*tree_height, (proof.clone(), chunk.clone()))
                    .encode()
                    .len() as u64;
                entry_pointer += bfe!(entry_size + 1);
            }
            record_pointer += bfe!(record.encode().len() as u64 + 1);
        }
        (tree_paths_pointers, chunk_pointers)
    }

    impl Procedure for ChunkWitness {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
            nondeterminism: &NonDeterminism,
            _public_input: &[BFieldElement],
            _sponge: &mut Option<Tip5>,
        ) -> Result<Vec<BFieldElement>, RustShadowError> {
            let records_pointer = stack.pop().unwrap();
            assert_eq!(RECORDS_POINTER, records_pointer);
            let removal_records =
                *Vec::<RemovalRecord>::decode_from_memory(memory, records_pointer).unwrap();

            let _ = nondeterminism;
            let (chunks, tree_paths, leaf_count) = mirror(&removal_records, memory)?;
            stack.push(chunks);
            stack.push(tree_paths);
            stack.push(bfe!(leaf_count >> 32));
            stack.push(bfe!(leaf_count & u64::from(u32::MAX)));
            Ok(vec![])
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            bench_case: Option<BenchmarkCase>,
        ) -> ProcedureInitialState {
            let mut rng = StdRng::from_seed(seed);
            let (num_records, aocl_size) = match bench_case {
                Some(BenchmarkCase::CommonCase) => (10, 1 << 20),
                Some(BenchmarkCase::WorstCase) => (100, 1 << 30),
                None => {
                    let log_max_aocl_size = rng.random_range(4..40);
                    (
                        rng.random_range(1..8),
                        rng.random_range(8..(1_u64 << log_max_aocl_size)),
                    )
                }
            };
            let msa_and_records = random_msa_and_records(&mut rng, num_records, aocl_size);
            self.initial_state(&msa_and_records)
        }

        fn corner_case_initial_states(&self) -> Vec<ProcedureInitialState> {
            let mut rng = StdRng::seed_from_u64(0);
            let mut states = vec![self.initial_state_of(&[])];
            for (num_records, aocl_size) in [(1, 1), (1, 9), (2, 17), (3, 1 << 12), (5, 1 << 45)] {
                let msa_and_records = random_msa_and_records(&mut rng, num_records, aocl_size);
                states.push(self.initial_state(&msa_and_records));
            }
            states
        }
    }

    impl ChunkWitness {
        pub(in crate::block::validity) fn initial_state(
            &self,
            msa_and_records: &MsaAndRecords,
        ) -> ProcedureInitialState {
            let packed = RemovalRecordList::pack(msa_and_records.unpacked_removal_records(), true);
            self.initial_state_of(&packed)
        }

        fn initial_state_of(&self, packed_records: &[RemovalRecord]) -> ProcedureInitialState {
            let mut memory = HashMap::new();
            let witness_records = ChunkWitness::with_unpacked_chunks(packed_records.to_vec(), true);
            encode_to_memory(&mut memory, RECORDS_POINTER, &witness_records);
            let stack = [self.init_stack_for_isolated_run(), vec![RECORDS_POINTER]].concat();

            ProcedureInitialState {
                stack,
                nondeterminism: NonDeterminism::default().with_ram(memory),
                public_input: vec![],
                sponge: None,
            }
        }
    }

    /// The chunks, digest lists and leaf count estimate the
    /// snippet leaves.
    fn outputs_in_vm(packed_records: &[RemovalRecord]) -> (Vec<Chunk>, Vec<Vec<Digest>>, u64) {
        let final_state = test_rust_equivalence_given_execution_state(
            &ShadowedProcedure::new(ChunkWitness),
            ChunkWitness.initial_state_of(packed_records).into(),
        );
        let mut stack = final_state.op_stack.stack.clone();
        let leaf_count_lo: u32 = stack.pop().unwrap().try_into().unwrap();
        let leaf_count_hi: u32 = stack.pop().unwrap().try_into().unwrap();
        let leaf_count = (u64::from(leaf_count_hi) << 32) | u64::from(leaf_count_lo);
        let tree_paths = stack.pop().unwrap();
        let chunks = stack.pop().unwrap();
        let chunk_pointers =
            *Vec::<BFieldElement>::decode_from_memory(&final_state.ram, chunks).unwrap();
        let tree_paths_pointers =
            *Vec::<BFieldElement>::decode_from_memory(&final_state.ram, tree_paths).unwrap();
        let chunks = chunk_pointers
            .into_iter()
            .map(|pointer| Chunk {
                relative_indices: *Vec::<u32>::decode_from_memory(&final_state.ram, pointer)
                    .unwrap(),
            })
            .collect();
        let tree_paths = tree_paths_pointers
            .into_iter()
            .map(|pointer| *Vec::<Digest>::decode_from_memory(&final_state.ram, pointer).unwrap())
            .collect();
        (chunks, tree_paths, leaf_count)
    }

    #[test]
    fn rust_shadow_agrees_with_tasm() {
        ShadowedProcedure::new(ChunkWitness).test();
    }

    #[test]
    fn outputs_agree_with_unpacked_records() {
        let mut rng = StdRng::seed_from_u64(0);
        for (num_records, aocl_size) in [(1, 1), (1, 100), (2, 1 << 10), (4, 1 << 20), (6, 1 << 50)]
        {
            let msa_and_records = random_msa_and_records(&mut rng, num_records, aocl_size);
            let unpacked = msa_and_records.unpacked_removal_records();
            let packed = RemovalRecordList::pack(unpacked.clone(), true);
            let (chunks, tree_paths, leaf_count) = outputs_in_vm(&packed);

            // The chunks are those of the unpacked records, by ascending
            // chunk index, each once.
            let expected_chunks = unpacked
                .iter()
                .flat_map(|record| record.target_chunks.indices_and_chunks())
                .sorted_by_key(|(index, _)| *index)
                .dedup_by(|(a, _), (b, _)| a == b)
                .map(|(_, chunk)| chunk)
                .collect::<Vec<_>>();
            assert_eq!(expected_chunks, chunks);

            // The digest lists are the packed list's, one per tree of the
            // estimated inactive SWBF, which is at most the true one.
            let entries = packed_entries(&packed).unwrap();
            let heights = entries
                .iter()
                .filter_map(|entry| match entry {
                    PackedEntry::Tree { height, .. } => Some(*height),
                    PackedEntry::ChunkOnly => None,
                })
                .collect::<Vec<_>>();
            assert!(heights.windows(2).all(|pair| pair[0] < pair[1]));
            let expected_leaf_count = heights.iter().map(|height| 1_u64 << height).sum::<u64>();
            assert_eq!(expected_leaf_count, leaf_count);
            let true_leaf_count = msa_and_records
                .mutator_set_accumulator
                .swbf_inactive
                .num_leafs();
            assert!(leaf_count <= true_leaf_count);
            let expected_tree_paths = entries
                .into_iter()
                .filter_map(|entry| match entry {
                    PackedEntry::Tree { tree_paths, .. } => Some(tree_paths),
                    PackedEntry::ChunkOnly => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(expected_tree_paths, tree_paths);
            assert_eq!(leaf_count.count_ones() as usize, tree_paths.len());
        }
    }

    #[test]
    fn empty_list_yields_nothing() {
        let (chunks, tree_paths, leaf_count) = outputs_in_vm(&[]);
        assert!(chunks.is_empty());
        assert!(tree_paths.is_empty());
        assert_eq!(0, leaf_count);
    }

    /// A packed list for a mutator set whose inactive SWBF has trees, with
    /// the dictionary's entries modified.
    fn packed_with_modified_entries(
        rng: &mut StdRng,
        modify: impl FnOnce(&mut Vec<(u64, (MmrMembershipProof, Chunk))>),
    ) -> Vec<RemovalRecord> {
        let msa_and_records = random_msa_and_records(rng, 3, 1 << 20);
        let mut packed = RemovalRecordList::pack(msa_and_records.unpacked_removal_records(), true);
        let mut entries = packed[0].target_chunks.clone().into_inner();
        assert!(
            entries
                .iter()
                .filter(|(height, _)| *height < 2 * RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET)
                .count()
                >= 2,
            "fixture must have at least two trees"
        );
        modify(&mut entries);
        packed[0].target_chunks = ChunkDictionary::new_in_given_order(entries);
        packed
    }

    fn assert_rejected(packed: &[RemovalRecord]) {
        test_assertion_failure(
            &ShadowedProcedure::new(ChunkWitness),
            ChunkWitness.initial_state_of(packed).into(),
            &[ChunkWitness::tree_heights_error_id()],
        );
    }

    /// The snippet run on the fixture's records with the memory changed,
    /// as the program sees it.
    fn run_with_memory(
        modify: impl FnOnce(&mut HashMap<BFieldElement, BFieldElement>),
    ) -> Result<(), InstructionError> {
        let mut rng = StdRng::seed_from_u64(31);
        let msa_and_records = random_msa_and_records(&mut rng, 3, 1 << 20);
        let packed = RemovalRecordList::pack(msa_and_records.unpacked_removal_records(), true);
        let mut state = ChunkWitness.initial_state_of(&packed);
        modify(&mut state.nondeterminism.ram);
        let program = Program::new(&ChunkWitness.link_for_isolated_run());
        let mut vm_state = VMState::new(program, PublicInput::default(), state.nondeterminism);
        vm_state.op_stack.stack = state.stack;
        vm_state.run()
    }

    fn is_size_rejection(result: Result<(), InstructionError>) -> bool {
        matches!(
            result,
            Err(InstructionError::AssertionFailed(AssertionError { id, .. }))
                if id == Some(ChunkWitness::tree_heights_error_id())
        )
    }

    /// The size words of the first record and of its first entry: the
    /// record's, the dictionary's, then the entry's, the inner pair's, the
    /// chunk's, the chunk list's length and the digest list's.
    fn first_size_words(memory: &HashMap<BFieldElement, BFieldElement>) -> Vec<BFieldElement> {
        let record_si = RECORDS_POINTER + bfe!(1);
        let record_start = record_si + bfe!(1);
        let dictionary_size = record_start + bfe!(1);
        let entry_si = record_start + bfe!(3);
        let entry_start = entry_si + bfe!(1);
        let chunk_size = entry_start + bfe!(1);
        let paths_size = entry_start + bfe!(2) + memory[&chunk_size];
        vec![
            record_si,
            dictionary_size,
            entry_si,
            entry_start,
            chunk_size,
            entry_start + bfe!(2),
            paths_size,
        ]
    }

    #[test]
    fn untouched_memory_is_accepted() {
        assert_eq!(Ok(()), run_with_memory(|_| {}));
    }

    #[test]
    fn every_size_word_off_by_one_is_rejected() {
        let state = ChunkWitness.initial_state_of(&RemovalRecordList::pack(
            random_msa_and_records(&mut StdRng::seed_from_u64(31), 3, 1 << 20)
                .unpacked_removal_records(),
            true,
        ));
        for address in first_size_words(&state.nondeterminism.ram) {
            for delta in [bfe!(1), -bfe!(1)] {
                let result = run_with_memory(|memory| {
                    *memory.get_mut(&address).unwrap() += delta;
                });
                assert!(
                    is_size_rejection(result),
                    "word at {address} changed by {delta}"
                );
            }
        }
    }

    #[test]
    fn sizes_beyond_u32_crash() {
        let state = ChunkWitness.initial_state_of(&RemovalRecordList::pack(
            random_msa_and_records(&mut StdRng::seed_from_u64(31), 3, 1 << 20)
                .unpacked_removal_records(),
            true,
        ));
        let words = first_size_words(&state.nondeterminism.ram);
        // The number of records, and the entry's chunk size with a chunk
        // length that agrees in the field but not as a u32.
        assert!(run_with_memory(|memory| {
            memory.insert(RECORDS_POINTER, -bfe!(1));
        })
        .is_err());
        assert!(run_with_memory(|memory| {
            memory.insert(words[4], bfe!(0));
            memory.insert(words[5], -bfe!(1));
        })
        .is_err());
    }

    fn is_tree(entry: &(u64, (MmrMembershipProof, Chunk))) -> bool {
        entry.0 < 2 * RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET
    }

    #[test]
    fn decreasing_tree_heights_are_rejected() {
        let mut rng = StdRng::seed_from_u64(1);
        let packed = packed_with_modified_entries(&mut rng, |entries| {
            let first = entries.iter().position(is_tree).unwrap();
            let second = entries.iter().skip(first + 1).position(is_tree).unwrap() + first + 1;
            entries.swap(first, second);
        });
        assert_rejected(&packed);
    }

    #[test]
    fn duplicate_tree_is_rejected() {
        let mut rng = StdRng::seed_from_u64(2);
        let packed = packed_with_modified_entries(&mut rng, |entries| {
            let first = entries.iter().position(is_tree).unwrap();
            let duplicate = entries[first].clone();
            entries.insert(first + 1, duplicate);
        });
        assert_rejected(&packed);
    }

    #[test]
    fn illegal_tree_height_is_rejected() {
        for illegal_height in [
            2 * RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET,
            1 << 32,
            u64::MAX - 1,
        ] {
            let mut rng = StdRng::seed_from_u64(3);
            let packed = packed_with_modified_entries(&mut rng, |entries| {
                entries.push((
                    illegal_height,
                    (MmrMembershipProof::new(vec![]), Chunk::empty_chunk()),
                ));
            });
            assert_rejected(&packed);
        }
    }

    #[test]
    fn fewer_trees_than_the_true_swbfi_are_accepted() {
        // Dropping the last tree keeps the heights increasing; the estimate
        // just shrinks.
        let mut rng = StdRng::seed_from_u64(4);
        let mut dropped_height = 0;
        let packed = packed_with_modified_entries(&mut rng, |entries| {
            let last = entries.iter().rposition(is_tree).unwrap();
            let (height, (_, chunk)) = entries.remove(last);
            dropped_height = height % RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET;
            if height < RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET {
                entries.push((
                    RemovalRecordList::ENCODING_DELIMITER_IGNORE_TREE_HEIGHT,
                    (MmrMembershipProof::new(vec![]), chunk),
                ));
            }
        });
        let (_, tree_paths, leaf_count) = outputs_in_vm(&packed);
        assert_eq!(leaf_count.count_ones() as usize, tree_paths.len());
        assert_eq!(0, leaf_count & (1 << dropped_height));
    }

    #[test]
    fn entries_in_later_records_are_read_too() {
        let mut rng = StdRng::seed_from_u64(6);
        let msa_and_records = random_msa_and_records(&mut rng, 3, 1 << 20);
        let mut packed = RemovalRecordList::pack(msa_and_records.unpacked_removal_records(), true);
        let expected = outputs_in_vm(&packed);

        // Move the last entry to the last record.
        let mut entries = packed[0].target_chunks.clone().into_inner();
        let last = entries.pop().unwrap();
        packed[0].target_chunks = ChunkDictionary::new_in_given_order(entries);
        packed[2].target_chunks = ChunkDictionary::new_in_given_order(vec![last]);
        assert_eq!(expected, outputs_in_vm(&packed));
    }
}
