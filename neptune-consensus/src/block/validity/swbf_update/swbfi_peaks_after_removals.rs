//! Rules 2.a, 2.b and 2.d and the inactive-SWBF half of 2.e, in the design
//! where the witness supplies the chunks of the inactive SWBF that the
//! inputs' indices fall in, with the trees' heights and paths.
//!
//! From the mutator set the transaction is built on: the witness's inputs
//! must hold exactly the chunks their indices need (2.a, 2.b), every input
//! has an unset index (2.b, 2.d), and setting the indices in the chunks
//! yields the inactive SWBF's new peaks.
//!
//! This is the part of the update that dominates its cost. It is the body of
//! [`CorrectSwbfUpdate`](super::leaf::CorrectSwbfUpdate),
//! the claim that proves it for the current block.

use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_mutator_set::removal_record::removal_record_list::RemovalRecordList;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_mutator_set::shared::CHUNK_SIZE;
use neptune_mutator_set::shared::WINDOW_SIZE;
use tasm_lib::arithmetic::u128::shift_left_static::ShiftLeftStatic;
use tasm_lib::field;
use tasm_lib::list::new::New;
use tasm_lib::memory::memcpy::MemCpy;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::prelude::Mmr;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

use super::chunk_insertions::ChunkInsertions;
use super::divined_chunk_indices::DivinedChunkIndices;
use super::mutate_swbfi_peaks::MutateSwbfiPeaks;
use super::removal_records_are_unspent::RemovalRecordsAreUnspent;
use super::resolve_chunk_indices::ResolveChunkIndices;
use super::witness_lists::WitnessLists;
use crate::consensus_rule_set::ConsensusRuleSet;

/// Computes the inactive SWBF's peaks after a transaction's removals, from
/// the chunks the witness supplies: rules 2.a, 2.b and 2.d, then the
/// insertions.
///
/// ```text
/// BEFORE: _ *inputs *mutator_set *chunks *tree_heights *tree_paths
/// AFTER:  _ *swbfi_peaks_after
/// ```
///
/// The lists are the witness's, as [`WitnessLists`] reads them.
#[derive(Debug, Copy, Clone)]
pub(in crate::block::validity) struct SwbfiPeaksAfterRemovals;

impl BasicSnippet for SwbfiPeaksAfterRemovals {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*inputs".to_string()),
            (DataType::VoidPointer, "*mutator_set".to_string()),
            (DataType::VoidPointer, "*chunks".to_string()),
            (
                DataType::List(Box::new(DataType::U32)),
                "*tree_heights".to_string(),
            ),
            (DataType::VoidPointer, "*tree_paths".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(
            DataType::List(Box::new(DataType::Digest)),
            "*swbfi_peaks_after".to_string(),
        )]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_swbfi_peaks_after_removals".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let new_list = library.import(Box::new(New));
        let memcpy = library.import(Box::new(MemCpy));
        let witness_lists = library.import(Box::new(WitnessLists));
        let divined_chunk_indices = library.import(Box::new(DivinedChunkIndices));
        let resolve_chunk_indices = library.import(Box::new(ResolveChunkIndices));
        let removal_records_are_unspent = library.import(Box::new(RemovalRecordsAreUnspent));
        let chunk_insertions = library.import(Box::new(ChunkInsertions));
        let mutate_swbfi_peaks = library.import(Box::new(MutateSwbfiPeaks));
        let to_window_start =
            library.import(Box::new(ShiftLeftStatic::<{ CHUNK_SIZE.ilog2() as u8 }>));

        // What the rules share: the chunks and path lists of the witness's
        // inputs, the estimate of the inactive SWBF's leaf count
        // from their tree heights, the chunk indices, and the insertions.
        let chunks_alloc = library.kmalloc(1);
        let tree_paths_alloc = library.kmalloc(1);
        let swbfi_leaf_count_estimate_alloc = library.kmalloc(2);
        let chunk_indices_alloc = library.kmalloc(1);
        let insertions_alloc = library.kmalloc(1);

        let entrypoint = self.entrypoint();
        let rule_2a = format!("{entrypoint}_rule_2a");
        let rules_2b_2d = format!("{entrypoint}_rules_2b_2d");
        let removals = format!("{entrypoint}_removals");

        let read_u64 = triton_asm!(addi 1 read_mem 2 pop 1);

        // BEFORE: _ *mutator_set
        // AFTER:  _ [swbfi_leaf_count: u64]
        let swbfi_leaf_count = triton_asm!(
            {&field!(MutatorSetAccumulator::swbf_inactive)}
            {&field!(MmrAccumulator::leaf_count)} {&read_u64}
        );

        // Copies a list of digests: appending to an MMR modifies its peaks
        // list in place.
        // BEFORE: _ *list
        // AFTER:  _ *copy
        let copy_digest_list = triton_asm!(
            dup 0 read_mem 1 pop 1 push {Digest::LEN} mul addi 1
            // _ *list size

            call {new_list}
            // _ *list size *copy

            place 1 dup 1 place 3
            // _ *copy *list *copy size

            call {memcpy}
            // _ *copy
        );

        triton_asm!(
            // BEFORE: _ *inputs *mutator_set *chunks *tree_heights *tree_paths
            // AFTER:  _ *swbfi_peaks_after
            {entrypoint}:
                call {rule_2a}
                call {rules_2b_2d}
                call {removals}
                // _ *inputs *mutator_set *swbfi_peaks_after

                place 2 pop 2
                return

            // The witness must hold the chunks the inputs' indices in the
            // inactive SWBF need, no more and no fewer, with the trees'
            // heights in ascending order.
            // BEFORE: _ *inputs *mutator_set *chunks *tree_heights *tree_paths
            // AFTER:  _ *inputs *mutator_set
            {rule_2a}:
                call {witness_lists}
                // _ [base] *chunk_pointers *path_pointers [swbfi_leaf_count_estimate]

                push {swbfi_leaf_count_estimate_alloc.write_address()} write_mem 2 pop 1
                push {tree_paths_alloc.write_address()} write_mem 1 pop 1
                dup 0 push {chunks_alloc.write_address()} write_mem 1 pop 1
                // _ [base] *chunk_pointers

                read_mem 1 pop 1 call {divined_chunk_indices}
                // _ [base] *chunk_indices

                dup 0 push {chunk_indices_alloc.write_address()} write_mem 1 pop 1
                dup 2 swap 1
                push {swbfi_leaf_count_estimate_alloc.read_address()} read_mem 2 pop 1
                // _ [base] *inputs *chunk_indices [swbfi_leaf_count_estimate]

                dup 4 {&swbfi_leaf_count}
                // _ [base] *inputs *chunk_indices [swbfi_leaf_count_estimate] [swbfi_leaf_count]

                call {resolve_chunk_indices}
                // _ [base]

                return

            // No input is spent: each record has an index that is unset in
            // the mutator set, shown absent from its chunk or from the active
            // window.
            // BEFORE: _ *inputs *mutator_set
            // AFTER:  _ *inputs *mutator_set
            {rules_2b_2d}:
                dup 1
                push {chunk_indices_alloc.read_address()} read_mem 1 pop 1
                push {chunks_alloc.read_address()} read_mem 1 pop 1
                // _ [base] *inputs *chunk_indices *chunks

                dup 3 {&field!(MutatorSetAccumulator::swbf_active)}
                // _ [base] *inputs *chunk_indices *chunks *active_window

                dup 4 {&swbfi_leaf_count}
                // _ [base] *inputs *chunk_indices *chunks *active_window [swbfi_leaf_count]

                call {removal_records_are_unspent}
                // _ [base]

                return

            // The indices in the inactive SWBF's chunks are set, and the
            // peaks recomputed, on a copy of the peaks list.
            // BEFORE: _ *inputs *mutator_set
            // AFTER:  _ *inputs *mutator_set *swbfi_peaks_after
            {removals}:
                dup 1
                push {chunk_indices_alloc.read_address()} read_mem 1 pop 1
                dup 2 {&swbfi_leaf_count}
                push 0 push 0 pick 3 pick 3 call {to_window_start}
                // _ [base] *inputs *chunk_indices [window_start]

                call {chunk_insertions}
                push {insertions_alloc.write_address()} write_mem 1 pop 1
                // _ [base]

                dup 0 {&field!(MutatorSetAccumulator::swbf_inactive)} {&field!(MmrAccumulator::peaks)}
                {&copy_digest_list}
                // _ [base] *swbfi_peaks_after

                push {chunk_indices_alloc.read_address()} read_mem 1 pop 1
                push {chunks_alloc.read_address()} read_mem 1 pop 1
                push {insertions_alloc.read_address()} read_mem 1 pop 1
                push {tree_paths_alloc.read_address()} read_mem 1 pop 1
                dup 4
                push {swbfi_leaf_count_estimate_alloc.read_address()} read_mem 2 pop 1
                dup 8 {&swbfi_leaf_count}
                // _ [base] *swbfi_peaks_after *chunk_indices *chunks *insertions *tree_paths *swbfi_peaks_after [swbfi_leaf_count_estimate] [swbfi_leaf_count]

                call {mutate_swbfi_peaks}
                // _ [base] *swbfi_peaks_after

                return
        )
    }
}

impl SwbfiPeaksAfterRemovals {
    /// The tokens for the witness's inputs: the chunk indices, then the
    /// position of the chunk of every index that lies in the inactive SWBF,
    /// then the unset index of every record, then the sorted indices
    /// inserted into each chunk with their positions, then the tokens that
    /// recompute the inactive SWBF's peaks. A witness with more or fewer
    /// chunks than its indices need gets a list padded or cut to its number
    /// of chunks, which the program then rejects.
    pub(in crate::block::validity) fn divined_tokens(
        inputs: &[RemovalRecord],
        mutator_set: &MutatorSetAccumulator,
        chunks: &[Vec<u32>],
        tree_heights: &[u32],
    ) -> Vec<BFieldElement> {
        let estimate = WitnessLists::swbfi_leaf_count_estimate(tree_heights);
        let swbfi_leaf_count = mutator_set.swbf_inactive.num_leafs();
        let mut chunk_indices =
            ResolveChunkIndices::chunk_indices_below(inputs, estimate.max(swbfi_leaf_count));
        chunk_indices.truncate(chunks.len());
        while chunk_indices.len() < chunks.len() {
            let next = chunk_indices.last().map_or(0, |last| last + 1);
            chunk_indices.push(next);
        }

        let window_start = Self::window_start(mutator_set);
        let insertions = ChunkInsertions::insertions(inputs, &chunk_indices, window_start);

        [
            DivinedChunkIndices::divined_tokens(&chunk_indices),
            ResolveChunkIndices::divined_tokens(inputs, &chunk_indices, estimate, swbfi_leaf_count),
            RemovalRecordsAreUnspent::divined_tokens(
                inputs,
                &chunk_indices,
                chunks,
                &mutator_set.swbf_active,
                swbfi_leaf_count,
            ),
            ChunkInsertions::divined_tokens(inputs, &chunk_indices, window_start),
            MutateSwbfiPeaks::divined_tokens(estimate, &chunk_indices, chunks, &insertions),
        ]
        .concat()
    }

    /// The chunk indices and the insertions into each chunk of honest
    /// inputs on this mutator set.
    pub(in crate::block::validity) fn chunk_indices_and_insertions(
        inputs: &[RemovalRecord],
        mutator_set: &MutatorSetAccumulator,
    ) -> (Vec<u64>, Vec<Vec<u32>>) {
        let chunk_indices =
            ResolveChunkIndices::chunk_indices_below(inputs, mutator_set.swbf_inactive.num_leafs());
        let insertions =
            ChunkInsertions::insertions(inputs, &chunk_indices, Self::window_start(mutator_set));
        (chunk_indices, insertions)
    }

    /// The first index of the active window.
    pub(in crate::block::validity) fn window_start(mutator_set: &MutatorSetAccumulator) -> u128 {
        u128::from(mutator_set.swbf_inactive.num_leafs()) << CHUNK_SIZE.ilog2()
    }

    /// The mutator set with the packed inputs removed, computed on the host
    /// machine.
    pub(in crate::block::validity) fn apply_removals(
        inputs: &[RemovalRecord],
        mutator_set: &MutatorSetAccumulator,
    ) -> MutatorSetAccumulator {
        Self::try_apply_removals(inputs, mutator_set).expect("inputs must be removable")
    }

    /// The mutator set with the packed inputs removed, if they unpack and
    /// can be removed from it.
    pub(in crate::block::validity) fn try_apply_removals(
        inputs: &[RemovalRecord],
        mutator_set: &MutatorSetAccumulator,
    ) -> Option<MutatorSetAccumulator> {
        let unpacked_inputs = RemovalRecordList::try_unpack(
            inputs.to_vec(),
            ConsensusRuleSet::HardforkDelta.allow_big_chunks(),
        )
        .ok()?;
        let window_end = Self::window_start(mutator_set) + u128::from(WINDOW_SIZE);
        let removable = unpacked_inputs.iter().all(|record| {
            mutator_set.can_remove(record)
                && record
                    .absolute_indices
                    .to_array()
                    .iter()
                    .all(|&index| index < window_end)
        });
        if !removable {
            return None;
        }

        let mut mutator_set_after = mutator_set.clone();
        mutator_set_after.batch_remove(unpacked_inputs, &mut []);
        Some(mutator_set_after)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(in crate::block::validity) mod tests {
    use neptune_mutator_set::shared::NUM_TRIALS;

    use super::super::update_tree_leaf::UpdateTreeLeaf;
    use super::*;
    use crate::proof_abstractions::tasm::builtins as tasm;

    impl SwbfiPeaksAfterRemovals {
        /// The host shadow: asserts what the snippet asserts, reading the
        /// same divined tokens, and returns the peaks it computes.
        pub(in crate::block::validity) fn verify(
            inputs: &[RemovalRecord],
            mutator_set: &MutatorSetAccumulator,
            chunks: &[Vec<u32>],
            tree_heights: &[u32],
            tree_paths: &[Vec<Digest>],
        ) -> Vec<Digest> {
            // 2.a) The witness describes an inactive SWBF by strictly
            // increasing tree heights, and holds the chunks of exactly the
            // indices below its window start, while every index below the
            // true window start has its chunk.
            assert_eq!(tree_heights.len(), tree_paths.len());
            assert!(tree_heights.windows(2).all(|pair| pair[0] < pair[1]));
            let estimate = WitnessLists::swbfi_leaf_count_estimate(tree_heights);
            let num_chunks = chunks.len();
            let chunk_indices = (0..num_chunks)
                .map(|_| {
                    let hi = tasm::tasmlib_io_read_secin___bfe().value();
                    let lo = tasm::tasmlib_io_read_secin___bfe().value();
                    (hi << 32) | lo
                })
                .collect::<Vec<_>>();
            assert!(chunk_indices.windows(2).all(|pair| pair[0] < pair[1]));
            let window_start = |leaf_count: u64| u128::from(leaf_count) << CHUNK_SIZE.ilog2();
            let use_start = window_start(estimate);
            let true_window_start = Self::window_start(mutator_set);
            let resolve_start = use_start.max(true_window_start);
            let mut used = vec![false; num_chunks];
            for index in inputs
                .iter()
                .flat_map(|record| record.absolute_indices.to_array())
            {
                if index >= resolve_start {
                    continue;
                }
                let position = tasm::tasmlib_io_read_secin___bfe().value() as usize;
                let chunk_index = (index >> CHUNK_SIZE.ilog2()) as u64;
                assert_eq!(Some(&chunk_index), chunk_indices.get(position));
                if index < use_start {
                    used[position] = true;
                }
            }
            assert!(used.iter().all(|&used| used), "every chunk must be used");

            // 2.b, 2.d) Every record has an unset index: the prover points
            // at it, and at the gap around it in its sorted chunk or in the
            // sorted active window.
            let window = &mutator_set.swbf_active.sbf;
            assert!(window.windows(2).all(|pair| pair[0] <= pair[1]));
            assert!(window.iter().all(|&set| set < WINDOW_SIZE));
            let gap_encloses = |sorted: &[u32], index: u32| {
                let gap = tasm::tasmlib_io_read_secin___bfe().value() as usize;
                assert!(gap <= sorted.len());
                assert!(gap == 0 || sorted[gap - 1] < index);
                assert!(gap == sorted.len() || index < sorted[gap]);
            };
            for record in inputs {
                let position = tasm::tasmlib_io_read_secin___bfe().value() as usize;
                assert!(position < NUM_TRIALS as usize);
                let index = record.absolute_indices.to_array()[position];
                if index < true_window_start {
                    let chunk_position = tasm::tasmlib_io_read_secin___bfe().value() as usize;
                    let chunk_index = (index >> CHUNK_SIZE.ilog2()) as u64;
                    assert_eq!(Some(&chunk_index), chunk_indices.get(chunk_position));
                    let relative_index = (index % u128::from(CHUNK_SIZE)) as u32;
                    gap_encloses(&chunks[chunk_position], relative_index);
                } else {
                    let relative_index = index - true_window_start;
                    assert!(relative_index < u128::from(WINDOW_SIZE));
                    gap_encloses(window, relative_index as u32);
                }
            }

            // The insertions and peak tokens are read and ignored; the peaks
            // are computed directly from the unpacked records.
            let insertions = ChunkInsertions::insertions(inputs, &chunk_indices, true_window_start);
            let num_tokens =
                ChunkInsertions::divined_tokens(inputs, &chunk_indices, true_window_start).len()
                    + MutateSwbfiPeaks::divined_tokens(
                        estimate,
                        &chunk_indices,
                        chunks,
                        &insertions,
                    )
                    .len();
            for _ in 0..num_tokens {
                tasm::tasmlib_io_read_secin___bfe();
            }

            // The chunks must authenticate against the inactive SWBF: each
            // tree's paths lead from its chunks to its peak, and the peaks
            // after the removals are what its paths lead to from the
            // mutated chunks.
            let mut peaks = mutator_set.swbf_inactive.peaks();
            for ((height, old_leafs, new_leafs), paths) in
                MutateSwbfiPeaks::runs(estimate, &chunk_indices, chunks, &insertions)
                    .into_iter()
                    .rev()
                    .zip(tree_paths)
                    .filter(|((_, old_leafs, _), _)| !old_leafs.is_empty())
            {
                let peak_index =
                    (mutator_set.swbf_inactive.num_leafs() >> (height + 1)).count_ones() as usize;
                let (old_root, new_root) =
                    UpdateTreeLeaf::try_roots(height, paths, &old_leafs, &new_leafs)
                        .expect("chunks must sit in the running tree");
                assert_eq!(
                    peaks.get(peak_index),
                    Some(&old_root),
                    "chunks must authenticate against the inactive SWBF"
                );
                peaks[peak_index] = new_root;
            }
            peaks
        }
    }
}
