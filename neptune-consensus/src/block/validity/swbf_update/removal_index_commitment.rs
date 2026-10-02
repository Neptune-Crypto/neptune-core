//! The commitment to a block transaction's inputs that
//! [`CorrectSwbfiUpdate`](super::leaf::CorrectSwbfiUpdate)
//! binds, to their index sets and nothing else: the peaks of an MMR over
//! the index sets, in block order.
//!
//! A claim outputs the peaks over its own inputs, so it is the same claim
//! wherever its inputs land in the block. An aggregation is given the index
//! sets' digests, recomputes its children's peaks from them and its own
//! over all of them; a verifier recomputes the root's from the inputs alone.

use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use neptune_mutator_set::removal_record::RemovalRecord;
use tasm_lib::field;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::list::new::New;
use tasm_lib::list::push::Push;
use tasm_lib::mmr::calculate_new_peaks_from_append::CalculateNewPeaksFromAppend;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::prelude::Mmr;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

use crate::block::validity::removal_record_pointers::RemovalRecordPointers;

/// ```text
/// BEFORE: _ *inputs
/// AFTER:  _ *peaks
/// ```
#[derive(Debug, Copy, Clone)]
pub(in crate::block::validity) struct RemovalIndexCommitment;

impl RemovalIndexCommitment {
    /// The peaks of the MMR over these inputs' index sets.
    pub(in crate::block::validity) fn peaks(inputs: &[RemovalRecord]) -> Vec<Digest> {
        DigestPeaks::peaks(&IndexSetDigests::digests(inputs))
    }
}

impl BasicSnippet for RemovalIndexCommitment {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "*inputs".to_string())]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(
            DataType::List(Box::new(DataType::Digest)),
            "*peaks".to_string(),
        )]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_removal_index_commitment".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let index_set_digests = library.import(Box::new(IndexSetDigests));
        let digest_peaks = library.import(Box::new(DigestPeaks));

        triton_asm!(
            // BEFORE: _ *inputs
            // AFTER:  _ *peaks
            {self.entrypoint()}:
                call {index_set_digests}
                dup 0 read_mem 1 pop 1
                push 0 place 1
                // _ *digests 0 count

                call {digest_peaks}
                return
        )
    }
}

/// ```text
/// BEFORE: _ *inputs
/// AFTER:  _ *digests
/// ```
///
/// Each input's index set hashed, in order.
#[derive(Debug, Copy, Clone)]
pub(in crate::block::validity) struct IndexSetDigests;

impl IndexSetDigests {
    pub(in crate::block::validity) fn digests(inputs: &[RemovalRecord]) -> Vec<Digest> {
        inputs
            .iter()
            .map(|input| Tip5::hash_varlen(&input.absolute_indices.encode()))
            .collect()
    }
}

impl BasicSnippet for IndexSetDigests {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "*inputs".to_string())]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(
            DataType::List(Box::new(DataType::Digest)),
            "*digests".to_string(),
        )]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_index_set_digests".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let removal_record_pointers = library.import(Box::new(RemovalRecordPointers));
        let hash_varlen = library.import(Box::new(HashVarlen));
        let new_list = library.import(Box::new(New));
        let push_digest = library.import(Box::new(Push::new(DataType::Digest)));
        let index_set_size = AbsoluteIndexSet::static_length().unwrap();

        let entrypoint = self.entrypoint();
        let hash_index_sets = format!("{entrypoint}_loop");

        triton_asm!(
            // BEFORE: _ *inputs
            // AFTER:  _ *digests
            {entrypoint}:
                call {removal_record_pointers}
                dup 0 read_mem 1 pop 1
                // _ *pointers count

                call {new_list}
                dup 2 dup 1 dup 3 push 0
                call {hash_index_sets}
                pop 4
                // _ *pointers count *digests

                place 2 pop 2
                return

            // INVARIANT: _ *pointers *digests count j
            {hash_index_sets}:
                dup 1 dup 1 eq skiz return
                dup 3 dup 1 addi 1 add read_mem 1 pop 1
                {&field!(RemovalRecord::absolute_indices)}
                push {index_set_size} call {hash_varlen}
                // _ *pointers *digests count j [digest]

                dup 7 place 5
                call {push_digest}
                // _ *pointers *digests count j

                addi 1
                recurse
        )
    }
}

/// ```text
/// BEFORE: _ *digests first count
/// AFTER:  _ *peaks
/// ```
///
/// The peaks of the MMR over `count` of the digests, from index `first`.
#[derive(Debug, Copy, Clone)]
pub(in crate::block::validity) struct DigestPeaks;

impl DigestPeaks {
    pub(in crate::block::validity) fn peaks(digests: &[Digest]) -> Vec<Digest> {
        let mut mmr = MmrAccumulator::init(vec![], 0);
        for &digest in digests {
            mmr.append(digest);
        }
        mmr.peaks()
    }
}

impl BasicSnippet for DigestPeaks {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (
                DataType::List(Box::new(DataType::Digest)),
                "*digests".to_string(),
            ),
            (DataType::U32, "first".to_string()),
            (DataType::U32, "count".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(
            DataType::List(Box::new(DataType::Digest)),
            "*peaks".to_string(),
        )]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_digest_peaks".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let new_list = library.import(Box::new(New));
        let append = library.import(Box::new(CalculateNewPeaksFromAppend));

        let entrypoint = self.entrypoint();
        let append_digests = format!("{entrypoint}_append_digests");

        triton_asm!(
            // BEFORE: _ *digests first count
            // AFTER:  _ *peaks
            {entrypoint}:
                call {new_list} place 1 push 0
                // _ *digests first *peaks count 0

                call {append_digests}
                // _ *digests first *peaks count count

                pop 2 place 2 pop 2
                return

            // INVARIANT: _ *digests first *peaks count j
            {append_digests}:
                dup 1 dup 1 eq skiz return
                push 0 dup 1 dup 4
                // _ *digests first *peaks count j [j: u64] *peaks

                dup 7 dup 7 dup 3 add push {Digest::LEN} mul add addi {Digest::LEN}
                read_mem {Digest::LEN} pop 1
                // _ *digests first *peaks count j [j: u64] *peaks [digests[first + j]]

                call {append}
                pop 1 swap 3 pop 1
                // _ *digests first *new_peaks count j

                addi 1
                recurse
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::prelude::TasmObject;
    use tasm_lib::triton_vm::vm::VMState;

    use super::*;
    use crate::block::validity::removal_record_pointers::tests::random_removal_records;

    /// The digest list a snippet leaves a pointer to, run in isolation on
    /// these arguments.
    fn tasm_digests(
        snippet: &dyn BasicSnippet,
        arguments: Vec<BFieldElement>,
        nondeterminism: NonDeterminism,
    ) -> Vec<Digest> {
        let program = Program::new(&snippet.link_for_isolated_run());
        let mut vm_state = VMState::new(program, PublicInput::default(), nondeterminism);
        vm_state.op_stack.stack = [snippet.init_stack_for_isolated_run(), arguments].concat();
        vm_state.run().unwrap();

        let pointer = *vm_state.op_stack.stack.last().unwrap();
        *Vec::<Digest>::decode_from_memory(&vm_state.ram, pointer).unwrap()
    }

    #[test]
    fn tasm_agrees_with_host_for_various_counts() {
        let mut rng = StdRng::seed_from_u64(0);
        for num_inputs in [0, 1, 2, 3, 7, 8, 11] {
            let inputs = random_removal_records(&mut rng, num_inputs);
            let inputs_pointer = bfe!(1_000);
            let mut nondeterminism = NonDeterminism::default();
            encode_to_memory(&mut nondeterminism.ram, inputs_pointer, &inputs);
            assert_eq!(
                RemovalIndexCommitment::peaks(&inputs),
                tasm_digests(
                    &RemovalIndexCommitment,
                    vec![inputs_pointer],
                    nondeterminism
                ),
                "{num_inputs} inputs"
            );
        }
    }

    #[test]
    fn digest_peaks_over_a_sub_range_agree_with_host() {
        let mut rng = StdRng::seed_from_u64(1);
        let digests = IndexSetDigests::digests(&random_removal_records(&mut rng, 11));
        for (first, count) in [(0, 0), (0, 11), (3, 5), (8, 3), (11, 0)] {
            let digests_pointer = bfe!(1_000);
            let mut nondeterminism = NonDeterminism::default();
            encode_to_memory(&mut nondeterminism.ram, digests_pointer, &digests);
            assert_eq!(
                DigestPeaks::peaks(&digests[first..first + count]),
                tasm_digests(
                    &DigestPeaks,
                    vec![digests_pointer, bfe!(first as u64), bfe!(count as u64)],
                    nondeterminism
                ),
                "{count} digests from {first}"
            );
        }
    }
}
