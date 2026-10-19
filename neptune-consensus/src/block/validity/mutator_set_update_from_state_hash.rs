//! The rest of rule 2.e once the mutator set after the transaction's
//! removals is known by hash: the inactive SWBF's peaks are divined and
//! checked against that hash together with the active window after the
//! removals, then the outputs are added and the result compared with the
//! expected accumulator.
//!
//! The hash comes from
//! [`CorrectSwbfUpdate`](super::swbf_update::leaf::CorrectSwbfUpdate)'s
//! claim, so this needs no chunk data.

use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_mutator_set::removal_record::RemovalRecord;
use tasm_lib::field;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::list::new::New;
use tasm_lib::list::push::Push;
use tasm_lib::memory::memcpy::MemCpy;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

use super::apply_addition_records::ApplyAdditionRecords;
use super::mutator_set_hash::MutatorSetHash;
use super::mutator_set_hash::MutatorSetHashFromComponents;
use super::swbf_update::window_after_removals::WindowAfterRemovals;
use crate::block::block_validation_error::BlockValidationRule;

/// Asserts that applying a transaction to the mutator set it is built on
/// yields the expected accumulator, given the hash of the mutator set after
/// the transaction's removals.
///
/// ```text
/// BEFORE: _ *inputs *outputs *mutator_set *expected_mutator_set [mutator_set_after_removals_hash]
/// AFTER:  _
/// ```
#[derive(Debug, Copy, Clone)]
pub(super) struct MutatorSetUpdateFromStateHash;

impl BasicSnippet for MutatorSetUpdateFromStateHash {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*inputs".to_string()),
            (DataType::VoidPointer, "*outputs".to_string()),
            (DataType::VoidPointer, "*mutator_set".to_string()),
            (DataType::VoidPointer, "*expected_mutator_set".to_string()),
            (
                DataType::Digest,
                "mutator_set_after_removals_hash".to_string(),
            ),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_mutator_set_update_from_state_hash".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let hash_varlen = library.import(Box::new(HashVarlen));
        let new_list = library.import(Box::new(New));
        let push_digest = library.import(Box::new(Push::new(DataType::Digest)));
        let memcpy = library.import(Box::new(MemCpy));
        let window_after_removals = library.import(Box::new(WindowAfterRemovals));
        let mutator_set_hash_from_components =
            library.import(Box::new(MutatorSetHashFromComponents));
        let apply_addition_records = library.import(Box::new(ApplyAdditionRecords));

        let hash_after_removals_alloc = library.kmalloc(Digest::LEN as u32);

        let entrypoint = self.entrypoint();
        let rule_2e = format!("{entrypoint}_rule_2e");
        let divine_peaks = format!("{entrypoint}_divine_peaks");

        let read_u64 = triton_asm!(addi 1 read_mem 2 pop 1);

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

        // BEFORE: _ *list
        // AFTER:  _ [digest]
        let hash_digest_list = triton_asm!(
            dup 0 read_mem 1 pop 1 push {Digest::LEN} mul addi 1
            call {hash_varlen}
        );

        // Hashes a window's encoding, whose first word is the length of the
        // rest.
        // BEFORE: _ *window_encoding
        // AFTER:  _ [digest]
        let hash_window_encoding = triton_asm!(
            read_mem 1 addi 2 swap 1
            call {hash_varlen}
        );

        // BEFORE: _ [a: u64] [b: u64]
        // AFTER:  _
        let assert_u64_eq = triton_asm!(
            pick 2 eq place 2 eq mul
            assert error_id {BlockValidationRule::MutatorSetUpdateIntegrity.error_id()}
        );

        triton_asm!(
            // BEFORE: _ *inputs *outputs *mutator_set *expected_mutator_set [hash_after_removals]
            // AFTER:  _
            {entrypoint}:
                push {hash_after_removals_alloc.write_address()} write_mem {Digest::LEN} pop 1
                call {rule_2e}
                pop 4
                return

            // BEFORE: _ [base]
            // AFTER:  _ [base]
            {rule_2e}:
                dup 3 dup 2 call {window_after_removals}
                // _ [base] *window'

                // The peaks after the removals are the prover's; the hash
                // check below binds them.
                divine 1
                // _ [base] *window' num_peaks

                /* Verify valid u32 */
                dup 0 pop_count pop 1
                // _ [base] *window' num_peaks

                call {new_list} swap 1
                call {divine_peaks}
                pop 1
                // _ [base] *window' *swbfi_peaks'

                // The accumulator with the new window and peaks; the AOCL
                // peaks copied, as appending modifies them.
                dup 3 {&MutatorSetHash::read_components()}
                // _ [base] *window' *swbfi_peaks' *window *swbfi_peaks [swbfi_leaf_count] [aocl_leaf_count] *aocl_peaks

                {&copy_digest_list}
                pick 5 pop 1
                pick 5 pop 1
                // _ [base] [components]

                dup 6 dup 6 dup 6 dup 6 dup 6 dup 6 dup 6
                call {mutator_set_hash_from_components}
                push {hash_after_removals_alloc.read_address()} read_mem {Digest::LEN} pop 1
                assert_vector error_id {BlockValidationRule::MutatorSetUpdateIntegrity.error_id()}
                pop 5
                // _ [base] [components]

                dup 9
                // _ [base] [components] *outputs

                call {apply_addition_records}
                // _ [base] [components']

                dup 7 place 7
                // _ [base] *expected *window'' *swbfi_peaks' [swbfi_leaf_count'] [aocl_leaf_count'] *aocl_peaks'

                dup 0 {&hash_digest_list}
                dup 12 {&field!(MutatorSetAccumulator::aocl)} {&field!(MmrAccumulator::peaks)}
                {&hash_digest_list}
                assert_vector error_id {BlockValidationRule::MutatorSetUpdateIntegrity.error_id()}
                pop 5
                // _ [base] *expected [components']

                dup 5 {&hash_digest_list}
                dup 12 {&field!(MutatorSetAccumulator::swbf_inactive)} {&field!(MmrAccumulator::peaks)}
                {&hash_digest_list}
                assert_vector error_id {BlockValidationRule::MutatorSetUpdateIntegrity.error_id()}
                pop 5
                // _ [base] *expected [components']

                dup 2 dup 2
                dup 9 {&field!(MutatorSetAccumulator::aocl)} {&field!(MmrAccumulator::leaf_count)}
                {&read_u64}
                {&assert_u64_eq}
                // _ [base] *expected [components']

                dup 4 dup 4
                dup 9 {&field!(MutatorSetAccumulator::swbf_inactive)}
                {&field!(MmrAccumulator::leaf_count)} {&read_u64}
                {&assert_u64_eq}
                // _ [base] *expected [components']

                dup 6 {&hash_window_encoding}
                dup 12 {&field!(MutatorSetAccumulator::swbf_active)} {&hash_window_encoding}
                assert_vector error_id {BlockValidationRule::MutatorSetUpdateIntegrity.error_id()}
                pop 5
                // _ [base] *expected [components']

                pop 5 pop 3
                // _ [base]

                return

            // INVARIANT: _ *peaks remaining
            {divine_peaks}:
                dup 0 push 0 eq skiz return
                dup 1 divine {Digest::LEN} call {push_digest}
                addi -1
                recurse
        )
    }
}

impl MutatorSetUpdateFromStateHash {
    /// The tokens for the transaction: the window's, then the inactive
    /// SWBF's peaks after the removals, counted. There are no peaks for
    /// inputs that cannot be removed.
    /// The tokens for these inputs on this mutator set: the window's, which
    /// need only the index sets, then the inactive SWBF's peaks after the
    /// removals, which whoever holds the chunks computes.
    pub(super) fn divined_tokens(
        inputs: &[RemovalRecord],
        mutator_set: &MutatorSetAccumulator,
        swbfi_peaks_after_removals: &[Digest],
    ) -> Vec<BFieldElement> {
        [
            WindowAfterRemovals::divined_tokens(inputs, mutator_set),
            vec![bfe!(swbfi_peaks_after_removals.len() as u64)],
            swbfi_peaks_after_removals
                .iter()
                .flat_map(|peak| peak.reversed().values())
                .collect(),
        ]
        .concat()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) mod tests {
    use neptune_mutator_set::addition_record::AdditionRecord;
    use tasm_lib::twenty_first::prelude::Mmr;

    use super::*;
    use crate::proof_abstractions::tasm::builtins as tasm;

    impl MutatorSetUpdateFromStateHash {
        /// The host shadow: asserts what the snippet asserts, reading the
        /// same divined tokens.
        pub(in crate::block::validity) fn verify(
            inputs: &[RemovalRecord],
            outputs: &[AdditionRecord],
            mutator_set: &MutatorSetAccumulator,
            hash_after_removals: Digest,
            expected_mutator_set: &MutatorSetAccumulator,
        ) {
            let window_after = WindowAfterRemovals::verify(inputs, mutator_set);
            let num_peaks = tasm::tasmlib_io_read_secin___bfe().value();
            let peaks = (0..num_peaks)
                .map(|_| tasm::tasmlib_io_read_secin___digest())
                .collect();

            let mut mutator_set_after = mutator_set.clone();
            mutator_set_after.swbf_inactive =
                MmrAccumulator::init(peaks, mutator_set.swbf_inactive.num_leafs());
            mutator_set_after.swbf_active = window_after;
            assert_eq!(hash_after_removals, mutator_set_after.hash());

            for output in outputs {
                mutator_set_after.add(output);
            }
            assert_eq!(
                mutator_set_after.aocl.peaks(),
                expected_mutator_set.aocl.peaks()
            );
            assert_eq!(
                mutator_set_after.aocl.num_leafs(),
                expected_mutator_set.aocl.num_leafs()
            );
            assert_eq!(
                mutator_set_after.swbf_inactive.num_leafs(),
                expected_mutator_set.swbf_inactive.num_leafs()
            );
            assert_eq!(
                mutator_set_after.swbf_inactive.peaks(),
                expected_mutator_set.swbf_inactive.peaks()
            );
            assert_eq!(
                mutator_set_after.swbf_active,
                expected_mutator_set.swbf_active
            );
        }
    }
}
