//! The rest of rule 2.e once the inactive SWBF's peaks after the
//! transaction's removals are known: the active window after the removals
//! is recomputed, the outputs are added and the result compared with the
//! expected accumulator.
//!
//! The peaks come from
//! [`CorrectSwbfUpdate`](super::swbf_update::leaf::CorrectSwbfUpdate)'s
//! claim, so this needs no chunk data.

use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use tasm_lib::field;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::list::new::New;
use tasm_lib::memory::memcpy::MemCpy;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

use super::apply_addition_records::ApplyAdditionRecords;
use super::mutator_set_hash::MutatorSetHash;
use super::swbf_update::window_after_removals::WindowAfterRemovals;
use crate::block::block_validation_error::BlockValidationRule;

/// Asserts that applying a transaction to the mutator set it is built on
/// yields the expected accumulator, given the inactive SWBF's peaks after
/// the transaction's removals.
///
/// ```text
/// BEFORE: _ *inputs *outputs *mutator_set *expected_mutator_set *swbfi_peaks_after
/// AFTER:  _
/// ```
#[derive(Debug, Copy, Clone)]
pub(super) struct MutatorSetUpdateFromPeaks;

impl BasicSnippet for MutatorSetUpdateFromPeaks {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*inputs".to_string()),
            (DataType::VoidPointer, "*outputs".to_string()),
            (DataType::VoidPointer, "*mutator_set".to_string()),
            (DataType::VoidPointer, "*expected_mutator_set".to_string()),
            (
                DataType::List(Box::new(DataType::Digest)),
                "*swbfi_peaks_after".to_string(),
            ),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_mutator_set_update_from_peaks".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let hash_varlen = library.import(Box::new(HashVarlen));
        let new_list = library.import(Box::new(New));
        let memcpy = library.import(Box::new(MemCpy));
        let window_after_removals = library.import(Box::new(WindowAfterRemovals));
        let apply_addition_records = library.import(Box::new(ApplyAdditionRecords));

        let entrypoint = self.entrypoint();
        let rule_2e = format!("{entrypoint}_rule_2e");

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
            // BEFORE: _ *inputs *outputs *mutator_set *expected_mutator_set *swbfi_peaks'
            // AFTER:  _
            {entrypoint}:
                call {rule_2e}
                pop 4
                return

            // BEFORE: _ [base] *swbfi_peaks'
            // AFTER:  _ [base]
            {rule_2e}:
                dup 4 dup 3 call {window_after_removals}
                // _ [base] *swbfi_peaks' *window'

                // The accumulator with the new window and peaks; both peaks
                // lists copied, as appending modifies them.
                swap 1 {&copy_digest_list}
                // _ [base] *window' *swbfi_peaks'

                dup 3 {&MutatorSetHash::read_components()}
                // _ [base] *window' *swbfi_peaks' *window *swbfi_peaks [swbfi_leaf_count] [aocl_leaf_count] *aocl_peaks

                {&copy_digest_list}
                pick 5 pop 1
                pick 5 pop 1
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
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) mod tests {
    use std::collections::HashMap;

    use neptune_mutator_set::addition_record::AdditionRecord;
    use neptune_mutator_set::removal_record::RemovalRecord;
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::prelude::TasmObject;
    use tasm_lib::triton_vm::isa::instruction::AssertionError;
    use tasm_lib::triton_vm::isa::instruction::InstructionError;
    use tasm_lib::triton_vm::vm::VMState;
    use tasm_lib::twenty_first::prelude::Mmr;

    use super::*;
    use crate::block::validity::swbf_update::leaf::tests::witness;
    use crate::block::validity::swbf_update::swbfi_peaks_after_removals::SwbfiPeaksAfterRemovals;

    const INPUTS: BFieldElement = BFieldElement::new(1 << 20);
    const OUTPUTS: BFieldElement = BFieldElement::new(1 << 22);
    const MUTATOR_SET: BFieldElement = BFieldElement::new(1 << 24);
    const EXPECTED: BFieldElement = BFieldElement::new(1 << 26);
    const PEAKS: BFieldElement = BFieldElement::new(1 << 28);

    /// A transaction on a mutator set: the set after its removals, and the
    /// one its outputs then produce.
    struct Fixture {
        inputs: Vec<RemovalRecord>,
        outputs: Vec<AdditionRecord>,
        before_removals: MutatorSetAccumulator,
        after_removals: MutatorSetAccumulator,
        expected: MutatorSetAccumulator,
    }

    fn fixture(seed: u64) -> Fixture {
        let witness = witness(3, seed);
        let inputs = witness.packed_inputs();
        let before_removals = witness.mutator_set().clone();
        let after_removals = SwbfiPeaksAfterRemovals::apply_removals(&inputs, &before_removals);
        let mut rng = StdRng::seed_from_u64(seed);
        let outputs = (0..3)
            .map(|_| AdditionRecord::new(rng.random()))
            .collect::<Vec<_>>();
        let mut expected = after_removals.clone();
        for output in &outputs {
            expected.add(output);
        }
        Fixture {
            inputs,
            outputs,
            before_removals,
            after_removals,
            expected,
        }
    }

    impl Fixture {
        fn tokens(&self) -> Vec<BFieldElement> {
            WindowAfterRemovals::divined_tokens(&self.inputs, &self.before_removals)
        }

        fn peaks(&self) -> Vec<Digest> {
            self.after_removals.swbf_inactive.peaks()
        }

        fn run(
            &self,
            peaks: &[Digest],
            expected: &MutatorSetAccumulator,
            tokens: Vec<BFieldElement>,
        ) -> Result<VMState, InstructionError> {
            let mut library = Library::new();
            let snippet = library.import(Box::new(MutatorSetUpdateFromPeaks));
            let program = Program::new(&triton_asm!(
                push {INPUTS} push {OUTPUTS} push {MUTATOR_SET} push {EXPECTED} push {PEAKS}
                call {snippet}
                halt
                {&library.all_imports()}
            ));
            let mut ram = HashMap::new();
            encode_to_memory(&mut ram, INPUTS, &self.inputs);
            encode_to_memory(&mut ram, OUTPUTS, &self.outputs);
            encode_to_memory(&mut ram, MUTATOR_SET, &self.before_removals);
            encode_to_memory(&mut ram, EXPECTED, expected);
            encode_to_memory(&mut ram, PEAKS, &peaks.to_vec());
            let nondeterminism = NonDeterminism::new(tokens).with_ram(ram);
            let mut state = VMState::new(program, PublicInput::default(), nondeterminism);
            state.run()?;
            Ok(state)
        }

        fn assert_accepts(&self) {
            self.run(&self.peaks(), &self.expected, self.tokens())
                .unwrap();
        }

        fn assert_rejects(
            &self,
            peaks: &[Digest],
            expected: &MutatorSetAccumulator,
            tokens: Vec<BFieldElement>,
            error_id: i128,
        ) {
            let id = match self.run(peaks, expected, tokens) {
                Err(
                    InstructionError::AssertionFailed(AssertionError { id, .. })
                    | InstructionError::VectorAssertionFailed(_, AssertionError { id, .. }),
                ) => id,
                other => panic!("must fail an assertion, got {other:?}"),
            };
            assert_eq!(Some(error_id), id);
        }
    }

    #[test]
    fn honest_tokens_are_accepted() {
        for seed in 0..3 {
            fixture(seed).assert_accepts();
        }
    }

    #[test]
    fn other_peaks_are_rejected() {
        let fixture = fixture(7);
        let honest = fixture.peaks();
        assert!(!honest.is_empty(), "the fixture must have peaks");

        // One peak too few or too many disagrees with the leaf count, which
        // the append rejects before the comparison.
        let fewer = &honest[..honest.len() - 1];
        assert!(fixture
            .run(fewer, &fixture.expected, fixture.tokens())
            .is_err());
        let more = [honest.clone(), vec![Digest::default()]].concat();
        assert!(fixture
            .run(&more, &fixture.expected, fixture.tokens())
            .is_err());

        for word in 0..Digest::LEN {
            let mut tampered = honest.clone();
            tampered[0].0[word] += bfe!(1);
            fixture.assert_rejects(
                &tampered,
                &fixture.expected,
                fixture.tokens(),
                BlockValidationRule::MutatorSetUpdateIntegrity.error_id(),
            );
        }
    }

    /// The claim's list stays as it is: the snippet appends to a copy.
    #[test]
    fn peaks_are_left_as_they_are() {
        let fixture = fixture(7);
        let peaks = fixture.peaks();
        let state = fixture
            .run(&peaks, &fixture.expected, fixture.tokens())
            .unwrap();
        assert_eq!(
            peaks,
            *Vec::<Digest>::decode_from_memory(&state.ram, PEAKS).unwrap()
        );
    }

    #[test]
    fn expected_set_differing_in_any_component_is_rejected() {
        let fixture = fixture(7);
        let honest = &fixture.expected;
        let rejects = |expected: &MutatorSetAccumulator| {
            fixture.assert_rejects(
                &fixture.peaks(),
                expected,
                fixture.tokens(),
                BlockValidationRule::MutatorSetUpdateIntegrity.error_id(),
            );
        };

        let mut one_more_output = honest.clone();
        one_more_output.add(&AdditionRecord::new(Digest::default()));
        rejects(&one_more_output);

        let mut other_peak = honest.clone();
        let mut peaks = other_peak.swbf_inactive.peaks();
        peaks[0] = Digest::default();
        other_peak.swbf_inactive = MmrAccumulator::init(peaks, honest.swbf_inactive.num_leafs());
        rejects(&other_peak);

        let mut other_window = honest.clone();
        other_window.swbf_active.insert(0);
        rejects(&other_window);

        rejects(&fixture.after_removals);
    }

    impl MutatorSetUpdateFromPeaks {
        /// The host shadow: asserts what the snippet asserts, reading the
        /// same divined tokens.
        pub(in crate::block::validity) fn verify(
            inputs: &[RemovalRecord],
            outputs: &[AdditionRecord],
            mutator_set: &MutatorSetAccumulator,
            swbfi_peaks_after: &[Digest],
            expected_mutator_set: &MutatorSetAccumulator,
        ) {
            let window_after = WindowAfterRemovals::verify(inputs, mutator_set);
            let mut mutator_set_after = mutator_set.clone();
            mutator_set_after.swbf_inactive = MmrAccumulator::init(
                swbfi_peaks_after.to_vec(),
                mutator_set.swbf_inactive.num_leafs(),
            );
            mutator_set_after.swbf_active = window_after;

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
