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
    use std::collections::HashMap;

    use neptune_mutator_set::addition_record::AdditionRecord;
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::triton_vm::isa::instruction::AssertionError;
    use tasm_lib::triton_vm::isa::instruction::InstructionError;
    use tasm_lib::triton_vm::isa::op_stack::OpStackError;
    use tasm_lib::triton_vm::vm::VMState;
    use tasm_lib::twenty_first::prelude::Mmr;

    use super::*;
    use crate::block::validity::mutator_set_hash::BagPeaksFromList;
    use crate::block::validity::swbf_update::leaf::tests::witness;
    use crate::block::validity::swbf_update::swbfi_peaks_after_removals::SwbfiPeaksAfterRemovals;
    use crate::proof_abstractions::tasm::builtins as tasm;

    const INPUTS: BFieldElement = BFieldElement::new(1 << 20);
    const OUTPUTS: BFieldElement = BFieldElement::new(1 << 22);
    const MUTATOR_SET: BFieldElement = BFieldElement::new(1 << 24);
    const EXPECTED: BFieldElement = BFieldElement::new(1 << 26);

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
            MutatorSetUpdateFromStateHash::divined_tokens(
                &self.inputs,
                &self.before_removals,
                &self.after_removals.swbf_inactive.peaks(),
            )
        }

        /// The position of the peak count among the tokens.
        fn num_peaks_token(&self) -> usize {
            WindowAfterRemovals::divined_tokens(&self.inputs, &self.before_removals).len()
        }

        fn run(
            &self,
            hash_after_removals: Digest,
            expected: &MutatorSetAccumulator,
            tokens: Vec<BFieldElement>,
        ) -> Result<(), InstructionError> {
            let mut library = Library::new();
            let snippet = library.import(Box::new(MutatorSetUpdateFromStateHash));
            let push_hash = hash_after_removals
                .reversed()
                .values()
                .into_iter()
                .flat_map(|word| triton_asm!(push { word }))
                .collect::<Vec<_>>();
            let program = Program::new(&triton_asm!(
                push {INPUTS} push {OUTPUTS} push {MUTATOR_SET} push {EXPECTED}
                {&push_hash}
                call {snippet}
                halt
                {&library.all_imports()}
            ));
            let mut ram = HashMap::new();
            encode_to_memory(&mut ram, INPUTS, &self.inputs);
            encode_to_memory(&mut ram, OUTPUTS, &self.outputs);
            encode_to_memory(&mut ram, MUTATOR_SET, &self.before_removals);
            encode_to_memory(&mut ram, EXPECTED, expected);
            let nondeterminism = NonDeterminism::new(tokens).with_ram(ram);
            VMState::new(program, PublicInput::default(), nondeterminism).run()
        }

        fn assert_accepts(&self) {
            self.run(self.after_removals.hash(), &self.expected, self.tokens())
                .unwrap();
        }

        fn assert_rejects(
            &self,
            hash_after_removals: Digest,
            expected: &MutatorSetAccumulator,
            tokens: Vec<BFieldElement>,
            error_id: i128,
        ) {
            let id = match self.run(hash_after_removals, expected, tokens) {
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
    fn peaks_are_bound_by_the_hash_after_removals() {
        let fixture = fixture(7);
        let at = fixture.num_peaks_token();
        let tokens = fixture.tokens();
        assert!(tokens[at].value() >= 1, "the fixture must have peaks");
        let hash = fixture.after_removals.hash();
        let integrity = BlockValidationRule::MutatorSetUpdateIntegrity.error_id();

        // One peak too few or too many: the count disagrees with the leaf
        // count before the hash is compared.
        let count = BagPeaksFromList::INCONSISTENT_NUM_PEAKS_ERROR_ID;
        let mut fewer = tokens.clone();
        fewer[at] -= bfe!(1);
        fixture.assert_rejects(hash, &fixture.expected, fewer, count);

        let mut more = tokens.clone();
        more[at] += bfe!(1);
        more.extend([bfe!(0); Digest::LEN]);
        fixture.assert_rejects(hash, &fixture.expected, more, count);

        for word in 0..Digest::LEN {
            let mut tampered = tokens.clone();
            tampered[at + 1 + word] += bfe!(1);
            fixture.assert_rejects(hash, &fixture.expected, tampered, integrity);
        }
    }

    #[test]
    fn peak_count_must_be_a_u32() {
        let fixture = fixture(7);
        let mut tokens = fixture.tokens();
        tokens[fixture.num_peaks_token()] = bfe!(1_u64 << 32);
        assert!(matches!(
            fixture.run(fixture.after_removals.hash(), &fixture.expected, tokens),
            Err(InstructionError::OpStackError(
                OpStackError::FailedU32Conversion(_)
            ))
        ));
    }

    #[test]
    fn other_hash_after_removals_is_rejected() {
        let fixture = fixture(7);
        fixture.assert_rejects(
            fixture.before_removals.hash(),
            &fixture.expected,
            fixture.tokens(),
            BlockValidationRule::MutatorSetUpdateIntegrity.error_id(),
        );
    }

    #[test]
    fn expected_set_differing_in_any_component_is_rejected() {
        let fixture = fixture(7);
        let honest = &fixture.expected;
        let rejects = |expected: &MutatorSetAccumulator| {
            fixture.assert_rejects(
                fixture.after_removals.hash(),
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
