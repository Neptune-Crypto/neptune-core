//! Two SWBFI update claims aggregated into one: from the mutator set the
//! left child starts on, removing both children's inputs yields the
//! mutator set the right child ends on. The claim has the leaf's input and
//! output layout, so a tree of aggregations over leaves is bound by its root
//! alone, and the leaf count in the output says how many leaves the root
//! stands on.
//!
//! The children are claims of the leaf program or of this one, and their
//! proofs are verified here. They must chain: the left child's input is
//! this claim's, and the right child's input is the mutator set the left
//! child outputs. The index sets' digests come as witness; the children's
//! peaks are recomputed from them, and this claim's over all of them.

use std::sync::OnceLock;

use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::data_type::Literal;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::library::Library;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::verifier::stark_verify::StarkVerify;

use super::correct_swbfi_update::CorrectSwbfiUpdate;
use super::removal_index_commitment::DigestPeaks;
use crate::block::block_validation_error::BlockValidationRule;
use crate::consensus_rule_set::ConsensusRuleSet;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::proof_abstractions::SecretWitness;

/// Where in an SWBFI update claim's output each part lies.
const OUTPUT_NUM_LEAVES: usize = 0;
const OUTPUT_COUNT: usize = 1;
const OUTPUT_MUTATOR_SET_HASH: usize = 2;
const OUTPUT_NUM_PEAKS: usize = OUTPUT_MUTATOR_SET_HASH + Digest::LEN;
const OUTPUT_PEAKS: usize = OUTPUT_NUM_PEAKS + 1;

/// An SWBFI update claim's output taken apart.
struct ClaimOutput {
    num_leaves: BFieldElement,
    count: usize,
    mutator_set_hash: Digest,
    peaks: Vec<Digest>,
}

impl ClaimOutput {
    fn parse(output: &[BFieldElement]) -> Self {
        let num_peaks = output[OUTPUT_NUM_PEAKS].value() as usize;
        assert_eq!(OUTPUT_PEAKS + Digest::LEN * num_peaks, output.len());
        Self {
            num_leaves: output[OUTPUT_NUM_LEAVES],
            count: output[OUTPUT_COUNT].value() as usize,
            mutator_set_hash: Digest::new(
                output[OUTPUT_MUTATOR_SET_HASH..OUTPUT_NUM_PEAKS]
                    .try_into()
                    .unwrap(),
            ),
            peaks: output[OUTPUT_PEAKS..]
                .chunks(Digest::LEN)
                .map(|words| Digest::new(words.try_into().unwrap()))
                .collect(),
        }
    }
}

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize, TasmObject)]
pub struct SwbfiUpdateAggregationWitness {
    left_claim: Claim,
    left_proof: Proof,
    right_claim: Claim,
    right_proof: Proof,

    /// The digests of the index sets both children cover, in order.
    index_set_digests: Vec<Digest>,
}

impl SwbfiUpdateAggregationWitness {
    pub fn new(
        left_claim: Claim,
        left_proof: Proof,
        right_claim: Claim,
        right_proof: Proof,
        index_set_digests: Vec<Digest>,
    ) -> Self {
        Self {
            left_claim,
            left_proof,
            right_claim,
            right_proof,
            index_set_digests,
        }
    }

    pub fn nondeterminism_for(&self, program: &SwbfiUpdateAggregation) -> NonDeterminism {
        let mut nondeterminism = NonDeterminism::default();
        encode_to_memory(
            &mut nondeterminism.ram,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self,
        );
        if program.verifies_children {
            let stark_verify = StarkVerify::new_with_dynamic_layout(Stark::default());
            stark_verify.update_nondeterminism(
                &mut nondeterminism,
                &self.left_proof,
                &self.left_claim,
            );
            stark_verify.update_nondeterminism(
                &mut nondeterminism,
                &self.right_proof,
                &self.right_claim,
            );
        }

        nondeterminism
    }
}

impl SecretWitness for SwbfiUpdateAggregationWitness {
    fn standard_input(&self) -> PublicInput {
        PublicInput::new(self.left_claim.input.clone())
    }

    fn output(&self) -> Vec<BFieldElement> {
        let left = ClaimOutput::parse(&self.left_claim.output);
        let right = ClaimOutput::parse(&self.right_claim.output);
        let digests = &self.index_set_digests;
        assert_eq!(left.peaks, DigestPeaks::peaks(&digests[..left.count]));
        assert_eq!(right.peaks, DigestPeaks::peaks(&digests[left.count..]));
        let peaks = DigestPeaks::peaks(digests);
        [
            vec![
                left.num_leaves + right.num_leaves,
                bfe!((left.count + right.count) as u64),
            ],
            right.mutator_set_hash.values().to_vec(),
            vec![bfe!(peaks.len() as u64)],
            peaks.iter().flat_map(|peak| peak.values()).collect(),
        ]
        .concat()
    }

    fn program(&self) -> Program {
        SwbfiUpdateAggregation::new().program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        self.nondeterminism_for(&SwbfiUpdateAggregation::new())
    }
}

/// Input and output as [`CorrectSwbfiUpdate`]'s, about both children's
/// inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, GetSize, BFieldCodec)]
pub struct SwbfiUpdateAggregation {
    /// Whether to verify the children's proofs. Only ever false in tests.
    ///
    /// A compile-time variable from the TASM perspective: two different
    /// programs are produced based on this value.
    verifies_children: bool,
}

impl SwbfiUpdateAggregation {
    #[expect(
        clippy::new_without_default,
        reason = "the other variant is for tests only"
    )]
    pub fn new() -> Self {
        Self {
            verifies_children: true,
        }
    }

    /// The claim aggregating these two over these index sets, as a block's
    /// appendix carries it. The children's proofs play no part in it.
    pub fn claim(left_claim: &Claim, right_claim: &Claim, index_set_digests: Vec<Digest>) -> Claim {
        SwbfiUpdateAggregationWitness::new(
            left_claim.clone(),
            Proof(vec![]),
            right_claim.clone(),
            Proof(vec![]),
            index_set_digests,
        )
        .claim()
        .about_version(
            ConsensusRuleSet::HardforkDelta
                .triton_proof_version()
                .version(),
        )
    }
}

impl TritonProgram for SwbfiUpdateAggregation {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        let mut library = Library::new();
        let audit_witness = library.import(Box::new(VerifyNdSiIntegrity::<
            SwbfiUpdateAggregationWitness,
        >::default()));
        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));
        let digest_peaks = library.import(Box::new(DigestPeaks));
        let hash_varlen = library.import(Box::new(HashVarlen));

        let own_program_digest_alloc = library.kmalloc(Digest::LEN as u32);
        let input_alloc = library.kmalloc(Digest::LEN as u32);

        let push_leaf_program_digest =
            Literal::Digest(CorrectSwbfiUpdate.hash()).push_to_stack_code();
        let version = ConsensusRuleSet::HardforkDelta
            .triton_proof_version()
            .version();
        let digests_are_equal = DataType::Digest.compare();
        let read_digest = triton_asm!(addi {Digest::LEN - 1} read_mem {Digest::LEN} pop 1);
        let chaining = BlockValidationRule::SwbfiUpdateChaining.error_id();

        // BEFORE: _ *list
        // AFTER:  _ [digest]
        let hash_digest_list = triton_asm!(
            dup 0 read_mem 1 pop 1 push {Digest::LEN} mul addi 1
            call {hash_varlen}
        );

        let check_child = "swbfi_update_aggregation_check_child".to_string();
        let audit_output = "swbfi_update_aggregation_audit_output".to_string();
        let write_peaks = "swbfi_update_aggregation_write_peaks".to_string();

        // The verifier crashes on an invalid proof; that crash carries no
        // error ID.
        let verify_left = if self.verifies_children {
            triton_asm!(
                // _ *w *left
                dup 0 dup 2 {&field!(SwbfiUpdateAggregationWitness::left_proof)}
                call {stark_verify}
            )
        } else {
            triton_asm!()
        };
        let verify_right = if self.verifies_children {
            triton_asm!(
                // _ *w *left_output *right
                dup 0 dup 3 {&field!(SwbfiUpdateAggregationWitness::right_proof)}
                call {stark_verify}
            )
        } else {
            triton_asm!()
        };

        let code = triton_asm!(
            dup 15 dup 15 dup 15 dup 15 dup 15
            push {own_program_digest_alloc.write_address()} write_mem {Digest::LEN} pop 1
            read_io {Digest::LEN}
            push {input_alloc.write_address()} write_mem {Digest::LEN} pop 1
            // _

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            hint witness = stack[0]
            dup 0 call {audit_witness} pop 1
            // _ *w

            dup 0 {&field!(SwbfiUpdateAggregationWitness::left_claim)}
            call {check_child}
            // _ *w *left [left_input]

            push {input_alloc.read_address()} read_mem {Digest::LEN} pop 1
            assert_vector error_id {chaining}
            pop {Digest::LEN}
            // _ *w *left

            {&verify_left}
            call {audit_output}
            // _ *w *left_output

            dup 1 {&field!(SwbfiUpdateAggregationWitness::right_claim)}
            call {check_child}
            // _ *w *left_output *right [right_input]

            dup 6 addi {OUTPUT_NUM_PEAKS} read_mem {Digest::LEN} pop 1
            assert_vector error_id {chaining}
            pop {Digest::LEN}
            // _ *w *left_output *right

            {&verify_right}
            call {audit_output}
            // _ *w *left_output *right_output

            dup 2 {&field!(SwbfiUpdateAggregationWitness::index_set_digests)}
            dup 0 read_mem 1 pop 1
            dup 3 addi {1 + OUTPUT_COUNT} read_mem 1 pop 1
            dup 3 addi {1 + OUTPUT_COUNT} read_mem 1 pop 1
            // _ *w *left_output *right_output *digests num_digests left_count right_count

            dup 1 dup 1 add pick 3 eq assert error_id {chaining}
            // _ *w *left_output *right_output *digests left_count right_count

            dup 2 push 0 dup 3 call {digest_peaks}
            {&hash_digest_list}
            dup 9 addi {1 + OUTPUT_NUM_PEAKS} {&hash_digest_list}
            assert_vector error_id {chaining}
            pop {Digest::LEN}
            // _ *w *left_output *right_output *digests left_count right_count

            dup 2 dup 2 dup 2 call {digest_peaks}
            {&hash_digest_list}
            dup 8 addi {1 + OUTPUT_NUM_PEAKS} {&hash_digest_list}
            assert_vector error_id {chaining}
            pop {Digest::LEN}
            // _ *w *left_output *right_output *digests left_count right_count

            dup 4 addi {1 + OUTPUT_NUM_LEAVES} read_mem 1 pop 1
            dup 4 addi {1 + OUTPUT_NUM_LEAVES} read_mem 1 pop 1
            add write_io 1
            dup 1 dup 1 add write_io 1
            dup 3 addi {OUTPUT_NUM_PEAKS} read_mem {Digest::LEN} pop 1 write_io {Digest::LEN}
            // _ *w *left_output *right_output *digests left_count right_count

            add push 0 place 1
            call {digest_peaks}
            // _ *w *left_output *right_output *peaks

            dup 0 read_mem 1 pop 1
            dup 0 write_io 1
            push {Digest::LEN} mul dup 1 add
            // _ *w *left_output *right_output *peaks *peaks_end

            swap 1 call {write_peaks}
            // _ *w *left_output *right_output *peaks_end *peaks_end

            pop 5
            halt

            // A claim of the leaf program or of this one, of the current
            // version, about one mutator set hash.
            // BEFORE: _ *claim
            // AFTER:  _ *claim [mutator_set_hash]
            {check_child}:
                dup 0 {&field!(Claim::program_digest)} {&read_digest}
                dup 4 dup 4 dup 4 dup 4 dup 4
                {&push_leaf_program_digest}
                {&digests_are_equal}
                place 5
                // _ *claim is_leaf [program_digest]

                push {own_program_digest_alloc.read_address()} read_mem {Digest::LEN} pop 1
                {&digests_are_equal}
                add assert error_id {chaining}
                // _ *claim

                dup 0 {&field!(Claim::version)} read_mem 1 pop 1
                push {version} eq assert error_id {chaining}
                dup 0 {&field_with_size!(Claim::input)}
                // _ *claim *input input_size

                // The size counts the length word the pointer points at.
                push {1 + Digest::LEN} eq assert error_id {chaining}
                addi {Digest::LEN} read_mem {Digest::LEN} pop 1
                swap 4 swap 1 swap 3 swap 1
                return

            // BEFORE: _ *claim
            // AFTER:  _ *output
            {audit_output}:
                {&field_with_size!(Claim::output)}
                dup 1 addi {1 + OUTPUT_NUM_PEAKS} read_mem 1 pop 1
                push {Digest::LEN} mul addi {1 + OUTPUT_PEAKS} eq
                assert error_id {chaining}
                return

            // INVARIANT: _ *end *peak[i]_previous_word
            {write_peaks}:
                dup 1 dup 1 eq skiz return
                addi {Digest::LEN} read_mem {Digest::LEN}
                addi {Digest::LEN} place {Digest::LEN}
                write_io {Digest::LEN}
                recurse

            {&library.all_imports()}
        );

        (library, code)
    }

    fn hash(&self) -> Digest {
        static VERIFYING: OnceLock<Digest> = OnceLock::new();
        static SKIPPING: OnceLock<Digest> = OnceLock::new();

        let cache = if self.verifies_children {
            &VERIFYING
        } else {
            &SKIPPING
        };

        *cache.get_or_init(|| self.program().hash())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::super::correct_swbfi_update::tests::archival_mutator_set_after;
    use super::super::correct_swbfi_update::tests::chained_witnesses;
    use super::super::correct_swbfi_update::CorrectSwbfiUpdateWitness;
    use super::super::removal_index_commitment::IndexSetDigests;
    use super::super::removal_index_commitment::RemovalIndexCommitment;
    use super::*;
    use crate::proof_abstractions::tasm::builtins as tasm;
    use crate::proof_abstractions::tasm::builtins::verify_stark;
    use crate::proof_abstractions::tasm::program::spec::TritonProgramSpecification;

    impl TritonProgramSpecification for SwbfiUpdateAggregation {
        fn source(&self) {
            let own_program_digest = tasm::own_program_digest();
            let mutator_set_hash = tasm::tasmlib_io_read_stdin___digest();
            let witness: SwbfiUpdateAggregationWitness =
                tasm::decode_from_memory(FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS);
            let version = ConsensusRuleSet::HardforkDelta
                .triton_proof_version()
                .version();

            let check_child = |claim: &Claim| {
                assert!(
                    claim.program_digest == CorrectSwbfiUpdate.hash()
                        || claim.program_digest == own_program_digest
                );
                assert_eq!(version, claim.version);
                assert_eq!(Digest::LEN, claim.input.len());
                Digest::new(claim.input.clone().try_into().unwrap()).reversed()
            };

            assert_eq!(mutator_set_hash, check_child(&witness.left_claim));
            if self.verifies_children {
                verify_stark(Stark::default(), &witness.left_claim, &witness.left_proof);
            }
            let left = ClaimOutput::parse(&witness.left_claim.output);

            assert_eq!(left.mutator_set_hash, check_child(&witness.right_claim));
            if self.verifies_children {
                verify_stark(Stark::default(), &witness.right_claim, &witness.right_proof);
            }
            let right = ClaimOutput::parse(&witness.right_claim.output);

            let digests = &witness.index_set_digests;
            assert_eq!(left.count + right.count, digests.len());
            assert_eq!(left.peaks, DigestPeaks::peaks(&digests[..left.count]));
            assert_eq!(right.peaks, DigestPeaks::peaks(&digests[left.count..]));

            tasm::tasmlib_io_write_to_stdout___bfe(left.num_leaves + right.num_leaves);
            tasm::tasmlib_io_write_to_stdout___bfe(bfe!((left.count + right.count) as u64));
            tasm::tasmlib_io_write_to_stdout___digest(right.mutator_set_hash);
            let peaks = DigestPeaks::peaks(digests);
            tasm::tasmlib_io_write_to_stdout___bfe(bfe!(peaks.len() as u64));
            for peak in peaks {
                tasm::tasmlib_io_write_to_stdout___digest(peak);
            }
        }
    }

    fn skipping() -> SwbfiUpdateAggregation {
        SwbfiUpdateAggregation {
            verifies_children: false,
        }
    }

    /// The claim of a leaf, or of an aggregation of the skipping program,
    /// with a placeholder proof.
    fn child(claim: Claim) -> (Claim, Proof) {
        (claim, Proof(vec![]))
    }

    /// The digests of these leaves' index sets, in order.
    fn index_set_digests(leaves: &[CorrectSwbfiUpdateWitness]) -> Vec<Digest> {
        leaves
            .iter()
            .flat_map(|leaf| IndexSetDigests::digests(leaf.inputs()))
            .collect()
    }

    /// A witness aggregating the leaves over these consecutive segments of
    /// one block's inputs, with placeholder proofs.
    fn witness_over_leaves(
        left_size: usize,
        right_size: usize,
        seed: u64,
    ) -> (
        SwbfiUpdateAggregationWitness,
        Vec<CorrectSwbfiUpdateWitness>,
    ) {
        let leaves = chained_witnesses(&[left_size, right_size], seed);
        let (left, left_proof) = child(leaves[0].versioned_claim());
        let (right, right_proof) = child(leaves[1].versioned_claim());
        let witness = SwbfiUpdateAggregationWitness::new(
            left,
            left_proof,
            right,
            right_proof,
            index_set_digests(&leaves),
        );
        (witness, leaves)
    }

    fn outputs(witness: &SwbfiUpdateAggregationWitness) -> Vec<BFieldElement> {
        let input = witness.standard_input();
        let nondeterminism = witness.nondeterminism_for(&skipping());
        let rust_output = skipping().run_rust(&input, nondeterminism.clone()).unwrap();
        let tasm_output = skipping().run_tasm(&input, nondeterminism).unwrap();
        assert_eq!(rust_output, tasm_output);
        assert_eq!(witness.output(), tasm_output);
        tasm_output
    }

    fn assert_rejects(witness: &SwbfiUpdateAggregationWitness, input: Option<PublicInput>) {
        skipping()
            .test_assertion_failure(
                input.unwrap_or_else(|| witness.standard_input()),
                witness.nondeterminism_for(&skipping()),
                &[BlockValidationRule::SwbfiUpdateChaining.error_id()],
            )
            .unwrap();
    }

    #[test]
    fn honest_leaves_aggregate_to_all_their_inputs() {
        for (left_size, right_size, seed) in [(1, 1, 0), (2, 3, 1), (4, 4, 2), (3, 0, 3)] {
            let (witness, leaves) = witness_over_leaves(left_size, right_size, seed);
            let output = outputs(&witness);
            let parsed = ClaimOutput::parse(&output);

            assert_eq!(bfe!(2), parsed.num_leaves);
            assert_eq!(left_size + right_size, parsed.count);
            assert_eq!(
                archival_mutator_set_after(&leaves[1]).hash(),
                parsed.mutator_set_hash
            );
            let all_inputs = [leaves[0].inputs(), leaves[1].inputs()].concat();
            assert_eq!(
                RemovalIndexCommitment::peaks(&all_inputs),
                parsed.peaks,
                "{left_size} + {right_size} inputs"
            );
        }
    }

    #[test]
    fn aggregation_of_aggregation_and_leaf_is_accepted() {
        let leaves = chained_witnesses(&[1, 2, 3], 4);
        let (left, left_proof) = child(leaves[0].versioned_claim());
        let (middle, middle_proof) = child(leaves[1].versioned_claim());
        let lower = SwbfiUpdateAggregationWitness::new(
            left,
            left_proof,
            middle,
            middle_proof,
            index_set_digests(&leaves[..2]),
        );
        let lower_claim = Claim::about_program(&skipping().program())
            .with_input(lower.standard_input().individual_tokens)
            .with_output(outputs(&lower))
            .about_version(
                ConsensusRuleSet::HardforkDelta
                    .triton_proof_version()
                    .version(),
            );

        let (lower_claim, lower_proof) = child(lower_claim);
        let (right, right_proof) = child(leaves[2].versioned_claim());
        let upper = SwbfiUpdateAggregationWitness::new(
            lower_claim,
            lower_proof,
            right,
            right_proof,
            index_set_digests(&leaves),
        );
        let parsed = ClaimOutput::parse(&outputs(&upper));

        assert_eq!(bfe!(3), parsed.num_leaves);
        assert_eq!(6, parsed.count);
        let all_inputs = leaves
            .iter()
            .flat_map(|leaf| leaf.inputs().to_vec())
            .collect::<Vec<_>>();
        assert_eq!(RemovalIndexCommitment::peaks(&all_inputs), parsed.peaks);
    }

    #[test]
    fn left_child_about_other_mutator_set_is_rejected() {
        let (witness, _) = witness_over_leaves(2, 2, 5);
        let mut input = witness.standard_input();
        input.individual_tokens[0] += bfe!(1);
        assert_rejects(&witness, Some(input));
    }

    #[test]
    fn right_child_not_starting_where_left_ends_is_rejected() {
        let (mut witness, _) = witness_over_leaves(2, 2, 5);
        witness.right_claim.input[0] += bfe!(1);
        assert_rejects(&witness, None);
    }

    #[test]
    fn other_index_set_digests_are_rejected() {
        let (mut witness, _) = witness_over_leaves(2, 2, 5);
        witness.index_set_digests[3] = Digest::default();
        assert_rejects(&witness, None);
    }

    #[test]
    fn index_set_digests_not_covering_the_children_are_rejected() {
        let (mut witness, _) = witness_over_leaves(2, 2, 5);
        witness.index_set_digests.pop();
        assert_rejects(&witness, None);
    }

    #[test]
    fn child_of_other_program_is_rejected() {
        let (mut witness, _) = witness_over_leaves(2, 2, 5);
        witness.left_claim.program_digest = Digest::default();
        assert_rejects(&witness, None);
    }

    #[test]
    fn child_of_other_version_is_rejected() {
        let (mut witness, _) = witness_over_leaves(2, 2, 5);
        witness.right_claim.version += 1;
        assert_rejects(&witness, None);
    }

    #[test]
    fn child_with_malformed_output_is_rejected() {
        let (mut witness, _) = witness_over_leaves(2, 2, 5);
        witness.left_claim.output.push(bfe!(0));
        assert_rejects(&witness, None);
    }

    /// The tests that need the leaves' proofs in the witness: they run the
    /// variant of this program that verifies them.
    mod require_proof {
        use super::*;
        use crate::proof_abstractions::tasm::program::proof_cache::load_proof_or_produce_and_save;

        /// A leaf's claim with its proof from the proof cache.
        fn proven_leaf(leaf: &CorrectSwbfiUpdateWitness) -> (Claim, Proof) {
            let claim = leaf.versioned_claim();
            let proof = load_proof_or_produce_and_save(
                &claim,
                CorrectSwbfiUpdate.program(),
                leaf.nondeterminism(),
            );
            (claim, proof.into())
        }

        #[test]
        fn proven_leaves_aggregate() {
            let leaves = chained_witnesses(&[1, 2], 8);
            let (left, left_proof) = proven_leaf(&leaves[0]);
            let (right, right_proof) = proven_leaf(&leaves[1]);
            let witness = SwbfiUpdateAggregationWitness::new(
                left,
                left_proof,
                right,
                right_proof,
                index_set_digests(&leaves),
            );
            let program = SwbfiUpdateAggregation::new();
            let input = witness.standard_input();
            let nondeterminism = witness.nondeterminism_for(&program);

            let rust_output = program.run_rust(&input, nondeterminism.clone()).unwrap();
            let tasm_output = program.run_tasm(&input, nondeterminism).unwrap();
            assert_eq!(rust_output, tasm_output);
            assert_eq!(witness.output(), tasm_output);
        }
    }

    /// Prints how the program's cycles and table rows distribute over its
    /// subroutines, without the children's proof verification.
    #[test]
    #[ignore = "prints a profile"]
    fn profile_aggregation() {
        let (witness, _) = witness_over_leaves(8, 8, 6);
        let profile = tasm_lib::generate_full_profile(
            "two leaves of 8 inputs",
            skipping().program(),
            &witness.standard_input(),
            &witness.nondeterminism_for(&skipping()),
        );
        println!("{profile}");
    }
}
