//! Two SWBFI update claims built on the same mutator set united into one:
//! from that mutator set, removing both children's inputs yields the
//! mutator set this claim outputs. The claim has the leaf's input and
//! output layout, so a tree of unions over leaves is bound by its root
//! alone, and the leaf count in the output says how many leaves the root
//! stands on.
//!
//! The children are claims of the leaf program or of this one, both about
//! this claim's mutator set, and their proofs are verified here. The
//! children's inputs come as witness, with their chunks, and so does their
//! union as one list of the same form: the index sets must be the
//! children's in order, and the removals are applied from the shared
//! mutator set three times, once per child to match their outputs and once
//! for the union.

use std::sync::OnceLock;

use get_size2::GetSize;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_mutator_set::removal_record::RemovalRecord;
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
use super::correct_swbfi_update::CorrectSwbfiUpdateWitness;
use super::mutator_set_hash::MutatorSetHash;
use super::mutator_set_hash_after_removals::MutatorSetHashAfterRemovals;
use super::removal_index_commitment::DigestPeaks;
use super::removal_index_commitment::IndexSetDigests;
use super::swbfi_peaks_after_removals::SwbfiPeaksAfterRemovals;
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
pub struct SwbfiUpdateUnionWitness {
    left_claim: Claim,
    left_proof: Proof,
    right_claim: Claim,
    right_proof: Proof,

    /// The children's inputs in the witness's form, with their chunks, and
    /// both together as one such list; all built on the mutator set.
    left_inputs: Vec<RemovalRecord>,
    right_inputs: Vec<RemovalRecord>,
    united_inputs: Vec<RemovalRecord>,
    mutator_set: MutatorSetAccumulator,
}

impl SwbfiUpdateUnionWitness {
    /// The union of these two leaves, built on one mutator set, with these
    /// claims about them.
    pub fn new(
        left_claim: Claim,
        left_proof: Proof,
        right_claim: Claim,
        right_proof: Proof,
        left: &CorrectSwbfiUpdateWitness,
        right: &CorrectSwbfiUpdateWitness,
    ) -> Self {
        assert_eq!(left.mutator_set(), right.mutator_set());
        Self {
            left_claim,
            left_proof,
            right_claim,
            right_proof,
            left_inputs: left.inputs().to_vec(),
            right_inputs: right.inputs().to_vec(),
            united_inputs: SwbfiPeaksAfterRemovals::witness_form(
                CorrectSwbfiUpdateWitness::united_inputs(&[left, right]),
                left.mutator_set(),
            ),
            mutator_set: left.mutator_set().clone(),
        }
    }

    pub fn nondeterminism_for(&self, program: &SwbfiUpdateUnion) -> NonDeterminism {
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
        nondeterminism.individual_tokens = [
            MutatorSetHashAfterRemovals::divined_tokens(&self.left_inputs, &self.mutator_set),
            MutatorSetHashAfterRemovals::divined_tokens(&self.right_inputs, &self.mutator_set),
            MutatorSetHashAfterRemovals::divined_tokens(&self.united_inputs, &self.mutator_set),
        ]
        .concat();

        nondeterminism
    }
}

impl SecretWitness for SwbfiUpdateUnionWitness {
    fn standard_input(&self) -> PublicInput {
        PublicInput::new(CorrectSwbfiUpdate::claim_input(&self.mutator_set))
    }

    fn output(&self) -> Vec<BFieldElement> {
        let left = ClaimOutput::parse(&self.left_claim.output);
        let right = ClaimOutput::parse(&self.right_claim.output);
        let packed = |inputs: &[RemovalRecord]| {
            SwbfiPeaksAfterRemovals::packed_form(inputs.to_vec(), &self.mutator_set)
        };
        for (child, inputs) in [(&left, &self.left_inputs), (&right, &self.right_inputs)] {
            assert_eq!(child.count, inputs.len());
            assert_eq!(
                child.mutator_set_hash,
                SwbfiPeaksAfterRemovals::apply_removals(&packed(inputs), &self.mutator_set).hash()
            );
            assert_eq!(
                child.peaks,
                DigestPeaks::peaks(&IndexSetDigests::digests(inputs))
            );
        }
        let mutator_set_after = SwbfiPeaksAfterRemovals::apply_removals(
            &packed(&self.united_inputs),
            &self.mutator_set,
        );
        let peaks = DigestPeaks::peaks(&IndexSetDigests::digests(&self.united_inputs));
        [
            vec![
                left.num_leaves + right.num_leaves,
                bfe!(self.united_inputs.len() as u64),
            ],
            mutator_set_after.hash().values().to_vec(),
            vec![bfe!(peaks.len() as u64)],
            peaks.iter().flat_map(|peak| peak.values()).collect(),
        ]
        .concat()
    }

    fn program(&self) -> Program {
        SwbfiUpdateUnion::new().program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        self.nondeterminism_for(&SwbfiUpdateUnion::new())
    }
}

/// Input and output as [`CorrectSwbfiUpdate`]'s, about both children's
/// inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, GetSize, BFieldCodec)]
pub struct SwbfiUpdateUnion {
    /// Whether to verify the children's proofs. Only ever false in tests.
    ///
    /// A compile-time variable from the TASM perspective: two different
    /// programs are produced based on this value.
    verifies_children: bool,
}

impl SwbfiUpdateUnion {
    #[expect(
        clippy::new_without_default,
        reason = "the other variant is for tests only"
    )]
    pub fn new() -> Self {
        Self {
            verifies_children: true,
        }
    }

    /// The claim uniting these two leaves, as a block's appendix carries it.
    pub fn claim(left: &CorrectSwbfiUpdateWitness, right: &CorrectSwbfiUpdateWitness) -> Claim {
        SwbfiUpdateUnionWitness::new(
            left.versioned_claim(),
            Proof(vec![]),
            right.versioned_claim(),
            Proof(vec![]),
            left,
            right,
        )
        .claim()
        .about_version(
            ConsensusRuleSet::HardforkDelta
                .triton_proof_version()
                .version(),
        )
    }
}

impl TritonProgram for SwbfiUpdateUnion {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        let mut library = Library::new();
        let audit_witness = library.import(Box::new(
            VerifyNdSiIntegrity::<SwbfiUpdateUnionWitness>::default(),
        ));
        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));
        let mutator_set_hash = library.import(Box::new(MutatorSetHash));
        let hash_after_removals = library.import(Box::new(MutatorSetHashAfterRemovals));
        let index_set_digests = library.import(Box::new(IndexSetDigests));
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
        let union = BlockValidationRule::SwbfiUpdateUnion.error_id();

        // BEFORE: _ *list
        // AFTER:  _ [digest]
        let hash_digest_list = triton_asm!(
            dup 0 read_mem 1 pop 1 push {Digest::LEN} mul addi 1
            call {hash_varlen}
        );

        // BEFORE: _ *digests
        // AFTER:  _ *digests [hash(peaks)]
        let hash_peaks = triton_asm!(
            dup 0 dup 0 read_mem 1 pop 1 push 0 place 1
            call {digest_peaks}
            {&hash_digest_list}
        );

        let check_child = "swbfi_update_union_check_child".to_string();
        let audit_output = "swbfi_update_union_audit_output".to_string();
        let compare_words = "swbfi_update_union_compare_words".to_string();
        let write_peaks = "swbfi_update_union_write_peaks".to_string();

        // The verifier crashes on an invalid proof; that crash carries no
        // error ID.
        let verify_left = if self.verifies_children {
            triton_asm!(
                // _ *w *left
                dup 0 dup 2 {&field!(SwbfiUpdateUnionWitness::left_proof)}
                call {stark_verify}
            )
        } else {
            triton_asm!()
        };
        let verify_right = if self.verifies_children {
            triton_asm!(
                // _ *w *left_output *right
                dup 0 dup 3 {&field!(SwbfiUpdateUnionWitness::right_proof)}
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

            dup 0 {&field!(SwbfiUpdateUnionWitness::mutator_set)}
            call {mutator_set_hash}
            push {input_alloc.read_address()} read_mem {Digest::LEN} pop 1
            assert_vector error_id {BlockValidationRule::TransactionMutatorSetMismatch.error_id()}
            pop {Digest::LEN}
            // _ *w

            dup 0 {&field!(SwbfiUpdateUnionWitness::left_claim)}
            call {check_child}
            push {input_alloc.read_address()} read_mem {Digest::LEN} pop 1
            assert_vector error_id {union}
            pop {Digest::LEN}
            // _ *w *left

            {&verify_left}
            call {audit_output}
            // _ *w *left_output

            dup 1 {&field!(SwbfiUpdateUnionWitness::right_claim)}
            call {check_child}
            push {input_alloc.read_address()} read_mem {Digest::LEN} pop 1
            assert_vector error_id {union}
            pop {Digest::LEN}
            // _ *w *left_output *right

            {&verify_right}
            call {audit_output}
            // _ *w *left_output *right_output

            dup 2 {&field!(SwbfiUpdateUnionWitness::left_inputs)} call {index_set_digests}
            dup 3 {&field!(SwbfiUpdateUnionWitness::right_inputs)} call {index_set_digests}
            dup 4 {&field!(SwbfiUpdateUnionWitness::united_inputs)} call {index_set_digests}
            // _ *w *left_output *right_output *left_digests *right_digests *united_digests

            /* The children's peaks are those of their index sets. */
            dup 2 {&hash_peaks}
            dup 10 addi {1 + OUTPUT_NUM_PEAKS} {&hash_digest_list}
            assert_vector error_id {union}
            pop {Digest::LEN} pop 1
            dup 1 {&hash_peaks}
            dup 9 addi {1 + OUTPUT_NUM_PEAKS} {&hash_digest_list}
            assert_vector error_id {union}
            pop {Digest::LEN} pop 1
            // _ *w *left_output *right_output *left_digests *right_digests *united_digests

            /* The united index sets are the left ones, then the right ones. */
            dup 0 read_mem 1 pop 1
            dup 3 read_mem 1 pop 1 dup 3 read_mem 1 pop 1 add
            eq assert error_id {union}
            dup 2 read_mem 1 pop 1 push {Digest::LEN} mul
            // _ *w *left_output *right_output *left_digests *right_digests *united_digests left_words

            dup 3 dup 1 add
            dup 2 dup 2 add
            dup 2
            call {compare_words} pop 3
            // _ *w *left_output *right_output *left_digests *right_digests *united_digests left_words

            dup 2 read_mem 1 pop 1 push {Digest::LEN} mul
            dup 3 dup 1 add
            dup 3 dup 3 dup 3 add add
            dup 2
            call {compare_words} pop 3
            pop 2
            // _ *w *left_output *right_output *left_digests *right_digests *united_digests

            /* The children's mutator sets are those after their removals. */
            dup 5 {&field!(SwbfiUpdateUnionWitness::left_inputs)}
            dup 6 {&field!(SwbfiUpdateUnionWitness::mutator_set)}
            call {hash_after_removals}
            dup 9 addi {OUTPUT_NUM_PEAKS} read_mem {Digest::LEN} pop 1
            assert_vector error_id {union}
            pop {Digest::LEN}
            dup 5 {&field!(SwbfiUpdateUnionWitness::right_inputs)}
            dup 6 {&field!(SwbfiUpdateUnionWitness::mutator_set)}
            call {hash_after_removals}
            dup 8 addi {OUTPUT_NUM_PEAKS} read_mem {Digest::LEN} pop 1
            assert_vector error_id {union}
            pop {Digest::LEN}
            // _ *w *left_output *right_output *left_digests *right_digests *united_digests

            dup 4 addi {1 + OUTPUT_NUM_LEAVES} read_mem 1 pop 1
            dup 4 addi {1 + OUTPUT_NUM_LEAVES} read_mem 1 pop 1
            add write_io 1
            dup 0 read_mem 1 pop 1 write_io 1
            dup 5 {&field!(SwbfiUpdateUnionWitness::united_inputs)}
            dup 6 {&field!(SwbfiUpdateUnionWitness::mutator_set)}
            call {hash_after_removals}
            write_io {Digest::LEN}
            // _ *w *left_output *right_output *left_digests *right_digests *united_digests

            dup 0 read_mem 1 pop 1 push 0 place 1
            call {digest_peaks}
            dup 0 read_mem 1 pop 1
            dup 0 write_io 1
            push {Digest::LEN} mul dup 1 add
            // _ *w *left_output *right_output *left_digests *right_digests *peaks *peaks_end

            swap 1 call {write_peaks}
            pop 5 pop 2
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
                add assert error_id {union}
                // _ *claim

                dup 0 {&field!(Claim::version)} read_mem 1 pop 1
                push {version} eq assert error_id {union}
                dup 0 {&field_with_size!(Claim::input)}
                // _ *claim *input input_size

                // The size counts the length word the pointer points at.
                push {1 + Digest::LEN} eq assert error_id {union}
                addi {Digest::LEN} read_mem {Digest::LEN} pop 1
                swap 4 swap 1 swap 3 swap 1
                return

            // BEFORE: _ *claim
            // AFTER:  _ *output
            {audit_output}:
                {&field_with_size!(Claim::output)}
                dup 1 addi {1 + OUTPUT_NUM_PEAKS} read_mem 1 pop 1
                push {Digest::LEN} mul addi {1 + OUTPUT_PEAKS} eq
                assert error_id {union}
                return

            // The n words at two addresses and below must agree.
            // INVARIANT: _ *a *b n
            {compare_words}:
                dup 0 push 0 eq skiz return
                pick 2 read_mem 1 place 3
                pick 2 read_mem 1 place 3
                // _ (*a - 1) (*b - 1) n a b

                eq assert error_id {union}
                addi -1
                recurse

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
    use neptune_mutator_set::removal_record::chunk::Chunk;
    use neptune_mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
    use neptune_mutator_set::removal_record::removal_record_list::RemovalRecordList;
    use tasm_lib::twenty_first::prelude::MmrMembershipProof;

    use super::super::correct_swbfi_update::tests::archival_mutator_set_after;
    use super::super::correct_swbfi_update::tests::sibling_witnesses;
    use super::super::removal_index_commitment::RemovalIndexCommitment;
    use super::super::window_after_removals::WindowAfterRemovals;
    use super::*;
    use crate::proof_abstractions::tasm::builtins as tasm;
    use crate::proof_abstractions::tasm::builtins::verify_stark;
    use crate::proof_abstractions::tasm::program::spec::TritonProgramSpecification;

    /// The mutator set after these removals, the way the program computes
    /// it from the divined peaks and window.
    fn mutator_set_after(
        inputs: &[RemovalRecord],
        mutator_set: &MutatorSetAccumulator,
    ) -> MutatorSetAccumulator {
        use tasm_lib::twenty_first::prelude::Mmr;
        use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

        let peaks = SwbfiPeaksAfterRemovals::verify(inputs, mutator_set);
        let window = WindowAfterRemovals::verify(inputs, mutator_set);
        let mut after = mutator_set.clone();
        after.swbf_inactive = MmrAccumulator::init(peaks, mutator_set.swbf_inactive.num_leafs());
        after.swbf_active = window;
        after
    }

    impl TritonProgramSpecification for SwbfiUpdateUnion {
        fn source(&self) {
            let own_program_digest = tasm::own_program_digest();
            let mutator_set_hash = tasm::tasmlib_io_read_stdin___digest();
            let witness: SwbfiUpdateUnionWitness =
                tasm::decode_from_memory(FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS);
            let version = ConsensusRuleSet::HardforkDelta
                .triton_proof_version()
                .version();
            assert_eq!(mutator_set_hash, witness.mutator_set.hash());

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
            assert_eq!(mutator_set_hash, check_child(&witness.right_claim));
            if self.verifies_children {
                verify_stark(Stark::default(), &witness.right_claim, &witness.right_proof);
            }
            let right = ClaimOutput::parse(&witness.right_claim.output);

            let left_digests = IndexSetDigests::digests(&witness.left_inputs);
            let right_digests = IndexSetDigests::digests(&witness.right_inputs);
            let united_digests = IndexSetDigests::digests(&witness.united_inputs);
            assert_eq!(left.peaks, DigestPeaks::peaks(&left_digests));
            assert_eq!(right.peaks, DigestPeaks::peaks(&right_digests));
            assert_eq!([left_digests, right_digests].concat(), united_digests);

            let mutator_set = &witness.mutator_set;
            assert_eq!(
                left.mutator_set_hash,
                mutator_set_after(&witness.left_inputs, mutator_set).hash()
            );
            assert_eq!(
                right.mutator_set_hash,
                mutator_set_after(&witness.right_inputs, mutator_set).hash()
            );

            tasm::tasmlib_io_write_to_stdout___bfe(left.num_leaves + right.num_leaves);
            tasm::tasmlib_io_write_to_stdout___bfe(bfe!(united_digests.len() as u64));
            tasm::tasmlib_io_write_to_stdout___digest(
                mutator_set_after(&witness.united_inputs, mutator_set).hash(),
            );
            let peaks = DigestPeaks::peaks(&united_digests);
            tasm::tasmlib_io_write_to_stdout___bfe(bfe!(peaks.len() as u64));
            for peak in peaks {
                tasm::tasmlib_io_write_to_stdout___digest(peak);
            }
        }
    }

    fn skipping() -> SwbfiUpdateUnion {
        SwbfiUpdateUnion {
            verifies_children: false,
        }
    }

    /// A witness uniting two leaves over these many inputs each, all built
    /// on one mutator set, with placeholder proofs.
    fn witness_over_leaves(
        left_size: usize,
        right_size: usize,
        seed: u64,
    ) -> (SwbfiUpdateUnionWitness, Vec<CorrectSwbfiUpdateWitness>) {
        let leaves = sibling_witnesses(&[left_size, right_size], seed);
        let witness = SwbfiUpdateUnionWitness::new(
            leaves[0].versioned_claim(),
            Proof(vec![]),
            leaves[1].versioned_claim(),
            Proof(vec![]),
            &leaves[0],
            &leaves[1],
        );
        (witness, leaves)
    }

    fn outputs(witness: &SwbfiUpdateUnionWitness) -> Vec<BFieldElement> {
        let input = witness.standard_input();
        let nondeterminism = witness.nondeterminism_for(&skipping());
        let rust_output = skipping().run_rust(&input, nondeterminism.clone()).unwrap();
        let tasm_output = skipping().run_tasm(&input, nondeterminism).unwrap();
        assert_eq!(rust_output, tasm_output);
        assert_eq!(witness.output(), tasm_output);
        tasm_output
    }

    fn assert_rejects(witness: &SwbfiUpdateUnionWitness, error_id: i128) {
        skipping()
            .test_assertion_failure(
                witness.standard_input(),
                witness.nondeterminism_for(&skipping()),
                &[error_id],
            )
            .unwrap();
    }

    #[test]
    fn honest_leaves_unite_to_all_their_inputs() {
        for (left_size, right_size, seed) in [(1, 1, 0), (2, 3, 1), (4, 4, 2), (3, 0, 3)] {
            let (witness, leaves) = witness_over_leaves(left_size, right_size, seed);
            let parsed = ClaimOutput::parse(&outputs(&witness));

            assert_eq!(bfe!(2), parsed.num_leaves);
            assert_eq!(left_size + right_size, parsed.count);
            let all_inputs = [leaves[0].inputs(), leaves[1].inputs()].concat();
            assert_eq!(RemovalIndexCommitment::peaks(&all_inputs), parsed.peaks);

            // The hash is that of the mutator set the archival update
            // computes for all the inputs.
            let all = CorrectSwbfiUpdateWitness::new(
                CorrectSwbfiUpdateWitness::united_inputs(&[&leaves[0], &leaves[1]]),
                leaves[0].mutator_set().clone(),
            );
            assert_eq!(
                archival_mutator_set_after(&all).hash(),
                parsed.mutator_set_hash,
                "{left_size} + {right_size} inputs"
            );
        }
    }

    #[test]
    fn union_of_union_and_leaf_is_accepted() {
        let leaves = sibling_witnesses(&[1, 2, 3], 4);
        let lower = SwbfiUpdateUnionWitness::new(
            leaves[0].versioned_claim(),
            Proof(vec![]),
            leaves[1].versioned_claim(),
            Proof(vec![]),
            &leaves[0],
            &leaves[1],
        );
        let lower_claim = Claim::about_program(&skipping().program())
            .with_input(lower.standard_input().individual_tokens)
            .with_output(outputs(&lower))
            .about_version(
                ConsensusRuleSet::HardforkDelta
                    .triton_proof_version()
                    .version(),
            );
        let lower_as_leaf = CorrectSwbfiUpdateWitness::new(
            SwbfiPeaksAfterRemovals::packed_form(lower.united_inputs.clone(), &lower.mutator_set),
            lower.mutator_set.clone(),
        );

        let upper = SwbfiUpdateUnionWitness::new(
            lower_claim,
            Proof(vec![]),
            leaves[2].versioned_claim(),
            Proof(vec![]),
            &lower_as_leaf,
            &leaves[2],
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

    /// The witness's three input lists.
    fn inputs_of(witness: &mut SwbfiUpdateUnionWitness, list: usize) -> &mut Vec<RemovalRecord> {
        match list {
            0 => &mut witness.left_inputs,
            1 => &mut witness.right_inputs,
            _ => &mut witness.united_inputs,
        }
    }

    /// Applies a spread of the modifications of single chunk dictionary
    /// entries, over every entry of every input of every list, each to a
    /// fresh copy of the witness, and expects the rule 2.b rejection.
    /// Returns how many modifications there were to choose from.
    fn spread_of_tampered_entries_is_rejected(
        honest: &SwbfiUpdateUnionWitness,
        at_most: usize,
        variants: impl Fn(
            &(u64, (MmrMembershipProof, Chunk)),
        ) -> Vec<(u64, (MmrMembershipProof, Chunk))>,
    ) -> usize {
        let mut modifications = vec![];
        for list in 0..3 {
            let records = inputs_of(&mut honest.clone(), list).clone();
            for (input, record) in records.iter().enumerate() {
                for (position, entry) in record.target_chunks.iter().enumerate() {
                    for tampered_entry in variants(entry) {
                        modifications.push((list, input, position, tampered_entry));
                    }
                }
            }
        }
        let total = modifications.len();
        let stride = total.div_ceil(at_most).max(1);
        for (list, input, position, tampered_entry) in modifications.into_iter().step_by(stride) {
            let mut witness = honest.clone();
            let inputs = inputs_of(&mut witness, list);
            let mut entries = inputs[input].target_chunks.clone().into_inner();
            entries[position] = tampered_entry;
            inputs[input].target_chunks = ChunkDictionary::new_in_given_order(entries);
            assert_rejects(
                &witness,
                BlockValidationRule::RemovalRecordsValidity.error_id(),
            );
        }
        total
    }

    /// Path digests are load-bearing in each of the three input lists: a
    /// spread over every word of every path digest. The leaf's and the
    /// snippet's tests go deeper.
    #[test]
    fn spread_of_path_digest_words_is_rejected() {
        let (honest, _) = witness_over_leaves(2, 2, 5);
        let total =
            spread_of_tampered_entries_is_rejected(&honest, 24, |(height, (proof, chunk))| {
                if *height >= 2 * RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET {
                    return vec![];
                }
                (0..proof.authentication_path.len())
                    .flat_map(|digest| (0..Digest::LEN).map(move |word| (digest, word)))
                    .map(|(digest, word)| {
                        let mut proof = proof.clone();
                        proof.authentication_path[digest].0[word] += bfe!(1);
                        (*height, (proof, chunk.clone()))
                    })
                    .collect()
            });
        assert!(total > 3 * Digest::LEN, "the test data must hold paths");
    }

    /// Chunk contents are load-bearing in each of the three input lists: a
    /// spread over an entry added to every chunk and every entry changed
    /// and removed.
    #[test]
    fn spread_of_chunk_entry_changes_is_rejected() {
        let (honest, _) = witness_over_leaves(2, 2, 5);
        let total =
            spread_of_tampered_entries_is_rejected(&honest, 24, |(height, (proof, chunk))| {
                if *height >= RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET
                    && *height != RemovalRecordList::ENCODING_DELIMITER_IGNORE_TREE_HEIGHT
                {
                    return vec![];
                }
                let with = |indices: Vec<u32>| {
                    (
                        *height,
                        (
                            proof.clone(),
                            Chunk {
                                relative_indices: indices,
                            },
                        ),
                    )
                };
                let mut variants = vec![with([vec![0], chunk.relative_indices.clone()].concat())];
                for index in 0..chunk.relative_indices.len() {
                    let mut changed = chunk.relative_indices.clone();
                    changed[index] = if changed[index] == 0 {
                        1
                    } else {
                        changed[index] - 1
                    };
                    variants.push(with(changed));
                    let mut removed = chunk.relative_indices.clone();
                    removed.remove(index);
                    variants.push(with(removed));
                }
                variants
            });
        assert!(total > 3, "the test data must hold chunks");
    }

    #[test]
    fn child_about_other_mutator_set_is_rejected() {
        let (mut witness, _) = witness_over_leaves(2, 2, 5);
        witness.right_claim.input[0] += bfe!(1);
        assert_rejects(&witness, BlockValidationRule::SwbfiUpdateUnion.error_id());
    }

    #[test]
    fn child_outputting_other_mutator_set_is_rejected() {
        let (mut witness, _) = witness_over_leaves(2, 2, 5);
        witness.left_claim.output[OUTPUT_MUTATOR_SET_HASH] += bfe!(1);
        assert_rejects(&witness, BlockValidationRule::SwbfiUpdateUnion.error_id());
    }

    #[test]
    fn child_about_other_inputs_is_rejected() {
        let (mut witness, leaves) = witness_over_leaves(2, 2, 5);
        witness.left_inputs = leaves[1].inputs().to_vec();
        assert_rejects(&witness, BlockValidationRule::SwbfiUpdateUnion.error_id());
    }

    #[test]
    fn union_missing_an_input_is_rejected() {
        let (mut witness, _) = witness_over_leaves(2, 2, 5);
        witness.united_inputs.pop();
        assert_rejects(&witness, BlockValidationRule::SwbfiUpdateUnion.error_id());
    }

    #[test]
    fn child_of_other_program_is_rejected() {
        let (mut witness, _) = witness_over_leaves(2, 2, 5);
        witness.left_claim.program_digest = Digest::default();
        assert_rejects(&witness, BlockValidationRule::SwbfiUpdateUnion.error_id());
    }

    /// Prints how the program's cycles and table rows distribute over its
    /// subroutines, without the children's proof verification.
    #[test]
    #[ignore = "prints a profile"]
    fn profile_union() {
        for (left_size, right_size) in [(4, 4), (8, 8)] {
            let (witness, _) = witness_over_leaves(left_size, right_size, 6);
            let profile = tasm_lib::generate_full_profile(
                &format!("{left_size} + {right_size} inputs"),
                skipping().program(),
                &witness.standard_input(),
                &witness.nondeterminism_for(&skipping()),
            );
            println!("{profile}");
        }
    }
}
