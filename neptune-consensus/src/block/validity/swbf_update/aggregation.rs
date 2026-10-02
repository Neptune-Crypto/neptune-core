//! Two SWBFI update claims aggregated into one: from the mutator set the
//! left child starts on, removing both children's inputs yields the
//! mutator set the right child ends on. The claim has the leaf's input and
//! output layout, so a tree of aggregations over leaves is bound by its root
//! alone, and the padded rows of the leaf proofs beneath it, summed in the
//! output, say how much proving work the root stands on.
//!
//! The children are claims of the leaf program or of this one, and their
//! proofs are verified here; a leaf's padded height is read from its proof,
//! an aggregation's rows from its output. They must chain: the left child's
//! input is this claim's, the right child's input is the mutator set the
//! left child outputs, and the right child's first leaf index is the left
//! child's last plus one, so that no leaf, and no proof, serves twice. The
//! index sets' digests come as witness; the children's peaks are recomputed
//! from them, and this claim's over all of them.

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
use tasm_lib::triton_vm::proof_item::ProofItemVariant;
use tasm_lib::verifier::stark_verify::StarkVerify;
use tasm_lib::verifier::vm_proof_iter::dequeue_next_as::DequeueNextAs;
use tasm_lib::verifier::vm_proof_iter::new::New as NewProofIter;

use super::leaf::CorrectSwbfiUpdate;
use super::leaf::CorrectSwbfiUpdateWitness;
use super::removal_index_commitment::DigestPeaks;
use super::removal_index_commitment::IndexSetDigests;
use super::ClaimOutput;
use super::INPUT_FIRST_LEAF_INDEX;
use super::INPUT_LEN;
use super::INPUT_MUTATOR_SET_HASH;
use super::OUTPUT_COUNT;
use super::OUTPUT_LAST_LEAF_INDEX;
use super::OUTPUT_MUTATOR_SET_HASH;
use super::OUTPUT_NUM_PEAKS;
use super::OUTPUT_PADDED_ROWS;
use super::OUTPUT_PEAKS;
use crate::block::block_validation_error::BlockValidationRule;
use crate::consensus_rule_set::ConsensusRuleSet;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::proof_abstractions::SecretWitness;

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

    /// The padded rows of the leaf proofs beneath a child: its proof's
    /// padded height for a leaf, its output's first word for an aggregation.
    fn child_padded_rows(claim: &Claim, proof: &Proof) -> BFieldElement {
        if claim.program_digest == CorrectSwbfiUpdate.hash() {
            let padded_height = proof
                .padded_height()
                .expect("child proof must declare its padded height");
            bfe!(padded_height as u64)
        } else {
            ClaimOutput::parse(&claim.output).padded_rows
        }
    }

    /// The claim about this witness for this variant of the program.
    fn claim_for(&self, program: &SwbfiUpdateAggregation) -> Claim {
        Claim::about_program(&program.program())
            .with_input(self.standard_input().individual_tokens)
            .with_output(self.output())
            .about_version(
                ConsensusRuleSet::HardforkDelta
                    .triton_proof_version()
                    .version(),
            )
    }

    /// The claim about this witness, as a block's appendix carries it.
    pub fn versioned_claim(&self) -> Claim {
        self.claim_for(&SwbfiUpdateAggregation::new())
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
        ClaimOutput {
            padded_rows: Self::child_padded_rows(&self.left_claim, &self.left_proof)
                + Self::child_padded_rows(&self.right_claim, &self.right_proof),
            count: left.count + right.count,
            mutator_set_hash: right.mutator_set_hash,
            last_leaf_index: right.last_leaf_index,
            peaks: DigestPeaks::peaks(digests),
        }
        .encode()
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

    /// The root claim and proof of a tree over these leaves: the consecutive
    /// segments of one block's inputs, numbered from the first leaf index,
    /// each lifted to the padded height it is to have. Adjacent nodes
    /// aggregate pairwise from the left, a node without a right neighbour
    /// waits for the next level, and so on until one node remains. The prover
    /// is called for every leaf and every aggregation. A single leaf is
    /// returned as is, though a block's root must be an aggregation.
    pub fn tree<P>(&self, leaves: &[CorrectSwbfiUpdateWitness], prove: P) -> (Claim, Proof)
    where
        P: Fn(&Claim, Program, NonDeterminism) -> Proof,
    {
        struct Node {
            claim: Claim,
            proof: Proof,
            index_set_digests: Vec<Digest>,
        }

        let mut level = leaves
            .iter()
            .map(|leaf| {
                let claim = leaf.versioned_claim();
                let proof = prove(&claim, CorrectSwbfiUpdate.program(), leaf.nondeterminism());
                Node {
                    claim,
                    proof,
                    index_set_digests: IndexSetDigests::digests(leaf.inputs()),
                }
            })
            .collect::<Vec<_>>();
        assert!(!level.is_empty(), "a tree needs a leaf");

        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut nodes = level.into_iter();
            while let Some(left) = nodes.next() {
                let Some(right) = nodes.next() else {
                    next.push(left);
                    break;
                };
                let index_set_digests = [left.index_set_digests, right.index_set_digests].concat();
                let witness = SwbfiUpdateAggregationWitness::new(
                    left.claim,
                    left.proof,
                    right.claim,
                    right.proof,
                    index_set_digests.clone(),
                );
                let claim = witness.claim_for(self);
                let proof = prove(&claim, self.program(), witness.nondeterminism_for(self));
                next.push(Node {
                    claim,
                    proof,
                    index_set_digests,
                });
            }
            level = next;
        }

        let root = level.pop().expect("a level has a node");
        (root.claim, root.proof)
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
        let new_proof_iter = library.import(Box::new(NewProofIter));
        let dequeue_log2_padded_height = library.import(Box::new(DequeueNextAs::new(
            ProofItemVariant::Log2PaddedHeight,
        )));

        let own_program_digest_alloc = library.kmalloc(Digest::LEN as u32);
        let input_msa_hash_alloc = library.kmalloc(Digest::LEN as u32);
        let first_leaf_index_alloc = library.kmalloc(1);
        let padded_rows_alloc = library.kmalloc(1);

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
        let child_padded_rows = "swbfi_update_aggregation_child_padded_rows".to_string();
        let audit_claim_output = "swbfi_update_aggregation_audit_output".to_string();
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
            /* Read from std-in: start mutator set hash, and first leaf index
               in proof tree */
            read_io {Digest::LEN}
            push {input_msa_hash_alloc.write_address()} write_mem {Digest::LEN} pop 1
            read_io 1
            push {first_leaf_index_alloc.write_address()} write_mem 1 pop 1

            /* Write own program digest to static memory */
            dup 15 dup 15 dup 15 dup 15 dup 15
            push {own_program_digest_alloc.write_address()} write_mem {Digest::LEN} pop 1
            // _

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            hint witness = stack[0]
            dup 0 call {audit_witness} pop 1
            // _ *w

            dup 0 {&field!(SwbfiUpdateAggregationWitness::left_claim)}
            call {check_child}
            // _ *w *left_claim left_first_leaf_index [left_mutator_set_hash]

            /* Assert left child's mutator set matches this execution's mutator
               set. */
            push {input_msa_hash_alloc.read_address()} read_mem {Digest::LEN} pop 1
            // _ *w *left_claim left_first_leaf_index [left_mutator_set_hash] [own_mutator_set_hash]

            assert_vector error_id {chaining}
            pop {Digest::LEN}
            // _ *w *left_claim left_first_leaf_index

            /* Assert left child's first leaf index matches this execution's
               first leaf index */
            push {first_leaf_index_alloc.read_address()} read_mem 1 pop 1
            eq
            // _ *w *left_claim (left_first_leaf_index == our_first_leaf_index)

            assert error_id {chaining}
            // _ *w *left_claim

            {&verify_left}
            // _ *w *left_claim

            /* Read out left claim's "accumulated proof complexity count": The
               sum of the padded heights of proofs in the leafs verified by the
               left claim */
            dup 0 dup 2 {&field!(SwbfiUpdateAggregationWitness::left_proof)}
            call {child_padded_rows}
            push {padded_rows_alloc.write_address()} write_mem 1 pop 1
            // _ *w *left_claim

            call {audit_claim_output}
            // _ *w *left_output

            /* Assert that right claim started where left claim ended */
            dup 1 {&field!(SwbfiUpdateAggregationWitness::right_claim)}
            call {check_child}
            // _ *w *left_output *right right_first_leaf_index [right_mutator_set_hash]

            dup 7 addi {OUTPUT_MUTATOR_SET_HASH + Digest::LEN} read_mem {Digest::LEN} pop 1
            // _ *w *left_output *right right_first_leaf_index [right_mutator_set_hash] [left_mutator_set_hash_after]

            assert_vector error_id {chaining}
            pop {Digest::LEN}
            // _ *w *left_output *right right_first_leaf_index

            /* Assert left claim outputs the next leaf index matching right
               claims' input leaf index */
            dup 2 addi {1 + OUTPUT_LAST_LEAF_INDEX} read_mem 1 pop 1
            addi 1 eq assert error_id {chaining}
            // _ *w *left_output *right

            {&verify_right}
            dup 0 dup 3 {&field!(SwbfiUpdateAggregationWitness::right_proof)}
            call {child_padded_rows}

            // The sum of the proving complexity (of the leaf executions) is a
            // field element, not a u32  or u64: each leaf adds at most 2^31, so
            // it takes over 2^33 verified leaf proofs to wrap the field. So
            // it's fine to keep it as a b-field element.
            push {padded_rows_alloc.read_address()} read_mem 1 pop 1 add
            push {padded_rows_alloc.write_address()} write_mem 1 pop 1
            // _ *w *left_output *right

            call {audit_claim_output}
            // _ *w *left_output *right_output

            dup 2 {&field!(SwbfiUpdateAggregationWitness::index_set_digests)}
            // _ *w *left_output *right_output *index_set_digests

            dup 0 read_mem 1 pop 1
            // _ *w *left_output *right_output *index_set_digests num_index_set_digests

            dup 3 addi {1 + OUTPUT_COUNT} read_mem 1 pop 1
            dup 3 addi {1 + OUTPUT_COUNT} read_mem 1 pop 1
            // _ *w *left_output *right_output *digests num_digests left_count right_count

            dup 1 dup 1 add
            // _ *w *left_output *right_output *digests num_digests left_count right_count (left_count + right_count)

            pick 3 eq
            // _ *w *left_output *right_output *digests left_count right_count (num_digests == (left_count + right_count))

            assert error_id {chaining}
            // _ *w *left_output *right_output *digests left_count right_count

            dup 2 push 0 dup 3
            // _ *w *left_output *right_output *digests left_count right_count *digests 0 left_count

            call {digest_peaks}
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

            push {padded_rows_alloc.read_address()} read_mem 1 pop 1 write_io 1
            dup 1 dup 1 add write_io 1
            dup 3 addi {OUTPUT_MUTATOR_SET_HASH + Digest::LEN}
            read_mem {Digest::LEN} pop 1 write_io {Digest::LEN}
            dup 3 addi {1 + OUTPUT_LAST_LEAF_INDEX} read_mem 1 pop 1 write_io 1
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
            // version, with the leaf's input layout.
            // BEFORE: _ *claim
            // AFTER:  _ *claim first_leaf_index [mutator_set_hash_init]
            {check_child}:
                /* Assert the claim's program digest is either the leaf program,
                   or the aggregation program (this program) */
                dup 0 {&field!(Claim::program_digest)} {&read_digest}
                dup 4 dup 4 dup 4 dup 4 dup 4
                {&push_leaf_program_digest}
                {&digests_are_equal}
                place 5
                // _ *claim is_leaf [program_digest]

                push {own_program_digest_alloc.read_address()} read_mem {Digest::LEN} pop 1
                {&digests_are_equal}
                add
                // _ *claim (is_leaf || is_self)

                assert error_id {chaining}
                // _ *claim

                /* Assert the claim's version matches out version */
                dup 0 {&field!(Claim::version)} read_mem 1 pop 1
                push {version}
                eq
                // _ *claim (claim_version == our_version)

                assert error_id {chaining}
                // _ *claim

                dup 0 {&field_with_size!(Claim::input)}
                // _ *claim *claim_input input_size

                /* Assert expected length of claim's input */
                // The size counts the length word the pointer points at.
                push {1 + INPUT_LEN} eq assert error_id {chaining}

                // _ *claim *claim_input
                dup 0 addi {1 + INPUT_FIRST_LEAF_INDEX} read_mem 1 pop 1
                // _ *claim *claim_input first_leaf_index

                place 1
                // _ *claim first_leaf_index *claim_input

                addi {INPUT_MUTATOR_SET_HASH + Digest::LEN} read_mem {Digest::LEN} pop 1
                swap 4 swap 1 swap 3 swap 1
                // _ *claim first_leaf_index [mutator_set_hash_init]

                return

            /* Return the padded height of the proof in case of a leaf, and
               the "effective" total proof size of all leafs below the node if
               it is not a leaf. Padded height is read from the proof which
               messes up the sponge state but that's OK: All callers that need
               it are required to reset it regardless of this mutation. */
            // BEFORE: _ *claim *proof
            // AFTER:  _ padded_rows
            {child_padded_rows}:
                sponge_init
                call {new_proof_iter}
                call {dequeue_log2_padded_height}
                read_mem 1 pop 1
                // _ *claim log2_padded_height

                push 2 pow
                // _ *claim padded_height

                dup 1 {&field!(Claim::output)} addi {1 + OUTPUT_PADDED_ROWS} read_mem 1 pop 1
                // _ *claim padded_height output_rows

                pick 2 {&field!(Claim::program_digest)} {&read_digest}
                {&push_leaf_program_digest}
                {&digests_are_equal}
                // _ padded_height output_rows is_leaf

                dup 1 push -1 mul pick 3 add
                // _ output_rows is_leaf (padded_height - output_rows)

                mul add
                // _ padded_rows

                return

            // BEFORE: _ *claim
            // AFTER:  _ *claim_output
            {audit_claim_output}:
                {&field_with_size!(Claim::output)}
                // _ *claim_output size

                dup 1 addi {1 + OUTPUT_NUM_PEAKS} read_mem 1 pop 1
                // _ *claim_output size num_peaks

                push {Digest::LEN} mul
                // _ *claim_output size expected_peaks_size

                addi {1 + OUTPUT_PEAKS} eq
                // _ *claim_output (size == expected_claim_output_size)

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
pub(in crate::block::validity) mod tests {
    use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
    use neptune_mutator_set::removal_record::RemovalRecord;
    use tasm_lib::triton_vm::proof_item::ProofItem;
    use tasm_lib::triton_vm::proof_stream::ProofStream;
    use tasm_lib::triton_vm::vm::VM;

    use super::super::leaf::tests::archival_mutator_set_after;
    use super::super::leaf::tests::chained_witnesses;
    use super::super::removal_index_commitment::RemovalIndexCommitment;
    use super::*;
    use crate::proof_abstractions::tasm::builtins as tasm;
    use crate::proof_abstractions::tasm::builtins::verify_stark;
    use crate::proof_abstractions::tasm::program::spec::TritonProgramSpecification;

    impl TritonProgramSpecification for SwbfiUpdateAggregation {
        fn source(&self) {
            let own_program_digest = tasm::own_program_digest();
            let mutator_set_hash = tasm::tasmlib_io_read_stdin___digest();
            let first_leaf_index = tasm::tasmlib_io_read_stdin___bfe();
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
                assert_eq!(INPUT_LEN, claim.input.len());
                let hash = &claim.input[INPUT_MUTATOR_SET_HASH..][..Digest::LEN];
                let hash = Digest::new(hash.try_into().unwrap()).reversed();
                (hash, claim.input[INPUT_FIRST_LEAF_INDEX])
            };

            assert_eq!(
                (mutator_set_hash, first_leaf_index),
                check_child(&witness.left_claim)
            );
            if self.verifies_children {
                verify_stark(Stark::default(), &witness.left_claim, &witness.left_proof);
            }
            let left = ClaimOutput::parse(&witness.left_claim.output);

            assert_eq!(
                (left.mutator_set_hash, left.last_leaf_index + bfe!(1)),
                check_child(&witness.right_claim)
            );
            if self.verifies_children {
                verify_stark(Stark::default(), &witness.right_claim, &witness.right_proof);
            }
            let right = ClaimOutput::parse(&witness.right_claim.output);

            let digests = &witness.index_set_digests;
            assert_eq!(left.count + right.count, digests.len());
            assert_eq!(left.peaks, DigestPeaks::peaks(&digests[..left.count]));
            assert_eq!(right.peaks, DigestPeaks::peaks(&digests[left.count..]));

            let padded_rows = SwbfiUpdateAggregationWitness::child_padded_rows;
            let output = ClaimOutput {
                padded_rows: padded_rows(&witness.left_claim, &witness.left_proof)
                    + padded_rows(&witness.right_claim, &witness.right_proof),
                count: left.count + right.count,
                mutator_set_hash: right.mutator_set_hash,
                last_leaf_index: right.last_leaf_index,
                peaks: DigestPeaks::peaks(digests),
            };
            for word in output.encode() {
                tasm::tasmlib_io_write_to_stdout___bfe(word);
            }
        }
    }

    fn skipping() -> SwbfiUpdateAggregation {
        SwbfiUpdateAggregation {
            verifies_children: false,
        }
    }

    /// A proof that declares this padded height, followed by one more item,
    /// so that the proof iterator does not reach the proof's end after the
    /// height, as it does not in a real proof. All the skipping program
    /// reads of a proof is the height.
    pub(in crate::block::validity) fn placeholder_proof(log2_padded_height: u32) -> Proof {
        let mut stream = ProofStream::new();
        stream.enqueue(ProofItem::Log2PaddedHeight(log2_padded_height));
        stream.enqueue(ProofItem::MerkleRoot(Digest::default()));
        stream.into()
    }

    const CHILD_LOG2_PADDED_HEIGHT: u32 = 20;

    /// The claim of a leaf, or of an aggregation of the skipping program,
    /// with a placeholder proof of the fixture height.
    fn child(claim: Claim) -> (Claim, Proof) {
        (claim, placeholder_proof(CHILD_LOG2_PADDED_HEIGHT))
    }

    /// The claim of an aggregation of the leaves over the two halves of
    /// these inputs, with placeholder proofs of these padded heights.
    pub(in crate::block::validity) fn claim_over_halves(
        inputs: &[RemovalRecord],
        mutator_set: &MutatorSetAccumulator,
        log2_padded_heights: [u32; 2],
    ) -> Claim {
        let split = inputs.len() / 2;
        let leaves = CorrectSwbfiUpdateWitness::segments(
            inputs,
            mutator_set,
            &[split, inputs.len() - split],
        );
        SwbfiUpdateAggregationWitness::new(
            leaves[0].versioned_claim(),
            placeholder_proof(log2_padded_heights[0]),
            leaves[1].versioned_claim(),
            placeholder_proof(log2_padded_heights[1]),
            index_set_digests(&leaves),
        )
        .versioned_claim()
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

            assert_eq!(bfe!(2 << CHILD_LOG2_PADDED_HEIGHT), parsed.padded_rows);
            assert_eq!(left_size + right_size, parsed.count);
            assert_eq!(bfe!(2), parsed.last_leaf_index);
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

        // The lower aggregation's own proof height is not counted; its output is.
        assert_eq!(bfe!(3 << CHILD_LOG2_PADDED_HEIGHT), parsed.padded_rows);
        assert_eq!(6, parsed.count);
        assert_eq!(bfe!(3), parsed.last_leaf_index);
        let all_inputs = leaves
            .iter()
            .flat_map(|leaf| leaf.inputs().to_vec())
            .collect::<Vec<_>>();
        assert_eq!(RemovalIndexCommitment::peaks(&all_inputs), parsed.peaks);
    }

    /// Runs the node in the VM and hands back a placeholder proof.
    fn run_and_placeholder(
        claim: &Claim,
        program: Program,
        nondeterminism: NonDeterminism,
    ) -> Proof {
        let input = PublicInput::new(claim.input.clone());
        let output = VM::run(program, input, nondeterminism).unwrap();
        assert_eq!(claim.output, output);
        placeholder_proof(CHILD_LOG2_PADDED_HEIGHT)
    }

    #[test]
    fn trees_of_any_height_chain_their_leaves() {
        for num_leaves in 1..=6 {
            let sizes = (0..num_leaves).map(|i| i % 3).collect::<Vec<_>>();
            let leaves = chained_witnesses(&sizes, 9);
            let (root, _) = skipping().tree(&leaves, run_and_placeholder);
            let parsed = ClaimOutput::parse(&root.output);

            assert_eq!(bfe!(num_leaves as u64), parsed.last_leaf_index);
            assert_eq!(sizes.iter().sum::<usize>(), parsed.count);
            let expected_rows = if num_leaves == 1 {
                0
            } else {
                (num_leaves as u64) << CHILD_LOG2_PADDED_HEIGHT
            };
            assert_eq!(
                bfe!(expected_rows),
                parsed.padded_rows,
                "{num_leaves} leaves"
            );
            assert_eq!(
                archival_mutator_set_after(leaves.last().unwrap()).hash(),
                parsed.mutator_set_hash
            );
        }
    }

    #[test]
    fn leaf_padded_rows_come_from_their_proofs() {
        let (mut witness, _) = witness_over_leaves(2, 2, 5);
        witness.left_proof = placeholder_proof(18);
        witness.right_proof = placeholder_proof(21);
        let parsed = ClaimOutput::parse(&outputs(&witness));
        assert_eq!(bfe!((1 << 18) + (1 << 21)), parsed.padded_rows);
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
    fn own_first_leaf_index_must_be_the_left_childs() {
        let (witness, _) = witness_over_leaves(2, 2, 5);
        let mut input = witness.standard_input();
        input.individual_tokens[INPUT_FIRST_LEAF_INDEX] += bfe!(1);
        assert_rejects(&witness, Some(input));
    }

    #[test]
    fn right_child_not_following_the_left_childs_last_leaf_is_rejected() {
        let (mut witness, _) = witness_over_leaves(2, 2, 5);
        witness.right_claim.input[INPUT_FIRST_LEAF_INDEX] += bfe!(1);
        assert_rejects(&witness, None);
    }

    #[test]
    fn empty_leaf_cannot_be_its_own_sibling() {
        // An empty leaf ends where it starts, so only its index keeps it
        // from chaining with itself.
        let (mut witness, _) = witness_over_leaves(0, 0, 5);
        witness.right_claim = witness.left_claim.clone();
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
