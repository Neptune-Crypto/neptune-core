use std::collections::HashMap;

use itertools::Itertools;
use neptune_primitives::mast_hash::HasDiscriminant;
use neptune_primitives::mast_hash::MastHash;
use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::library::Library;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Digest;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::verifier::stark_verify::StarkVerify;

use super::link_kernel::no_thruputs_subtree_root;
use super::link_kernel::LinkKernel;
use super::link_kernel::LinkKernelField;
use super::link_proof::link_proof_public_input;
use super::link_proof::merge_bit_false_leaf;
use super::link_proof::no_coinbase_leaf;
use super::link_proof::LinkProof;
use super::link_proof_witness::LinkProofWitnessMemory;
use super::link_proof_witness::DISCRIMINANT_FOR_CAST;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::proof_abstractions::SecretWitness;
use crate::transaction::transaction_kernel::TransactionKernel;
use crate::transaction::transaction_proof::TransactionProof;
use crate::transaction::validity::neptune_proof::Proof;
use crate::transaction::validity::tasm::claims::generate_single_proof_claim::GenerateSingleProofClaim;
use crate::transaction::Transaction;

const CAST_KERNEL_IS_NOT_THE_CLAIMED_ONE_ERROR: i128 = 1_000_570;

/// The witness consumed by [`Cast`].
///
/// Holds the legacy transaction being pulled into the chain pipeline: its
/// kernel and the `SingleProof` backing it.
///
/// Like [`ChainWitness`](super::chain::ChainWitness) and
/// [`UpdateWitness`](super::update::UpdateWitness) it is its own memory image.
/// The branch reads only the proof out of it: the kernel is bound to the claim
/// through its MAST hash, which is divined rather than recomputed, so the copy
/// in memory is there for the *prover*'s sake -- to derive that hash and the two
/// authentication paths -- and the tasm never looks at it.
#[derive(Clone, Debug, BFieldCodec, TasmObject)]
pub struct CastWitness {
    pub(super) kernel: TransactionKernel,

    pub(super) proof: Proof,

    /// The program digest `D` the transaction's proof was made under, and which
    /// the claim `Cast` verifies it against names as its *program*.
    ///
    /// Rust-side only, as in [`ChainWitness`](super::chain::ChainWitness): it is
    /// here to build the public input and the inner claim, while the tasm branch
    /// reads `D` off the public input.
    pub(super) single_proof_digest: Digest,
}

impl CastWitness {
    /// Pull a `SingleProof`-backed [`Transaction`] into the chain pipeline.
    ///
    /// The resulting link transaction has no thruputs: a legacy transaction is
    /// complete on its own, and all `Cast` adds is the ability to be an operand
    /// of `Chain`.
    ///
    /// `single_proof_digest` is the program digest the transaction's proof was
    /// made under; it goes into the inner claim verbatim, so a transaction
    /// proven under any other one simply fails to verify. `Cast` does *not*
    /// check that it is the real `SingleProof` digest -- it cannot, that being
    /// the circular dependency which promoting `D` to a claim parameter breaks.
    /// A `LinkTx` cast under a junk digest is inert rather than invalid: it
    /// attests to nothing, and `Fix`, which names the real digest, rejects it.
    pub fn cast(transaction: Transaction, single_proof_digest: Digest) -> Self {
        let TransactionProof::SingleProof(proof) = transaction.proof else {
            panic!("cannot cast a transaction that is not backed by a single proof");
        };

        Self {
            kernel: transaction.kernel,
            proof,
            single_proof_digest,
        }
    }

    /// The [`LinkKernel`] this cast produces: the transaction's kernel, with no
    /// thruputs.
    pub fn link_kernel(&self) -> LinkKernel {
        LinkKernel {
            kernel: self.kernel.clone(),
            thruputs: std::vec![],
        }
    }

    /// MAST hash of the produced [`LinkKernel`]: the public input of the
    /// `LinkProof` claim this witness is proven against.
    pub(super) fn kernel_mast_hash(&self) -> Digest {
        self.link_kernel().mast_hash()
    }

    /// The claim the transaction's proof is verified against: `D` as the
    /// program, the transaction kernel's MAST hash as the input. This is the
    /// one place in the whole `LinkProof` program where `D` names a program
    /// rather than being passed along.
    fn single_proof_claim(&self) -> Claim {
        Claim::new(self.single_proof_digest).with_input(self.kernel.mast_hash().reversed().values())
    }
}

impl SecretWitness for CastWitness {
    fn standard_input(&self) -> PublicInput {
        link_proof_public_input(self.kernel_mast_hash(), self.single_proof_digest)
    }

    fn output(&self) -> Vec<BFieldElement> {
        std::vec![]
    }

    fn program(&self) -> Program {
        LinkProof.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        // `Cast` is a branch of `LinkProof`, so the memory image is that of the
        // enum variant's associated data: field size, then the payload.
        let mut memory = HashMap::default();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            &LinkProofWitnessMemory::Cast(Box::new(self.clone())),
        );

        // The transaction kernel's MAST hash is divined -- bound to `lkmh` by
        // the single hash the branch does, and to the transaction itself by the
        // recursive verification.
        let individual_tokens = self.kernel.mast_hash().reversed().values().to_vec();
        let mut nondeterminism = NonDeterminism::new(individual_tokens).with_ram(memory);

        // Then the two constant leafs, in program order.
        let link_kernel = self.link_kernel();
        nondeterminism.digests.extend(
            [
                link_kernel.mast_path(LinkKernelField::Coinbase),
                link_kernel.mast_path(LinkKernelField::MergeBit),
            ]
            .concat(),
        );

        // Then the recursive verification, which the branch does last. A mock
        // proof has no proof stream to extract nondeterminism from, and never
        // reaches a real `StarkVerify` either: in the negative tests some
        // earlier assertion fires first.
        if !self.proof.is_mock() {
            StarkVerify::new_with_dynamic_layout(Stark::default()).update_nondeterminism(
                &mut nondeterminism,
                &self.proof,
                &self.single_proof_claim(),
            );
        }

        nondeterminism
    }
}

/// `Cast: Transaction -> LinkTx`: pull a legacy transaction into the chain
/// pipeline, so that it can be an operand of `Chain`.
///
/// The branch recursively verifies the transaction's `SingleProof` against the
/// claim `{ program: D, input: [txkmh] }`, where `D` is the program digest off
/// the *public input*. This is the only place any `LinkProof` branch lets `D`
/// name a program -- everywhere else it is copied along untouched -- and it is
/// the half of the `Fix`/`Cast` cycle break that lives here: `LinkProof` cannot
/// hardcode the `SingleProof` digest, because `SingleProof` will hardcode
/// `LinkProof`'s.
///
/// Everything else the branch has to establish is that the `LinkKernel` it is
/// claimed under *is* that transaction's kernel with no thruputs. That takes a
/// single hash: a `LinkKernel`'s MAST root is the wrapped transaction kernel's
/// root paired with the subtree holding the thruputs leaf and the padding, and
/// for empty thruputs the latter is a constant (see
/// `no_thruputs_subtree_root`). So the branch divines `txkmh`, hashes it with
/// that constant, and asserts the result is `lkmh`. The empty thruputs are not a
/// separate check; they are baked into the constant.
///
/// On top of that, the two leafs every branch owes on the kernel it produces:
/// no coinbase and no merge bit. Together these say a coinbase or an already
/// merged transaction cannot be cast -- deliberately, since `Chain` relies on
/// both by induction rather than re-checking them.
///
/// Nothing here inspects the transaction's *contents*. It does not need to: the
/// `SingleProof` is what says the transaction is valid, and `Cast` neither adds
/// to nor subtracts from it. Note in particular that the mutator set is not
/// touched -- the cast link transaction names whichever one the transaction
/// named, and `Chain` is what requires its operands to agree on it.
#[derive(Debug, Copy, Clone)]
pub struct Cast {
    /// Where the dispatcher stashed the `SingleProof` program digest `D` it read
    /// off the public input. `Cast` names it as the program of the inner claim;
    /// see [`LinkProof`].
    pub(super) single_proof_digest_address: BFieldElement,
}

impl BasicSnippet for Cast {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "link_kernel_mast_hash".to_string()),
            (DataType::VoidPointer, "link_proof_witness".to_string()),
            (DataType::Bfe, "discriminant".to_string()),
        ]
    }

    /// The digest slot is the dispatcher's scratch space, not a return value;
    /// this branch leaves the cast kernel's MAST hash there. See `LinkProof`.
    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "dispatcher_scratch".to_string()),
            (DataType::VoidPointer, "link_proof_witness".to_string()),
            (DataType::Bfe, "minus_1".to_string()),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_chaintx_link_proof_cast_branch".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let audit_preloaded_data =
            library.import(Box::new(VerifyNdSiIntegrity::<CastWitness>::default()));
        let generate_single_proof_claim = library.import(Box::new(GenerateSingleProofClaim));
        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));
        let merkle_verify = library.import(Box::new(MerkleVerify));

        let field_proof = field!(CastWitness::proof);

        // Push a compile-time-known digest such that its 0th element ends up on
        // top -- the layout `merkle_verify` and `hash` expect.
        let push_digest = |digest: Digest| {
            digest
                .reversed()
                .values()
                .into_iter()
                .flat_map(|v| triton_asm!(push { v }))
                .collect_vec()
        };

        // A cast transaction is no more a coinbase transaction, and no more
        // merged, than a forged one: the constant leaf is authenticated
        // directly, which asserts the field's value at the same time (only one
        // preimage hashes to it).
        //
        // BEFORE: _ .. disc [lkmh] *witness [txkmh]
        // AFTER:  _ .. disc [lkmh] *witness [txkmh]
        let authenticate_constant_leaf = |leaf_index: LinkKernelField, leaf: Digest| {
            triton_asm!(
                dup 10 dup 10 dup 10 dup 10 dup 10
                // _ .. [lkmh] *witness [txkmh] [lkmh]

                push {LinkKernel::MAST_HEIGHT}
                push {leaf_index.discriminant() as u32}
                {&push_digest(leaf)}
                // _ .. [lkmh] *witness [txkmh] [lkmh] height index [leaf]

                call {merkle_verify}
                // _ .. [lkmh] *witness [txkmh]
            )
        };

        triton_asm!(
            {self.entrypoint()}:
            // _ [own_program_digest] [lkmh] *link_proof_witness disc

            place 6
            // _ [own_program_digest] disc [lkmh] *link_proof_witness

            addi 2
            hint witness = stack[0]
            // _ [own_program_digest] disc [lkmh] *witness
            // `disc` stays buried below the frame until the epilogue; the own
            // program digest -- which this branch has no use for, recursing as
            // it does into `D` and not into `LinkProof` -- stays below that,
            // where the dispatcher left it.

            dup 0 call {audit_preloaded_data} pop 1
            // _ [own_program_digest] disc [lkmh] *witness

            /* The transaction kernel's MAST hash, and the claimed link kernel
               is it with no thruputs. Divined, then bound to `lkmh` by the one
               hash below: the legacy kernel's eight leafs are the left half of
               the `LinkKernel`'s sixteen, so its root is `lkmh`'s left child,
               and with empty thruputs the right child is a constant. The
               recursive verification at the end is what forces the divined
               value to be a kernel a `SingleProof` attests to. */
            divine {Digest::LEN}
            hint transaction_kernel_mast_hash = stack[0..5]
            // _ [own_program_digest] disc [lkmh] *witness [txkmh]

            {&push_digest(no_thruputs_subtree_root())}
            // _ .. [lkmh] *witness [txkmh] [no_thruputs]

            dup 9 dup 9 dup 9 dup 9 dup 9
            // _ .. [lkmh] *witness [txkmh] [no_thruputs] [txkmh]

            hash
            // _ .. [lkmh] *witness [txkmh] [lkmh']
            // (lkmh' = hash_pair(txkmh, no_thruputs): tasm `hash` takes the top
            // operand as the first argument, so txkmh sits on top.)

            dup 15 dup 15 dup 15 dup 15 dup 15
            // _ .. [lkmh] *witness [txkmh] [lkmh'] [lkmh]

            assert_vector error_id {CAST_KERNEL_IS_NOT_THE_CLAIMED_ONE_ERROR}
            pop {Digest::LEN}
            // _ [own_program_digest] disc [lkmh] *witness [txkmh]

            {&authenticate_constant_leaf(LinkKernelField::Coinbase, no_coinbase_leaf())}
            {&authenticate_constant_leaf(LinkKernelField::MergeBit, merge_bit_false_leaf())}
            // _ [own_program_digest] disc [lkmh] *witness [txkmh]

            /* Last: the recursion. `D` comes from where the dispatcher put the
               public input -- audit-critical: never divined, never taken from
               the witness. Here it names the program itself, so a gap is not
               merely a forged link but a forged transaction. */
            push {self.single_proof_digest_address}
            read_mem {Digest::LEN}
            pop 1
            // _ .. [lkmh] *witness [txkmh] [D]

            call {generate_single_proof_claim}
            // _ [own_program_digest] disc [lkmh] *witness *claim

            dup 1
            {&field_proof}
            // _ [own_program_digest] disc [lkmh] *witness *claim *proof

            call {stark_verify}
            // _ [own_program_digest] disc [lkmh] *witness

            pick 6
            // _ [own_program_digest] [lkmh] *witness disc
            // (`lkmh` -- the cast kernel's MAST hash -- is left untouched in the
            // dispatcher's scratch slot, which it pops unread.)

            addi {-(DISCRIMINANT_FOR_CAST as isize) - 1}
            // _ [own_program_digest] [lkmh] *witness -1

            return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use proptest::strategy::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use tasm_lib::prelude::Tip5;

    use super::*;
    use crate::consensus_rule_set::ConsensusRuleSet;
    use crate::proof_abstractions::tasm::builtins as tasm;
    use crate::proof_abstractions::tasm::program::spec::TritonProgramSpecification;
    use crate::proof_abstractions::tasm::program::TritonVmProofJobOptions;
    use crate::proof_abstractions::triton_vm_job_queue::vm_job_queue;
    use crate::transaction::primitive_witness::PrimitiveWitness;
    use crate::transaction::validity::single_proof::produce_single_proof;
    use crate::transaction::validity::single_proof::SingleProof;

    /// The `Cast` branch of the `LinkProof` rust shadow, called by
    /// [`LinkProof::source`](super::super::link_proof::LinkProof) once it has
    /// read the own program digest, `lkmh` and `D`, and matched the witness
    /// discriminant -- mirroring the tasm, where the dispatcher does exactly
    /// that before `call`ing this branch.
    ///
    /// `single_proof_digest` comes from the dispatcher, i.e. from the public
    /// input. Never from `witness.single_proof_digest`, which is present in the
    /// memory image and must stay unread!
    pub(in crate::chaintx) fn cast_branch_source(
        lkmh: Digest,
        single_proof_digest: Digest,
        witness: CastWitness,
    ) {
        /* the transaction kernel's MAST hash. Free to be anything until the
        recursion at the end, which is what forces it to be a kernel some single
        proof attests to. */
        let txkmh: Digest = tasm::tasmlib_io_read_secin___digest();

        /* the claimed link kernel is that transaction's kernel, with no
        thruputs */
        assert_eq!(lkmh, Tip5::hash_pair(txkmh, no_thruputs_subtree_root()));

        /* a cast transaction is no more a coinbase transaction, and no more
        merged, than a forged one */
        let height = LinkKernel::MAST_HEIGHT as u32;
        tasm::tasmlib_hashing_merkle_verify(
            lkmh,
            LinkKernelField::Coinbase.discriminant() as u32,
            no_coinbase_leaf(),
            height,
        );
        tasm::tasmlib_hashing_merkle_verify(
            lkmh,
            LinkKernelField::MergeBit.discriminant() as u32,
            merge_bit_false_leaf(),
            height,
        );

        /* last: recursively verify the transaction's single proof */
        let claim = Claim::new(single_proof_digest).with_input(txkmh.reversed().values().to_vec());
        tasm::verify_stark(Stark::default(), &claim, &witness.proof);
    }

    /// `Cast` writes nothing to stdout, so the assertion is that both the Rust
    /// shadow and the tasm run to completion: every `assert` in either one held.
    fn prop_positive(witness: CastWitness) {
        LinkProof
            .run_rust(&witness.standard_input(), witness.nondeterminism())
            .unwrap();
        LinkProof
            .run_tasm(&witness.standard_input(), witness.nondeterminism())
            .unwrap();
    }

    /// A `SingleProof`-backed transaction, cast under the real `SingleProof`
    /// digest.
    ///
    /// Deterministic on purpose: same transaction means the same claim, hence a
    /// proof-cache hit rather than a fresh single proof. Shared by every
    /// proof-backed test below; the negatives that need no valid proof draw
    /// their fixtures at random instead.
    pub(super) async fn deterministic_cast_witness() -> CastWitness {
        // `Cast` never inspects `D`, only names it, so the rule set here is
        // whichever one keeps the transaction's single proof in the cache -- not
        // necessarily the one the chain pipeline activates under.
        let consensus_rule_set = ConsensusRuleSet::HardforkGamma;

        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 1)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let proof = produce_single_proof(
            &primitive_witness,
            vm_job_queue(),
            TritonVmProofJobOptions::default(),
            consensus_rule_set,
        )
        .await
        .unwrap();

        CastWitness::cast(
            Transaction {
                kernel: primitive_witness.kernel,
                proof: TransactionProof::SingleProof(proof),
            },
            SingleProof::new(consensus_rule_set).hash(),
        )
    }

    /// A legacy transaction enters the chain pipeline: its single proof is
    /// recursively verified, and the link kernel it is cast to is that
    /// transaction's kernel with no thruputs.
    ///
    /// The one test that runs the recursion against a real `SingleProof`, and
    /// hence the one that says `D` is read and *used*: a branch that ignored it,
    /// or built the inner claim any other way, has no proof to answer with.
    ///
    /// This test involves producing proofs and might take a while to complete
    /// if there is no proof cache.
    #[tokio::test]
    async fn cast_accepts_a_single_proof_backed_transaction() {
        prop_positive(deterministic_cast_witness().await);
    }

    /// `D` sits in the witness's memory image, and the branch must never look at
    /// it.
    ///
    /// Poked to a value the transaction's proof was *not* made under, while the
    /// public input keeps the real one. A branch that divined `D` from the
    /// witness would name a program no proof answers for and fail; this one
    /// passes, which is the guard, not the accident.
    ///
    /// Reuses the proof the positive test above makes -- same transaction, hence
    /// the same claim -- so it costs a cache hit, not a proof.
    #[tokio::test]
    async fn witness_supplied_single_proof_digest_is_ignored() {
        let mut witness = deterministic_cast_witness().await;

        // Both derived from the honest witness, before the poke: the claim the
        // proof answers, and the digest stream extracted against it.
        let input = witness.standard_input();
        let mut nondeterminism = witness.nondeterminism();

        witness.single_proof_digest = crate::chaintx::mock_single_proof_digest(1);
        encode_to_memory(
            &mut nondeterminism.ram,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            &LinkProofWitnessMemory::Cast(Box::new(witness)),
        );

        LinkProof.run_rust(&input, nondeterminism.clone()).unwrap();
        LinkProof.run_tasm(&input, nondeterminism).unwrap();
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod negative_tests {
    use neptune_mutator_set::addition_record::AdditionRecord;
    use test_strategy::proptest;

    use super::tests::deterministic_cast_witness;
    use super::*;
    use crate::chaintx::mock_single_proof_digest;
    use crate::proof_abstractions::tasm::program::spec::TritonProgramSpecification;
    use crate::proof_abstractions::tasm::program::TritonError;
    use crate::transaction::primitive_witness::PrimitiveWitness;
    use crate::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

    /// A witness of random contents whose single proof is a mock.
    ///
    /// Sound for every negative below that does not concern the proof itself:
    /// the recursion is the *last* thing the `Cast` branch does, so any other
    /// assertion fires before a proof is ever looked at.
    fn pokeable_witness() -> proptest::strategy::BoxedStrategy<CastWitness> {
        use proptest::strategy::Strategy;

        PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 1)
            .prop_map(|pw| {
                CastWitness::cast(
                    Transaction {
                        kernel: pw.kernel,
                        proof: TransactionProof::SingleProof(Proof::invalid_mock()),
                    },
                    mock_single_proof_digest(0),
                )
            })
            .boxed()
    }

    /// Run `Cast` on `witness` -- against the claim that witness itself names --
    /// and expect one of `error_ids`.
    fn expect_failure(
        witness: CastWitness,
        error_ids: &[i128],
    ) -> Result<(), proptest::test_runner::TestCaseError> {
        LinkProof.test_assertion_failure(
            witness.standard_input(),
            witness.nondeterminism(),
            error_ids,
        )
    }

    /// The cast kernel is bound to the claim by a single hash, so a witness
    /// built around some *other* transaction fails it -- as does a claim whose
    /// link kernel carries thruputs, which is the same failure: the constant the
    /// branch hashes with is the empty thruput list's subtree, and nothing else.
    #[proptest(cases = 4)]
    fn link_kernel_must_be_the_transaction_kernel_without_thruputs(
        #[strategy(pokeable_witness())] witness: CastWitness,
    ) {
        // varies the *claim*, not the witness, so it cannot go through
        // `expect_failure` above
        let expect_kernel_mismatch = |lkmh| {
            LinkProof.test_assertion_failure(
                link_proof_public_input(lkmh, witness.single_proof_digest),
                witness.nondeterminism(),
                &[CAST_KERNEL_IS_NOT_THE_CLAIMED_ONE_ERROR],
            )
        };

        // the transaction kernel's own root, which is a link kernel's *left
        // child* and never a link kernel root
        let txkmh = witness.kernel.mast_hash();
        expect_kernel_mismatch(txkmh).unwrap();

        // the same transaction, but claimed with a thruput on it
        let with_thruput = LinkKernel {
            kernel: witness.kernel.clone(),
            thruputs: std::vec![AdditionRecord::new(Digest::default())],
        };
        expect_kernel_mismatch(with_thruput.mast_hash()).unwrap();
    }

    /// A coinbase transaction, or one that has been through `Merge`, cannot be
    /// cast. Both leafs are constants the branch authenticates directly, so a
    /// kernel holding anything else has the wrong leaf, not merely the wrong
    /// value.
    #[proptest(cases = 4)]
    fn coinbase_or_merge_bit_on_the_cast_kernel_is_rejected(
        #[strategy(pokeable_witness())] original: CastWitness,
    ) {
        let mut witness = original.clone();
        witness.kernel = TransactionKernelModifier::default()
            .coinbase(Some(NativeCurrencyAmount::coins(1)))
            .modify(witness.kernel);
        expect_failure(witness, &[MerkleVerify::ROOT_MISMATCH_ERROR_ID]).unwrap();

        let mut witness = original.clone();
        witness.kernel = TransactionKernelModifier::default()
            .merge_bit(true)
            .modify(witness.kernel);
        expect_failure(witness, &[MerkleVerify::ROOT_MISMATCH_ERROR_ID]).unwrap();
    }

    /// `D` is *in* the inner claim, as its program, and it is the one off the
    /// public input.
    ///
    /// The transaction here is proven under the real `SingleProof` digest while
    /// the claim the cast is run against names another. A branch that dropped
    /// `D` from the inner claim, or took it from the witness instead, would
    /// verify the transaction happily.
    ///
    /// This doubles as "the recursion actually runs, on a proof that does not
    /// answer the claim". The seemingly more direct route -- feed the branch a
    /// mock proof and watch it fail -- is deliberately not taken: the verifier
    /// reads a garbage proof stream as lengths and allocates against them, so
    /// what it does is exhaust the machine, not reject.
    ///
    /// Reuses the proof `cast_accepts_a_single_proof_backed_transaction` makes,
    /// so it costs a cache hit, not a proof.
    #[tokio::test]
    async fn transaction_proven_under_another_program_digest_is_rejected() {
        let witness = deterministic_cast_witness().await;

        // The claim, and only the claim, names the other `D`. `lkmh` is
        // untouched, so everything before the recursion still passes.
        let input =
            link_proof_public_input(witness.kernel_mast_hash(), mock_single_proof_digest(1));
        let nondeterminism = witness.nondeterminism();
        LinkProof
            .run_rust(&input, nondeterminism.clone())
            .unwrap_err();

        let Err(TritonError::TritonVMPanic(vm_state, _)) =
            LinkProof.run_tasm(&input, nondeterminism)
        else {
            panic!("`Cast` must reject a transaction proven under another program digest");
        };
        assert!(
            vm_state.contains("stark_verify"),
            "must fail in the recursive verification, not before it:\n{vm_state}"
        );
    }
}
