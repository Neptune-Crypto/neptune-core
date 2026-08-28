use itertools::Itertools;
use neptune_primitives::mast_hash::MastHash;
use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Library;
use tasm_lib::prelude::Tip5;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::verifier::stark_verify::StarkVerify;

use crate::chaintx::generate_link_proof_claim::GenerateLinkProofClaim;
use crate::chaintx::link_kernel::no_thruputs_subtree_root;
use crate::chaintx::link_proof::link_proof_public_input;
use crate::chaintx::link_proof::link_proof_public_output;
use crate::chaintx::link_proof::LinkProof;
use crate::chaintx::link_tx::LinkTx;
use crate::chaintx::link_tx::LinkTxProof;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::transaction::validity::neptune_proof::Proof;
use crate::transaction::validity::single_proof::DISCRIMINANT_FOR_FIX;
use crate::transaction::TransactionKernel;

/// The witness consumed by [`FixBranch`].
///
/// Holds the chained transaction leaving the chain pipeline: the kernel it
/// becomes, and the `LinkProof` backing it.
///
/// The thruputs are not among the fields, and neither is the `LinkKernel`. They
/// do not have to be: a `LinkKernel` with no thruputs is its transaction kernel
/// paired with a constant (see `no_thruputs_subtree_root`), so this branch
/// derives the link kernel's MAST hash from the transaction kernel's under the
/// assumption that the `thruputs` field is empty. A `LinkTx` that has thruputs
/// will not have a proof for the claim this branch builds. This branch is the
/// inverse of [`Cast`](crate::chaintx::cast::Cast).
///
/// The tasm reads only the proof out of the memory image; the kernel is there
/// for the prover's sake, being bound to the claim through its MAST hash, which
/// the branch takes off the public input.
#[derive(Debug, Clone, BFieldCodec, TasmObject)]
pub struct FixWitness {
    pub(crate) kernel: TransactionKernel,

    pub(crate) link_proof: Proof,
}

impl FixWitness {
    /// Send a fully resolved chained transaction back to the single-proof pipeline.
    ///
    /// # Panics
    ///
    /// - if `link_tx` still carries thruputs, which is to say it is not yet
    ///   block-eligible: a thruput is an input no mutator set knows about, and
    ///   only `Chain` can resolve one.
    /// - if `link_tx` is witness-backed rather than proof-backed.
    pub fn fix(link_tx: LinkTx) -> Self {
        assert!(
            link_tx.kernel.thruputs.is_empty(),
            "cannot fix a link transaction with unresolved thruputs"
        );
        let LinkTxProof::Proof(link_proof) = link_tx.proof else {
            panic!("cannot fix a link transaction that is not backed by a link proof");
        };

        Self {
            kernel: link_tx.kernel.kernel,
            link_proof,
        }
    }

    /// MAST hash of the transaction kernel this fix produces -- the public
    /// input of the `SingleProof` claim.
    pub(crate) fn kernel_mast_hash(&self) -> Digest {
        self.kernel.mast_hash()
    }

    /// MAST hash of the [`LinkKernel`](crate::chaintx::link_kernel::LinkKernel)
    /// the link proof attests to: this transaction's kernel, no thruputs.
    fn link_kernel_mast_hash(&self) -> Digest {
        Tip5::hash_pair(self.kernel_mast_hash(), no_thruputs_subtree_root())
    }

    /// The claim the link proof is verified against.
    ///
    /// `single_proof_digest` is `own_program_digest()` at run time. That is the
    /// whole of the tie between the two programs: `LinkProof` is a family
    /// `Link[D]` indexed by a `SingleProof` digest it never names itself, and
    /// `Fix` is what instantiates `D` -- with the digest of the very program
    /// doing the instantiating, which the outer verifier has already pinned.
    fn link_proof_claim(&self, single_proof_digest: Digest) -> Claim {
        let input = link_proof_public_input(self.link_kernel_mast_hash(), single_proof_digest);
        Claim::new(LinkProof.hash())
            .with_input(input.individual_tokens)
            .with_output(link_proof_public_output(single_proof_digest))
    }

    pub(crate) fn populate_nd_streams(
        &self,
        nondeterminism: &mut NonDeterminism,
        single_proof_program_hash: Digest,
    ) {
        let claim = self.link_proof_claim(single_proof_program_hash);

        // this check is needed for regtest mode, to prevent a panic
        // because regtest mode uses mock (empty) proofs.
        if !triton_vm::verify(Stark::default(), &claim, &self.link_proof) {
            tracing::warn!("attempting to fix invalid link transaction ...");
            return;
        }

        StarkVerify::new_with_dynamic_layout(Stark::default()).update_nondeterminism(
            nondeterminism,
            &self.link_proof,
            &claim,
        );
    }
}

/// `Fix: LinkTx -> Transaction`: send a chained transaction whose thruputs are
/// all resolved back to the single-proof pipeline, where a block can include it.
///
/// The counterpart of [`Cast`](crate::chaintx::cast::Cast), and the other half
/// of the `Fix`/`Cast` cycle break. `Cast` cannot hardcode the `SingleProof`
/// digest -- it reads it off the public input -- precisely so that `Fix` *can*
/// hardcode the `LinkProof` digest, which it does here. The dependency between
/// the two programs runs one way only, and this is that way.
///
/// The branch verifies the link proof against
/// `{ program: LinkProof, input: [lkmh, own_program_digest()] }`, and that is
/// nearly all it does. Two things are worth spelling out:
///
/// - **`lkmh` is derived, not divined.** It is the transaction kernel's MAST
///   hash -- which the claim being proven *is about* -- paired with the constant
///   subtree of an empty thruput list. So the claim binds the link transaction
///   to this transaction and asserts its thruputs are empty.
/// - **`D := own_program_digest()`.** Every `LinkProof` in the derivation tree
///   was verified against the `D` its claim carries (`Chain` and `Update` copy
///   it verbatim, `Forge` ignores it, `Cast` is the only one that lets it name
///   a program), so instantiating it here means: anything reaching a block was
///   `Cast` from a genuine `SingleProof` under these very rules.
///
/// Nothing else is checked. It does not need to be: no coinbase and no merge
/// bit hold on the link kernel by induction over the `LinkProof` branches, and
/// those two leafs sit at the same MAST positions in a `LinkKernel` as in the
/// `TransactionKernel` it wraps.
///
/// This branch exists only from hardfork delta onwards; see
/// [`ConsensusRuleSet::has_fix_branch`](crate::consensus_rule_set::ConsensusRuleSet::has_fix_branch).
#[derive(Debug, Copy, Clone)]
pub struct FixBranch;

impl BasicSnippet for FixBranch {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "txk_digest".to_string()),
            (DataType::VoidPointer, "single_proof_witness".to_string()),
            (DataType::Bfe, "discriminant".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "txk_digest".to_string()),
            (DataType::VoidPointer, "single_proof_witness".to_string()),
            (DataType::Bfe, "minus_1".to_string()),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_transaction_single_proof_fix_branch".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let audit_preloaded_data =
            library.import(Box::new(VerifyNdSiIntegrity::<FixWitness>::default()));

        // `D`, from the `LinkProof` claim's point of view, is this program's own
        // digest. So it is read in this branch.
        let single_proof_digest_alloc = library.kmalloc(u32::try_from(Digest::LEN).unwrap());
        let generate_link_proof_claim = library.import(Box::new(GenerateLinkProofClaim {
            single_proof_digest_address: single_proof_digest_alloc.read_address(),
        }));
        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));

        let field_link_proof = field!(FixWitness::link_proof);

        // Push a compile-time-known digest such that its 0th element ends up on
        // top -- the layout `hash` and the claim generator expect.
        let push_digest = |digest: Digest| {
            digest
                .reversed()
                .values()
                .into_iter()
                .flat_map(|v| triton_asm!(push { v }))
                .collect_vec()
        };

        triton_asm!(
            {self.entrypoint()}:
            // _ [own_program_digest] [txk_digest] *single_proof_witness disc

            place 6
            // _ [own_program_digest] disc [txk_digest] *single_proof_witness

            addi 2
            hint witness = stack[0]
            // _ [own_program_digest] disc [txk_digest] *witness

            dup 0 call {audit_preloaded_data} pop 1
            // _ [own_program_digest] disc [txk_digest] *witness

            dup 11 dup 11 dup 11 dup 11 dup 11
            // _ [own_program_digest] disc [txk_digest] *witness [own_program_digest]

            push {single_proof_digest_alloc.write_address()}
            write_mem {Digest::LEN}
            pop 1
            // _ [own_program_digest] disc [txk_digest] *witness

            /* Construct the link kernel MAST hash this transaction must have
               had for it to be eligible for fix, namely: no thruputs. */
            {&push_digest(no_thruputs_subtree_root())}
            // _ .. [txk_digest] *witness [no_thruputs]

            dup 10 dup 10 dup 10 dup 10 dup 10
            // _ .. [txk_digest] *witness [no_thruputs] [txk_digest]

            hash
            // _ [own_program_digest] disc [txk_digest] *witness [lkmh]
            // (lkmh = hash_pair(txkmh, no_thruputs)

            {&push_digest(LinkProof.hash())}
            // _ .. *witness [lkmh] [link_proof_digest]

            call {generate_link_proof_claim}
            // _ [own_program_digest] disc [txk_digest] *witness *claim

            dup 1
            {&field_link_proof}
            // _ [own_program_digest] disc [txk_digest] *witness *claim *link_proof

            call {stark_verify}
            // _ [own_program_digest] disc [txk_digest] *witness

            pick 6
            // _ [own_program_digest] [txk_digest] *witness disc

            addi {-(DISCRIMINANT_FOR_FIX as isize) - 1}
            // _ [own_program_digest] [txk_digest] *witness -1

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

    use super::*;
    use crate::chaintx::cast::CastWitness;
    use crate::chaintx::mock_single_proof_digest;
    use crate::chaintx::test_helpers::deterministic_chainable_link_primitive_witnesses;
    use crate::chaintx::test_helpers::forge;
    use crate::consensus_rule_set::ConsensusRuleSet;
    use crate::proof_abstractions::tasm::builtins as tasm;
    use crate::proof_abstractions::tasm::program::prove_triton_program;
    use crate::proof_abstractions::tasm::program::spec::TritonProgramSpecification;
    use crate::proof_abstractions::tasm::program::TritonError;
    use crate::proof_abstractions::tasm::program::TritonVmProofJobOptions;
    use crate::proof_abstractions::triton_vm_job_queue::vm_job_queue;
    use crate::proof_abstractions::SecretWitness;
    use crate::transaction::primitive_witness::PrimitiveWitness;
    use crate::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::transaction::validity::single_proof::produce_single_proof;
    use crate::transaction::validity::single_proof::single_proof_claim;
    use crate::transaction::validity::single_proof::SingleProof;
    use crate::transaction::validity::single_proof::SingleProofWitness;
    use crate::transaction::Transaction;
    use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

    impl FixWitness {
        /// The `Fix` branch of the `SingleProof` rust shadow, called by
        /// [`SingleProof::source`](crate::transaction::validity::single_proof::SingleProof)
        /// once it has read the own program digest and `txk_digest` -- mirroring
        /// the tasm, where the dispatcher does exactly that before `call`ing
        /// this branch.
        pub fn branch_source(&self, single_proof_program_digest: Digest, txk_digest: Digest) {
            /* the link kernel this transaction came from: its kernel, with no
            thruputs */
            let lkmh: Digest = Tip5::hash_pair(txk_digest, no_thruputs_subtree_root());

            /* recursively verify the link proof, naming this very program as the
            `D` the whole `LinkProof` derivation was indexed by */
            let input = link_proof_public_input(lkmh, single_proof_program_digest);
            let claim = Claim::new(LinkProof.hash())
                .with_input(input.individual_tokens)
                .with_output(link_proof_public_output(single_proof_program_digest));
            tasm::verify_stark(Stark::default(), &claim, &self.link_proof);
        }
    }

    /// The rule set whose `SingleProof` program has this branch. Every test
    /// below runs that program and no other.
    const CONSENSUS_RULE_SET: ConsensusRuleSet = ConsensusRuleSet::HardforkDelta;

    /// The `D` a link transaction must be forged under to be fixable: the digest
    /// of the very program that fixes it.
    fn single_proof_digest() -> Digest {
        SingleProof::new(CONSENSUS_RULE_SET).hash()
    }

    /// Forge a `LinkTx` from the `n`th of the chainable pair, under `d`.
    ///
    /// The fixture is `Chain`'s, deliberately: with `d` set to
    /// `mock_single_proof_digest(0)` the link proof is one `chain.rs` has
    /// already produced, so the negative below costs a cache hit rather than a
    /// forge. The predecessor has no thruputs; the successor has one.
    async fn forged_link_tx(index: usize, num_thruputs: usize, d: Digest) -> LinkTx {
        let (predecessor, successor) =
            deterministic_chainable_link_primitive_witnesses(2, num_thruputs);
        let lpw = [predecessor, successor].into_iter().nth(index).unwrap();

        forge(&lpw, d).await
    }

    /// `Fix` writes nothing to stdout, so the assertion is that both the Rust
    /// shadow and the tasm run to completion: every `assert` in either one held,
    /// and the recursion accepted.
    fn prop_positive(witness: FixWitness) {
        let single_proof = SingleProof::new(CONSENSUS_RULE_SET);
        let witness = SingleProofWitness::from_fix(witness);
        let input = witness.standard_input();

        single_proof
            .run_rust(&input, witness.nondeterminism(CONSENSUS_RULE_SET))
            .unwrap();
        single_proof
            .run_tasm(&input, witness.nondeterminism(CONSENSUS_RULE_SET))
            .unwrap();
    }

    /// Run `Fix` against `input` and require that it fails, inside the recursive
    /// verification rather than before it.
    ///
    /// The branch asserts nothing of its own -- the link kernel it derives goes
    /// straight into the claim -- so *every* way of getting it wrong is a claim
    /// no link proof answers, and "did the recursion actually run" is the only
    /// thing there is to check.
    fn expect_rejection_in_stark_verify(witness: FixWitness, input: PublicInput) {
        let single_proof = SingleProof::new(CONSENSUS_RULE_SET);
        let witness = SingleProofWitness::from_fix(witness);
        let nondeterminism = || witness.nondeterminism(CONSENSUS_RULE_SET);

        single_proof.run_rust(&input, nondeterminism()).unwrap_err();

        let Err(TritonError::TritonVMPanic(vm_state, _)) =
            single_proof.run_tasm(&input, nondeterminism())
        else {
            panic!("`Fix` must reject a link proof that does not answer its claim");
        };
        assert!(
            vm_state.contains("stark_verify"),
            "must fail in the recursive verification, not before it:\n{vm_state}"
        );
    }

    /// A chained transaction with no thruputs left outstanding can leave the
    /// chaining pipeline: its LinkProof is recursively verified, under a claim
    /// naming this very program as the `D` the whole derivation was indexed by.
    ///
    /// This test involves producing proofs and might take a while to complete
    /// if there is no proof cache.
    #[tokio::test]
    async fn fix_accepts_a_resolved_link_transaction() {
        let link_tx = forged_link_tx(0, 0, single_proof_digest()).await;
        prop_positive(FixWitness::fix(link_tx));
    }

    /// A link transaction that still carries thruputs cannot become block-borne.
    ///
    /// This is the property the whole design rests on: a thruput is an input no
    /// mutator set knows about, so an unresolved -- or fabricated -- one must
    /// never reach a block. It is enforced by *arithmetic*, not by an assertion:
    /// the branch derives the link kernel's MAST hash from the transaction
    /// kernel's on the assumption that there are no thruputs, so a link proof
    /// about a thruput-carrying kernel simply answers a different claim.
    ///
    /// This test involves producing proofs and might take a while to complete
    /// if there is no proof cache.
    #[tokio::test]
    async fn link_transaction_with_thruputs_is_rejected() {
        let link_tx = forged_link_tx(1, 1, single_proof_digest()).await;
        assert!(!link_tx.kernel.thruputs.is_empty());

        // `FixWitness::fix` refuses to build this one, which is the Rust-side
        // half of the same rule; the branch has to refuse it too.
        let LinkTxProof::Proof(link_proof) = link_tx.proof else {
            unreachable!("`forge` produces a proof-backed link transaction")
        };
        let witness = FixWitness {
            kernel: link_tx.kernel.kernel,
            link_proof,
        };

        let input = witness.kernel_mast_hash().reversed().values().into();
        expect_rejection_in_stark_verify(witness, input);
    }

    /// `D` is `own_program_digest()`, and nothing else will do.
    ///
    /// The link transaction here is forged under a junk `D`, which is what makes
    /// such a transaction *inert* rather than invalid: `Forge` and `Cast` let a
    /// prover name any `D` at all, `Chain` and `Update` refuse to mix them, and
    /// this is where that freedom is finally cashed out -- the one verifier that
    /// names a `D` names its own, so a chain indexed by anything else has
    /// nowhere to go.
    ///
    /// Reuses a link proof `chain.rs` produces, so it costs a cache hit rather
    /// than a forge.
    #[tokio::test]
    async fn link_proof_forged_under_another_single_proof_digest_is_rejected() {
        let link_tx = forged_link_tx(0, 0, mock_single_proof_digest(0)).await;
        let witness = FixWitness::fix(link_tx);

        let input = witness.kernel_mast_hash().reversed().values().into();
        expect_rejection_in_stark_verify(witness, input);
    }

    /// A `Cast` under a bogus "`SingleProof`" program succeeds -- and is worth
    /// nothing.
    ///
    /// `Cast` does not check the program digest `D` it is handed. It cannot:
    /// that circularity is the whole reason `D` is a claim parameter rather
    /// than a constant. So a prover may name any program at all, including one
    /// that approves everything. Here that program is `read_io 5 halt`, which
    /// consumes a transaction kernel's MAST hash and halts -- exactly the shape
    /// `Cast`'s inner claim asks for. Its proof verifies, the `Cast` is
    /// accepted, and a link transaction now exists that attests to nothing
    /// whatsoever about the transaction it wraps.
    ///
    /// What stops it is the far end, and only the far end. The claim its link
    /// proof answers carries the bogus `D`; `Chain` and `Update` copy `D` along
    /// unchanged and refuse to mix two of them; and `Fix` names its own
    /// program's digest. So the whole derivation is sealed off from the block
    /// chain rather than admitted to it. The rejection landing *inside* the
    /// recursive verification is what says the link proof is itself real, and
    /// that the digest is the sole disqualification.
    ///
    /// This is the sharp version of
    /// [`link_proof_forged_under_another_single_proof_digest_is_rejected`],
    /// which makes the same point on the `Forge` side -- where the junk `D` is
    /// never used for anything, so nothing was ever at stake. Here the junk `D`
    /// *is* used, as a program, and it really does verify a real proof.
    ///
    /// This test involves producing proofs and might take a while to complete
    /// if there is no proof cache.
    #[tokio::test]
    async fn cast_under_a_bogus_single_proof_program_is_un_fixable() {
        let (predecessor, _) = deterministic_chainable_link_primitive_witnesses(2, 0);
        let kernel = predecessor.kernel.kernel.clone();

        // A "validator" that approves every transaction put to it.
        let bogus = Program::new(&triton_asm!(read_io 5 halt));
        let bogus_proof = prove_triton_program(
            bogus.clone(),
            Claim::new(bogus.hash()).with_input(kernel.mast_hash().reversed().values()),
            NonDeterminism::default(),
            vm_job_queue(),
            TritonVmProofJobOptions::default(),
        )
        .await
        .unwrap();

        // The `Cast` itself is accepted: the proof answers the claim it builds.
        let transaction = Transaction::new_single_proof(kernel.clone(), bogus_proof);
        let cast = CastWitness::cast(transaction, bogus.hash());
        LinkProof
            .run_tasm(&cast.standard_input(), cast.nondeterminism())
            .unwrap();

        let link_proof = LinkProof
            .prove(
                cast.claim(),
                cast.nondeterminism(),
                vm_job_queue(),
                TritonVmProofJobOptions::default(),
            )
            .await
            .unwrap();
        let witness = FixWitness { kernel, link_proof };

        let input = witness.kernel_mast_hash().reversed().values().into();
        expect_rejection_in_stark_verify(witness, input);
    }

    /// The link proof must attest to the transaction the claim is about.
    ///
    /// Only the claim moves here: the witness, and hence the proof and the
    /// digests extracted against it, are the ones the positive test uses. The
    /// branch reads `txkmh` off the public input and derives the link kernel
    /// from it, so a different `txkmh` is a different `lkmh` -- the very same
    /// single hash that [`link_transaction_with_thruputs_is_rejected`] breaks,
    /// approached from the other side.
    ///
    /// Reuses the proof the positive test makes, so it costs a cache hit rather
    /// than a forge.
    #[tokio::test]
    async fn link_proof_must_attest_to_the_claimed_transaction() {
        let witness = FixWitness::fix(forged_link_tx(0, 0, single_proof_digest()).await);

        let other_kernel = TransactionKernelModifier::default()
            .fee(witness.kernel.fee + NativeCurrencyAmount::coins(1))
            .clone_modify(&witness.kernel);
        let input = other_kernel.mast_hash().reversed().values().into();

        expect_rejection_in_stark_verify(witness, input);
    }

    /// Compute a `Fix`.
    ///
    /// Prove the fixed transaction, and verify the resulting `SingleProof`
    /// against the claim it will be checked against out in the world.
    ///
    /// Returns the claim, so the caller can say what the transaction leaving
    /// the pipeline turned out to be.
    async fn produce_and_verify_single_proof(witness: FixWitness) -> Claim {
        let claim = single_proof_claim(witness.kernel_mast_hash(), CONSENSUS_RULE_SET);
        let single_proof = SingleProofWitness::from_fix(witness)
            .produce(
                CONSENSUS_RULE_SET,
                vm_job_queue(),
                TritonVmProofJobOptions::default(),
            )
            .await
            .unwrap();

        assert!(
            triton_vm::verify(Stark::default(), &claim, &single_proof),
            "a fixed transaction must carry a valid single proof"
        );

        claim
    }

    /// The whole `Forge -> Fix` pipeline, end to end: a link primitive witness
    /// becomes a link transaction, which becomes an ordinary
    /// `SingleProof`-backed transaction, and that single proof verifies.
    ///
    /// [`fix_accepts_a_resolved_link_transaction`] takes the same route but
    /// stops at running the program. What this adds is the last step, the one
    /// that says the chain pipeline's output is *interchangeable* with the
    /// single-proof pipeline's: a proof answering the very claim
    /// [`single_proof_claim`] hands to a block.
    ///
    /// This test involves producing proofs and might take a while to complete
    /// if there is no proof cache.
    #[tokio::test]
    async fn forge_then_fix_yields_a_verifying_single_proof() {
        let link_tx = forged_link_tx(0, 0, single_proof_digest()).await;
        produce_and_verify_single_proof(FixWitness::fix(link_tx)).await;
    }

    /// The whole `Cast -> Fix` pipeline, end to end -- and a round trip: a
    /// single-proof transaction is pulled into the chain pipeline and sent straight
    /// back out, and what comes out answers the claim that went in.
    ///
    /// That equality is the point. `Cast` adds nothing to a transaction and
    /// `Fix` takes nothing away, so the composition is the identity on the
    /// claim -- which is what makes casting safe to do opportunistically: a
    /// transaction that joins a chain and finds no partner is no worse off than
    /// one that never joined.
    ///
    /// Unlike `cast.rs`'s own fixture, the transaction here is proven under the
    /// rule set that *has* `Fix`. It has to be: `Fix` names its own program
    /// digest as the `D` indexing the whole derivation, and `Cast` verifies the
    /// transaction against that same `D` as a program. So this is the one test
    /// where the cycle closes -- a real `SingleProof` recursively verified by
    /// `Cast`, under a digest a real `SingleProof` then instantiates.
    ///
    /// This test involves producing proofs and might take a while to complete
    /// if there is no proof cache.
    #[tokio::test]
    async fn cast_then_fix_yields_a_verifying_single_proof() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 1)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let single_proof = produce_single_proof(
            &primitive_witness,
            vm_job_queue(),
            TritonVmProofJobOptions::default(),
            CONSENSUS_RULE_SET,
        )
        .await
        .unwrap();
        let transaction = Transaction::new_single_proof(primitive_witness.kernel, single_proof);
        let original_claim = single_proof_claim(transaction.kernel.mast_hash(), CONSENSUS_RULE_SET);

        let cast = CastWitness::cast(transaction, single_proof_digest());
        let link_proof = LinkProof
            .prove(
                cast.claim(),
                cast.nondeterminism(),
                vm_job_queue(),
                TritonVmProofJobOptions::default(),
            )
            .await
            .unwrap();
        let link_tx = LinkTx {
            kernel: cast.link_kernel(),
            proof: LinkTxProof::Proof(link_proof),
        };
        assert!(link_tx.kernel.thruputs.is_empty(), "a cast has no thruputs");

        let fixed_claim = produce_and_verify_single_proof(FixWitness::fix(link_tx)).await;
        assert_eq!(
            original_claim, fixed_claim,
            "`Fix` after `Cast` must land on the transaction it started from"
        );
    }
}
