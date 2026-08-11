use itertools::Itertools;
use tasm_lib::data_type::DataType;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::isa::instruction::LabelledInstruction;
use tasm_lib::triton_vm::isa::parser::to_labelled_instructions;
use tasm_lib::triton_vm::isa::parser::tokenize;
use tasm_lib::triton_vm::prelude::NonDeterminism;
use tasm_lib::triton_vm::prelude::Program;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::proof::Proof as VmProof;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib_legacy::traits::basic_snippet::BasicSnippet as LegacyBasicSnippet;
use tasm_lib_legacy::triton_vm as triton_vm_legacy;

use crate::consensus_rule_set::ConsensusRuleSet;

/// The pre-delta STARK verifier, transplanted from `tasm-lib-legacy` so that
/// pre-delta consensus programs keep their byte-exact instruction streams --
/// and hence their pinned program digests -- when assembled by a binary whose
/// linked `tasm-lib` implements the post-delta proof system.
///
/// The two `tasm-lib`s differ only in the STARK verification snippet; their
/// instruction sets, [`Library`] semantics, and every other snippet are
/// identical. This wrapper therefore reproduces exactly what the old build's
/// `library.import(StarkVerify)` produced:
///
///  - The legacy snippet's own body and its whole dependency tree are
///    generated against a throwaway legacy library and re-parsed as
///    instructions of the linked ISA (a pure text round-trip; the ISA is
///    unchanged). Labels are preserved, so the alphabetical function ordering
///    of the assembled program is untouched, and dependencies shared with the
///    surrounding program (identical in both `tasm-lib`s) deduplicate under
///    their original names.
///  - Static memory is mirrored: the throwaway library starts with zero
///    allocated words, which matches the surrounding program because at every
///    import site of this snippet the verifier is the first kmalloc-affecting
///    import. Afterwards the surrounding library's allocation counter is
///    advanced by the legacy verifier's total, so later allocations land on
///    the same addresses as in the old build.
///
/// Both invariants are guarded by the `program_hash_has_not_changed` snapshot
/// tests.
///
/// The Rust-side nondeterminism helpers below must dispatch, too, even though
/// the verifier snippet's Rust source is identical in both `tasm-lib`s: the
/// helpers replay the proof through the *linked* `triton-vm`, whose AIR
/// dimensions (`NUM_COLUMNS` et al.) changed -- so table rows hash to
/// different Merkle leafs and the linked snippet rejects legacy proofs with
/// `BadMerkleAuthenticationPath`. Only the proof geometry (proof stream, FRI,
/// Stark parameters) is shared between the generations.
#[derive(Debug, Clone)]
pub(crate) struct LegacyStarkVerify {
    inner: tasm_lib_legacy::verifier::stark_verify::StarkVerify,
}

impl LegacyStarkVerify {
    pub(crate) fn new_with_dynamic_layout() -> Self {
        let inner = tasm_lib_legacy::verifier::stark_verify::StarkVerify::new_with_dynamic_layout(
            triton_vm_legacy::stark::Stark::default(),
        );

        Self { inner }
    }

    /// Prepare the nondeterminism for in-VM verification of a proof answering
    /// the pre-delta proof system, mirroring the legacy
    /// `StarkVerify::update_nondeterminism`.
    ///
    /// Both `tasm-lib`s share `twenty-first`, so the conversion into legacy
    /// types and back moves fields without re-encoding.
    pub(crate) fn update_nondeterminism(
        &self,
        nondeterminism: &mut NonDeterminism,
        proof: &VmProof,
        claim: &Claim,
    ) {
        let legacy_claim = triton_vm_legacy::proof::Claim::new(claim.program_digest)
            .about_version(claim.version)
            .with_input(claim.input.clone())
            .with_output(claim.output.clone());
        let legacy_proof = triton_vm_legacy::proof::Proof(proof.0.clone());

        let mut legacy_nondeterminism = triton_vm_legacy::prelude::NonDeterminism::new(
            nondeterminism.individual_tokens.clone(),
        )
        .with_digests(nondeterminism.digests.clone())
        .with_ram(nondeterminism.ram.clone());
        self.inner
            .update_nondeterminism(&mut legacy_nondeterminism, &legacy_proof, &legacy_claim);

        nondeterminism.individual_tokens = legacy_nondeterminism.individual_tokens;
        nondeterminism.digests = legacy_nondeterminism.digests;
        nondeterminism.ram = legacy_nondeterminism.ram;
    }

    /// See the legacy `StarkVerify::number_of_nondeterministic_digests_consumed`.
    pub(crate) fn number_of_nondeterministic_digests_consumed(&self, proof: &VmProof) -> usize {
        let legacy_proof = triton_vm_legacy::proof::Proof(proof.0.clone());

        self.inner
            .number_of_nondeterministic_digests_consumed(&legacy_proof)
    }

    /// See the legacy `StarkVerify::number_of_nondeterministic_tokens_consumed`.
    pub(crate) fn number_of_nondeterministic_tokens_consumed(
        &self,
        proof: &VmProof,
        claim: &Claim,
    ) -> usize {
        let legacy_proof = triton_vm_legacy::proof::Proof(proof.0.clone());
        let legacy_claim = triton_vm_legacy::proof::Claim::new(claim.program_digest)
            .about_version(claim.version)
            .with_input(claim.input.clone())
            .with_output(claim.output.clone());

        self.inner
            .number_of_nondeterministic_tokens_consumed(&legacy_proof, &legacy_claim)
    }
}

/// Re-parse legacy instructions as instructions of the linked ISA.
///
/// A pure text round-trip: the two `tasm-lib`s bundle the same instruction
/// set, only as distinct Rust types.
fn convert_legacy_assembly(
    legacy_assembly: &[triton_vm_legacy::isa::instruction::LabelledInstruction],
) -> Vec<LabelledInstruction> {
    let source = legacy_assembly
        .iter()
        .map(|instruction| instruction.to_string())
        .join("\n");
    let (_, tokens) = tokenize(&source).expect("legacy assembly must parse under the linked ISA");

    to_labelled_instructions(&tokens)
}

impl BasicSnippet for LegacyStarkVerify {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "claim".to_string()),
            (DataType::VoidPointer, "*proof".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![]
    }

    fn entrypoint(&self) -> String {
        self.inner.entrypoint()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let mut legacy_library = tasm_lib_legacy::library::Library::new();
        let body = self.inner.code(&mut legacy_library);

        for dependency in legacy_library.all_external_dependencies() {
            let converted = convert_legacy_assembly(&dependency);
            let label = converted
                .iter()
                .find_map(|instruction| match instruction {
                    LabelledInstruction::Label(label) => Some(label.clone()),
                    _ => None,
                })
                .expect("every dependency of the legacy verifier must be labelled");
            library.explicit_import(&label, &converted);
        }

        // Advance the surrounding library's allocation counter by the legacy
        // verifier's total, so subsequent `kmalloc`s land on the same
        // addresses as in the old build.
        let probe = legacy_library.kmalloc(1);
        let num_allocated_words =
            (tasm_lib_legacy::library::STATIC_MEMORY_FIRST_ADDRESS - probe.write_address()).value();
        let num_allocated_words =
            u32::try_from(num_allocated_words).expect("legacy verifier's static memory fits u32");
        if num_allocated_words > 0 {
            library.kmalloc(num_allocated_words);
        }

        convert_legacy_assembly(&body)
    }
}

/// Import the STARK verification snippet matching the rule set's proof system.
///
/// Proofs from before hardfork delta use the legacy proof system, which the
/// linked `tasm-lib`'s verifier no longer implements; programs of those rule
/// sets use [`LegacyStarkVerify`] instead.
pub(crate) fn import_stark_verify(
    library: &mut Library,
    consensus_rule_set: ConsensusRuleSet,
) -> String {
    if uses_legacy_proof_system(consensus_rule_set) {
        library.import(Box::new(LegacyStarkVerify::new_with_dynamic_layout()))
    } else {
        library.import(Box::new(
            tasm_lib::verifier::stark_verify::StarkVerify::new_with_dynamic_layout(
                tasm_lib::triton_vm::stark::Stark::default(),
            ),
        ))
    }
}

pub(crate) fn uses_legacy_proof_system(consensus_rule_set: ConsensusRuleSet) -> bool {
    consensus_rule_set.triton_proof_version().version() <= triton_vm_legacy::proof::CURRENT_VERSION
}

/// Whether the claim's proof must answer the proof system of
/// `tasm-lib-legacy` rather than that of the linked `tasm-lib`.
///
/// The claim's version is stamped by this node from the consensus rule set.
/// Never taken from a peer. so it soundly selects the proof system.
pub fn claim_uses_legacy_proof_system(claim: &Claim) -> bool {
    claim.version <= triton_vm_legacy::proof::CURRENT_VERSION
}

/// The pre-delta prover pipeline: trace and prove under the legacy proof
/// system, keeping the legacy types internal.
///
/// Mirrors the two-step structure of the prover binary -- trace first, so the
/// padded height can be inspected before committing to the expensive proving
/// step.
#[derive(Debug)]
pub struct LegacyProverPipeline {
    aet: triton_vm_legacy::aet::AlgebraicExecutionTrace,
    claim: triton_vm_legacy::proof::Claim,
}

impl LegacyProverPipeline {
    /// Trace the program's execution under the legacy VM.
    ///
    /// # Panics
    ///
    /// Panics if the program's execution fails, like the prover binary does
    /// for the linked VM.
    pub fn trace(program: &Program, claim: &Claim, non_determinism: NonDeterminism) -> Self {
        let legacy_program = triton_vm_legacy::prelude::Program::decode(&program.encode())
            .expect("the two VM generations share the program encoding");
        let legacy_claim = triton_vm_legacy::proof::Claim::new(claim.program_digest)
            .about_version(claim.version)
            .with_input(claim.input.clone())
            .with_output(claim.output.clone());
        let legacy_non_determinism =
            triton_vm_legacy::prelude::NonDeterminism::new(non_determinism.individual_tokens)
                .with_digests(non_determinism.digests)
                .with_ram(non_determinism.ram);

        let (aet, _) = triton_vm_legacy::vm::VM::trace_execution(
            *legacy_program,
            (&legacy_claim.input).into(),
            legacy_non_determinism,
        )
        .expect("legacy trace execution must succeed");

        Self {
            aet,
            claim: legacy_claim,
        }
    }

    pub fn log2_padded_height(&self) -> u8 {
        self.aet.padded_height().ilog2() as u8
    }

    /// # Panics
    ///
    /// Panics if proving fails, like the prover binary does for the linked VM.
    pub fn prove(self) -> VmProof {
        let proof = triton_vm_legacy::stark::Stark::default()
            .prove(&self.claim, &self.aet)
            .expect("legacy proving must succeed");

        VmProof(proof.0)
    }
}

/// Prepare the nondeterminism for in-VM verification of the given (claim,
/// proof) pair, dispatching on the proof system the proof answers.
///
/// The claim's version is stamped by this node from the consensus rule set --
/// never taken from a peer -- so it soundly selects the proof system, exactly
/// as `verifier::verify` does on the Rust side: at most the legacy VM's
/// version means pre-delta.
pub(crate) fn update_nondeterminism_for_stark_verification(
    nondeterminism: &mut NonDeterminism,
    proof: &VmProof,
    claim: &Claim,
) {
    if claim_uses_legacy_proof_system(claim) {
        LegacyStarkVerify::new_with_dynamic_layout().update_nondeterminism(
            nondeterminism,
            proof,
            claim,
        );
    } else {
        tasm_lib::verifier::stark_verify::StarkVerify::new_with_dynamic_layout(
            tasm_lib::triton_vm::stark::Stark::default(),
        )
        .update_nondeterminism(nondeterminism, proof, claim);
    }
}
