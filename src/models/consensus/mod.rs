use anyhow::Result;
use get_size::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::maybe_write_debuggable_program_to_disk;
use tasm_lib::triton_vm;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::triton_vm::vm::VMState;
use tasm_lib::twenty_first::shared_math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::shared_math::bfield_codec::BFieldCodec;
use tracing::{debug, warn};
use triton_vm::prelude::Claim;
use triton_vm::prelude::NonDeterminism;
use triton_vm::prelude::Program;
use triton_vm::prelude::Proof;
use triton_vm::prelude::PublicInput;

pub mod mast_hash;
pub mod tasm;

/// This file contains abstractions for verifying consensus logic using TritonVM STARK
/// proofs. The concrete logic is specified in the directories `transaction` and `block`.

/// A Witness is any data that supports the truth of a claim, typically related to the
/// validity of a block or transaction.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub enum Witness<PrimitiveWitness, ValidationLogic> {
    /// All the first-order witness data that supports the validity claim, including
    /// sensitive secrets.
    Primitive(PrimitiveWitness),
    /// A decomposition of the validity claim into smaller claims, each one of which has
    /// its own supporting witness.
    ValidationLogic(ValidationLogic),
    /// A single proof for the entire claim, typically produced via recursion.
    SingleProof(SingleProof),
    /// As we do not have recursion yet, sometimes we just need to take things on faith.
    /// This must be depracated before mainnet launch!
    Faith,
}

/// Single proofs are the final abstaction layer for
/// witnesses. They represent the merger of a set of linked proofs
/// into one. They hide information that linked proofs expose, but
/// the downside is that their production requires multiple runs of the recursive
/// prover.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec)]
pub struct SingleProof(pub Proof);

impl GetSize for SingleProof {
    fn get_stack_size() -> usize {
        std::mem::size_of::<Self>()
    }

    fn get_heap_size(&self) -> usize {
        self.0.get_heap_size()
    }

    fn get_size(&self) -> usize {
        Self::get_stack_size() + GetSize::get_heap_size(self)
    }
}

pub trait SecretWitness:
    Clone + Serialize + PartialEq + Eq + GetSize + BFieldCodec + Sized
{
    /// The program's (public/standard) input
    fn standard_input(&self) -> PublicInput;

    /// The non-determinism for the VM that this witness corresponds to
    fn nondeterminism(&self) -> NonDeterminism<BFieldElement>;

    /// Returns the subprogram that this secret witness relates to
    fn subprogram(&self) -> Program;
}

/// When a claim to validity decomposes into multiple subclaims via variant
/// `ValidationLogic` of `Witness`, those subclaims are `SupportedClaims`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct SupportedClaim<SubprogramWitness: SecretWitness> {
    pub claim: crate::triton_vm::proof::Claim,
    pub support: ClaimSupport<SubprogramWitness>,
}

/// When a claim to validity decomposes into multiple subclaims via variant
/// `ValidationLogic` of `Witness`, those subclaims pertain to the graceful halting of
/// programs ("subprograms"), which is itself supported by either a proof or some witness
/// that can help the prover produce one.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub enum ClaimSupport<SubprogramWitness: SecretWitness> {
    Proof(Proof),
    MultipleSupports(Vec<SubprogramWitness>),
    SecretWitness(SubprogramWitness),
    DummySupport, // TODO: Remove this when all claims are implemented
}

/// SupportedClaim is a helper struct. It
/// encodes a Claim with an optional witness.

impl<SubprogramWitness: SecretWitness> SupportedClaim<SubprogramWitness> {
    // TODO: REMOVE when all validity logic is implemented
    pub fn dummy() -> Self {
        let dummy_claim = crate::triton_vm::proof::Claim {
            input: Default::default(),
            output: Default::default(),
            program_digest: Default::default(),
        };

        Self {
            claim: dummy_claim,
            support: ClaimSupport::DummySupport,
        }
    }
}

/// A trait for proving and verifying claims to validity of transactions or blocks,
/// sometimes with and sometimes without witness data.
pub trait ValidationLogic<T: SecretWitness> {
    type PrimitiveWitness;

    fn validation_program(&self) -> Program;
    fn support(&self) -> ClaimSupport<T>;
    fn claim(&self) -> Claim;

    /// Update witness secret witness to proof
    fn upgrade(&mut self, _proof: Proof) {
        todo!()
    }

    fn new_from_primitive_witness(primitive_witness: &Self::PrimitiveWitness) -> Self;

    /// Prove the claim.
    fn prove(&mut self) -> Result<()> {
        match &self.support() {
            ClaimSupport::Proof(_) => {
                // nothing to do; proof already exists
                Ok(())
            }
            ClaimSupport::SecretWitness(witness) => {
                // Run program before proving
                self.validation_program()
                    .run(
                        self.claim().public_input().into(),
                        witness.nondeterminism().clone(),
                    )
                    .expect("Program execution prior to proving must succeed");

                let proof = triton_vm::prove(
                    Stark::default(),
                    &self.claim(),
                    &self.validation_program(),
                    witness.nondeterminism().clone(),
                )
                .expect("Proving integrity of removal records must succeed.");
                self.upgrade(proof);
                Ok(())
            }
            ClaimSupport::DummySupport => {
                // nothing to do
                warn!("Trying to prove claim supported by dummy support");
                Ok(())
            }
            ClaimSupport::MultipleSupports(_supports) => {
                warn!("Trying to prove claim with multiple supports; not supported yet");
                Ok(())
            }
        }
    }

    /// Verify the claim.
    fn verify(&self) -> bool {
        match &self.support() {
            ClaimSupport::Proof(proof) => triton_vm::verify(Stark::default(), &self.claim(), proof),
            ClaimSupport::SecretWitness(w) => {
                let nondeterminism = w.nondeterminism();
                let input = &self.claim().input;
                let vm_result = w
                    .subprogram()
                    .run(PublicInput::new(input.to_vec()), nondeterminism);
                match vm_result {
                    Ok(observed_output) => {
                        let found_expected_output = observed_output == self.claim().output;
                        if !found_expected_output {
                            warn!("Observed output does not match claimed output for RRI");
                            debug!("Got output: {found_expected_output}");
                        }

                        found_expected_output
                    }
                    Err(err) => {
                        warn!("VM execution for removal records integrity did not halt gracefully");
                        debug!("Last state was: {err}");
                        false
                    }
                }
            }
            ClaimSupport::DummySupport => {
                warn!("dummy support encountered");
                false
            }
            ClaimSupport::MultipleSupports(secret_witnesses) => {
                let claim = self.claim();
                #[allow(clippy::never_loop)]
                for witness in secret_witnesses.iter() {
                    let public_input = PublicInput::new(claim.input.to_vec());
                    let vm_result = witness
                        .subprogram()
                        .run(public_input.clone(), witness.nondeterminism());
                    match vm_result {
                        Ok(_) => {}
                        Err(err) => {
                            warn!("Multiple-support witness failed to validate: {err}");
                            maybe_write_debuggable_program_to_disk(
                                &witness.subprogram(),
                                &VMState::new(
                                    &witness.subprogram(),
                                    public_input,
                                    witness.nondeterminism(),
                                ),
                            );
                            return false;
                        }
                    }
                }

                true
            }
        }
    }
}
