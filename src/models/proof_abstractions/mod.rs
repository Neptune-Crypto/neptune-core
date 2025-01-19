/// This file contains abstractions for verifying consensus logic using TritonVM STARK
/// proofs. The concrete logic is specified in the directories `transaction` and `block`.
use tasm_lib::triton_vm;
use tasm_lib::triton_vm::prelude::Program;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use triton_vm::prelude::Claim;
use triton_vm::prelude::NonDeterminism;
use triton_vm::prelude::PublicInput;

pub mod mast_hash;
pub mod tasm;
pub mod timestamp;
pub mod verifier;

/// A `SecretWitness` is data that makes a `ConsensusProgram` halt gracefully, but
/// that should be hidden behind a zero-knowledge proof.
///
/// Phrased differently, after proving the matching `ConsensusProgram`, the
/// `SecretWitness` should be securely deleted.
pub trait SecretWitness {
    /// The program's (public/standard) input
    fn standard_input(&self) -> PublicInput;

    /// The program's (public/standard) output.
    fn output(&self) -> Vec<BFieldElement> {
        vec![]
    }

    fn program(&self) -> Program;

    fn claim(&self) -> Claim {
        Claim::about_program(&self.program())
            .with_input(self.standard_input().individual_tokens)
            .with_output(self.output())
    }

    /// The non-determinism for the VM that this witness corresponds to
    fn nondeterminism(&self) -> NonDeterminism;
}
