/// This file contains abstractions for verifying consensus logic using TritonVM STARK
/// proofs. The concrete logic is specified in the directories `transaction` and `block`.
use get_size::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm;
use tasm_lib::triton_vm::program::Program;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::Digest;
use triton_vm::prelude::Claim;
use triton_vm::prelude::NonDeterminism;
use triton_vm::prelude::Proof;
use triton_vm::prelude::PublicInput;

pub mod mast_hash;
pub mod tasm;
pub mod timestamp;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec, Hash)]
pub struct RawWitness {
    tokens: Vec<BFieldElement>,
    ram: Vec<(BFieldElement, BFieldElement)>,
    digests: Vec<Digest>,
}

impl From<NonDeterminism> for RawWitness {
    fn from(nondeterminism: NonDeterminism) -> Self {
        Self {
            tokens: nondeterminism.individual_tokens,
            ram: nondeterminism.ram.into_iter().collect_vec(),
            digests: nondeterminism.digests,
        }
    }
}

impl From<RawWitness> for NonDeterminism {
    fn from(value: RawWitness) -> Self {
        Self {
            individual_tokens: value.tokens.clone(),
            ram: value.ram.iter().cloned().collect(),
            digests: value.digests.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub enum WitnessType {
    /// A single proof for the entire claim, typically produced via recursion.
    Proof(Proof),
    RawWitness(RawWitness),
    /// As we do not have recursion yet, sometimes we just need to take things on faith.
    /// This should be depracated before mainnet launch, or just not accepted in the
    /// peer loop.
    Faith,
    /// As the claim decomposes into a conjunction or disjunction or smaller claims,
    /// it is those smaller claims not this one that need supporting raw witnesses.
    Decomposition,
    /// No witness.
    None,
}

impl core::hash::Hash for WitnessType {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.encode().hash(state);
    }
}

/// A `SecretWitness` is data that makes a `ConsensusProgram` halt gracefully, but
/// that should be hidden behind a zero-knowledge proof. Phrased differently, after
/// proving the matching `ConsensusProgram`, the `SecretWitness` should be securely
/// deleted.
pub trait SecretWitness {
    /// The program's (public/standard) input
    fn standard_input(&self) -> PublicInput;

    /// The program's (standard/public) output.
    fn output(&self) -> Vec<BFieldElement> {
        vec![]
    }

    fn program(&self) -> Program;

    fn claim(&self) -> Claim {
        Claim::new(self.program().hash())
            .with_input(self.standard_input().individual_tokens)
            .with_output(self.output())
    }

    /// The non-determinism for the VM that this witness corresponds to
    fn nondeterminism(&self) -> NonDeterminism;
}
