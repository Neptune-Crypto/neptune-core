use std::sync::OnceLock;

use get_size::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::*;

use crate::models::blockchain::block::BFieldCodec;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::SecretWitness;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrectMutatorSetUpdateWitness {
    previous_mutator_set_accumulator: MutatorSetAccumulator,
}

impl SecretWitness for CorrectMutatorSetUpdateWitness {
    fn nondeterminism(&self) -> NonDeterminism {
        todo!()
    }

    fn standard_input(&self) -> PublicInput {
        todo!()
    }

    fn program(&self) -> Program {
        todo!()
    }
}

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrectMutatorSetUpdate {
    pub witness: CorrectMutatorSetUpdateWitness,
}

impl ConsensusProgram for CorrectMutatorSetUpdate {
    /// Get the program hash digest.
    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }

    fn source(&self) {
        todo!()
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        todo!()
    }
}
