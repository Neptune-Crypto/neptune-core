use std::sync::OnceLock;

use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::library::Library;
use tasm_lib::triton_vm::prelude::*;

use crate::protocol::consensus::block::BFieldCodec;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::SecretWitness;
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
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        todo!()
    }

    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::protocol::proof_abstractions::tasm::program::tests::ConsensusProgramSpecification;

    impl ConsensusProgramSpecification for CorrectMutatorSetUpdate {
        fn source(&self) {
            todo!()
        }
    }
}
