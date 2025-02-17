use std::sync::OnceLock;

use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::library::Library;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use crate::models::blockchain::block::Block;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::SecretWitness;

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredecessorIsValidWitness {
    pub predecessor_block: Block,
}

impl SecretWitness for PredecessorIsValidWitness {
    fn standard_input(&self) -> PublicInput {
        todo!()
    }

    fn program(&self) -> Program {
        todo!()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        todo!()
    }
}

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredecessorIsValid {
    pub witness: PredecessorIsValidWitness,
}

impl ConsensusProgram for PredecessorIsValid {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        todo!()
    }

    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::proof_abstractions::tasm::program::test::ConsensusProgramSpecification;

    impl ConsensusProgramSpecification for PredecessorIsValid {
        fn source(&self) {
            todo!()
        }
    }
}
