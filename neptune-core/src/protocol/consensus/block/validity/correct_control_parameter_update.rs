use std::sync::OnceLock;

use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::library::Library;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use crate::protocol::consensus::block::Block;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::SecretWitness;

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrectControlParameterUpdateWitness {
    pub previous_block: Block,
}

impl SecretWitness for CorrectControlParameterUpdateWitness {
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
pub struct CorrectControlParameterUpdate {
    pub witness: CorrectControlParameterUpdateWitness,
}

impl ConsensusProgram for CorrectControlParameterUpdate {
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
pub mod tests {
    use super::*;
    use crate::protocol::proof_abstractions::tasm::program::tests::ConsensusProgramSpecification;

    impl ConsensusProgramSpecification for CorrectControlParameterUpdate {
        fn source(&self) {
            todo!()
        }
    }
}
