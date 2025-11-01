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

/// Verifies that the coinbase *amount* is in line with the issuance schedule.
#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinbaseIsValidWitness {
    pub block: Block,
}

impl SecretWitness for CoinbaseIsValidWitness {
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
pub struct CoinbaseIsValid {
    witness: CoinbaseIsValidWitness,
}

impl ConsensusProgram for CoinbaseIsValid {
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

    impl ConsensusProgramSpecification for CoinbaseIsValid {
        fn source(&self) {
            todo!()
        }
    }
}
