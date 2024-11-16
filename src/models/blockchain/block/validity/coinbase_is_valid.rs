use std::sync::OnceLock;

use get_size::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first;
use twenty_first::math::bfield_codec::BFieldCodec;

use crate::models::blockchain::block::Block;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::SecretWitness;

/// Verifies that the coinbase *amount* is in line with the issuance schedule.
#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinbaseIsValidWitness {
    pub block: Block,
}

impl SecretWitness for CoinbaseIsValidWitness {
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
pub struct CoinbaseIsValid {
    witness: CoinbaseIsValidWitness,
}

impl ConsensusProgram for CoinbaseIsValid {
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
