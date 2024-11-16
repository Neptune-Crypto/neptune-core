use std::sync::OnceLock;

use get_size::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::*;
use twenty_first::math::bfield_codec::BFieldCodec;
use twenty_first::prelude::MmrMembershipProof;

use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::SecretWitness;

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrMembershipWitness {
    pub membership_proof: MmrMembershipProof,
}

impl SecretWitness for MmrMembershipWitness {
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
pub struct MmrMembership {
    witness: MmrMembershipWitness,
}

impl ConsensusProgram for MmrMembership {
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
