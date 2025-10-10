use std::sync::OnceLock;

use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::library::Library;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::prelude::MmrMembershipProof;

use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::SecretWitness;

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrMembershipWitness {
    pub membership_proof: MmrMembershipProof,
}

impl SecretWitness for MmrMembershipWitness {
    fn standard_input(&self) -> PublicInput {
        unimplemented!()
    }

    fn program(&self) -> Program {
        unimplemented!()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        unimplemented!()
    }
}

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrMembership {
    witness: MmrMembershipWitness,
}

impl ConsensusProgram for MmrMembership {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        unimplemented!()
    }

    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }
}
