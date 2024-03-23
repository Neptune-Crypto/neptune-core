use crate::models::blockchain::block::BFieldCodec;
use crate::models::blockchain::block::Deserialize;
use crate::models::blockchain::block::GetSize;
use crate::models::blockchain::block::Serialize;
use crate::models::blockchain::shared::Hash;
use crate::models::consensus::tasm::program::ConsensusProgram;
use crate::models::consensus::SecretWitness;
use crate::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
use tasm_lib::triton_vm::instruction::LabelledInstruction;
use tasm_lib::triton_vm::program::NonDeterminism;
use tasm_lib::triton_vm::program::PublicInput;
use tasm_lib::twenty_first::shared_math::b_field_element::BFieldElement;

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrMembershipWitness {
    pub membership_proof: MmrMembershipProof<Hash>,
}

impl SecretWitness for MmrMembershipWitness {
    fn nondeterminism(&self) -> NonDeterminism<BFieldElement> {
        todo!()
    }

    fn standard_input(&self) -> PublicInput {
        todo!()
    }

    fn program(&self) -> tasm_lib::prelude::triton_vm::program::Program {
        todo!()
    }
}

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrMembership {
    witness: MmrMembershipWitness,
}

impl ConsensusProgram for MmrMembership {
    fn source(&self) {
        todo!()
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        todo!()
    }
}
