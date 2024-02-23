use crate::models::blockchain::block::BFieldCodec;
use crate::models::blockchain::block::Deserialize;
use crate::models::blockchain::block::GetSize;
use crate::models::blockchain::block::Serialize;
use crate::models::blockchain::shared::Hash;
use crate::models::consensus::SecretWitness;
use crate::models::consensus::SupportedClaim;
use crate::triton_vm::program::Program;
use tasm_lib::triton_vm::program::NonDeterminism;
use tasm_lib::triton_vm::program::PublicInput;
use tasm_lib::twenty_first::shared_math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrMembershipWitness {
    pub membership_proof: MmrMembershipProof<Hash>,
}

impl SecretWitness for MmrMembershipWitness {
    fn nondeterminism(&self) -> NonDeterminism<BFieldElement> {
        todo!()
    }

    fn subprogram(&self) -> Program {
        todo!()
    }

    fn standard_input(&self) -> PublicInput {
        todo!()
    }
}

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrMembership {
    supported_claim: SupportedClaim<MmrMembershipWitness>,
}
