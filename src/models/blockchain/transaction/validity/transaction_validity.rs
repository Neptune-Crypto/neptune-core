use get_size::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::*;

use super::proof_collection::ProofCollection;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct TransactionValidity;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub enum TransactionValidityEvidence {
    StandardDecomposition(ProofCollection),
    // MultiClaimProof(MultiClaimProofEvidence),
    // TransactionMerger(TransactionMergerEvidence),
    // IntegralMempoolMembership(IntegralMempoolMembershipEvidence),
    // TransactionDataUpdate(TransactionDataUpdateEvidence),
}

impl ConsensusProgram for TransactionValidity {
    fn source(&self) {
        todo!()
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        todo!()
    }
}
