use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use crate::models::blockchain::transaction::BFieldCodec;
use crate::models::blockchain::transaction::PrimitiveWitness;
use crate::models::blockchain::transaction::Proof;
use crate::models::blockchain::transaction::ProofCollection;
use crate::models::blockchain::transaction::SingleProof;
use crate::models::peer::transfer_transaction::TransactionProofQuality;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::verifier::verify;

/// represents available types of transaction proofs
///
/// the types are ordered (asc) by proof-generation complexity.
#[derive(Clone, Debug, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, strum::Display)]
#[repr(u8)]
pub enum TransactionProofType {
    /// a primitive-witness.  exposes secrets (keys).  this proof must not be shared.
    PrimitiveWitness = 1,
    /// a weak proof that does not expose secrets. can be shared with peers, but cannot be confirmed into a block.
    ProofCollection = 2,
    /// a strong proof.  required for confirming a transaction into a block.
    SingleProof = 3,
}

impl From<&TransactionProof> for TransactionProofType {
    fn from(proof: &TransactionProof) -> Self {
        match *proof {
            TransactionProof::Witness(_) => Self::PrimitiveWitness,
            TransactionProof::ProofCollection(_) => Self::ProofCollection,
            TransactionProof::SingleProof(_) => Self::SingleProof,
        }
    }
}

/// represents a transaction proof, which can be of different types.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub enum TransactionProof {
    /// a primitive-witness.  exposes secrets (keys).  this proof must not be shared.
    Witness(PrimitiveWitness),
    /// a strong proof.  required for confirming a transaction into a block.
    SingleProof(Proof),
    /// a weak proof that does not expose secrets. can be shared with peers, but cannot be confirmed into a block.
    ProofCollection(ProofCollection),
}

impl TransactionProof {
    /// A proof that will always be invalid
    #[cfg(test)]
    pub(crate) fn invalid() -> Self {
        Self::SingleProof(Proof(vec![]))
    }

    pub(crate) fn into_single_proof(self) -> Proof {
        match self {
            TransactionProof::SingleProof(proof) => proof,
            TransactionProof::Witness(_) => {
                panic!("Expected SingleProof, got Witness")
            }
            TransactionProof::ProofCollection(_) => {
                panic!("Expected SingleProof, got ProofCollection")
            }
        }
    }

    pub(crate) fn proof_quality(&self) -> anyhow::Result<TransactionProofQuality> {
        match self {
            TransactionProof::Witness(_) => {
                anyhow::bail!("Primitive witness does not have a proof")
            }
            TransactionProof::ProofCollection(_) => Ok(TransactionProofQuality::ProofCollection),
            TransactionProof::SingleProof(_) => Ok(TransactionProofQuality::SingleProof),
        }
    }

    pub async fn verify(&self, kernel_mast_hash: Digest) -> bool {
        match self {
            TransactionProof::Witness(primitive_witness) => {
                !primitive_witness.kernel.merge_bit
                    && primitive_witness.validate().await
                    && primitive_witness.kernel.mast_hash() == kernel_mast_hash
            }
            TransactionProof::SingleProof(single_proof) => {
                let claim = SingleProof::claim(kernel_mast_hash);
                verify(claim, single_proof.clone()).await
            }
            TransactionProof::ProofCollection(proof_collection) => {
                proof_collection.verify(kernel_mast_hash).await
            }
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum TransactionProofError {
    CannotUpdateProofVariant,
    CannotUpdatePrimitiveWitness,
    CannotUpdateSingleProof,
    ProverLockWasTaken,
}
