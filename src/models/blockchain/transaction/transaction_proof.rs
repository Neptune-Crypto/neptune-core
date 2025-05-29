use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use crate::config_models::network::Network;
use crate::models::blockchain::transaction::BFieldCodec;
use crate::models::blockchain::transaction::PrimitiveWitness;
use crate::models::blockchain::transaction::Proof;
use crate::models::blockchain::transaction::ProofCollection;
use crate::models::blockchain::transaction::SingleProof;
use crate::models::peer::transfer_transaction::TransactionProofQuality;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::verifier::verify;
use crate::models::state::vm_proving_capability::VmProvingCapability;

/// represents available types of transaction proofs
///
/// the types are ordered (asc) by proof-generation complexity.
#[derive(
    Clone,
    Debug,
    Copy,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    PartialOrd,
    strum::Display,
    strum::EnumIs,
)]
pub enum TransactionProofType {
    /// a primitive-witness.  exposes secrets (keys).  this proof must not be shared.
    /// note: not a real TritonVm proof.
    PrimitiveWitness,
    /// a weak proof that does not expose secrets. can be shared with peers, but cannot be confirmed into a block.
    ProofCollection,
    /// a strong proof.  required for confirming a transaction into a block.
    SingleProof,
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

impl From<VmProvingCapability> for TransactionProofType {
    fn from(c: VmProvingCapability) -> Self {
        let max: u8 = c.into();

        if max >= TransactionProofType::SingleProof.log2_padded_height() {
            TransactionProofType::SingleProof
        } else if max >= TransactionProofType::ProofCollection.log2_padded_height() {
            TransactionProofType::ProofCollection
        } else {
            TransactionProofType::PrimitiveWitness
        }
    }
}

impl From<TransactionProofType> for VmProvingCapability {
    fn from(proof_type: TransactionProofType) -> Self {
        proof_type.log2_padded_height().into()
    }
}

impl From<TransactionProofType> for u8 {
    fn from(proof_type: TransactionProofType) -> Self {
        proof_type.log2_padded_height()
    }
}

impl From<TransactionProofType> for u32 {
    fn from(proof_type: TransactionProofType) -> Self {
        proof_type.log2_padded_height().into()
    }
}

impl TransactionProofType {
    /// indicates if the proof executes in triton-vm.
    pub fn executes_in_vm(&self) -> bool {
        matches!(self, Self::ProofCollection | Self::SingleProof)
    }

    /// provides an estimate of padded-height complexity for each variant.
    ///
    /// these values were determined by running unit tests
    /// and logging padded-height values in the ProverJob.
    ///
    /// They might need to be adjusted in the future.
    pub(crate) const fn log2_padded_height(&self) -> u8 {
        match *self {
            Self::PrimitiveWitness => 0,
            Self::ProofCollection => 15,
            Self::SingleProof => 22,
        }
    }
}

/// represents a transaction proof, which can be of different types.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub enum TransactionProof {
    /// a primitive-witness.  exposes secrets (keys).  this proof must not be shared.
    /// note: not a real TritonVm proof.
    Witness(PrimitiveWitness),
    /// a strong proof.  required for confirming a transaction into a block.
    SingleProof(Proof),
    /// a weak proof that does not expose secrets. can be shared with peers, but cannot be confirmed into a block.
    ProofCollection(ProofCollection),
}

impl TransactionProof {
    pub fn is_witness(&self) -> bool {
        matches!(self, Self::Witness(_))
    }

    pub fn is_proof_collection(&self) -> bool {
        matches!(self, Self::ProofCollection(_))
    }

    pub fn is_single_proof(&self) -> bool {
        matches!(self, Self::SingleProof(_))
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

    /// verify this proof is valid for a provided transaction id
    pub async fn verify(&self, kernel_mast_hash: Digest, network: Network) -> bool {
        match self {
            TransactionProof::Witness(primitive_witness) => {
                !primitive_witness.kernel.merge_bit
                    && primitive_witness.validate().await.is_ok()
                    && primitive_witness.kernel.mast_hash() == kernel_mast_hash
            }
            TransactionProof::SingleProof(single_proof) => {
                let claim = SingleProof::claim(kernel_mast_hash);
                verify(claim, single_proof.clone(), network).await
            }
            TransactionProof::ProofCollection(proof_collection) => {
                proof_collection.verify(kernel_mast_hash, network).await
            }
        }
    }
}

/// error variants associated with a transaction proof
#[derive(Debug, Copy, Clone)]
pub enum TransactionProofError {
    CannotUpdateProofVariant,
    CannotUpdatePrimitiveWitness,
    CannotUpdateSingleProof,
    ProverLockWasTaken,
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::twenty_first::bfe_vec;
    use crate::BFieldElement;

    impl TransactionProof {
        /// A proof that will always be invalid
        pub(crate) fn invalid() -> Self {
            Self::SingleProof(Proof::from(vec![]))
        }

        /// A proof that will always be invalid, with a specified size measured in
        /// number of [`BFieldElement`](twenty_first::math::b_field_element::BFieldElement)s.
        pub(crate) fn invalid_single_proof_of_size(size: usize) -> Self {
            Self::SingleProof(Proof::from(bfe_vec![0; size]))
        }

        pub(crate) fn into_proof_collection(self) -> ProofCollection {
            match self {
                TransactionProof::Witness(_primitive_witness) => {
                    panic!("Expected ProofCollection, got Witness")
                }
                TransactionProof::SingleProof(_proof) => {
                    panic!("Expected ProofCollection, got SingleProof")
                }
                TransactionProof::ProofCollection(proof_collection) => proof_collection,
            }
        }
    }
}
