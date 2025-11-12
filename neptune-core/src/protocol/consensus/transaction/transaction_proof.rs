use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use crate::api::export::NeptuneProof;
use crate::application::config::network::Network;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::validity::single_proof::single_proof_claim;
use crate::protocol::consensus::transaction::BFieldCodec;
use crate::protocol::consensus::transaction::PrimitiveWitness;
use crate::protocol::consensus::transaction::ProofCollection;
use crate::protocol::peer::transfer_transaction::TransactionProofQuality;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::protocol::proof_abstractions::verifier::verify;

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

impl TransactionProofType {
    /// indicates if the proof executes in triton-vm.
    pub fn executes_in_vm(&self) -> bool {
        matches!(self, Self::ProofCollection | Self::SingleProof)
    }

    pub fn is_single_proof(&self) -> bool {
        *self == TransactionProofType::SingleProof
    }
}

/// represents a transaction proof, which can be of different types.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub enum TransactionProof {
    /// a primitive-witness.  exposes secrets (keys).  this proof must not be shared.
    Witness(PrimitiveWitness),
    /// a strong proof.  required for confirming a transaction into a block.
    SingleProof(NeptuneProof),
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

    /// Convert a transaction proof into a Triton VM proof.
    ///
    /// # Panics
    ///
    /// - If the proof type is any other than [TransactionProof::SingleProof].
    pub(crate) fn into_single_proof(self) -> NeptuneProof {
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

    /// Convert a transaction proof into a Triton VM proof, if the transaction
    /// is single proof backed. Otherwise returns `None`.
    pub(crate) fn as_single_proof(&self) -> Option<NeptuneProof> {
        match self {
            TransactionProof::Witness(_) => None,
            TransactionProof::ProofCollection(_) => None,
            TransactionProof::SingleProof(neptune_proof) => Some(neptune_proof.to_owned()),
        }
    }

    /// Convert a transaction proof into a primitive witness
    ///
    /// # Panics
    ///
    /// - If the proof type is any other than [TransactionProof::Witness].
    pub(crate) fn into_primitive_witness(self) -> PrimitiveWitness {
        match self {
            TransactionProof::Witness(primitive_witness) => primitive_witness,
            TransactionProof::SingleProof(_) => {
                panic!("Expected primitive witness, got SingleProof")
            }
            TransactionProof::ProofCollection(_) => {
                panic!("Expected primitive witness, got ProofCollection")
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

    /// verify this proof is valid for a provided transaction id.
    ///
    /// Block height is the height of the block that matches the transaction's
    /// mutator set accumulator.
    pub async fn verify(
        &self,
        kernel_mast_hash: Digest,
        network: Network,
        consensus_rule_set: ConsensusRuleSet,
    ) -> bool {
        match self {
            TransactionProof::Witness(primitive_witness) => {
                primitive_witness.validate().await.is_ok()
                    && primitive_witness.kernel.mast_hash() == kernel_mast_hash
            }
            TransactionProof::SingleProof(single_proof) => {
                let claim = single_proof_claim(kernel_mast_hash, consensus_rule_set);
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

#[cfg(feature = "mock-rpc")]
impl rand::distr::Distribution<TransactionProofType> for rand::distr::StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> TransactionProofType {
        match rng.random_range(0..3) {
            0 => TransactionProofType::PrimitiveWitness,
            1 => TransactionProofType::ProofCollection,
            2 => TransactionProofType::SingleProof,
            _ => unreachable!(),
        }
    }
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
            Self::SingleProof(NeptuneProof::from(vec![]))
        }

        /// A proof that will always be invalid, with a specified size measured in
        /// number of [`BFieldElement`](twenty_first::math::b_field_element::BFieldElement)s.
        pub(crate) fn invalid_single_proof_of_size(size: usize) -> Self {
            Self::SingleProof(NeptuneProof::from(bfe_vec![0; size]))
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
