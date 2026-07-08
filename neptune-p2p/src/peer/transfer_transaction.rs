use anyhow::bail;
use neptune_consensus::transaction::Transaction;
use neptune_consensus::transaction::TransactionProof;
use neptune_consensus::transaction::transaction_kernel::TransactionKernel;
use neptune_consensus::transaction::validity::neptune_proof::Proof;
use neptune_consensus::transaction::validity::proof_collection::ProofCollection;
use neptune_mempool::transaction_proof_quality::TransactionProofQuality;
use serde::Deserialize;
use serde::Serialize;

/// Enumerates the kind of proofs that can be transferred to peers without
/// loss of funds.
///
/// Specifically disallows `[TransactionProof::PrimitiveWitness]` to be sent to
/// peers, as this would leak secret key material.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransferTransactionProof {
    //OnlyLockScripts(OnlyLockScriptWitness) TODO: Add when Transaction supports
    ProofCollection(Box<ProofCollection>),
    SingleProof(Proof),
}

/// For transferring proved transactions between peers.
///
/// This type exists to ensure that a transaction supported by
/// [TransactionProof::Witness] is never shared between peers, as this would
/// leak secret keys and lead to loss of funds.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferTransaction {
    pub kernel: TransactionKernel,
    pub proof: TransferTransactionProof,
}

impl TryFrom<&Transaction> for TransferTransaction {
    type Error = anyhow::Error;

    fn try_from(value: &Transaction) -> Result<Self, Self::Error> {
        let transfer_proof = match &value.proof {
            TransactionProof::Witness(_) => {
                bail!(
                    "Cannot share primitive witness-supported transaction, as this would leak secret data"
                )
            }
            TransactionProof::SingleProof(proof) => {
                TransferTransactionProof::SingleProof(proof.to_owned())
            }
            TransactionProof::ProofCollection(proof_collection) => {
                TransferTransactionProof::ProofCollection(Box::new(proof_collection.to_owned()))
            }
        };

        Ok(Self {
            kernel: value.kernel.to_owned(),
            proof: transfer_proof,
        })
    }
}

impl TransferTransactionProof {
    pub fn proof_quality(&self) -> TransactionProofQuality {
        match self {
            TransferTransactionProof::ProofCollection(_) => {
                TransactionProofQuality::ProofCollection
            }
            TransferTransactionProof::SingleProof(_) => TransactionProofQuality::SingleProof,
        }
    }
}

impl From<TransferTransaction> for Transaction {
    fn from(value: TransferTransaction) -> Self {
        Self {
            kernel: value.kernel,
            proof: match value.proof {
                TransferTransactionProof::ProofCollection(proof_collection) => {
                    TransactionProof::ProofCollection(*proof_collection)
                }
                TransferTransactionProof::SingleProof(proof) => {
                    TransactionProof::SingleProof(proof)
                }
            },
        }
    }
}
