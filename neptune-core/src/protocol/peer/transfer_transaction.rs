use anyhow::bail;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumIter;

use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::validity::neptune_proof::Proof;
use crate::protocol::consensus::transaction::validity::proof_collection::ProofCollection;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::consensus::transaction::TransactionProof;

/// Enumerates the kind of transaction proof that can be shared without the risk
/// of loss of funds.
///
/// SingleProof is the highest quality, as they can be merged with the miner's
/// coinbase transaction, which also is supported by a SingleProof.
/// ProofCollection requires upgrade to a SingleProof before mining, so it is
/// of lover quality.
#[derive(Clone, Copy, EnumIter, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TransactionProofQuality {
    // OnlyLockScripts, // TODO: Add this once Transaction has support
    ProofCollection,
    SingleProof,
}

/// Enumerates the kind of proofs that can be transferred to peers without
/// loss of funds.
///
/// Specifically disallows `[TransactionProof::PrimitiveWitness]` to be sent to
/// peers, as this would leak secret key material.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum TransferTransactionProof {
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
pub(crate) struct TransferTransaction {
    pub(crate) kernel: TransactionKernel,
    pub(crate) proof: TransferTransactionProof,
}

impl TryFrom<&Transaction> for TransferTransaction {
    type Error = anyhow::Error;

    fn try_from(value: &Transaction) -> Result<Self, Self::Error> {
        let transfer_proof = match &value.proof {
            TransactionProof::Witness(_) => {
                bail!("Cannot share primitive witness-supported transaction, as this would leak secret data")
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn transaction_proof_quality_ordering() {
        assert!(TransactionProofQuality::ProofCollection < TransactionProofQuality::SingleProof);
        assert!(
            TransactionProofQuality::ProofCollection >= TransactionProofQuality::ProofCollection
        );
        assert!(TransactionProofQuality::SingleProof >= TransactionProofQuality::SingleProof);
    }
}
