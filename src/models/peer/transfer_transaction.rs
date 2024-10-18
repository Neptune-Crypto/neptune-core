use anyhow::bail;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::proof::Proof;

use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::validity::proof_collection::ProofCollection;
use crate::models::blockchain::transaction::Transaction;
use crate::models::blockchain::transaction::TransactionProof;

/// Enumerates the kind of proof associated with a transaction.
///
/// SingleProof is the highest quality, as they can be merged with the miner's
/// coinbase transaction, which also is supported by a SingleProof.
/// ProofCollection requires upgrade to a SingleProof before mining, so it is
/// of lover quality.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TransactionProofQuality {
    // OnlyLockScripts, // TODO: Add this once Transaction has support
    ProofCollection,
    SingleProof,
}

/// Enumerates the kind of proofs that can be transferred to peers without
/// lose of funds.
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
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct TransferTransaction {
    pub(crate) kernel: TransactionKernel,
    pub(crate) proof: TransferTransactionProof,
}

impl TryFrom<Transaction> for TransferTransaction {
    type Error = anyhow::Error;

    fn try_from(value: Transaction) -> Result<Self, Self::Error> {
        let transfer_proof = match value.proof {
            TransactionProof::Invalid => bail!("Cannot share invalid transaction with peer"),
            TransactionProof::Witness(_) => {
                bail!("Cannot share primitive witness-supported transaction, as this would leak secret data")
            }
            TransactionProof::SingleProof(proof) => TransferTransactionProof::SingleProof(proof),
            TransactionProof::ProofCollection(proof_collection) => {
                TransferTransactionProof::ProofCollection(Box::new(proof_collection))
            }
        };

        Ok(Self {
            kernel: value.kernel,
            proof: transfer_proof,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_proof_quality_ordering() {
        assert!(TransactionProofQuality::ProofCollection < TransactionProofQuality::SingleProof);
    }
}
