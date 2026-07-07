use neptune_consensus::transaction::TransactionProof;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumIter;

/// Enumerates the kind of transaction proof that can be shared without the risk
/// of loss of funds.
///
/// SingleProof is the highest quality, as they can be merged with the miner's
/// coinbase transaction, which also is supported by a SingleProof.
/// ProofCollection requires upgrade to a SingleProof before mining, so it is
/// of lover quality.
#[derive(Clone, Copy, EnumIter, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum TransactionProofQuality {
    // OnlyLockScripts, // TODO: Add this once Transaction has support
    ProofCollection,
    SingleProof,
}

/// Classifies a [`TransactionProof`] by its shareable [`TransactionProofQuality`].
///
/// `TransactionProofQuality` is a node-level policy concept (used for mempool
/// replacement and peer-gossip preference), so this lives in the mempool layer
/// rather than alongside `TransactionProof` in consensus.
pub trait TransactionProofQualityExt {
    fn proof_quality(&self) -> anyhow::Result<TransactionProofQuality>;
}

impl TransactionProofQualityExt for TransactionProof {
    fn proof_quality(&self) -> anyhow::Result<TransactionProofQuality> {
        match self {
            TransactionProof::Witness(_) => {
                anyhow::bail!("Primitive witness does not have a proof")
            }
            TransactionProof::ProofCollection(_) => Ok(TransactionProofQuality::ProofCollection),
            TransactionProof::SingleProof(_) => Ok(TransactionProofQuality::SingleProof),
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
