use std::fmt::Display;
use std::str::FromStr;

use clap::error::ErrorKind;
use clap::Parser;
use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;

use crate::protocol::consensus::transaction::transaction_proof::TransactionProofType;

/// represents which type of proof a given device is capable of generating
///
/// see also:
/// * [TransactionProofType]
/// * [TransactionProof](crate::protocol::consensus::transaction::transaction_proof::TransactionProof)
#[derive(Parser, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, GetSize)]
pub enum TxProvingCapability {
    // Enumeration here must match that used in TransactionProofType.
    #[default]
    PrimitiveWitness = 0,
    LockScript = 1,
    ProofCollection = 2,
    SingleProof = 3,
}

impl From<TxProvingCapability> for TransactionProofType {
    fn from(c: TxProvingCapability) -> Self {
        match c {
            TxProvingCapability::PrimitiveWitness => Self::PrimitiveWitness,
            TxProvingCapability::LockScript => unimplemented!(),
            TxProvingCapability::ProofCollection => Self::ProofCollection,
            TxProvingCapability::SingleProof => Self::SingleProof,
        }
    }
}

impl TxProvingCapability {
    pub(crate) fn can_prove(&self, proof_type: TransactionProofType) -> bool {
        let self_val = *self as u8;
        self_val >= proof_type as u8
    }
}

impl Display for TxProvingCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                TxProvingCapability::PrimitiveWitness => "primitive witness",
                TxProvingCapability::LockScript => "lock script",
                TxProvingCapability::ProofCollection => "proof collection",
                TxProvingCapability::SingleProof => "single proof",
            }
        )
    }
}

impl FromStr for TxProvingCapability {
    type Err = clap::Error;
    // This implementation exists to allow CLI arguments to be converted to an
    // instance of this type.

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            // PrimitiveWitness is not covered here, as it's only used
            // internally, and cannot be set on the client.
            "lockscript" => Ok(TxProvingCapability::LockScript),
            "proofcollection" => Ok(TxProvingCapability::ProofCollection),
            "singleproof" => Ok(TxProvingCapability::SingleProof),
            _ => Err(clap::Error::raw(
                ErrorKind::InvalidValue,
                "Invalid machine proving power",
            )),
        }
    }
}

#[cfg(feature = "mock-rpc")]
impl rand::distr::Distribution<TxProvingCapability> for rand::distr::StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> TxProvingCapability {
        match rng.random_range(0..4) {
            0 => TxProvingCapability::PrimitiveWitness,
            1 => TxProvingCapability::LockScript,
            2 => TxProvingCapability::ProofCollection,
            3 => TxProvingCapability::SingleProof,
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_prove_simple() {
        assert!(
            TxProvingCapability::PrimitiveWitness.can_prove(TransactionProofType::PrimitiveWitness)
        );
        assert!(
            !TxProvingCapability::PrimitiveWitness.can_prove(TransactionProofType::ProofCollection)
        );
        assert!(!TxProvingCapability::PrimitiveWitness.can_prove(TransactionProofType::SingleProof));

        assert!(TxProvingCapability::LockScript.can_prove(TransactionProofType::PrimitiveWitness));
        assert!(!TxProvingCapability::LockScript.can_prove(TransactionProofType::ProofCollection));
        assert!(!TxProvingCapability::LockScript.can_prove(TransactionProofType::SingleProof));

        assert!(
            TxProvingCapability::ProofCollection.can_prove(TransactionProofType::PrimitiveWitness)
        );
        assert!(
            TxProvingCapability::ProofCollection.can_prove(TransactionProofType::ProofCollection)
        );
        assert!(!TxProvingCapability::ProofCollection.can_prove(TransactionProofType::SingleProof));

        assert!(TxProvingCapability::SingleProof.can_prove(TransactionProofType::PrimitiveWitness));
        assert!(TxProvingCapability::SingleProof.can_prove(TransactionProofType::ProofCollection));
        assert!(TxProvingCapability::SingleProof.can_prove(TransactionProofType::SingleProof));
    }
}
