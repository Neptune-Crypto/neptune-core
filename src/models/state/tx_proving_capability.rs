use std::fmt::Display;
use std::str::FromStr;

use clap::error::ErrorKind;
use clap::Parser;
use serde::Deserialize;
use serde::Serialize;

use crate::models::blockchain::transaction::TransactionProof;

#[derive(
    Parser, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, PartialOrd,
)]
#[repr(u8)]
pub enum TxProvingCapability {
    #[default]
    LockScript = 1,
    PrimitiveWitness = 2,
    ProofCollection = 3,
    SingleProof = 4,
}

impl From<&TransactionProof> for TxProvingCapability {
    fn from(proof: &TransactionProof) -> Self {
        match *proof {
            TransactionProof::Witness(_) => Self::PrimitiveWitness,
            TransactionProof::ProofCollection(_) => Self::ProofCollection,
            TransactionProof::SingleProof(_) => Self::SingleProof,
        }
    }
}

impl TxProvingCapability {
    pub(crate) fn can_prove(&self, other: Self) -> bool {
        // LockScript is not yet supported.
        *self >= other && other != Self::LockScript
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
