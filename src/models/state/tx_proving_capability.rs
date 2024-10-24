use std::str::FromStr;

use clap::error::ErrorKind;
use clap::Parser;

#[derive(Parser, Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxProvingCapability {
    PrimitiveWitness,
    LockScript,
    ProofCollection,
    SingleProof,
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
