use std::str::FromStr;

use clap::error::ErrorKind;
use clap::Parser;

#[derive(Parser, Debug, Clone, Copy)]
pub enum TxProvingCapability {
    LockScript,
    ProofCollection,
    SingleProof,
}

impl FromStr for TxProvingCapability {
    type Err = clap::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
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
