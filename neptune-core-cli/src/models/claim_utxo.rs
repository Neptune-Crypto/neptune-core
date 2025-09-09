use std::path::PathBuf;

use clap::Subcommand;

/// represents data format of input to claim-utxo
#[derive(Debug, Clone, Subcommand)]
pub(crate) enum ClaimUtxoFormat {
    /// reads a utxo-transfer json file
    File {
        /// path to the file
        path: PathBuf,
    },
    Raw {
        /// The encrypted UTXO notification payload.
        ciphertext: String,
    },
}
