pub mod multiaddr;

use num_traits::Zero;
use sysinfo::System;

use crate::api::export::TxProvingCapability;
use crate::application::config::auto_consolidation::AutoConsolidationSetting;

use super::cli_args::Args;

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub(crate) enum CliArgsParseError {
    #[error("Consolidation address is invalid: {0}")]
    InvalidConsolidationAddress(String),

    #[error("If composition is selected, proving capability must be single proof")]
    ComposerMustBeSingleProofCapable,
}

impl Args {
    /// Parse CLI arguments supplementary to CLAP's native parsing.
    ///
    /// # Side Effects
    ///
    /// Sets cache.
    pub(crate) fn second_parse(&mut self) -> Result<(), CliArgsParseError> {
        let auto_consolidate =
            AutoConsolidationSetting::parse(&self.auto_consolidate, self.network)
                .map_err(CliArgsParseError::InvalidConsolidationAddress)?;
        self.auto_consolidate_cache.set(auto_consolidate).unwrap();

        let proving_capability = self.derive_proving_capability()?;
        self.tx_proving_capability_cache
            .set(proving_capability)
            .expect("This function may only be called once.");

        Ok(())
    }

    pub(super) fn derive_proving_capability(
        &self,
    ) -> Result<TxProvingCapability, CliArgsParseError> {
        let proving_capability = match self.tx_proving_capability {
            Some(cap) => cap,
            None => Self::estimate_proving_capability(),
        };

        if self.compose && proving_capability != TxProvingCapability::SingleProof {
            return Err(CliArgsParseError::ComposerMustBeSingleProofCapable);
        };

        Ok(proving_capability)
    }

    fn estimate_proving_capability() -> TxProvingCapability {
        const SINGLE_PROOF_CORE_REQ: usize = 19;
        // see https://github.com/Neptune-Crypto/neptune-core/issues/426
        const SINGLE_PROOF_MEMORY_USAGE: u64 = (1u64 << 30) * 120;

        const PROOF_COLLECTION_CORE_REQ: usize = 2;
        const PROOF_COLLECTION_MEMORY_USAGE: u64 = (1u64 << 30) * 16;

        let s = System::new_all();
        let total_memory = s.total_memory();
        assert!(
            !total_memory.is_zero(),
            "Total memory reported illegal value of 0"
        );

        let physical_core_count = s.physical_core_count().unwrap_or(1);

        if total_memory > SINGLE_PROOF_MEMORY_USAGE && physical_core_count > SINGLE_PROOF_CORE_REQ {
            TxProvingCapability::SingleProof
        } else if total_memory > PROOF_COLLECTION_MEMORY_USAGE
            && physical_core_count > PROOF_COLLECTION_CORE_REQ
        {
            TxProvingCapability::ProofCollection
        } else {
            TxProvingCapability::PrimitiveWitness
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_own_proving_capability() {
        // doubles as a no-crash test
        println!("{}", Args::estimate_proving_capability());
    }

    #[test]
    fn can_parse_default_cli_args() {
        let mut cli = Args::default();
        assert!(cli.second_parse().is_ok());
    }
}
