//! Consensus logic and proof abstractions for Neptune Cash.
//!
//! This crate defines the protocol's consensus rules -- `block`, `transaction`,
//! `network`, `consensus_rule_set`, and `type_scripts` -- and the
//! `proof_abstractions` used to verify them via Triton VM STARK proofs.

// recursion limit for macros (e.g. triton_asm!)
#![recursion_limit = "2048"]
// If code coverage tool `cargo-llvm-cov` is running with the nightly toolchain,
// enable the unstable "coverage" attribute, so that `#[cfg_attr(coverage_nightly,
// coverage(off))]` annotations on test modules resolve.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::env;
use std::time::Instant;

// Derive macros for `BFieldCodec`/`TasmObject` (and friends) generate paths
// like `crate::twenty_first` / `crate::triton_vm` / `crate::tasm_lib`. These
// re-exports make those generated paths resolve within this crate.
pub use tasm_lib;
pub use tasm_lib::prelude::triton_vm;
pub use tasm_lib::prelude::twenty_first;

pub mod macros;
pub mod prelude;

/// If an optional threshold value is provided then nothing will be
/// logged unless execution duration exceeds the threshold.
/// In that case a tracing::warn!() is logged.
///
/// If no threshold value is provided then a tracing::debug!()
/// is always logged with the duration.
///
/// for convenience see macros:
///  crate::macros::log_slow_scope,
///  crate::macros::log_scope_duration,
#[derive(Debug, Clone)]
pub struct ScopeDurationLogger<'a> {
    start: Instant,
    description: &'a str,
    log_slow_fn_threshold: Option<f64>,
    location: &'static std::panic::Location<'static>,
}
impl<'a> ScopeDurationLogger<'a> {
    #[track_caller]
    pub fn new(description: &'a str, log_slow_fn_threshold: Option<f64>) -> Self {
        Self {
            start: Instant::now(),
            description,
            log_slow_fn_threshold,
            location: std::panic::Location::caller(),
        }
    }

    #[track_caller]
    pub fn new_with_threshold(description: &'a str, log_slow_fn_threshold: f64) -> Self {
        Self::new(description, Some(log_slow_fn_threshold))
    }

    #[track_caller]
    pub fn new_default_threshold(description: &'a str) -> Self {
        Self::new_with_threshold(
            description,
            match env::var("LOG_SLOW_SCOPE_THRESHOLD") {
                Ok(t) => t.parse().unwrap(),
                Err(_) => 0.001,
            },
        )
    }

    #[track_caller]
    pub fn new_without_threshold(description: &'a str) -> Self {
        Self::new(description, None)
    }
}

impl Drop for ScopeDurationLogger<'_> {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed();
        let duration = elapsed.as_secs_f64();

        if let Some(threshold) = self.log_slow_fn_threshold {
            if duration >= threshold {
                let msg = format!(
                    "executed {} in {} secs.  exceeds slow fn threshold of {} secs.  location: {}",
                    self.description, duration, threshold, self.location,
                );

                tracing::debug!("{}", msg);
            }
        } else {
            let msg = format!(
                "executed {} in {} secs.  location: {}",
                self.description, duration, self.location,
            );

            tracing::debug!("{}", msg);
        }
    }
}

pub mod block;
pub mod consensus_rule_set;
pub mod proof_abstractions;
pub mod transaction;
pub mod type_scripts;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use itertools::Itertools;

    use crate::block;
    use crate::proof_abstractions::tasm::program::TritonProgram;
    use crate::transaction;
    use crate::type_scripts;

    #[test]
    fn print_all_validity_program_names() {
        macro_rules! name_and_lib {
            [$($t:expr),* $(,)?] => {[$({
                let (library, _) = $t.library_and_code();
                let snippet_names = library
                    .get_all_snippet_names()
                    .into_iter()
                    .map(annotate_with_sign_off_status)
                    .collect_vec();
                (stringify!($t), snippet_names)
            }),*]};
        }

        /// Annotate a snippet name with a somewhat dramatic visualization of the
        /// sign-off status.
        fn annotate_with_sign_off_status(name: String) -> String {
            let Some(snippet) = tasm_lib::exported_snippets::name_to_snippet(&name) else {
                return format!("⚠ {name}");
            };

            let sign_offs = snippet.sign_offs();
            if sign_offs.is_empty() {
                return format!("🅾 {name}");
            }

            format!("{} {name}", sign_offs.len())
        }

        let all_consensus_critical_imports = name_and_lib![
            block::validity::block_program::BlockProgram,
            transaction::validity::collect_lock_scripts::CollectLockScripts,
            transaction::validity::collect_type_scripts::CollectTypeScripts,
            transaction::validity::kernel_to_outputs::KernelToOutputs,
            type_scripts::native_currency::NativeCurrency,
            transaction::validity::removal_records_integrity::RemovalRecordsIntegrity,
            transaction::validity::single_proof::SingleProof,
            type_scripts::time_lock::TimeLock,
            // todo: what about those?
            // block_validity::coinbase_is_valid::CoinbaseIsValid,
            // block_validity::correct_control_parameter_update::CorrectControlParameterUpdate,
            // block_validity::correct_mmr_update::CorrectMmrUpdate,
            // block_validity::correct_mutator_set_update::CorrectMutatorSetUpdate,
            // block_validity::mmr_membership::MmrMembership,
            // block_validity::predecessor_is_valid::PredecessorIsValid,
            // block_validity::PrincipalBlockValidationLogic,
        ]
        .into_iter()
        .flat_map(|(name, snippet_names)| [vec![format!("\n{name}")], snippet_names].concat())
        .unique()
        .join("\n");

        println!("{all_consensus_critical_imports}");
    }
}
