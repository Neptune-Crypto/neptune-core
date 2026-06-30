//! Consensus logic and proof abstractions for Neptune Cash.
//!
//! This crate contains the `protocol::consensus` and
//! `protocol::proof_abstractions` subtrees, which define the protocol's
//! consensus rules and the abstractions used to verify them via Triton VM
//! STARK proofs.

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

pub mod protocol {
    pub mod consensus;
    pub mod proof_abstractions;
}
