//! The Neptune transaction mempool.
//!
//! This crate holds the [`Mempool`](mempool::Mempool) store together with the
//! small set of abstractions it is built on:
//!
//! - [`transaction_kernel_id`] — the `TransactionKernelId`/`Txid` identifiers
//!   used to key transactions in the mempool.
//! - [`upgrade_incentive`] and [`mempool::upgrade_priority`] — the priority
//!   model that decides which transactions are worth proof-upgrading.
//! - [`transaction_proof_quality`] — the node-level proof-quality policy used
//!   for mempool replacement and peer gossip.
//! - [`tx_upgrade_filter`] — the TXID filter that partitions upgrade work.

// enable the unstable "coverage" attribute, so that `#[cfg_attr(coverage_nightly,
// coverage(off))]` compiles under `cargo +nightly llvm-cov` and is a no-op
// otherwise.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod mempool;
pub mod transaction_kernel_id;
pub mod transaction_proof_quality;
pub mod tx_upgrade_filter;
pub mod upgrade_incentive;

/// Test-only helpers. Mirrors the per-crate `shared_tokio_runtime` macro,
/// delegating to the shared runtime in `neptune-consensus` so async tests can
/// run under `#[apply(...)]`.
#[cfg(test)]
mod test_utils {
    macro_rules! shared_tokio_runtime {
        (
            $(#[$fn_meta:meta])*
            $vis:vis async fn $fn_name:ident() $(-> $ret:ty)? {
                $($tt:tt)*
            }
        ) => {
            $(#[$fn_meta])*
            #[test]
            $vis fn $fn_name() $(-> $ret)? {
                let runtime = neptune_consensus::proof_abstractions::test_runtime::tokio_runtime();
                runtime.block_on(async {
                    $vis async fn __inner() $(-> $ret)? {
                        $($tt)*
                    }
                    __inner().await
                })
            }
        };
    }
    pub(crate) use shared_tokio_runtime;
}
