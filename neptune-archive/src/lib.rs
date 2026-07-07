//! Neptune archival state.
//!
//! This crate holds the node's archival storage: on-disk block files, the
//! block index ([`block_index`]), the archival block MMR
//! ([`rusty_archival_block_mmr`]), the archival mutator set, and the optional
//! UTXO index — together with the
//! [`ArchivalState`](archival_state::ArchivalState) that ties them together.

// enable the unstable "coverage" attribute, so that `#[cfg_attr(coverage_nightly,
// coverage(off))]` compiles under `cargo +nightly llvm-cov` and is a no-op
// otherwise.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod archival_state;
pub mod block_index;
pub mod rusty_archival_block_mmr;
pub mod shared;

#[cfg(test)]
mod archival_state_tests;

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
