//! Archival mutator set: the database-backed companion to the in-memory
//! accumulator defined in [`neptune_mutator_set`].
//!
//! This crate holds the parts of the mutator set that depend on
//! [`neptune_database`] storage — the [`ArchivalMutatorSet`] and its
//! `neptune-database`-backed wrapper [`RustyArchivalMutatorSet`]. It was split
//! out of `neptune-mutator-set` so that consumers of the consensus logic that
//! only need the accumulator (e.g. `neptune-consensus` and the RPC API
//! contract) do not have to depend on `neptune-database`.
//!
//! [`ArchivalMutatorSet`]: archival_mutator_set::ArchivalMutatorSet
//! [`RustyArchivalMutatorSet`]: rusty_archival_mutator_set::RustyArchivalMutatorSet

pub mod archival_mutator_set;
pub mod rusty_archival_mutator_set;

#[cfg(any(test, feature = "test-helpers"))]
pub mod test_shared;

#[cfg(test)]
mod test_utils {
    use std::sync::OnceLock;

    use tokio::runtime::Runtime;

    pub fn tokio_runtime() -> &'static Runtime {
        static RUNTIME: OnceLock<Runtime> = OnceLock::new();
        RUNTIME.get_or_init(|| Runtime::new().unwrap())
    }

    /// Runs an `async fn` test on a shared, multi-thread tokio runtime.
    ///
    /// Apply with `#[apply(shared_tokio_runtime)]` (from `macro_rules_attr`).
    macro_rules! shared_tokio_runtime {
        (
            $(#[$fn_meta:meta])*
            $vis:vis async fn $fn_name:ident() $(-> $ret:ty)? {
                $($tt:tt)*
            }
        ) => {
            $(#[$fn_meta])*
            #[test]
            // Propagate the return type and visibility to the #[test] fn.
            $vis fn $fn_name() $(-> $ret)? {
                let runtime = $crate::test_utils::tokio_runtime();
                runtime.block_on(async {
                    $vis async fn __inner() $(-> $ret)? {
                        $($tt)*
                    }
                    __inner().await // Return the awaited result
                })
            }
        };
    }

    pub(crate) use shared_tokio_runtime;
}

// Tests relocated from `neptune-mutator-set`: these exercise the in-memory
// accumulator / membership-proof types against a database-backed archival
// mutator set, so they must live in the crate that can depend on both.
#[cfg(test)]
mod ms_membership_proof_tests;
#[cfg(test)]
mod mutator_set_accumulator_tests;
