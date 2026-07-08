//! The Neptune JSON-RPC API contract.
//!
//! This crate holds the client-facing surface of the node's JSON-RPC: the
//! [`RpcApi`](api::rpc::RpcApi) trait plus the `Rpc*` data-transfer model types.
//! It is node-independent — it depends only on the shared library crates, not on
//! neptune-core — so clients (and the RPC client crate) can speak the API
//! without pulling in the whole node. The node implements the server side.
pub mod api;
pub mod model;

/// Test-only helpers. Mirrors the per-crate `shared_tokio_runtime` macro
/// convention used across the workspace; delegates to the shared runtime in
/// `neptune-consensus` so async tests can run under `#[apply(...)]`.
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
