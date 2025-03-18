//! provides public API for interacting with regtest mode.
//!
//! regtest mode is useful for local testing in a more controlled
//! and predictable manner than mainnet or testnet.
//!
//! regtest mode:
//! 1. provides a locally controlled network without peer discovery.
//! 2. enables blocks to be generated quickly without real proofs.
mod regtest_impl;

// these represent the public tx_initiator API
pub mod error;
pub use regtest_impl::RegTest;
