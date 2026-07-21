//! Transaction chaining.
//!
//! Data structures and consensus programs for the transaction-chaining
//! (`LinkTx`) pipeline that runs parallel to the legacy `Transaction` pipeline.

pub mod link_kernel;
pub mod link_witness;
