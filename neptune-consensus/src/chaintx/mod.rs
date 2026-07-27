//! Transaction chaining.
//!
//! Data structures and consensus programs for the transaction-chaining
//! (`LinkTx`) pipeline that runs parallel to the legacy `Transaction` pipeline.

pub mod forge;
pub mod link_kernel;
pub mod link_primitive_witness;
pub mod link_proof;
pub mod link_proof_witness;
pub mod link_tx;
