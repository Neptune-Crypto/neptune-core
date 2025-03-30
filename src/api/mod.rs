//! public api for common neptune-core operations
//!
//! the neptune-core library crate has been implemented to build the
//! neptune-core (binary) server.  As such, it does not have a clean
//! public API.  This module attempts to rectify that situation
//! by providing types for performing common user tasks.
//!
//! further, this module aims to:
//! 1. bring the public rust API to parity with the RPC layer.
//! 2. be the layer beneath the RPC layer, so those method just call these.
pub mod export;
pub mod regtest;
pub mod tx_initiation;

// developers:  this module has its own conventions and rules.  please read the
// README file in this directory before making any changes to this module, or a
// sub-module.
