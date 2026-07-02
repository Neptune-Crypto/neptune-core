//! Wallet functionality for Neptune Cash.
//!
//! This crate provides storage-agnostic wallet building blocks — key and address
//! derivation, transaction-output construction, coin selection and change — for
//! Neptune Cash. It deliberately makes no decisions about how owned UTXOs are
//! persisted; that is left to consumers such as neptune-core.

pub mod coin_with_possible_timelock;
pub mod scan_mode_configuration;
