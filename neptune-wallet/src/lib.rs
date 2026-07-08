//! Wallet functionality for Neptune Cash.
//!
//! This crate provides storage-agnostic wallet building blocks — key and address
//! derivation, transaction-output construction, coin selection and change — for
//! Neptune Cash. It deliberately makes no decisions about how owned UTXOs are
//! persisted; that is left to consumers such as neptune-core.

// Derive macros for `BFieldCodec`/`TasmObject` (and friends) generate paths like
// `crate::twenty_first` / `crate::triton_vm` / `crate::tasm_lib`. These re-exports
// make those generated paths resolve within this crate.
pub use tasm_lib;
pub use tasm_lib::prelude::triton_vm;
pub use tasm_lib::prelude::twenty_first;

pub mod address;
pub mod change_policy;
pub mod coin_with_possible_timelock;
pub mod coinbase_distribution;
pub mod composer_parameters;
pub mod expected_utxo;
pub mod fee_notification_policy;
pub mod incoming_utxo;
#[cfg(any(test, feature = "test-helpers"))]
pub mod mock_block;
pub mod scan_mode_configuration;
pub mod secret_key_material;
pub mod transaction_details;
pub mod transaction_output;
pub mod unlocked_utxo;
pub mod utxo_notification;
pub mod wallet_entropy;
pub mod wallet_file;
