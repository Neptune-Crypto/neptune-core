//! provides public API for the neptune-core wallet.
mod wallet_balances;
mod wallet_impl;

// these represent the public API
pub mod error;
pub use wallet_balances::WalletBalances;
pub use wallet_impl::Wallet;
