//! public api for common neptune-core operations
//!
//! The neptune-core library crate has been implemented to build the
//! neptune-core (binary) server.  As such, it was not built with a cohesive
//! public API in mind.
//!
//! This module aims to:
//! 1. simplify and/or enable common tasks.
//! 2. bring the public rust API to parity with the RPC layer.
//! 3. be the layer beneath the RPC layer, so those methods wrap these.
//!
//! This module is a work-in-progress and is presently incomplete for many tasks
//! that a wallet software might need to do, however it can serve as a starting
//! point.
//!
//! Starting out, it is necessary to understand how to start a node
//! and obtain a GlobalStateLock handle.  here's how:
//!
//! ```no_run
//! use neptune_cash::api::export;
//! use export::GlobalStateLock;
//! use export::Args;
//! use export::Timestamp;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!
//!     let args = Args::default();
//!
//!     // initialize
//!     let mut main_loop_handler = neptune_cash::initialize(args).await?;
//!     let gsl = main_loop_handler.global_state_lock();
//!
//!     // spawn tokio task to start the node running
//!     let main_loop_join_handle =
//!         tokio::task::spawn(async move { main_loop_handler.run().await });
//!
//!     // use the API ...
//!     println!("wallet balances:\n\n{}", gsl.api().wallet().balances(Timestamp::now()).await);
//!
//!     Ok(())
//! }
//! ```
//!
//! Please read the [GlobalStateLock](crate::GlobalStateLock) docs carefully because it is critical
//! not to hold the lock too long or cause a deadlock situation.
mod api_impl;
pub mod export;
pub mod regtest;
pub mod tx_initiation;
pub mod wallet;

pub use api_impl::Api;

// developers:  this module has its own conventions and rules.  please read the
// README file in this directory before making any changes to this module, or a
// sub-module.
