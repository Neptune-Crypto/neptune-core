//! provides builders and APIs for initiating transactions.
//!
//! The module is designed to provide flexible, low-level manipulation
//! of transactions as well as an easy to use high-level [send()](send::TransactionSender::send()) method.
//!
//! It is composed of three layers:
//!
//! 1. [builder] provides a set of transaction builders.
//! 2. [initiator] provides [TransactionInitiator](initiator) that wraps the builders and broadcasts the tx.
//! 3. [send] provides [TransactionSender](initiator) with a single, simple `send()` method.
//!
//! The RPC layer wraps and mirrors this API, except for the builders.
//!
//! note: The only API that neptune-core truly needs for transaction initiation
//! is [record_and_broadcast_transaction()](initiator::TransactionInitiator::record_and_broadcast_transaction()).
//! Everything else is provided to facilitate transaction creation.
//!
//! # Transaction Initiation Sequence
//!
//! When initiating a transaction, the typical sequence is:
//!  1. create tx inputs and outputs.
//!  2. create tx details.
//!  3. generate a primitive witness proof for tx details.
//!  4. assemble the transaction.
//!  5. record and broadcast the transaction.
//!
//!  (6-10 are internal to neptune-core)
//!
//!  6. upgrade the proof to ProofCollection.
//!  7. broadcast the transaction to other nodes.
//!  8. a powerful node upgrades the proof to SingleProof, collecting a portion of fee.
//!  9. a composer adds the proof to a block-template
//! 10. a prover (miner) mines the Tx into a block.
//!
//! note: `TransactionSender::send()` performs steps 1-5.
//!
//! # Client Provides Proof Initiation Sequence
//!
//! One can save neptune network resources and possibly save on fees by
//! generating a `SingleProof` yourself, outside neptune-core. This requires a
//! powerful machine.  As of this writing, minimum requirements are 64 CPU cores
//! and 128Gb RAM, with 256Gb RAM or more being faster.
//!
//! This sequence looks like:
//!
//!  1. create tx inputs and outputs.
//!  2. create tx details.
//!  3. generate a SingleProof for tx details.
//!  4. assemble the transaction.
//!  5. record and broadcast the transaction.
//!
//!  (6-8 are internal to neptune-core)
//!
//!  6. neptune-core broadcasts the transaction to other nodes.
//!  7. a composer adds the proof to a block-template
//!  8. a prover (miner) mines the Tx into a block.
//!
//! this sequence requires using the [builder] or [initiator] API.

// note to neptune devs:
//
// a lot of design and effort went into re-writing account creation code and
// organizing it into this module, documenting, etc.  It is quite clean now.
//
// Let's keep it that way!   Please no commits in this module without review!!

// these represent the public tx_initiator API
pub mod builder;
pub mod error;
pub mod initiator;
pub mod send;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod test_util;

// private worker
mod private;
