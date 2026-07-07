//! The Neptune peer-to-peer protocol types.
//!
//! This crate holds the wire types exchanged between nodes — the
//! [`PeerMessage`](peer::PeerMessage) enum and its payloads (handshake, block
//! and transaction transfers, notifications, sync challenges) — together with
//! the peer-identity and peer-standing types used to track and score peers.
//!
//! It contains data types only; the peer connection/loop orchestration lives in
//! neptune-core.

// enable the unstable "coverage" attribute, so that `#[cfg_attr(coverage_nightly,
// coverage(off))]` compiles under `cargo +nightly llvm-cov` and is a no-op
// otherwise.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod block_proposal_notification;
pub mod peer;
pub mod synchronization_bit_mask;
