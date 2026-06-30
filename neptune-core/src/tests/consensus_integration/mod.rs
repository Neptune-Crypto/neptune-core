//! Tests that exercise consensus behaviour through node-level state
//! (GlobalState, mining loop, wallet). They validate consensus rules and block
//! validity but require machinery that lives above the consensus layer, so they
//! cannot live in (the to-be-extracted) neptune-consensus. Distinct from the
//! RegTest integration tests in `neptune-core/tests/`.

pub mod block;
pub mod block_program;
pub mod block_validation_error;
pub mod consensus_rule_set;
pub mod primitive_witness;
pub mod transaction;
