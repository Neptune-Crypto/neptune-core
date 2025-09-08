use std::sync::Arc;

use crate::protocol::consensus::block::Block;

// perf: we make LightState an Arc<Block> so it can be
// cheaply cloned and passed around, eg in
// channel messages.

/// LightState is just a thread-safe Block.
/// (always representing the latest block)
pub type LightState = Arc<Block>;
