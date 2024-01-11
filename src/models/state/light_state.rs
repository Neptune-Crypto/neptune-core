use crate::models::blockchain::block::Block;

/// LightState is just a thread-safe Block.
/// (always representing the latest block)
pub type LightState = Block;
