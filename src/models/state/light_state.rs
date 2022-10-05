use std::sync::Arc;

use crate::models::blockchain::block::block_header::BlockHeader;
use crate::models::blockchain::block::Block;

#[derive(Debug, Clone)]
pub struct LightState {
    // The documentation recommends using `std::sync::Mutex` for data that lives in memory,
    // but the `stad::sync::Mutex` cannot be held across `await` and that is too restrictive
    // at the moment, since we often want to hold multiple locks at the same time, and some
    // of these require calls to await.
    pub latest_block: Arc<tokio::sync::Mutex<Block>>,
}

impl LightState {
    // TODO: Consider renaming to `new_threadsafe()` to reflect it does not return a `Self`.
    pub fn new(initial_latest_block: Block) -> Self {
        Self {
            latest_block: Arc::new(tokio::sync::Mutex::new(initial_latest_block)),
        }
    }

    pub async fn get_latest_block(&self) -> Block {
        self.latest_block.lock().await.clone()
    }

    pub async fn get_latest_block_header(&self) -> BlockHeader {
        self.latest_block.lock().await.header.clone()
    }
}
