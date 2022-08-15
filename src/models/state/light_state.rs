use std::sync::Arc;
use std::sync::Mutex as StdMutex;

use crate::models::blockchain::block::block_header::BlockHeader;

#[derive(Debug, Clone)]
pub struct LightState {
    // From the documentation of `tokio::sync::Mutex`:
    // "If the value behind the mutex is just data, it's usually appropriate to use a blocking mutex
    // such as the one in the standard library or (...)"
    pub latest_block_header: Arc<StdMutex<BlockHeader>>,
}

impl LightState {
    // TODO: Consider renaming to `new_threadsafe()` to reflect it does not return a `Self`.
    pub fn new(initial_latest_block_header: BlockHeader) -> Self {
        Self {
            latest_block_header: Arc::new(StdMutex::new(initial_latest_block_header)),
        }
    }

    pub fn get_latest_block_header(&self) -> BlockHeader {
        self.latest_block_header.lock().unwrap().clone()
    }
}
