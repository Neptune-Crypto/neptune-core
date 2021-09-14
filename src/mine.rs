use crate::model::{FromMiner, ToMiner};
use anyhow::Result;
use tokio::select;
use tokio::sync::watch;
use tokio::time::{sleep, Duration};
use tracing::{info, instrument};

const MOCK_REGTEST_MINE_INTERVAL_SECONDS: u64 = 10;

static mut BLOCK_HEIGHT: u32 = 0;

#[instrument]
pub async fn mock_regtest_mine(
    mut from_main: watch::Receiver<ToMiner>,
    to_main: watch::Sender<FromMiner>,
) -> Result<()> {
    unsafe {
        loop {
            select! {
                _ = from_main.changed() => {
                    let main_message: ToMiner = from_main.borrow().clone();
                    match main_message {
                        ToMiner::NewBlock(block_height) => {
                            if block_height > BLOCK_HEIGHT {
                                info!("Received new regtest mock block");
                                BLOCK_HEIGHT = block_height;
                            }
                        }
                    }
                }
                _ = sleep(Duration::from_secs(MOCK_REGTEST_MINE_INTERVAL_SECONDS)) => {
                    BLOCK_HEIGHT += 1;
                    to_main.send(FromMiner::NewBlock(BLOCK_HEIGHT))?;
                    info!("Found new regtest block with block height {}", BLOCK_HEIGHT);
                }
            }
        }
    }
}
