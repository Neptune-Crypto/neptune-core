use crate::model::{Block, FromMinerToMain, ToMiner, Transaction, Utxo};
use anyhow::Result;
use std::time::SystemTime;
use tokio::select;
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep, Duration};
use tracing::{info, instrument};

const MOCK_REGTEST_MINE_INTERVAL_SECONDS: u64 = 10;

static mut BLOCK_HEIGHT: u64 = 0;

fn make_mock_block(height: u64) -> Block {
    let utxo_pol = [0u32; 2048];
    let utxo = Utxo {
        pol0: utxo_pol,
        pol1: utxo_pol,
    };

    let tx = Transaction {
        input: vec![utxo.clone()],
        output: vec![utxo.clone()],
        public_scripts: vec![],
        proof: vec![],
    };
    Block {
        version_bits: [0u8; 4],
        timestamp: SystemTime::now(),
        height,
        nonce: [0u8; 32],
        predecessor: [0u8; 32],
        predecessor_proof: vec![],
        accumulated_pow_line: 0u128,
        accumulated_pow_family: 0u128,
        uncles: vec![],
        target_difficulty: 0u128,
        retarget_proof: vec![],
        transaction: tx,
        mixed_edges: vec![],
        mix_proof: vec![],
        edge_mmra: utxo,
        edge_mmra_update: vec![],
        hash: [0u8; 32],
    }
}

#[instrument]
pub async fn mock_regtest_mine(
    mut from_main: watch::Receiver<ToMiner>,
    to_main: mpsc::Sender<FromMinerToMain>,
) -> Result<()> {
    // This is unsafe because the Rust compiler will not allow manipulation of a static
    // data type (BLOCK_HEIGHT) in an async function. This is because updates to it are
    // not thread-safe. But if we only run *one* mining thread, this should be fine.
    // Also: This is a mock example, and we don't need to spend too much mental effort
    // on making it perfect.
    unsafe {
        loop {
            select! {
                _ = from_main.changed() => {
                    let main_message: ToMiner = from_main.borrow().clone();
                    match main_message {
                        ToMiner::NewBlock(block) => {
                            if block.height > BLOCK_HEIGHT {
                                info!("Miner thread received new regtest mock block from main thread");
                                BLOCK_HEIGHT = block.height;
                            }
                        }
                        ToMiner::Empty => ()
                    }
                }
                _ = sleep(Duration::from_secs(MOCK_REGTEST_MINE_INTERVAL_SECONDS)) => {
                    BLOCK_HEIGHT += 1;

                    to_main.send(FromMinerToMain::NewBlock(Box::new(make_mock_block(BLOCK_HEIGHT)))).await?;
                    info!("Found new regtest block with block height {}", BLOCK_HEIGHT);
                }
            }
        }
    }
}
