use crate::models::blockchain::{Block, BlockHash, BlockHeight, Transaction, Utxo};
use crate::models::channel::{MainToMiner, MinerToMain};
use crate::models::shared::LatestBlockInfo;
use anyhow::{Context, Result};
use std::time::SystemTime;
use tokio::select;
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep, Duration};
use tracing::{info, instrument};

const MOCK_REGTEST_MINIMUM_MINE_INTERVAL_SECONDS: u64 = 8;
const MOCK_REGTEST_MAX_MINING_DIFFERENCE_SECONDS: u64 = 8;

/// Return a fake block with a random hash
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
    let block_hash_raw: [u8; 32] = rand::random();
    Block {
        version_bits: [0u8; 4],
        timestamp: SystemTime::now(),
        height: BlockHeight::from(height),
        nonce: [0u8; 32],
        predecessor: BlockHash::from([0u8; 32]),
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
        hash: BlockHash::from(block_hash_raw),
    }
}

#[instrument]
pub async fn mock_regtest_mine(
    mut from_main: watch::Receiver<MainToMiner>,
    to_main: mpsc::Sender<MinerToMain>,
    latest_block_info_res: Option<LatestBlockInfo>,
) -> Result<()> {
    let mut block_height: u64 = match latest_block_info_res {
        None => 0u64,
        Some(latest_block_info) => latest_block_info.height.into(),
    };
    loop {
        let rand_time: u64 = rand::random::<u64>() % MOCK_REGTEST_MAX_MINING_DIFFERENCE_SECONDS;
        select! {
            changed = from_main.changed() => {
                if let e@Err(_) = changed {
                    return e.context("Miner failed to read from watch channel");
                }

                let main_message: MainToMiner = from_main.borrow_and_update().clone();
                match main_message {
                    MainToMiner::NewBlock(block) => {
                        block_height = block.height.into();
                        info!("Miner thread received regtest block height {}", block_height);
                    }
                    MainToMiner::Empty => ()
                }
            }
            _ = sleep(Duration::from_secs(MOCK_REGTEST_MINIMUM_MINE_INTERVAL_SECONDS + rand_time)) => {
                block_height += 1;

                let new_fake_block = make_mock_block(block_height);
                info!("Found new regtest block with block height {}. Hash: {:?}", new_fake_block.height, new_fake_block.hash);
                to_main.send(MinerToMain::NewBlock(Box::new(new_fake_block))).await?;
            }
        }
    }
}
