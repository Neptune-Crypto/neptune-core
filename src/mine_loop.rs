use crate::models::blockchain::block::{Block, BlockBody, BlockHeader, BlockHeight};
use crate::models::blockchain::digest::RescuePrimeDigest;
use crate::models::blockchain::mutator_set_update::MutatorSetUpdate;
use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::{Transaction, Utxo, AMOUNT_SIZE_FOR_U32};
use crate::models::channel::{MainToMiner, MinerToMain};
use crate::models::shared::LatestBlockInfo;
use anyhow::{Context, Result};
use num_traits::identities::Zero;
use rand::thread_rng;
use secp256k1::{rand::rngs::OsRng, Message, Secp256k1};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::select;
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep, Duration};
use tracing::{info, instrument};
use twenty_first::amount::u32s::U32s;
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::util_types::mutator_set::addition_record::{self, AdditionRecord};
use twenty_first::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use twenty_first::util_types::mutator_set::mutator_set_trait::MutatorSet;

const MOCK_REGTEST_MINIMUM_MINE_INTERVAL_SECONDS: u64 = 8;
const MOCK_REGTEST_MAX_MINING_DIFFERENCE_SECONDS: u64 = 8;

/// Return a fake block with a random hash
fn make_mock_block(height: u64) -> Block {
    // TODO: Replace this with public key sent from the main thread
    let secp = Secp256k1::new();
    let mut rng = thread_rng();
    let mut rng = OsRng::new().expect("OsRng");
    let (secret_key, public_key): (secp256k1::SecretKey, secp256k1::PublicKey) =
        secp.generate_keypair(&mut rng);

    let coinbase_utxo = Utxo {
        amount: U32s::new([100u32, 0, 0, 0]),
        public_key,
    };

    let timestamp: BFieldElement = BFieldElement::new(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Got bad time timestamp in mining process")
            .as_secs(),
    );
    let tx = Transaction {
        inputs: vec![],
        outputs: vec![coinbase_utxo],
        public_scripts: vec![],
        fee: U32s::zero(),
        timestamp,
    };

    // For now, we just assume that the mutator set was empty prior to this block
    let mut new_ms = MutatorSetAccumulator::default();

    let coinbase_digest: RescuePrimeDigest = coinbase_utxo.hash();

    // TODO: Change randomness here
    let addition_record: AdditionRecord<Hash> =
        new_ms.commit(&coinbase_digest.into(), &coinbase_digest.into());
    let mutator_set_update: MutatorSetUpdate = MutatorSetUpdate {
        removals: vec![],
        additions: vec![addition_record],
    };
    new_ms.add(&addition_record);

    let block_body: BlockBody = BlockBody {
        transactions: vec![tx],
        mutator_set_accumulator: MutatorSetAccumulator::default(),
        mutator_set_update,
    };

    let block_header = BlockHeader {
        version: BFieldElement::ring_zero(),
        height: BlockHeight::from(height),
        mutator_set_commitment: todo!(),
        prev_block_digest: todo!(),
        timestamp,
        nonce: todo!(),
        max_block_size: todo!(),
        proof_of_work_line: todo!(),
        proof_of_work_family: todo!(),
        target_difficulty: todo!(),
        block_body_merkle_root: todo!(),
        uncles: todo!(),
    };

    // let block_hash_raw: [u8; 32] = rand::random();
    // Block {
    //     version_bits: [0u8; 4],
    //     timestamp: SystemTime::now(),
    //     height: BlockHeight::from(height),
    //     nonce: [0u8; 32],
    //     predecessor: BlockHash::from([0u8; 32]),
    //     predecessor_proof: vec![],
    //     accumulated_pow_line: 0u128,
    //     accumulated_pow_family: 0u128,
    //     uncles: vec![],
    //     target_difficulty: 0u128,
    //     retarget_proof: vec![],
    //     transaction: tx,
    //     mixed_edges: vec![],
    //     mix_proof: vec![],
    //     edge_mmra: coinbase_utxo,
    //     edge_mmra_update: vec![],
    //     hash: BlockHash::from(block_hash_raw),
    // }
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
