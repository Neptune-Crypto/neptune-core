use crate::models::blockchain::block::block_body::BlockBody;
use crate::models::blockchain::block::block_header::BlockHeader;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::mutator_set_update::*;
use crate::models::blockchain::block::*;
use crate::models::blockchain::digest::ordered_digest::*;
use crate::models::blockchain::digest::*;
use crate::models::blockchain::shared::*;
use crate::models::blockchain::simple::*;
use crate::models::blockchain::transaction::utxo::*;
use crate::models::blockchain::transaction::*;
use crate::models::channel::*;
use crate::models::state::State;
use anyhow::{Context, Result};
use futures::channel::oneshot;
use mutator_set_tf::util_types::mutator_set::addition_record::AdditionRecord;
use mutator_set_tf::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use mutator_set_tf::util_types::mutator_set::mutator_set_trait::MutatorSet;
use num_traits::identities::Zero;
use rand::thread_rng;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::select;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::*;
use twenty_first::amount::u32s::U32s;
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::shared_math::traits::GetRandomElements;

const MOCK_MAX_BLOCK_SIZE: u32 = 1_000_000;
const MOCK_DIFFICULTY: u32 = 10_000;

/// Attempt to mine a valid block for the network
#[tracing::instrument(skip_all, level = "debug")]
async fn make_devnet_block(
    previous_block: Block,
    sender: oneshot::Sender<Block>,
    public_key: secp256k1::PublicKey,
    state: State,
    incoming_simple_transactions: Vec<SignedSimpleTransaction>,
) {
    let next_block_height: BlockHeight = previous_block.header.height.next();
    let coinbase_utxo = Utxo {
        amount: Block::get_mining_reward(next_block_height),
        public_key,
    };

    let timestamp: BFieldElement = BFieldElement::new(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Got bad time timestamp in mining process")
            .as_secs(),
    );

    let output_randomness: Vec<BFieldElement> =
        BFieldElement::random_elements(RESCUE_PRIME_OUTPUT_SIZE_IN_BFES, &mut thread_rng());
    let coinbase_transaction = Transaction {
        inputs: vec![],
        outputs: vec![(coinbase_utxo.clone(), output_randomness.clone().into())],
        public_scripts: vec![],
        fee: U32s::zero(),
        timestamp,
    };

    let incoming_transactions = incoming_simple_transactions
        .iter()
        .map(|stx: &SignedSimpleTransaction| -> Transaction {
            Transaction {
                inputs: vec![],
                outputs: stx
                    .tx
                    .outputs
                    .iter()
                    .map(|utxo| (utxo.clone(), output_randomness.clone().into()))
                    .collect(),
                public_scripts: vec![],
                fee: U32s::zero(),
                timestamp,
            }
        })
        .collect();

    // For now, we just mine blocks with only the coinbase transaction. Therefore, the
    // mutator set update structure only contains an addition record, and no removal
    // records, as these represent spent UTXOs
    let mut new_ms: MutatorSetAccumulator<Hash> =
        previous_block.body.next_mutator_set_accumulator.clone();
    let coinbase_digest: Digest = coinbase_utxo.hash();
    let mut coinbase_addition_record: AdditionRecord<Hash> =
        new_ms.commit(&coinbase_digest.into(), &output_randomness);
    let mutator_set_update: MutatorSetUpdate = MutatorSetUpdate {
        removals: vec![],
        additions: vec![coinbase_addition_record.clone()],
    };
    new_ms.add(&mut coinbase_addition_record);

    let block_body: BlockBody = BlockBody {
        transactions: [vec![coinbase_transaction], incoming_transactions].concat(),
        next_mutator_set_accumulator: new_ms.clone(),
        mutator_set_update,
        previous_mutator_set_accumulator: previous_block.body.next_mutator_set_accumulator,
        stark_proof: vec![],
    };

    let zero = BFieldElement::ring_zero();
    let difficulty: U32s<5> = U32s::new([MOCK_DIFFICULTY, 0, 0, 0, 0]);
    let new_pow_line = previous_block.header.proof_of_work_family + difficulty;
    let mut block_header = BlockHeader {
        version: zero,
        height: next_block_height,
        mutator_set_commitment: new_ms.get_commitment().into(),
        prev_block_digest: previous_block.header.hash(),
        timestamp,
        nonce: [zero, zero, zero],
        max_block_size: MOCK_MAX_BLOCK_SIZE,
        proof_of_work_line: new_pow_line,
        proof_of_work_family: new_pow_line,
        target_difficulty: difficulty,
        block_body_merkle_root: block_body.hash(),
        uncles: vec![],
    };

    // Mining takes place here
    while Into::<OrderedDigest>::into(block_header.hash())
        >= OrderedDigest::to_digest_threshold(difficulty)
    {
        // If the sender is cancelled, the parent to this thread most
        // likely received a new block, and this thread hasn't been stopped
        // yet by the operating system, although the call to abort this
        // thread *has* been made.
        if sender.is_canceled() {
            info!(
                "Abandoning mining of current block with height {}",
                next_block_height
            );
            return;
        }

        // Don't mine if we are syncing
        if block_header.nonce[2].value() % 100 == 0 && state.net.syncing.read().unwrap().to_owned()
        {
            return;
        }

        if block_header.nonce[2].value() == BFieldElement::MAX {
            block_header.nonce[2] = BFieldElement::ring_zero();
            if block_header.nonce[1].value() == BFieldElement::MAX {
                block_header.nonce[1] = BFieldElement::ring_zero();
                block_header.nonce[0].increment();
                continue;
            }
            block_header.nonce[1].increment();
            continue;
        }
        block_header.nonce[2].increment();
    }
    info!(
        "Found valid block with nonce: ({}, {}, {})",
        block_header.nonce[0], block_header.nonce[1], block_header.nonce[2]
    );

    sender
        .send(Block::new(block_header, block_body))
        .unwrap_or_else(|_| warn!("Receiver in mining loop closed prematurely"))
}

#[tracing::instrument(skip_all)]
pub async fn mock_regtest_mine(
    mut from_main: watch::Receiver<MainToMiner>,
    to_main: mpsc::Sender<MinerToMain>,
    mut latest_block: Block,
    own_public_key: secp256k1::PublicKey,
    state: State,
) -> Result<()> {
    let mut incoming_transactions_tmp = vec![];
    loop {
        let (sender, receiver) = oneshot::channel::<Block>();
        let state_clone = state.clone();
        let miner_thread: Option<JoinHandle<()>> = if state.net.syncing.read().unwrap().to_owned() {
            info!("Not mining because we are syncing");
            None
        } else {
            let itx_owned = incoming_transactions_tmp.clone();
            incoming_transactions_tmp = vec![];
            Some(tokio::spawn(make_devnet_block(
                latest_block.clone(),
                sender,
                own_public_key,
                state_clone,
                itx_owned,
            )))
        };

        select! {
            changed = from_main.changed() => {
                info!("Mining thread got message from main");
                if let e@Err(_) = changed {
                    return e.context("Miner failed to read from watch channel");
                }

                let main_message: MainToMiner = from_main.borrow_and_update().clone();
                match main_message {
                    MainToMiner::NewBlock(block) => {
                        if let Some(mt) = miner_thread {
                            mt.abort();
                        }
                        latest_block = *block;
                        info!("Miner thread received regtest block height {}", latest_block.header.height);
                    }
                    MainToMiner::Empty => (),
                    MainToMiner::Send(incoming_txs) => {
                        debug!("Miner thread received incoming transactions from main: {:?}", incoming_txs);
                        incoming_transactions_tmp = incoming_txs
                    },
                }
            }
            new_fake_block_res = receiver => {
                let new_fake_block = match new_fake_block_res {
                    Ok(block) => block,
                    Err(err) => {
                        warn!("Mining thread was cancelled prematurely. Got: {}", err);
                        continue;
                    }
                };

                info!("Found new regtest block with block height {}. Hash: {:?}", new_fake_block.header.height, new_fake_block.hash);
                latest_block = new_fake_block.clone();
                to_main.send(MinerToMain::NewBlock(Box::new(new_fake_block))).await?;
            }
        }
    }
}
