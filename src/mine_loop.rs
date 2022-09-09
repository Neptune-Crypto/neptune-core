use crate::models::blockchain::block::block_body::BlockBody;
use crate::models::blockchain::block::block_header::BlockHeader;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::mutator_set_update::*;
use crate::models::blockchain::block::*;
use crate::models::blockchain::digest::ordered_digest::*;
use crate::models::blockchain::digest::*;
use crate::models::blockchain::shared::*;
use crate::models::blockchain::transaction::utxo::*;
use crate::models::blockchain::transaction::*;
use crate::models::channel::*;
use crate::models::state::GlobalState;
use anyhow::{Context, Result};
use futures::channel::oneshot;
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

/// Prepare a Block for Devnet mining
fn make_devnet_block_template(
    previous_block: &Block,
    transaction: Transaction,
) -> (BlockHeader, BlockBody) {
    let mut additions = Vec::with_capacity(transaction.outputs.len());
    let mut removals = Vec::with_capacity(transaction.inputs.len());
    let mut next_mutator_set_accumulator: MutatorSetAccumulator<Hash> =
        previous_block.body.next_mutator_set_accumulator.clone();

    for (output_utxo, randomness) in transaction.outputs.iter() {
        let addition_record =
            next_mutator_set_accumulator.commit(&output_utxo.hash().into(), &(*randomness).into());
        additions.push(addition_record);
    }

    for devnet_input in transaction.inputs.iter() {
        let _diff_indices = next_mutator_set_accumulator.remove(&devnet_input.removal_record);
        removals.push(devnet_input.removal_record.clone());
    }

    let mutator_set_update = MutatorSetUpdate::new(removals, additions);

    // Apply the mutator set update to the mutator set accumulator
    // This function mutates the MS accumulator that is given as argument to
    // the function such that the next mutator set accumulator is calculated.
    mutator_set_update
        .apply(&mut next_mutator_set_accumulator)
        .expect("Mutator set mutation must work");

    let block_body: BlockBody = BlockBody {
        transaction,
        next_mutator_set_accumulator: next_mutator_set_accumulator.clone(),
        mutator_set_update,
        previous_mutator_set_accumulator: previous_block.body.next_mutator_set_accumulator.clone(),
        stark_proof: vec![],
    };

    let zero = BFieldElement::ring_zero();
    let difficulty: U32s<5> = U32s::new([MOCK_DIFFICULTY, 0, 0, 0, 0]);
    let new_pow_line: U32s<5> = previous_block.header.proof_of_work_family + difficulty;
    let mutator_set_commitment: Digest = next_mutator_set_accumulator.get_commitment().into();
    let next_block_height = previous_block.header.height.next();
    let block_timestamp = BFieldElement::new(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Got bad time timestamp in mining process")
            .as_secs(),
    );

    let block_header = BlockHeader {
        version: zero,
        height: next_block_height,
        mutator_set_commitment,
        prev_block_digest: previous_block.header.hash(),
        timestamp: block_timestamp,
        nonce: [zero, zero, zero],
        max_block_size: MOCK_MAX_BLOCK_SIZE,
        proof_of_work_line: new_pow_line,
        proof_of_work_family: new_pow_line,
        target_difficulty: difficulty,
        block_body_merkle_root: block_body.hash(),
        uncles: vec![],
    };

    (block_header, block_body)
}

/// Attempt to mine a valid block for the network
#[tracing::instrument(skip_all, level = "debug")]
async fn mine_devnet_block(
    mut block_header: BlockHeader,
    block_body: BlockBody,
    sender: oneshot::Sender<Block>,
    state: GlobalState,
) {
    // Mining takes place here
    while Into::<OrderedDigest>::into(block_header.hash())
        >= OrderedDigest::to_digest_threshold(block_header.target_difficulty)
    {
        // If the sender is cancelled, the parent to this thread most
        // likely received a new block, and this thread hasn't been stopped
        // yet by the operating system, although the call to abort this
        // thread *has* been made.
        if sender.is_canceled() {
            info!(
                "Abandoning mining of current block with height {}",
                block_header.height
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

fn make_coinbase_transaction(
    public_key: secp256k1::PublicKey,
    previous_block_header: &BlockHeader,
) -> Transaction {
    let next_block_height: BlockHeight = previous_block_header.height.next();
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

    Transaction {
        inputs: vec![],
        outputs: vec![(coinbase_utxo, output_randomness.into())],
        public_scripts: vec![],
        fee: U32s::zero(),
        timestamp,
    }
}

#[tracing::instrument(skip_all)]
pub async fn mock_regtest_mine(
    mut from_main: watch::Receiver<MainToMiner>,
    to_main: mpsc::Sender<MinerToMain>,
    mut latest_block: Block,
    own_public_key: secp256k1::PublicKey,
    state: GlobalState,
) -> Result<()> {
    loop {
        let (sender, receiver) = oneshot::channel::<Block>();
        let miner_thread: Option<JoinHandle<()>> = if state.net.syncing.read().unwrap().to_owned() {
            info!("Not mining because we are syncing");
            None
        } else {
            // For now, we just mine blocks with only the coinbase transaction.
            let coinbase_transaction =
                make_coinbase_transaction(own_public_key, &latest_block.header);

            // Merge incoming transactions with the coinbase transaction
            // let transaction =
            //     Transaction::merge_transaction(&coinbase_transaction, &incoming_transaction);

            let (block_header, block_body) =
                make_devnet_block_template(&latest_block, coinbase_transaction);
            let miner_task = mine_devnet_block(block_header, block_body, sender, state.clone());
            Some(tokio::spawn(miner_task))
        };

        select! {
            changed = from_main.changed() => {
                info!("Mining thread got message from main");
                if let e@Err(_) = changed {
                    return e.context("Miner failed to read from watch channel");
                }

                let main_message: MainToMiner = from_main.borrow_and_update().clone();
                match main_message {
                    MainToMiner::Shutdown => {
                        debug!("Miner shutting down.");

                        if let Some(mt) = miner_thread {
                            mt.abort();
                        }

                        break;
                    }
                    MainToMiner::NewBlock(block) => {
                        if let Some(mt) = miner_thread {
                            mt.abort();
                        }
                        latest_block = *block;
                        info!("Miner thread received regtest block height {}", latest_block.header.height);
                    }
                    MainToMiner::Empty => (),
                    MainToMiner::Transaction(incoming_transaction) => {
                        debug!("Miner thread received incoming transaction from main: {:?}", incoming_transaction);
                        // TODO: Replace this message with a transaction pool (mempool).
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
    debug!("Miner shut down gracefully.");
    Ok(())
}

#[cfg(test)]
mod mine_loop_tests {
    use crate::tests::shared::{get_mock_wallet_state, make_mock_block};

    use super::*;

    #[test]
    fn make_devnet_block_template_is_valid_test() {
        let previous_block = Block::genesis_block();
        let wallet_state = get_mock_wallet_state();
        let coinbase_tx =
            make_coinbase_transaction(wallet_state.get_public_key(), &previous_block.header);
        let (block_header, block_body) = make_devnet_block_template(&previous_block, coinbase_tx);
        let block_template_1 = Block::new(block_header, block_body);
        assert!(block_template_1.devnet_is_valid(&previous_block));

        let mock_block_1 = make_mock_block(&previous_block, None, wallet_state.get_public_key());
        let coinbase_tx_2 =
            make_coinbase_transaction(wallet_state.get_public_key(), &mock_block_1.header);
        let (block_header_2, block_body_2) =
            make_devnet_block_template(&mock_block_1, coinbase_tx_2);
        let block_template_2 = Block::new(block_header_2, block_body_2);
        assert!(block_template_2.devnet_is_valid(&mock_block_1));
    }
}
