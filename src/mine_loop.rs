use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use difficulty_control::Difficulty;
use difficulty_control::ProofOfWork;
use futures::channel::oneshot;
use num_traits::identities::Zero;
use rand::rngs::StdRng;
use rand::thread_rng;
use rand::Rng;
use rand::SeedableRng;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;
use tokio::select;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::*;
use transaction_output::TxOutput;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::math::digest::Digest;

use crate::models::blockchain::block::block_body::BlockBody;
use crate::models::blockchain::block::block_header::BlockHeader;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::difficulty_control::difficulty_control;
use crate::models::blockchain::block::mutator_set_update::*;
use crate::models::blockchain::block::*;
use crate::models::blockchain::transaction::*;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::channel::*;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::shared::SIZE_20MB_IN_BYTES;
use crate::models::state::transaction_details::TransactionDetails;
use crate::models::state::tx_proving_capability::TxProvingCapability;
use crate::models::state::wallet::expected_utxo::ExpectedUtxo;
use crate::models::state::wallet::expected_utxo::UtxoNotifier;
use crate::models::state::GlobalState;
use crate::models::state::GlobalStateLock;
use crate::prelude::twenty_first;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

const MOCK_MAX_BLOCK_SIZE: u32 = 1_000_000;

/// Prepare a Block for mining
pub(crate) fn make_block_template(
    previous_block: &Block,
    transaction: Transaction,
    mut block_timestamp: Timestamp,
    target_block_interval: Option<Timestamp>,
) -> (BlockHeader, BlockBody, BlockProof) {
    let additions = transaction.kernel.outputs.clone();
    let removals = transaction.kernel.inputs.clone();
    let mut next_mutator_set_accumulator: MutatorSetAccumulator =
        previous_block.kernel.body.mutator_set_accumulator.clone();

    // Apply the mutator set update to the mutator set accumulator
    // This function mutates the MS accumulator that is given as argument to
    // the function such that the next mutator set accumulator is calculated.
    let mutator_set_update = MutatorSetUpdate::new(removals, additions);
    mutator_set_update
        .apply_to_accumulator(&mut next_mutator_set_accumulator)
        .expect("Mutator set mutation must work");

    let mut block_mmra = previous_block.kernel.body.block_mmr_accumulator.clone();
    block_mmra.append(previous_block.hash());
    let block_body: BlockBody = BlockBody::new(
        transaction.kernel,
        next_mutator_set_accumulator.clone(),
        MmrAccumulator::new_from_leafs(vec![]),
        block_mmra,
    );

    let zero = BFieldElement::zero();
    let new_pow: ProofOfWork = previous_block.kernel.header.cumulative_proof_of_work
        + previous_block.kernel.header.difficulty;
    let next_block_height = previous_block.kernel.header.height.next();
    if block_timestamp < previous_block.kernel.header.timestamp {
        warn!("Received block is timestamped in the future; mining on future-timestamped block.");
        block_timestamp = previous_block.kernel.header.timestamp + Timestamp::seconds(1);
    }
    let difficulty: Difficulty = difficulty_control(
        block_timestamp,
        previous_block.header().timestamp,
        previous_block.header().difficulty,
        target_block_interval,
        previous_block.header().height,
    );

    let block_header = BlockHeader {
        version: zero,
        height: next_block_height,
        prev_block_digest: previous_block.hash(),
        timestamp: block_timestamp,
        nonce: [zero, zero, zero],
        max_block_size: MOCK_MAX_BLOCK_SIZE,
        cumulative_proof_of_work: new_pow,
        difficulty,
    };

    let block_proof = BlockProof::DummyProof; // TODO: produce SingleProof

    (block_header, block_body, block_proof)
}

/// Attempt to mine a valid block for the network
#[allow(clippy::too_many_arguments)]
async fn mine_block(
    block_header: BlockHeader,
    block_body: BlockBody,
    block_proof: BlockProof,
    previous_block: Block,
    sender: oneshot::Sender<NewBlockFound>,
    coinbase_utxo_info: ExpectedUtxo,
    unrestricted_mining: bool,
    target_block_interval: Option<Timestamp>,
) {
    // We wrap mining loop with spawn_blocking() because it is a
    // very lengthy and CPU intensive task, which should execute
    // on its own thread.
    //
    // Instead of spawn_blocking(), we could start a native OS
    // thread which avoids using one from tokio's threadpool
    // but that doesn't seem a concern for neptune-core.
    // Also we would need to use a oneshot channel to avoid
    // blocking while joining the thread.
    // see: https://ryhl.io/blog/async-what-is-blocking/
    //
    // note: there is no async code inside the mining loop.
    tokio::task::spawn_blocking(move || {
        mine_block_worker(
            block_header,
            block_body,
            block_proof,
            previous_block,
            sender,
            coinbase_utxo_info,
            unrestricted_mining,
            target_block_interval,
        )
    })
    .await
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn mine_block_worker(
    block_header: BlockHeader,
    block_body: BlockBody,
    block_proof: BlockProof,
    previous_block: Block,
    sender: oneshot::Sender<NewBlockFound>,
    coinbase_utxo_info: ExpectedUtxo,
    unrestricted_mining: bool,
    target_block_interval: Option<Timestamp>,
) {
    // This must match the rules in `[Block::has_proof_of_work]`.
    let prev_difficulty = previous_block.header().difficulty;
    let threshold = prev_difficulty.target();
    info!(
        "Mining on block with {} outputs and difficulty {}. Attempting to find block with height {} with digest less than target: {}",
        block_body.transaction_kernel.outputs.len(),
        previous_block.header().difficulty,
        block_header.height,
        threshold
    );

    // The RNG used to sample nonces must be thread-safe, which `thread_rng()` is not.
    // Solution: use `thread_rng()` to generate a seed, and generate a thread-safe RNG
    // seeded with that seed. The `thread_rng()` object is dropped immediately.
    let mut rng: StdRng = SeedableRng::from_seed(thread_rng().gen());

    let mut block = Block::new(block_header, block_body, block_proof);

    // Mining loop
    while !mine_iteration(
        &mut block,
        &previous_block,
        &sender,
        target_block_interval,
        threshold,
        unrestricted_mining,
        &mut rng,
    ) {}
    // If the sender is cancelled, the parent to this thread most
    // likely received a new block, and this thread hasn't been stopped
    // yet by the operating system, although the call to abort this
    // thread *has* been made.
    if sender.is_canceled() {
        info!(
            "Abandoning mining of current block with height {}",
            block.kernel.header.height
        );
        return;
    }

    let nonce = block.kernel.header.nonce;
    info!(
        "Found valid block with nonce: ({}, {}, {}).",
        nonce[0], nonce[1], nonce[2]
    );

    let new_block_found = NewBlockFound {
        block: Box::new(block),
        coinbase_utxo_info: Box::new(coinbase_utxo_info),
    };

    let timestamp = new_block_found.block.kernel.header.timestamp;
    let timestamp_standard = timestamp.standard_format();
    let hash = new_block_found.block.hash();
    let hex = hash.to_hex();
    let height = new_block_found.block.kernel.header.height;
    info!(
        r#"Newly mined block details:
              Height: {height}
              Time:   {timestamp_standard} ({timestamp})
        Digest (Hex): {hex}
        Digest (Raw): {hash}
Difficulty threshold: {threshold}
          Difficulty: {prev_difficulty}
"#
    );

    sender
        .send(new_block_found)
        .unwrap_or_else(|_| warn!("Receiver in mining loop closed prematurely"))
}

/// Run a single iteration of the mining loop.
///
/// Returns true if a) a valid block is found; or b) the task is terminated.
#[inline]
fn mine_iteration(
    block: &mut Block,
    previous_block: &Block,
    sender: &oneshot::Sender<NewBlockFound>,
    target_block_interval: Option<Timestamp>,
    threshold: Digest,
    unrestricted_mining: bool,
    rng: &mut StdRng,
) -> bool {
    if sender.is_canceled() {
        info!(
            "Abandoning mining of current block with height {}",
            block.kernel.header.height
        );
        return true;
    }

    // mutate nonce in the block's header.
    // Block::hash() will subsequently return a new digest.
    block.set_header_nonce(rng.gen());

    // See issue #149 and test block_timestamp_represents_time_block_found()
    // this ensures header timestamp represents the moment block is found.
    // this is simplest impl.  Efficiencies can perhaps be gained by only
    // performing every N iterations, or other strategies.
    let now = Timestamp::now();
    let new_difficulty = difficulty_control(
        now,
        previous_block.header().timestamp,
        previous_block.header().difficulty,
        target_block_interval,
        previous_block.header().height,
    );
    block.set_header_timestamp_and_difficulty(now, new_difficulty);

    let success = block.hash() <= threshold;

    if !unrestricted_mining {
        std::thread::sleep(Duration::from_millis(100));
    }

    success
}

pub(crate) async fn make_coinbase_transaction(
    global_state_lock: &GlobalStateLock,
    transaction_fees: NeptuneCoins,
    timestamp: Timestamp,
) -> Result<(Transaction, ExpectedUtxo)> {
    // note: it is Ok to always use the same key here because:
    //  1. if we find a block, the utxo will go to our wallet
    //     and notification occurs offchain, so there is no privacy issue.
    //  2. if we were to derive a new addr for each block then we would
    //     have large gaps since an address only receives funds when
    //     we actually win the mining lottery.
    //  3. also this way we do not have to modify global/wallet state.

    let coinbase_recipient_spending_key = global_state_lock
        .lock_guard()
        .await
        .wallet_state
        .wallet_secret
        .nth_generation_spending_key(0);
    let receiving_address = coinbase_recipient_spending_key.to_address();
    let latest_block = global_state_lock
        .lock_guard()
        .await
        .chain
        .light_state()
        .clone();
    let mutator_set_accumulator = latest_block.body().mutator_set_accumulator.clone();
    let next_block_height: BlockHeight = latest_block.header().height.next();

    let coinbase_amount = Block::get_mining_reward(next_block_height) + transaction_fees;
    let sender_randomness: Digest = global_state_lock
        .lock_guard()
        .await
        .wallet_state
        .wallet_secret
        .generate_sender_randomness(next_block_height, receiving_address.privacy_digest);

    // There is no reason to put coinbase UTXO notifications on chain, because:
    // Both sender randomness and receiver preimage are derived
    // deterministically from the wallet's seed.
    let coinbase_output = TxOutput::offchain_native_currency(
        coinbase_amount,
        sender_randomness,
        receiving_address.into(),
    );

    let transaction_details = TransactionDetails::new_with_coinbase(
        vec![],
        vec![coinbase_output.clone()].into(),
        coinbase_amount,
        timestamp,
        mutator_set_accumulator,
    )
    .expect(
        "all inputs' ms membership proofs must be valid because inputs are empty;\
 and tx must be balanced because the one output receives exactly the coinbase amount",
    );

    // 2. Create the transaction
    // A coinbase transaction implies mining. So you *must*
    // be able to create a SingleProof.

    // It's important to not hold any locks (not even read-locks), as
    // that prevents peers from connecting to this node.
    info!("Start: generate single proof for coinbase transaction");
    let wait_if_busy = global_state_lock.wait_if_busy();
    let transaction = GlobalState::create_raw_transaction(
        transaction_details,
        TxProvingCapability::SingleProof,
        &wait_if_busy,
    )
    .await?;
    info!("Done: generating single proof for coinbase transaction");

    let utxo_info_for_coinbase = ExpectedUtxo::new(
        coinbase_output.utxo(),
        coinbase_output.sender_randomness(),
        coinbase_recipient_spending_key.privacy_preimage,
        UtxoNotifier::OwnMiner,
    );

    Ok((transaction, utxo_info_for_coinbase))
}

/// Create the transaction that goes into the block template. The transaction is
/// built from the mempool and from the coinbase transaction. Also returns the
/// "sender randomness" used in the coinbase transaction.
pub(crate) async fn create_block_transaction(
    predecessor_block: &Block,
    global_state_lock: &GlobalStateLock,
    timestamp: Timestamp,
) -> Result<(Transaction, ExpectedUtxo)> {
    let block_capacity_for_transactions = SIZE_20MB_IN_BYTES;

    // Get most valuable transactions from mempool
    let transactions_to_include = global_state_lock
        .lock_guard()
        .await
        .mempool
        .get_transactions_for_block(block_capacity_for_transactions, None);

    // Build coinbase UTXO
    let transaction_fees = transactions_to_include
        .iter()
        .fold(NeptuneCoins::zero(), |acc, tx| acc + tx.kernel.fee);

    let (coinbase_transaction, coinbase_as_expected_utxo) =
        make_coinbase_transaction(global_state_lock, transaction_fees, timestamp).await?;

    debug!(
        "Creating block transaction with mutator set hash: {}",
        predecessor_block.kernel.body.mutator_set_accumulator.hash()
    );

    let mut rng: StdRng =
        SeedableRng::from_seed(global_state_lock.lock_guard().await.shuffle_seed());

    // Merge incoming transactions with the coinbase transaction
    let num_transactions_to_include = transactions_to_include.len();
    let mut block_transaction = coinbase_transaction;
    let wait_if_busy = global_state_lock.wait_if_busy();
    for (i, transaction_to_include) in transactions_to_include.into_iter().enumerate() {
        info!(
            "Merging transaction {} / {}",
            i + 1,
            num_transactions_to_include
        );
        block_transaction = Transaction::merge_with(
            block_transaction,
            transaction_to_include,
            rng.gen(),
            &wait_if_busy,
        )
        .await
        .expect("Must be able to merge transactions in mining context");
    }

    Ok((block_transaction, coinbase_as_expected_utxo))
}

/// Locking:
///   * acquires `global_state_lock` for write
pub async fn mine(
    mut from_main: watch::Receiver<MainToMiner>,
    to_main: mpsc::Sender<MinerToMain>,
    mut latest_block: Block,
    mut global_state_lock: GlobalStateLock,
) -> Result<()> {
    // Wait before starting mining task to ensure that peers have sent us information about
    // their latest blocks. This should prevent the client from finding blocks that will later
    // be orphaned.
    const INITIAL_MINING_SLEEP_IN_SECONDS: u64 = 60;
    tokio::time::sleep(Duration::from_secs(INITIAL_MINING_SLEEP_IN_SECONDS)).await;

    let mut pause_mine = false;
    loop {
        let (worker_task_tx, worker_task_rx) = oneshot::channel::<NewBlockFound>();
        let is_syncing = global_state_lock.lock(|s| s.net.syncing).await;

        let miner_task: Option<JoinHandle<()>> = if is_syncing {
            info!("Not mining because we are syncing");
            global_state_lock.set_mining(false).await;
            None
        } else if pause_mine {
            info!("Not mining because mining was paused");
            global_state_lock.set_mining(false).await;
            None
        } else {
            // Build the block template and spawn the worker task to mine on it
            let now = Timestamp::now();

            // TODO: Spawn a task for generating this transaction, such that it
            // can be aborted on shutdown.
            let (transaction, coinbase_utxo_info) =
                create_block_transaction(&latest_block, &global_state_lock, now).await?;
            let (block_header, block_body, block_proof) =
                make_block_template(&latest_block, transaction, now, None);
            let miner_task = mine_block(
                block_header,
                block_body,
                block_proof,
                latest_block.clone(),
                worker_task_tx,
                coinbase_utxo_info,
                global_state_lock.cli().unrestricted_mining,
                None, // using default TARGET_BLOCK_INTERVAL
            );
            global_state_lock.set_mining(true).await;
            Some(
                tokio::task::Builder::new()
                    .name("mine_block")
                    .spawn(miner_task)?,
            )
        };

        // Await a message from either the worker task or from the main loop
        select! {
            changed = from_main.changed() => {
                info!("Mining task got message from main");
                if let e@Err(_) = changed {
                    return e.context("Miner failed to read from watch channel");
                }

                let main_message: MainToMiner = from_main.borrow_and_update().clone();
                debug!("Miner received message {:?}", main_message);

                match main_message {
                    MainToMiner::Shutdown => {
                        debug!("Miner shutting down.");

                        if let Some(mt) = miner_task {
                            mt.abort();
                            debug!("Abort-signal sent to mining worker.");
                        }

                        break;
                    }
                    MainToMiner::NewBlock(block) => {
                        if let Some(mt) = miner_task {
                            mt.abort();
                        }
                        latest_block = *block;
                        info!("Miner task received {} block height {}", global_state_lock.lock(|s| s.cli().network).await, latest_block.kernel.header.height);
                    }
                    MainToMiner::Empty => (),
                    MainToMiner::ReadyToMineNextBlock => {}
                    MainToMiner::StopMining => {
                        pause_mine = true;

                        if let Some(mt) = miner_task {
                            mt.abort();
                            debug!("Abort-signal sent to mining worker.");
                        }
                    }
                    MainToMiner::StartMining => {
                        pause_mine = false;
                    }
                    MainToMiner::StopSyncing => {
                        // no need to do anything here.  Mining will
                        // resume or not at top of loop depending on
                        // pause_mine and syncing variables.
                    }
                    MainToMiner::StartSyncing => {
                        // when syncing begins, we must halt the mining
                        // task.  But we don't change the pause_mine
                        // variable, because it reflects the logical on/off
                        // of mining, which syncing can temporarily override
                        // but not alter the setting.
                        if let Some(mt) = miner_task {
                            mt.abort();
                        }
                    }
                }
            }
            new_block_res = worker_task_rx => {
                let new_block_found = match new_block_res {
                    Ok(res) => res,
                    Err(err) => {
                        warn!("Mining task was cancelled prematurely. Got: {}", err);
                        continue;
                    }
                };

                debug!("Worker task reports new block of height {}", new_block_found.block.kernel.header.height);

                // Sanity check, remove for more efficient mining.
                // The below PoW check could fail due to race conditions. So we don't panic,
                // we only ignore what the worker task sent us.
                if !new_block_found.block.has_proof_of_work(&latest_block) {
                    error!("Own mined block did not have valid PoW Discarding.");
                }

                // The block, however, *must* be valid on other parameters. So here, we should panic
                // if it is not.
                let now = Timestamp::now();
                assert!(new_block_found.block.is_valid(&latest_block, now), "Own mined block must be valid. Failed validity check after successful PoW check.");

                info!("Found new {} block with block height {}. Hash: {}", global_state_lock.cli().network, new_block_found.block.kernel.header.height, new_block_found.block.hash());

                latest_block = *new_block_found.block.to_owned();
                to_main.send(MinerToMain::NewBlockFound(new_block_found)).await?;

                // Wait until `main_loop` has updated `global_state` before proceding. Otherwise, we would use
                // a deprecated version of the mempool to build the next block. We don't mark the from-main loop
                // received value as read yet as this would open up for race conditions if `main_loop` received
                // a block from a peer at the same time as this block was found.
                let _wait = from_main.changed().await;
                let msg = from_main.borrow().clone();
                debug!("Got {:?} msg from main after finding block", msg);
                if !matches!(msg, MainToMiner::ReadyToMineNextBlock) {
                    error!("Got bad message from `main_loop`: {:?}", msg);

                    // TODO: Handle this case
                    // We found a new block but the main task updated with a block
                    // before ours could be registered. We should mine on the one
                    // received from the main loop and not the one we found here.
                }
            }
        }
    }
    debug!("Miner shut down gracefully.");
    Ok(())
}

#[cfg(test)]
mod mine_loop_tests {
    use block_header::block_header_tests::random_block_header;
    use num_bigint::BigUint;
    use tracing_test::traced_test;
    use transaction_output::TxOutput;
    use transaction_output::UtxoNotificationMedium;

    use super::*;
    use crate::config_models::network::Network;
    use crate::models::proof_abstractions::tasm::program::TritonProverSync;
    use crate::models::proof_abstractions::timestamp::Timestamp;
    use crate::tests::shared::dummy_expected_utxo;
    use crate::tests::shared::make_mock_transaction;
    use crate::tests::shared::mock_genesis_global_state;
    use crate::tests::shared::random_transaction_kernel;
    use crate::util_types::test_shared::mutator_set::random_mmra;
    use crate::util_types::test_shared::mutator_set::random_mutator_set_accumulator;
    use crate::WalletSecret;

    /// Estimates the hash rate in number of hashes per milliseconds
    async fn estimate_own_hash_rate(
        target_block_interval: Option<Timestamp>,
        unrestricted_mining: bool,
    ) -> f64 {
        let mut rng: StdRng = SeedableRng::from_rng(thread_rng()).unwrap();
        let network = Network::RegTest;
        let global_state_lock =
            mock_genesis_global_state(network, 2, WalletSecret::devnet_wallet()).await;

        let previous_block = global_state_lock
            .lock_guard()
            .await
            .chain
            .light_state()
            .clone();

        let (transaction, _coinbase_utxo_info) =
            { (make_mock_transaction(vec![], vec![]), dummy_expected_utxo()) };
        let start_time = Timestamp::now();
        let (block_header, block_body, block_proof) = Block::make_block_template(
            &previous_block,
            transaction,
            start_time,
            target_block_interval,
        );
        let mut block = Block::new(block_header, block_body, block_proof);
        let threshold = previous_block.header().difficulty.target();

        let (worker_task_tx, _worker_task_rx) = oneshot::channel::<NewBlockFound>();

        let num_iterations = 10000;
        let tick = std::time::SystemTime::now();
        for _ in 0..num_iterations {
            mine_iteration(
                &mut block,
                &previous_block,
                &worker_task_tx,
                target_block_interval,
                threshold,
                unrestricted_mining,
                &mut rng,
            );
        }
        let time_spent_mining = tick.elapsed().unwrap();

        (num_iterations as f64) / (time_spent_mining.as_millis() as f64)
    }

    #[traced_test]
    #[tokio::test]
    async fn block_template_is_valid_test() -> Result<()> {
        // Verify that a block template made with transaction from the mempool is a valid block
        let network = Network::Main;
        let mut alice = mock_genesis_global_state(network, 2, WalletSecret::devnet_wallet()).await;
        assert!(
            alice.lock_guard().await.mempool.is_empty(),
            "Mempool must be empty at startup"
        );

        let mut rng = StdRng::seed_from_u64(u64::from_str_radix("2350404", 6).unwrap());
        let genesis_block = Block::genesis_block(network);
        let now = genesis_block.kernel.header.timestamp;
        let in_seven_months = now + Timestamp::months(7);
        assert!(
            !alice
                .lock_guard()
                .await
                .get_wallet_status_for_tip()
                .await
                .synced_unspent_available_amount(in_seven_months)
                .is_zero(),
            "Assumed to be premine-recipient"
        );

        // Verify constructed coinbase transaction and block template when mempool is empty
        let (transaction_empty_mempool, _coinbase_utxo_info) = {
            make_coinbase_transaction(&alice, NeptuneCoins::zero(), now)
                .await
                .unwrap()
        };

        assert_eq!(
            1,
            transaction_empty_mempool.kernel.outputs.len(),
            "Coinbase transaction with empty mempool must have exactly one output"
        );
        assert!(
            transaction_empty_mempool.kernel.inputs.is_empty(),
            "Coinbase transaction with empty mempool must have zero inputs"
        );
        let (block_header_template_empty_mempool, block_body_empty_mempool, block_proof) =
            Block::make_block_template(
                &genesis_block,
                transaction_empty_mempool,
                in_seven_months,
                None,
            );
        let block_template_empty_mempool = Block::new(
            block_header_template_empty_mempool,
            block_body_empty_mempool,
            block_proof,
        );
        assert!(
            block_template_empty_mempool.is_valid(&genesis_block, in_seven_months),
            "Block template created by miner with empty mempool must be valid"
        );

        // Add a transaction to the mempool
        let alice_key = alice
            .lock_guard()
            .await
            .wallet_state
            .wallet_secret
            .nth_generation_spending_key_for_tests(0);
        let output_to_alice = TxOutput::offchain_native_currency(
            NeptuneCoins::new(4),
            rng.gen(),
            alice_key.to_address().into(),
        );
        // About ProveCapability::SingleProof:
        // The thing being tested is that the block template *for the _miner_*
        // is valid. The miner is assumed capable of producing `SingleProof`s.
        let (tx_by_preminer, _maybe_change_output) = alice
            .lock_guard()
            .await
            .create_transaction_with_prover_capability(
                vec![output_to_alice].into(),
                alice_key.into(),
                UtxoNotificationMedium::OffChain,
                NeptuneCoins::new(1),
                in_seven_months,
                TxProvingCapability::SingleProof,
                &TritonProverSync::dummy(),
            )
            .await
            .unwrap();

        // no need to inform wallet of expected utxos; block template validity
        // is what is being tested

        {
            let mut alice_gsm = alice.lock_guard_mut().await;
            alice_gsm.mempool_insert(tx_by_preminer).await;
            assert_eq!(1, alice_gsm.mempool.len());
        }

        // Build transaction for block
        let (transaction_non_empty_mempool, _new_coinbase_sender_randomness) = {
            create_block_transaction(&genesis_block, &alice, in_seven_months)
                .await
                .unwrap()
        };
        assert_eq!(
            3,
            transaction_non_empty_mempool.kernel.outputs.len(),
            "Transaction for block with non-empty mempool must contain coinbase output, send output, and change output"
        );
        assert_eq!(1, transaction_non_empty_mempool.kernel.inputs.len(), "Transaction for block with non-empty mempool must contain one input: the genesis UTXO being spent");

        // Build and verify block template
        let (block_header_template, block_body, new_block_proof) = Block::make_block_template(
            &genesis_block,
            transaction_non_empty_mempool,
            in_seven_months,
            None,
        );
        let block_template_non_empty_mempool =
            Block::new(block_header_template, block_body, new_block_proof);
        assert!(
            block_template_non_empty_mempool
                .is_valid(&genesis_block, in_seven_months + Timestamp::seconds(2)),
            "Block template created by miner with non-empty mempool must be valid"
        );

        Ok(())
    }

    /// This test mines a single block at height 1 on the regtest network
    /// and then validates it with `Block::is_valid()` and
    /// `Block::has_proof_of_work()`.
    ///
    /// This is a regression test for issue #131.
    /// https://github.com/Neptune-Crypto/neptune-core/issues/131
    ///
    /// The cause of the failure was that `mine_block_worker()` was comparing
    /// hash(block_header) against difficulty threshold while
    /// `Block::has_proof_of_work` uses hash(block) instead.
    ///
    /// The fix was to modify `mine_block_worker()` so that it also
    /// uses hash(block) and subsequently the test passes (unmodified).
    ///
    /// This test is present and fails in commit
    /// b093631fd0d479e6c2cc252b08f18d920a1ec2e5 which is prior to the fix.
    #[traced_test]
    #[tokio::test]
    async fn mined_block_has_proof_of_work() {
        let network = Network::Main;
        let global_state_lock =
            mock_genesis_global_state(network, 2, WalletSecret::devnet_wallet()).await;
        let tip_block_orig = Block::genesis_block(network);
        let launch_date = tip_block_orig.header().timestamp;
        let (worker_task_tx, worker_task_rx) = oneshot::channel::<NewBlockFound>();

        let (transaction, coinbase_utxo_info) =
            make_coinbase_transaction(&global_state_lock, NeptuneCoins::zero(), launch_date)
                .await
                .unwrap();

        let (block_header, block_body, block_proof) =
            Block::make_block_template(&tip_block_orig, transaction, launch_date, None);

        let unrestricted_mining = true;

        mine_block_worker(
            block_header,
            block_body,
            block_proof,
            tip_block_orig.clone(),
            worker_task_tx,
            coinbase_utxo_info,
            unrestricted_mining,
            None,
        );

        let mined_block_info = worker_task_rx.await.unwrap();

        assert!(mined_block_info
            .block
            .is_valid(&tip_block_orig, Timestamp::now()));
        assert!(mined_block_info.block.has_proof_of_work(&tip_block_orig));
    }

    /// This test mines a single block at height 1 on the main network
    /// and then validates that the header timestamp has changed and
    /// that it is within the 100 seconds (from now).
    ///
    /// This is a regression test for issue #149.
    /// https://github.com/Neptune-Crypto/neptune-core/issues/149
    ///
    /// note: this test fails in 318b7a20baf11a7a99f249660f1f70484c586012
    ///       and should always pass in later commits.
    #[traced_test]
    #[tokio::test]
    async fn block_timestamp_represents_time_block_found() -> Result<()> {
        let network = Network::Main;
        let global_state_lock =
            mock_genesis_global_state(network, 2, WalletSecret::devnet_wallet()).await;
        let (worker_task_tx, worker_task_rx) = oneshot::channel::<NewBlockFound>();

        let tip_block_orig = global_state_lock
            .lock_guard()
            .await
            .chain
            .light_state()
            .clone();

        let now = tip_block_orig.header().timestamp + Timestamp::minutes(10);

        // pretend/simulate that it takes at least 10 seconds to mine the block.
        let ten_seconds_ago = now - Timestamp::seconds(10);

        let (transaction, coinbase_utxo_info) =
            make_coinbase_transaction(&global_state_lock, NeptuneCoins::zero(), ten_seconds_ago)
                .await
                .unwrap();

        let (block_header, block_body, block_proof) =
            Block::make_block_template(&tip_block_orig, transaction, ten_seconds_ago, None);

        // sanity check that our initial state is correct.
        assert_eq!(block_header.timestamp, ten_seconds_ago);

        let initial_header_timestamp = block_header.timestamp;
        let unrestricted_mining = true;

        mine_block_worker(
            block_header,
            block_body,
            block_proof,
            tip_block_orig.clone(),
            worker_task_tx,
            coinbase_utxo_info,
            unrestricted_mining,
            None,
        );

        let mined_block_info = worker_task_rx.await.unwrap();

        let block_timestamp = mined_block_info.block.kernel.header.timestamp;

        // Mining updates the timestamp. So block timestamp will be >= to what
        // was set in the block template, and <= current time.
        assert!(block_timestamp >= initial_header_timestamp);
        assert!(block_timestamp <= Timestamp::now());

        // verify timestamp is within the last 100 seconds (allows for some CI slack).
        assert!(Timestamp::now() - block_timestamp < Timestamp::seconds(100));

        Ok(())
    }

    /// Test the difficulty adjustment algorithm.
    ///
    /// Specifically, verify that the observed concrete block interval when mining
    /// tracks the target block interval, assuming:
    ///  - No time is spent proving
    ///  - Constant mining power
    ///  - Mining power exceeds lower bound (hashing once every target interval).
    ///
    /// Note that the second assumption is broken when running the entire test suite.
    /// So if this test fails when all others pass, it is not necessarily a cause
    /// for worry.
    ///
    /// We mine ten blocks with a target block interval of 1 second, so all
    /// blocks should be mined in approx 10 seconds.
    ///
    /// We set a test time limit of 3x the expected time, ie 30 seconds, and
    /// panic if mining all blocks takes longer than that.
    ///
    /// We also assert upper and lower bounds for variance from the expected 10
    /// seconds.  The variance limit is 1.3, so the upper bound is 13 seconds
    /// and the lower bound is 7692ms.
    ///
    /// We ignore the first 2 blocks after genesis because they are typically
    /// mined very fast.
    ///
    /// We use unrestricted mining (100% CPU) to avoid complications from the
    /// sleep(100 millis) call in mining loop when restricted mining is enabled.
    ///
    /// This serves as a regression test for issue #154.
    /// https://github.com/Neptune-Crypto/neptune-core/issues/154
    #[traced_test]
    #[tokio::test]
    async fn mine_ten_blocks_in_ten_seconds() -> Result<()> {
        let network = Network::RegTest;
        let global_state_lock =
            mock_genesis_global_state(network, 2, WalletSecret::devnet_wallet()).await;

        let mut prev_block = global_state_lock
            .lock_guard()
            .await
            .chain
            .light_state()
            .clone();

        // adjust these to simulate longer mining runs, possibly
        // with shorter or longer target intervals.
        // expected_duration = num_blocks * target_block_interval
        let num_blocks = 100;
        let target_block_interval = Timestamp::millis(100);

        // set initial difficulty in accordance with own hash rate
        let unrestricted_mining = true;
        let hash_rate =
            estimate_own_hash_rate(Some(target_block_interval), unrestricted_mining).await;
        println!("estimating hash rate at {} per millisecond", hash_rate);
        let initial_difficulty =
            BigUint::from((hash_rate * (target_block_interval.to_millis() as f64)) as u128);
        println!("initial difficulty: {}", initial_difficulty);
        prev_block.set_header_timestamp_and_difficulty(
            prev_block.header().timestamp,
            Difficulty::from_biguint(initial_difficulty),
        );

        let expected_duration = target_block_interval * num_blocks;
        let allowed_variance = 1.3;
        let min_duration = (expected_duration.0.value() as f64 / allowed_variance) as u64;
        let max_duration = (expected_duration.0.value() as f64 * allowed_variance) as u64;
        let max_test_time = expected_duration * 3;

        // we ignore the first 2 blocks after genesis because they are
        // typically mined very fast.
        let ignore_first_n_blocks = 2;

        let mut start_instant = std::time::SystemTime::now();

        for i in 0..num_blocks + ignore_first_n_blocks {
            if i == ignore_first_n_blocks {
                start_instant = std::time::SystemTime::now();
            }

            let start_time = Timestamp::now();
            let start_st = std::time::SystemTime::now();

            let (transaction, coinbase_utxo_info) =
                { (make_mock_transaction(vec![], vec![]), dummy_expected_utxo()) };

            let (block_header, block_body, block_proof) = Block::make_block_template(
                &prev_block,
                transaction,
                start_time,
                Some(target_block_interval),
            );

            let (worker_task_tx, worker_task_rx) = oneshot::channel::<NewBlockFound>();
            let height = block_header.height;

            mine_block_worker(
                block_header,
                block_body,
                block_proof,
                prev_block.clone(),
                worker_task_tx,
                coinbase_utxo_info,
                unrestricted_mining,
                Some(target_block_interval),
            );

            let mined_block_info = worker_task_rx.await.unwrap();

            // note: this assertion often fails prior to fix for #154.
            // Also note that `is_valid` is a wrapper around `is_valid_extended`
            // which is the method we need here because it allows us to override
            // default values for the target block interval and the minimum
            // block interval.
            assert!(mined_block_info.block.is_valid_extended(
                &prev_block,
                Timestamp::now(),
                Some(target_block_interval),
                Some(Timestamp::millis(0))
            ));

            prev_block = *mined_block_info.block;

            println!(
                "Found block {} in {} milliseconds",
                height,
                start_st.elapsed()?.as_millis()
            );

            let elapsed = start_instant.elapsed()?.as_millis();
            if elapsed > max_test_time.0.value().into() {
                panic!("test time limit exceeded.  expected_duration: {expected_duration}, limit: {max_test_time}, actual: {elapsed}");
            }
        }

        let actual_duration = start_instant.elapsed()?.as_millis() as u64;

        println!("actual duration: {actual_duration}\nexpected duration: {expected_duration}\nmin_duration: {min_duration}\nmax_duration: {max_duration}\nallowed_variance: {allowed_variance}");

        assert!(actual_duration > min_duration);
        assert!(actual_duration < max_duration);

        Ok(())
    }

    #[test]
    fn block_hash_relates_to_predecessor_difficulty() {
        let difficulty = 100u32;
        // Difficulty X means we expect X trials before success.
        // Modeling the process as a geometric distribution gives the
        // probability of success in a single trial, p = 1/X.
        // Then the probability of seeing k failures is (1-1/X)^k.
        // We want this to be five nines certain that we do get a success
        // after k trials, so this quantity must be less than 0.0001.
        // So: log_10 0.0001 = -4 > log_10 (1-1/X)^k = k * log_10 (1 - 1/X).
        // Difficulty 100 sets k = 917.
        let cofactor = (1.0 - (1.0 / (difficulty as f64))).log10();
        let k = (-4.0 / cofactor).ceil() as usize;

        let mut predecessor_header = random_block_header();
        predecessor_header.difficulty = Difficulty::from(difficulty);
        let predecessor_body = BlockBody::new(
            random_transaction_kernel(),
            random_mutator_set_accumulator(),
            random_mmra(),
            random_mmra(),
        );
        let predecessor_block =
            Block::new(predecessor_header, predecessor_body, BlockProof::Invalid);

        let mut successor_header = random_block_header();
        successor_header.prev_block_digest = predecessor_block.hash();
        // note that successor's difficulty is random
        let successor_body = BlockBody::new(
            random_transaction_kernel(),
            random_mutator_set_accumulator(),
            random_mmra(),
            random_mmra(),
        );

        let mut rng = thread_rng();
        let mut counter = 0;
        loop {
            successor_header.nonce = rng.gen();
            let successor_block = Block::new(
                successor_header.clone(),
                successor_body.clone(),
                BlockProof::Invalid,
            );

            if successor_block.has_proof_of_work(&predecessor_block) {
                break;
            }

            counter += 1;

            assert!(
                counter < k,
                "number of hash trials before finding valid pow exceeds statistical limit"
            )
        }
    }
}
