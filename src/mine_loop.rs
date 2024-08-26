use std::ops::Deref;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use futures::channel::oneshot;
use num_traits::identities::Zero;
use primitive_witness::SaltedUtxos;
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
use twenty_first::amount::u32s::U32s;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::math::bfield_codec::BFieldCodec;
use twenty_first::math::digest::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

use crate::models::blockchain::block::block_body::BlockBody;
use crate::models::blockchain::block::block_header::BlockHeader;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::mutator_set_update::*;
use crate::models::blockchain::block::*;
use crate::models::blockchain::shared::*;
use crate::models::blockchain::transaction;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::utxo::*;
use crate::models::blockchain::transaction::validity::TransactionValidationLogic;
use crate::models::blockchain::transaction::*;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::blockchain::type_scripts::TypeScript;
use crate::models::channel::*;
use crate::models::consensus::timestamp::Timestamp;
use crate::models::shared::SIZE_20MB_IN_BYTES;
use crate::models::state::wallet::expected_utxo::ExpectedUtxo;
use crate::models::state::wallet::expected_utxo::UtxoNotifier;
use crate::models::state::wallet::WalletSecret;
use crate::models::state::GlobalState;
use crate::models::state::GlobalStateLock;
use crate::prelude::twenty_first;
use crate::util_types::mutator_set::commit;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

const MOCK_MAX_BLOCK_SIZE: u32 = 1_000_000;

/// Prepare a Block for mining
pub(crate) fn make_block_template(
    previous_block: &Block,
    transaction: Transaction,
    mut block_timestamp: Timestamp,
    target_block_interval: Option<u64>,
) -> (BlockHeader, BlockBody) {
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
    let block_body: BlockBody = BlockBody {
        transaction,
        mutator_set_accumulator: next_mutator_set_accumulator.clone(),
        lock_free_mmr_accumulator: MmrAccumulator::<Hash>::new(vec![]),
        block_mmr_accumulator: block_mmra,
        uncle_blocks: vec![],
    };

    let zero = BFieldElement::zero();
    let new_pow_line: U32s<5> =
        previous_block.kernel.header.proof_of_work_family + previous_block.kernel.header.difficulty;
    let next_block_height = previous_block.kernel.header.height.next();
    if block_timestamp < previous_block.kernel.header.timestamp {
        warn!("Received block is timestamped in the future; mining on future-timestamped block.");
        block_timestamp = previous_block.kernel.header.timestamp + Timestamp::seconds(1);
    }
    let difficulty: U32s<5> =
        Block::difficulty_control(previous_block, block_timestamp, target_block_interval);

    let block_header = BlockHeader {
        version: zero,
        height: next_block_height,
        prev_block_digest: previous_block.hash(),
        timestamp: block_timestamp,
        nonce: [zero, zero, zero],
        max_block_size: MOCK_MAX_BLOCK_SIZE,
        proof_of_work_line: new_pow_line,
        proof_of_work_family: new_pow_line,
        difficulty,
    };

    (block_header, block_body)
}

/// Attempt to mine a valid block for the network
#[allow(clippy::too_many_arguments)]
async fn mine_block(
    block_header: BlockHeader,
    block_body: BlockBody,
    previous_block: Block,
    sender: oneshot::Sender<NewBlockFound>,
    coinbase_utxo_info: ExpectedUtxo,
    difficulty: U32s<5>,
    unrestricted_mining: bool,
    target_block_interval: Option<u64>,
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
            previous_block,
            sender,
            coinbase_utxo_info,
            difficulty,
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
    previous_block: Block,
    sender: oneshot::Sender<NewBlockFound>,
    coinbase_utxo_info: ExpectedUtxo,
    difficulty: U32s<5>,
    unrestricted_mining: bool,
    target_block_interval: Option<u64>,
) {
    let mut threshold = Block::difficulty_to_digest_threshold(difficulty);
    info!(
        "Mining on block with {} outputs. Attempting to find block with height {} with digest less than difficulty threshold: {}",
        block_body.transaction.kernel.outputs.len(),
        block_header.height,
        threshold
    );

    // The RNG used to sample nonces must be thread-safe, which `thread_rng()` is not.
    // Solution: use `thread_rng()` to generate a seed, and generate a thread-safe RNG
    // seeded with that seed. The `thread_rng()` object is dropped immediately.
    let mut rng: StdRng = SeedableRng::from_seed(thread_rng().gen());

    let block_type = Block::mk_std_block_type(None);
    let mut block = Block::new(block_header, block_body, block_type);

    // Mining takes place here
    while block.hash() >= threshold {
        if !unrestricted_mining {
            std::thread::sleep(Duration::from_millis(100));
        }

        // If the sender is cancelled, the parent of this task most
        // likely received a new block, and this task hasn't been stopped
        // yet by the executor, although the call to abort this
        // task *has* been made.
        if sender.is_canceled() {
            info!(
                "Abandoning mining of current block with height {}",
                block.kernel.header.height
            );
            return;
        }

        // mutate nonce in the block's header.
        // Block::hash() will subsequently return a new digest.
        block.set_header_nonce(rng.gen());

        // See issue #149 and test block_timestamp_represents_time_block_found()
        // this ensures header timestamp represents the moment block is found.
        // this is simplest impl.  Efficiencies can perhaps be gained by only
        // performing every N iterations, or other strategies.
        let now = Timestamp::now();
        let new_difficulty: U32s<5> =
            Block::difficulty_control(&previous_block, now, target_block_interval);
        threshold = Block::difficulty_to_digest_threshold(new_difficulty);
        block.set_header_timestamp_and_difficulty(now, new_difficulty);
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
          Difficulty: {difficulty}
"#
    );

    sender
        .send(new_block_found)
        .unwrap_or_else(|_| warn!("Receiver in mining loop closed prematurely"))
}

/// Return the coinbase UTXO for the receiving address and the "sender" randomness
/// used for the canonical AOCL commitment.
fn make_coinbase_transaction(
    coinbase_utxo: &Utxo,
    receiver_digest: Digest,
    wallet_secret: &WalletSecret,
    block_height: BlockHeight,
    mutator_set_accumulator: MutatorSetAccumulator,
    timestamp: Timestamp,
) -> (Transaction, Digest) {
    let sender_randomness: Digest =
        wallet_secret.generate_sender_randomness(block_height, receiver_digest);

    let coinbase_amount = coinbase_utxo
        .coins
        .iter()
        .filter(|coin| coin.type_script_hash == TypeScript::native_currency().hash())
        .map(|coin| {
            *NeptuneCoins::decode(&coin.state)
                .expect("Make coinbase transaction: failed to parse coin state as amount.")
        })
        .sum::<NeptuneCoins>();
    let coinbase_addition_record = commit(
        Hash::hash(coinbase_utxo),
        sender_randomness,
        receiver_digest,
    );

    let kernel = TransactionKernel {
        inputs: vec![],
        outputs: vec![coinbase_addition_record],
        public_announcements: vec![],
        fee: NeptuneCoins::zero(),
        coinbase: Some(coinbase_amount),
        timestamp,
        mutator_set_hash: mutator_set_accumulator.hash(),
    };

    let primitive_witness = transaction::primitive_witness::PrimitiveWitness {
        input_utxos: SaltedUtxos::empty(),
        type_scripts: vec![TypeScript::native_currency()],
        input_lock_scripts: vec![],
        lock_script_witnesses: vec![],
        input_membership_proofs: vec![],
        output_utxos: SaltedUtxos::new(vec![coinbase_utxo.clone()]),
        mutator_set_accumulator,
        kernel: kernel.clone(),
    };
    let transaction_validation_logic = TransactionValidationLogic::from(primitive_witness);
    (
        Transaction {
            kernel,
            witness: transaction_validation_logic,
        },
        sender_randomness,
    )
}

/// Create the transaction that goes into the block template. The transaction is
/// built from the mempool and from the coinbase transaction. Also returns the
/// "sender randomness" used in the coinbase transaction.
pub(crate) fn create_block_transaction(
    latest_block: &Block,
    global_state: &GlobalState,
    timestamp: Timestamp,
) -> (Transaction, ExpectedUtxo) {
    let block_capacity_for_transactions = SIZE_20MB_IN_BYTES;

    // Get most valuable transactions from mempool
    let transactions_to_include = global_state
        .mempool
        .get_transactions_for_block(block_capacity_for_transactions);

    // Build coinbase UTXO
    let transaction_fees = transactions_to_include
        .iter()
        .fold(NeptuneCoins::zero(), |acc, tx| acc + tx.kernel.fee);

    // note: it is Ok to always use the same key here because:
    //  1. if we find a block, the utxo will go to our wallet
    //     and notification occurs offchain, so there is no privacy issue.
    //  2. if we were to derive a new addr for each block then we would
    //     have large gaps since an address only receives funds when
    //     we actually win the mining lottery.
    //  3. also this way we do not have to modify global/wallet state.
    let coinbase_recipient_spending_key = global_state
        .wallet_state
        .wallet_secret
        .nth_generation_spending_key(0);
    let receiving_address = coinbase_recipient_spending_key.to_address();
    let next_block_height: BlockHeight = latest_block.kernel.header.height.next();

    let lock_script = receiving_address.lock_script();
    let coinbase_amount = Block::get_mining_reward(next_block_height) + transaction_fees;
    let coinbase_utxo = Utxo::new_native_coin(lock_script, coinbase_amount);

    let (coinbase_transaction, coinbase_sender_randomness) = make_coinbase_transaction(
        &coinbase_utxo,
        receiving_address.privacy_digest(),
        &global_state.wallet_state.wallet_secret,
        next_block_height,
        latest_block.kernel.body.mutator_set_accumulator.clone(),
        timestamp,
    );

    debug!(
        "Creating block transaction with mutator set hash: {}",
        latest_block.kernel.body.mutator_set_accumulator.hash()
    );

    // Merge incoming transactions with the coinbase transaction
    let merged_transaction = transactions_to_include
        .into_iter()
        .fold(coinbase_transaction, |acc, transaction| {
            Transaction::merge_with(acc, transaction)
        });

    let utxo_info_for_coinbase = ExpectedUtxo::new(
        coinbase_utxo,
        coinbase_sender_randomness,
        coinbase_recipient_spending_key.privacy_preimage,
        UtxoNotifier::OwnMiner,
    );

    (merged_transaction, utxo_info_for_coinbase)
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
    const INITIAL_MINING_SLEEP_IN_SECONDS: u64 = 10;
    tokio::time::sleep(Duration::from_secs(INITIAL_MINING_SLEEP_IN_SECONDS)).await;

    let mut pause_mine = false;
    loop {
        let (worker_task_tx, worker_task_rx) = oneshot::channel::<NewBlockFound>();
        let miner_task: Option<JoinHandle<()>> = if global_state_lock.lock(|s| s.net.syncing).await
        {
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
            let (transaction, coinbase_utxo_info) = create_block_transaction(
                &latest_block,
                global_state_lock.lock_guard().await.deref(),
                now,
            );
            let (block_header, block_body) =
                make_block_template(&latest_block, transaction, now, None);
            let miner_task = mine_block(
                block_header,
                block_body,
                latest_block.clone(),
                worker_task_tx,
                coinbase_utxo_info,
                latest_block.kernel.header.difficulty,
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
    use tracing_test::traced_test;

    use crate::config_models::network::Network;
    use crate::models::consensus::timestamp::Timestamp;
    use crate::tests::shared::mock_genesis_global_state;

    use super::*;

    #[traced_test]
    #[tokio::test]
    async fn block_template_is_valid_test() -> Result<()> {
        // Verify that a block template made with transaction from the mempool is a valid block
        let network = Network::Regtest;
        let mut premine_receiver_global_state_lock =
            mock_genesis_global_state(network, 2, WalletSecret::devnet_wallet()).await;
        let mut premine_receiver_global_state =
            premine_receiver_global_state_lock.lock_guard_mut().await;
        assert!(
            premine_receiver_global_state.mempool.is_empty(),
            "Mempool must be empty at startup"
        );

        // Verify constructed coinbase transaction and block template when mempool is empty
        let genesis_block = Block::genesis_block(network);
        let now = genesis_block.kernel.header.timestamp;
        let (transaction_empty_mempool, _coinbase_sender_randomness) =
            create_block_transaction(&genesis_block, &premine_receiver_global_state, now);
        assert_eq!(
            1,
            transaction_empty_mempool.kernel.outputs.len(),
            "Coinbase transaction with empty mempool must have exactly one output"
        );
        assert!(
            transaction_empty_mempool.kernel.inputs.is_empty(),
            "Coinbase transaction with empty mempool must have zero inputs"
        );
        let (block_header_template_empty_mempool, block_body_empty_mempool) =
            make_block_template(&genesis_block, transaction_empty_mempool, now, None);
        let block_template_empty_mempool = Block::new(
            block_header_template_empty_mempool,
            block_body_empty_mempool,
            Block::mk_std_block_type(None),
        );
        assert!(
            block_template_empty_mempool.is_valid(&genesis_block, now),
            "Block template created by miner with empty mempool must be valid"
        );

        // Add a transaction to the mempool
        let four_neptune_coins = NeptuneCoins::new(4).to_native_coins();
        let receiver_privacy_digest = Digest::default();
        let sender_randomness = Digest::default();
        let tx_output = Utxo {
            coins: four_neptune_coins,
            lock_script_hash: LockScript::anyone_can_spend().hash(),
        };
        let (tx_by_preminer, expected_utxos) = premine_receiver_global_state
            .create_transaction_test_wrapper(
                vec![TxOutput::fake_address(
                    tx_output,
                    sender_randomness,
                    receiver_privacy_digest,
                )],
                NeptuneCoins::new(1),
                now + Timestamp::months(7),
            )
            .await
            .unwrap();

        // inform wallet of any expected utxos from this tx.
        premine_receiver_global_state
            .add_expected_utxos_to_wallet(expected_utxos)
            .await?;

        premine_receiver_global_state
            .mempool
            .insert(&tx_by_preminer);
        assert_eq!(1, premine_receiver_global_state.mempool.len());

        // Build transaction
        let (transaction_non_empty_mempool, _new_coinbase_sender_randomness) =
            create_block_transaction(
                &genesis_block,
                &premine_receiver_global_state,
                now + Timestamp::months(7),
            );
        assert_eq!(
            3,
            transaction_non_empty_mempool.kernel.outputs.len(),
            "Transaction for block with non-empty mempool must contain coinbase output, send output, and change output"
        );
        assert_eq!(1, transaction_non_empty_mempool.kernel.inputs.len(), "Transaction for block with non-empty mempool must contain one input: the genesis UTXO being spent");

        // Build and verify block template
        let (block_header_template, block_body) = make_block_template(
            &genesis_block,
            transaction_non_empty_mempool,
            now + Timestamp::months(7),
            None,
        );
        let block_template_non_empty_mempool = Block::new(
            block_header_template,
            block_body,
            Block::mk_std_block_type(None),
        );
        assert!(
            block_template_non_empty_mempool.is_valid(
                &genesis_block,
                now + Timestamp::months(7) + Timestamp::seconds(2)
            ),
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
    async fn mined_block_has_proof_of_work() -> Result<()> {
        let network = Network::Regtest;
        let global_state_lock =
            mock_genesis_global_state(network, 2, WalletSecret::devnet_wallet()).await;

        let (worker_task_tx, worker_task_rx) = oneshot::channel::<NewBlockFound>();

        let global_state = global_state_lock.lock_guard().await;
        let tip_block_orig = global_state.chain.light_state();
        let now = Timestamp::now();

        let (transaction, coinbase_utxo_info) =
            create_block_transaction(tip_block_orig, &global_state, now);

        let (block_header, block_body) =
            make_block_template(tip_block_orig, transaction, now, None);

        let block_timestamp = tip_block_orig.kernel.header.timestamp + Timestamp::seconds(1);
        let difficulty: U32s<5> = Block::difficulty_control(tip_block_orig, block_timestamp, None);
        let unrestricted_mining = false;

        mine_block_worker(
            block_header,
            block_body,
            tip_block_orig.clone(),
            worker_task_tx,
            coinbase_utxo_info,
            difficulty,
            unrestricted_mining,
            None,
        );

        let mined_block_info = worker_task_rx.await.unwrap();

        assert!(mined_block_info.block.is_valid(tip_block_orig, now));
        assert!(mined_block_info.block.has_proof_of_work(tip_block_orig));

        Ok(())
    }

    /// This test mines a single block at height 1 on the regtest network
    /// and then validates that the header timestamp has changed and
    /// that it is within the last second (from now).
    ///
    /// This is a regression test for issue #149.
    /// https://github.com/Neptune-Crypto/neptune-core/issues/149
    ///
    /// note: this test fails in 318b7a20baf11a7a99f249660f1f70484c586012
    ///       and should always pass in later commits.
    #[traced_test]
    #[tokio::test]
    async fn block_timestamp_represents_time_block_found() -> Result<()> {
        let network = Network::Regtest;
        let global_state_lock =
            mock_genesis_global_state(network, 2, WalletSecret::devnet_wallet()).await;

        let (worker_task_tx, worker_task_rx) = oneshot::channel::<NewBlockFound>();

        let global_state = global_state_lock.lock_guard().await;
        let tip_block_orig = global_state.chain.light_state();

        // pretend/simulate that it takes at least 10 seconds to mine the block.
        let ten_seconds_ago = Timestamp::now() - Timestamp::seconds(10);

        let (transaction, coinbase_utxo_info) =
            create_block_transaction(tip_block_orig, &global_state, ten_seconds_ago);

        let (block_header, block_body) =
            make_block_template(tip_block_orig, transaction, ten_seconds_ago, None);

        // sanity check that our initial state is correct.
        assert_eq!(block_header.timestamp, ten_seconds_ago);

        let initial_header_timestamp = block_header.timestamp;
        let unrestricted_mining = false;
        let difficulty: U32s<5> = Block::difficulty_control(tip_block_orig, ten_seconds_ago, None);

        mine_block_worker(
            block_header,
            block_body,
            tip_block_orig.clone(),
            worker_task_tx,
            coinbase_utxo_info,
            difficulty,
            unrestricted_mining,
            None,
        );

        let mined_block_info = worker_task_rx.await.unwrap();

        let block_timestamp = mined_block_info.block.kernel.header.timestamp;

        assert!(block_timestamp >= initial_header_timestamp);
        assert!(block_timestamp <= Timestamp::now());

        // verify timestamp is within the last 100 seconds (allows for some CI slack).
        assert!(Timestamp::now() - block_timestamp < Timestamp::seconds(100));

        Ok(())
    }

    /// This tests the difficulty adjustment algorithm.
    ///
    /// We mine ten blocks with a target block interval of 1 second, so all
    /// blocks should be mined in approx 10 seconds.
    ///
    /// We set a test time limit of 3x the expected time, ie 30 seconds, and
    /// panic if mining all blocks takes longer than that.
    ///
    /// We also assert upper and lower bounds for variance from the expected 10
    /// seconds.  The variance limit is 1.3, so the upper bound is 13 seconds
    /// and the lower bound is 7692.
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
        let network = Network::Regtest;
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
        let num_blocks = 10;
        let target_block_interval = 1000; // 1 seconds.

        let unrestricted_mining = false;
        let expected_duration = (target_block_interval * num_blocks) as u128;
        let allowed_variance = 1.3;
        let min_duration = (expected_duration as f64 / allowed_variance) as u64;
        let max_duration = (expected_duration as f64 * allowed_variance) as u64;
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

            let (transaction, coinbase_utxo_info) = {
                let global_state = global_state_lock.lock_guard().await;
                create_block_transaction(&prev_block, &global_state, start_time)
            };

            let (block_header, block_body) = make_block_template(
                &prev_block,
                transaction,
                start_time,
                Some(target_block_interval),
            );

            let difficulty: U32s<5> = Block::difficulty_control(
                &prev_block,
                block_header.timestamp,
                Some(target_block_interval),
            );

            let (worker_task_tx, worker_task_rx) = oneshot::channel::<NewBlockFound>();
            let height = block_header.height;

            mine_block_worker(
                block_header,
                block_body,
                prev_block.clone(),
                worker_task_tx,
                coinbase_utxo_info,
                difficulty,
                unrestricted_mining,
                Some(target_block_interval),
            );

            let mined_block_info = worker_task_rx.await.unwrap();

            // note: this assertion often fails prior to fix for #154.
            assert!(mined_block_info.block.is_valid_extended(
                &prev_block,
                Timestamp::now(),
                Some(target_block_interval)
            ));

            prev_block = *mined_block_info.block;

            println!(
                "Found block {} in {} milliseconds",
                height,
                start_st.elapsed()?.as_millis()
            );

            let elapsed = start_instant.elapsed()?.as_millis();
            if elapsed > max_test_time {
                panic!("test time limit exceeded.  expected_duration: {expected_duration}, limit: {max_test_time}, actual: {elapsed}");
            }
        }

        let actual_duration = start_instant.elapsed()?.as_millis() as u64;

        println!("actual duration: {actual_duration}\nexpected duration: {expected_duration}\nmin_duration: {min_duration}\nmax_duration: {max_duration}\nallowed_variance: {allowed_variance}");

        assert!(actual_duration > min_duration);
        assert!(actual_duration < max_duration);

        Ok(())
    }
}
