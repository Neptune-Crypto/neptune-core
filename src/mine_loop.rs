pub(crate) mod composer_parameters;
use std::cmp::max;
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use anyhow::Result;
use block_header::BlockHeader;
use composer_parameters::ComposerParameters;
use futures::channel::oneshot;
use num_traits::CheckedSub;
use num_traits::Zero;
use primitive_witness::PrimitiveWitness;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use rayon::iter::ParallelIterator;
use rayon::ThreadPoolBuilder;
use tasm_lib::twenty_first::tip5::digest::Digest;
use tokio::select;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tokio::time::sleep;
use tracing::*;

use crate::api::export::ReceivingAddress;
use crate::api::export::TxInputList;
use crate::api::tx_initiation::builder::transaction_builder::TransactionBuilder;
use crate::api::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
use crate::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
use crate::api::tx_initiation::error::CreateProofError;
use crate::config_models::network::Network;
use crate::job_queue::errors::JobHandleError;
use crate::models::blockchain::block::block_header::BlockPow;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::block_transaction::BlockOrRegularTransaction;
use crate::models::blockchain::block::block_transaction::BlockTransaction;
use crate::models::blockchain::block::difficulty_control::difficulty_control;
use crate::models::blockchain::block::pow::GuesserBuffer;
use crate::models::blockchain::block::pow::Pow;
use crate::models::blockchain::block::*;
use crate::models::blockchain::consensus_rule_set::ConsensusRuleSet;
use crate::models::blockchain::transaction::transaction_proof::TransactionProofType;
use crate::models::blockchain::transaction::*;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::channel::*;
use crate::models::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::shared::SIZE_20MB_IN_BYTES;
use crate::models::state::mining_status::MiningStatus;
use crate::models::state::transaction_details::TransactionDetails;
use crate::models::state::wallet::expected_utxo::ExpectedUtxo;
use crate::models::state::wallet::transaction_output::TxOutput;
use crate::models::state::wallet::transaction_output::TxOutputList;
use crate::models::state::GlobalStateLock;
use crate::triton_vm_job_queue::vm_job_queue;
use crate::triton_vm_job_queue::TritonVmJobPriority;
use crate::triton_vm_job_queue::TritonVmJobQueue;
use crate::COMPOSITION_FAILED_EXIT_CODE;

/// Information related to guessing.
#[derive(Debug, Clone)]
pub(crate) struct GuessingConfiguration {
    pub(crate) num_guesser_threads: Option<usize>,
    pub(crate) address: ReceivingAddress,
}

/// Creates a block transaction and composes a block from it. Returns the block
/// and the composer UTXOs. Block will reward caller according to block
/// proposal parameters.
pub(crate) async fn compose_block_helper(
    latest_block: Block,
    global_state_lock: GlobalStateLock,
    block_timestamp: Timestamp,
    job_options: TritonVmProofJobOptions,
) -> Result<(Block, Vec<ExpectedUtxo>)> {
    let (transaction, composer_utxos) = create_block_transaction(
        &latest_block,
        &global_state_lock,
        block_timestamp,
        job_options.clone(),
    )
    .await?;

    let compose_result = Block::compose(
        &latest_block,
        transaction,
        block_timestamp,
        vm_job_queue(),
        job_options,
    )
    .await?;

    Ok((compose_result, composer_utxos))
}

async fn compose_block(
    latest_block: Block,
    global_state_lock: GlobalStateLock,
    sender: oneshot::Sender<(Block, Vec<ExpectedUtxo>)>,
    cancel_compose_rx: tokio::sync::watch::Receiver<()>,
    now: Timestamp,
) -> Result<()> {
    let timestamp = max(
        now,
        latest_block.header().timestamp + global_state_lock.cli().network.minimum_block_time(),
    );

    let mut job_options = global_state_lock
        .cli()
        .proof_job_options(TritonVmJobPriority::High);
    job_options.cancel_job_rx = Some(cancel_compose_rx);

    let (proposal, composer_utxos) =
        compose_block_helper(latest_block, global_state_lock, timestamp, job_options).await?;

    // Please clap.
    match sender.send((proposal, composer_utxos)) {
        Ok(_) => Ok(()),
        Err(_) => bail!("Composer task failed to send to miner master"),
    }
}

/// Attempt to mine a valid block for the network.
pub(crate) async fn guess_nonce(
    network: Network,
    block: Block,
    previous_block_header: BlockHeader,
    sender: oneshot::Sender<NewBlockFound>,
    guessing_configuration: GuessingConfiguration,
) {
    // We wrap mining loop with spawn_blocking() because it is a
    // very lengthy and CPU intensive task, which should execute
    // on its own thread(s).
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
        guess_worker(
            network,
            block,
            previous_block_header,
            sender,
            guessing_configuration,
            Timestamp::now(),
            None,
        )
    })
    .await
    .unwrap()
}

/// Guess the nonce in parallel until success.
fn guess_worker(
    network: Network,
    mut block: Block,
    previous_block_header: BlockHeader,
    sender: oneshot::Sender<NewBlockFound>,
    guessing_configuration: GuessingConfiguration,
    now: Timestamp,
    override_target_block_interval: Option<Timestamp>,
) {
    let target_block_interval =
        override_target_block_interval.unwrap_or(network.target_block_interval());

    let GuessingConfiguration {
        num_guesser_threads,
        address: guesser_address,
    } = guessing_configuration;

    // Following code must match the rules in `[Block::has_proof_of_work]`.

    // a difficulty reset (to min difficulty) occurs on testnet(s)
    // when the elapsed time between two blocks is greater than a
    // max interval, defined by the network.  It never occurs for
    // mainnet.
    let should_reset_difficulty =
        Block::should_reset_difficulty(network, now, previous_block_header.timestamp);

    info!(
        "prev block height: {}, prev block time: {}, now: {}",
        previous_block_header.height, previous_block_header.timestamp, now
    );

    let prev_difficulty = previous_block_header.difficulty;
    let new_difficulty = if should_reset_difficulty {
        let new_difficulty = network.genesis_difficulty();
        info!(
            "resetting difficulty to genesis: {}. {} seconds elapsed since previous block",
            new_difficulty,
            (now - previous_block_header.timestamp).to_millis() / 1000
        );
        new_difficulty
    } else {
        difficulty_control(
            now,
            previous_block_header.timestamp,
            previous_block_header.difficulty,
            target_block_interval,
            previous_block_header.height,
        )
    };

    let threshold = prev_difficulty.target();
    let threads_to_use = num_guesser_threads.unwrap_or_else(rayon::current_num_threads);
    info!(
        "Guessing with {} threads on block {} with {} outputs and difficulty {}. Target: {}",
        threads_to_use,
        block.header().height,
        block.body().transaction_kernel.outputs.len(),
        previous_block_header.difficulty,
        threshold.to_hex()
    );

    // note: this article discusses rayon strategies for mining.
    // https://www.innoq.com/en/blog/2018/06/blockchain-mining-embarrassingly-parallel/
    //
    // note: number of rayon threads can be set with env var RAYON_NUM_THREADS
    // see:  https://docs.rs/rayon/latest/rayon/fn.max_num_threads.html
    block.set_header_timestamp_and_difficulty(now, new_difficulty);

    block.set_header_guesser_address(guesser_address);

    info!("Start: guess preprocessing.");
    let guesser_buffer = block.guess_preprocess(Some(&sender), Some(threads_to_use));
    if sender.is_canceled() {
        info!("Guess preprocessing canceled. Stopping guessing task.");
        return;
    }
    info!("Completed: guess preprocessing.");

    let pool = ThreadPoolBuilder::new()
        .num_threads(threads_to_use)
        .build()
        .unwrap();
    let guess_result = pool.install(|| {
        rayon::iter::repeat(0)
            .map_init(rand::rng, |rng, _i| {
                guess_nonce_iteration(&guesser_buffer, threshold, rng, &sender)
            })
            .find_any(|r| !r.block_not_found())
            .unwrap()
    });

    let pow = match guess_result {
        GuessNonceResult::Cancelled => {
            info!("Stopping guessing task",);
            return;
        }
        GuessNonceResult::NonceFound { pow } => pow,
        GuessNonceResult::BlockNotFound => unreachable!(),
    };

    info!("Found valid block with nonce ({:x}).", pow.nonce);

    block.set_header_pow(*pow);

    let timestamp = block.header().timestamp;
    let timestamp_standard = timestamp.standard_format();
    let elapsed_human = (timestamp - previous_block_header.timestamp).format_human_duration();
    let hash = block.hash();
    let hex = hash.to_hex();
    let height = block.kernel.header.height;
    let num_inputs = block.body().transaction_kernel.inputs.len();
    let num_outputs = block.body().transaction_kernel.outputs.len();
    info!(
        r#"Newly mined block details:
              Height: {height}
                Time: {timestamp_standard} ({timestamp})
Since previous block: {elapsed_human}
        Digest (Hex): {hex}
        Digest (Raw): {hash}
Difficulty threshold: {threshold}
          Difficulty: {prev_difficulty}
           #inputs  : {num_inputs}
           #outputs : {num_outputs}
"#
    );

    let new_block_found = NewBlockFound {
        block: Box::new(block),
    };

    sender
        .send(new_block_found)
        .unwrap_or_else(|_| warn!("Receiver in mining loop closed prematurely"))
}

enum GuessNonceResult {
    NonceFound { pow: Box<BlockPow> },
    BlockNotFound,
    Cancelled,
}
impl GuessNonceResult {
    fn block_not_found(&self) -> bool {
        matches!(self, Self::BlockNotFound)
    }
}

/// Run a single iteration of the mining loop.
#[inline]
fn guess_nonce_iteration(
    guesser_buffer: &GuesserBuffer<{ BlockPow::MERKLE_TREE_HEIGHT }>,
    threshold: Digest,
    rng: &mut rand::rngs::ThreadRng,
    sender: &oneshot::Sender<NewBlockFound>,
) -> GuessNonceResult {
    let nonce: Digest = rng.random();

    // Check every N guesses if task has been cancelled.
    if nonce.values()[0].raw_u64().trailing_zeros() >= 16 && sender.is_canceled() {
        debug!("Guesser was cancelled.");
        return GuessNonceResult::Cancelled;
    }

    let result = Pow::guess(guesser_buffer, nonce, threshold);

    match result {
        Some(pow) => GuessNonceResult::NonceFound { pow: Box::new(pow) },
        None => GuessNonceResult::BlockNotFound,
    }
}

/// Make a coinbase transaction rewarding the composer identified by receiving
/// address with the block subsidy minus the guesser fee. The rest, including
/// transaction fees, goes to the guesser.
pub(crate) async fn make_coinbase_transaction_stateless(
    latest_block: &Block,
    composer_parameters: ComposerParameters,
    timestamp: Timestamp,
    vm_job_queue: Arc<TritonVmJobQueue>,
    job_options: TritonVmProofJobOptions,
) -> Result<(Transaction, TxOutputList)> {
    let network = job_options.job_settings.network;
    let (composer_outputs, transaction_details) = prepare_coinbase_transaction_stateless(
        latest_block,
        composer_parameters,
        timestamp,
        network,
    );

    let witness = PrimitiveWitness::from_transaction_details(&transaction_details);

    info!("Start: generate single proof for coinbase transaction");

    // note: we provide an owned witness to proof-builder and clone the kernel
    // because this fn accepts arbitrary proving power and generates proof to
    // match highest.  If we were guaranteed to NOT be generating a witness
    // proof, we could use primitive_witness_ref() instead to avoid clone.

    let kernel = witness.kernel.clone();

    let target_block_height = latest_block.header().height;
    let consensus_rule_set = ConsensusRuleSet::infer_from(network, target_block_height);
    let proof = TransactionProofBuilder::new()
        .consensus_rule_set(consensus_rule_set)
        .transaction_details(&transaction_details)
        .primitive_witness(witness)
        .job_queue(vm_job_queue)
        .proof_job_options(job_options)
        .build()
        .await?;

    info!("Done: generating single proof for coinbase transaction");

    let transaction = TransactionBuilder::new()
        .transaction_kernel(kernel)
        .transaction_proof(proof)
        .build()?;

    Ok((transaction, composer_outputs))
}

/// Produce outputs spending a given portion of the coinbase amount. Returns
/// two outputs unless this composition awards the entire coinbase amount to
/// the guesser, in which case zero outputs are returned.
///
/// The coinbase amount is usually set to the block subsidy for this block
/// height.
///
/// There are two equal-value outputs because one is liquid immediately, and the
/// other is locked for 3 years. The portion of the entire block subsidy that
/// goes to the composer is determined by the `guesser_fee_fraction` field of
/// the composer parameters.
///
/// The sum of the value of the outputs is guaranteed to not exceed the
/// coinbase amount, since the guesser fee fraction is guaranteed to be in the
/// range \[0;1\].
///
/// Returns: Either the empty list, or two outputs, one immediately liquid, the
/// other timelocked for three years, as required by the consensus rules.
///
/// # Panics
///
/// If the provided guesser fee fraction is not between 0 and 1 (inclusive).
pub(crate) fn composer_outputs(
    coinbase_amount: NativeCurrencyAmount,
    composer_parameters: ComposerParameters,
    timestamp: Timestamp,
) -> TxOutputList {
    let guesser_fee =
        coinbase_amount.lossy_f64_fraction_mul(composer_parameters.guesser_fee_fraction());

    let amount_to_composer = coinbase_amount
        .checked_sub(&guesser_fee)
        .expect("total_composer_fee cannot exceed coinbase_amount");

    if amount_to_composer.is_zero() {
        return Vec::<TxOutput>::default().into();
    }

    // Note that this calculation guarantees that at least half of the coinbase
    // is timelocked, as a rounding error in the last digit subtracts from the
    // liquid amount. This quality is required by the NativeCurrency type
    // script.
    let mut liquid_composer_amount = amount_to_composer;
    liquid_composer_amount.div_two();
    let timelocked_composer_amount = amount_to_composer
        .checked_sub(&liquid_composer_amount)
        .expect("Amount to composer must be larger than liquid amount to composer.");

    let owned = true;
    let liquid_coinbase_output = TxOutput::native_currency(
        liquid_composer_amount,
        composer_parameters.sender_randomness(),
        composer_parameters.reward_address(),
        composer_parameters.notification_policy().into(),
        owned,
    );

    // Set the time lock to 3 years (minimum) plus 30 minutes margin, since the
    // timestamp might be bumped by future merges. These timestamp bumps affect
    // only the `timestamp` field of the transaction kernel and not the state
    // of the `TimeLock` type script. So in the end you might end up with a
    // transaction whose time-locked portion is not time-locked long enough.
    let timelocked_coinbase_output = TxOutput::native_currency(
        timelocked_composer_amount,
        composer_parameters.sender_randomness(),
        composer_parameters.reward_address(),
        composer_parameters.notification_policy().into(),
        owned,
    )
    .with_time_lock(timestamp + MINING_REWARD_TIME_LOCK_PERIOD + Timestamp::minutes(30));

    vec![liquid_coinbase_output, timelocked_coinbase_output].into()
}

/// Compute `TransactionDetails` and a list of `TxOutput`s for a coinbase
/// transaction.
///
/// # Panics
///
///  - If `latest_block` has a negative transaction fee
pub(super) fn prepare_coinbase_transaction_stateless(
    latest_block: &Block,
    composer_parameters: ComposerParameters,
    timestamp: Timestamp,
    network: Network,
) -> (TxOutputList, TransactionDetails) {
    let mutator_set_accumulator = latest_block.mutator_set_accumulator_after().unwrap();
    let next_block_height: BlockHeight = latest_block.header().height.next();
    info!("Creating coinbase for block of height {next_block_height}.");

    let coinbase_amount = Block::block_subsidy(next_block_height);
    let composer_outputs = composer_outputs(coinbase_amount, composer_parameters, timestamp);
    let total_composer_fee = composer_outputs.total_native_coins();

    let guesser_fee = coinbase_amount
        .checked_sub(&total_composer_fee)
        .expect("total_composer_fee cannot exceed coinbase_amount");

    info!(
        "Coinbase amount is set to {coinbase_amount} and is divided between \
        composer fee ({total_composer_fee}) and guesser fee ({guesser_fee})."
    );

    let transaction_details = TransactionDetails::new_with_coinbase(
        TxInputList::empty(),
        composer_outputs.clone(),
        coinbase_amount,
        guesser_fee,
        timestamp,
        mutator_set_accumulator,
        network,
    );

    (composer_outputs, transaction_details)
}

/// Enumerates origins of transactions to be merged into a block transaction.
///
/// In the general case, this is (just) the mempool.
pub(crate) enum TxMergeOrigin {
    Mempool,
    #[cfg(test)]
    ExplicitList(Vec<Transaction>),
}

/// Create the transaction that goes into the block template. The transaction is
/// built from the mempool and from the coinbase transaction. Also returns the
/// "sender randomness" used in the coinbase transaction.
pub(crate) async fn create_block_transaction(
    predecessor_block: &Block,
    global_state_lock: &GlobalStateLock,
    timestamp: Timestamp,
    job_options: TritonVmProofJobOptions,
) -> Result<(BlockTransaction, Vec<ExpectedUtxo>)> {
    create_block_transaction_from(
        predecessor_block,
        global_state_lock,
        timestamp,
        job_options,
        TxMergeOrigin::Mempool,
    )
    .await
}

/// # Panics
///  - If predecessor has a negative transaction fee
pub(crate) async fn create_block_transaction_from(
    predecessor_block: &Block,
    global_state_lock: &GlobalStateLock,
    timestamp: Timestamp,
    job_options: TritonVmProofJobOptions,
    tx_merge_origin: TxMergeOrigin,
) -> Result<(BlockTransaction, Vec<ExpectedUtxo>)> {
    let block_capacity_for_transactions = SIZE_20MB_IN_BYTES;

    let predecessor_block_ms = predecessor_block
        .mutator_set_accumulator_after()
        .expect("predecessor should be valid");
    let mutator_set_hash = predecessor_block_ms.hash();
    debug!("Creating block transaction with mutator set hash: {mutator_set_hash}",);

    let mut rng: StdRng =
        SeedableRng::from_seed(global_state_lock.lock_guard().await.shuffle_seed());

    let composer_parameters = global_state_lock
        .lock_guard()
        .await
        .composer_parameters(predecessor_block.header().height.next());
    let block_height = predecessor_block.header().height.next();
    let network = global_state_lock.cli().network;
    let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);

    // A coinbase transaction implies mining. So you *must*
    // be able to create a SingleProof.
    let vm_job_queue = vm_job_queue();
    let (coinbase_transaction, composer_txos) = make_coinbase_transaction_stateless(
        predecessor_block,
        composer_parameters.clone(),
        timestamp,
        vm_job_queue.clone(),
        job_options.clone(),
    )
    .await?;

    // Get most valuable transactions from mempool.
    let max_num_mergers = global_state_lock.cli().max_num_compose_mergers.get();
    let mut transactions_to_merge = match tx_merge_origin {
        TxMergeOrigin::Mempool => global_state_lock
            .lock_guard()
            .await
            .mempool
            .get_transactions_for_block_composition(
                block_capacity_for_transactions,
                Some(max_num_mergers),
            ),
        #[cfg(test)]
        TxMergeOrigin::ExplicitList(transactions) => transactions,
    };

    // If necessary, populate list with nop-tx.
    // Guarantees that some merge happens in below loop, which sets merge-bit.
    if transactions_to_merge.is_empty() {
        let nop = TransactionDetails::nop(
            predecessor_block_ms,
            timestamp,
            global_state_lock.cli().network,
        );
        let nop = PrimitiveWitness::from_transaction_details(&nop);

        let options = TritonVmProofJobOptionsBuilder::new()
            .template(&job_options)
            .proof_type(TransactionProofType::SingleProof)
            .build();

        let proof = TransactionProofBuilder::new()
            .consensus_rule_set(consensus_rule_set)
            .primitive_witness_ref(&nop)
            .job_queue(vm_job_queue.clone())
            .proof_job_options(options)
            .build()
            .await?;
        let nop = Transaction {
            kernel: nop.kernel,
            proof,
        };

        transactions_to_merge = vec![nop];
    }

    let num_merges = transactions_to_merge.len();
    let mut block_transaction = BlockOrRegularTransaction::from(coinbase_transaction);
    for (i, tx_to_include) in transactions_to_merge.into_iter().enumerate() {
        info!("Merging transaction {} / {}", i + 1, num_merges);
        info!(
            "Merging tx with {} inputs, {} outputs. With fee {}.",
            tx_to_include.kernel.inputs.len(),
            tx_to_include.kernel.outputs.len(),
            tx_to_include.kernel.fee
        );
        block_transaction = BlockTransaction::merge(
            block_transaction,
            tx_to_include,
            rng.random(),
            vm_job_queue.clone(),
            job_options.clone(),
            consensus_rule_set,
        )
        .await?
        .into(); // fix #579.  propagate error up.
    }

    let own_expected_utxos = composer_parameters.extract_expected_utxos(composer_txos);

    Ok((
        block_transaction
            .try_into()
            .expect("Must have merged at least once"),
        own_expected_utxos,
    ))
}

///
///
/// Locking:
///   * acquires `global_state_lock` for write
pub(crate) async fn mine(
    mut from_main: mpsc::Receiver<MainToMiner>,
    to_main: mpsc::Sender<MinerToMain>,
    mut global_state_lock: GlobalStateLock,
) -> Result<()> {
    // Set PoW guessing to restart every N seconds, if it has been started. Only
    // the guesser task may set this to actually resolve, as this will otherwise
    // abort e.g. the composer. Since preprocessing is expensive, don't do this
    // very often!
    const GUESSING_RESTART_INTERVAL_IN_SECONDS: u64 = 1800;

    // we disable the initial sleep when invoked for unit tests.
    //
    // note: it can take an arbitrary amount of time to obtain latest-block info
    // from peers.  If that is important, we should be listening on a channel
    // instead or better this task should not be started until obtained.
    #[cfg(not(test))]
    {
        // Wait before starting mining task to ensure that peers have sent us
        // information about their latest blocks. This should prevent the client
        // from finding blocks that will later be orphaned.
        const INITIAL_MINING_SLEEP_IN_SECONDS: u64 = 60;

        tracing::info!(
            "sleeping for {} seconds while node initializes",
            INITIAL_MINING_SLEEP_IN_SECONDS
        );
        tokio::time::sleep(Duration::from_secs(INITIAL_MINING_SLEEP_IN_SECONDS)).await;
    }

    let cli_args = global_state_lock.cli().clone();
    let network = cli_args.network;

    let guess_restart_interval = Duration::from_secs(GUESSING_RESTART_INTERVAL_IN_SECONDS);
    let infinite = Duration::from_secs(u32::MAX.into());
    let guess_restart_timer = time::sleep(infinite);
    tokio::pin!(guess_restart_timer);

    let mut pause_mine = false;
    let mut wait_for_confirmation = false;
    loop {
        // Ensure restart timer doesn't resolve again, without guesser
        // task actually being spawned.
        guess_restart_timer
            .as_mut()
            .reset(tokio::time::Instant::now() + infinite);

        let (is_connected, is_syncing, mining_status) = global_state_lock
            .lock(|s| {
                (
                    !s.net.peer_map.is_empty(),
                    s.net.sync_anchor.is_some(),
                    s.mining_state.mining_status,
                )
            })
            .await;
        if !is_connected {
            const WAIT_TIME_WHEN_DISCONNECTED_IN_SECONDS: u64 = 5;
            global_state_lock.set_mining_status_to_inactive().await;
            warn!("Not mining because client has no connections");
            sleep(Duration::from_secs(WAIT_TIME_WHEN_DISCONNECTED_IN_SECONDS)).await;
            continue;
        }

        let (guesser_tx, guesser_rx) = oneshot::channel::<NewBlockFound>();
        let (composer_tx, composer_rx) = oneshot::channel::<(Block, Vec<ExpectedUtxo>)>();

        let maybe_proposal = global_state_lock
            .lock_guard()
            .await
            .mining_state
            .block_proposal
            .clone();
        let guess = cli_args.guess;

        let should_guess = !wait_for_confirmation
            && guess
            && maybe_proposal.is_some()
            && !is_syncing
            && !pause_mine
            && is_connected;

        // if start_guessing is true, then we are in a state change from
        // inactive state to guessing state.
        //
        // if start_guessing is false and should_guess is true then we
        // have already been guessing and are restarting with new params.
        let start_guessing = matches!(
            (mining_status, should_guess),
            (MiningStatus::Inactive, true)
        );

        if start_guessing {
            let proposal = maybe_proposal.unwrap(); // is_some() verified above
            global_state_lock
                .set_mining_status_to_guessing(proposal)
                .await;
        }

        let guesser_task: Option<JoinHandle<()>> = if should_guess {
            // safe because above `is_some`
            let proposal = maybe_proposal.unwrap();
            let guesser_key = global_state_lock
                .lock_guard()
                .await
                .wallet_state
                .wallet_entropy
                .guesser_fee_key();

            let latest_block_header = global_state_lock
                .lock(|s| s.chain.light_state().header().to_owned())
                .await;
            let guesser_task = guess_nonce(
                network,
                proposal.to_owned(),
                latest_block_header,
                guesser_tx,
                GuessingConfiguration {
                    num_guesser_threads: cli_args.guesser_threads,
                    address: guesser_key.to_address().into(),
                },
            );

            // Only run for N seconds to allow for updating of block's timestamp
            // and difficulty.
            guess_restart_timer
                .as_mut()
                .reset(tokio::time::Instant::now() + guess_restart_interval);

            Some(
                tokio::task::Builder::new()
                    .name("guesser")
                    .spawn(guesser_task)
                    .expect("Failed to spawn guesser task"),
            )
        } else {
            None
        };

        let (cancel_compose_tx, cancel_compose_rx) = tokio::sync::watch::channel(());

        let compose = cli_args.compose;
        let mut composer_task = if !wait_for_confirmation
            && compose
            && guesser_task.is_none()
            && !is_syncing
            && !pause_mine
            && is_connected
        {
            global_state_lock.set_mining_status_to_composing().await;

            let latest_block = global_state_lock
                .lock(|s| s.chain.light_state().to_owned())
                .await;
            let compose_task = compose_block(
                latest_block,
                global_state_lock.clone(),
                composer_tx,
                cancel_compose_rx,
                Timestamp::now(),
            );

            let task = tokio::task::Builder::new()
                .name("composer")
                .spawn(compose_task)
                .expect("Failed to spawn composer task.");

            task
        } else {
            tokio::spawn(async { Ok(()) })
        };

        let mut restart_guessing = false;
        let mut stop_guessing = false;
        let mut stop_composing = false;
        let mut stop_looping = false;

        // Await a message from either the worker task or from the main loop,
        // or the restart of the guesser-task.
        select! {
            _ = &mut guess_restart_timer => {
                restart_guessing = true;
            }
            Ok(Err(e)) = &mut composer_task => {

                match e.root_cause().downcast_ref::<CreateProofError>() {
                    // address issue 579.
                    //
                    // check if error indicates job was cancelled. If so,
                    // simply log and continue, but ignore the error.
                    //
                    // this is a fail-safe and appears unreachable for present
                    // codebase during normal mining-loop operation.
                    //
                    // job cancellation can occur any time that the cancellation
                    // channel Sender gets dropped, which occurs if
                    // composer_task gets aborted which occurs if any other
                    // branch of this select!{} resolves first.  Common causes
                    // are NewBlock and NewBlockProposal messages from main.
                    //
                    // HOWEVER: if the composer_task is aborted because another
                    // branch of the select resolves first then this branch
                    // should not execute making this check unnecessary.
                    //
                    // The remaining sources of cancellation are:
                    // 1. mining loop exits, eg during graceful shutdown.
                    // 2. some future change to codebase
                    Some(CreateProofError::JobHandleError(JobHandleError::JobCancelled)) => {
                        debug!("composer job was cancelled. continuing normal operation");
                    }
                    _ => {
                        // Ensure graceful shutdown in case of error during composition.
                        stop_composing = true;
                        error!("Composition failed: {}", e);
                        to_main.send(MinerToMain::Shutdown(COMPOSITION_FAILED_EXIT_CODE)).await?;
                    }
                }
            },

            Some(main_message) = from_main.recv() => {
                debug!("Miner received message type: {}", main_message.get_type());

                match main_message {
                    MainToMiner::Shutdown => {
                        debug!("Miner shutting down.");

                        stop_guessing = true;
                        stop_composing = true;
                        stop_looping = true;
                    }
                    MainToMiner::NewBlock => {
                        stop_guessing = true;
                        stop_composing = true;

                        info!("Miner task received notification about new block");
                    }
                    MainToMiner::NewBlockProposal => {
                        stop_guessing = true;
                        stop_composing = true;

                        info!("Miner received message about new block proposal for guessing.");
                    }
                    MainToMiner::WaitForContinue => {
                        stop_guessing = true;
                        stop_composing = true;

                        wait_for_confirmation = true;
                    }
                    MainToMiner::Continue => {
                        wait_for_confirmation = false;
                    }
                    MainToMiner::StopMining => {
                        pause_mine = true;

                        stop_guessing = true;
                        stop_composing = true;
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
                        stop_guessing = true;
                        stop_composing = true;
                    }
                }
            }
            new_composition = composer_rx => {
                stop_composing = true;

                match new_composition {
                    Ok((new_block_proposal, composer_utxos)) => {
                        to_main.send(MinerToMain::BlockProposal(Box::new((new_block_proposal, composer_utxos)))).await?;
                        wait_for_confirmation = true;
                    },
                    Err(e) => warn!("composing task was cancelled prematurely. Got: {}", e),
                };
            }
            new_block = guesser_rx => {
                stop_guessing = true;

                match new_block {
                    Err(err) => {
                        warn!("Mining task was cancelled prematurely. Got: {}", err);
                    }
                    Ok(new_block_found) => {
                        debug!("Worker task reports new block of height {}", new_block_found.block.kernel.header.height);

                        // Sanity check, remove for more efficient mining.
                        // The below PoW check could fail due to race conditions. So we don't panic,
                        // we only ignore what the worker task sent us.
                        let latest_block = global_state_lock
                            .lock(|s| s.chain.light_state().to_owned())
                            .await;

                        if !new_block_found.block.has_proof_of_work(cli_args.network, latest_block.header()) {
                            error!("Own mined block did not have valid PoW Discarding.");
                        } else if !new_block_found.block.is_valid(&latest_block, Timestamp::now(), global_state_lock.cli().network).await {
                                // Block could be invalid if for instance the proof and proof-of-work
                                // took less time than the minimum block time.
                                error!("Found block with valid proof-of-work but block is invalid.");
                        } else {

                            info!("Found new {} block with block height {}. Hash: {}", global_state_lock.cli().network, new_block_found.block.kernel.header.height, new_block_found.block.hash());

                            to_main.send(MinerToMain::NewBlockFound(new_block_found)).await?;

                            wait_for_confirmation = true;
                        }
                    },
                };
            }
        }

        if restart_guessing {
            if let Some(gt) = &guesser_task {
                gt.abort();
                debug!("Abort-signal sent to guesser worker.");
                debug!("Restarting guesser task with new parameters");
            }
        }
        if stop_guessing {
            if let Some(gt) = &guesser_task {
                gt.abort();
                debug!("Abort-signal sent to guesser worker.");
            }
            global_state_lock.set_mining_status_to_inactive().await;
        }
        if stop_composing {
            if !composer_task.is_finished() {
                cancel_compose_tx.send(())?;
                debug!("Cancel signal sent to composer worker.");
            }
            // avoid duplicate call if stop_guessing is also true.
            if !stop_guessing {
                global_state_lock.set_mining_status_to_inactive().await;
            }
        }

        if stop_looping {
            break;
        }
    }
    debug!("Miner shut down gracefully.");
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use std::hint::black_box;

    use arbitrary::Arbitrary;
    use block_appendix::BlockAppendix;
    use block_body::BlockBody;
    use block_header::tests::random_block_header;
    use difficulty_control::Difficulty;
    use itertools::Itertools;
    use macro_rules_attr::apply;
    use num_bigint::BigUint;
    use num_traits::One;
    use num_traits::Pow;
    use num_traits::Zero;
    use rand::RngCore;
    use tracing_test::traced_test;

    use super::*;
    use crate::api::export::GenerationSpendingKey;
    use crate::config_models::cli_args;
    use crate::config_models::fee_notification_policy::FeeNotificationPolicy;
    use crate::config_models::network::Network;
    use crate::job_queue::errors::JobHandleError;
    use crate::models::blockchain::block::mock_block_generator::MockBlockGenerator;
    use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelProxy;
    use crate::models::blockchain::transaction::validity::single_proof::single_proof_claim;
    use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use crate::models::proof_abstractions::mast_hash::MastHash;
    use crate::models::proof_abstractions::timestamp::Timestamp;
    use crate::models::proof_abstractions::verifier::verify;
    use crate::models::state::mempool::upgrade_priority::UpgradePriority;
    use crate::models::state::tx_creation_config::TxCreationConfig;
    use crate::models::state::tx_proving_capability::TxProvingCapability;
    use crate::models::state::wallet::address::symmetric_key::SymmetricKey;
    use crate::models::state::wallet::transaction_output::TxOutput;
    use crate::models::state::wallet::wallet_entropy::WalletEntropy;
    use crate::tests::shared::dummy_expected_utxo;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared::mock_tx::make_mock_block_transaction_with_mutator_set_hash;
    use crate::tests::shared::mock_tx::make_mock_transaction_with_mutator_set_hash;
    use crate::tests::shared::wait_until;
    use crate::tests::shared_tokio_runtime;
    use crate::triton_vm_job_queue::TritonVmJobQueue;
    use crate::util_types::test_shared::mutator_set::pseudorandom_addition_record;
    use crate::util_types::test_shared::mutator_set::random_mmra;
    use crate::util_types::test_shared::mutator_set::random_mutator_set_accumulator;
    use crate::MINER_CHANNEL_CAPACITY;

    /// Produce a transaction that allocates the given fraction of the block
    /// subsidy to the wallet in two UTXOs, one time-locked and one liquid.
    pub(crate) async fn make_coinbase_transaction_from_state(
        latest_block: &Block,
        global_state_lock: &GlobalStateLock,
        timestamp: Timestamp,
        job_options: TritonVmProofJobOptions,
    ) -> Result<(Transaction, Vec<ExpectedUtxo>)> {
        // It's important to use the input `latest_block` here instead of
        // reading it from state, since that could, because of a race condition
        // lead to an inconsistent witness higher up in the call graph. This is
        // done to avoid holding a read-lock throughout this function.
        let next_block_height: BlockHeight = latest_block.header().height.next();
        let vm_job_queue = vm_job_queue();

        let composer_parameters = global_state_lock
            .lock_guard()
            .await
            .composer_parameters(next_block_height);
        let (transaction, composer_outputs) = make_coinbase_transaction_stateless(
            latest_block,
            composer_parameters.clone(),
            timestamp,
            vm_job_queue,
            job_options,
        )
        .await?;

        let own_expected_utxos = composer_parameters.extract_expected_utxos(composer_outputs);

        Ok((transaction, own_expected_utxos))
    }

    /// Estimates the hash rate in number of hashes per milliseconds
    async fn estimate_own_hash_rate(target_block_interval: Timestamp, num_outputs: usize) -> f64 {
        let network = Network::RegTest;
        let mut rng = rand::rng();
        let global_state_lock = mock_genesis_global_state(
            2,
            WalletEntropy::devnet_wallet(),
            cli_args::Args::default_with_network(network),
        )
        .await;

        let previous_block = global_state_lock
            .lock_guard()
            .await
            .chain
            .light_state()
            .clone();

        let (transaction, _coinbase_utxo_info) = {
            let outputs = (0..num_outputs)
                .map(|_| pseudorandom_addition_record(rng.random()))
                .collect_vec();
            (
                make_mock_block_transaction_with_mutator_set_hash(
                    vec![],
                    outputs,
                    previous_block
                        .mutator_set_accumulator_after()
                        .unwrap()
                        .hash(),
                ),
                dummy_expected_utxo(),
            )
        };
        let start_time = Timestamp::now();
        let block = Block::block_template_invalid_proof(
            &previous_block,
            transaction,
            start_time,
            Some(target_block_interval),
            network,
        );
        let threshold = previous_block.header().difficulty.target();
        let num_iterations_launched = 1_000_000;
        let tick = std::time::SystemTime::now();

        let (worker_task_tx, worker_task_rx) = oneshot::channel::<NewBlockFound>();
        let guesser_buffer = block.guess_preprocess(Some(&worker_task_tx), None);
        let num_iterations_run =
            rayon::iter::IntoParallelIterator::into_par_iter(0..num_iterations_launched)
                .map_init(rand::rng, |prng, _i| {
                    guess_nonce_iteration(&guesser_buffer, threshold, prng, &worker_task_tx);
                })
                .count();
        drop(worker_task_rx);

        let time_spent_mining = tick.elapsed().unwrap();

        (num_iterations_run as f64) / (time_spent_mining.as_millis() as f64)
    }

    /// Estimate the time it takes to prepare a block so we can start guessing
    /// nonces.
    async fn estimate_block_preparation_time_invalid_proof() -> f64 {
        let network = Network::Main;
        let genesis_block = Block::genesis(network);
        let guesser_fee_fraction = 0.0;
        let cli_args = cli_args::Args {
            guesser_fraction: guesser_fee_fraction,
            network,
            ..Default::default()
        };

        let global_state_lock =
            mock_genesis_global_state(2, WalletEntropy::devnet_wallet(), cli_args).await;
        let tick = std::time::SystemTime::now();
        let (transaction, _coinbase_utxo_info) = make_coinbase_transaction_from_state(
            &genesis_block,
            &global_state_lock,
            network.launch_date(),
            global_state_lock
                .cli()
                .proof_job_options_primitive_witness(),
        )
        .await
        .unwrap();
        let transaction = BlockTransaction::upgrade(transaction);

        let in_seven_months = network.launch_date() + Timestamp::months(7);
        let block = Block::block_template_invalid_proof(
            &genesis_block,
            transaction,
            in_seven_months,
            None,
            network,
        );
        let tock = tick.elapsed().unwrap().as_millis() as f64;
        black_box(block);
        tock
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn block_proposal_for_height_one_is_valid_for_various_guesser_fee_fractions() {
        // Verify that a block template made with transaction from the mempool is a valid block
        let network = Network::Main;
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, BlockHeight::genesis());
        let mut alice = mock_genesis_global_state(
            2,
            WalletEntropy::devnet_wallet(),
            cli_args::Args::default_with_network(network),
        )
        .await;
        let genesis_block = Block::genesis(network);
        let now = genesis_block.kernel.header.timestamp + Timestamp::months(7);
        assert!(
            !alice
                .lock_guard()
                .await
                .get_wallet_status_for_tip()
                .await
                .synced_unspent_available_amount(now)
                .is_zero(),
            "Assumed to be premine-recipient"
        );

        let mut rng = StdRng::seed_from_u64(u64::from_str_radix("2350404", 6).unwrap());

        let alice_key = alice
            .lock_guard()
            .await
            .wallet_state
            .wallet_entropy
            .nth_generation_spending_key_for_tests(0);
        let amt_to_alice = NativeCurrencyAmount::coins(4);
        let output_to_alice = TxOutput::offchain_native_currency(
            amt_to_alice,
            rng.random(),
            alice_key.to_address().into(),
            false,
        );
        let config = TxCreationConfig::default()
            .recover_change_off_chain(alice_key.into())
            .with_prover_capability(TxProvingCapability::SingleProof);
        let tx_from_alice = alice
            .api()
            .tx_initiator_internal()
            .create_transaction(
                vec![output_to_alice].into(),
                NativeCurrencyAmount::coins(1),
                now,
                config,
                consensus_rule_set,
            )
            .await
            .unwrap()
            .transaction;

        let mut cli = cli_args::Args::default();
        for guesser_fee_fraction in [0f64, 0.5, 1.0] {
            // Verify constructed coinbase transaction and block template when mempool is empty
            assert!(
                alice.lock_guard().await.mempool.is_empty(),
                "Mempool must be empty at start of loop"
            );

            cli.guesser_fraction = guesser_fee_fraction;
            alice.set_cli(cli.clone()).await;
            let (transaction_empty_mempool, coinbase_utxo_info) = {
                create_block_transaction(
                    &genesis_block,
                    &alice,
                    now,
                    TritonVmProofJobOptions::default_with_network(network),
                )
                .await
                .unwrap()
            };
            assert!(
                coinbase_utxo_info.is_empty(),
                "Default composer UTXO notification policy is onchain. \
             So no expected UTXOs should be returned here."
            );

            let cb_txkmh = transaction_empty_mempool.kernel.mast_hash();
            let cb_tx_claim = single_proof_claim(cb_txkmh, consensus_rule_set);
            assert!(
                verify(
                    cb_tx_claim,
                    transaction_empty_mempool
                        .proof
                        .clone()
                        .into_single_proof()
                        .clone(),
                    network,
                )
                .await,
                "Transaction proof for coinbase transaction must be valid."
            );

            let num_coinbase_outputs = if guesser_fee_fraction == 1.0 { 0 } else { 2 };
            assert_eq!(
                num_coinbase_outputs,
                transaction_empty_mempool.kernel.outputs.len(),
                "Coinbase transaction with empty mempool must have exactly {num_coinbase_outputs} outputs"
            );
            assert!(
                transaction_empty_mempool.kernel.inputs.is_empty(),
                "Coinbase transaction with empty mempool must have zero inputs"
            );
            let block_1_empty_mempool = Block::compose(
                &genesis_block,
                transaction_empty_mempool,
                now,
                TritonVmJobQueue::get_instance(),
                TritonVmJobPriority::High.into(),
            )
            .await
            .unwrap();
            assert!(
                block_1_empty_mempool
                    .is_valid(&genesis_block, now, network)
                    .await,
                "Block template created by miner with empty mempool must be valid"
            );

            {
                let mut alice_gsm = alice.lock_guard_mut().await;
                alice_gsm
                    .mempool_insert((*tx_from_alice).clone(), UpgradePriority::Critical)
                    .await;
                assert_eq!(1, alice_gsm.mempool.len());
            }

            // Build transaction for block
            let (transaction_non_empty_mempool, _new_coinbase_sender_randomness) = {
                create_block_transaction(
                    &genesis_block,
                    &alice,
                    now,
                    (TritonVmJobPriority::Normal, None).into(),
                )
                .await
                .unwrap()
            };

            let num_outputs_after_merge = num_coinbase_outputs + 2;
            assert_eq!(
                num_outputs_after_merge,
                transaction_non_empty_mempool.kernel.outputs.len(),
                "Transaction for block with non-empty mempool must contain {num_coinbase_outputs} outputs from coinbase, \
                send output, and change output"
            );
            assert_eq!(
                1,
                transaction_non_empty_mempool.kernel.inputs.len(),
                "Transaction for block with non-empty mempool must contain one input: the genesis UTXO being spent"
            );

            // Build and verify block template
            let block_1_nonempty_mempool = Block::compose(
                &genesis_block,
                transaction_non_empty_mempool,
                now,
                TritonVmJobQueue::get_instance(),
                TritonVmJobPriority::default().into(),
            )
            .await
            .unwrap();
            assert!(
                block_1_nonempty_mempool
                    .is_valid(&genesis_block, now + Timestamp::seconds(2), network)
                    .await,
                "Block template created by miner with non-empty mempool must be valid"
            );

            alice.lock_guard_mut().await.mempool_clear().await;
        }
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn block_proposal_for_height_two_is_valid() {
        // Verify that block proposals of both height 1 and 2 are valid.
        let network = Network::Main;

        // force SingleProof capability.
        let cli = cli_args::Args {
            tx_proving_capability: Some(TxProvingCapability::SingleProof),
            network,
            ..Default::default()
        };

        let mut alice = mock_genesis_global_state(2, WalletEntropy::devnet_wallet(), cli).await;
        let genesis_block = Block::genesis(network);
        let mocked_now = genesis_block.header().timestamp + Timestamp::months(7);

        assert!(
            alice.lock_guard().await.mempool.is_empty(),
            "Mempool must be empty at start of test"
        );
        let (sender_1, receiver_1) = oneshot::channel();
        let (_cancel_compose_tx, cancel_compose_rx) = tokio::sync::watch::channel(());
        compose_block(
            genesis_block.clone(),
            alice.clone(),
            sender_1,
            cancel_compose_rx.clone(),
            mocked_now,
        )
        .await
        .unwrap();
        let (block_1, _) = receiver_1.await.unwrap();
        let validation_result = block_1.validate(&genesis_block, mocked_now, network).await;
        assert!(validation_result.is_ok(), "{:?}", validation_result);
        alice.set_new_tip(block_1.clone()).await.unwrap();

        let (sender_2, receiver_2) = oneshot::channel();
        compose_block(
            block_1.clone(),
            alice.clone(),
            sender_2,
            cancel_compose_rx,
            mocked_now,
        )
        .await
        .unwrap();
        let (block_2, _) = receiver_2.await.unwrap();
        assert!(block_2.is_valid(&block_1, mocked_now, network).await);
    }

    /// This test mines a single block at height 1 on the main network
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
    #[apply(shared_tokio_runtime)]
    async fn mined_block_has_proof_of_work() {
        let network = Network::Main;
        let cli_args = cli_args::Args {
            guesser_fraction: 0.0,
            network,
            ..Default::default()
        };
        let global_state_lock =
            mock_genesis_global_state(2, WalletEntropy::devnet_wallet(), cli_args).await;
        let tip_block_orig = Block::genesis(network);
        let launch_date = tip_block_orig.header().timestamp;
        let (worker_task_tx, worker_task_rx) = oneshot::channel::<NewBlockFound>();

        let (transaction, _composer_utxo_info) = make_coinbase_transaction_from_state(
            &tip_block_orig,
            &global_state_lock,
            launch_date,
            global_state_lock
                .cli()
                .proof_job_options_primitive_witness(),
        )
        .await
        .unwrap();

        let guesser_key = global_state_lock
            .lock_guard()
            .await
            .wallet_state
            .wallet_entropy
            .guesser_fee_key();
        let transaction = BlockTransaction::upgrade(transaction);
        let mut block = Block::block_template_invalid_proof(
            &tip_block_orig,
            transaction,
            launch_date,
            None,
            network,
        );
        block.set_header_guesser_address(guesser_key.to_address().into());

        let num_guesser_threads = None;

        guess_worker(
            network,
            block,
            tip_block_orig.header().to_owned(),
            worker_task_tx,
            GuessingConfiguration {
                num_guesser_threads,
                address: guesser_key.to_address().into(),
            },
            Timestamp::now(),
            None,
        );

        let mined_block_info = worker_task_rx.await.unwrap();

        assert!(mined_block_info
            .block
            .has_proof_of_work(network, tip_block_orig.header()));
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
    #[apply(shared_tokio_runtime)]
    async fn block_timestamp_represents_time_guessing_started() -> Result<()> {
        let network = Network::Main;
        let cli_args = cli_args::Args {
            guesser_fraction: 0.0,
            network,
            ..Default::default()
        };
        let global_state_lock =
            mock_genesis_global_state(2, WalletEntropy::devnet_wallet(), cli_args).await;
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

        let (transaction, _composer_utxo_info) = make_coinbase_transaction_from_state(
            &tip_block_orig,
            &global_state_lock,
            ten_seconds_ago,
            global_state_lock
                .cli()
                .proof_job_options_primitive_witness(),
        )
        .await
        .unwrap();

        let mut rng = StdRng::seed_from_u64(0);
        let guesser_key = GenerationSpendingKey::derive_from_seed(rng.random());

        let transaction = BlockTransaction::upgrade(transaction);
        let template = Block::block_template_invalid_proof(
            &tip_block_orig,
            transaction,
            ten_seconds_ago,
            None,
            network,
        );

        // sanity check that our initial state is correct.
        let initial_header_timestamp = template.header().timestamp;
        assert_eq!(ten_seconds_ago, initial_header_timestamp);

        let num_guesser_threads = None;

        guess_worker(
            network,
            template,
            tip_block_orig.header().to_owned(),
            worker_task_tx,
            GuessingConfiguration {
                num_guesser_threads,
                address: guesser_key.to_address().into(),
            },
            Timestamp::now(),
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
    /// This serves as a regression test for issue #154.
    /// https://github.com/Neptune-Crypto/neptune-core/issues/154
    async fn mine_m_blocks_in_n_seconds<const NUM_BLOCKS: usize, const NUM_SECONDS: usize>(
    ) -> Result<()> {
        let network = Network::RegTest;
        let global_state_lock = mock_genesis_global_state(
            2,
            WalletEntropy::devnet_wallet(),
            cli_args::Args::default_with_network(network),
        )
        .await;

        let mut prev_block = global_state_lock
            .lock_guard()
            .await
            .chain
            .light_state()
            .clone();

        // adjust these to simulate longer mining runs, possibly
        // with shorter or longer target intervals.
        // expected_duration = num_blocks * target_block_interval
        let target_block_interval =
            Timestamp::millis((1000.0 * (NUM_SECONDS as f64) / (NUM_BLOCKS as f64)).round() as u64);
        println!(
            "target block interval: {} ms",
            target_block_interval.0.value()
        );

        // set initial difficulty in accordance with own hash rate
        let num_guesser_threads = None;
        let num_outputs = 0;
        let hash_rate = estimate_own_hash_rate(target_block_interval, num_outputs).await;
        println!("estimating hash rate at {} per millisecond", hash_rate);
        let prepare_time = estimate_block_preparation_time_invalid_proof().await;
        println!("estimating block preparation time at {prepare_time} ms");
        if 1.5 * prepare_time > target_block_interval.0.value() as f64 {
            println!(
                "Cannot perform meaningful test! Block preparation time \
            too large for target block interval."
            );
            return Ok(());
        }

        let guessing_time = (target_block_interval.to_millis() as f64) - prepare_time;
        let initial_difficulty = BigUint::from((hash_rate * guessing_time) as u128);
        println!("initial difficulty: {}", initial_difficulty);
        prev_block.set_header_timestamp_and_difficulty(
            prev_block.header().timestamp,
            Difficulty::from_biguint(initial_difficulty),
        );

        let expected_duration = target_block_interval * NUM_BLOCKS;
        let stddev = (guessing_time.pow(2.0_f64) / (NUM_BLOCKS as f64)).sqrt();
        let allowed_standard_deviations = 4;
        let min_duration = (expected_duration.0.value() as f64)
            - f64::from(allowed_standard_deviations) * stddev * (NUM_BLOCKS as f64);
        let max_duration = (expected_duration.0.value() as f64)
            + f64::from(allowed_standard_deviations) * stddev * (NUM_BLOCKS as f64);
        let max_test_time = expected_duration * 3;

        // we ignore the first 2 blocks after genesis because they are
        // typically mined very fast.
        let ignore_first_n_blocks = 2;

        let mut durations = Vec::with_capacity(NUM_BLOCKS);
        let mut start_instant = std::time::SystemTime::now();

        let mut rng = StdRng::seed_from_u64(1);

        for i in 0..NUM_BLOCKS + ignore_first_n_blocks {
            if i <= ignore_first_n_blocks {
                start_instant = std::time::SystemTime::now();
            }

            let start_time = Timestamp::now();
            let start_st = std::time::SystemTime::now();

            let transaction = make_mock_transaction_with_mutator_set_hash(
                vec![],
                vec![],
                prev_block.mutator_set_accumulator_after().unwrap().hash(),
            );

            let guesser_key = GenerationSpendingKey::derive_from_seed(rng.random());

            let transaction = BlockTransaction::upgrade(transaction);
            let block = Block::block_template_invalid_proof(
                &prev_block,
                transaction,
                start_time,
                Some(target_block_interval),
                network,
            );

            let (worker_task_tx, worker_task_rx) = oneshot::channel::<NewBlockFound>();
            let height = block.header().height;

            guess_worker(
                network,
                block,
                *prev_block.header(),
                worker_task_tx,
                GuessingConfiguration {
                    num_guesser_threads,
                    address: guesser_key.to_address().into(),
                },
                Timestamp::now(),
                Some(target_block_interval),
            );

            let mined_block_info = worker_task_rx.await.unwrap();

            // note: this assertion often fails prior to fix for #154.
            assert!(mined_block_info
                .block
                .has_proof_of_work(network, prev_block.header()));

            prev_block = *mined_block_info.block;

            let block_time = start_st.elapsed()?.as_millis();
            println!(
                "Found block {} in {block_time} milliseconds; \
                difficulty was {}; total time elapsed so far: {} ms",
                height,
                BigUint::from(prev_block.header().difficulty),
                start_instant.elapsed()?.as_millis()
            );
            if i > ignore_first_n_blocks {
                durations.push(block_time as f64);
            }

            let elapsed = start_instant.elapsed()?.as_millis();
            assert!(
                elapsed <= max_test_time.0.value().into(),
                "test time limit exceeded. \
                 expected_duration: {expected_duration}, limit: {max_test_time}, actual: {elapsed}"
            );
        }

        let actual_duration = start_instant.elapsed()?.as_millis() as u64;

        println!(
            "actual duration: {actual_duration}\n\
        expected duration: {expected_duration}\n\
        min_duration: {min_duration}\n\
        max_duration: {max_duration}\n\
        allowed deviation: {allowed_standard_deviations}"
        );
        println!(
            "average block time: {} whereas target: {}",
            durations.into_iter().sum::<f64>() / (NUM_BLOCKS as f64),
            target_block_interval
        );

        assert!((actual_duration as f64) > min_duration);
        assert!((actual_duration as f64) < max_duration);

        Ok(())
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn mine_20_blocks_in_40_seconds() -> Result<()> {
        mine_m_blocks_in_n_seconds::<20, 40>().await.unwrap();
        Ok(())
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn hash_rate_independent_of_tx_size() {
        let network = Network::Main;

        // It's crucial that the hash rate is independent of the size of the
        // block, since miners are otherwise heavily incentivized to mine small
        // or empty blocks.
        let hash_rate_empty_tx = estimate_own_hash_rate(network.target_block_interval(), 0).await;
        println!("hash_rate_empty_tx: {hash_rate_empty_tx}");

        let hash_rate_big_tx = estimate_own_hash_rate(network.target_block_interval(), 10000).await;
        println!("hash_rate_big_tx: {hash_rate_big_tx}");

        assert!(
            hash_rate_empty_tx * 1.1 > hash_rate_big_tx
                && hash_rate_empty_tx * 0.9 < hash_rate_big_tx,
            "Hash rate for big and small block must be within 10 %"
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn coinbase_transaction_has_one_timelocked_and_one_liquid_output() {
        for notification_policy in [
            FeeNotificationPolicy::OffChain,
            FeeNotificationPolicy::OnChainGeneration,
            FeeNotificationPolicy::OnChainSymmetric,
        ] {
            let network = Network::Main;
            let cli_args = cli_args::Args {
                guesser_fraction: 0.0,
                fee_notification: notification_policy,
                network,
                ..Default::default()
            };
            let global_state_lock =
                mock_genesis_global_state(2, WalletEntropy::devnet_wallet(), cli_args).await;
            let genesis_block = Block::genesis(network);
            let launch_date = genesis_block.header().timestamp;

            let (transaction, coinbase_utxo_info) = make_coinbase_transaction_from_state(
                &genesis_block,
                &global_state_lock,
                launch_date,
                global_state_lock
                    .cli()
                    .proof_job_options_primitive_witness(),
            )
            .await
            .unwrap();

            let expected_number_of_expected_utxos = match notification_policy {
                FeeNotificationPolicy::OffChain => 2,
                FeeNotificationPolicy::OnChainSymmetric
                | FeeNotificationPolicy::OnChainGeneration => 0,
            };
            assert_eq!(
                2,
                transaction.kernel.outputs.len(),
                "Expected two outputs in coinbase tx"
            );
            assert_eq!(
                expected_number_of_expected_utxos,
                coinbase_utxo_info.len(),
                "Expected {expected_number_of_expected_utxos} expected UTXOs for composer."
            );

            if notification_policy == FeeNotificationPolicy::OffChain {
                assert!(
                    coinbase_utxo_info
                        .iter()
                        .filter(|x| x.utxo.release_date().is_some())
                        .count()
                        .is_one(),
                    "Expected one timelocked coinbase UTXO"
                );
                assert!(
                    coinbase_utxo_info
                        .iter()
                        .filter(|x| x.utxo.release_date().is_none())
                        .count()
                        .is_one(),
                    "Expected one liquid coinbase UTXO"
                );
            } else {
                let announced_outputs = global_state_lock
                    .lock_guard()
                    .await
                    .wallet_state
                    .scan_for_utxos_announced_to_known_keys(&transaction.kernel)
                    .collect_vec();
                assert_eq!(2, announced_outputs.len());
                assert_eq!(
                    1,
                    announced_outputs
                        .iter()
                        .filter(|x| x.utxo.release_date().is_some())
                        .count()
                );
                assert_eq!(
                    1,
                    announced_outputs
                        .iter()
                        .filter(|x| x.utxo.release_date().is_none())
                        .count()
                );
            }
        }
    }

    #[test]
    fn composer_outputs_has_length_zero_if_guesser_fraction_is_1() {
        let mut rng = rand::rng();
        let address = SymmetricKey::from_seed(rng.random()).into();
        let composer_parameters = ComposerParameters::new(
            address,
            rng.random(),
            None,
            1.0,
            FeeNotificationPolicy::OffChain,
        );
        let composer_outputs = composer_outputs(
            NativeCurrencyAmount::coins(1),
            composer_parameters,
            Timestamp::now(),
        );
        assert!(composer_outputs.is_empty());
    }

    #[test]
    fn composer_outputs_has_length_two_if_guesser_fraction_is_between_0_and_1() {
        let mut rng = rand::rng();
        let address = SymmetricKey::from_seed(rng.random()).into();
        let guesser_fraction = rng.random_range(0f64..=0.99999f64);
        let composer_parameters = ComposerParameters::new(
            address,
            rng.random(),
            None,
            guesser_fraction,
            FeeNotificationPolicy::OffChain,
        );
        let composer_outputs = composer_outputs(
            NativeCurrencyAmount::coins(1),
            composer_parameters,
            Timestamp::now(),
        );
        assert_eq!(2, composer_outputs.len());
    }

    #[traced_test]
    #[tokio::test]
    async fn coinbase_tx_has_two_outputs_or_zero_outputs() {
        for guesser_fraction in [0.6, 1.0] {
            for notification_policy in [
                FeeNotificationPolicy::OffChain,
                FeeNotificationPolicy::OnChainGeneration,
                FeeNotificationPolicy::OnChainSymmetric,
            ] {
                let network = Network::Main;
                let cli_args = cli_args::Args {
                    guesser_fraction,
                    fee_notification: notification_policy,
                    network,
                    ..Default::default()
                };
                let global_state_lock =
                    mock_genesis_global_state(2, WalletEntropy::devnet_wallet(), cli_args.clone())
                        .await;
                let genesis_block = Block::genesis(cli_args.network);
                let launch_date = genesis_block.header().timestamp;

                let (transaction, expected_utxos) = make_coinbase_transaction_from_state(
                    &genesis_block,
                    &global_state_lock,
                    launch_date,
                    global_state_lock
                        .cli()
                        .proof_job_options_primitive_witness(),
                )
                .await
                .unwrap();

                // Verify zero outputs if guesser gets it all, otherwise two outputs.
                let num_expected_outputs = if guesser_fraction == 1.0 { 0 } else { 2 };
                assert_eq!(num_expected_outputs, transaction.kernel.outputs.len());

                // Verify that the public notifications/expected UTXOs match
                if notification_policy == FeeNotificationPolicy::OffChain {
                    assert_eq!(num_expected_outputs, expected_utxos.len());
                    assert!(transaction.kernel.announcements.is_empty());
                } else {
                    assert!(expected_utxos.is_empty());
                    assert_eq!(num_expected_outputs, transaction.kernel.announcements.len());
                }
            }
        }
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
        let cofactor = (1.0 - (1.0 / f64::from(difficulty))).log10();
        let k = (-4.0 / cofactor).ceil() as usize;

        let mut rng = rand::rng();
        let mut unstructured_source = vec![0u8; TransactionKernelProxy::size_hint(2).0];
        rng.fill_bytes(&mut unstructured_source);
        let mut unstructured = arbitrary::Unstructured::new(&unstructured_source);

        let mut predecessor_header = random_block_header();
        predecessor_header.difficulty = Difficulty::from(difficulty);
        let predecessor_body = BlockBody::new(
            TransactionKernelProxy::arbitrary(&mut unstructured)
                .unwrap()
                .into_kernel(),
            random_mutator_set_accumulator(),
            random_mmra(),
            random_mmra(),
        );
        let appendix = BlockAppendix::default();
        let predecessor_block = Block::new(
            predecessor_header,
            predecessor_body,
            appendix.clone(),
            BlockProof::Invalid,
        );

        let mut successor_header = random_block_header();
        successor_header.prev_block_digest = predecessor_block.hash();
        // note that successor's difficulty is random
        let successor_body = BlockBody::new(
            TransactionKernelProxy::arbitrary(&mut unstructured)
                .unwrap()
                .into_kernel(),
            random_mutator_set_accumulator(),
            random_mmra(),
            random_mmra(),
        );

        let mut counter = 0;
        let successor_block = Block::new(
            successor_header,
            successor_body.clone(),
            appendix,
            BlockProof::Invalid,
        );

        let guesser_buffer = successor_block.guess_preprocess(None, None);
        let target = predecessor_block.header().difficulty.target();
        loop {
            if BlockPow::guess(&guesser_buffer, rng.random(), target).is_some() {
                println!("found solution after {counter} guesses.");
                break;
            }

            counter += 1;

            assert!(
                counter < k,
                "number of hash trials before finding valid pow exceeds statistical limit"
            )
        }
    }

    // tests that a job cancel message cancels composing and results in JobCancelled error
    //
    // This test spawns a task that executes create_block_transaction_from()
    // and then sends a job cancellation message to that task.
    //
    // It verifies that the task ends and the result is a JobCancelled error.
    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn job_cancel_msg_cancels_composing() -> anyhow::Result<()> {
        let network = Network::Main;
        let cli_args = cli_args::Args {
            compose: true,
            network,
            ..Default::default()
        };
        let global_state_lock =
            mock_genesis_global_state(2, WalletEntropy::devnet_wallet(), cli_args.clone()).await;

        let (cancel_job_tx, cancel_job_rx) = tokio::sync::watch::channel(());

        let compose_task = async move {
            let genesis_block = Block::genesis(network);
            let gsl = global_state_lock.clone();
            let cli = &cli_args;
            let mut job_options: TritonVmProofJobOptions = cli.into();
            job_options.cancel_job_rx = Some(cancel_job_rx);
            create_block_transaction_from(
                &genesis_block,
                &gsl,
                Timestamp::now(),
                job_options,
                TxMergeOrigin::Mempool,
            )
            .await
        };

        // start the task running
        let jh = tokio::task::spawn(compose_task);

        // wait a little while for a job to get added to the queue.
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        // now cancel the job and wait for the task to complete (after job cancellation)
        cancel_job_tx.send(()).unwrap();
        let job_result = jh.await?;

        // we must receive an error
        let error = job_result.unwrap_err();

        println!("error: {}", error);

        // the error must indicate the job was cancelled.
        let job_cancelled = matches!(
            error.root_cause().downcast_ref::<CreateProofError>(),
            Some(CreateProofError::JobHandleError(
                JobHandleError::JobCancelled
            ))
        );

        assert!(job_cancelled);

        Ok(())
    }

    // tests that Stop/Start mining messages work as expected while composing.
    //
    // This test spawns task that executes the mining loop ie mine().
    // and then sends StopMining, StartMining messages to the task.
    //
    // The StopMining message causes a job-cancelation message to be sent to
    // prove_concensus_program() which forwards to to proving job.
    //
    // The result is that the composer_task terminates early with a JobCancelled error and for
    // correct behavior, that error must not cause the mining loop to shut-down.
    //
    // The test verifies that the mining status actually changes after each message is
    // sent and that the mining loop continues processing.
    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn msg_from_main_does_not_crash_composer() -> anyhow::Result<()> {
        let network = Network::Main;
        let cli_args = cli_args::Args {
            compose: true,
            network,
            ..Default::default()
        };
        let global_state_lock =
            mock_genesis_global_state(2, WalletEntropy::devnet_wallet(), cli_args).await;

        let (miner_to_main_tx, _miner_to_main_rx) =
            mpsc::channel::<MinerToMain>(MINER_CHANNEL_CAPACITY);
        let (main_to_miner_tx, main_to_miner_rx) =
            mpsc::channel::<MainToMiner>(MINER_CHANNEL_CAPACITY);

        // create a task that for the mining-loop
        let mine_task = mine(
            main_to_miner_rx,
            miner_to_main_tx,
            global_state_lock.clone(),
        );

        // spawn the mining-loop task.
        let jh = tokio::task::spawn(mine_task);

        let timeout = std::time::Duration::from_secs(5);

        // wait until mining-status is Composing.
        // we should have a proving job in queue
        let gsl = global_state_lock.clone();
        wait_until(timeout, move || {
            let gsl = gsl.clone();
            async move {
                matches!(
                    gsl.lock_guard().await.mining_state.mining_status,
                    MiningStatus::Composing(_)
                )
            }
        })
        .await?;

        // send StopMining message to the mining loop
        main_to_miner_tx.send(MainToMiner::StopMining).await?;

        // wait until mining status is inactive.
        // job should have been cancelled and removed from queue, but we have no way to verify
        let gsl2 = global_state_lock.clone();
        wait_until(timeout, move || {
            let gsl2 = gsl2.clone();
            async move {
                matches!(
                    gsl2.lock_guard().await.mining_state.mining_status,
                    MiningStatus::Inactive
                )
            }
        })
        .await?;

        // send StartMining message to the mining loop
        main_to_miner_tx.send(MainToMiner::StartMining).await?;

        // wait until mining-status is Composing again.
        // there should be a proving job in queue again
        let gsl3 = global_state_lock.clone();
        wait_until(timeout, move || {
            let gsl3 = gsl3.clone();
            async move {
                matches!(
                    gsl3.lock_guard().await.mining_state.mining_status,
                    MiningStatus::Composing(_)
                )
            }
        })
        .await?;

        // wait a bit longer for mine-loop processing.
        tokio::time::sleep(timeout).await;

        // ensure mine-loop is still up and running.
        assert!(!main_to_miner_tx.is_closed());
        assert!(!jh.is_finished());

        // abort the mining task, so we can ensure that cancels the job also.
        jh.abort();
        let _ = jh.await;

        // ensure mine-loop is gone.
        assert!(main_to_miner_tx.is_closed());

        Ok(())
    }

    /// A test for difficulty reset logic, which occurs for the TestnetMock
    /// network.
    ///
    /// note: or any future network that returns a Some value from
    /// Network::difficulty_reset_interval()
    ///
    /// The test performs guessing (via guess_worker()) for 20 blocks
    /// and simulates a random block interval between (most) blocks.
    ///
    /// Heights 1, 5, 10, and 15 use a block interval that is >= to
    /// Network::difficulty_reset_interval(), which triggers a difficulty
    /// reset within guess_worker(), under test.
    ///
    /// For each mined block:
    ///  + asserts Block::has_proof_of_work() is true
    ///  + asserts Block::validate().is_ok() is true
    ///
    /// For each block with difficulty reset:
    ///  + asserts block difficulty matches Network::genesis_difficulty()
    ///
    /// For each normal block (without difficulty reset):
    ///  + asserts block difficulty does NOT match Network::genesis_difficulty()
    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn testnet_mock_reset_difficulty() -> anyhow::Result<()> {
        // we are testing the TestnetMock network.
        let network = Network::TestnetMock;

        // basic setup
        let mut rng = rand::rng();
        let num_guesser_threads = None;
        let num_blocks = 20; // generate 20 blocks
        let mut block_time = Timestamp::now();

        // obtain global state
        let global_state_lock = mock_genesis_global_state(
            2,
            WalletEntropy::devnet_wallet(),
            cli_args::Args::default_with_network(network),
        )
        .await;

        // obtain previous (genesis) block
        let mut prev_block = global_state_lock
            .lock_guard()
            .await
            .chain
            .light_state()
            .clone();

        // generate 20 blocks
        for i in 1..=num_blocks {
            // we simulate a block_interval since doing this in real-time would
            // be too slow.

            // height 1 resets because interval since genesis block is large.
            // 5,10,15 we choose arbitrarily.
            let reset_interval = network.difficulty_reset_interval().unwrap();
            let (block_interval, should_reset) = if [1, 5, 10, 15].contains(&i) {
                (reset_interval, true)
            } else {
                // generate random interval between min_block_time and difficulty_reset_interval.
                // this encourages difficulty_control() to modify the difficulty.
                let interval_millis = rng.random_range(
                    network.minimum_block_time().to_millis()..reset_interval.to_millis(),
                );
                (Timestamp::millis(interval_millis), false)
            };
            block_time += block_interval;

            // create tx
            let transaction = make_mock_transaction_with_mutator_set_hash(
                vec![],
                vec![],
                prev_block.mutator_set_accumulator_after().unwrap().hash(),
            );

            // gen guesser key
            let guesser_key = GenerationSpendingKey::derive_from_seed(rng.random());

            // generate a block template / proposal
            let transaction = BlockTransaction::upgrade(transaction);
            let block_template = MockBlockGenerator::mock_block_from_tx_without_pow(
                prev_block.clone(),
                transaction,
                guesser_key.to_address().into(),
                network,
            );

            // create channel to listen for guessing results.
            let (worker_task_tx, worker_task_rx) = oneshot::channel::<NewBlockFound>();

            // perform the guessing.
            guess_worker(
                network,
                block_template,
                *prev_block.header(),
                worker_task_tx,
                GuessingConfiguration {
                    num_guesser_threads,
                    address: guesser_key.to_address().into(),
                },
                block_time,
                None,
            );

            // await a mined block
            let mined_block_info = worker_task_rx.await.unwrap();
            let block = *mined_block_info.block;

            // verify mined block has proof-of-work
            assert!(block.has_proof_of_work(network, prev_block.header()));

            // verify mined block validates
            assert!(block
                .validate(&prev_block, block_time, network)
                .await
                .is_ok());

            if should_reset {
                // verify difficulty matches genesis difficulty
                assert_eq!(block.header().difficulty, network.genesis_difficulty());
            } else {
                // verify difficulty does NOT match genesis difficulty
                assert_ne!(block.header().difficulty, network.genesis_difficulty());
            }

            prev_block = block;
        }

        Ok(())
    }
}
