use futures::channel::oneshot;
use itertools::Itertools;
use neptune_consensus::block::block_transaction::BlockTransaction;
use neptune_consensus::block::test_helpers::invalid_block_with_transaction;
use neptune_consensus::block::test_helpers::invalid_empty_block;
use neptune_consensus::block::test_helpers::invalid_empty_block_with_proof_size;
use neptune_consensus::block::validity::block_primitive_witness::BlockPrimitiveWitness;
use neptune_consensus::block::validity::block_program::BlockProgram;
use neptune_consensus::block::validity::block_proof_witness::BlockProofWitness;
use neptune_consensus::block::Block;
use neptune_consensus::block::BlockProof;
use neptune_consensus::consensus_rule_set::ConsensusRuleSet;
use neptune_consensus::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use neptune_consensus::proof_abstractions::triton_vm_job_queue::TritonVmJobQueue;
use neptune_consensus::proof_abstractions::verifier::cache_true_claims;
use neptune_consensus::transaction::announcement::Announcement;
use neptune_consensus::transaction::transaction_kernel::TransactionKernelModifier;
use neptune_consensus::transaction::transaction_kernel::TransactionKernelProxy;
use neptune_consensus::transaction::validity::neptune_proof::Proof;
use neptune_consensus::transaction::Transaction;
use neptune_mutator_set::addition_record::AdditionRecord;
use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use neptune_mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_mutator_set::shared::CHUNK_SIZE;
use neptune_mutator_set::shared::NUM_TRIALS;
use neptune_mutator_set::shared::WINDOW_SIZE;
use neptune_primitives::network::Network;
use neptune_primitives::timestamp::Timestamp;
use neptune_wallet::address::generation_address;
use neptune_wallet::address::generation_address::GenerationReceivingAddress;
use neptune_wallet::address::generation_address::GenerationSpendingKey;
use neptune_wallet::address::ReceivingAddress;
use neptune_wallet::expected_utxo::ExpectedUtxo;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use tasm_lib::prelude::Digest;

use crate::api::export::GlobalStateLock;
use crate::api::export::OutputFormat;
use crate::application::config::fee_notification_policy::FeeNotificationPolicy;
use crate::application::loops::channel::NewBlockFound;
use crate::application::loops::mine_loop::coinbase_distribution::CoinbaseDistribution;
use crate::application::loops::mine_loop::compose_block_helper;
use crate::application::loops::mine_loop::composer_parameters::ComposerParameters;
use crate::application::loops::mine_loop::guess_nonce;
use crate::application::loops::mine_loop::guesser_configuration::GuessingConfiguration;
use crate::application::loops::mine_loop::make_coinbase_transaction_stateless;
use crate::tests::shared::mock_tx::send_coins;
use crate::tests::shared::Randomness;

/// Create a valid block on top of provided block. Returned block is valid in
/// terms of both block validity and PoW, and is thus the new canonical block of
/// the chain, assuming that tip is already the most canonical block.
///
/// Returned PoW solution is deterministic, as is the block proof, and
/// consequently the entire block and its hash.
///
/// The most valuable synced SingleProof-backed transaction in the mempool will
/// be included in the block. If mempool is empty a dummy transaction will be
/// merged with the coinbase transaction to set the merge bit.
pub(crate) async fn next_block(
    global_state_lock: GlobalStateLock,
    parent: Block,
    coinbase_timestamp: Option<Timestamp>,
) -> Block {
    let network = global_state_lock.cli().network;
    let coinbase_timestamp = coinbase_timestamp.unwrap_or(parent.header().timestamp);
    let (child_no_pow, _) = compose_block_helper(
        parent.clone(),
        global_state_lock.clone(),
        coinbase_timestamp,
        TritonVmProofJobOptions::default_with_network(network),
    )
    .await
    .unwrap();

    let height = child_no_pow.header().height;
    if let Ok(status) = child_no_pow.header().pow.lustration_status() {
        println!("Before guess: Lustration status, height {height}: {status}");
    }

    let deterministic_guesser_rng = StdRng::seed_from_u64(55512345);

    let (guesser_address, _) = global_state_lock
        .lock_guard()
        .await
        .mining_rewards_address();
    let new_timestamp = parent.header().timestamp + Timestamp::minutes(9);
    let new_timestamp = std::cmp::max(new_timestamp, child_no_pow.header().timestamp);
    let (guesser_tx, guesser_rx) = oneshot::channel::<NewBlockFound>();
    guess_nonce(
        network,
        child_no_pow,
        *parent.header(),
        guesser_tx,
        GuessingConfiguration {
            num_guesser_threads: global_state_lock.cli().guesser_threads,
            address: guesser_address,
            override_rng: Some(deterministic_guesser_rng),
            override_timestamp: Some(new_timestamp),
        },
    )
    .await;
    let child = *guesser_rx.await.unwrap().block;

    if let Ok(status) = child.header().pow.lustration_status() {
        println!("After guess: Lustration status, height {height}: {status}");
    }

    child
}

/// Return a block with the specified puts, along with randomized
/// composer rewards.
pub(crate) async fn block_with_puts(
    network: Network,
    predecessor: &Block,
    outputs: Vec<AdditionRecord>,
    inputs: Vec<RemovalRecord>,
) -> Block {
    let mut rng = rand::rng();
    let (block, _) = make_mock_block_with_inputs_and_outputs(
        predecessor,
        inputs,
        outputs,
        None,
        GenerationSpendingKey::derive_from_seed(rng.random()),
        rng.random(),
        network,
    )
    .await;

    block
}

/// Build a fake and invalid block where the caller can specify the
/// guesser-preimage and guesser fraction.
///
/// Returns (block, composer's expected UTXOs).
#[expect(clippy::too_many_arguments)]
pub(crate) async fn make_mock_block_with_puts_and_guesser_preimage_and_guesser_fraction(
    previous_block: &Block,
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
    block_timestamp: Option<Timestamp>,
    composer_key: generation_address::GenerationSpendingKey,
    coinbase_sender_randomness: Digest,
    guesser_parameters: (f64, ReceivingAddress),
    network: Network,
) -> (Block, Vec<ExpectedUtxo>) {
    let (guesser_fraction, guesser_address) = guesser_parameters;

    // Build coinbase UTXO and associated data
    let block_timestamp = match block_timestamp {
        Some(ts) => ts,
        None => previous_block.kernel.header.timestamp + network.target_block_interval(),
    };

    let coinbase_distribution = CoinbaseDistribution::solo(composer_key.to_address().into());
    let composer_parameters = ComposerParameters::new(
        coinbase_distribution,
        coinbase_sender_randomness,
        Some(composer_key.receiver_preimage()),
        guesser_fraction,
        FeeNotificationPolicy::OffChain,
    );

    let cli = crate::application::config::cli_args::Args {
        network,
        ..Default::default()
    };

    let consensus_rule_set =
        ConsensusRuleSet::infer_from(network, previous_block.header().height.next());
    let (mut transaction, composer_txos) = make_coinbase_transaction_stateless(
        previous_block,
        composer_parameters,
        block_timestamp,
        TritonVmJobQueue::get_instance(),
        cli.proof_job_options_primitive_witness(),
        consensus_rule_set,
    )
    .await
    .unwrap();

    let kernel_proxy = TransactionKernelProxy::from(transaction.kernel.clone());
    let new_outputs = [kernel_proxy.outputs, outputs].concat();
    let new_inputs = [kernel_proxy.inputs, inputs].concat();

    let new_kernel = TransactionKernelModifier::default()
        .outputs(new_outputs)
        .inputs(new_inputs)
        .modify(transaction.kernel.clone());
    transaction.kernel = new_kernel;
    let transaction = BlockTransaction::upgrade(transaction);

    let mut block = Block::block_template_invalid_proof(
        previous_block,
        transaction,
        block_timestamp,
        None,
        network,
    );
    block.set_header_guesser_data(guesser_address.into());

    let composer_expected_utxos = composer_txos
        .iter()
        .map(|txo| {
            ExpectedUtxo::new(
                txo.utxo(),
                txo.sender_randomness(),
                composer_key.receiver_preimage(),
                neptune_wallet::expected_utxo::UtxoNotifier::OwnMinerComposeBlock,
            )
        })
        .collect();

    (block, composer_expected_utxos)
}

/// Return a block with the specied number of inputs/outputs. Inputs and
/// outputs are random. Also contains randomized composer rewards.
///
/// Does not have a valid proof, nor valid PoW. Not deterministic.
pub(crate) async fn block_with_num_puts(
    network: Network,
    predecessor: &Block,
    num_inputs: u128,
    num_outputs: usize,
) -> Block {
    let mut rng = rand::rng();
    let active_window_start = u128::from(
        predecessor
            .mutator_set_accumulator_after()
            .unwrap()
            .get_batch_index(),
    ) * u128::from(CHUNK_SIZE);
    let inputs = (0..num_inputs)
        .map(|_| RemovalRecord {
            absolute_indices: AbsoluteIndexSet::new(
                (0..NUM_TRIALS)
                    .map(|_| rng.random_range(u128::from(CHUNK_SIZE * 3)..u128::from(WINDOW_SIZE)))
                    .map(|ri| ri + active_window_start)
                    .collect_vec()
                    .try_into()
                    .unwrap(),
            ),
            target_chunks: ChunkDictionary::default(),
        })
        .collect_vec();

    let outputs = vec![rng.random(); num_outputs];

    let (block, _) = make_mock_block_with_inputs_and_outputs(
        predecessor,
        inputs,
        outputs,
        None,
        GenerationSpendingKey::derive_from_seed(rng.random()),
        rng.random(),
        network,
    )
    .await;

    block
}

/// Build a fake block with a random hash, containing *two* outputs for the
/// composer.
///
/// Returns (block, composer-utxos).
pub(crate) async fn make_mock_block(
    previous_block: &Block,
    block_timestamp: Option<Timestamp>,
    composer_key: generation_address::GenerationSpendingKey,
    coinbase_sender_randomness: Digest,
    network: Network,
) -> (Block, Vec<ExpectedUtxo>) {
    make_mock_block_with_inputs_and_outputs(
        previous_block,
        vec![],
        vec![],
        block_timestamp,
        composer_key,
        coinbase_sender_randomness,
        network,
    )
    .await
}

/// Build a fake block with a random hash, containing the given inputs and
/// outputs as well as two outputs for the composer.
///
/// Returns (block, composer-utxos).
pub(crate) async fn make_mock_block_with_inputs_and_outputs(
    previous_block: &Block,
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
    block_timestamp: Option<Timestamp>,
    composer_key: generation_address::GenerationSpendingKey,
    coinbase_sender_randomness: Digest,
    network: Network,
) -> (Block, Vec<ExpectedUtxo>) {
    let deterministic_generation_spending_key =
        GenerationSpendingKey::derive_from_seed(Digest::default());
    let guesser_address = deterministic_generation_spending_key.to_address();
    make_mock_block_with_puts_and_guesser_preimage_and_guesser_fraction(
        previous_block,
        inputs,
        outputs,
        block_timestamp,
        composer_key,
        coinbase_sender_randomness,
        (0f64, guesser_address.into()),
        network,
    )
    .await
}

/// Create and store the next block including any transactions presently in the
/// mempool.  The coinbase and guesser fee will go to our own wallet.
///
/// the stored block does NOT have valid proof-of-work, nor does it have a valid
/// block proof.
pub(crate) async fn mine_block_to_wallet_invalid_block_proof(
    global_state_lock: &mut GlobalStateLock,
    timestamp: Option<Timestamp>,
) -> anyhow::Result<Block> {
    let tip = global_state_lock.lock_guard().await.chain.tip().to_owned();

    let timestamp = timestamp.unwrap_or_else(|| tip.header().timestamp + Timestamp::minutes(10));
    let network = global_state_lock.cli().network;
    let job_options = TritonVmProofJobOptions::default_with_network(network);
    let (transaction, expected_composer_utxos) =
        crate::application::loops::mine_loop::create_block_transaction(
            &tip,
            global_state_lock.clone(),
            timestamp,
            job_options,
        )
        .await?;

    let (guesser_address, _) = global_state_lock
        .lock_guard()
        .await
        .mining_rewards_address();
    let mut block =
        Block::block_template_invalid_proof(&tip, transaction, timestamp, None, network);
    block.set_header_guesser_data(guesser_address.into());

    global_state_lock
        .set_new_self_composed_tip(block.clone(), expected_composer_utxos)
        .await?;

    Ok(block)
}

pub(crate) async fn invalid_empty_block1_with_guesser_fraction(
    network: Network,
    guesser_fraction: f64,
) -> Block {
    let genesis = Block::genesis(network);
    let mut rng: StdRng = SeedableRng::seed_from_u64(222555000140);
    let guesser_receiver = GenerationReceivingAddress::derive_from_seed(rng.random());

    make_mock_block_with_puts_and_guesser_preimage_and_guesser_fraction(
        &genesis,
        vec![],
        vec![],
        None,
        GenerationSpendingKey::derive_from_seed(rng.random()),
        rng.random(),
        (guesser_fraction, guesser_receiver.into()),
        network,
    )
    .await
    .0
}

/// Return a list of `n` invalid, empty blocks.
pub(crate) fn invalid_empty_blocks_with_proof_size(
    parent: &Block,
    n: usize,
    network: Network,
    proof_size: usize,
) -> Vec<Block> {
    let mut blocks = vec![];
    let mut predecessor = parent;
    for _ in 0..n {
        blocks.push(invalid_empty_block_with_proof_size(
            predecessor,
            network,
            proof_size,
        ));
        predecessor = blocks.last().unwrap();
    }

    blocks
}

pub(crate) fn invalid_empty_block_with_announcements(
    predecessor: &Block,
    network: Network,
    announcements: Vec<Announcement>,
) -> Block {
    let tx =
        neptune_consensus::transaction::test_helpers::make_mock_transaction_with_mutator_set_hash(
            vec![],
            vec![],
            predecessor.mutator_set_accumulator_after().unwrap().hash(),
        );
    let kernel = TransactionKernelModifier::default()
        .announcements(announcements)
        .clone_modify(&tx.kernel);
    let tx = Transaction {
        kernel,
        proof: tx.proof,
    };
    let timestamp = predecessor.header().timestamp + Timestamp::hours(1);
    let tx = BlockTransaction::upgrade(tx);
    Block::block_template_invalid_proof(predecessor, tx, timestamp, None, network)
}

/// Return a list of `n` invalid, empty blocks.
pub(crate) fn invalid_empty_blocks(ancestor: &Block, n: usize, network: Network) -> Vec<Block> {
    let mut blocks = vec![];
    let mut predecessor = ancestor;
    for _ in 0..n {
        blocks.push(invalid_empty_block(predecessor, network));
        predecessor = blocks.last().unwrap();
    }

    blocks
}

/// Create a fake block proposal; will pass `is_valid` but fail pow-check. Will
/// be a valid block except for proof and PoW.
pub(crate) async fn fake_valid_block_proposal_from_tx(
    predecessor: &Block,
    tx: BlockTransaction,
    network: Network,
) -> Block {
    let timestamp = tx.kernel().timestamp;

    let primitive_witness = BlockPrimitiveWitness::new(predecessor.to_owned(), tx, network);

    let body = primitive_witness.body().to_owned();
    let header = primitive_witness.header(timestamp, network.target_block_interval());
    let (appendix, proof) = {
        let block_proof_witness = BlockProofWitness::produce(primitive_witness);
        let appendix = block_proof_witness.appendix();
        let consensus_rules = ConsensusRuleSet::infer_from(network, header.height);
        let claim = BlockProgram::claim(&body, &appendix, consensus_rules);
        cache_true_claims([claim.clone()]).await;
        (appendix, BlockProof::SingleProof(Proof::invalid()))
    };

    Block::new(header, body, appendix, proof)
}

/// Create a block from a transaction without the hassle of proving but such
/// that it appears valid.
async fn fake_valid_block_from_block_tx_for_tests(
    predecessor: &Block,
    tx: BlockTransaction,
    network: Network,
) -> Block {
    let mut block = fake_valid_block_proposal_from_tx(predecessor, tx, network).await;

    let block_height = block.header().height;
    let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);
    block.satisfy_pow(predecessor.header().difficulty, consensus_rule_set);

    block
}

async fn fake_block_successor(
    predecessor: &Block,
    timestamp: Timestamp,
    with_valid_pow: bool,
    rness: Randomness<2, 2>,
    network: Network,
) -> Block {
    fake_block_successor_with_merged_tx(
        predecessor,
        timestamp,
        with_valid_pow,
        vec![],
        rness,
        network,
    )
    .await
}

/// Return a fake, deterministic, empty block for testing purposes, with a
/// specified successsor and specified network. Does not have valid PoW.
pub(crate) async fn fake_valid_deterministic_successor(
    predecessor: &Block,
    network: Network,
) -> Block {
    let timestamp = predecessor.header().timestamp + Timestamp::hours(1);
    fake_valid_block_proposal_successor_for_test(
        predecessor,
        timestamp,
        Randomness::default(),
        network,
    )
    .await
}

pub async fn fake_block_successor_with_merged_tx(
    predecessor: &Block,
    timestamp: Timestamp,
    with_valid_pow: bool,
    txs: Vec<Transaction>,
    rness: Randomness<2, 2>,
    network: Network,
) -> Block {
    let (mut seed_bytes, mut seed_digests) = (rness.bytes_arr.to_vec(), rness.digests.to_vec());

    let coinbase_reward_address =
        GenerationReceivingAddress::derive_from_seed(seed_digests.pop().unwrap());
    let coinbase_distribution = CoinbaseDistribution::solo(coinbase_reward_address.into());
    let composer_parameters = ComposerParameters::new(
        coinbase_distribution,
        seed_digests.pop().unwrap(),
        None,
        0.5f64,
        FeeNotificationPolicy::OffChain,
    );
    let (block_tx, _) = super::fake_create_block_transaction_for_tests(
        predecessor,
        composer_parameters,
        timestamp,
        seed_bytes.pop().unwrap(),
        txs,
        network,
    )
    .await
    .unwrap();

    if with_valid_pow {
        fake_valid_block_from_block_tx_for_tests(predecessor, block_tx, network).await
    } else {
        fake_valid_block_proposal_from_tx(predecessor, block_tx, network).await
    }
}

pub(crate) async fn fake_valid_block_proposal_successor_for_test(
    predecessor: &Block,
    timestamp: Timestamp,
    rness: Randomness<2, 2>,
    network: Network,
) -> Block {
    fake_block_successor(predecessor, timestamp, false, rness, network).await
}

pub(crate) async fn fake_valid_successor_for_tests(
    predecessor: &Block,
    timestamp: Timestamp,
    rness: Randomness<2, 2>,
    network: Network,
) -> Block {
    fake_block_successor(predecessor, timestamp, true, rness, network).await
}

/// Create a block with coinbase going to self. For testing purposes.
///
/// The block will be valid both in terms of PoW and and will pass the
/// Block::is_valid() function. However, the associated (claim, proof) pair will
/// will not pass `triton_vm::verify`, as its validity is only mocked.
pub(crate) async fn fake_valid_block_for_tests(
    state_lock: &GlobalStateLock,
    rness: Randomness<2, 2>,
) -> Block {
    let current_tip = state_lock.lock_guard().await.chain.tip().to_owned();
    fake_valid_successor_for_tests(
        &current_tip,
        current_tip.header().timestamp + Timestamp::hours(1),
        rness,
        state_lock.cli().network,
    )
    .await
}

/// Create a deterministic sequence of valid blocks.
///
/// Sequence is N-long. Every block i with i > 0 has block i-1 as its
/// predecessor; block 0 has the `predecessor` argument as predecessor. Every
/// block is valid in terms of both `is_valid` and `has_proof_of_work`. But
/// the STARK proofs are mocked.
pub(crate) async fn fake_valid_sequence_of_blocks_for_tests<const N: usize>(
    predecessor: &Block,
    block_interval: Timestamp,
    rness: [Randomness<2, 2>; N],
    network: Network,
) -> [Block; N] {
    fake_valid_sequence_of_blocks_for_tests_dyn(
        predecessor,
        block_interval,
        rness.to_vec(),
        network,
    )
    .await
    .try_into()
    .unwrap()
}

/// Create a deterministic sequence of valid blocks.
///
/// Sequence is N-long. Every block i with i > 0 has block i-1 as its
/// predecessor; block 0 has the `predecessor` argument as predecessor. Every
/// block is valid in terms of both `is_valid` and `has_proof_of_work`. But
/// the STARK proofs are mocked.
pub(crate) async fn fake_valid_sequence_of_blocks_for_tests_dyn(
    mut predecessor: &Block,
    block_interval: Timestamp,
    mut rness_vec: Vec<Randomness<2, 2>>,
    network: Network,
) -> Vec<Block> {
    let mut blocks = vec![];
    while let Some(rness) = rness_vec.pop() {
        let block = fake_valid_successor_for_tests(
            predecessor,
            predecessor.header().timestamp + block_interval,
            rness,
            network,
        )
        .await;
        blocks.push(block);
        predecessor = blocks.last().unwrap();
    }
    blocks
}

/// Build a block with the specified outputs. Includes change outputs if
/// balance exceeds output value. Notifies wallet of expected incoming
/// UTXOs that can be claimed from the transaction.
pub(crate) async fn block_with_outputs(
    gsl: &mut GlobalStateLock,
    outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
) -> Block {
    let light_state = gsl.lock_guard().await.chain.light_state_clone();
    let parent_block = light_state.tip();
    let timestamp = parent_block.header().timestamp + Timestamp::months(7);
    let tx = send_coins(gsl, outputs, timestamp).await;
    invalid_block_with_transaction(parent_block, tx)
}

mod tests {
    use macro_rules_attr::apply;

    use super::*;
    use crate::tests::shared_tokio_runtime;

    #[apply(shared_tokio_runtime)]
    async fn fake_valid_deterministic_successor_is_deterministic() {
        let network = Network::Main;
        let block = Block::genesis(network);
        let ret0 = fake_valid_deterministic_successor(&block, network).await;
        let ret1 = fake_valid_deterministic_successor(&block, network).await;
        assert_eq!(ret0, ret1);
    }
}
