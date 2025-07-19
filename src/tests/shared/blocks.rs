use tasm_lib::prelude::Digest;
use tasm_lib::twenty_first;
use tasm_lib::twenty_first::bfe;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::util_types::mmr::mmr_trait::Mmr;

use crate::api::export::GlobalStateLock;
use crate::api::export::Network;
use crate::api::export::Timestamp;
use crate::config_models::fee_notification_policy::FeeNotificationPolicy;
use crate::mine_loop::composer_parameters::ComposerParameters;
use crate::mine_loop::make_coinbase_transaction_stateless;
use crate::mine_loop::tests::mine_iteration_for_tests;
use crate::models::blockchain::block::block_appendix::BlockAppendix;
use crate::models::blockchain::block::block_body::BlockBody;
use crate::models::blockchain::block::block_header::BlockHeader;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::mutator_set_update::MutatorSetUpdate;
use crate::models::blockchain::block::validity::block_primitive_witness::BlockPrimitiveWitness;
use crate::models::blockchain::block::validity::block_program::BlockProgram;
use crate::models::blockchain::block::validity::block_proof_witness::BlockProofWitness;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::block::BlockProof;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelModifier;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelProxy;
use crate::models::blockchain::transaction::validity::neptune_proof::Proof;
use crate::models::blockchain::transaction::Transaction;
use crate::models::proof_abstractions::verifier::cache_true_claim;
use crate::models::state::wallet::address::generation_address;
use crate::models::state::wallet::address::generation_address::GenerationReceivingAddress;
use crate::models::state::wallet::expected_utxo::ExpectedUtxo;
use crate::tests::shared::Randomness;
use crate::triton_vm_job_queue::TritonVmJobQueue;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::removal_record::RemovalRecord;

/// Create a block containing the supplied transaction kernel, starting from
/// the supplied mutator set.
///
/// The block proof will be invalid.
pub(crate) fn mock_block_from_transaction_and_msa(
    tx_kernel: TransactionKernel,
    mutator_set_before: MutatorSetAccumulator,
    network: Network,
) -> Block {
    let genesis_block = Block::genesis(network);
    let new_block_height: BlockHeight = BlockHeight::from(100u64);
    let block_header = BlockHeader {
        version: bfe!(0),
        height: new_block_height,
        prev_block_digest: genesis_block.hash().hash(),
        timestamp: tx_kernel.timestamp,
        nonce: Digest::default(),
        guesser_digest: Digest::default(),
        cumulative_proof_of_work: genesis_block.header().cumulative_proof_of_work,
        difficulty: genesis_block.header().difficulty,
    };

    let mut next_mutator_set = mutator_set_before.clone();
    let ms_update = MutatorSetUpdate::new(tx_kernel.inputs.clone(), tx_kernel.outputs.clone());
    ms_update
        .apply_to_accumulator(&mut next_mutator_set)
        .unwrap();

    let empty_mmr = MmrAccumulator::init(vec![], 0);
    let body = BlockBody::new(tx_kernel, next_mutator_set, empty_mmr.clone(), empty_mmr);
    let appendix = BlockAppendix::default();

    Block::new(block_header, body, appendix, BlockProof::Invalid)
}

/// Create a block containing the supplied transaction.
///
/// The returned block has an invalid block proof.
pub(crate) fn invalid_block_with_transaction(
    previous_block: &Block,
    transaction: Transaction,
) -> Block {
    let new_block_height: BlockHeight = previous_block.kernel.header.height.next();
    let block_header = BlockHeader {
        version: bfe!(0),
        height: new_block_height,
        prev_block_digest: previous_block.hash(),
        timestamp: transaction.kernel.timestamp,
        nonce: Digest::default(),
        guesser_digest: Digest::default(),
        cumulative_proof_of_work: previous_block.header().cumulative_proof_of_work,
        difficulty: previous_block.header().difficulty,
    };

    let mut next_mutator_set = previous_block.mutator_set_accumulator_after().unwrap();
    let mut block_mmr = previous_block.kernel.body.block_mmr_accumulator.clone();
    block_mmr.append(previous_block.hash());

    let ms_update = MutatorSetUpdate::new(
        transaction.kernel.inputs.clone(),
        transaction.kernel.outputs.clone(),
    );
    ms_update
        .apply_to_accumulator(&mut next_mutator_set)
        .unwrap();

    let body = BlockBody::new(
        transaction.kernel,
        next_mutator_set,
        previous_block.body().lock_free_mmr_accumulator.clone(),
        block_mmr,
    );
    let appendix = BlockAppendix::default();

    Block::new(block_header, body, appendix, BlockProof::Invalid)
}

/// Build a fake and invalid block where the caller can specify the
/// guesser-preimage and guesser fraction.
///
/// Returns (block, composer's expected UTXOs).
#[expect(clippy::too_many_arguments)]
pub(crate) async fn make_mock_block_with_puts_and_guesser_preimage_and_guesser_fraction(
    network: Network,
    previous_block: &Block,
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
    block_timestamp: Option<Timestamp>,
    composer_key: generation_address::GenerationSpendingKey,
    coinbase_sender_randomness: Digest,
    guesser_parameters: (f64, Digest),
) -> (Block, Vec<ExpectedUtxo>) {
    let (guesser_fraction, guesser_preimage) = guesser_parameters;

    // Build coinbase UTXO and associated data
    let block_timestamp = match block_timestamp {
        Some(ts) => ts,
        None => previous_block.kernel.header.timestamp + network.target_block_interval(),
    };

    let composer_parameters = ComposerParameters::new(
        composer_key.to_address().into(),
        coinbase_sender_randomness,
        Some(composer_key.privacy_preimage()),
        guesser_fraction,
        FeeNotificationPolicy::OffChain,
    );

    let cli = crate::config_models::cli_args::Args {
        network,
        ..Default::default()
    };

    let (mut transaction, composer_txos) = make_coinbase_transaction_stateless(
        previous_block,
        composer_parameters,
        block_timestamp,
        TritonVmJobQueue::get_instance(),
        cli.proof_job_options_primitive_witness(),
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

    let mut block = Block::block_template_invalid_proof(
        previous_block,
        transaction,
        block_timestamp,
        network.target_block_interval(),
    );
    block.set_header_guesser_digest(guesser_preimage.hash());

    let composer_expected_utxos = composer_txos
        .iter()
        .map(|txo| {
            ExpectedUtxo::new(
                txo.utxo(),
                txo.sender_randomness(),
                composer_key.privacy_preimage(),
                crate::models::state::wallet::expected_utxo::UtxoNotifier::OwnMinerComposeBlock,
            )
        })
        .collect();

    (block, composer_expected_utxos)
}

/// Build a fake block with a random hash, containing *two* outputs for the
/// composer.
///
/// Returns (block, composer-utxos).
pub(crate) async fn make_mock_block(
    network: Network,
    previous_block: &Block,
    block_timestamp: Option<Timestamp>,
    composer_key: generation_address::GenerationSpendingKey,
    coinbase_sender_randomness: Digest,
) -> (Block, Vec<ExpectedUtxo>) {
    make_mock_block_with_inputs_and_outputs(
        network,
        previous_block,
        vec![],
        vec![],
        block_timestamp,
        composer_key,
        coinbase_sender_randomness,
    )
    .await
}

/// Build a fake block with a random hash, containing the given inputs and
/// outputs as well as two outputs for the composer.
///
/// Returns (block, composer-utxos).
pub(crate) async fn make_mock_block_with_inputs_and_outputs(
    network: Network,
    previous_block: &Block,
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
    block_timestamp: Option<Timestamp>,
    composer_key: generation_address::GenerationSpendingKey,
    coinbase_sender_randomness: Digest,
) -> (Block, Vec<ExpectedUtxo>) {
    make_mock_block_with_puts_and_guesser_preimage_and_guesser_fraction(
        network,
        previous_block,
        inputs,
        outputs,
        block_timestamp,
        composer_key,
        coinbase_sender_randomness,
        (0f64, Digest::default()),
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
    let tip_block = global_state_lock
        .lock_guard()
        .await
        .chain
        .light_state()
        .to_owned();

    let timestamp =
        timestamp.unwrap_or_else(|| tip_block.header().timestamp + Timestamp::minutes(10));

    let (transaction, expected_composer_utxos) = crate::mine_loop::create_block_transaction(
        &tip_block,
        global_state_lock,
        timestamp,
        Default::default(),
    )
    .await?;

    let guesser_preimage = global_state_lock
        .lock_guard()
        .await
        .wallet_state
        .wallet_entropy
        .guesser_preimage(tip_block.hash());
    let mut block = Block::block_template_invalid_proof(
        &tip_block,
        transaction,
        timestamp,
        global_state_lock.cli().network.target_block_interval(),
    );
    block.set_header_guesser_digest(guesser_preimage.hash());

    global_state_lock
        .set_new_self_composed_tip(block.clone(), expected_composer_utxos)
        .await?;

    Ok(block)
}

pub(crate) fn invalid_empty_block(network: Network, predecessor: &Block) -> Block {
    let tx = crate::tests::shared::mock_tx::make_mock_transaction_with_mutator_set_hash(
        vec![],
        vec![],
        predecessor.mutator_set_accumulator_after().unwrap().hash(),
    );
    let timestamp = predecessor.header().timestamp + Timestamp::hours(1);
    Block::block_template_invalid_proof(predecessor, tx, timestamp, network.target_block_interval())
}

/// Return a list of `n` invalid, empty blocks.
pub(crate) fn invalid_empty_blocks(network: Network, ancestor: &Block, n: usize) -> Vec<Block> {
    let mut blocks = vec![];
    let mut predecessor = ancestor;
    for _ in 0..n {
        blocks.push(invalid_empty_block(network, predecessor));
        predecessor = blocks.last().unwrap();
    }

    blocks
}

pub(crate) fn invalid_empty_block_with_timestamp(
    network: Network,
    predecessor: &Block,
    timestamp: Timestamp,
) -> Block {
    let tx = super::mock_tx::make_mock_transaction_with_mutator_set_hash_and_timestamp(
        vec![],
        vec![],
        predecessor.mutator_set_accumulator_after().unwrap().hash(),
        timestamp,
    );
    Block::block_template_invalid_proof(predecessor, tx, timestamp, network.target_block_interval())
}

/// Create a fake block proposal; will pass `is_valid` but fail pow-check. Will
/// be a valid block except for proof and PoW.
pub(crate) async fn fake_valid_block_proposal_from_tx(
    network: Network,
    predecessor: &Block,
    tx: Transaction,
) -> Block {
    let timestamp = tx.kernel.timestamp;

    let primitive_witness = BlockPrimitiveWitness::new(predecessor.to_owned(), tx);

    let body = primitive_witness.body().to_owned();
    let header = primitive_witness.header(timestamp, network.target_block_interval());
    let (appendix, proof) = {
        let block_proof_witness = BlockProofWitness::produce(primitive_witness);
        let appendix = block_proof_witness.appendix();
        let claim = BlockProgram::claim(&body, &appendix);
        cache_true_claim(claim.clone()).await;
        (appendix, BlockProof::SingleProof(Proof::invalid()))
    };

    Block::new(header, body, appendix, proof)
}

/// Create a block from a transaction without the hassle of proving but such
/// that it appears valid.
pub(crate) async fn fake_valid_block_from_tx_for_tests(
    network: Network,
    predecessor: &Block,
    tx: Transaction,
    seed: [u8; 32],
) -> Block {
    let mut block = fake_valid_block_proposal_from_tx(network, predecessor, tx).await;

    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::from_seed(seed);
    while !block.has_proof_of_work(network, predecessor.header()) {
        mine_iteration_for_tests(&mut block, &mut rng);
    }

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
pub(crate) async fn fake_deterministic_successor(predecessor: &Block, network: Network) -> Block {
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
    let composer_parameters = ComposerParameters::new(
        GenerationReceivingAddress::derive_from_seed(seed_digests.pop().unwrap()).into(),
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
        fake_valid_block_from_tx_for_tests(
            network,
            predecessor,
            block_tx,
            seed_bytes.pop().unwrap(),
        )
        .await
    } else {
        fake_valid_block_proposal_from_tx(network, predecessor, block_tx).await
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
    let current_tip = state_lock.lock_guard().await.chain.light_state().clone();
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

pub(crate) mod tests {
    use macro_rules_attr::apply;

    use crate::tests::shared_tokio_runtime;

    use super::*;

    #[apply(shared_tokio_runtime)]
    async fn fake_deterministic_successor_is_deterministic() {
        let network = Network::Main;
        let block = Block::genesis(network);
        let ret0 = fake_deterministic_successor(&block, network).await;
        let ret1 = fake_deterministic_successor(&block, network).await;
        assert_eq!(ret0, ret1);
    }
}
