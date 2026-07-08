//! Test-only builders for fake blocks.
//!
//! These produce blocks that are structurally valid enough for tests that
//! exercise block storage, mutator-set updates, and wallet bookkeeping, but
//! carry an invalid block proof and invalid proof-of-work. The coinbase
//! transaction likewise carries an invalid proof: its kernel is modified after
//! construction, so any real proof would be invalidated regardless.

use itertools::Itertools;
use neptune_consensus::block::block_transaction::BlockTransaction;
use neptune_consensus::block::Block;
use neptune_consensus::transaction::transaction_kernel::TransactionKernelModifier;
use neptune_consensus::transaction::transaction_kernel::TransactionKernelProxy;
use neptune_consensus::transaction::Transaction;
use neptune_consensus::transaction::TransactionProof;
use neptune_mutator_set::addition_record::AdditionRecord;
use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use neptune_mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_mutator_set::shared::CHUNK_SIZE;
use neptune_mutator_set::shared::NUM_TRIALS;
use neptune_mutator_set::shared::WINDOW_SIZE;
use neptune_primitives::network::Network;
use neptune_primitives::timestamp::Timestamp;
use rand::Rng;
use tasm_lib::prelude::Digest;

use crate::address::generation_address;
use crate::address::generation_address::GenerationSpendingKey;
use crate::address::ReceivingAddress;
use crate::coinbase_distribution::CoinbaseDistribution;
use crate::composer_parameters::prepare_coinbase_transaction_stateless;
use crate::composer_parameters::ComposerParameters;
use crate::expected_utxo::ExpectedUtxo;
use crate::expected_utxo::UtxoNotifier;
use crate::fee_notification_policy::FeeNotificationPolicy;

/// Return a block with the specified puts, along with randomized
/// composer rewards.
pub fn block_with_puts(
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
    );

    block
}

/// Build a fake and invalid block where the caller can specify the
/// guesser-preimage and guesser fraction.
///
/// Returns (block, composer's expected UTXOs).
#[expect(clippy::too_many_arguments)]
pub fn make_mock_block_with_puts_and_guesser_preimage_and_guesser_fraction(
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

    // The coinbase transaction is given an invalid proof: the kernel is modified
    // below to splice in the caller's inputs/outputs, which would invalidate any
    // real proof anyway.
    let (composer_txos, transaction_details) = prepare_coinbase_transaction_stateless(
        previous_block,
        composer_parameters,
        block_timestamp,
        network,
    );
    let mut transaction = Transaction {
        kernel: transaction_details.primitive_witness().kernel,
        proof: TransactionProof::invalid(),
    };

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
                UtxoNotifier::OwnMinerComposeBlock,
            )
        })
        .collect();

    (block, composer_expected_utxos)
}

/// Return a block with the specied number of inputs/outputs. Inputs and
/// outputs are random. Also contains randomized composer rewards.
///
/// Does not have a valid proof, nor valid PoW. Not deterministic.
pub fn block_with_num_puts(
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
    );

    block
}

/// Build a fake block with a random hash, containing *two* outputs for the
/// composer.
///
/// Returns (block, composer-utxos).
pub fn make_mock_block(
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
}

/// Build a fake block with a random hash, containing the given inputs and
/// outputs as well as two outputs for the composer.
///
/// Returns (block, composer-utxos).
pub fn make_mock_block_with_inputs_and_outputs(
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
}
