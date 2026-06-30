//! Test-support constructors for blocks with invalid proofs.

use neptune_mutator_set::addition_record::AdditionRecord;
use neptune_primitives::timestamp::Timestamp;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::twenty_first::bfe;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;

use crate::protocol::consensus::block::block_appendix::BlockAppendix;
use crate::protocol::consensus::block::block_body::BlockBody;
use crate::protocol::consensus::block::block_header::BlockHeader;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::block_transaction::BlockTransaction;
use crate::protocol::consensus::block::guesser_receiver_data::GuesserReceiverData;
use crate::protocol::consensus::block::mutator_set_update::MutatorSetUpdate;
use crate::protocol::consensus::block::pow::Pow;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::block::BlockProof;
use crate::protocol::consensus::network::Network;
use crate::protocol::consensus::transaction::test_helpers::make_mock_transaction_with_mutator_set_hash_and_timestamp;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::validity::neptune_proof::Proof;
use crate::protocol::consensus::transaction::Transaction;

pub fn invalid_block_with_tx_kernel(previous_block: &Block, tx_kernel: TransactionKernel) -> Block {
    // 60s min block time on main and testnet
    let minimum_block_time = Timestamp::seconds(60);
    let timestamp = Timestamp::max(
        previous_block.header().timestamp + minimum_block_time,
        tx_kernel.timestamp,
    );
    let new_block_height: BlockHeight = previous_block.kernel.header.height.next();
    let difficulty = previous_block.header().difficulty;
    let block_header = BlockHeader {
        version: bfe!(0),
        height: new_block_height,
        prev_block_digest: previous_block.hash(),
        timestamp,
        pow: Pow::default(),
        guesser_receiver_data: GuesserReceiverData::default(),
        cumulative_proof_of_work: previous_block.header().cumulative_proof_of_work + difficulty,
        difficulty,
    };

    let mut next_mutator_set = previous_block.mutator_set_accumulator_after().unwrap();
    let mut block_mmr = previous_block.kernel.body.block_mmr_accumulator.clone();
    block_mmr.append(previous_block.hash());

    let ms_update = MutatorSetUpdate::new(tx_kernel.inputs.clone(), tx_kernel.outputs.clone());
    ms_update
        .apply_to_accumulator(&mut next_mutator_set)
        .unwrap();

    let transaction = BlockTransaction::from_tx_kernel(tx_kernel);
    let body = BlockBody::new(
        transaction.kernel.into(),
        next_mutator_set,
        previous_block.body().lock_free_mmr_accumulator.clone(),
        block_mmr,
    );
    let appendix = BlockAppendix::default();

    Block::new(block_header, body, appendix, BlockProof::Invalid)
}

/// Create a block containing the supplied transaction.
///
/// The returned block has an invalid block proof.
pub fn invalid_block_with_transaction(previous_block: &Block, transaction: Transaction) -> Block {
    invalid_block_with_tx_kernel(previous_block, transaction.kernel)
}

pub fn invalid_empty_block_with_proof_size(
    predecessor: &Block,
    network: Network,
    proof_size: usize,
) -> Block {
    let mut block = invalid_empty_block(predecessor, network);
    block.set_proof(BlockProof::SingleProof(Proof::invalid_with_size(
        proof_size,
    )));

    block
}

pub fn invalid_empty_block(predecessor: &Block, network: Network) -> Block {
    invalid_empty_block_with_num_outputs(predecessor, network, 0)
}

pub fn invalid_empty_block_with_num_outputs(
    predecessor: &Block,
    network: Network,
    num_outputs: usize,
) -> Block {
    let timestamp = predecessor.header().timestamp + Timestamp::hours(1);
    let outputs = vec![AdditionRecord::new(Digest::default()); num_outputs];
    let tx = make_mock_transaction_with_mutator_set_hash_and_timestamp(
        vec![],
        outputs,
        predecessor.mutator_set_accumulator_after().unwrap().hash(),
        timestamp,
    );
    let tx = BlockTransaction::upgrade(tx);
    Block::block_template_invalid_proof(predecessor, tx, timestamp, None, network)
}

pub fn invalid_empty_block_with_timestamp(
    predecessor: &Block,
    timestamp: Timestamp,
    network: Network,
) -> Block {
    let tx = make_mock_transaction_with_mutator_set_hash_and_timestamp(
        vec![],
        vec![],
        predecessor.mutator_set_accumulator_after().unwrap().hash(),
        timestamp,
    );
    let tx = BlockTransaction::upgrade(tx);
    Block::block_template_invalid_proof(predecessor, tx, timestamp, None, network)
}
