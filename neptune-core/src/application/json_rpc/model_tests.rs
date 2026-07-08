//! Tests for `neptune-rpc-api` model conversions that need neptune-core test
//! helpers (e.g. `block_with_num_puts`, which builds real node blocks). The DTO
//! definitions live in the `neptune-rpc-api` crate; these tests exercise their
//! conversions from consensus types using node-side block builders.

use macro_rules_attr::apply;
use neptune_consensus::block::block_appendix::BlockAppendix;
use neptune_consensus::block::block_body::BlockBody;
use neptune_consensus::block::block_header::BlockHeader;
use neptune_consensus::block::test_helpers::invalid_empty_block_with_proof_size;
use neptune_consensus::block::Block;
use neptune_consensus::block::BlockProof;
use neptune_consensus::transaction::transaction_kernel::TransactionKernelProxy;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use neptune_mutator_set::removal_record::chunk::Chunk;
use neptune_mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_primitives::network::Network;
use neptune_primitives::timestamp::Timestamp;
use neptune_rpc_api::model::wallet::block::RpcWalletBlock;
use neptune_wallet::mock_block::block_with_num_puts;
use num_traits::Zero;
use tasm_lib::prelude::Digest;
use tasm_lib::twenty_first::prelude::MmrMembershipProof;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

use crate::tests::shared_tokio_runtime;

fn assert_rpc_block_hash_and_block_hash_agree(block: &Block) {
    let rpc_block: RpcWalletBlock = RpcWalletBlock::from(block);
    assert_eq!(block.hash(), rpc_block.hash());
}

#[apply(shared_tokio_runtime)]
async fn rpc_wallet_block_hash_agrees_with_block_hash() {
    let network = Network::Main;
    let proof_size1 = 234;
    let block1 =
        invalid_empty_block_with_proof_size(&Block::genesis(network), network, proof_size1);
    assert_rpc_block_hash_and_block_hash_agree(&block1);

    let proof_size2 = 534;
    let block2 = invalid_empty_block_with_proof_size(&block1, network, proof_size2);
    assert_rpc_block_hash_and_block_hash_agree(&block2);

    let block3 = block_with_num_puts(network, &block2, 2, 2);
    assert_rpc_block_hash_and_block_hash_agree(&block3);
}

#[apply(shared_tokio_runtime)]
async fn rpc_block_hash_correct_repeated_chunk_indices() {
    // Verify that block hash is preserved when a compressed chunk
    // dictionary contains repeated keys, which is allowed under the
    // compression scheme defined in [`RemovalRecordList`].
    // See issue #886:
    // https://github.com/Neptune-Crypto/neptune-core/issues/886
    let repeated_element = (0, (MmrMembershipProof::new(vec![]), Chunk::empty_chunk()));
    let repeated_keys = vec![RemovalRecord {
        absolute_indices: AbsoluteIndexSet::empty_dummy(),
        target_chunks: ChunkDictionary::new(vec![repeated_element.clone(), repeated_element]),
    }];

    let tx_kernel = TransactionKernelProxy {
        inputs: repeated_keys,
        outputs: vec![],
        announcements: vec![],
        fee: NativeCurrencyAmount::zero(),
        coinbase: None,
        timestamp: Timestamp::now(),
        mutator_set_hash: Digest::default(),
        merge_bit: true,
    }
    .into_kernel();

    let network = Network::Main;
    let block_with_repeated_chunk_dictionary_keys = Block::new(
        BlockHeader::genesis(network),
        BlockBody::new(
            tx_kernel,
            MutatorSetAccumulator::default(),
            MmrAccumulator::new_from_leafs(vec![]),
            MmrAccumulator::new_from_leafs(vec![]),
        ),
        BlockAppendix::default(),
        BlockProof::Invalid,
    );

    assert_rpc_block_hash_and_block_hash_agree(&block_with_repeated_chunk_dictionary_keys);
}
