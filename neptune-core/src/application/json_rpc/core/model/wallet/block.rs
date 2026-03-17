use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::BFieldCodec;

use crate::application::json_rpc::core::model::block::RpcBlockKernel;
use crate::protocol::consensus::block::Block;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcWalletBlock {
    pub kernel: RpcBlockKernel,
    pub proof_leaf: Digest,
}

impl From<&Block> for RpcWalletBlock {
    fn from(block: &Block) -> Self {
        RpcWalletBlock {
            kernel: RpcBlockKernel::from(&block.kernel),
            proof_leaf: Tip5::hash_varlen(&block.proof.encode()),
        }
    }
}

impl RpcWalletBlock {
    pub fn hash(&self) -> Digest {
        Tip5::hash_pair(
            Tip5::hash_varlen(&self.kernel.mast_hash().encode()),
            self.proof_leaf,
        )
    }
}

#[cfg(test)]
mod tests {
    use macro_rules_attr::apply;
    use num_traits::Zero;
    use tasm_lib::twenty_first::prelude::MmrMembershipProof;
    use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

    use super::*;
    use crate::api::export::AbsoluteIndexSet;
    use crate::api::export::NativeCurrencyAmount;
    use crate::api::export::Network;
    use crate::api::export::Timestamp;
    use crate::protocol::consensus::block::block_appendix::BlockAppendix;
    use crate::protocol::consensus::block::block_body::BlockBody;
    use crate::protocol::consensus::block::block_header::BlockHeader;
    use crate::protocol::consensus::block::BlockProof;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelProxy;
    use crate::tests::shared::blocks::block_with_num_puts;
    use crate::tests::shared::blocks::invalid_empty_block_with_proof_size;
    use crate::tests::shared_tokio_runtime;
    use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
    use crate::util_types::mutator_set::removal_record::chunk::Chunk;
    use crate::util_types::mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
    use crate::util_types::mutator_set::removal_record::RemovalRecord;

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

        let block3 = block_with_num_puts(network, &block2, 2, 2).await;
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
            target_chunks: ChunkDictionary {
                dictionary: vec![repeated_element.clone(), repeated_element],
            },
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
}
