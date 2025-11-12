use anyhow::bail;
use anyhow::ensure;
use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;

use crate::protocol::consensus::block::block_appendix::BlockAppendix;
use crate::protocol::consensus::block::block_body::BlockBody;
use crate::protocol::consensus::block::block_header::BlockHeader;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::block::BlockProof;
use crate::protocol::consensus::transaction::validity::neptune_proof::Proof;

/// Data structure for communicating blocks with peers. The hash digest is not
/// communicated such that the receiver is forced to calculate it themselves.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Eq)]
pub struct TransferBlock {
    pub header: BlockHeader,
    pub body: BlockBody,
    pub(crate) appendix: BlockAppendix,
    pub proof: Proof,
}

impl TryFrom<TransferBlock> for Block {
    type Error = anyhow::Error;

    fn try_from(t_block: TransferBlock) -> std::result::Result<Self, Self::Error> {
        ensure!(
            t_block.header.height != BlockHeight::genesis(),
            "The genesis block cannot be transferred or decoded from transfer",
        );

        let block = Block::new(
            t_block.header,
            t_block.body,
            t_block.appendix,
            BlockProof::SingleProof(t_block.proof),
        );
        Ok(block)
    }
}

impl TryFrom<Block> for TransferBlock {
    type Error = anyhow::Error;

    fn try_from(value: Block) -> Result<Self> {
        (&value).try_into()
    }
}

impl TryFrom<&Block> for TransferBlock {
    type Error = anyhow::Error;

    fn try_from(block: &Block) -> Result<Self> {
        let proof = match &block.proof {
            BlockProof::SingleProof(sp) => sp.clone(),
            BlockProof::Genesis => {
                bail!("The Genesis block cannot be transferred")
            }
            BlockProof::Invalid => {
                bail!("Invalid blocks cannot be transferred");
            }
        };
        Ok(Self {
            header: block.kernel.header,
            body: block.kernel.body.clone(),
            proof,
            appendix: block.kernel.appendix.clone(),
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use macro_rules_attr::apply;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tracing_test::traced_test;

    use super::*;
    use crate::protocol::peer::Network;
    use crate::protocol::proof_abstractions::timestamp::Timestamp;
    use crate::tests::shared::blocks::fake_valid_sequence_of_blocks_for_tests;
    use crate::tests::shared::blocks::invalid_empty_block;
    use crate::tests::shared_tokio_runtime;

    #[test]
    fn cannot_transfer_blocks_that_are_not_single_proof_supported() {
        let network = Network::Main;
        let genesis = Block::genesis(network);
        let tblock_genesis: Result<TransferBlock> = (&genesis).try_into();
        assert!(
            tblock_genesis.is_err(),
            "Transferring genesis block is disallowed"
        );
        let invalid_block_1 = invalid_empty_block(&genesis, network);
        let tblock_1 = TransferBlock::try_from(invalid_block_1);
        assert!(
            tblock_1.is_err(),
            "Transferring invalid block is disallowed"
        );
    }

    // test: verify digest is the same after conversion from
    //       TransferBlock and back.
    #[apply(shared_tokio_runtime)]
    #[traced_test]
    async fn from_transfer_block() {
        let network = Network::Main;
        // note: we have to generate a block because
        // TransferBlock::into() will panic if it
        // encounters the genesis block.
        let genesis = Block::genesis(network);
        let [block1] = fake_valid_sequence_of_blocks_for_tests(
            &genesis,
            Timestamp::hours(1),
            StdRng::seed_from_u64(5550001).random(),
            network,
        )
        .await;

        let transfer_block = TransferBlock::try_from(block1.clone()).unwrap();
        let new_block = Block::try_from(transfer_block).unwrap();
        assert_eq!(block1.hash(), new_block.hash());
    }
}
