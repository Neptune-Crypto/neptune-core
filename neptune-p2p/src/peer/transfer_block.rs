use anyhow::Result;
use anyhow::bail;
use anyhow::ensure;
use neptune_consensus::block::Block;
use neptune_consensus::block::BlockProof;
use neptune_consensus::block::block_appendix::BlockAppendix;
use neptune_consensus::block::block_body::BlockBody;
use neptune_consensus::block::block_header::BlockHeader;
use neptune_consensus::transaction::validity::neptune_proof::Proof;
use neptune_primitives::block_height::BlockHeight;
use serde::Deserialize;
use serde::Serialize;

/// Data structure for communicating blocks with peers. The hash digest is not
/// communicated such that the receiver is forced to calculate it themselves.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Eq)]
pub struct TransferBlock {
    pub header: BlockHeader,
    pub body: BlockBody,
    pub appendix: BlockAppendix,
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
            appendix: block.kernel.appendix().clone(),
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use neptune_consensus::block::test_helpers::invalid_empty_block;
    use neptune_primitives::network::Network;

    use super::*;

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
}
