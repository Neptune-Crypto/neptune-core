use anyhow::bail;
use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::proof::Proof;

use crate::models::blockchain::block::block_appendix::BlockAppendix;
use crate::models::blockchain::block::block_body::BlockBody;
use crate::models::blockchain::block::block_header::BlockHeader;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::block::BlockProof;

/// Data structure for communicating blocks with peers. The hash digest is not
/// communicated such that the receiver is forced to calculate it themselves.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Eq)]
pub struct TransferBlock {
    pub header: BlockHeader,
    pub body: BlockBody,
    pub(crate) appendix: BlockAppendix,
    pub proof: Proof,
}

// todo: change to try_from
impl From<TransferBlock> for Block {
    fn from(t_block: TransferBlock) -> Self {
        Block::new(
            t_block.header,
            t_block.body,
            t_block.appendix,
            BlockProof::SingleProof(t_block.proof),
        )
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
            header: block.kernel.header.clone(),
            body: block.kernel.body.clone(),
            proof,
            appendix: block.kernel.appendix.clone(),
        })
    }
}

#[cfg(test)]
mod test {
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tracing_test::traced_test;

    use super::*;
    use crate::models::peer::Network;
    use crate::models::proof_abstractions::timestamp::Timestamp;
    use crate::tests::shared::invalid_empty_block;
    use crate::tests::shared::valid_sequence_of_blocks_for_tests;

    #[test]
    fn cannot_transfer_blocks_that_are_not_single_proof_supported() {
        let genesis = Block::genesis_block(Network::Main);
        let tblock_genesis: Result<TransferBlock> = (&genesis).try_into();
        assert!(
            tblock_genesis.is_err(),
            "Transfering genesis block is disallowed"
        );
        let invalid_block_1 = invalid_empty_block(&genesis);
        let tblock_1 = TransferBlock::try_from(invalid_block_1);
        assert!(tblock_1.is_err(), "Transfering invalid block is disallowed");
    }

    // test: verify digest is the same after conversion from
    //       TransferBlock and back.
    #[tokio::test]
    #[traced_test]
    async fn from_transfer_block() {
        let network = Network::Main;
        // note: we have to generate a block because
        // TransferBlock::into() will panic if it
        // encounters the genesis block.
        let genesis = Block::genesis_block(network);
        let [block1] = valid_sequence_of_blocks_for_tests(
            &genesis,
            Timestamp::hours(1),
            StdRng::seed_from_u64(5550001).gen(),
        )
        .await;

        let transfer_block = TransferBlock::try_from(block1.clone()).unwrap();
        let new_block = Block::from(transfer_block);
        assert_eq!(block1.hash(), new_block.hash());
    }
}
