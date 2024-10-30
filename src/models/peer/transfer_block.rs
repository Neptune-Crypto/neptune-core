use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::proof::Proof;
use tracing::error;

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

// todo: change to try_from
impl From<Block> for TransferBlock {
    fn from(block: Block) -> Self {
        let proof = match &block.proof {
            BlockProof::SingleProof(sp) => sp.clone(),
            BlockProof::Genesis => {
                error!("The Genesis block cannot be transferred");
                // TODO: Don't panic in `From` imlementations! Fix!
                panic!()
            }
            BlockProof::Invalid => {
                error!("Invalid blocks cannot be transferred");
                panic!()
            }
        };
        Self {
            header: block.kernel.header.clone(),
            body: block.kernel.body.clone(),
            proof,
            appendix: block.kernel.appendix.clone(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::models::peer::Network;
    use crate::models::state::wallet::WalletSecret;
    use crate::tests::shared::make_mock_block;
    use crate::tests::shared::mock_genesis_global_state;
    use rand::thread_rng;
    use rand::Rng;

    use super::*;

    // test: verify digest is the same after conversion from
    //       TransferBlock and back.
    #[tokio::test]
    async fn from_transfer_block() {
        // note: we have to generate a block because
        // TransferBlock::into() will panic if it
        // encounters the genesis block.
        let global_state_lock =
            mock_genesis_global_state(Network::RegTest, 2, WalletSecret::devnet_wallet()).await;
        let spending_key = global_state_lock
            .lock_guard()
            .await
            .wallet_state
            .wallet_secret
            .nth_generation_spending_key_for_tests(0);
        let address = spending_key.to_address();
        let mut rng = thread_rng();

        let gblock = Block::genesis_block(Network::RegTest);

        let (source_block, _, _) = make_mock_block(&gblock, None, address, rng.gen());

        let transfer_block = TransferBlock::from(source_block.clone());
        let new_block = Block::from(transfer_block);
        assert_eq!(source_block.hash(), new_block.hash());
    }
}
