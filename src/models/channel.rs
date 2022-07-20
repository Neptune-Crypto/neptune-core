use std::net::{IpAddr, SocketAddr};

use twenty_first::amount::u32s::U32s;

use super::blockchain::block::{
    block_header::PROOF_OF_WORK_COUNT_U32_SIZE, block_height::BlockHeight, Block,
};

#[derive(Clone, Debug)]
pub enum MainToMiner {
    Empty,
    NewBlock(Box<Block>),
    // StopMining,
    // StartMining,
    // SetCoinbasePubkey,
}

#[derive(Clone, Debug)]
pub enum MinerToMain {
    NewBlock(Box<Block>),
}

#[derive(Clone, Debug)]
pub enum MainToPeerThread {
    Block(Box<Block>),
    BlockFromMiner(Box<Block>),
    Transaction(i32),
    RequestBlockBatch(BlockHeight, SocketAddr), // (start_block_height, peer_socket_to_request)
    PeerSynchronizationTimeout(IpAddr), // Abort a synchronization attempt that has timed out
}

#[derive(Clone, Debug)]
pub enum PeerThreadToMain {
    NewBlocks(Vec<Block>),
    NewTransaction(i32),
    PeerMaxBlockHeight((SocketAddr, BlockHeight, U32s<PROOF_OF_WORK_COUNT_U32_SIZE>)),
}
