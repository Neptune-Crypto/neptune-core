use std::net::SocketAddr;

use twenty_first::amount::u32s::U32s;

use super::blockchain::{
    block::{block_header::PROOF_OF_WORK_COUNT_U32_SIZE, block_height::BlockHeight, Block},
    digest::Digest,
    transaction::Transaction,
};

#[derive(Clone, Debug)]
pub enum MainToMiner {
    Empty,
    NewBlock(Box<Block>),
    NewTransactions(Vec<Transaction>),
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
    // Transaction(i32),
    RequestBlockBatch(Vec<Digest>, SocketAddr), // (most canonical known digests, peer_socket_to_request)
    PeerSynchronizationTimeout(SocketAddr), // sanction a peer for failing to respond to sync request
    MakePeerDiscoveryRequest,               // Request peer list from connected peers
    MakeSpecificPeerDiscoveryRequest(SocketAddr), // Request peers from a specific peer to get peers further away
    Disconnect(SocketAddr),                       // Disconnect from a specific peer
    Transactions(Vec<Transaction>),
    DisconnectAll(), // Disconnect from all peers
}

impl MainToPeerThread {
    pub fn get_type(&self) -> String {
        match self {
            MainToPeerThread::Block(_) => "block".to_string(),
            MainToPeerThread::BlockFromMiner(_) => "block from miner".to_string(),
            // MainToPeerThread::Transaction(_) => "tx".to_string(),
            MainToPeerThread::RequestBlockBatch(_, _) => "req block batch".to_string(),
            MainToPeerThread::PeerSynchronizationTimeout(_) => "peer sync timeout".to_string(),
            MainToPeerThread::MakePeerDiscoveryRequest => "make peer discovery req".to_string(),
            MainToPeerThread::MakeSpecificPeerDiscoveryRequest(_) => {
                "make specific peer discovery req".to_string()
            }
            MainToPeerThread::Transactions(_) => "send".to_string(),
            MainToPeerThread::Disconnect(_) => "disconnect".to_string(),
            MainToPeerThread::DisconnectAll() => "disconnect all".to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum PeerThreadToMain {
    NewBlocks(Vec<Block>),
    // NewTransaction(i32),
    AddPeerMaxBlockHeight((SocketAddr, BlockHeight, U32s<PROOF_OF_WORK_COUNT_U32_SIZE>)),
    RemovePeerMaxBlockHeight(SocketAddr),
    PeerDiscoveryAnswer((Vec<(SocketAddr, u128)>, SocketAddr, u8)), // ([(peer_listen_address)], reported_by, distance)
    NewTransactions(Vec<Transaction>),
}

impl PeerThreadToMain {
    pub fn get_type(&self) -> String {
        match self {
            PeerThreadToMain::NewBlocks(_) => "new blocks".to_string(),
            // PeerThreadToMain::NewTransaction(_) => "new transaction".to_string(),
            PeerThreadToMain::AddPeerMaxBlockHeight(_) => "add peer max block height".to_string(),
            PeerThreadToMain::RemovePeerMaxBlockHeight(_) => {
                "remove peer max block height".to_string()
            }
            PeerThreadToMain::PeerDiscoveryAnswer(_) => "peer discovery answer".to_string(),
            PeerThreadToMain::NewTransactions(_) => "send".to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum RPCServerToMain {
    Send(Vec<Transaction>),
    Shutdown(),
}
