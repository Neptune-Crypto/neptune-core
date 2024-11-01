use std::net::SocketAddr;

use tasm_lib::triton_vm::prelude::Digest;

use super::blockchain::block::block_height::BlockHeight;
use super::blockchain::block::difficulty_control::ProofOfWork;
use super::blockchain::block::Block;
use super::blockchain::transaction::Transaction;
use super::peer::transaction_notification::TransactionNotification;
use super::state::wallet::expected_utxo::ExpectedUtxo;

#[derive(Clone, Debug)]
pub enum MainToMiner {
    Empty,
    NewBlock(Box<Block>),
    Shutdown,

    // `ReadyToMineNextBlock` is used to communicate that a block received from the miner has
    // been processed by `main_loop` and that the mempool thus is in an updated state, ready to
    // mine the next block.
    ReadyToMineNextBlock,

    StopMining,
    StartMining,

    StartSyncing,
    StopSyncing,
    // SetCoinbasePubkey,
}

#[derive(Clone, Debug)]
pub struct NewBlockFound {
    pub block: Box<Block>,
    pub coinbase_utxo_info: Box<ExpectedUtxo>,
    pub guesser_fee_utxo_infos: Vec<ExpectedUtxo>,
}

#[derive(Clone, Debug)]
pub enum MinerToMain {
    NewBlockFound(NewBlockFound),
}

#[derive(Clone, Debug)]
pub struct MainToPeerTaskBatchBlockRequest {
    /// The peer to whom this request should be directed.
    pub(crate) peer_addr_target: SocketAddr,

    /// Sorted list of most preferred blocks. The first digest is the block
    /// that the we would prefer to build on top off, if it belongs to the
    /// canonical chain.
    pub(crate) known_blocks: Vec<Digest>,
}

#[derive(Clone, Debug)]
pub(crate) enum MainToPeerTask {
    Block(Box<Block>),
    RequestBlockBatch(MainToPeerTaskBatchBlockRequest),
    PeerSynchronizationTimeout(SocketAddr), // sanction a peer for failing to respond to sync request
    MakePeerDiscoveryRequest,               // Request peer list from connected peers
    MakeSpecificPeerDiscoveryRequest(SocketAddr), // Request peers from a specific peer to get peers further away
    TransactionNotification(TransactionNotification), // Publish knowledge of a transaction
    Disconnect(SocketAddr),                       // Disconnect from a specific peer
    DisconnectAll(),                              // Disconnect from all peers
}

impl MainToPeerTask {
    pub fn get_type(&self) -> String {
        match self {
            MainToPeerTask::Block(_) => "block".to_string(),
            MainToPeerTask::RequestBlockBatch(_) => "req block batch".to_string(),
            MainToPeerTask::PeerSynchronizationTimeout(_) => "peer sync timeout".to_string(),
            MainToPeerTask::MakePeerDiscoveryRequest => "make peer discovery req".to_string(),
            MainToPeerTask::MakeSpecificPeerDiscoveryRequest(_) => {
                "make specific peer discovery req".to_string()
            }
            MainToPeerTask::TransactionNotification(_) => "transaction notification".to_string(),
            MainToPeerTask::Disconnect(_) => "disconnect".to_string(),
            MainToPeerTask::DisconnectAll() => "disconnect all".to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum PeerTaskToMain {
    NewBlocks(Vec<Block>),
    AddPeerMaxBlockHeight((SocketAddr, BlockHeight, ProofOfWork)),
    RemovePeerMaxBlockHeight(SocketAddr),
    PeerDiscoveryAnswer((Vec<(SocketAddr, u128)>, SocketAddr, u8)), // ([(peer_listen_address)], reported_by, distance)
    Transaction(Box<PeerTaskToMainTransaction>),
}

#[derive(Clone, Debug)]
pub struct PeerTaskToMainTransaction {
    pub transaction: Transaction,
    pub confirmable_for_block: Digest,
}

impl PeerTaskToMain {
    pub fn get_type(&self) -> String {
        match self {
            PeerTaskToMain::NewBlocks(_) => "new blocks".to_string(),
            PeerTaskToMain::AddPeerMaxBlockHeight(_) => "add peer max block height".to_string(),
            PeerTaskToMain::RemovePeerMaxBlockHeight(_) => {
                "remove peer max block height".to_string()
            }
            PeerTaskToMain::PeerDiscoveryAnswer(_) => "peer discovery answer".to_string(),
            PeerTaskToMain::Transaction(_) => "transaction".to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum RPCServerToMain {
    BroadcastTx(Box<Transaction>),
    Shutdown,
    PauseMiner,
    RestartMiner,
}

impl RPCServerToMain {
    pub fn get_type(&self) -> String {
        match self {
            RPCServerToMain::BroadcastTx(_) => "broadcast transaction".to_string(),
            RPCServerToMain::Shutdown => "shutdown".to_string(),
            RPCServerToMain::PauseMiner => "pause miner".to_owned(),
            RPCServerToMain::RestartMiner => "restart miner".to_owned(),
        }
    }
}
