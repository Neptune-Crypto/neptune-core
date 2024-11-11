use std::net::SocketAddr;

use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::Digest;

use super::blockchain::block::block_height::BlockHeight;
use super::blockchain::block::difficulty_control::ProofOfWork;
use super::blockchain::block::Block;
use super::blockchain::transaction::Transaction;
use super::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use super::peer::transaction_notification::TransactionNotification;
use super::proof_abstractions::mast_hash::MastHash;
use super::state::wallet::expected_utxo::ExpectedUtxo;

#[derive(Clone, Debug)]
pub(crate) enum MainToMiner {
    NewBlock(Box<Block>),
    Shutdown,

    /// Communicates to miner that it should work on a new block proposal
    NewBlockProposal,

    /// Main has received a new block or block proposal, and the miner should
    /// stop all work until it receives a [MainToMiner::Continue] message.
    WaitForContinue,

    /// Used to communicate that main loop has received the block or block
    /// proposal from the miner, and that miner can start a new task.
    Continue,

    StopMining,
    StartMining,

    StartSyncing,
    StopSyncing,
    // SetCoinbasePubkey,
}

impl MainToMiner {
    pub(crate) fn get_type(&self) -> &str {
        match self {
            MainToMiner::NewBlock(_) => "new block",
            MainToMiner::Shutdown => "shutdown",
            MainToMiner::NewBlockProposal => "new block proposal",
            MainToMiner::WaitForContinue => "wait for continue",
            MainToMiner::Continue => "continue",
            MainToMiner::StopMining => "stop mining",
            MainToMiner::StartMining => "start mining",
            MainToMiner::StartSyncing => "start syncing",
            MainToMiner::StopSyncing => "stop syncing",
        }
    }
}

#[derive(Clone, Debug)]
pub struct NewBlockFound {
    pub block: Box<Block>,
    pub composer_utxos: Vec<ExpectedUtxo>,
    pub guesser_fee_utxo_infos: Vec<ExpectedUtxo>,
}

#[derive(Clone, Debug)]
pub enum MinerToMain {
    NewBlockFound(NewBlockFound),
    BlockProposal(Box<(Block, Vec<ExpectedUtxo>)>),
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct BlockProposalNotification {
    pub(crate) body_mast_hash: Digest,
    pub(crate) guesser_fee: NeptuneCoins,
    pub(crate) height: BlockHeight,
}

impl From<&Block> for BlockProposalNotification {
    fn from(value: &Block) -> Self {
        Self {
            body_mast_hash: value.body().mast_hash(),
            guesser_fee: value.body().transaction_kernel.fee,
            height: value.header().height,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum MainToPeerTask {
    Block(Box<Block>),
    BlockProposalNotification(BlockProposalNotification),
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
            MainToPeerTask::Block(_) => "block",
            MainToPeerTask::RequestBlockBatch(_) => "req block batch",
            MainToPeerTask::PeerSynchronizationTimeout(_) => "peer sync timeout",
            MainToPeerTask::MakePeerDiscoveryRequest => "make peer discovery req",
            MainToPeerTask::MakeSpecificPeerDiscoveryRequest(_) => {
                "make specific peer discovery req"
            }
            MainToPeerTask::TransactionNotification(_) => "transaction notification",
            MainToPeerTask::Disconnect(_) => "disconnect",
            MainToPeerTask::DisconnectAll() => "disconnect all",
            MainToPeerTask::BlockProposalNotification(_) => "block proposal notification",
        }
        .to_string()
    }
}

#[derive(Clone, Debug)]
pub(crate) enum PeerTaskToMain {
    NewBlocks(Vec<Block>),
    AddPeerMaxBlockHeight((SocketAddr, BlockHeight, ProofOfWork)),
    RemovePeerMaxBlockHeight(SocketAddr),
    PeerDiscoveryAnswer((Vec<(SocketAddr, u128)>, SocketAddr, u8)), // ([(peer_listen_address)], reported_by, distance)
    Transaction(Box<PeerTaskToMainTransaction>),
    BlockProposal(Box<Block>),
}

#[derive(Clone, Debug)]
pub struct PeerTaskToMainTransaction {
    pub transaction: Transaction,
    pub confirmable_for_block: Digest,
}

impl PeerTaskToMain {
    pub fn get_type(&self) -> String {
        match self {
            PeerTaskToMain::NewBlocks(_) => "new blocks",
            PeerTaskToMain::AddPeerMaxBlockHeight(_) => "add peer max block height",
            PeerTaskToMain::RemovePeerMaxBlockHeight(_) => "remove peer max block height",
            PeerTaskToMain::PeerDiscoveryAnswer(_) => "peer discovery answer",
            PeerTaskToMain::Transaction(_) => "transaction",
            PeerTaskToMain::BlockProposal(_) => "block proposal",
        }
        .to_string()
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
