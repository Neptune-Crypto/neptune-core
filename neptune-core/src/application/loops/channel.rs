use std::net::SocketAddr;
use std::sync::Arc;

use futures::channel::oneshot;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::Digest;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

use crate::application::loops::main_loop::proof_upgrader::UpgradeJob;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::difficulty_control::ProofOfWork;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::peer::transaction_notification::TransactionNotification;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::state::wallet::expected_utxo::ExpectedUtxo;
use crate::state::wallet::monitored_utxo::MonitoredUtxo;

#[derive(Clone, Debug, strum::Display)]
pub(crate) enum MainToMiner {
    /// Communicates that a new block is now considered canonical
    NewBlock,

    Shutdown,

    /// Communicates to miner that it should work on a new block proposal.
    /// This message may only be sent when the delta in guesser fees between the
    /// old proposal and the new proposal meets a threshold value.
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
            MainToMiner::NewBlock => "new block",
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
pub(crate) struct NewBlockFound {
    pub block: Box<Block>,
}

#[derive(Clone, Debug, strum::Display)]
pub(crate) enum MinerToMain {
    NewBlockFound(NewBlockFound),
    BlockProposal(Box<(Block, Vec<ExpectedUtxo>)>),

    /// Request main loop to shut down entire application and return the
    /// indicated exit code.
    Shutdown(i32),
}

#[derive(Clone, Debug)]
pub struct MainToPeerTaskBatchBlockRequest {
    /// The peer to whom this request should be directed.
    pub(crate) peer_addr_target: SocketAddr,

    /// Sorted list of most preferred blocks. The first digest is the block
    /// that we would prefer to build on top off, if it belongs to the
    /// canonical chain.
    pub(crate) known_blocks: Vec<Digest>,

    /// The block MMR accumulator relative to which incoming blocks are
    /// authenticated.
    pub(crate) anchor_mmr: MmrAccumulator,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct BlockProposalNotification {
    pub(crate) body_mast_hash: Digest,
    pub(crate) guesser_fee: NativeCurrencyAmount,
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

#[derive(Clone, Debug, strum::Display)]
pub(crate) enum MainToPeerTask {
    Block(Box<Block>),
    BlockProposalNotification(BlockProposalNotification),
    RequestBlockBatch(MainToPeerTaskBatchBlockRequest),

    /// sanction a peer for failing to respond to sync request
    PeerSynchronizationTimeout(SocketAddr),

    /// Request peer list from connected peers
    MakePeerDiscoveryRequest,

    /// Request peers from a specific peer to get peers further away
    MakeSpecificPeerDiscoveryRequest(SocketAddr),

    /// Publish knowledge of a transaction
    TransactionNotification(TransactionNotification),

    /// Disconnect from a specific peer
    Disconnect(SocketAddr),

    /// Disconnect from all peers
    DisconnectAll(),
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

    /// Function to filter out messages that should be ignored when all state
    /// updates have been paused.
    pub(crate) fn ignore_on_freeze(&self) -> bool {
        match self {
            MainToPeerTask::Block(_) => true,
            MainToPeerTask::BlockProposalNotification(_) => true,
            MainToPeerTask::RequestBlockBatch(_) => true,
            MainToPeerTask::PeerSynchronizationTimeout(_) => true,
            MainToPeerTask::MakePeerDiscoveryRequest => false,
            MainToPeerTask::MakeSpecificPeerDiscoveryRequest(_) => false,
            MainToPeerTask::TransactionNotification(_) => true,
            MainToPeerTask::Disconnect(_) => false,
            MainToPeerTask::DisconnectAll() => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, strum::Display)]
pub(crate) enum PeerTaskToMain {
    NewBlocks(Vec<Block>),
    AddPeerMaxBlockHeight {
        peer_address: SocketAddr,
        claimed_height: BlockHeight,
        claimed_cumulative_pow: ProofOfWork,

        /// The MMR *after* adding the tip hash, so not the one contained in the
        /// tip, but in its child.
        claimed_block_mmra: MmrAccumulator,
    },
    RemovePeerMaxBlockHeight(SocketAddr),

    /// (\[(peer_listen_address)\], reported_by, distance)
    PeerDiscoveryAnswer((Vec<(SocketAddr, u128)>, SocketAddr, u8)),

    Transaction(Box<PeerTaskToMainTransaction>),
    BlockProposal(Box<Block>),
    DisconnectFromLongestLivedPeer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerTaskToMainTransaction {
    pub transaction: Transaction,
    pub confirmable_for_block: Digest,
}

impl PeerTaskToMain {
    pub fn get_type(&self) -> String {
        match self {
            PeerTaskToMain::NewBlocks(_) => "new blocks",
            PeerTaskToMain::AddPeerMaxBlockHeight { .. } => "add peer max block height",
            PeerTaskToMain::RemovePeerMaxBlockHeight(_) => "remove peer max block height",
            PeerTaskToMain::PeerDiscoveryAnswer(_) => "peer discovery answer",
            PeerTaskToMain::Transaction(_) => "transaction",
            PeerTaskToMain::BlockProposal(_) => "block proposal",
            PeerTaskToMain::DisconnectFromLongestLivedPeer => "disconnect from longest lived peer",
        }
        .to_string()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ClaimUtxoData {
    /// Some(mutxo) if UTXO has already been mined. Otherwise, None.
    pub(crate) prepared_monitored_utxo: Option<MonitoredUtxo>,

    /// Indicates if wallet already expects this UTXO.
    pub(crate) has_expected_utxo: bool,

    pub(crate) expected_utxo: ExpectedUtxo,
}

/// represents messages that can be sent from RPC server to main loop.
#[derive(Clone, Debug, strum::Display)]
pub enum RPCServerToMain {
    BroadcastTx(Arc<Transaction>),
    PerformTxProofUpgrade(Box<UpgradeJob>),
    BroadcastMempoolTransactions,
    BroadcastBlockProposal,
    ClearMempool,
    ProofOfWorkSolution(Box<Block>),
    Shutdown,
    PauseMiner,
    RestartMiner,
    SetTipToStoredBlock(Digest),
}

pub trait Cancelable: Send + Sync {
    fn is_canceled(&self) -> bool;
}

impl<T: Send + Sync> Cancelable for oneshot::Sender<T> {
    fn is_canceled(&self) -> bool {
        self.is_canceled()
    }
}
