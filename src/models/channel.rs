use std::net::SocketAddr;
use std::sync::Arc;

use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::Digest;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

use super::blockchain::block::block_height::BlockHeight;
use super::blockchain::block::difficulty_control::ProofOfWork;
use super::blockchain::block::Block;
use super::blockchain::transaction::Transaction;
use super::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use super::peer::transaction_notification::TransactionNotification;
use super::proof_abstractions::mast_hash::MastHash;
use super::state::mining_status::MiningStatus;
use super::state::wallet::expected_utxo::ExpectedUtxo;
use super::state::wallet::monitored_utxo::MonitoredUtxo;

#[derive(Clone, Debug)]
pub(crate) enum MainToMiner {
    /// Communicates that a new block is now considered canonical
    NewBlock,

    Shutdown,

    /// Communicates to miner that it should work on a new block proposal
    NewBlockProposal(Arc<Block>),

    /// Main has received a new block or block proposal, and the miner should
    /// stop all work until it receives a [MainToMiner::Continue] message.
    WaitForContinue,

    /// Used to communicate that main loop has received the block or block
    /// proposal from the miner, and that miner can start a new task.
    Continue,

    PauseByRpc,
    UnPauseByRpc,

    PauseBySyncBlocks,
    UnPauseBySyncBlocks,

    PauseByNeedConnection,
    UnPauseByNeedConnection,
}

impl MainToMiner {
    pub(crate) fn get_type(&self) -> &str {
        match self {
            MainToMiner::NewBlock => "new block",
            MainToMiner::Shutdown => "shutdown",
            MainToMiner::NewBlockProposal(_) => "new block proposal",
            MainToMiner::WaitForContinue => "wait for continue",
            MainToMiner::Continue => "continue",
            MainToMiner::PauseByRpc => "pause mining (rpc)",
            MainToMiner::UnPauseByRpc => "unpause mining (rpc)",
            MainToMiner::PauseBySyncBlocks => "pause mining (syncing blocks)",
            MainToMiner::UnPauseBySyncBlocks => "unpause mining (synced blocks)",
            MainToMiner::PauseByNeedConnection => "pause mining (need connection)",
            MainToMiner::UnPauseByNeedConnection => "unpause mining (got connection)",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct NewBlockFound {
    pub block: Arc<Block>,
}

#[derive(Clone, Debug)]
pub(crate) enum MinerToMain {
    NewBlockFound(NewBlockFound),
    BlockProposal(Box<(Block, Vec<ExpectedUtxo>)>),

    StatusChange(MiningStatus),

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

#[derive(Clone, Debug)]
pub(crate) enum MainToPeerTask {
    Block(Arc<Block>),
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
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

    ConnectionCountChange {
        old_count: usize,
        new_count: usize,
    },

    /// (\[(peer_listen_address)\], reported_by, distance)
    PeerDiscoveryAnswer((Vec<(SocketAddr, u128)>, SocketAddr, u8)),

    Transaction(Box<PeerTaskToMainTransaction>),
    BlockProposal(Arc<Block>),
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
            PeerTaskToMain::ConnectionCountChange { .. } => "connection count change",
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

#[derive(Clone, Debug)]
pub(crate) enum RPCServerToMain {
    BroadcastTx(Box<Transaction>),
    Shutdown,
    MinerPauseByRpc,
    MinerUnPauseByRpc,
}
