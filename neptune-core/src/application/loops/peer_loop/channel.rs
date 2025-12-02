use crate::application::loops::channel::BlockProposalNotification;
use crate::protocol::consensus::block::difficulty_control::ProofOfWork;
use crate::protocol::peer::transaction_notification::TransactionNotification;

use std::net::SocketAddr;

use tasm_lib::triton_vm::prelude::Digest;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::transaction::Transaction;

#[derive(Clone, Debug, strum::Display)]
pub(crate) enum MainToPeerTask {
    Block(Box<Block>),
    BlockProposalNotification(BlockProposalNotification),
    RequestBlockByHeight {
        peer_addr_target: SocketAddr,
        height: BlockHeight,
    },
    RequestBlockNotification,

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
            MainToPeerTask::RequestBlockByHeight { .. } => "req block by height",
            MainToPeerTask::PeerSynchronizationTimeout(_) => "peer sync timeout",
            MainToPeerTask::MakePeerDiscoveryRequest => "make peer discovery req",
            MainToPeerTask::MakeSpecificPeerDiscoveryRequest(_) => {
                "make specific peer discovery req"
            }
            MainToPeerTask::TransactionNotification(_) => "transaction notification",
            MainToPeerTask::Disconnect(_) => "disconnect",
            MainToPeerTask::DisconnectAll() => "disconnect all",
            MainToPeerTask::BlockProposalNotification(_) => "block proposal notification",
            MainToPeerTask::RequestBlockNotification => "request for block notification",
        }
        .to_string()
    }

    /// Function to filter out messages that should be ignored when all state
    /// updates have been paused.
    pub(crate) fn ignore_on_freeze(&self) -> bool {
        match self {
            MainToPeerTask::Block(_) => true,
            MainToPeerTask::BlockProposalNotification(_) => true,
            MainToPeerTask::RequestBlockByHeight { .. } => true,
            MainToPeerTask::PeerSynchronizationTimeout(_) => true,
            MainToPeerTask::MakePeerDiscoveryRequest => false,
            MainToPeerTask::MakeSpecificPeerDiscoveryRequest(_) => false,
            MainToPeerTask::TransactionNotification(_) => true,
            MainToPeerTask::Disconnect(_) => false,
            MainToPeerTask::DisconnectAll() => false,
            MainToPeerTask::RequestBlockNotification => false,
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
        claimed_block_digest: Digest,
    },

    /// (\[(peer_listen_address)\], reported_by, distance)
    PeerDiscoveryAnswer((Vec<(SocketAddr, u128)>, SocketAddr, u8)),

    Transaction(Box<PeerTaskToMainTransaction>),
    BlockProposal(Box<Block>),
    DisconnectFromLongestLivedPeer,
    NewSyncTarget(Box<Block>),
    NewSyncBlock(Box<Block>, SocketAddr),
    NewPeer(SocketAddr),
    DroppedPeer(SocketAddr),
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
            PeerTaskToMain::PeerDiscoveryAnswer(_) => "peer discovery answer",
            PeerTaskToMain::Transaction(_) => "transaction",
            PeerTaskToMain::BlockProposal(_) => "block proposal",
            PeerTaskToMain::DisconnectFromLongestLivedPeer => "disconnect from longest lived peer",
            PeerTaskToMain::NewSyncTarget(_block) => "new sync target",
            PeerTaskToMain::NewSyncBlock(_block, _socket_addr) => "new sync block",
            PeerTaskToMain::NewPeer(_) => "new peer",
            PeerTaskToMain::DroppedPeer(_) => "dropped peer",
        }
        .to_string()
    }
}
