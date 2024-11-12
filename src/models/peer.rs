pub mod transaction_notification;
pub mod transfer_block;
pub mod transfer_transaction;

use std::fmt::Display;
use std::net::SocketAddr;
use std::time::SystemTime;

use serde::Deserialize;
use serde::Serialize;
use transaction_notification::TransactionNotification;
use transfer_transaction::TransferTransaction;
use twenty_first::math::digest::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

use super::blockchain::block::block_header::BlockHeader;
use super::blockchain::block::block_height::BlockHeight;
use super::blockchain::block::difficulty_control::ProofOfWork;
use super::blockchain::block::Block;
use super::blockchain::shared::Hash;
use super::channel::BlockProposalNotification;
use super::state::transaction_kernel_id::TransactionKernelId;
use crate::config_models::network::Network;
use crate::models::peer::transfer_block::TransferBlock;
use crate::prelude::twenty_first;

const BAD_BLOCK_BATCH_REQUEST_SEVERITY: u16 = 10;
const INVALID_BLOCK_SEVERITY: u16 = 10;
const DIFFERENT_GENESIS_SEVERITY: u16 = u16::MAX;
const SYNCHRONIZATION_TIMEOUT_SEVERITY: u16 = 5;
const FLOODED_PEER_LIST_RESPONSE_SEVERITY: u16 = 2;
const FORK_RESOLUTION_ERROR_SEVERITY_PER_BLOCK: u16 = 3;
const INVALID_MESSAGE_SEVERITY: u16 = 2;
const UNKNOWN_BLOCK_HEIGHT: u16 = 1;
const INVALID_TRANSACTION: u16 = 10;
const UNCONFIRMABLE_TRANSACTION: u16 = 2;
const NO_STANDING_FOUND_MAYBE_CRASH: u16 = 10;
const BLOCK_PROPOSAL_NOT_FOUND_SEVERITY: u16 = 1;
const UNWANTED_MESSAGE_SEVERITY: u16 = 1;

pub type InstanceId = u128;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PeerInfo {
    pub port_for_incoming_connections: Option<u16>,
    pub connected_address: SocketAddr,
    pub instance_id: InstanceId,
    pub inbound: bool,
    pub connection_established: SystemTime,
    pub standing: PeerStanding,
    pub version: String,
    pub is_archival_node: bool,
}

impl PeerInfo {
    /// Return the socket address that the peer is expected to listen on. Returns `None` if peer does not accept
    /// incoming connections.
    pub fn listen_address(&self) -> Option<SocketAddr> {
        self.port_for_incoming_connections
            .map(|port| SocketAddr::new(self.connected_address.ip(), port))
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PeerSanctionReason {
    InvalidBlock((BlockHeight, Digest)),
    DifferentGenesis,
    ForkResolutionError((BlockHeight, u16, Digest)),
    SynchronizationTimeout,
    FloodPeerListResponse,
    BlockRequestUnknownHeight,
    // Be careful about using this too much as it's bad for log opportunities
    InvalidMessage,
    NonMinedTransactionHasCoinbase,
    TooShortBlockBatch,
    ReceivedBatchBlocksOutsideOfSync,
    BatchBlocksInvalidStartHeight,
    BatchBlocksUnknownRequest,
    InvalidTransaction,
    UnconfirmableTransaction,

    BlockProposalNotFound,
    InvalidBlockProposal,
    NonFavorableBlockProposal,

    UnwantedMessage,

    NoStandingFoundMaybeCrash,
}

impl Display for PeerSanctionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = match self {
            PeerSanctionReason::InvalidBlock(_) => "invalid block",
            PeerSanctionReason::DifferentGenesis => "different genesis",
            PeerSanctionReason::ForkResolutionError(_) => "fork resolution error",
            PeerSanctionReason::SynchronizationTimeout => "synchronization timeout",
            PeerSanctionReason::FloodPeerListResponse => "flood peer list response",
            PeerSanctionReason::BlockRequestUnknownHeight => "block request unknown height",
            PeerSanctionReason::InvalidMessage => "invalid message",
            PeerSanctionReason::TooShortBlockBatch => "too short block batch",
            PeerSanctionReason::ReceivedBatchBlocksOutsideOfSync => {
                "received block batch outside of sync"
            }
            PeerSanctionReason::BatchBlocksInvalidStartHeight => {
                "invalid start height of batch blocks"
            }
            PeerSanctionReason::BatchBlocksUnknownRequest => "batch blocks unkonwn request",
            PeerSanctionReason::InvalidTransaction => "invalid transaction",
            PeerSanctionReason::UnconfirmableTransaction => "unconfirmable transaction",
            PeerSanctionReason::NonMinedTransactionHasCoinbase => {
                "non-mined transaction has coinbase"
            }
            PeerSanctionReason::NoStandingFoundMaybeCrash => {
                "No standing found in map. Did peer task crash?"
            }
            PeerSanctionReason::BlockProposalNotFound => "Block proposal not found",
            PeerSanctionReason::InvalidBlockProposal => "Invalid block proposal",
            PeerSanctionReason::UnwantedMessage => "unwanted message",
            PeerSanctionReason::NonFavorableBlockProposal => "non-favorable block proposal",
        };
        write!(f, "{string}")
    }
}

/// Used by main task to manage synchronizations/catch-up. Main task has
/// a value of this type for each connected peer.

#[derive(Debug, Clone, Copy)]
pub struct PeerSynchronizationState {
    pub claimed_max_height: BlockHeight,
    pub(crate) claimed_max_pow: ProofOfWork,
    pub synchronization_start: SystemTime,
    pub last_request_received: Option<SystemTime>,
}

impl PeerSynchronizationState {
    pub(crate) fn new(claimed_max_height: BlockHeight, claimed_max_pow: ProofOfWork) -> Self {
        Self {
            claimed_max_height,
            claimed_max_pow,
            synchronization_start: SystemTime::now(),
            last_request_received: None,
        }
    }
}

impl PeerSanctionReason {
    pub fn to_severity(self) -> u16 {
        match self {
            PeerSanctionReason::InvalidBlock(_) => INVALID_BLOCK_SEVERITY,
            PeerSanctionReason::DifferentGenesis => DIFFERENT_GENESIS_SEVERITY,
            PeerSanctionReason::ForkResolutionError((_height, count, _digest)) => {
                FORK_RESOLUTION_ERROR_SEVERITY_PER_BLOCK * count
            }
            PeerSanctionReason::SynchronizationTimeout => SYNCHRONIZATION_TIMEOUT_SEVERITY,
            PeerSanctionReason::FloodPeerListResponse => FLOODED_PEER_LIST_RESPONSE_SEVERITY,
            PeerSanctionReason::InvalidMessage => INVALID_MESSAGE_SEVERITY,
            PeerSanctionReason::TooShortBlockBatch => INVALID_MESSAGE_SEVERITY,
            PeerSanctionReason::ReceivedBatchBlocksOutsideOfSync => INVALID_MESSAGE_SEVERITY,
            PeerSanctionReason::BatchBlocksInvalidStartHeight => INVALID_MESSAGE_SEVERITY,
            PeerSanctionReason::BatchBlocksUnknownRequest => BAD_BLOCK_BATCH_REQUEST_SEVERITY,
            PeerSanctionReason::BlockRequestUnknownHeight => UNKNOWN_BLOCK_HEIGHT,
            PeerSanctionReason::InvalidTransaction => INVALID_TRANSACTION,
            PeerSanctionReason::UnconfirmableTransaction => UNCONFIRMABLE_TRANSACTION,
            PeerSanctionReason::NonMinedTransactionHasCoinbase => INVALID_TRANSACTION,
            PeerSanctionReason::NoStandingFoundMaybeCrash => NO_STANDING_FOUND_MAYBE_CRASH,
            PeerSanctionReason::BlockProposalNotFound => BLOCK_PROPOSAL_NOT_FOUND_SEVERITY,
            PeerSanctionReason::InvalidBlockProposal => INVALID_BLOCK_SEVERITY,
            PeerSanctionReason::UnwantedMessage => UNWANTED_MESSAGE_SEVERITY,
            PeerSanctionReason::NonFavorableBlockProposal => UNWANTED_MESSAGE_SEVERITY,
        }
    }
}

/// This is object that gets stored in the database to record how well a peer
/// at a certain IP behaves. A lower number is better.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub struct PeerStanding {
    pub standing: i32,
    pub latest_sanction: Option<PeerSanctionReason>,
    pub timestamp_of_latest_sanction: Option<SystemTime>,
}

impl PeerStanding {
    /// Sanction peer and return latest standing score
    pub fn sanction(&mut self, reason: PeerSanctionReason) -> i32 {
        self.standing = self.standing.saturating_sub(reason.to_severity().into());
        self.latest_sanction = Some(reason);
        self.timestamp_of_latest_sanction = Some(SystemTime::now());
        self.standing
    }

    /// Clear peer standing record
    pub fn clear_standing(&mut self) {
        *self = PeerStanding::default();
    }

    pub fn is_negative(&self) -> bool {
        self.standing.is_negative()
    }

    pub fn new_on_no_standing_found_in_map() -> Self {
        Self {
            standing: -(NO_STANDING_FOUND_MAYBE_CRASH as i32),
            latest_sanction: Some(PeerSanctionReason::NoStandingFoundMaybeCrash),
            timestamp_of_latest_sanction: Some(SystemTime::now()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandshakeData {
    pub tip_header: BlockHeader,
    pub listen_port: Option<u16>,
    pub network: Network,
    pub instance_id: u128,
    pub version: String,
    pub is_archival_node: bool,
}

/// Used to tell peers that a new block has been found without having to
/// send the entire block
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerBlockNotification {
    pub hash: Digest,
    pub height: BlockHeight,
    pub(crate) cumulative_proof_of_work: ProofOfWork,
}

impl From<&Block> for PeerBlockNotification {
    fn from(block: &Block) -> Self {
        PeerBlockNotification {
            hash: block.hash(),
            height: block.kernel.header.height,
            cumulative_proof_of_work: block.kernel.header.cumulative_proof_of_work,
        }
    }
}

impl From<Block> for PeerBlockNotification {
    fn from(block: Block) -> Self {
        PeerBlockNotification {
            hash: block.hash(),
            height: block.kernel.header.height,
            cumulative_proof_of_work: block.kernel.header.cumulative_proof_of_work,
        }
    }
}

impl From<&BlockHeader> for PeerBlockNotification {
    fn from(value: &BlockHeader) -> Self {
        PeerBlockNotification {
            hash: Hash::hash(value),
            height: value.height,
            cumulative_proof_of_work: value.cumulative_proof_of_work,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConnectionRefusedReason {
    AlreadyConnected,
    BadStanding,
    IncompatibleVersion,
    MaxPeerNumberExceeded,
    SelfConnect,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConnectionStatus {
    Refused(ConnectionRefusedReason),
    Accepted,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockRequestBatch {
    /// Sorted list of most preferred blocks. The first digest is the block
    /// that the peer would prefer to build on top off, if it belongs to the
    /// canonical chain.
    pub(crate) known_blocks: Vec<Digest>,

    /// Indicates the maximum allowed number of blocks in the response.
    pub(crate) max_response_len: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct BlockProposalRequest {
    pub(crate) body_mast_hash: Digest,
}

impl BlockProposalRequest {
    pub(crate) fn new(body_mast_hash: Digest) -> Self {
        Self { body_mast_hash }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum PeerMessage {
    Handshake(Box<(Vec<u8>, HandshakeData)>),
    Block(Box<TransferBlock>),
    BlockNotificationRequest,
    BlockNotification(PeerBlockNotification),
    BlockRequestByHeight(BlockHeight),
    BlockRequestByHash(Digest),

    /// A list of block digests containing the
    BlockRequestBatch(BlockRequestBatch), // TODO: Consider restricting this in size
    BlockResponseBatch(Vec<TransferBlock>), // TODO: Consider restricting this in size

    BlockProposalNotification(BlockProposalNotification),

    BlockProposalRequest(BlockProposalRequest),

    BlockProposal(Box<Block>),

    /// Send a full transaction object to a peer.
    Transaction(Box<TransferTransaction>),
    /// Send a notification to a peer, informing it that this node stores the
    /// transaction with digest and timestamp specified in
    /// `TransactionNotification`.
    TransactionNotification(TransactionNotification),
    /// Send a request that this node would like a copy of the transaction with
    /// digest as specified by the argument.
    TransactionRequest(TransactionKernelId),
    PeerListRequest,
    /// (socket address, instance_id)
    PeerListResponse(Vec<(SocketAddr, u128)>),
    /// Inform peer that we are disconnecting them.
    Bye,
    ConnectionStatus(ConnectionStatus),
}

impl PeerMessage {
    pub fn get_type(&self) -> String {
        match self {
            PeerMessage::Handshake(_) => "handshake",
            PeerMessage::Block(_) => "block",
            PeerMessage::BlockNotificationRequest => "block notification request",
            PeerMessage::BlockNotification(_) => "block notification",
            PeerMessage::BlockRequestByHeight(_) => "block req by height",
            PeerMessage::BlockRequestByHash(_) => "block req by hash",
            PeerMessage::BlockRequestBatch(_) => "block req batch",
            PeerMessage::BlockResponseBatch(_) => "block resp batch",
            PeerMessage::Transaction(_) => "send",
            PeerMessage::TransactionNotification(_) => "transaction notification",
            PeerMessage::TransactionRequest(_) => "transaction request",
            PeerMessage::PeerListRequest => "peer list req",
            PeerMessage::PeerListResponse(_) => "peer list resp",
            PeerMessage::Bye => "bye",
            PeerMessage::ConnectionStatus(_) => "connection status",
            PeerMessage::BlockProposalNotification(_) => "block proposal notification",
            PeerMessage::BlockProposalRequest(_) => "block proposal request",
            PeerMessage::BlockProposal(_) => "block proposal",
        }
        .to_string()
    }

    pub fn ignore_when_not_sync(&self) -> bool {
        match self {
            PeerMessage::Handshake(_) => false,
            PeerMessage::Block(_) => false,
            PeerMessage::BlockNotificationRequest => false,
            PeerMessage::BlockNotification(_) => false,
            PeerMessage::BlockRequestByHeight(_) => false,
            PeerMessage::BlockRequestByHash(_) => false,
            PeerMessage::BlockRequestBatch(_) => false,
            PeerMessage::BlockResponseBatch(_) => true,
            PeerMessage::Transaction(_) => false,
            PeerMessage::TransactionNotification(_) => false,
            PeerMessage::TransactionRequest(_) => false,
            PeerMessage::PeerListRequest => false,
            PeerMessage::PeerListResponse(_) => false,
            PeerMessage::Bye => false,
            PeerMessage::ConnectionStatus(_) => false,
            PeerMessage::BlockProposalNotification(_) => false,
            PeerMessage::BlockProposalRequest(_) => false,
            PeerMessage::BlockProposal(_) => false,
        }
    }

    /// Function to filter out messages that should not be handled while the client is syncing
    pub fn ignore_during_sync(&self) -> bool {
        match self {
            PeerMessage::Handshake(_) => false,
            PeerMessage::Block(_) => true,
            PeerMessage::BlockNotificationRequest => false,
            PeerMessage::BlockNotification(_) => false,
            PeerMessage::BlockRequestByHeight(_) => false,
            PeerMessage::BlockRequestByHash(_) => false,
            PeerMessage::BlockRequestBatch(_) => false,
            PeerMessage::BlockResponseBatch(_) => false,
            PeerMessage::Transaction(_) => true,
            PeerMessage::TransactionNotification(_) => false,
            PeerMessage::TransactionRequest(_) => false,
            PeerMessage::PeerListRequest => false,
            PeerMessage::PeerListResponse(_) => false,
            PeerMessage::Bye => false,
            PeerMessage::ConnectionStatus(_) => false,
            PeerMessage::BlockProposalNotification(_) => true,
            PeerMessage::BlockProposalRequest(_) => true,
            PeerMessage::BlockProposal(_) => true,
        }
    }
}

/// `MutablePeerState` contains the part of the peer-loop's state that is mutable
#[derive(Clone, Debug)]
pub struct MutablePeerState {
    pub highest_shared_block_height: BlockHeight,
    pub fork_reconciliation_blocks: Vec<Block>,
}

impl MutablePeerState {
    pub fn new(block_height: BlockHeight) -> Self {
        Self {
            highest_shared_block_height: block_height,
            fork_reconciliation_blocks: vec![],
        }
    }
}
