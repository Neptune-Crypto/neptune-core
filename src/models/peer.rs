use crate::prelude::twenty_first;

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::SystemTime;
use twenty_first::shared_math::digest::Digest;

use twenty_first::amount::u32s::U32s;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

use super::blockchain::block::block_header::{BlockHeader, PROOF_OF_WORK_COUNT_U32_SIZE};
use super::blockchain::block::block_height::BlockHeight;
use super::blockchain::block::transfer_block::TransferBlock;
use super::blockchain::block::Block;
use super::blockchain::shared::Hash;
use super::blockchain::transaction::Transaction;
use crate::config_models::network::Network;

// PeerSanctionReason score modifiers.
//
// These represent how much a given `PeerSanctionReason` variant
// will subtract from a `PeerStanding` score.  (higher is worse)
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
pub(crate) const CONNECT_FAILED: u16 = 25;

// PeerUnsanctionReason score modifiers.
//
// These represent how much a given `PeerUnsanctionReason` variant
// will add to a `PeerStanding` score. (higher is better)
pub(crate) const CONNECT_SUCCESS: u16 = CONNECT_FAILED; // should always match CONNECT_FAILED

/// Globally unique identifier for our Node.  (and each Peer)
pub type InstanceId = u128;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PeerInfo {
    pub port_for_incoming_connections: Option<u16>,
    pub connected_address: SocketAddr,
    pub instance_id: InstanceId,
    pub inbound: bool,
    pub last_seen: SystemTime,
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

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, strum::Display)]
pub enum PeerSanctionReason {
    #[strum(to_string = "invalid block")]
    InvalidBlock((BlockHeight, Digest)),

    #[strum(to_string = "different genesis")]
    DifferentGenesis,

    #[strum(to_string = "fork resolution error")]
    ForkResolutionError((BlockHeight, u16, Digest)),

    #[strum(to_string = "synchronization timeout")]
    SynchronizationTimeout,

    #[strum(to_string = "flood peer list response")]
    FloodPeerListResponse,

    #[strum(to_string = "block request unknown height")]
    BlockRequestUnknownHeight,

    // Be careful about using this too much as it's bad for log opportunities
    #[strum(to_string = "invalid message")]
    InvalidMessage,

    #[strum(to_string = "non mined transaction has coinbase")]
    NonMinedTransactionHasCoinbase,

    #[strum(to_string = "too short block batch")]
    TooShortBlockBatch,

    #[strum(to_string = "received block batch outside of sync")]
    ReceivedBatchBlocksOutsideOfSync,

    #[strum(to_string = "invalid start height of batch blocks")]
    BatchBlocksInvalidStartHeight,

    #[strum(to_string = "batch blocks unkonwn request")]
    BatchBlocksUnknownRequest,

    #[strum(to_string = "invalid transaction")]
    InvalidTransaction,

    #[strum(to_string = "unconfirmable transaction")]
    UnconfirmableTransaction,

    #[strum(to_string = "connect failed")]
    ConnectFailed,

    #[strum(to_string = "No standing found in map. Did peer thread crash?")]
    NoStandingFoundMaybeCrash,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, strum::Display)]
pub enum PeerUnsanctionReason {
    #[strum(to_string = "connect success")]
    ConnectSuccess, // reciprocal of PeerSanctionReason::ConnectFailed.
}

impl PeerUnsanctionReason {
    pub fn as_severity(&self) -> u16 {
        match self {
            Self::ConnectSuccess => CONNECT_SUCCESS,
        }
    }
}

/// Used by main thread to manage synchronizations/catch-up. Main thread has
/// a value of this type for each connected peer.

#[derive(Debug, Clone, Copy)]
pub struct PeerSynchronizationState {
    pub claimed_max_height: BlockHeight,
    pub claimed_max_pow_family: U32s<PROOF_OF_WORK_COUNT_U32_SIZE>,
    pub synchronization_start: SystemTime,
    pub last_request_received: Option<SystemTime>,
}

impl PeerSynchronizationState {
    pub fn new(
        claimed_max_height: BlockHeight,
        claimed_max_pow_family: U32s<PROOF_OF_WORK_COUNT_U32_SIZE>,
    ) -> Self {
        Self {
            claimed_max_height,
            claimed_max_pow_family,
            synchronization_start: SystemTime::now(),
            last_request_received: None,
        }
    }
}

impl PeerSanctionReason {
    pub fn as_severity(&self) -> u16 {
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
            PeerSanctionReason::ConnectFailed => CONNECT_FAILED,
            PeerSanctionReason::NonMinedTransactionHasCoinbase => INVALID_TRANSACTION,
            PeerSanctionReason::NoStandingFoundMaybeCrash => NO_STANDING_FOUND_MAYBE_CRASH,
        }
    }
}

/// This object gets stored in the database to record how well a peer
/// identified by SocketAddr behaves. A higher score is better.
///
/// The default starting score for a peer is presently 0, but API users should
/// use [default_score()](Self::default_score()) in case that ever changes.
///
/// The score can be increased by calling [unsanction()](Self::unsanction()) or
/// decreased by calling [sanction()](Self::sanction()).
///
/// note that Peers are not banned in this model. That is a higher level
/// concept that requires additional application state.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub struct PeerStanding {
    pub score: i32,
    pub latest_sanction: Option<PeerSanctionReason>,
    pub timestamp_of_latest_sanction: Option<SystemTime>,
}

impl PeerStanding {
    /// Sanction peer and return latest standing score
    ///
    /// `min_score` represents the minimum possible score.  So the new score will
    /// be `max(min_score, newly_calculated_score)`
    pub fn sanction(&mut self, reason: PeerSanctionReason, min_score: i32) -> i32 {
        let new_score = self.score.saturating_sub(reason.as_severity().into());

        self.score = match new_score >= min_score {
            true => new_score,
            false => min_score,
        };

        self.latest_sanction = Some(reason);
        self.timestamp_of_latest_sanction = Some(SystemTime::now());
        self.score
    }

    /// Un-Sanction peer and return latest standing score
    ///
    /// `max_score` represents the maximum possible score.  So the new score will
    /// be `min(max_score, newly_calculated_score)`
    pub fn unsanction(&mut self, reason: PeerUnsanctionReason, max_score: i32) -> i32 {
        let new_score = self.score.saturating_add(reason.as_severity().into());

        self.score = match new_score <= max_score {
            true => new_score,
            false => max_score,
        };

        self.score
    }

    /// returns the default (starting) score for a new/unknown peer.
    pub fn default_score() -> i32 {
        Default::default()
    }

    /// Clear peer standing record
    pub fn clear_standing(&mut self) {
        *self = PeerStanding::default();
    }

    /// Indicates if the standing score is in the negative.
    pub fn is_negative(&self) -> bool {
        self.score.is_negative()
    }

    pub fn new_on_no_standing_found_in_map() -> Self {
        Self {
            score: -(NO_STANDING_FOUND_MAYBE_CRASH as i32),
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

/// Used to tell peers that a new block has been found without having toPeerMessage
/// send the entire block
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerBlockNotification {
    pub hash: Digest,
    pub height: BlockHeight,
    pub proof_of_work_family: U32s<PROOF_OF_WORK_COUNT_U32_SIZE>,
}

impl From<&Block> for PeerBlockNotification {
    fn from(block: &Block) -> Self {
        PeerBlockNotification {
            hash: block.hash(),
            height: block.kernel.header.height,
            proof_of_work_family: block.kernel.header.proof_of_work_family,
        }
    }
}

impl From<Block> for PeerBlockNotification {
    fn from(block: Block) -> Self {
        PeerBlockNotification {
            hash: block.hash(),
            height: block.kernel.header.height,
            proof_of_work_family: block.kernel.header.proof_of_work_family,
        }
    }
}

impl From<&BlockHeader> for PeerBlockNotification {
    fn from(value: &BlockHeader) -> Self {
        PeerBlockNotification {
            hash: Hash::hash(value),
            height: value.height,
            proof_of_work_family: value.proof_of_work_family,
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

/// A sender broadcasts to all peers a `TransactionNotification` when it has
/// received a transaction with the given `TransactionId`.  It is implied
/// that interested peers can request the full transaction object from this
/// sender.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionNotification {
    pub transaction_digest: Digest,
    // TODO: Consider adding `timestamp` here
    // pub timestamp: SystemTime,
}

impl From<Transaction> for TransactionNotification {
    fn from(transaction: Transaction) -> Self {
        let transaction_digest = Hash::hash(&transaction);

        Self { transaction_digest }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PeerMessage {
    Handshake(Box<(Vec<u8>, HandshakeData)>),
    Block(Box<TransferBlock>),
    BlockNotificationRequest,
    BlockNotification(PeerBlockNotification),
    BlockRequestByHeight(BlockHeight),
    BlockRequestByHash(Digest),
    BlockRequestBatch(Vec<Digest>, usize), // TODO: Consider restricting this in size
    BlockResponseBatch(Vec<TransferBlock>), // TODO: Consider restricting this in size
    /// Send a full transaction object to a peer.
    Transaction(Box<Transaction>),
    /// Send a notification to a peer, informing it that this node stores the
    /// transaction with digest and timestamp specified in
    /// `TransactionNotification`.
    TransactionNotification(TransactionNotification),
    /// Send a request that this node would like a copy of the transaction with
    /// digest as specified by the argument.
    TransactionRequest(Digest),
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
            PeerMessage::Handshake(_) => "handshake".to_string(),
            PeerMessage::Block(_) => "block".to_string(),
            PeerMessage::BlockNotificationRequest => "block notification request".to_string(),
            PeerMessage::BlockNotification(_) => "block notification".to_string(),
            PeerMessage::BlockRequestByHeight(_) => "block req by height".to_string(),
            PeerMessage::BlockRequestByHash(_) => "block req by hash".to_string(),
            PeerMessage::BlockRequestBatch(_, _) => "block req batch".to_string(),
            PeerMessage::BlockResponseBatch(_) => "block resp batch".to_string(),
            PeerMessage::Transaction(_) => "send".to_string(),
            PeerMessage::TransactionNotification(_) => "transaction notification".to_string(),
            PeerMessage::TransactionRequest(_) => "transaction request".to_string(),
            PeerMessage::PeerListRequest => "peer list req".to_string(),
            PeerMessage::PeerListResponse(_) => "peer list resp".to_string(),
            PeerMessage::Bye => "bye".to_string(),
            PeerMessage::ConnectionStatus(_) => "connection status".to_string(),
        }
    }

    pub fn ignore_when_not_sync(&self) -> bool {
        match self {
            PeerMessage::Handshake(_) => false,
            PeerMessage::Block(_) => false,
            PeerMessage::BlockNotificationRequest => false,
            PeerMessage::BlockNotification(_) => false,
            PeerMessage::BlockRequestByHeight(_) => false,
            PeerMessage::BlockRequestByHash(_) => false,
            PeerMessage::BlockRequestBatch(_, _) => false,
            PeerMessage::BlockResponseBatch(_) => true,
            PeerMessage::Transaction(_) => false,
            PeerMessage::TransactionNotification(_) => false,
            PeerMessage::TransactionRequest(_) => false,
            PeerMessage::PeerListRequest => false,
            PeerMessage::PeerListResponse(_) => false,
            PeerMessage::Bye => false,
            PeerMessage::ConnectionStatus(_) => false,
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
            PeerMessage::BlockRequestBatch(_, _) => false,
            PeerMessage::BlockResponseBatch(_) => false,
            PeerMessage::Transaction(_) => true,
            PeerMessage::TransactionNotification(_) => false,
            PeerMessage::TransactionRequest(_) => false,
            PeerMessage::PeerListRequest => false,
            PeerMessage::PeerListResponse(_) => false,
            PeerMessage::Bye => false,
            PeerMessage::ConnectionStatus(_) => false,
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
