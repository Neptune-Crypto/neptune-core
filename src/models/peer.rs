pub mod transaction_notification;
pub mod transfer_block;
pub mod transfer_transaction;

use std::fmt::Display;
use std::net::SocketAddr;
use std::time::SystemTime;

use serde::Deserialize;
use serde::Serialize;
use tracing::trace;
use transaction_notification::TransactionNotification;
use transfer_transaction::TransferTransaction;
use twenty_first::math::digest::Digest;


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

pub(crate) type InstanceId = u128;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) struct PeerConnectionInfo {
    port_for_incoming_connections: Option<u16>,
    connected_address: SocketAddr,
    inbound: bool,
}

impl PeerConnectionInfo {
    pub(crate) fn new(
        port_for_incoming_connections: Option<u16>,
        connected_address: SocketAddr,
        inbound: bool,
    ) -> Self {
        Self {
            port_for_incoming_connections,
            connected_address,
            inbound,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PeerInfo {
    peer_connection_info: PeerConnectionInfo,
    instance_id: InstanceId,
    connection_established: SystemTime,
    pub(crate) standing: PeerStanding,
    version: String,
    is_archival_node: bool,
}

impl PeerInfo {
    pub(crate) fn new(
        peer_connection_info: PeerConnectionInfo,
        instance_id: InstanceId,
        connection_established: SystemTime,
        version: String,
        is_archival_node: bool,
        peer_tolerance: u16,
    ) -> Self {
        assert!(peer_tolerance > 0, "Peer tolerance must be positive");
        let standing = PeerStanding::new(peer_tolerance);
        Self {
            peer_connection_info,
            instance_id,
            connection_established,
            standing,
            version,
            is_archival_node,
        }
    }

    pub(crate) fn with_standing(mut self, standing: PeerStanding) -> Self {
        self.standing = standing;
        self
    }

    pub(crate) fn instance_id(&self) -> u128 {
        self.instance_id
    }

    pub fn standing(&self) -> PeerStanding {
        self.standing
    }

    pub fn connected_address(&self) -> SocketAddr {
        self.peer_connection_info.connected_address
    }

    pub fn connection_established(&self) -> SystemTime {
        self.connection_established
    }

    pub fn is_archival_node(&self) -> bool {
        self.is_archival_node
    }

    pub(crate) fn connection_is_inbound(&self) -> bool {
        self.peer_connection_info.inbound
    }

    /// Return the socket address that the peer is expected to listen on. Returns `None` if peer does not accept
    /// incoming connections.
    pub fn listen_address(&self) -> Option<SocketAddr> {
        self.peer_connection_info
            .port_for_incoming_connections
            .map(|port| SocketAddr::new(self.peer_connection_info.connected_address.ip(), port))
    }

    #[cfg(test)]
    pub(crate) fn set_connection_established(&mut self, new_timestamp: SystemTime) {
        self.connection_established = new_timestamp;
    }
}

trait Sanction {
    fn severity(self) -> i32;
}
/// The reason for degrading a peer's standing
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum NegativePeerSanction {
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

/// The reason for improving a peer's standing
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PositivePeerSanction {
    // positive sanctions (standing-improving)
    // We only reward events that are unlikely to occur more frequently than the
    // target block frequency. This should make it impossible for an attacker
    // to quickly ramp up their standing with peers, provided that they are on
    // the global tip.
    ValidBlocks(usize),
    NewBlockProposal,
}

impl Display for NegativePeerSanction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = match self {
            NegativePeerSanction::InvalidBlock(_) => "invalid block",
            NegativePeerSanction::DifferentGenesis => "different genesis",
            NegativePeerSanction::ForkResolutionError(_) => "fork resolution error",
            NegativePeerSanction::SynchronizationTimeout => "synchronization timeout",
            NegativePeerSanction::FloodPeerListResponse => "flood peer list response",
            NegativePeerSanction::BlockRequestUnknownHeight => "block request unknown height",
            NegativePeerSanction::InvalidMessage => "invalid message",
            NegativePeerSanction::TooShortBlockBatch => "too short block batch",
            NegativePeerSanction::ReceivedBatchBlocksOutsideOfSync => {
                "received block batch outside of sync"
            }
            NegativePeerSanction::BatchBlocksInvalidStartHeight => {
                "invalid start height of batch blocks"
            }
            NegativePeerSanction::BatchBlocksUnknownRequest => "batch blocks unkonwn request",
            NegativePeerSanction::InvalidTransaction => "invalid transaction",
            NegativePeerSanction::UnconfirmableTransaction => "unconfirmable transaction",
            NegativePeerSanction::NonMinedTransactionHasCoinbase => {
                "non-mined transaction has coinbase"
            }
            NegativePeerSanction::NoStandingFoundMaybeCrash => {
                "No standing found in map. Did peer task crash?"
            }
            NegativePeerSanction::BlockProposalNotFound => "Block proposal not found",
            NegativePeerSanction::InvalidBlockProposal => "Invalid block proposal",
            NegativePeerSanction::UnwantedMessage => "unwanted message",
            NegativePeerSanction::NonFavorableBlockProposal => "non-favorable block proposal",
        };
        write!(f, "{string}")
    }
}

impl Display for PositivePeerSanction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = match self {
            PositivePeerSanction::ValidBlocks(_) => "valid blocks",
            PositivePeerSanction::NewBlockProposal => "new block proposal",
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

impl Sanction for NegativePeerSanction {
    fn severity(self) -> i32 {
        match self {
            NegativePeerSanction::InvalidBlock(_) => -10,
            NegativePeerSanction::DifferentGenesis => i32::MIN,
            NegativePeerSanction::ForkResolutionError((_height, count, _digest)) => {
                i32::from(count).saturating_mul(-3)
            }
            NegativePeerSanction::SynchronizationTimeout => -5,
            NegativePeerSanction::FloodPeerListResponse => -2,
            NegativePeerSanction::InvalidMessage => -2,
            NegativePeerSanction::TooShortBlockBatch => -2,
            NegativePeerSanction::ReceivedBatchBlocksOutsideOfSync => -2,
            NegativePeerSanction::BatchBlocksInvalidStartHeight => -2,
            NegativePeerSanction::BatchBlocksUnknownRequest => -10,
            NegativePeerSanction::BlockRequestUnknownHeight => -1,
            NegativePeerSanction::InvalidTransaction => -10,
            NegativePeerSanction::UnconfirmableTransaction => -2,
            NegativePeerSanction::NonMinedTransactionHasCoinbase => -10,
            NegativePeerSanction::NoStandingFoundMaybeCrash => -10,
            NegativePeerSanction::BlockProposalNotFound => -1,
            NegativePeerSanction::InvalidBlockProposal => -10,
            NegativePeerSanction::UnwantedMessage => -1,
            NegativePeerSanction::NonFavorableBlockProposal => -1,
        }
    }
}

/// The reason for changing a peer's standing.
///
/// Sanctions can be positive (rewards) or negative (punishments).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) enum PeerSanction {
    Positive(PositivePeerSanction),
    Negative(NegativePeerSanction),
}

impl Sanction for PositivePeerSanction {
    fn severity(self) -> i32 {
        match self {
            PositivePeerSanction::ValidBlocks(number) => number
                .try_into()
                .map(|n: i32| n.saturating_mul(10))
                .unwrap_or(i32::MAX),
            PositivePeerSanction::NewBlockProposal => 7,
        }
    }
}

impl Sanction for PeerSanction {
    fn severity(self) -> i32 {
        match self {
            PeerSanction::Positive(positive_peer_sanction) => positive_peer_sanction.severity(),
            PeerSanction::Negative(negative_peer_sanction) => negative_peer_sanction.severity(),
        }
    }
}

/// This is object that gets stored in the database to record how well a peer
/// at a certain IP behaves. A lower number is better.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PeerStanding {
    pub standing: i32,
    pub latest_punishment: Option<(NegativePeerSanction, SystemTime)>,
    pub latest_reward: Option<(PositivePeerSanction, SystemTime)>,
    peer_tolerance: i32,
}
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct StandingExceedsBanThreshold;

impl PeerStanding {
    #[cfg(test)]
    pub(crate) fn init(
        standing: i32,
        latest_punishment: Option<(NegativePeerSanction, SystemTime)>,
        latest_reward: Option<(PositivePeerSanction, SystemTime)>,
        peer_tolerance: i32,
    ) -> PeerStanding {
        Self {
            standing,
            latest_punishment,
            latest_reward,
            peer_tolerance,
        }
    }

    pub(crate) fn new(peer_tolerance: u16) -> Self {
        Self {
            peer_tolerance: i32::from(peer_tolerance),
            standing: 0,
            latest_punishment: None,
            latest_reward: None,
        }
    }

    /// Sanction peer and return latest standing score
    pub(crate) fn sanction(
        &mut self,
        reason: PeerSanction,
    ) -> Result<i32, StandingExceedsBanThreshold> {
        self.standing = self
            .standing
            .saturating_add(reason.severity())
            .clamp(-self.peer_tolerance, self.peer_tolerance);
        trace!(
            "new standing: {}, peer tolerance: {}",
            self.standing,
            self.peer_tolerance
        );
        match reason {
            PeerSanction::Negative(negative_peer_sanction) => {
                self.latest_punishment = Some((negative_peer_sanction, SystemTime::now()))
            }
            PeerSanction::Positive(positive_peer_sanction) => {
                self.latest_reward = Some((positive_peer_sanction, SystemTime::now()))
            }
        }
        if self.standing == -self.peer_tolerance {
            Err(StandingExceedsBanThreshold)
        } else {
            Ok(self.standing)
        }
    }

    /// Clear peer standing record
    pub(crate) fn clear_standing(&mut self) {
        self.standing = 0;
        self.latest_punishment = None;
        self.latest_reward = None;
    }

    pub fn is_negative(&self) -> bool {
        self.standing.is_negative()
    }

    /// Should only be used if peer was expected to be found in the peer map
    /// but, for some reason, was not there. Please only use this function for
    /// that purpose.
    pub fn new_on_no_standing_found(peer_tolerance: u16) -> Self {
        assert!(
            peer_tolerance > 0,
            " peer tolerance must be greater than zero"
        );
        Self {
            standing: NegativePeerSanction::NoStandingFoundMaybeCrash.severity(),
            latest_punishment: Some((
                NegativePeerSanction::NoStandingFoundMaybeCrash,
                SystemTime::now(),
            )),
            latest_reward: None,
            peer_tolerance: peer_tolerance.into(),
        }
    }
}

impl Display for PeerStanding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.standing)
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

/// A message sent between peers to inform them whether the connection was
/// accepted or refused (and if so, for what reason).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransferConnectionStatus {
    Refused(ConnectionRefusedReason),
    Accepted,
}

/// A success code for internal use, pertaining to the establishment
/// of a connection to a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InternalConnectionStatus {
    Refused(ConnectionRefusedReason),
    AcceptedMaxReached,
    Accepted,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConnectionRefusedReason {
    AlreadyConnected,
    BadStanding,
    IncompatibleVersion,
    MaxPeerNumberExceeded,
    SelfConnect,
}

impl From<InternalConnectionStatus> for TransferConnectionStatus {
    fn from(value: InternalConnectionStatus) -> Self {
        match value {
            InternalConnectionStatus::Refused(connection_refused_reason) => {
                TransferConnectionStatus::Refused(connection_refused_reason)
            }
            InternalConnectionStatus::AcceptedMaxReached | InternalConnectionStatus::Accepted => {
                TransferConnectionStatus::Accepted
            }
        }
    }
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
    ConnectionStatus(TransferConnectionStatus),
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

/// `MutablePeerState` contains information about the peer's blockchain state.
/// Under normal conditions, this information varies across time.
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
