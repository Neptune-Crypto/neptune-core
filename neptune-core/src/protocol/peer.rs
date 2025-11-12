pub(crate) mod handshake_data;
pub mod peer_block_notifications;
pub mod peer_info;
pub mod transaction_notification;
pub mod transfer_block;
pub mod transfer_transaction;

use std::fmt::Display;
use std::net::SocketAddr;
use std::time::SystemTime;

use handshake_data::HandshakeData;
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use num_traits::Zero;
use peer_block_notifications::PeerBlockNotification;
use rand::rngs::StdRng;
use rand::Rng;
use rand::RngCore;
use rand::SeedableRng;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::twenty_first::prelude::Mmr;
use tasm_lib::twenty_first::prelude::MmrMembershipProof;
use tasm_lib::twenty_first::tip5::digest::Digest;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tracing::debug;
use tracing::trace;
use tracing::warn;
use transaction_notification::TransactionNotification;
use transfer_transaction::TransferTransaction;

use super::consensus::block::block_header::BlockHeader;
use super::consensus::block::block_header::BlockHeaderWithBlockHashWitness;
use super::consensus::block::block_height::BlockHeight;
use super::consensus::block::difficulty_control::Difficulty;
use super::consensus::block::difficulty_control::ProofOfWork;
use super::consensus::block::Block;
use super::proof_abstractions::timestamp::Timestamp;
use crate::application::config::network::Network;
use crate::application::loops::channel::BlockProposalNotification;
use crate::protocol::consensus::block::difficulty_control::max_cumulative_pow_after;
use crate::protocol::peer::transfer_block::TransferBlock;
use crate::state::transaction::transaction_kernel_id::TransactionKernelId;

pub(crate) type InstanceId = u128;

pub(crate) const SYNC_CHALLENGE_POW_WITNESS_LENGTH: usize = 10;
pub(crate) const SYNC_CHALLENGE_NUM_BLOCK_PAIRS: usize = 10;

pub(crate) trait Sanction {
    fn severity(self) -> i32;
}

/// The reason for degrading a peer's standing
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[cfg_attr(any(test, feature = "mock-rpc"), derive(strum::EnumCount))]
pub enum NegativePeerSanction {
    InvalidBlock((BlockHeight, Digest)),
    DifferentGenesis,
    ForkResolutionError((BlockHeight, u16, Digest)),
    SynchronizationTimeout,

    InvalidSyncChallenge,
    InvalidSyncChallengeResponse,
    TimedOutSyncChallengeResponse,
    UnexpectedSyncChallengeResponse,
    FishyPowEvolutionChallengeResponse,
    FishyDifficultiesChallengeResponse,

    FloodPeerListResponse,
    BlockRequestUnknownHeight,

    // Be careful about using this too much as it's bad for log opportunities.
    InvalidMessage,
    NonMinedTransactionHasCoinbase,
    TooShortBlockBatch,
    ReceivedBatchBlocksOutsideOfSync,
    BatchBlocksInvalidStartHeight,
    BatchBlocksUnknownRequest,
    BatchBlocksRequestEmpty,
    BatchBlocksRequestTooManyDigests,

    InvalidTransaction,
    UnconfirmableTransaction,
    TransactionWithNegativeFee,
    DoubleSpendingTransaction,
    CannotApplyTransactionToMutatorSet,

    InvalidBlockMmrAuthentication,

    InvalidTransferBlock,

    BlockProposalNotFound,
    InvalidBlockProposal,
    NonFavorableBlockProposal,
    BlockProposalFromBlockedPeer,

    UnwantedMessage,

    NoStandingFoundMaybeCrash,

    /// A sync challenge was received. Is punished to prevent many challenges
    /// from same peer, as they're expensive (in disk I/O and networking
    /// bandwidth) to respond to.
    ReceivedSyncChallenge,
    UnrelayableTransaction,
}

/// The reason for improving a peer's standing
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[cfg_attr(any(test, feature = "mock-rpc"), derive(strum::EnumCount))]
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
            NegativePeerSanction::BatchBlocksUnknownRequest => "batch blocks unknown request",
            NegativePeerSanction::InvalidTransaction => "invalid transaction",
            NegativePeerSanction::UnconfirmableTransaction => "unconfirmable transaction",
            NegativePeerSanction::TransactionWithNegativeFee => "negative-fee transaction",
            NegativePeerSanction::DoubleSpendingTransaction => "double-spending transaction",
            NegativePeerSanction::CannotApplyTransactionToMutatorSet => {
                "cannot apply tx to mutator set"
            }
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
            NegativePeerSanction::BlockProposalFromBlockedPeer => {
                "got block proposal from non-whitelisted peer"
            }
            NegativePeerSanction::BatchBlocksRequestEmpty => "batch block request empty",
            NegativePeerSanction::InvalidSyncChallenge => "invalid sync challenge",
            NegativePeerSanction::InvalidSyncChallengeResponse => "invalid sync challenge response",
            NegativePeerSanction::UnexpectedSyncChallengeResponse => {
                "unexpected sync challenge response"
            }
            NegativePeerSanction::InvalidTransferBlock => "invalid transfer block",
            NegativePeerSanction::TimedOutSyncChallengeResponse => {
                "timed-out sync challenge response"
            }
            NegativePeerSanction::InvalidBlockMmrAuthentication => {
                "invalid block mmr authentication"
            }
            NegativePeerSanction::BatchBlocksRequestTooManyDigests => {
                "too many digests in batch block request"
            }
            NegativePeerSanction::FishyPowEvolutionChallengeResponse => "fishy pow evolution",
            NegativePeerSanction::FishyDifficultiesChallengeResponse => "fishy difficulties",
            NegativePeerSanction::ReceivedSyncChallenge => "received sync challenge",
            NegativePeerSanction::UnrelayableTransaction => "unrelayable transaction",
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
                i32::from(count).saturating_mul(-1)
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
            NegativePeerSanction::TransactionWithNegativeFee => -22,
            NegativePeerSanction::DoubleSpendingTransaction => -14,
            NegativePeerSanction::CannotApplyTransactionToMutatorSet => -3,
            NegativePeerSanction::NonMinedTransactionHasCoinbase => -10,
            NegativePeerSanction::NoStandingFoundMaybeCrash => -10,
            NegativePeerSanction::BlockProposalNotFound => -1,
            NegativePeerSanction::InvalidBlockProposal => -10,
            NegativePeerSanction::UnwantedMessage => -1,
            NegativePeerSanction::NonFavorableBlockProposal => -1,
            NegativePeerSanction::BlockProposalFromBlockedPeer => -10,
            NegativePeerSanction::BatchBlocksRequestEmpty => -10,
            NegativePeerSanction::InvalidSyncChallenge => -50,
            NegativePeerSanction::InvalidSyncChallengeResponse => -500,
            NegativePeerSanction::UnexpectedSyncChallengeResponse => -1,
            NegativePeerSanction::InvalidTransferBlock => -50,
            NegativePeerSanction::TimedOutSyncChallengeResponse => -50,
            NegativePeerSanction::InvalidBlockMmrAuthentication => -4,
            NegativePeerSanction::BatchBlocksRequestTooManyDigests => -50,
            NegativePeerSanction::FishyPowEvolutionChallengeResponse => -51,
            NegativePeerSanction::FishyDifficultiesChallengeResponse => -51,
            NegativePeerSanction::ReceivedSyncChallenge => -50,
            NegativePeerSanction::UnrelayableTransaction => -10,
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

/// This is the object that gets stored in the database to record how well a
/// peer has behaved so far.
//
// The most central methods are [PeerStanding::sanction] and
// [PeerStanding::is_bad].
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PeerStanding {
    /// The actual standing. The higher, the better.
    pub standing: i32,
    pub latest_punishment: Option<(NegativePeerSanction, SystemTime)>,
    pub latest_reward: Option<(PositivePeerSanction, SystemTime)>,
    peer_tolerance: i32,
}
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct StandingExceedsBanThreshold;

impl Display for StandingExceedsBanThreshold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "standing exceeds ban threshold")
    }
}

impl std::error::Error for StandingExceedsBanThreshold {}

impl PeerStanding {
    pub(crate) fn new(peer_tolerance: u16) -> Self {
        assert!(peer_tolerance > 0, "peer tolerance must be positive");
        Self {
            peer_tolerance: i32::from(peer_tolerance),
            standing: 0,
            latest_punishment: None,
            latest_reward: None,
        }
    }

    /// Sanction peer. If (and only if) the peer is now in
    /// [bad standing](Self::is_bad), returns an error.
    pub(crate) fn sanction(
        &mut self,
        sanction: PeerSanction,
    ) -> Result<(), StandingExceedsBanThreshold> {
        self.standing = self
            .standing
            .saturating_add(sanction.severity())
            .clamp(-self.peer_tolerance, self.peer_tolerance);
        trace!(
            "new standing: {}, peer tolerance: {}",
            self.standing,
            self.peer_tolerance
        );
        let now = SystemTime::now();
        match sanction {
            PeerSanction::Negative(sanction) => self.latest_punishment = Some((sanction, now)),
            PeerSanction::Positive(sanction) => self.latest_reward = Some((sanction, now)),
        }

        self.is_good()
            .then_some(())
            .ok_or(StandingExceedsBanThreshold)
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

    pub(crate) fn is_bad(&self) -> bool {
        self.standing <= -self.peer_tolerance
    }

    pub(crate) fn is_good(&self) -> bool {
        !self.is_bad()
    }
}

impl Display for PeerStanding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.standing)
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

    /// Use for any other reasons, when adding new reasons in the future.
    Other(u8),
}

impl ConnectionRefusedReason {
    pub(crate) fn bad_timestamp() -> Self {
        Self::Other(0)
    }
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

    /// The block MMR accumulator of the tip of the chain which the node is
    /// syncing towards. Its number of leafs is the block height the node is
    /// syncing towards.
    ///
    /// The receiver needs this value to know which MMR authentication paths to
    /// attach to the blocks in the response. These paths allow the receiver of
    /// a batch of blocks to verify that the received blocks are indeed
    /// ancestors to a given tip.
    pub(crate) anchor: MmrAccumulator,
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

#[non_exhaustive]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum PeerMessage {
    Handshake {
        magic_value: [u8; 15],
        data: Box<HandshakeData>,
    },
    Block(Box<TransferBlock>),
    BlockNotificationRequest,
    BlockNotification(PeerBlockNotification),
    BlockRequestByHeight(BlockHeight),
    BlockRequestByHash(Digest),

    BlockRequestBatch(BlockRequestBatch), // TODO: Consider restricting this in size
    BlockResponseBatch(Vec<(TransferBlock, MmrMembershipProof)>), // TODO: Consider restricting this in size
    UnableToSatisfyBatchRequest,

    SyncChallenge(SyncChallenge),
    SyncChallengeResponse(Box<SyncChallengeResponse>),

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
    // New variants must be added here at the bottom to be backwards compatible.
}

impl PeerMessage {
    pub fn get_type(&self) -> String {
        match self {
            PeerMessage::Handshake { .. } => "handshake",
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
            PeerMessage::UnableToSatisfyBatchRequest => "unable to satisfy batch request",
            PeerMessage::SyncChallenge(_) => "sync challenge",
            PeerMessage::SyncChallengeResponse(_) => "sync challenge response",
        }
        .to_string()
    }

    pub fn ignore_when_not_sync(&self) -> bool {
        match self {
            PeerMessage::Handshake { .. } => false,
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
            PeerMessage::UnableToSatisfyBatchRequest => true,
            PeerMessage::SyncChallenge(_) => false,
            PeerMessage::SyncChallengeResponse(_) => false,
        }
    }

    /// Function to filter out messages that should not be handled while the client is syncing
    pub fn ignore_during_sync(&self) -> bool {
        match self {
            PeerMessage::Handshake { .. } => false,
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
            PeerMessage::UnableToSatisfyBatchRequest => false,
            PeerMessage::SyncChallenge(_) => false,
            PeerMessage::SyncChallengeResponse(_) => false,
        }
    }

    /// Function to filter out messages that should be ignored when all state
    /// updates have been paused.
    pub fn ignore_on_freeze(&self) -> bool {
        match self {
            PeerMessage::Handshake { .. } => false,
            PeerMessage::Block(_) => true,
            PeerMessage::BlockNotificationRequest => true,
            PeerMessage::BlockNotification(_) => true,
            PeerMessage::BlockRequestByHeight(_) => true,
            PeerMessage::BlockRequestByHash(_) => true,
            PeerMessage::BlockRequestBatch(_) => true,
            PeerMessage::BlockResponseBatch(_) => true,
            PeerMessage::UnableToSatisfyBatchRequest => true,
            PeerMessage::SyncChallenge(_) => true,
            PeerMessage::SyncChallengeResponse(_) => true,
            PeerMessage::BlockProposalNotification(_) => true,
            PeerMessage::BlockProposalRequest(_) => true,
            PeerMessage::BlockProposal(_) => true,
            PeerMessage::Transaction(_) => true,
            PeerMessage::TransactionNotification(_) => true,
            PeerMessage::TransactionRequest(_) => true,
            PeerMessage::PeerListRequest => false,
            PeerMessage::PeerListResponse(_) => false,
            PeerMessage::Bye => false,
            PeerMessage::ConnectionStatus(_) => false,
        }
    }
}

/// `MutablePeerState` contains information about the peer's blockchain state.
/// Under normal conditions, this information varies across time.
#[derive(Clone, Debug)]
pub struct MutablePeerState {
    pub highest_shared_block_height: BlockHeight,
    pub fork_reconciliation_blocks: Vec<Block>,
    pub(crate) sync_challenge: Option<IssuedSyncChallenge>,

    /// Timestamp for the last successful sync challenge response.
    ///
    /// Used to prevent issuing multiple sync challenges in short succession.
    pub(crate) successful_sync_challenge_response_time: Option<Timestamp>,
}

impl MutablePeerState {
    pub fn new(block_height: BlockHeight) -> Self {
        Self {
            highest_shared_block_height: block_height,
            fork_reconciliation_blocks: vec![],
            sync_challenge: None,
            successful_sync_challenge_response_time: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct IssuedSyncChallenge {
    pub(crate) challenge: SyncChallenge,
    pub(crate) issued_at: Timestamp,
    pub(crate) accumulated_pow: ProofOfWork,
}
impl IssuedSyncChallenge {
    pub(crate) fn new(
        challenge: SyncChallenge,
        claimed_pow: ProofOfWork,
        timestamp: Timestamp,
    ) -> Self {
        Self {
            challenge,
            issued_at: timestamp,
            accumulated_pow: claimed_pow,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SyncChallenge {
    pub(crate) tip_digest: Digest,

    /// Block heights of the child blocks, for which the peer must respond with
    /// (parent, child) blocks. Assumed to be ordered from small to big.
    pub(crate) challenges: [BlockHeight; SYNC_CHALLENGE_NUM_BLOCK_PAIRS],
}

impl SyncChallenge {
    /// Generate a `SyncChallenge`.
    ///
    /// Sample 10 block heights, 5 each from two distributions:
    ///  1. An exponential distribution smaller than the peer's claimed height
    ///     but skewed towards this number.
    ///  2. A uniform distribution between own tip height and the peer's claimed
    ///     height.
    ///
    /// # Panics
    ///
    ///  - Panics if the difference in height between own tip and peer's tip is
    ///    less than 10.
    pub(crate) fn generate(
        block_notification: &PeerBlockNotification,
        own_tip_height: BlockHeight,
        randomness: [u8; 32],
    ) -> Self {
        let mut rng = StdRng::from_seed(randomness);
        let mut heights = vec![];

        assert!(
            block_notification.height - own_tip_height >= 10,
            "Cannot issue sync challenge when height difference ({} - {} = {}) is less than 10.",
            block_notification.height,
            own_tip_height,
            block_notification.height - own_tip_height
        );

        // sample 5 block heights skewed towards peer's claimed tip height
        while heights.len() < 5 {
            let distance = rng.next_u64().leading_zeros() * 31
                + rng.next_u64().leading_zeros() * 7
                + rng.next_u64().leading_zeros() * 3
                + rng.next_u64().leading_zeros()
                + 1;
            let Some(height) = block_notification.height.checked_sub(distance.into()) else {
                continue;
            };

            // Don't require peer to send genesis block, as that's impossible.
            if height <= 1.into() {
                continue;
            }
            heights.push(height);
        }

        // sample 5 block heights uniformly from the interval between own tip
        // height and peer's claimed tip height
        let interval = u64::from(own_tip_height)..u64::from(block_notification.height);
        while heights.len() < 10 {
            let height = rng.random_range(interval.clone()).into();

            // Don't require peer to send genesis block, as that's impossible.
            if height <= 1.into() {
                continue;
            }
            heights.push(height);
        }

        // sort from small to big as that makes some validation checks easier.
        heights.sort();

        Self {
            tip_digest: block_notification.hash,
            challenges: heights.try_into().unwrap(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SyncChallengeResponse {
    /// (parent, child) blocks. blocks are assumed to be ordered from small to
    /// big block height.
    pub(crate) blocks: [(TransferBlock, TransferBlock); SYNC_CHALLENGE_NUM_BLOCK_PAIRS],

    /// Membership proof of the child blocks, relative to the tip-MMR (after
    /// appending digest of tip). Must match ordering of blocks.
    pub(crate) membership_proofs: [MmrMembershipProof; SYNC_CHALLENGE_NUM_BLOCK_PAIRS],

    pub(crate) tip_parent: TransferBlock,
    pub(crate) tip: TransferBlock,

    /// Pow-witnesses from tip and X blocks back, in reverse-chronological
    /// order. So a witness to the `tip` hash should be the 1st element in this
    /// array.
    pub(crate) pow_witnesses: [BlockHeaderWithBlockHashWitness; SYNC_CHALLENGE_POW_WITNESS_LENGTH],
}

impl SyncChallengeResponse {
    fn pow_witnesses_form_chain_from_tip(
        tip_digest: Digest,
        pow_witnesses: &[BlockHeaderWithBlockHashWitness; SYNC_CHALLENGE_POW_WITNESS_LENGTH],
    ) -> bool {
        let tip_header_with_witness = &pow_witnesses[0];
        let mut is_chain_from_tip = tip_header_with_witness.hash() == tip_digest;
        for (child, parent) in pow_witnesses.iter().tuple_windows() {
            is_chain_from_tip &= child.is_successor_of(parent);
        }

        is_chain_from_tip
    }

    /// Determine whether the `SyncChallengeResponse` answers the given
    /// `IssuedSyncChallenge`, and not some other one.
    pub(crate) fn matches(&self, network: Network, issued_challenge: IssuedSyncChallenge) -> bool {
        let Ok(tip_parent) = Block::try_from(self.tip_parent.clone()) else {
            return false;
        };
        let Ok(tip) = Block::try_from(self.tip.clone()) else {
            return false;
        };

        let pow_witnesses_form_chain_from_tip =
            Self::pow_witnesses_form_chain_from_tip(tip.hash(), &self.pow_witnesses);

        self.blocks
            .iter()
            .zip(issued_challenge.challenge.challenges.iter())
            .all(|((_, child), challenge_height)| child.header.height == *challenge_height)
            && issued_challenge.challenge.tip_digest == tip.hash()
            && issued_challenge.accumulated_pow == tip.header().cumulative_proof_of_work
            && tip.has_proof_of_work(network, tip_parent.header())
            && pow_witnesses_form_chain_from_tip
    }

    /// Determine whether the proofs in `SyncChallengeResponse` are valid. Also
    /// checks proof-of-work.
    pub(crate) async fn is_valid(&self, now: Timestamp, network: Network) -> bool {
        let Ok(tip_predecessor) = Block::try_from(self.tip_parent.clone()) else {
            return false;
        };
        let Ok(tip) = Block::try_from(self.tip.clone()) else {
            return false;
        };
        if !tip.is_valid(&tip_predecessor, now, network).await
            || !tip.has_proof_of_work(network, tip_predecessor.header())
        {
            return false;
        }

        let mut mmra_anchor = tip.body().block_mmr_accumulator.to_owned();
        mmra_anchor.append(tip.hash());
        for ((parent, child), membership_proof) in
            self.blocks.iter().zip(self.membership_proofs.iter())
        {
            let Ok(child) = Block::try_from(child.clone()) else {
                return false;
            };
            if !membership_proof.verify(
                child.header().height.into(),
                child.hash(),
                &mmra_anchor.peaks(),
                mmra_anchor.num_leafs(),
            ) {
                return false;
            }

            let Ok(parent) = Block::try_from(parent.clone()) else {
                return false;
            };

            if !child.is_valid(&parent, now, network).await
                || !child.has_proof_of_work(network, parent.header())
            {
                return false;
            }
        }

        true
    }

    /// Determine whether the claimed evolution of the cumulative proof-of-work
    /// is a) possible, and b) likely, given the difficulties.
    pub(crate) fn check_pow(&self, network: Network, own_tip_height: BlockHeight) -> bool {
        let genesis_header = BlockHeader::genesis(network);
        let parent_triples = [(
            genesis_header.height,
            genesis_header.cumulative_proof_of_work,
            genesis_header.difficulty,
        )]
        .into_iter()
        .chain(self.blocks.iter().map(|(child, _parent)| {
            (
                child.header.height,
                child.header.cumulative_proof_of_work,
                child.header.difficulty,
            )
        }))
        .chain([(
            self.tip_parent.header.height,
            self.tip_parent.header.cumulative_proof_of_work,
            self.tip_parent.header.difficulty,
        )])
        .collect_vec();
        let cumulative_pow_evolution_okay = parent_triples.iter().copied().tuple_windows().all(
            |((start_height, start_cpow, start_difficulty), (stop_height, stop_cpow, _))| {
                let max_pow = max_cumulative_pow_after(
                    start_cpow,
                    start_difficulty,
                    (stop_height - start_height)
                        .try_into()
                        .expect("difference of block heights guaranteed to be non-negative"),
                    network.target_block_interval(),
                    network.minimum_block_time(),
                );
                // cpow must increase for each block, and is upward-bounded. But
                // since response may contain duplicates, allow equality.
                max_pow >= stop_cpow && start_cpow <= stop_cpow
            },
        );

        let first = self.blocks[0].0.header;
        let last = self.tip.header;
        let total_pow_increase = BigUint::from(last.cumulative_proof_of_work)
            - BigUint::from(first.cumulative_proof_of_work);
        let span = last.height - first.height;
        let average_difficulty = total_pow_increase.to_f64().unwrap() / (span as f64);
        debug_assert!(
            average_difficulty > 0.0,
            "Average difficulty must be positive. Got: {average_difficulty}"
        );

        // In principle, the cumulative proof-of-work could have been boosted by
        // a small number of outlying large difficulties. We require here that
        // "enough" observed difficulties are above this average. This strategy
        // is a heuristic and its use implies false positives: some evolutions
        // will be flagged as fishy, even though they came about legally.
        //
        // To quantify the heuristic somewhat: Suppose we are okay with assuming
        // that for all honest responders 10% of the difficulties must be larger
        // than the mean; and otherwise the node should flag the sync challenge
        // response as fishy. Then the probability of observing k above-mean
        // difficulties out of a random selection of 22, is
        //   {22 choose k} * (0.1)^k * (0.9)^(22-k) .
        // And in particular:
        //   k: probability
        //   ----------------------
        //   0: 0.09847709021836118
        //   1: 0.24072177608932735
        //   2: 0.28084207210421525
        //   3: 0.20803116452164094
        //   4: 0.10979422571975492
        //   5: 0.043917690287901975 .
        //
        // The tip is included in the below check, so if *it* doesn't have an
        // above average difficulty, something is almost certainly off.

        let too_few_above_mean_difficulties = !own_tip_height.is_genesis()
            && self
                .blocks
                .iter()
                .flat_map(|(l, r)| [l, r])
                .chain([&self.tip_parent, &self.tip])
                .map(|b| b.header.difficulty)
                .filter(|d| BigUint::from(*d).to_f64().unwrap() >= average_difficulty)
                .count()
                == 0;

        if too_few_above_mean_difficulties {
            warn!("Too few above mean difficulties.");
        }

        if !cumulative_pow_evolution_okay {
            warn!("Impossible evolution of cumulative pow.");
            for (start, stop) in parent_triples.into_iter().tuple_windows() {
                let upper_bound = max_cumulative_pow_after(
                    start.1,
                    start.2,
                    (stop.0 - start.0).try_into().unwrap(),
                    network.target_block_interval(),
                    network.minimum_block_time(),
                );
                debug!(
                    "start ({} / {} / {}) -> stop ({} / {} / {}) with max {}",
                    start.0, start.1, start.2, stop.0, stop.1, stop.2, upper_bound
                );
            }
        }

        cumulative_pow_evolution_okay && !too_few_above_mean_difficulties
    }

    /// Check whether the claimed difficulties are large enough relative to that
    /// of our own tip.
    ///
    /// Sum all verified difficulties and verify that this number is larger than
    /// our own tip difficulty. This inequality guarantees that the successful
    /// attacker must have spent at least one block's worth of guessing power to
    /// produce the malicious chain, and probably much more.
    pub(crate) fn check_difficulty(&self, own_tip_difficulty: Difficulty) -> bool {
        let own_tip_difficulty = ProofOfWork::zero() + own_tip_difficulty;
        let mut fork_relative_cumpow = ProofOfWork::zero();
        for (_parent, child) in &self.blocks {
            fork_relative_cumpow = fork_relative_cumpow + child.header.difficulty;
        }

        fork_relative_cumpow > own_tip_difficulty
    }
}

#[cfg(any(feature = "mock-rpc", test))]
impl rand::distr::Distribution<NegativePeerSanction> for rand::distr::StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> NegativePeerSanction {
        match rng.random_range(0..<NegativePeerSanction as strum::EnumCount>::COUNT) {
            0 => NegativePeerSanction::InvalidBlock((rng.random(), rng.random())),
            1 => NegativePeerSanction::DifferentGenesis,
            2 => NegativePeerSanction::ForkResolutionError((
                rng.random(),
                rng.random(),
                rng.random(),
            )),
            3 => NegativePeerSanction::InvalidSyncChallengeResponse,

            4 => NegativePeerSanction::InvalidSyncChallenge,
            5 => NegativePeerSanction::InvalidSyncChallengeResponse,
            6 => NegativePeerSanction::TimedOutSyncChallengeResponse,
            7 => NegativePeerSanction::UnexpectedSyncChallengeResponse,
            8 => NegativePeerSanction::FishyPowEvolutionChallengeResponse,
            9 => NegativePeerSanction::FishyDifficultiesChallengeResponse,

            10 => NegativePeerSanction::FloodPeerListResponse,
            11 => NegativePeerSanction::BlockRequestUnknownHeight,

            12 => NegativePeerSanction::InvalidMessage,
            13 => NegativePeerSanction::NonMinedTransactionHasCoinbase,
            14 => NegativePeerSanction::TooShortBlockBatch,
            15 => NegativePeerSanction::ReceivedBatchBlocksOutsideOfSync,
            16 => NegativePeerSanction::BatchBlocksInvalidStartHeight,
            17 => NegativePeerSanction::BatchBlocksUnknownRequest,
            18 => NegativePeerSanction::BatchBlocksRequestEmpty,
            19 => NegativePeerSanction::BatchBlocksRequestTooManyDigests,

            20 => NegativePeerSanction::InvalidTransaction,
            21 => NegativePeerSanction::UnconfirmableTransaction,
            22 => NegativePeerSanction::TransactionWithNegativeFee,
            23 => NegativePeerSanction::DoubleSpendingTransaction,
            24 => NegativePeerSanction::CannotApplyTransactionToMutatorSet,

            25 => NegativePeerSanction::InvalidBlockMmrAuthentication,

            26 => NegativePeerSanction::InvalidTransferBlock,

            27 => NegativePeerSanction::BlockProposalNotFound,
            28 => NegativePeerSanction::InvalidBlockProposal,
            29 => NegativePeerSanction::NonFavorableBlockProposal,
            30 => NegativePeerSanction::BlockProposalFromBlockedPeer,

            31 => NegativePeerSanction::UnwantedMessage,

            32 => NegativePeerSanction::NoStandingFoundMaybeCrash,

            33 => NegativePeerSanction::ReceivedSyncChallenge,
            34 => NegativePeerSanction::UnrelayableTransaction,
            _ => unreachable!(),
        }
    }
}

#[cfg(any(feature = "mock-rpc", test))]
impl rand::distr::Distribution<PositivePeerSanction> for rand::distr::StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> PositivePeerSanction {
        match rng.random_range(0..<PositivePeerSanction as strum::EnumCount>::COUNT) {
            0 => PositivePeerSanction::ValidBlocks(rng.random_range(0_usize..1000)),
            1 => PositivePeerSanction::NewBlockProposal,
            _ => unreachable!(),
        }
    }
}

#[cfg(any(test, feature = "mock-rpc"))]
impl rand::distr::Distribution<PeerStanding> for rand::distr::StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> PeerStanding {
        let punishment_time =
            SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(rng.next_u64() >> 20);
        let punishment_sanction = rng.random();
        let reward_time =
            SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(rng.next_u64() >> 20);
        let reward_sanction = rng.random();
        PeerStanding {
            standing: rng.random(),
            latest_punishment: if rng.random_bool(0.5) {
                Some((punishment_sanction, punishment_time))
            } else {
                None
            },
            latest_reward: if rng.random_bool(0.5) {
                Some((reward_sanction, reward_time))
            } else {
                None
            },
            peer_tolerance: rng.random(),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use macro_rules_attr::apply;
    use rand::{random, rng};

    use super::*;
    use crate::protocol::consensus::block::block_header::HeaderToBlockHashWitness;
    use crate::protocol::consensus::block::Block;
    use crate::tests::shared::blocks::fake_valid_sequence_of_blocks_for_tests;
    use crate::tests::shared_tokio_runtime;

    impl PeerStanding {
        pub fn init(
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
    }

    #[apply(shared_tokio_runtime)]
    async fn sync_challenge_response_pow_witnesses_must_be_a_chain() {
        let network = Network::Main;
        let genesis = Block::genesis(network);
        let mut rng = rand::rng();
        let ten_blocks: [Block; SYNC_CHALLENGE_POW_WITNESS_LENGTH] =
            fake_valid_sequence_of_blocks_for_tests(
                &genesis,
                Timestamp::minutes(20),
                rng.random(),
                network,
            )
            .await;

        let to_pow_witness = |block: &Block| {
            BlockHeaderWithBlockHashWitness::new(
                *block.header(),
                HeaderToBlockHashWitness::from(block),
            )
        };

        let mut i = SYNC_CHALLENGE_POW_WITNESS_LENGTH;
        let mut block;
        let mut valid_pow_chain = vec![];
        while valid_pow_chain.len() < SYNC_CHALLENGE_POW_WITNESS_LENGTH {
            i -= 1;
            block = &ten_blocks[i];
            valid_pow_chain.push(to_pow_witness(block));
        }

        let tip = &ten_blocks[SYNC_CHALLENGE_POW_WITNESS_LENGTH - 1];
        let valid_pow_chain: [BlockHeaderWithBlockHashWitness; SYNC_CHALLENGE_POW_WITNESS_LENGTH] =
            valid_pow_chain.try_into().unwrap();
        assert!(SyncChallengeResponse::pow_witnesses_form_chain_from_tip(
            tip.hash(),
            &valid_pow_chain
        ));

        for j in 0..SYNC_CHALLENGE_POW_WITNESS_LENGTH {
            let mut invalid_pow_chain = valid_pow_chain.clone();
            invalid_pow_chain[j].header.prev_block_digest = random();
            assert!(!SyncChallengeResponse::pow_witnesses_form_chain_from_tip(
                tip.hash(),
                &invalid_pow_chain
            ));
        }

        for j in 0..SYNC_CHALLENGE_POW_WITNESS_LENGTH {
            let mut invalid_pow_chain = valid_pow_chain.clone();
            invalid_pow_chain[j].header.set_nonce(random());
            assert!(!SyncChallengeResponse::pow_witnesses_form_chain_from_tip(
                tip.hash(),
                &invalid_pow_chain
            ));
        }
    }

    #[test]
    fn random_negative_peer_sanction_does_not_crash() {
        println!(
            "FYI the number of variants in NegativePeerSanction is {}",
            <NegativePeerSanction as strum::EnumCount>::COUNT
        );
        for _ in 0..200 {
            let _nps = rng().random::<NegativePeerSanction>();
        }
    }
}
