//! P2P protocol messages
//!
//! This module contains the P2P protocol message definitions.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::transaction::Transaction;

/// P2P protocol message enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PeerMessage {
    /// Handshake message
    Handshake {
        /// Magic value for protocol identification
        magic_value: [u8; 15],
        /// Handshake data
        data: Box<HandshakeData>,
    },
    /// Block message
    Block(Box<TransferBlock>),
    /// Block notification request
    BlockNotificationRequest,
    /// Block notification
    BlockNotification(PeerBlockNotification),
    /// Block request by height
    BlockRequestByHeight(BlockHeight),
    /// Block request by hash
    BlockRequestByHash(Digest),
    /// Block request batch
    BlockRequestBatch(BlockRequestBatch),
    /// Block response batch
    BlockResponseBatch(Vec<(TransferBlock, MmrMembershipProof)>),
    /// Unable to satisfy batch request
    UnableToSatisfyBatchRequest,
    /// Sync challenge
    SyncChallenge(SyncChallenge),
    /// Sync challenge response
    SyncChallengeResponse(Box<SyncChallengeResponse>),
    /// Block proposal notification
    BlockProposalNotification(BlockProposalNotification),
    /// Block proposal request
    BlockProposalRequest(BlockProposalRequest),
    /// Block proposal
    BlockProposal(Box<Block>),
    /// Transaction message
    Transaction(Box<TransferTransaction>),
    /// Transaction notification
    TransactionNotification(TransactionNotification),
    /// Transaction request
    TransactionRequest(TransactionKernelId),
    /// Peer list request
    PeerListRequest,
    /// Peer list response
    PeerListResponse(Vec<(SocketAddr, u128)>),
    /// Bye message
    Bye,
    /// Connection status
    ConnectionStatus(TransferConnectionStatus),
}

impl PeerMessage {
    /// Get the message type as a string
    pub fn get_type(&self) -> &'static str {
        match self {
            PeerMessage::Handshake { .. } => "Handshake",
            PeerMessage::Block(_) => "Block",
            PeerMessage::BlockNotificationRequest => "BlockNotificationRequest",
            PeerMessage::BlockNotification(_) => "BlockNotification",
            PeerMessage::BlockRequestByHeight(_) => "BlockRequestByHeight",
            PeerMessage::BlockRequestByHash(_) => "BlockRequestByHash",
            PeerMessage::BlockRequestBatch(_) => "BlockRequestBatch",
            PeerMessage::BlockResponseBatch(_) => "BlockResponseBatch",
            PeerMessage::UnableToSatisfyBatchRequest => "UnableToSatisfyBatchRequest",
            PeerMessage::SyncChallenge(_) => "SyncChallenge",
            PeerMessage::SyncChallengeResponse(_) => "SyncChallengeResponse",
            PeerMessage::BlockProposalNotification(_) => "BlockProposalNotification",
            PeerMessage::BlockProposalRequest(_) => "BlockProposalRequest",
            PeerMessage::BlockProposal(_) => "BlockProposal",
            PeerMessage::Transaction(_) => "Transaction",
            PeerMessage::TransactionNotification(_) => "TransactionNotification",
            PeerMessage::TransactionRequest(_) => "TransactionRequest",
            PeerMessage::PeerListRequest => "PeerListRequest",
            PeerMessage::PeerListResponse(_) => "PeerListResponse",
            PeerMessage::Bye => "Bye",
            PeerMessage::ConnectionStatus(_) => "ConnectionStatus",
        }
    }

    /// Check if message should be ignored during sync
    pub fn ignore_during_sync(&self) -> bool {
        match self {
            PeerMessage::Block(_) => false,
            PeerMessage::BlockNotification(_) => false,
            PeerMessage::BlockResponseBatch(_) => false,
            PeerMessage::SyncChallenge(_) => false,
            PeerMessage::SyncChallengeResponse(_) => false,
            _ => true, // Ignore other messages during sync
        }
    }

    /// Check if message should be ignored when not syncing
    pub fn ignore_when_not_sync(&self) -> bool {
        match self {
            PeerMessage::SyncChallenge(_) => true,
            PeerMessage::SyncChallengeResponse(_) => true,
            _ => false,
        }
    }

    /// Check if message should be ignored when frozen
    pub fn ignore_on_freeze(&self) -> bool {
        match self {
            PeerMessage::Transaction(_) => true,
            PeerMessage::TransactionNotification(_) => true,
            PeerMessage::TransactionRequest(_) => true,
            _ => false,
        }
    }
}

// Use original Neptune Core types for compatibility
pub type HandshakeData = crate::protocol::peer::handshake_data::HandshakeData;
pub type TransactionNotification =
    crate::protocol::peer::transaction_notification::TransactionNotification;

/// Transfer block structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferBlock {
    /// Block data
    pub block: Block,
}

impl From<TransferBlock> for Block {
    fn from(transfer: TransferBlock) -> Self {
        transfer.block
    }
}

/// Transfer transaction structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferTransaction {
    /// Transaction data
    pub transaction: Transaction,
}

impl From<TransferTransaction> for Transaction {
    fn from(transfer: TransferTransaction) -> Self {
        transfer.transaction
    }
}

/// Peer block notification - use original type from protocol::peer
pub use crate::protocol::peer::peer_block_notifications::PeerBlockNotification;

/// Block request batch
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockRequestBatch {
    /// Requested block hashes
    pub block_hashes: Vec<Digest>,
}

/// Sync challenge
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncChallenge {
    /// Challenge data
    pub challenge: Vec<u8>,
}

/// Sync challenge response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncChallengeResponse {
    /// Response data
    pub response: Vec<u8>,
}

/// Block proposal notification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockProposalNotification {
    /// Block proposal data
    pub proposal: Block,
}

/// Block proposal request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockProposalRequest {
    /// Requested block height
    pub height: BlockHeight,
}

// Transaction notification is re-exported from the original type above

// Use original Neptune Core TransferConnectionStatus type for compatibility
pub type TransferConnectionStatus = crate::protocol::peer::TransferConnectionStatus;

/// Connection status enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConnectionStatus {
    /// Connection accepted
    Accepted,
    /// Connection accepted but max peers reached
    AcceptedMaxReached,
    /// Connection refused
    Refused(ConnectionRefusedReason),
}

/// Connection refused reason
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConnectionRefusedReason {
    /// Bad peer standing
    BadStanding,
    /// Maximum peer number exceeded
    MaxPeerNumberExceeded,
    /// Already connected to this peer
    AlreadyConnected,
    /// Self-connection attempt
    SelfConnect,
    /// Incompatible version
    IncompatibleVersion,
    /// Network mismatch
    NetworkMismatch,
    /// Invalid handshake
    InvalidHandshake,
}

// Import necessary types
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::state::transaction::transaction_kernel_id::TransactionKernelId;
use tasm_lib::twenty_first::prelude::MmrMembershipProof;
use tasm_lib::twenty_first::tip5::digest::Digest;
