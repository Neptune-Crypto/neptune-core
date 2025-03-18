use super::super::PeerMessage;
use crate::models::blockchain::block::Block;
use crate::models::peer::peer_block_notifications::PeerBlockNotification;
use crate::models::peer::SyncChallengeResponse;
use crate::models::proof_abstractions::timestamp::Timestamp;

mod strategy_the;
mod strategy_variants;
mod utils;

// both can go without a `...Request`

/// BlockNotificationRequest --> BlockNotification
/// BlockNotification --> SyncChallenge
/// SyncChallenge --> SyncChallengeResponse
///
/// BlockProposalRequest --> BlockProposal
///
/// BlockRequestBatch --> BlockResponseBatch
/// BlockRequestBatch --> UnableToSatisfyBatchRequest
///
/// TODO what if both exchanges are started? what should be done when an exchange is reinititalized?
#[derive(Debug, Clone)]
enum SyncStage {
    // Init(Vec<Block>),
    /// The requested `BlockNotification` have been sent
    WaitingForChallenge(PeerBlockNotification, Block),
    /// An unexpected `BlockNotification` have been challenged
    WaitingForChallengeResponse,
    // DoneWithRandomness([u8; 32])
}

// Feels like for peering it's not relevant what mode the node is on: syncing or mining.
#[derive(Debug, Clone)]
pub(crate) struct Automaton {
    blocks: Vec<Block>,
    // inbound_connection: bool,
    // distance: u8,
    sync_stage: Option<SyncStage>,
    pub is_inbound: bool,
}

#[derive(Debug, Clone)]
pub struct Transition(pub PeerMessage, pub Option<AssosiatedData>);
#[derive(Debug, Clone)]
pub enum AssosiatedData {
    NewBlock(Block),
    Randomness(/* [u8; 32] */),
    MakeNewBlocks(Timestamp, [u8; 32]),
}
impl From<SyncChallengeResponse> for Transition {
    fn from(v: SyncChallengeResponse) -> Self {
        Transition(
            v.into(),
            // #noValidProp #SyncChallengeResponse
            None,
        )
    }
}
