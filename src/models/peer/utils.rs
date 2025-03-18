use super::{PeerMessage, SyncChallenge, SyncChallengeResponse};

impl From<SyncChallenge> for PeerMessage {
    fn from(sync_challenge: SyncChallenge) -> Self {
        PeerMessage::SyncChallenge(sync_challenge)
    }
}

impl From<SyncChallengeResponse> for PeerMessage {
    fn from(sync_challenge_response: SyncChallengeResponse) -> Self {
        PeerMessage::SyncChallengeResponse(Box::new(sync_challenge_response))
    }
}
