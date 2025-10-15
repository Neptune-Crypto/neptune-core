use libp2p::Multiaddr;
use tracing::warn;

use crate::application::loops::channel::PeerTaskToMain;
use crate::protocol::peer::{NegativePeerSanction, PeerSanction};

pub(crate) async fn the(
    global_state_lock: crate::state::GlobalStateLock,
    to_main: tokio::sync::mpsc::Sender<PeerTaskToMain>,
    now: crate::api::export::Timestamp,
    peer_address: Multiaddr,
    proposal: crate::protocol::consensus::block::Block,
) -> Option<PeerSanction> {
    match proposal.body().total_guesser_reward() {
        Err(_) => Some(PeerSanction::Negative(
            NegativePeerSanction::InvalidBlockProposal,
        )),
        Ok(incoming_guesser_fee) if num_traits::Zero::is_zero(&incoming_guesser_fee) => {
            warn!("Rejecting new block proposal:\nInsufficient fee. Proposal was zero.");
            // @skaunov find the error here a bit confusing, but I double-checked that it would return this before my changes. (This note is to avoid further rechecks.) %)
            Some(PeerSanction::Negative(
                NegativePeerSanction::NonFavorableBlockProposal,
            ))
        }
        Ok(incoming_guesser_fee) => {
            // Avoid taking any locks if we don't accept block proposals from this IP.
            if global_state_lock
                .cli()
                .accept_block_proposal_from(peer_address)
                .is_err()
            {
                /* This will be cryptic in Gossip-sub until additional peer connections limited, but the scores are local hence no harm.
                Also the node has no incentive to distribute the proposals, so kinda no harm either. */
                Some(PeerSanction::Negative(
                    NegativePeerSanction::BlockProposalFromBlockedPeer,
                ))
            } else {
                // Is the proposal valid?
                /* Lock needs to be held here because race conditions: otherwise the block proposal
                that was validated might not match with the one whose favorability is being computed. */
                let state = global_state_lock.lock_guard().await;
                if proposal
                    .is_valid(
                        state.chain.light_state(),
                        &now,
                        global_state_lock.cli().network,
                    )
                    .await
                {
                    // Is block proposal favorable?
                    let is_favorable = state.favor_incoming_block_proposal(
                        proposal.header().prev_block_digest,
                        incoming_guesser_fee,
                    );
                    drop(state);

                    match is_favorable {
                        // No need to punish and log if the fees are equal. We just ignore the incoming proposal.
                        Err(crate::state::mining::block_proposal::BlockProposalRejectError::InsufficientFee { current, received })
                        if received == current.expect("checked in the beginning via `num_traits::Zero::is_zero(&incoming_guesser_fee)`") => {
                            tracing::debug!("ignoring new block proposal because the fee is equal to the present one");
                            None
                        }
                        Err(rejection_reason) => {
                            warn!("Rejecting new block proposal:\n{rejection_reason}");
                            Some(PeerSanction::Negative(NegativePeerSanction::NonFavorableBlockProposal))
                        }
                        Ok(()) => {
                            to_main.send(PeerTaskToMain::BlockProposal(proposal.into())).await.expect(super::MSG_CHAN_CRITICAL);

                            // Valuable, new, hard-to-produce information. Reward peer.
                            Some(PeerSanction::Positive(crate::protocol::peer::PositivePeerSanction::NewBlockProposal))
                        }
                    }
                } else {
                    drop(state);
                    Some(PeerSanction::Negative(
                        NegativePeerSanction::InvalidBlockProposal,
                    ))
                }
            }
        }
    }
}
