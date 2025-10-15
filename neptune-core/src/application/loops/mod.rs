pub mod channel;
pub mod connect_to_peers;
pub(super) mod handle_proposal_from_peer;
pub(super) mod handle_tx_from_peer;
pub mod main_loop;
pub mod mine_loop;
pub mod peer_loop;

const MSG_CONDIT: &str = "checked in the condition";
const MSG_CHAN_CRITICAL: &str = "can't lose this channel";
