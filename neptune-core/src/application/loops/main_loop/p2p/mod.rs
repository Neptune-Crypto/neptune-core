mod behaviour;
pub mod tmp_utils_multiaddr;

pub(super) use behaviour::swarmutil::swarm;
use itertools::Itertools;
use multiaddr::Protocol;

const MSG_NOTALLOWED: &str = "currently it's only for filtered subscription";

// would be cool to `const` actual `IdentTopic` and `::hash()` but it's not possible (yet?)
const TOPIC_BLOCK: &str = "block";
const TOPIC_TX_SINGLEPROOF: &str = "tx_singleproof";
const TOPIC_PROPOSAL: &str = "proposal";
const TOPIC_TX_PROOFCOL_: &str = "tx_proofcollection_";
const TOPIC_TX_PROOFCOL_NOTIF: &str = "tx_proofcollection_notification";

// https://t.me/neptune_dev/526
const BLOCK_SIZE: usize = 8 << 20;
const TX_SINGLEPROOF_SIZE: usize = 3 << 19;
const TX_PROOFCOL_SIZE: usize = 65 << 20;

/// `false` when the m-addr is on a relay itself or doesn't have `Protocol::Tcp`
///
/// needs a test by another hand
fn relay_maybe(adr: &libp2p::Multiaddr) -> bool {
    !adr.protocol_stack().contains(&Protocol::P2pCircuit.tag()) // a relay *client* m-addr differs basically with this part from a relay
    && adr.protocol_stack().contains(&Protocol::Tcp(0).tag())
}
