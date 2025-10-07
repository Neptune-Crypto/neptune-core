mod behaviour;
pub mod tmp_utils_multiaddr;

pub(super) use behaviour::swarm;

// would be cool to `const` actual `IdentTopic` and `::hash()` but it's not possible (yet?)
const TOPIC_BLOCK: &str = "block";
const TOPIC_TX_SINGLEPROOF: &str = "tx_singleproof";
const TOPIC_PROPOSAL: &str = "proposal";
const TOPIC_TX_PROOFCOL_: &str = "tx_proofcollection_";
const TOPIC_TX_PROOFCOL_NOTIF: &str = "tx_proofcollection_notification";
// https://t.me/neptune_dev/526
const BLOCK_SIZE: usize = 8 << 6;
const TX_SINGLEPROOF_SIZE: usize = 15 << 5;
const TX_PROOFCOL_SIZE: usize = 65 << 6;