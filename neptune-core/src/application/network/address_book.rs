use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::ops::Deref;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use std::time::SystemTime;

use get_size2::GetSize;
use itertools::Itertools;
use libp2p::Multiaddr;
use libp2p::PeerId;
use libp2p::StreamProtocol;
use serde::Deserialize;
use serde::Serialize;

use crate::application::config::network::Network;
use crate::application::network::stack::NEPTUNE_PROTOCOL_STR;

pub(crate) const ADDRESS_BOOK_MAX_SIZE: usize = 1000_usize;

/// Peer metadata managed by the [`AddressBook`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) struct Peer {
    /// Addresses the peer is listening on, as reported by Identify.
    /// Unlike the active connection, these are persistent locations.
    pub(crate) listen_addresses: Vec<Multiaddr>,

    /// The software version of the node (e.g., "neptune-cash/0.6.0").
    /// Useful for telemetry and identifying "heavy" or "light" nodes.
    pub(crate) agent_version: String,

    /// The protocol version (e.g., "/neptune/-main").
    /// Essential for ensuring you don't sync with incompatible forks.
    pub(crate) protocol_version: String,

    /// Protocols supported by this peer (e.g., Kademlia, Gossipsub, etc.).
    #[serde(with = "protocol_vec_serde")]
    pub(crate) supported_protocols: Vec<StreamProtocol>,

    /// The first time we successfully exchanged Identify info with this peer.
    pub(crate) first_seen: SystemTime,

    /// The last time we successfully exchanged Identify info with this peer.
    pub(crate) last_seen: SystemTime,

    /// The number of times a connection attempt failed since the last success.
    pub(crate) fail_count: u32,
}

impl GetSize for Peer {
    fn get_heap_size(&self) -> usize {
        let mut size = 0;

        for addr in &self.listen_addresses {
            size += addr.as_ref().len();
        }

        size += self.agent_version.get_heap_size();
        size += self.protocol_version.get_heap_size();

        for proto in &self.supported_protocols {
            size += proto.as_ref().len();
        }

        size
    }
}

/// Helper module to bridge `Vec<StreamProtocol>` and `Vec<String>`.
///
/// Enables `serde` to encode and decode `Vec<StreamProtocol>` as though it were
/// `Vec<String>`.
mod protocol_vec_serde {
    use serde::Deserialize;
    use serde::Deserializer;
    use serde::Serializer;

    use super::*;

    pub fn serialize<S>(vec: &[StreamProtocol], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert StreamProtocol back to string for serialization
        let s_vec: Vec<&str> = vec.iter().map(|p| p.as_ref()).collect();
        s_vec.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<StreamProtocol>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s_vec = Vec::<String>::deserialize(deserializer)?;

        // We convert the String into a StreamProtocol.
        // In recent libp2p, StreamProtocol::new() takes a parameter
        // that implements Into<Cow<'static, str>>.
        Ok(s_vec
            .into_iter()
            .map(|s| StreamProtocol::new(Box::leak(s.into_boxed_str())))
            .collect())
    }
}

/// Maps [`PeerId`]s to peer metadata such as listen addresses, among other
/// fields.
///
/// The [`AddressBook`] contains a [`HashMap`] of [`PeerId`] --> [`Peer`], in
/// addition to a filename which determines where it is persisted.
///
/// By encapsulating the [`Peer`] struct, it ensures that peer metadata—such as
/// 'first seen' and 'last seen' timestamps—is managed consistently and cannot
/// be modified arbitrarily by external actors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AddressBook {
    pub(super) book: HashMap<PeerId, Peer>,
    pub(super) filename: PathBuf,
    pub(super) network: Network,
}

impl Deref for AddressBook {
    type Target = HashMap<PeerId, Peer>;

    fn deref(&self) -> &Self::Target {
        &self.book
    }
}

impl AddressBook {
    /// Create a new *empty* (except for the file name) [`AddressBook`].
    pub(super) fn new_empty<P: AsRef<Path>>(network: Network, file_path: P) -> Self {
        Self {
            book: HashMap::<PeerId, Peer>::new(),
            filename: file_path.as_ref().to_path_buf(),
            network,
        }
    }

    /// Inserts a new peer or updates an existing one with raw data fields.
    ///
    /// This method is the primary entry point for data coming from the
    /// `Identify` protocol. It automatically manages the `first_seen` and
    /// `last_seen` timestamps:
    ///  - If the peer is new, both timestamps are set to the current time.
    ///  - If the peer exists, only `last_seen` is refreshed, and all metadata
    ///    is overwritten with the latest reported values.
    ///
    /// # Arguments
    ///  * `peer_id` - The unique cryptographic identifier of the remote peer.
    ///    This field serves as the index of the map.
    ///  * `listen_addresses` - The dialable multiaddresses the peer is
    ///    listening on.
    ///  * `agent_version` - The specific software version string of the client.
    ///  * `protocol_version` - The Neptune protocol version (e.g.,
    ///    `/neptune/`).
    ///  * `supported_protocols` - The list of all libp2p protocols the peer
    ///    supports.
    pub(crate) fn insert_or_update(
        &mut self,
        peer_id: PeerId,
        listen_addresses: Vec<Multiaddr>,
        agent_version: String,
        protocol_version: String,
        supported_protocols: Vec<StreamProtocol>,
    ) {
        // Number of items in containers should not exceed a reasonable limit.
        if listen_addresses.len() > 100 || supported_protocols.len() > 100 {
            tracing::warn!(%peer_id, "Rejected peer: too many data items.");
            return;
        }

        // Filter out non-global addresses and circuit addresses.
        let listen_addresses = listen_addresses
            .into_iter()
            .filter(|addr| {
                addr.iter().all(|proto| match proto {
                    libp2p::multiaddr::Protocol::Ip4(ipv4_addr) => {
                        !ipv4_addr.is_link_local()
                            && !ipv4_addr.is_loopback()
                            && !ipv4_addr.is_private()
                            && !ipv4_addr.is_unspecified()
                    }
                    libp2p::multiaddr::Protocol::Ip6(ipv6_addr) => {
                        !ipv6_addr.is_loopback()
                            && !ipv6_addr.is_unicast_link_local()
                            && !ipv6_addr.is_unspecified()
                    }
                    libp2p::multiaddr::Protocol::P2pCircuit => false,
                    _ => true,
                })
            })
            .collect_vec();
        if listen_addresses.is_empty() {
            return;
        }

        // Total size of all data should not exceed a reasonable limit.
        let mut total_size: usize = 0;
        total_size += peer_id.to_bytes().len();
        total_size += listen_addresses
            .iter()
            .map(|a| a.as_ref().len())
            .sum::<usize>();
        total_size += agent_version.to_string().len();
        total_size += protocol_version.to_string().len();
        total_size += supported_protocols
            .iter()
            .map(|a| a.as_ref().len())
            .sum::<usize>();
        if total_size > 4096 {
            tracing::warn!(%peer_id, "Rejected peer: data too large");
            return;
        }

        if let Some(peer) = self.book.get_mut(&peer_id) {
            peer.listen_addresses = listen_addresses;
            peer.agent_version = agent_version;
            peer.protocol_version = protocol_version;
            peer.supported_protocols = supported_protocols;
            peer.last_seen = SystemTime::now();
        } else {
            let peer = Peer {
                listen_addresses,
                agent_version,
                protocol_version,
                supported_protocols,
                first_seen: SystemTime::now(),
                last_seen: SystemTime::now(),
                fail_count: 0,
            };
            self.book.insert(peer_id, peer);
        }
    }

    /// Prunes the address book down to the specified length.
    ///
    /// The prioritization strategy keeps peers that:
    /// 1. Match the current Neptune protocol version.
    /// 2. Whether the peer was seen in the last 10 minutes.
    /// 3. Have the oldest 'first_seen' timestamp (demonstrated longevity).
    pub(crate) fn prune_to_length(&mut self, target_length: usize) {
        if self.book.len() <= target_length {
            return;
        }

        // Collect scores for sorting by.
        let mut peer_scores: Vec<(PeerId, PeerScore)> = self
            .book
            .iter()
            .map(|(id, peer)| (*id, PeerScore::from_peer(peer)))
            .collect();

        // Sort in *descending* order. Note that `sort_by` produces ascending
        // order so `b.cmp(a)` instead of `a.cmp(b)` reverses that.
        peer_scores.sort_by(|(_, a), (_, b)| b.cmp(a));

        // 3. Retain only the top N PeerIds
        let keys_to_keep: HashSet<PeerId> = peer_scores
            .into_iter()
            .take(target_length)
            .map(|(id, _)| id)
            .collect();

        self.book.retain(|id, _| keys_to_keep.contains(id));

        tracing::debug!(
            target = target_length,
            remaining = self.book.len(),
            "Address book pruned."
        );
    }

    /// Increment by one the `fail_count`. Return the new count.
    ///
    /// This variable which tracks how often a connection attempt has failed
    /// since the last success.
    pub(crate) fn bump_fail_count(&mut self, peer_id: PeerId) -> u32 {
        if let Some(peer) = self.book.get_mut(&peer_id) {
            peer.fail_count = peer.fail_count.saturating_add(1);
            return peer.fail_count;
        }

        0
    }

    /// Reset to 0 the `fail_count` variable, which tracks how often a
    /// connection has failed since the last success.
    pub(crate) fn reset_fail_count(&mut self, peer_id: PeerId) {
        if let Some(peer) = self.book.get_mut(&peer_id) {
            peer.fail_count = 0;
        }
    }

    /// Select the top N peers to dial upon restart.
    ///
    /// Prioritizes peers matching our supported protocols and recent activity.
    pub(crate) fn select_initial_peers(&self, limit: usize) -> Vec<Multiaddr> {
        let mut scores: Vec<(PeerScore, &Peer)> = self
            .book
            .values()
            .map(|p| (PeerScore::from_peer(p), p))
            // Only dial peers that support Neptune Cash
            .filter(|(score, _)| score.is_correct_protocol)
            .collect();

        // Sort by PeerScore (Protocol > Recency > Lifespan)
        // Sort is descending so the "best" peers are at the start.
        scores.sort_by(|(a, _), (b, _)| b.cmp(a));

        // Insert bootstrap nodes if list is under-populated.
        let hardcoded_bootstrap_nodes = match self.network {
            Network::Main => vec![
                (
                    IpAddr::V4(Ipv4Addr::from_str("139.162.193.206").unwrap()),
                    9801,
                ),
                (
                    IpAddr::V4(Ipv4Addr::from_str("51.15.139.238").unwrap()),
                    9801,
                ),
                (
                    IpAddr::V6(
                        Ipv6Addr::from_str("2001:bc8:17c0:41e:46a8:42ff:fe22:e8e9").unwrap(),
                    ),
                    9801,
                ),
            ],
            Network::Testnet(0) => vec![
                (
                    IpAddr::V4(Ipv4Addr::from_str("51.15.139.238").unwrap()),
                    19801,
                ),
                (
                    IpAddr::V6(
                        Ipv6Addr::from_str("2001:bc8:17c0:41e:46a8:42ff:fe22:e8e9").unwrap(),
                    ),
                    19801,
                ),
            ],
            _ => vec![],
        };
        let hardcoded_bootstrap_nodes = hardcoded_bootstrap_nodes.into_iter().map(|(ip, port)| {
            let mut multiaddr = Multiaddr::from(ip);
            multiaddr.push(libp2p::multiaddr::Protocol::Tcp(port));
            multiaddr
        });

        scores
            .into_iter()
            .take(limit)
            .flat_map(|(_, peer)| peer.listen_addresses.clone())
            .chain(hardcoded_bootstrap_nodes)
            .collect()
    }

    /// Persists the address book to a JSON file.
    ///
    /// This allows the node to recover its address book after a restart,
    /// significantly speeding up the peer discovery process.
    pub(crate) fn save_to_disk(&self) -> anyhow::Result<()> {
        let file = File::create(self.filename.clone())?;
        let writer = BufWriter::new(file);

        // Pretty-printing during development; swap to to_writer if file size
        // becomes an issue.
        serde_json::to_writer_pretty(writer, &self.book)?;

        tracing::debug!("Address book persisted to disk.");
        Ok(())
    }

    /// Loads the address book from the given file.
    ///
    /// If the file does not exist, the empty address book is returned.
    ///
    /// # Return Value
    ///
    ///  - `Ok(empty_address_book)` if the file does not exist.
    ///  - `Ok(address_book)` if the file does exist and everything succeeded.
    ///  - `Err(e)` if there was a decoding or file operations error.
    pub(crate) fn load_or_new<P: AsRef<Path>>(network: Network, path: P) -> anyhow::Result<Self> {
        if !path.as_ref().exists() {
            return Ok(Self::new_empty(network, path));
        }

        let file = File::open(&path)?;
        let reader = BufReader::new(file);
        let book: HashMap<PeerId, Peer> = serde_json::from_reader(reader)?;

        tracing::trace!(peer_count = book.len(), "Address book loaded from disk.");

        Ok(AddressBook {
            book,
            filename: path.as_ref().to_path_buf(),
            network,
        })
    }
}

impl PartialEq for AddressBook {
    fn eq(&self, other: &Self) -> bool {
        let lhs = self
            .book
            .iter()
            .map(|(peer_id, peer)| (*peer_id, peer.clone()))
            .collect::<HashSet<_>>();
        let rhs = other
            .book
            .iter()
            .map(|(peer_id, peer)| (*peer_id, peer.clone()))
            .collect::<HashSet<_>>();
        lhs == rhs
    }
}

/// A helper struct for comparing peer quality without exposing Peer fields.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct PeerScore {
    // Order of fields defines sorting priority for #[derive(Ord)]
    is_correct_protocol: bool,
    recent: bool,
    fail_count_inverse: u32,
    total_lifespan: std::time::Duration,
}

impl PeerScore {
    fn from_peer(peer: &Peer) -> Self {
        let now = SystemTime::now();
        let ten_minutes_ago = now.checked_sub(Duration::from_mins(10)).unwrap_or(now);
        Self {
            is_correct_protocol: peer.protocol_version == NEPTUNE_PROTOCOL_STR,
            recent: peer.last_seen.duration_since(ten_minutes_ago).is_ok(),
            fail_count_inverse: u32::MAX - peer.fail_count,
            // duration between first discovery and last activity
            total_lifespan: peer
                .last_seen
                .duration_since(peer.first_seen)
                .expect("last_seen is always determined after first_seen"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;

    use proptest::collection::vec;
    use proptest::prelude::any;
    use proptest::prelude::BoxedStrategy;
    use proptest::prelude::Strategy;
    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;
    use crate::application::network::actor::NetworkActor;
    use crate::application::network::arbitrary::arb_peer_id;

    impl AddressBook {
        /// Create a new [`AddressBook`] with the given fields.
        fn new<P: AsRef<Path>>(network: Network, book: HashMap<PeerId, Peer>, filename: P) -> Self {
            Self {
                book,
                filename: filename.as_ref().to_path_buf(),
                network,
            }
        }

        pub(crate) fn arbitrary() -> BoxedStrategy<Self> {
            let network = Network::Main;
            ((0usize..20), any::<String>())
                .prop_flat_map(move |(num_entries, filename)| {
                    let filename = filename.clone();
                    (
                        vec(arb_peer_id(), num_entries),
                        vec(Peer::arbitrary(), num_entries),
                    )
                        .prop_map(move |(peer_ids, entries)| {
                            let hash_map: HashMap<PeerId, Peer> =
                                peer_ids.into_iter().zip(entries).collect();
                            AddressBook::new(network, hash_map, filename.clone())
                        })
                })
                .boxed()
        }
    }

    #[proptest]
    fn write_read_address_book_round_trip(
        #[strategy(AddressBook::arbitrary())] mut address_book: AddressBook,
        #[strategy(arb::<u64>())] file_id: u64,
    ) {
        let network = Network::Main;
        let mut path = env::temp_dir();
        path.push(format!("address_book_test_{}.json", file_id));
        address_book.filename = path.clone();

        address_book.save_to_disk().unwrap();

        let loaded_book = AddressBook::load_or_new(network, &path).unwrap();

        prop_assert_eq!(address_book, loaded_book);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn can_select_bootstrap_peers() {
        let network = Network::Main;
        let address_book = AddressBook::new(network, HashMap::new(), "not-loaded.file");
        let bootstrap_peers = address_book.select_initial_peers(10); // no crash
        assert!(!bootstrap_peers.is_empty());
    }

    #[test]
    fn test_peer_score_hierarchy_with_fail_count() {
        let network = Network::Main;
        let now = SystemTime::now();
        let one_hour_ago = now - Duration::from_secs(3600);
        let two_hours_ago = now - Duration::from_secs(2 * 3600);
        let three_hours_ago = now - Duration::from_secs(3 * 3600);

        // The baseline Peer
        let p0 = Peer {
            listen_addresses: vec![],
            agent_version: "".to_string(),
            protocol_version: NetworkActor::protocol_version(network),
            supported_protocols: vec![libp2p::StreamProtocol::new(NEPTUNE_PROTOCOL_STR)],
            first_seen: three_hours_ago,
            last_seen: now,
            fail_count: 0,
        };

        // P1: Worse because of total life span
        let mut p1 = p0.clone();
        p1.first_seen = two_hours_ago;

        // P2: Worse because of fail count
        let mut p2 = p1.clone();
        p2.fail_count = 1;

        // P3: Worse because not recent
        let mut p3 = p2.clone();
        p3.last_seen = one_hour_ago;

        // P4: Worse because of wrong_protocol
        let mut p4 = p3.clone();
        p4.protocol_version = "QUICK-CACHE".to_string();

        // verify pairs
        assert!(
            PeerScore::from_peer(&p0) > PeerScore::from_peer(&p1),
            "failed to prefer longer-lived peers"
        );
        assert!(
            PeerScore::from_peer(&p1) > PeerScore::from_peer(&p2),
            "failed to prefer peers with lower fail counts"
        );
        assert!(
            PeerScore::from_peer(&p2) > PeerScore::from_peer(&p3),
            "failed to prefer recent peers"
        );
        assert!(
            PeerScore::from_peer(&p3) > PeerScore::from_peer(&p4),
            "failed to prefer peers with same protocol"
        );

        // verify sorting (descending order)
        let original_list = vec![p0, p1, p2, p3];
        let mut sorted_list = original_list.clone();
        sorted_list.sort_by(|l, r| PeerScore::from_peer(r).cmp(&PeerScore::from_peer(l)));
        assert_eq!(original_list, sorted_list);
    }
}
