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
use std::str::FromStr;
use std::time::Duration;
use std::time::SystemTime;

use anyhow::bail;
use get_size2::GetSize;
use libp2p::Multiaddr;
use libp2p::PeerId;
use libp2p::StreamProtocol;
use serde::Deserialize;
use serde::Serialize;

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

    /// The protocol version (e.g., "/neptune/0.6.0").
    /// Essential for ensuring you don't sync with incompatible forks.
    pub(crate) protocol_version: String,

    /// Protocols supported by this peer (e.g., Kademlia, Gossipsub, etc.).
    #[serde(with = "protocol_vec_serde")]
    pub(crate) supported_protocols: Vec<StreamProtocol>,

    /// The first time we successfully exchanged Identify info with this peer.
    pub(crate) first_seen: SystemTime,

    /// The last time we successfully exchanged Identify info with this peer.
    pub(crate) last_seen: SystemTime,
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

/// Helper module to bridge Vec<StreamProtocol> and Vec<String>
mod protocol_vec_serde {
    use super::*;
    use serde::{Deserialize, Deserializer, Serializer};

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
/// The [`AddressBook`] acts as a specialized wrapper around a [`HashMap`].
///
/// By encapsulating the [`Peer`] struct, it ensures that peer metadata—such as
/// 'first seen' and 'last seen' timestamps—is managed consistently and cannot
/// be modified arbitrarily by external actors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AddressBook(pub(super) HashMap<PeerId, Peer>);

impl Deref for AddressBook {
    type Target = HashMap<PeerId, Peer>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AddressBook {
    /// Creates a new, empty `AddressBook`.
    pub(crate) fn new() -> Self {
        Self(HashMap::new())
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
    ///    `/neptune/0.6.0`).
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

        if let Some(peer) = self.0.get_mut(&peer_id) {
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
            };
            self.0.insert(peer_id, peer);
        }
    }

    /// Prunes the address book down to the specified length.
    ///
    /// The prioritization strategy keeps peers that:
    /// 1. Match the current Neptune protocol version.
    /// 2. Whether the peer was seen in the last 10 minutes.
    /// 3. Have the oldest 'first_seen' timestamp (demonstrated longevity).
    pub(crate) fn prune_to_length(&mut self, target_length: usize) {
        if self.0.len() <= target_length {
            return;
        }

        // 1. Collect PeerIds and a "score" for sorting
        let mut peer_scores: Vec<(PeerId, PeerScore)> = self
            .0
            .iter()
            .map(|(id, peer)| (*id, PeerScore::from_peer(peer)))
            .collect();

        // 2. Sort: We want the "best" peers at the beginning.
        // Rust's sort_by is ascending, so we use cmp().reverse()
        // or compare (best, worst).
        peer_scores.sort_by(|(_, a), (_, b)| b.cmp(a));

        // 3. Retain only the top N PeerIds
        let keys_to_keep: HashSet<PeerId> = peer_scores
            .into_iter()
            .take(target_length)
            .map(|(id, _)| id)
            .collect();

        self.0.retain(|id, _| keys_to_keep.contains(id));

        tracing::info!(
            target = target_length,
            remaining = self.0.len(),
            "Address book pruned."
        );
    }

    /// Selects the top N peers to dial upon restart.
    ///
    /// Prioritizes peers matching our supported protocols and recent activity.
    pub(crate) fn select_initial_peers(&self, limit: usize) -> Vec<Multiaddr> {
        let mut scores: Vec<(PeerScore, &Peer)> = self
            .0
            .values()
            .map(|p| (PeerScore::from_peer(p), p))
            // Only dial peers that support Neptune Cash
            .filter(|(score, _)| score.is_correct_protocol)
            .collect();

        // Sort by PeerScore (Protocol > Recency > Lifespan)
        // Sort is descending so the "best" peers are at the start.
        scores.sort_by(|(a, _), (b, _)| b.cmp(a));

        // Insert bootstrap nodes if list is under-populated.
        let hardcoded_bootstrap_nodes = [
            (
                IpAddr::V4(Ipv4Addr::from_str("139.162.193.206").unwrap()),
                9800,
            ),
            (
                IpAddr::V4(Ipv4Addr::from_str("51.15.139.238").unwrap()),
                9800,
            ),
            (
                IpAddr::V6(Ipv6Addr::from_str("2001:bc8:17c0:41e:46a8:42ff:fe22:e8e9").unwrap()),
                9800,
            ),
        ]
        .into_iter()
        .map(|(ip, port)| {
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

    /// Persists the address book to a JSON file at the specified path.
    ///
    /// This allows the node to recover its address book after a restart,
    /// significantly speeding up the peer discovery process.
    pub(crate) fn save_to_disk<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        let file = File::create(path)?;
        let writer = BufWriter::new(file);

        // Pretty-printing during development; swap to to_writer if file size
        // becomes an issue.
        serde_json::to_writer_pretty(writer, &self.0)?;

        tracing::info!("Address book persisted to disk.");
        Ok(())
    }

    /// Populates the address book with the entries from a given JSON file.
    ///
    /// If the file does not exist, an error is returned but otherwise nothing
    /// happens. If the file contains one or more entries that already live in
    /// the address book, they will be overwritten.
    pub(crate) fn load_from_disk<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<()> {
        if !path.as_ref().exists() {
            bail!("No address book file found; starting with an empty list.");
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let map: HashMap<PeerId, Peer> = serde_json::from_reader(reader)?;

        tracing::info!(peer_count = map.len(), "Address book loaded from disk.");

        for (peer_id, peer) in map {
            self.0.insert(peer_id, peer);
        }
        Ok(())
    }
}

impl PartialEq for AddressBook {
    fn eq(&self, other: &Self) -> bool {
        let lhs = self
            .0
            .iter()
            .map(|(peer_id, peer)| (*peer_id, peer.clone()))
            .collect::<HashSet<_>>();
        let rhs = other
            .0
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
    total_lifespan: std::time::Duration,
}

impl PeerScore {
    fn from_peer(peer: &Peer) -> Self {
        let now = SystemTime::now();
        let ten_minutes_ago = now.checked_sub(Duration::from_mins(10)).unwrap_or(now);
        Self {
            is_correct_protocol: peer.protocol_version == NEPTUNE_PROTOCOL_STR,
            recent: peer.last_seen.duration_since(ten_minutes_ago).is_ok(),
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
    use std::time::UNIX_EPOCH;

    use proptest::prop_assert_eq;
    use test_strategy::proptest;

    use super::*;

    #[proptest]
    fn write_read_address_book_round_trip(
        #[strategy(AddressBook::arbitrary())] address_book: AddressBook,
    ) {
        let mut path = env::temp_dir();

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("address_book_test_{}.json", timestamp));

        address_book.save_to_disk(&path).unwrap();

        let mut loaded_book = AddressBook::new();
        loaded_book.load_from_disk(&path).unwrap();

        prop_assert_eq!(address_book, loaded_book);

        let _ = fs::remove_file(&path);
    }

    #[proptest]
    fn read_fail_address_book_no_change(
        #[strategy(AddressBook::arbitrary())] address_book: AddressBook,
    ) {
        let mut path = env::temp_dir();

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("address_book_test_{}.json", timestamp));

        let mut new_address_book = address_book.clone();

        new_address_book.load_from_disk(&path).unwrap_err();

        prop_assert_eq!(address_book, new_address_book);
    }

    #[test]
    fn can_select_bootstrap_peers() {
        let address_book = AddressBook::new();
        let bootstrap_peers = address_book.select_initial_peers(10); // no crash
        assert!(!bootstrap_peers.is_empty());
    }
}
