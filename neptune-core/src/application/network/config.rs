use std::net::IpAddr;
use std::path::PathBuf;

use libp2p::Multiaddr;

use crate::api::export::Network;

pub(crate) const DEFAULT_SUBDIRECTORY: &str = "network/";
pub(crate) const DEFAULT_IDENTITY_FILENAME: &str = "identity.key";
pub(crate) const DEFAULT_ADDRESS_BOOK_FILENAME: &str = "address-book.json";
pub(crate) const DEFAULT_BLACKLIST_FILENAME: &str = "blacklist.json";

#[derive(Debug, Clone)]
pub(crate) struct NetworkConfig {
    /// Which network we are on: Main / Testnet / Regtest / ...
    pub(super) network: Network,

    /// Subdirectory of the data directory where the network-specific data is
    /// stored.
    pub(super) subdirectory: Option<PathBuf>,

    identify_file: Option<PathBuf>,
    address_book_file: Option<PathBuf>,
    blacklist_file: Option<PathBuf>,

    banned_peers: Vec<Multiaddr>,
    pub(super) sticky_peers: Vec<Multiaddr>,

    /// The max. number of peers to connect to.
    pub(super) max_num_peers: usize,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            network: Network::default(),
            subdirectory: None,
            identify_file: None,
            address_book_file: None,
            blacklist_file: None,
            banned_peers: vec![],
            sticky_peers: vec![],
            max_num_peers: 10,
        }
    }
}

impl NetworkConfig {
    pub(crate) fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    pub(crate) fn with_subdirectory(mut self, path: PathBuf) -> Self {
        self.subdirectory = Some(path);
        self
    }

    pub(crate) fn with_max_num_peers(mut self, new_max: usize) -> Self {
        self.max_num_peers = new_max;
        self
    }

    pub(crate) fn with_cli_bans(mut self, banned_peers: Vec<Multiaddr>) -> Self {
        self.banned_peers.extend(banned_peers);
        self
    }

    pub(crate) fn with_cli_peers(mut self, sticky_peers: Vec<Multiaddr>) -> Self {
        self.sticky_peers.extend(sticky_peers);
        self
    }

    pub(crate) fn subdirectory(&self) -> PathBuf {
        self.subdirectory
            .clone()
            .unwrap_or_else(|| DEFAULT_SUBDIRECTORY.into())
    }

    pub(crate) fn identity_file(&self) -> PathBuf {
        self.subdirectory().join(
            self.identify_file
                .clone()
                .unwrap_or_else(|| PathBuf::from(DEFAULT_IDENTITY_FILENAME)),
        )
    }

    pub(crate) fn address_book_file(&self) -> PathBuf {
        self.subdirectory().join(
            self.address_book_file
                .clone()
                .unwrap_or_else(|| PathBuf::from(DEFAULT_ADDRESS_BOOK_FILENAME)),
        )
    }

    pub(crate) fn blacklist_file(&self) -> PathBuf {
        self.subdirectory().join(
            self.blacklist_file
                .clone()
                .unwrap_or_else(|| PathBuf::from(DEFAULT_BLACKLIST_FILENAME)),
        )
    }

    pub(crate) fn banned_ips(&self) -> Vec<IpAddr> {
        self.banned_peers
            .iter()
            .filter_map(|ma| {
                ma.iter().find_map(|protocol| match protocol {
                    libp2p::multiaddr::Protocol::Ip4(ipv4_addr) => Some(IpAddr::V4(ipv4_addr)),
                    libp2p::multiaddr::Protocol::Ip6(ipv6_addr) => Some(IpAddr::V6(ipv6_addr)),
                    _ => None,
                })
            })
            .collect()
    }
}
