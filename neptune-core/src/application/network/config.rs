use std::path::PathBuf;

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
}
