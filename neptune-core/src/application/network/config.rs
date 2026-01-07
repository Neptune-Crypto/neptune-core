use std::path::PathBuf;

use crate::api::export::Network;

#[derive(Debug, Clone)]
pub(crate) struct NetworkConfig {
    /// Which network we are on: Main / Testnet / Regtest / ...
    pub(super) network: Network,

    /// Where to find the persistent address book.
    pub(super) address_book: Option<PathBuf>,

    /// The max. number of peers to connect to.
    pub(super) max_num_peers: usize,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            network: Network::default(),
            address_book: None,
            max_num_peers: 10,
        }
    }
}

impl NetworkConfig {
    pub(crate) fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    pub(crate) fn with_address_book(mut self, path: PathBuf) -> Self {
        self.address_book = Some(path);
        self
    }

    pub(crate) fn with_max_num_peers(mut self, new_max: usize) -> Self {
        self.max_num_peers = new_max;
        self
    }
}
