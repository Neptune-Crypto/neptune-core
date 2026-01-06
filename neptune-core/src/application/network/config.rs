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
        Self::new()
    }
}

impl NetworkConfig {
    pub(crate) fn new() -> Self {
        Self {
            max_num_peers: 10,
            ..Default::default()
        }
    }

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
