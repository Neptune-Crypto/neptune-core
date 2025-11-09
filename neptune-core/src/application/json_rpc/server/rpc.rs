use std::collections::HashSet;

use tracing::warn;

use crate::application::json_rpc::core::api::ops::Namespace;
use crate::state::GlobalStateLock;

#[derive(Clone, Debug)]
pub struct RpcServer {
    pub(crate) state: GlobalStateLock,
    pub(crate) unrestricted: bool,
}

impl RpcServer {
    pub fn new(state: GlobalStateLock, unrestricted: Option<bool>) -> Self {
        let unrestricted = unrestricted.unwrap_or(state.cli().unsafe_rpc);

        Self {
            state,
            unrestricted,
        }
    }

    /// Returns the enabled set of RPC namespaces with node configuration check.
    pub async fn enabled_namespaces(&self) -> HashSet<Namespace> {
        let state = self.state.lock_guard().await;
        let mut namespaces: HashSet<Namespace> =
            self.state.cli().rpc_modules.iter().copied().collect();

        if namespaces.contains(&Namespace::Archival) {
            let is_archival = state.chain.is_archival_node();

            if !is_archival {
                namespaces.remove(&Namespace::Archival);
                warn!("Node is not archival, cannot enable Archival namespace.");
            }
        }

        // TODO: warn if its restricted but networking etc. is enabled

        namespaces
    }
}
