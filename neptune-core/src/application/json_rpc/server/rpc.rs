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

        if !self.unrestricted && namespaces.contains(&Namespace::Networking) {
            warn!("Networking module is enabled without unsafe mode - this may expose sensitive data.")
        }

        namespaces
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use macro_rules_attr::apply;

    use crate::api::export::Network;
    use crate::application::config::cli_args;
    use crate::application::json_rpc::server::rpc::RpcServer;
    use crate::state::wallet::wallet_entropy::WalletEntropy;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared_tokio_runtime;

    #[apply(shared_tokio_runtime)]
    async fn rpc_respects_safety_configuration() {
        let global_state_lock = mock_genesis_global_state(
            2,
            WalletEntropy::new_random(),
            cli_args::Args::default_with_network(Network::Main),
        )
        .await;

        // By default, the RPC server should run in restricted (safe) mode
        let server = RpcServer::new(global_state_lock.clone(), None);
        assert!(!server.unrestricted);

        // When explicitly requested, the RPC server should allow unrestricted (unsafe) mode
        // This can be used in transports where UX is prioritized over security
        let server = RpcServer::new(global_state_lock, Some(true));
        assert!(server.unrestricted);
    }
}
