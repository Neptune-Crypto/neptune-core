#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::{
        api::export::Network,
        application::{
            config::cli_args,
            json_rpc::{core::api::rpc::RpcApi, server::server::RpcServer},
        },
        state::wallet::wallet_entropy::WalletEntropy,
        tests::{shared::globalstate::mock_genesis_global_state, shared_tokio_runtime},
    };
    use anyhow::Result;
    use macro_rules_attr::apply;

    async fn test_rpc_server() -> RpcServer {
        let global_state_lock = mock_genesis_global_state(
            2,
            WalletEntropy::new_random(),
            cli_args::Args::default_with_network(Network::Main),
        )
        .await;

        RpcServer::new(global_state_lock)
    }

    #[apply(shared_tokio_runtime)]
    async fn test_height_is_correct() -> Result<()> {
        let rpc_server = test_rpc_server().await;
        assert_eq!(0, rpc_server.get_height().await.height);
        Ok(())
    }
}
