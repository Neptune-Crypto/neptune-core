use std::net::IpAddr;
use std::ops::Deref;

use neptune_cash::api::export::BlockHeight;
use neptune_cash::api::export::ChangePolicy;
use neptune_cash::api::export::KeyType;
use neptune_cash::api::export::NativeCurrencyAmount;
use neptune_cash::api::export::Network;
use neptune_cash::api::export::OutputFormat;
use neptune_cash::api::export::ReceivingAddress;
use neptune_cash::api::export::SpendingKey;
use neptune_cash::api::export::Timestamp;
use neptune_cash::api::export::TxCreationArtifacts;
use neptune_cash::application::rpc::auth;
use neptune_cash::application::rpc::server::mempool_transaction_info::MempoolTransactionInfo;
use neptune_cash::application::rpc::server::overview_data::OverviewData;
use neptune_cash::application::rpc::server::ui_utxo::UiUtxo;
use neptune_cash::application::rpc::server::RPCClient;
use neptune_cash::application::rpc::server::RpcResult;
use neptune_cash::protocol::peer::peer_info::PeerInfo;
use tasm_lib::prelude::Digest;

#[derive(Debug, Clone)]
pub(crate) enum DashboardRpcClient {
    Authentic(RPCClient),

    #[cfg(feature = "mock")]
    Mock(crate::mock_rpc_client::MockRpcClient),
}

// Derive all of [RPCClient]'s implementations for for [DashboardRpcClient]
// whenever the variant is `Authentic`.
impl Deref for DashboardRpcClient {
    type Target = RPCClient;

    fn deref(&self) -> &Self::Target {
        #[allow(
            irrefutable_let_patterns,
            reason = "refutable with feature \"mock\" enabled"
        )]
        if let DashboardRpcClient::Authentic(client) = self {
            client
        } else {
            panic!(
                "Mock override not implemented. You are calling an RPC method\
            on a *mock* RPC client. You need to implement the mock RPC response;\
            otherwise, control passes to Deref which attempts to call the \
            authentic RPCClient and obviously fails because it is mock and not \
            authentic."
            );
        }
    }
}

impl DashboardRpcClient {
    pub async fn network(
        &self,
        ctx: ::tarpc::context::Context,
    ) -> ::core::result::Result<RpcResult<Network>, ::tarpc::client::RpcError> {
        match self {
            DashboardRpcClient::Authentic(rpcclient) => rpcclient.network(ctx).await,
            #[cfg(feature = "mock")]
            DashboardRpcClient::Mock(mock_rpc_client) => mock_rpc_client.network(ctx).await,
        }
    }

    pub async fn dashboard_overview_data(
        &self,
        ctx: ::tarpc::context::Context,
        token: auth::Token,
    ) -> ::core::result::Result<RpcResult<OverviewData>, ::tarpc::client::RpcError> {
        match self {
            DashboardRpcClient::Authentic(rpcclient) => {
                rpcclient.dashboard_overview_data(ctx, token).await
            }
            #[cfg(feature = "mock")]
            DashboardRpcClient::Mock(mock_client) => {
                mock_client.dashboard_overview_data(ctx, token).await
            }
        }
    }

    pub async fn known_keys(
        &self,
        ctx: ::tarpc::context::Context,
        token: auth::Token,
    ) -> ::core::result::Result<RpcResult<Vec<SpendingKey>>, ::tarpc::client::RpcError> {
        match self {
            DashboardRpcClient::Authentic(rpcclient) => rpcclient.known_keys(ctx, token).await,
            #[cfg(feature = "mock")]
            DashboardRpcClient::Mock(mock_client) => mock_client.known_keys(ctx, token).await,
        }
    }

    pub async fn history(
        &self,
        ctx: ::tarpc::context::Context,
        token: auth::Token,
    ) -> ::core::result::Result<
        RpcResult<Vec<(Digest, BlockHeight, Timestamp, NativeCurrencyAmount)>>,
        ::tarpc::client::RpcError,
    > {
        match self {
            DashboardRpcClient::Authentic(rpcclient) => rpcclient.history(ctx, token).await,
            #[cfg(feature = "mock")]
            DashboardRpcClient::Mock(mock_client) => mock_client.history(ctx, token).await,
        }
    }

    pub async fn mempool_overview(
        &self,
        ctx: ::tarpc::context::Context,
        token: auth::Token,
        page_start: usize,
        page_size: usize,
    ) -> ::core::result::Result<RpcResult<Vec<MempoolTransactionInfo>>, ::tarpc::client::RpcError>
    {
        match self {
            DashboardRpcClient::Authentic(rpcclient) => {
                rpcclient
                    .mempool_overview(ctx, token, page_start, page_size)
                    .await
            }
            #[cfg(feature = "mock")]
            DashboardRpcClient::Mock(mock_client) => {
                mock_client
                    .mempool_overview(ctx, token, page_start, page_size)
                    .await
            }
        }
    }

    pub async fn peer_info(
        &self,
        ctx: ::tarpc::context::Context,
        token: auth::Token,
    ) -> ::core::result::Result<RpcResult<Vec<PeerInfo>>, ::tarpc::client::RpcError> {
        match self {
            DashboardRpcClient::Authentic(rpcclient) => rpcclient.peer_info(ctx, token).await,
            #[cfg(feature = "mock")]
            DashboardRpcClient::Mock(mock_client) => mock_client.peer_info(ctx, token).await,
        }
    }

    pub async fn clear_peer_standing(
        &self,
        ctx: ::tarpc::context::Context,
        token: auth::Token,
        peer_ip: IpAddr,
    ) -> ::core::result::Result<RpcResult<()>, ::tarpc::client::RpcError> {
        match self {
            DashboardRpcClient::Authentic(rpcclient) => {
                rpcclient.clear_standing_by_ip(ctx, token, peer_ip).await
            }
            #[cfg(feature = "mock")]
            DashboardRpcClient::Mock(mock_client) => {
                mock_client.clear_standing_by_ip(ctx, token, peer_ip).await
            }
        }
    }

    pub async fn latest_address(
        &self,
        ctx: ::tarpc::context::Context,
        token: auth::Token,
        address_type: KeyType,
    ) -> ::core::result::Result<RpcResult<ReceivingAddress>, ::tarpc::client::RpcError> {
        match self {
            DashboardRpcClient::Authentic(rpcclient) => {
                rpcclient.latest_address(ctx, token, address_type).await
            }
            #[cfg(feature = "mock")]
            DashboardRpcClient::Mock(mock_client) => {
                mock_client.latest_address(ctx, token, address_type).await
            }
        }
    }

    pub async fn next_receiving_address(
        &self,
        ctx: ::tarpc::context::Context,
        token: auth::Token,
        address_type: KeyType,
    ) -> ::core::result::Result<RpcResult<ReceivingAddress>, ::tarpc::client::RpcError> {
        match self {
            DashboardRpcClient::Authentic(rpcclient) => {
                rpcclient
                    .next_receiving_address(ctx, token, address_type)
                    .await
            }
            #[cfg(feature = "mock")]
            DashboardRpcClient::Mock(mock_client) => {
                mock_client
                    .next_receiving_address(ctx, token, address_type)
                    .await
            }
        }
    }

    pub async fn send(
        &self,
        ctx: ::tarpc::context::Context,
        token: auth::Token,
        outputs: Vec<OutputFormat>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        max_inputs: Option<usize>,
    ) -> ::core::result::Result<RpcResult<TxCreationArtifacts>, ::tarpc::client::RpcError> {
        match self {
            DashboardRpcClient::Authentic(rpcclient) => {
                rpcclient
                    .send(ctx, token, outputs, change_policy, fee, max_inputs)
                    .await
            }

            #[cfg(feature = "mock")]
            DashboardRpcClient::Mock(mock_rpc_client) => {
                mock_rpc_client
                    .send(ctx, token, outputs, change_policy, fee, max_inputs)
                    .await
            }
        }
    }

    pub async fn list_utxos(
        &self,
        ctx: ::tarpc::context::Context,
        token: auth::Token,
    ) -> ::core::result::Result<RpcResult<Vec<UiUtxo>>, ::tarpc::client::RpcError> {
        match self {
            DashboardRpcClient::Authentic(rpcclient) => rpcclient.list_utxos(ctx, token).await,

            #[cfg(feature = "mock")]
            DashboardRpcClient::Mock(mock_rpc_client) => {
                mock_rpc_client.list_utxos(ctx, token).await
            }
        }
    }
}
