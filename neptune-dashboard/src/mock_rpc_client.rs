use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;

use neptune_cash::api::export::BlockHeight;
use neptune_cash::api::export::ChangePolicy;
use neptune_cash::api::export::GenerationSpendingKey;
use neptune_cash::api::export::KeyType;
use neptune_cash::api::export::NativeCurrencyAmount;
use neptune_cash::api::export::Network;
use neptune_cash::api::export::OutputFormat;
use neptune_cash::api::export::ReceivingAddress;
use neptune_cash::api::export::SpendingKey;
use neptune_cash::api::export::SymmetricKey;
use neptune_cash::api::export::Timestamp;
use neptune_cash::api::export::TxCreationArtifacts;
use neptune_cash::application::rpc::auth;
use neptune_cash::application::rpc::server::error::RpcError;
use neptune_cash::application::rpc::server::mempool_transaction_info::MempoolTransactionInfo;
use neptune_cash::application::rpc::server::overview_data::OverviewData;
use neptune_cash::application::rpc::server::ui_utxo::UiUtxo;
use neptune_cash::application::rpc::server::RpcResult;
use neptune_cash::protocol::peer::peer_info::PeerInfo;
use neptune_cash::state::wallet::address::generation_address::GenerationReceivingAddress;
use rand::rng;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use tasm_lib::prelude::Digest;

#[derive(Debug, Clone)]
pub(crate) struct MockRpcClient {
    state: Arc<Mutex<MockState>>,
}

#[derive(Debug, Clone)]
struct MockState {
    peers: Vec<PeerInfo>,
    utxos: Vec<UiUtxo>,
    known_keys: Vec<SpendingKey>,
    history: Vec<(Digest, BlockHeight, Timestamp, NativeCurrencyAmount)>,
    mempool_transactions: Vec<MempoolTransactionInfo>,
    overview_data: OverviewData,
    listen_address: Option<SocketAddr>,
    generation_address: ReceivingAddress,
    symmetric_address: ReceivingAddress,
}

impl MockRpcClient {
    pub(crate) fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(Self::init_mock_data())),
        }
    }

    fn init_mock_data() -> MockState {
        let mut rng = StdRng::from_seed(rng().random());

        let num_peers = 100;
        let peers: Vec<PeerInfo> = (0..num_peers).map(|_| rng.random()).collect();

        let num_utxos = rng.random_range(1..20);
        let utxos: Vec<UiUtxo> = (0..num_utxos)
            .map(|_| UiUtxo {
                amount: rng
                    .random::<NativeCurrencyAmount>()
                    .lossy_f64_fraction_mul(0.0001),
                release_date: if rng.random_bool(0.5) {
                    Some(rng.random())
                } else {
                    None
                },
                received: rng.random(),
                aocl_leaf_index: if rng.random_bool(0.5) {
                    Some(rng.random_range(0u64..(u64::MAX >> 20)))
                } else {
                    None
                },
                spent: rng.random(),
            })
            .collect();

        let num_keys = rng.random_range(1..100);
        let known_keys: Vec<SpendingKey> = (0..num_keys)
            .map(|_| match rng.random_range(0..2) {
                0 => SpendingKey::from(GenerationSpendingKey::derive_from_seed(rng.random())),
                1 => SpendingKey::from(SymmetricKey::from_seed(rng.random())),
                _ => unreachable!(),
            })
            .collect();

        let num_history = rng.random_range(0..100);
        let history: Vec<(Digest, BlockHeight, Timestamp, NativeCurrencyAmount)> = (0..num_history)
            .map(|_| {
                let digest = rng.random::<Digest>();
                let block_height = rng.random::<BlockHeight>();
                let timestamp = rng.random::<Timestamp>();
                let native_currency_amount = rng
                    .random::<NativeCurrencyAmount>()
                    .lossy_f64_fraction_mul(0.0001);
                (digest, block_height, timestamp, native_currency_amount)
            })
            .collect();

        let total_num_entries = rng.random_range(5..100);
        let mempool_transactions: Vec<MempoolTransactionInfo> =
            (0..total_num_entries).map(|_| rng.random()).collect();

        let overview_data: OverviewData = rng.random();

        let listen_address = Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                rng.random(),
                rng.random(),
                rng.random(),
                rng.random(),
            )),
            rng.random_range(1..65535),
        ));

        let generation_address =
            ReceivingAddress::from(GenerationReceivingAddress::derive_from_seed(rng.random()));
        let symmetric_address = ReceivingAddress::from(SymmetricKey::from_seed(rng.random()));

        MockState {
            peers,
            utxos,
            known_keys,
            history,
            mempool_transactions,
            overview_data,
            listen_address,
            generation_address,
            symmetric_address,
        }
    }
    pub async fn network(
        &self,
        _ctx: ::tarpc::context::Context,
    ) -> ::core::result::Result<RpcResult<Network>, ::tarpc::client::RpcError> {
        tokio::task::yield_now().await;
        Ok(Ok(Network::Main))
    }

    pub async fn own_listen_address_for_peers(
        &self,
        _ctx: ::tarpc::context::Context,
        _token: auth::Token,
    ) -> ::core::result::Result<RpcResult<Option<SocketAddr>>, ::tarpc::client::RpcError> {
        tokio::task::yield_now().await;
        let state = self.state.lock().unwrap();
        Ok(Ok(state.listen_address))
    }

    pub(crate) async fn dashboard_overview_data(
        &self,
        _ctx: ::tarpc::context::Context,
        _token: auth::Token,
    ) -> ::core::result::Result<RpcResult<OverviewData>, ::tarpc::client::RpcError> {
        tokio::task::yield_now().await;
        let state = self.state.lock().unwrap();
        Ok(Ok(state.overview_data.clone()))
    }

    pub async fn known_keys(
        &self,
        _ctx: ::tarpc::context::Context,
        _token: auth::Token,
    ) -> ::core::result::Result<RpcResult<Vec<SpendingKey>>, ::tarpc::client::RpcError> {
        tokio::task::yield_now().await;
        let state = self.state.lock().unwrap();
        Ok(Ok(state.known_keys.clone()))
    }

    pub async fn history(
        &self,
        _ctx: ::tarpc::context::Context,
        _token: auth::Token,
    ) -> ::core::result::Result<
        RpcResult<Vec<(Digest, BlockHeight, Timestamp, NativeCurrencyAmount)>>,
        ::tarpc::client::RpcError,
    > {
        tokio::task::yield_now().await;
        let state = self.state.lock().unwrap();
        Ok(Ok(state.history.clone()))
    }

    pub async fn mempool_overview(
        &self,
        _ctx: ::tarpc::context::Context,
        _token: auth::Token,
        page_start: usize,
        page_size: usize,
    ) -> ::core::result::Result<RpcResult<Vec<MempoolTransactionInfo>>, ::tarpc::client::RpcError>
    {
        tokio::task::yield_now().await;
        let state = self.state.lock().unwrap();

        let total_num_entries = state.mempool_transactions.len();
        let range_start = usize::min(page_start * page_size, total_num_entries);
        let range_stop = usize::min((page_start + 1) * page_size, total_num_entries);

        let result = state.mempool_transactions[range_start..range_stop].to_vec();
        Ok(Ok(result))
    }

    pub async fn peer_info(
        &self,
        _ctx: ::tarpc::context::Context,
        _token: auth::Token,
    ) -> ::core::result::Result<RpcResult<Vec<PeerInfo>>, ::tarpc::client::RpcError> {
        tokio::task::yield_now().await;
        let state = self.state.lock().unwrap();
        Ok(Ok(state.peers.clone()))
    }

    pub async fn latest_address(
        &self,
        _ctx: ::tarpc::context::Context,
        _token: auth::Token,
        address_type: KeyType,
    ) -> ::core::result::Result<RpcResult<ReceivingAddress>, ::tarpc::client::RpcError> {
        tokio::task::yield_now().await;
        let state = self.state.lock().unwrap();
        let receiving_address = match address_type {
            KeyType::Generation => state.generation_address.clone(),
            KeyType::Symmetric => state.symmetric_address.clone(),
        };
        Ok(Ok(receiving_address))
    }

    pub async fn next_receiving_address(
        &self,
        _ctx: ::tarpc::context::Context,
        _token: auth::Token,
        address_type: KeyType,
    ) -> ::core::result::Result<RpcResult<ReceivingAddress>, ::tarpc::client::RpcError> {
        tokio::task::yield_now().await;
        let mut state = self.state.lock().unwrap();
        let receiving_address = match address_type {
            KeyType::Generation => {
                state.generation_address =
                    GenerationReceivingAddress::derive_from_seed(rng().random()).into();
                state.generation_address.clone()
            }
            KeyType::Symmetric => {
                state.symmetric_address = neptune_cash::api::export::ReceivingAddress::Symmetric(
                    SymmetricKey::from_seed(rng().random()),
                );
                state.symmetric_address.clone()
            }
        };
        Ok(Ok(receiving_address))
    }

    pub async fn send(
        &self,
        _ctx: ::tarpc::context::Context,
        _token: auth::Token,
        _outputs: Vec<OutputFormat>,
        _change_policy: ChangePolicy,
        _fee: NativeCurrencyAmount,
    ) -> ::core::result::Result<RpcResult<TxCreationArtifacts>, ::tarpc::client::RpcError> {
        tokio::task::yield_now().await;
        Ok(Err(RpcError::Failed("cannot send; mocking".to_string())))
    }

    pub async fn list_utxos(
        &self,
        _ctx: ::tarpc::context::Context,
        _token: auth::Token,
    ) -> ::core::result::Result<RpcResult<Vec<UiUtxo>>, ::tarpc::client::RpcError> {
        tokio::task::yield_now().await;
        let state = self.state.lock().unwrap();
        Ok(Ok(state.utxos.clone()))
    }

    pub async fn clear_standing_by_ip(
        &self,
        _ctx: ::tarpc::context::Context,
        _token: auth::Token,
        peer_ip: IpAddr,
    ) -> ::core::result::Result<RpcResult<()>, ::tarpc::client::RpcError> {
        tokio::task::yield_now().await;
        // can't modify PeerInfo from outside neptune-core crate since all fields and
        // constructors are pub(crate). to show any ui behavior, we just replace the peer with a new random one
        let mut state = self.state.lock().unwrap();
        if let Some(idx) = state.peers.iter().position(|p| {
            p.address()
                .iter()
                .find_map(|component| match component {
                    multiaddr::Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
                    multiaddr::Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
                    _ => None,
                })
                .is_some_and(|ip| ip == peer_ip)
        }) {
            let mut rng = StdRng::from_seed(rng().random());
            state.peers[idx] = rng.random();
        }
        Ok(Ok(()))
    }
}
