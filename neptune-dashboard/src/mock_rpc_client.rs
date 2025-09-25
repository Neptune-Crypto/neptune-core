use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;

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
use rand::RngCore;
use rand::SeedableRng;
use tasm_lib::prelude::Digest;

#[derive(Debug, Clone)]
pub(crate) struct MockRpcClient {
    seed: [u8; 32],
}

impl MockRpcClient {
    pub(crate) fn new() -> Self {
        Self {
            seed: rng().random(),
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
        fn random_socket_addr() -> SocketAddr {
            let mut rng = rng();
            let ip = IpAddr::V4(Ipv4Addr::new(
                rng.random(),
                rng.random(),
                rng.random(),
                rng.random(),
            ));
            let port = rng.random_range(1..65535);
            SocketAddr::new(ip, port)
        }
        tokio::task::yield_now().await;
        Ok(Ok(Some(random_socket_addr())))
    }

    pub(crate) async fn dashboard_overview_data(
        &self,
        _ctx: ::tarpc::context::Context,
        _token: auth::Token,
    ) -> ::core::result::Result<RpcResult<OverviewData>, ::tarpc::client::RpcError> {
        let mut rng = StdRng::from_seed(self.seed);
        let data = rng.random();
        tokio::task::yield_now().await;
        Ok(RpcResult::Ok(data))
    }

    pub async fn known_keys(
        &self,
        _ctx: ::tarpc::context::Context,
        _token: auth::Token,
    ) -> ::core::result::Result<RpcResult<Vec<SpendingKey>>, ::tarpc::client::RpcError> {
        let mut rng = StdRng::from_seed(self.seed);
        tokio::task::yield_now().await;
        let mut known_keys = vec![];
        for _ in 0..rng.random_range(1..100) {
            match rng.random_range(0..2) {
                0 => {
                    known_keys.push(SpendingKey::from(GenerationSpendingKey::derive_from_seed(
                        rng.random(),
                    )));
                }
                1 => {
                    known_keys.push(SpendingKey::from(SymmetricKey::from_seed(rng.random())));
                }
                _ => {
                    unreachable!()
                }
            }
        }
        Ok(Ok(known_keys))
    }

    pub async fn history(
        &self,
        _ctx: ::tarpc::context::Context,
        _token: auth::Token,
    ) -> ::core::result::Result<
        RpcResult<Vec<(Digest, BlockHeight, Timestamp, NativeCurrencyAmount)>>,
        ::tarpc::client::RpcError,
    > {
        let mut rng = StdRng::from_seed(self.seed);
        tokio::task::yield_now().await;
        let mut history = vec![];

        for _ in 0..rng.random_range(0..100) {
            let digest = rng.random::<Digest>();
            let block_height = rng.random::<BlockHeight>();
            let timestamp = rng.random::<Timestamp>();
            let native_currency_amount = rng
                .random::<NativeCurrencyAmount>()
                .lossy_f64_fraction_mul(0.0001);
            history.push((digest, block_height, timestamp, native_currency_amount));
        }

        Ok(Ok(history))
    }

    pub async fn mempool_overview(
        &self,
        _ctx: ::tarpc::context::Context,
        _token: auth::Token,
        page_start: usize,
        page_size: usize,
    ) -> ::core::result::Result<RpcResult<Vec<MempoolTransactionInfo>>, ::tarpc::client::RpcError>
    {
        let mut rng = StdRng::from_seed(self.seed);
        let total_num_entries = rng.random_range(5..100);
        let mut rng = StdRng::seed_from_u64(rng.next_u64().wrapping_add(page_start as u64));

        tokio::task::yield_now().await;
        let mut mempool_transactions = vec![];

        let range_start = usize::min(page_start * page_size, total_num_entries);
        let range_stop = usize::min((page_start + 1) * page_size, total_num_entries);
        for _ in range_start..range_stop {
            mempool_transactions.push(rng.random());
        }

        Ok(Ok(mempool_transactions))
    }

    pub async fn peer_info(
        &self,
        _ctx: ::tarpc::context::Context,
        _token: auth::Token,
    ) -> ::core::result::Result<RpcResult<Vec<PeerInfo>>, ::tarpc::client::RpcError> {
        let mut rng = StdRng::from_seed(self.seed);
        tokio::task::yield_now().await;

        let num_peers = rng.random_range(1..10);
        let mut peers = vec![];
        for _ in 0..num_peers {
            peers.push(rng.random());
        }

        Ok(Ok(peers))
    }

    pub async fn next_receiving_address(
        &self,
        _ctx: ::tarpc::context::Context,
        _token: auth::Token,
        address_type: KeyType,
    ) -> ::core::result::Result<RpcResult<ReceivingAddress>, ::tarpc::client::RpcError> {
        let mut rng = StdRng::from_seed(self.seed);
        tokio::task::yield_now().await;
        let receiving_address = match address_type {
            KeyType::Generation => {
                ReceivingAddress::from(GenerationReceivingAddress::derive_from_seed(rng.random()))
            }
            KeyType::Symmetric => ReceivingAddress::from(SymmetricKey::from_seed(rng.random())),
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
        // thank you!
        tokio::task::yield_now().await;
        Ok(Err(RpcError::Failed("cannot send; mocking".to_string())))
    }

    pub async fn list_utxos(
        &self,
        _ctx: ::tarpc::context::Context,
        _token: auth::Token,
    ) -> ::core::result::Result<RpcResult<Vec<UiUtxo>>, ::tarpc::client::RpcError> {
        let mut rng = StdRng::from_seed(self.seed);
        tokio::task::yield_now().await;

        let num_utxos = rng.random_range(1..20);
        let mut utxos = vec![];
        for _ in 0..num_utxos {
            let utxo = UiUtxo {
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
            };
            utxos.push(utxo);
        }
        Ok(Ok(utxos))
    }
}
