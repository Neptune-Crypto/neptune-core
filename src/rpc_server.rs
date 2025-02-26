//! implements an RPC server and client based on [tarpc]
//!
//! request and response data is json serialized.
//!
//! It is presently easiest to create a tarpc client in rust.
//! To do so, one should add neptune-cash as a dependency and
//! then do something like:
//!
//! ```no_run
//! use anyhow::Result;
//! use neptune_cash::rpc_server::RPCClient;
//! use neptune_cash::rpc_auth;
//! use tarpc::tokio_serde::formats::Json;
//! use tarpc::serde_transport::tcp;
//! use tarpc::client;
//! use tarpc::context;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<()>{
//! // create a serde/json transport over tcp.
//! let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
//!
//! // create an rpc client using the transport.
//! let client = RPCClient::new(client::Config::default(), transport).spawn();
//!
//! // query neptune-core server how to find the cookie file
//! let cookie_hint = client.cookie_hint(context::current()).await.unwrap().unwrap();
//!
//! // load the cookie file from disk and assign it to a token.
//! let token: rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
//!
//! // query any RPC API, passing the auth token.  here we query block_height.
//! let block_height = client.block_height(context::current(), token).await??;
//! # Ok(())
//! # }
//! ```
//!
//! For other languages, one would need to connect to the RPC TCP port and then
//! manually construct the appropriate json method call.  Examples of this will
//! be forthcoming in the future.
//!
//! See [rpc_auth] for descriptions of the authentication mechanisms.
//!
//! Every RPC method returns an [RpcResult] which is wrapped inside a
//! [tarpc::Response] by the rpc server.
use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;

use anyhow::anyhow;
use anyhow::Result;
use get_size2::GetSize;
use itertools::Itertools;
use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;
use systemstat::Platform;
use systemstat::System;
use tarpc::context;
use tasm_lib::twenty_first::prelude::Mmr;
use tracing::error;
use tracing::info;
use tracing::warn;
use twenty_first::math::digest::Digest;

use crate::config_models::network::Network;
use crate::macros::fn_name;
use crate::macros::log_slow_scope;
use crate::models::blockchain::block::block_header::BlockHeader;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::block_info::BlockInfo;
use crate::models::blockchain::block::block_selector::BlockSelector;
use crate::models::blockchain::block::difficulty_control::Difficulty;
use crate::models::blockchain::transaction::Transaction;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::channel::ClaimUtxoData;
use crate::models::channel::RPCServerToMain;
use crate::models::peer::peer_info::PeerInfo;
use crate::models::peer::InstanceId;
use crate::models::peer::PeerStanding;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::mining_status::MiningStatus;
use crate::models::state::transaction_kernel_id::TransactionKernelId;
use crate::models::state::tx_proving_capability::TxProvingCapability;
use crate::models::state::wallet::address::encrypted_utxo_notification::EncryptedUtxoNotification;
use crate::models::state::wallet::address::KeyType;
use crate::models::state::wallet::address::ReceivingAddress;
use crate::models::state::wallet::address::SpendingKey;
use crate::models::state::wallet::coin_with_possible_timelock::CoinWithPossibleTimeLock;
use crate::models::state::wallet::expected_utxo::UtxoNotifier;
use crate::models::state::wallet::incoming_utxo::IncomingUtxo;
use crate::models::state::wallet::monitored_utxo::MonitoredUtxo;
use crate::models::state::wallet::utxo_notification::PrivateNotificationData;
use crate::models::state::wallet::utxo_notification::UtxoNotificationMedium;
use crate::models::state::wallet::wallet_status::WalletStatus;
use crate::models::state::GlobalState;
use crate::models::state::GlobalStateLock;
use crate::prelude::twenty_first;
use crate::rpc_auth;
use crate::twenty_first::prelude::Tip5;
use crate::DataDirectory;

/// result returned by RPC methods
pub type RpcResult<T> = Result<T, error::RpcError>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DashBoardOverviewDataFromClient {
    pub tip_digest: Digest,
    pub tip_header: BlockHeader,
    pub syncing: bool,
    pub confirmed_available_balance: NativeCurrencyAmount,
    pub confirmed_total_balance: NativeCurrencyAmount,
    pub unconfirmed_available_balance: NativeCurrencyAmount,
    pub unconfirmed_total_balance: NativeCurrencyAmount,
    pub mempool_size: usize,
    pub mempool_total_tx_count: usize,
    pub mempool_own_tx_count: usize,

    // `None` symbolizes failure in getting peer count
    pub peer_count: Option<usize>,
    pub max_num_peers: usize,

    // `None` symbolizes failure to get mining status
    pub mining_status: Option<MiningStatus>,

    pub proving_capability: TxProvingCapability,

    // # of confirmations of the last wallet balance change.
    //
    // Starts at 1, as the block in which a tx is included is considered the 1st
    // confirmation.
    //
    // `None` indicates that wallet balance has never changed.
    pub confirmations: Option<BlockHeight>,

    /// CPU temperature in degrees Celcius
    pub cpu_temp: Option<f32>,
}

#[derive(Clone, Debug, Copy, Serialize, Deserialize, strum::Display)]
pub enum TransactionProofType {
    SingleProof,
    ProofCollection,
    PrimitiveWitness,
}

#[derive(Clone, Debug, Copy, Serialize, Deserialize)]
pub struct MempoolTransactionInfo {
    pub id: TransactionKernelId,
    pub proof_type: TransactionProofType,
    pub num_inputs: usize,
    pub num_outputs: usize,
    pub positive_balance_effect: NativeCurrencyAmount,
    pub negative_balance_effect: NativeCurrencyAmount,
    pub fee: NativeCurrencyAmount,
    pub synced: bool,
}

impl From<&Transaction> for MempoolTransactionInfo {
    fn from(mptx: &Transaction) -> Self {
        MempoolTransactionInfo {
            id: mptx.kernel.txid(),
            proof_type: match mptx.proof {
                TransactionProof::Witness(_) => TransactionProofType::PrimitiveWitness,
                TransactionProof::SingleProof(_) => TransactionProofType::SingleProof,
                TransactionProof::ProofCollection(_) => TransactionProofType::ProofCollection,
            },
            num_inputs: mptx.kernel.inputs.len(),
            num_outputs: mptx.kernel.outputs.len(),
            positive_balance_effect: NativeCurrencyAmount::zero(),
            negative_balance_effect: NativeCurrencyAmount::zero(),
            fee: mptx.kernel.fee,
            synced: false,
        }
    }
}

impl MempoolTransactionInfo {
    pub(crate) fn with_positive_effect_on_balance(
        mut self,
        positive_balance_effect: NativeCurrencyAmount,
    ) -> Self {
        self.positive_balance_effect = positive_balance_effect;
        self
    }

    pub(crate) fn with_negative_effect_on_balance(
        mut self,
        negative_balance_effect: NativeCurrencyAmount,
    ) -> Self {
        self.negative_balance_effect = negative_balance_effect;
        self
    }

    pub fn synced(mut self) -> Self {
        self.synced = true;
        self
    }
}

#[tarpc::service]
pub trait RPC {
    /******** READ DATA ********/
    // Place all methods that only read here
    /// Returns a [rpc_auth::CookieHint] for purposes of zero-conf authentication
    ///
    /// The CookieHint provides a location for the cookie file used by this
    /// neptune-core instance as well as the [Network].
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// // query neptune-core server how to find the cookie file
    /// let cookie_hint = client.cookie_hint(context::current()).await??;
    /// # Ok(())
    /// # }
    /// ```
    /// this method does not require authentication because local clients must
    /// be able to call this method in order to bootstrap cookie-based
    /// authentication.
    ///
    async fn cookie_hint() -> RpcResult<rpc_auth::CookieHint>;

    /// Return the network this neptune-core instance is running
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// // query neptune-core server the network it is running on.
    /// let network = client.network(context::current()).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn network() -> RpcResult<Network>;

    /// Returns local socket used for incoming peer-connections. Does not show
    /// the public IP address, as the client does not know this.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get local socket used for incoming peer-connections.
    /// let own_listen_address = client.own_listen_address_for_peers(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn own_listen_address_for_peers(token: rpc_auth::Token) -> RpcResult<Option<SocketAddr>>;

    /// Return the node's instance-ID which is a globally unique random generated number
    /// set at startup used to ensure that the node does not connect to itself, or the
    /// same peer twice.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get own instance ID.
    /// let own_instance_id = client.own_instance_id(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn own_instance_id(token: rpc_auth::Token) -> RpcResult<InstanceId>;

    /// Returns the current block height.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get the block height.
    /// let block_height = client.block_height(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn block_height(token: rpc_auth::Token) -> RpcResult<BlockHeight>;

    /// Returns the number of blocks (confirmations) since wallet balance last changed.
    ///
    /// returns `Option<BlockHeight>`
    ///
    /// return value will be None if wallet has not received any incoming funds.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get the blocks since wallet balance changed.
    /// let block_height = client.confirmations(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn confirmations(token: rpc_auth::Token) -> RpcResult<Option<BlockHeight>>;

    /// Returns info about the peers we are connected to
    ///
    /// return value will be None if wallet has not received any incoming funds.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> anyhow::Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get the info about the peers we are connected to
    /// let peers = client.peer_info(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn peer_info(token: rpc_auth::Token) -> RpcResult<Vec<PeerInfo>>;

    /// Return info about all peers that have been negatively sanctioned.
    ///
    /// return value will be None if wallet has not received any incoming funds.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get the info about the peers that are negatively sanctioned
    /// let punished_peers = client.all_punished_peers(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn all_punished_peers(token: rpc_auth::Token)
        -> RpcResult<HashMap<IpAddr, PeerStanding>>;

    /// Returns the digest of the latest n blocks
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // number of latest blocks digests you want to get
    /// let n : usize = 10;
    ///
    /// // query neptune-core server to get the digests of the n latest blocks
    /// let latest_tip_digests = client.latest_tip_digests(context::current(), token, n).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn latest_tip_digests(token: rpc_auth::Token, n: usize) -> RpcResult<Vec<Digest>>;

    /// Returns information about the specified block if found
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// use neptune_cash::models::blockchain::block::block_selector::BlockSelector;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // set the way to look up for a block : it can be `Digest`, `Height`, `Genesis`, `Tip`
    /// let block_selector : BlockSelector = BlockSelector::Genesis;
    ///
    /// // query neptune-core server to get block info
    /// let latest_tip_digests = client.block_info(context::current(), token, block_selector).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn block_info(
        token: rpc_auth::Token,
        block_selector: BlockSelector,
    ) -> RpcResult<Option<BlockInfo>>;

    /// Return the digests of known blocks with specified height.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// use neptune_cash::models::blockchain::block::block_selector::BlockSelector;
    /// use neptune_cash::models::blockchain::block::block_height::BlockHeight;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // set block height value to genesis bloc
    /// let height : BlockHeight = BlockHeight::genesis();
    ///
    /// // query neptune-core server to block digests by height
    /// let block_digests_by_height = client.block_digests_by_height(context::current(), token, height).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn block_digests_by_height(
        token: rpc_auth::Token,
        height: BlockHeight,
    ) -> RpcResult<Vec<Digest>>;

    /// Return the digest for the specified block if found
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// use neptune_cash::models::blockchain::block::block_selector::BlockSelector;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // set the way to look up for a block : it can be `Digest`, `Height`, `Genesis`, `Tip`
    /// let block_selector : BlockSelector = BlockSelector::Tip;
    ///
    /// // query neptune-core server to get block digest
    /// let block_digest = client.block_digest(context::current(), token, block_selector).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn block_digest(
        token: rpc_auth::Token,
        block_selector: BlockSelector,
    ) -> RpcResult<Option<Digest>>;

    /// Return the digest for the specified UTXO leaf index if found
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// use neptune_cash::models::blockchain::block::block_selector::BlockSelector;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // leaf index is set to 5
    /// let leaf_index : u64 = 5;
    ///
    /// // query neptune-core server to get utxo digest
    /// let block_digest = client.utxo_digest(context::current(), token, leaf_index).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn utxo_digest(token: rpc_auth::Token, leaf_index: u64) -> RpcResult<Option<Digest>>;

    /// Return the block header for the specified block
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// use neptune_cash::models::blockchain::block::block_selector::BlockSelector;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // set the way to look up for a block : it can be `Digest`, `Height`, `Genesis`, `Tip`
    /// let block_selector : BlockSelector = BlockSelector::Genesis;
    ///
    /// // query neptune-core server to get block header
    /// let block_header = client.header(context::current(), token, block_selector).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn header(
        token: rpc_auth::Token,
        block_selector: BlockSelector,
    ) -> RpcResult<Option<BlockHeader>>;

    /// Get sum of confirmed, unspent, available UTXOs
    /// excludes time-locked utxos
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get sum of confirmed unspent UTXO
    /// let confirmed_available_balance = client.confirmed_available_balance(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn confirmed_available_balance(token: rpc_auth::Token)
        -> RpcResult<NativeCurrencyAmount>;

    /// Get sum of unconfirmed, unspent available UTXOs
    /// includes mempool transactions, excludes time-locked utxos
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get sum of unconfirmed unspent UTXOs
    /// let unconfirmed_available_balance = client.unconfirmed_available_balance(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn unconfirmed_available_balance(
        token: rpc_auth::Token,
    ) -> RpcResult<NativeCurrencyAmount>;

    /// Get the client's wallet transaction history
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get history of transactions, a vec containing digest, block height, timestamp and neptune coins tuples.
    /// let history_transactions = client.history(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn history(
        token: rpc_auth::Token,
    ) -> RpcResult<Vec<(Digest, BlockHeight, Timestamp, NativeCurrencyAmount)>>;

    /// Return information about funds in the wallet
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get the funds in the wallet
    /// let wallet_status = client.wallet_status(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn wallet_status(token: rpc_auth::Token) -> RpcResult<WalletStatus>;

    /// Return the number of expected UTXOs, including already received UTXOs.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get the number of expected utxos including already received ones.
    /// let wallet_status = client.num_expected_utxos(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn num_expected_utxos(token: rpc_auth::Token) -> RpcResult<u64>;

    /// Return an address that this client can receive funds on
    /// Return the number of expected UTXOs, including already received UTXOs.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// use neptune_cash::models::state::wallet::address::KeyType;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // set cryptographic key type for receiving funds
    /// let key_type = KeyType::Symmetric;
    ///
    /// // query neptune-core server to get a receiving address
    /// let wallet_status = client.next_receiving_address(context::current(), token, key_type).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn next_receiving_address(
        token: rpc_auth::Token,
        key_type: KeyType,
    ) -> RpcResult<Option<ReceivingAddress>>;

    /// Return all known keys, for every [KeyType]
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get all known keys for every [KeyType]
    /// let known_keys = client.known_keys(context::current(), token ).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn known_keys(token: rpc_auth::Token) -> RpcResult<Vec<SpendingKey>>;

    /// Return known keys for the provided [KeyType]
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// use neptune_cash::models::state::wallet::address::KeyType;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // set a key type
    /// let key_type = KeyType::Symmetric;
    ///
    /// // query neptune-core server to get all known keys by [KeyType]
    /// let known_keys_by_keytype = client.known_keys_by_keytype(context::current(), token, key_type ).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn known_keys_by_keytype(
        token: rpc_auth::Token,
        key_type: KeyType,
    ) -> RpcResult<Vec<SpendingKey>>;

    /// Return the number of transactions in the mempool
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get the number of transactions in the mempool
    /// let mempool_tx_count = client.mempool_tx_count(context::current(), token ).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn mempool_tx_count(token: rpc_auth::Token) -> RpcResult<usize>;

    // TODO: Change to return current size and max size
    async fn mempool_size(token: rpc_auth::Token) -> RpcResult<usize>;

    /// Return info about the transactions in the mempool
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // index to start from in the mempool
    /// let start_index : usize = 37;
    ///
    /// // number of transactions
    /// let number : usize = 8;
    ///
    /// // query neptune-core server to get the info of transactions in the mempool
    /// let mempool_overview = client.mempool_overview(context::current(), token, start_index, number ).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn mempool_overview(
        token: rpc_auth::Token,
        start_index: usize,
        number: usize,
    ) -> RpcResult<Vec<MempoolTransactionInfo>>;

    /// Return the information used on the dashboard's overview tab
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get the info used on dashboard overview tab
    /// let dashboard_data = client.dashboard_overview_data(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn dashboard_overview_data(
        token: rpc_auth::Token,
    ) -> RpcResult<DashBoardOverviewDataFromClient>;

    /// Determine whether the user-supplied string is a valid address
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// use neptune_cash::config_models::network::Network;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // address to validate
    /// let address : String = "0x484389349834834DF23".to_string();
    ///
    /// // network type
    /// let network : Network = Network::Main;
    ///
    /// // query neptune-core server to check if the supplied address is valid
    /// let is_valid_address = client.validate_address(context::current(), token, address, network).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn validate_address(
        token: rpc_auth::Token,
        address: String,
        network: Network,
    ) -> RpcResult<Option<ReceivingAddress>>;

    /// Determine whether the user-supplied string is a valid amount
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // address to validate
    /// let amount : String = "132".to_string();
    ///
    /// // query neptune-core server to determine if the amount is valid
    /// let is_valid_address = client.validate_amount(context::current(), token, amount ).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn validate_amount(
        token: rpc_auth::Token,
        amount: String,
    ) -> RpcResult<Option<NativeCurrencyAmount>>;

    /// Determine whether the given amount is less than (or equal to) the balance
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// use neptune_cash::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // setting the amount to 47
    /// let amount : NativeCurrencyAmount = NativeCurrencyAmount::coins(47);
    ///
    /// // query neptune-core server to determine if the amount is less than or equal to the balance
    /// let amount_less_or_equals_balance = client.amount_leq_confirmed_available_balance(context::current(), token, amount ).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn amount_leq_confirmed_available_balance(
        token: rpc_auth::Token,
        amount: NativeCurrencyAmount,
    ) -> RpcResult<bool>;

    /// Generate a report of all owned and unspent coins, whether time-locked or not.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get the list of owned and unspent coins
    /// let own_coins = client.list_own_coins(context::current(), token ).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn list_own_coins(token: rpc_auth::Token) -> RpcResult<Vec<CoinWithPossibleTimeLock>>;

    /// Get CPU temperature.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server instance to get its CPU temperature
    /// let cpu_temperature = client.cpu_temp(context::current(), token ).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn cpu_temp(token: rpc_auth::Token) -> RpcResult<Option<f32>>;

    /******** BLOCKCHAIN STATISTICS ********/
    // Place all endpoints that relate to statistics of the blockchain here

    /// Return the block intervals of a range of blocks. Return value is the
    /// number of milliseconds it took to mine the (canonical) block with the
    /// specified height. Does not include the interval between genesis block
    /// and block 1 since genesis block was not actually mined and its timestamp
    /// doesn't carry the same meaning as those of later blocks.
    async fn block_intervals(
        token: rpc_auth::Token,
        last_block: BlockSelector,
        max_num_blocks: Option<usize>,
    ) -> RpcResult<Option<Vec<(u64, u64)>>>;

    /// Return the difficulties of a range of blocks.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// use neptune_cash::models::blockchain::block::block_selector::BlockSelector;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // sets the last block
    /// let last_block : BlockSelector = BlockSelector::Genesis;
    ///
    /// // set maximum number of blocks to 5 blocks
    /// let max_num_blocks : Option<usize> = Some(5);
    ///
    /// // query neptune-core server to get difficulties of a range of blocks
    /// let block_difficulties = client.block_difficulties(context::current(), token, last_block, max_num_blocks).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn block_difficulties(
        token: rpc_auth::Token,
        last_block: BlockSelector,
        max_num_blocks: Option<usize>,
    ) -> RpcResult<Vec<(u64, Difficulty)>>;

    /******** CHANGE THINGS ********/
    // Place all things that change state here

    /// Clears standing for all peers, connected or not
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // neptune-core server clears standing for all peers that are connected or not
    /// let _ = client.clear_all_standings(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn clear_all_standings(token: rpc_auth::Token) -> RpcResult<()>;

    /// Clears standing for ip, whether connected or not
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// # use std::net::{IpAddr, Ipv4Addr};
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// // create an rpc client using the transport.
    /// let client = RPCClient::new(client::Config::default(), transport).spawn();
    ///
    /// // Defines cookie hint
    /// let cookie_hint = client.cookie_hint(context::current()).await??;
    ///
    /// // load the cookie file from disk and assign it to a token
    /// let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    ///
    /// // IP address 87.23.90.12 to clear standing
    /// let ip = IpAddr::V4(Ipv4Addr::new(87, 23, 90, 12));
    ///
    /// // neptune-core server clears standing for all peers that are connected or not
    /// let _ = client.clear_standing_by_ip(context::current(), token, ip).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn clear_standing_by_ip(token: rpc_auth::Token, ip: IpAddr) -> RpcResult<()>;

    /// Send coins to a single recipient.
    ///
    /// See docs for [send_to_many()](Self::send_to_many())
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::config_models::network::Network;
    /// # use neptune_cash::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
    /// # use neptune_cash::models::state::wallet::address::ReceivingAddress;
    /// # use neptune_cash::models::state::wallet::utxo_notification::UtxoNotificationMedium;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// # use std::net::IpAddr;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // Send amount set to 20 coins
    /// let amount : NativeCurrencyAmount = NativeCurrencyAmount::coins(20);
    /// // The coins receiving address
    /// let address = ReceivingAddress::from_bech32m("nolgam1lf8vc5xpa4jf9vjakts632fct5q80d4m6tax39nrl8c55dta2h7n7lnkh9pmwckl0ndwc7897xwfgx5vv02xdt3099z62222wazz7tjl6umzewla9xzxyqefh2w47v4eh0xzvfsxjk6kq5u84rwwlflq7cs726ljttl6ls860te04cwpy5kk8n40qqjnps0gdp46namhsa3cqt0uc0s5e34h6s5rw2kl77uvvs4rlnn5t8wtuefsduuccwsxmk27r8d48g49swgafhj6wmvu5cx3lweqhnxgdgm7mmdq7ck6wkurw2jzl64k9u34kzgu9stgd47ljzte0hz0n2lcng83vtpf0u9f4hggw4llqsz2fqpe4096d9v5fzg7xvxg6zvr7gksq4yqgn8shepg5xsczmzz256m9c6r8zqdkzy4tk9he59ndtdkrrr8u5v6ztnvkvmy4sed7p7plm2y09sgksw6zcjayls4wl9fnqu97kyx9cdknksar7h8jetygur979rt5arcwmvp2dy3ynt6arna2yjpevt9209v9g2p5cvp6gjp9850w3w6afeg8yuhp6u447hrudcssyjauqa2p7jk4tz37wg70yrdhsgn35sc0hdkclvpapu75dgtmswk0vtgadx44mqdps6ry6005xqups9dpc93u66qj9j7lfaqgdqrrfg9pkxhjl99ge387rh257x2phfvjvc8y66p22wax8myyhm7mgmlxu9gug0km3lmn4lzcyj32mduy6msy4kfn5z2tr67zfxadnj6wc0av27mk0j90pf67uzp9ps8aekr24kpv5n3qeczfznen9vj67ft95s93t26l8uh87qr6kp8lsyuzm4h36de830h6rr3lhg5ac995nrsu6h0p56t5tnglvx0s02mr0ts95fgcevveky5kkw6zgj6jd5m3n5ljhw862km8sedr30xvg8t9vh409ufuxdnfuypvqdq49z6mp46p936pjzwwqjda6yy5wuxx9lffrxwcmfqzch6nz2l4mwd2vlsdr58vhygppy6nm6tduyemw4clwj9uac4v990xt6jt7e2al7m6sjlq4qgxfjf4ytx8f5j460vvr7yac9hsvlsat2vh5gl55mt4wr7v5p3m6k5ya5442xdarastxlmpf2vqz5lusp8tlglxkj0jksgwqgtj6j0kxwmw40egpzs5rr996xpv8wwqyja4tmw599n9fh77f5ruxk69vtpwl9z5ezmdn92cpyyhwff59ypp0z5rv98vdvm67umqzt0ljjan30u3a8nga35fdy450ht9gef24mveucxqwv5aflge5r3amxsvd7l30j9kcqm7alq0ks2wqpde7pdct2gmvafxvjg3ad0a3h58assjaszvmykl3k5tn238gstm2shlvad4a53mm5ztvp5q2zt4pdzj0ssevlkumwhc0g5cxnxc9u7rh9gffkq7h9ufcxkgtghe32sv3vwzkessr52mcmajt83lvz45wqru9hht8cytfedtjlv7z7en6pp0guja85ft3rv6hzf2e02e7wfu38s0nyfzkc2qy2k298qtmxgrpduntejtvenr80csnckajnhu44399tkm0a7wdldalf678n9prd54twwlw24xhppxqlquatfztllkeejlkfxuayddwagh6uzx040tqlcs7hcflnu0ywynmz0chz48qcx7dsc4gpseu0dqvmmezpuv0tawm78nleju2vp4lkehua56hrnuj2wuc5lqvxlnskvp53vu7e2399pgp7xcwe3ww23qcd9pywladq34nk6cwcvtj3vdfgwf6r7s6vq46y2x05e043nj6tu8am2und8z3ftf3he5ccjxamtnmxfd79m04ph36kzx6e789dhqrwmwcfrn9ulsedeplk3dvrmad6f20y9qfl6n6kzaxkmmmaq4d6s5rl4kmhc7fcdkrkandw2jxdjckuscu56syly8rtjatj4j2ug23cwvep3dgcdvmtr32296nf9vdl3rcu0r7hge23ydt83k5nhtnexuqrnamveacz6c43eay9nz4pjjwjatkgp80lg9tnf5kdr2eel8s2fk6v338x4hu00htemm5pq6qlucqqq5tchhtekjzdu50erqd2fkdu9th3wl0mqxz5u7wnpgwgpammv2yqpa5znljegyhke0dz9vg27uh5t5x6qdgf7vu54lqssejekwzfxchjyq2s8frm9fmt688w76aug56v6n3w5xdre78xplfsdw3e4j6dc5w7tf83r25re0duq6h8z54wnkqr9yh2k0skjqea4elgcr4aw7hks9m8w3tx8w9xlxpqqll2zeql55ew7e90dyuynkqxfuqzv45t22ljamdll3udvqrllprdltthzm866jdaxkkrnryj4cmc2m7sk99clgql3ynrhe9kynqn4mh3tepk8dtq7cndtc2hma29s4cuylsvg04s70uyr53w5656su5rjem5egss08zrfaef0mww6t8pr26uph2n8a2cs55ydx4xhasjqk7xs0akh6f26j2ec4d8pd0kdf4jya6p9jl48wmy5autdpw2q8mehrq6kypt573genj66l5zkq6xvrdqugmfczxa2gj9ylx3pgpjqnhuem9udfkj9qr2y8lh728sr7uaedu5wwmfa72ykh395jqh7f7f9p2gskn6u7k844kpnwe3eqv84pl53r6x9af88a8ey7298njdg03h8mxqz2x6z8ys3qpuxq768tjq0zhrnjgns8d78euzwsvx6vn4f9tftrp68zcch3h75mc9drpt7tpvnyyqfjuqclxhdwhdwtsakecv04p9r3jx90htql9a3ht5mxrj4ercv4cd52wk4qhu7dn4tqe7yclqx2l36gcsrzmdlv440qls7qjpq6k95mst485vpennnur8h62a7d7syvyer89qtyfzlfhz8a5a0x5tuwhc9mah0e944xzhsc6uvpv8vat44w7r3xyw8q85y77jux8zhndrhdn36swryffqmpkxgcw4g29q40sul4fl5vrfru08a5j3rd3jl8799srpf2xqpxq38wwvhr4mxqf5wwdqfqq7harshggvufzlgn0l9fq0j76dyuge75jmzy8celvw6wesfs82n4jw2k8jnus2zds5a67my339uuzka4w72tau6j7wyu0lla0mcjpaflphsuy7f2phev6tr8vc9nj2mczkeg4vy3n5jkgecwgrvwu3vw9x5knpkxzv8kw3dpzzxy3rvrs56vxw8ugmyz2vdj6dakjyq3feym4290l7hgdt0ac5u49sekezzf0ghwmlek4h75fkzpvuly9zupw32dd3l9my282nekgk78fe6ayjyhczetxf8r82yd2askl52kmupr9xaxw0jd08dsd3523ea6ge48384rlmt4mu4w4x0q9s", Network::Main)?;
    /// // owned utxo notify method
    /// let notify_self : UtxoNotificationMedium = UtxoNotificationMedium::OnChain;
    /// #
    /// // unwowned utxo notify method
    /// let notify_other : UtxoNotificationMedium = UtxoNotificationMedium::OnChain;
    /// #
    /// // Max fee
    /// let fee : NativeCurrencyAmount = NativeCurrencyAmount::coins(10);
    /// #
    /// // neptune-core server sends token to a single receipient
    /// let send_result = client.send(context::current(), token, amount, address, notify_self, notify_other, fee).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn send(
        token: rpc_auth::Token,
        amount: NativeCurrencyAmount,
        address: ReceivingAddress,
        owned_utxo_notify_method: UtxoNotificationMedium,
        unowned_utxo_notify_medium: UtxoNotificationMedium,
        fee: NativeCurrencyAmount,
    ) -> RpcResult<(TransactionKernelId, Vec<PrivateNotificationData>)>;

    /// Send coins to multiple recipients
    ///
    /// note: sending is rate-limited to 2 sends per block until block
    /// 25000 is reached.
    ///
    /// `outputs` is a list of transaction outputs in the format
    /// `[(address:amount)]`.  The address may be any type supported by
    /// [ReceivingAddress].
    ///
    /// `owned_utxo_notify_method` specifies how our wallet will be notified of
    /// any outputs destined for it. This includes the change output if one is
    /// necessary. [UtxoNotificationMedium] defines `OnChain` and `OffChain` delivery
    /// of notifications.
    ///
    /// `OffChain` delivery requires less blockchain space and may result in a
    /// lower fee than `OnChain` delivery however there is more potential of
    /// losing funds should the wallet files become corrupted or lost.
    ///
    ///  tip: if using `OnChain` notification use a
    /// [ReceivingAddress::Symmetric] as the receiving address for any
    /// outputs destined for your own wallet.  This happens automatically for
    /// the Change output only.
    ///
    /// `unowned_utxo_notify_method` specifies how to notify other wallets of
    /// any outputs destined for them.
    ///
    ///
    /// `fee` represents the fee in native coins to pay the miner who mines
    /// the block that initially confirms the resulting transaction.
    ///
    /// a [Digest] of the resulting [Transaction](crate::models::blockchain::transaction::Transaction) is returned on success, else [None].
    ///
    /// A list of the encoded transaction notifications is also returned. The relevant notifications
    /// should be sent to the transaction receiver in case `Offchain` notifications are used.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::config_models::network::Network;
    /// # use neptune_cash::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
    /// # use neptune_cash::models::state::wallet::address::ReceivingAddress;
    /// # use neptune_cash::models::state::wallet::utxo_notification::UtxoNotificationMedium;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// # use std::net::IpAddr;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // List of receiving addresses and the amounts to send
    /// let outputs : Vec<(ReceivingAddress, NativeCurrencyAmount)> = vec![
    ///     (ReceivingAddress::from_bech32m("nolgam1lf8vc5xpa4jf9vjakts632fct5q80d4m6tax39nrl8c55dta2h7n7lnkh9pmwckl0ndwc7897xwfgx5vv02xdt3099z62222wazz7tjl6umzewla9xzxyqefh2w47v4eh0xzvfsxjk6kq5u84rwwlflq7cs726ljttl6ls860te04cwpy5kk8n40qqjnps0gdp46namhsa3cqt0uc0s5e34h6s5rw2kl77uvvs4rlnn5t8wtuefsduuccwsxmk27r8d48g49swgafhj6wmvu5cx3lweqhnxgdgm7mmdq7ck6wkurw2jzl64k9u34kzgu9stgd47ljzte0hz0n2lcng83vtpf0u9f4hggw4llqsz2fqpe4096d9v5fzg7xvxg6zvr7gksq4yqgn8shepg5xsczmzz256m9c6r8zqdkzy4tk9he59ndtdkrrr8u5v6ztnvkvmy4sed7p7plm2y09sgksw6zcjayls4wl9fnqu97kyx9cdknksar7h8jetygur979rt5arcwmvp2dy3ynt6arna2yjpevt9209v9g2p5cvp6gjp9850w3w6afeg8yuhp6u447hrudcssyjauqa2p7jk4tz37wg70yrdhsgn35sc0hdkclvpapu75dgtmswk0vtgadx44mqdps6ry6005xqups9dpc93u66qj9j7lfaqgdqrrfg9pkxhjl99ge387rh257x2phfvjvc8y66p22wax8myyhm7mgmlxu9gug0km3lmn4lzcyj32mduy6msy4kfn5z2tr67zfxadnj6wc0av27mk0j90pf67uzp9ps8aekr24kpv5n3qeczfznen9vj67ft95s93t26l8uh87qr6kp8lsyuzm4h36de830h6rr3lhg5ac995nrsu6h0p56t5tnglvx0s02mr0ts95fgcevveky5kkw6zgj6jd5m3n5ljhw862km8sedr30xvg8t9vh409ufuxdnfuypvqdq49z6mp46p936pjzwwqjda6yy5wuxx9lffrxwcmfqzch6nz2l4mwd2vlsdr58vhygppy6nm6tduyemw4clwj9uac4v990xt6jt7e2al7m6sjlq4qgxfjf4ytx8f5j460vvr7yac9hsvlsat2vh5gl55mt4wr7v5p3m6k5ya5442xdarastxlmpf2vqz5lusp8tlglxkj0jksgwqgtj6j0kxwmw40egpzs5rr996xpv8wwqyja4tmw599n9fh77f5ruxk69vtpwl9z5ezmdn92cpyyhwff59ypp0z5rv98vdvm67umqzt0ljjan30u3a8nga35fdy450ht9gef24mveucxqwv5aflge5r3amxsvd7l30j9kcqm7alq0ks2wqpde7pdct2gmvafxvjg3ad0a3h58assjaszvmykl3k5tn238gstm2shlvad4a53mm5ztvp5q2zt4pdzj0ssevlkumwhc0g5cxnxc9u7rh9gffkq7h9ufcxkgtghe32sv3vwzkessr52mcmajt83lvz45wqru9hht8cytfedtjlv7z7en6pp0guja85ft3rv6hzf2e02e7wfu38s0nyfzkc2qy2k298qtmxgrpduntejtvenr80csnckajnhu44399tkm0a7wdldalf678n9prd54twwlw24xhppxqlquatfztllkeejlkfxuayddwagh6uzx040tqlcs7hcflnu0ywynmz0chz48qcx7dsc4gpseu0dqvmmezpuv0tawm78nleju2vp4lkehua56hrnuj2wuc5lqvxlnskvp53vu7e2399pgp7xcwe3ww23qcd9pywladq34nk6cwcvtj3vdfgwf6r7s6vq46y2x05e043nj6tu8am2und8z3ftf3he5ccjxamtnmxfd79m04ph36kzx6e789dhqrwmwcfrn9ulsedeplk3dvrmad6f20y9qfl6n6kzaxkmmmaq4d6s5rl4kmhc7fcdkrkandw2jxdjckuscu56syly8rtjatj4j2ug23cwvep3dgcdvmtr32296nf9vdl3rcu0r7hge23ydt83k5nhtnexuqrnamveacz6c43eay9nz4pjjwjatkgp80lg9tnf5kdr2eel8s2fk6v338x4hu00htemm5pq6qlucqqq5tchhtekjzdu50erqd2fkdu9th3wl0mqxz5u7wnpgwgpammv2yqpa5znljegyhke0dz9vg27uh5t5x6qdgf7vu54lqssejekwzfxchjyq2s8frm9fmt688w76aug56v6n3w5xdre78xplfsdw3e4j6dc5w7tf83r25re0duq6h8z54wnkqr9yh2k0skjqea4elgcr4aw7hks9m8w3tx8w9xlxpqqll2zeql55ew7e90dyuynkqxfuqzv45t22ljamdll3udvqrllprdltthzm866jdaxkkrnryj4cmc2m7sk99clgql3ynrhe9kynqn4mh3tepk8dtq7cndtc2hma29s4cuylsvg04s70uyr53w5656su5rjem5egss08zrfaef0mww6t8pr26uph2n8a2cs55ydx4xhasjqk7xs0akh6f26j2ec4d8pd0kdf4jya6p9jl48wmy5autdpw2q8mehrq6kypt573genj66l5zkq6xvrdqugmfczxa2gj9ylx3pgpjqnhuem9udfkj9qr2y8lh728sr7uaedu5wwmfa72ykh395jqh7f7f9p2gskn6u7k844kpnwe3eqv84pl53r6x9af88a8ey7298njdg03h8mxqz2x6z8ys3qpuxq768tjq0zhrnjgns8d78euzwsvx6vn4f9tftrp68zcch3h75mc9drpt7tpvnyyqfjuqclxhdwhdwtsakecv04p9r3jx90htql9a3ht5mxrj4ercv4cd52wk4qhu7dn4tqe7yclqx2l36gcsrzmdlv440qls7qjpq6k95mst485vpennnur8h62a7d7syvyer89qtyfzlfhz8a5a0x5tuwhc9mah0e944xzhsc6uvpv8vat44w7r3xyw8q85y77jux8zhndrhdn36swryffqmpkxgcw4g29q40sul4fl5vrfru08a5j3rd3jl8799srpf2xqpxq38wwvhr4mxqf5wwdqfqq7harshggvufzlgn0l9fq0j76dyuge75jmzy8celvw6wesfs82n4jw2k8jnus2zds5a67my339uuzka4w72tau6j7wyu0lla0mcjpaflphsuy7f2phev6tr8vc9nj2mczkeg4vy3n5jkgecwgrvwu3vw9x5knpkxzv8kw3dpzzxy3rvrs56vxw8ugmyz2vdj6dakjyq3feym4290l7hgdt0ac5u49sekezzf0ghwmlek4h75fkzpvuly9zupw32dd3l9my282nekgk78fe6ayjyhczetxf8r82yd2askl52kmupr9xaxw0jd08dsd3523ea6ge48384rlmt4mu4w4x0q9s", Network::Main)?, NativeCurrencyAmount::coins(20)),
    ///     (ReceivingAddress::from_bech32m("nolgam1ld9vc5xpa4jf9vjakts632fct5q80d4m6tax39nrl8c55dta2h7n7lnkh9pmwckl0ndwc7897xwfgx5vv02xdt3099z62222wazz7tjl6umzewla9xzxyqefh2w47v4eh0xzvfsxjk6kq5u84rwwlflq7cs726ljttl6ls860te04cwpy5kk8n40qqjnps0gdp46namhsa3cqt0uc0s5e34h6s5rw2kl77uvvs4rlnn5t8wtuefsduuccwsxmk27r8d48g49swgafhj6wmvu5cx3lweqhnxgdgm7mmdq7ck6wkurw2jzl64k9u34kzgu9stgd47ljzte0hz0n2lcng83vtpf0u9f4hggw4llqsz2fqpe4096d9v5fzg7xvxg6zvr7gksq4yqgn8shepg5xsczmzz256m9c6r8zqdkzy4tk9he59ndtdkrrr8u5v6ztnvkvmy4sed7p7plm2y09sgksw6zcjayls4wl9fnqu97kyx9cdknksar7h8jetygur979rt5arcwmvp2dy3ynt6arna2yjpevt9209v9g2p5cvp6gjp9850w3w6afeg8yuhp6u447hrudcssyjauqa2p7jk4tz37wg70yrdhsgn35sc0hdkclvpapu75dgtmswk0vtgadx44mqdps6ry6005xqups9dpc93u66qj9j7lfaqgdqrrfg9pkxhjl99ge387rh257x2phfvjvc8y66p22wax8myyhm7mgmlxu9gug0km3lmn4lzcyj32mduy6msy4kfn5z2tr67zfxadnj6wc0av27mk0j90pf67uzp9ps8aekr24kpv5n3qeczfznen9vj67ft95s93t26l8uh87qr6kp8lsyuzm4h36de830h6rr3lhg5ac995nrsu6h0p56t5tnglvx0s02mr0ts95fgcevveky5kkw6zgj6jd5m3n5ljhw862km8sedr30xvg8t9vh409ufuxdnfuypvqdq49z6mp46p936pjzwwqjda6yy5wuxx9lffrxwcmfqzch6nz2l4mwd2vlsdr58vhygppy6nm6tduyemw4clwj9uac4v990xt6jt7e2al7m6sjlq4qgxfjf4ytx8f5j460vvr7yac9hsvlsat2vh5gl55mt4wr7v5p3m6k5ya5442xdarastxlmpf2vqz5lusp8tlglxkj0jksgwqgtj6j0kxwmw40egpzs5rr996xpv8wwqyja4tmw599n9fh77f5ruxk69vtpwl9z5ezmdn92cpyyhwff59ypp0z5rv98vdvm67umqzt0ljjan30u3a8nga35fdy450ht9gef24mveucxqwv5aflge5r3amxsvd7l30j9kcqm7alq0ks2wqpde7pdct2gmvafxvjg3ad0a3h58assjaszvmykl3k5tn238gstm2shlvad4a53mm5ztvp5q2zt4pdzj0ssevlkumwhc0g5cxnxc9u7rh9gffkq7h9ufcxkgtghe32sv3vwzkessr52mcmajt83lvz45wqru9hht8cytfedtjlv7z7en6pp0guja85ft3rv6hzf2e02e7wfu38s0nyfzkc2qy2k298qtmxgrpduntejtvenr80csnckajnhu44399tkm0a7wdldalf678n9prd54twwlw24xhppxqlquatfztllkeejlkfxuayddwagh6uzx040tqlcs7hcflnu0ywynmz0chz48qcx7dsc4gpseu0dqvmmezpuv0tawm78nleju2vp4lkehua56hrnuj2wuc5lqvxlnskvp53vu7e2399pgp7xcwe3ww23qcd9pywladq34nk6cwcvtj3vdfgwf6r7s6vq46y2x05e043nj6tu8am2und8z3ftf3he5ccjxamtnmxfd79m04ph36kzx6e789dhqrwmwcfrn9ulsedeplk3dvrmad6f20y9qfl6n6kzaxkmmmaq4d6s5rl4kmhc7fcdkrkandw2jxdjckuscu56syly8rtjatj4j2ug23cwvep3dgcdvmtr32296nf9vdl3rcu0r7hge23ydt83k5nhtnexuqrnamveacz6c43eay9nz4pjjwjatkgp80lg9tnf5kdr2eel8s2fk6v338x4hu00htemm5pq6qlucqqq5tchhtekjzdu50erqd2fkdu9th3wl0mqxz5u7wnpgwgpammv2yqpa5znljegyhke0dz9vg27uh5t5x6qdgf7vu54lqssejekwzfxchjyq2s8frm9fmt688w76aug56v6n3w5xdre78xplfsdw3e4j6dc5w7tf83r25re0duq6h8z54wnkqr9yh2k0skjqea4elgcr4aw7hks9m8w3tx8w9xlxpqqll2zeql55ew7e90dyuynkqxfuqzv45t22ljamdll3udvqrllprdltthzm866jdaxkkrnryj4cmc2m7sk99clgql3ynrhe9kynqn4mh3tepk8dtq7cndtc2hma29s4cuylsvg04s70uyr53w5656su5rjem5egss08zrfaef0mww6t8pr26uph2n8a2cs55ydx4xhasjqk7xs0akh6f26j2ec4d8pd0kdf4jya6p9jl48wmy5autdpw2q8mehrq6kypt573genj66l5zkq6xvrdqugmfczxa2gj9ylx3pgpjqnhuem9udfkj9qr2y8lh728sr7uaedu5wwmfa72ykh395jqh7f7f9p2gskn6u7k844kpnwe3eqv84pl53r6x9af88a8ey7298njdg03h8mxqz2x6z8ys3qpuxq768tjq0zhrnjgns8d78euzwsvx6vn4f9tftrp68zcch3h75mc9drpt7tpvnyyqfjuqclxhdwhdwtsakecv04p9r3jx90htql9a3ht5mxrj4ercv4cd52wk4qhu7dn4tqe7yclqx2l36gcsrzmdlv440qls7qjpq6k95mst485vpennnur8h62a7d7syvyer89qtyfzlfhz8a5a0x5tuwhc9mah0e944xzhsc6uvpv8vat44w7r3xyw8q85y77jux8zhndrhdn36swryffqmpkxgcw4g29q40sul4fl5vrfru08a5j3rd3jl8799srpf2xqpxq38wwvhr4mxqf5wwdqfqq7harshggvufzlgn0l9fq0j76dyuge75jmzy8celvw6wesfs82n4jw2k8jnus2zds5a67my339uuzka4w72tau6j7wyu0lla0mcjpaflphsuy7f2phev6tr8vc9nj2mczkeg4vy3n5jkgecwgrvwu3vw9x5knpkxzv8kw3dpzzxy3rvrs56vxw8ugmyz2vdj6dakjyq3feym4290l7hgdt0ac5u49sekezzf0ghwmlek4h75fkzpvuly9zupw32dd3l9my282nekgk78fe6ayjyhczetxf8r82yd2askl52kmupr9xaxw0jd08dsd3523ea6ge48384rlmt4mu4w4x0q9s", Network::Main)?, NativeCurrencyAmount::coins(57)),
    /// ];
    /// // owned utxo notify method
    /// let notify_self : UtxoNotificationMedium = UtxoNotificationMedium::OnChain;
    /// #
    /// // unwowned utxo notify method
    /// let notify_other : UtxoNotificationMedium = UtxoNotificationMedium::OnChain;
    /// #
    /// // Max fee
    /// let fee : NativeCurrencyAmount = NativeCurrencyAmount::coins(10);
    /// #
    /// // neptune-core server sends token to a single receipient
    /// let send_result = client.send_to_many(context::current(), token, outputs, notify_self, notify_other, fee).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn send_to_many(
        token: rpc_auth::Token,
        outputs: Vec<(ReceivingAddress, NativeCurrencyAmount)>,
        owned_utxo_notify_medium: UtxoNotificationMedium,
        unowned_utxo_notify_medium: UtxoNotificationMedium,
        fee: NativeCurrencyAmount,
    ) -> RpcResult<(TransactionKernelId, Vec<PrivateNotificationData>)>;

    /// claim a utxo
    ///
    /// The input string must be a valid bech32m encoded `UtxoTransferEncrypted`
    /// for the current network and the wallet must have the corresponding
    /// `SpendingKey` for decryption.
    ///
    /// upon success, a new `ExpectedUtxo` will be added to the local wallet
    /// state.
    ///
    /// if the utxo has already been claimed, this call has no effect.
    ///
    /// Return true if a new expected UTXO was added, otherwise false.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // Encryted value of utxo transfer
    /// let utxo_transfer_encrypted = "XXXXXXX".to_string();
    ///
    /// // max search depth is set to 3
    /// let max_search_depth : Option<u64> = Some(3);
    ///
    /// // claim utxo
    /// let utxo_claimed = client.claim_utxo(context::current(), token, utxo_transfer_encrypted, max_search_depth).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn claim_utxo(
        token: rpc_auth::Token,
        utxo_transfer_encrypted: String,
        max_search_depth: Option<u64>,
    ) -> RpcResult<bool>;

    /// Stop miner if running
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    ///  // stops miner if running
    /// let _ = client.pause_miner(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn pause_miner(token: rpc_auth::Token) -> RpcResult<()>;

    /// Start miner if not running
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    ///  // start miner if not running
    /// let _ = client.restart_miner(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn restart_miner(token: rpc_auth::Token) -> RpcResult<()>;

    /// mark MUTXOs as abandoned
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    ///  // marks mutxos as abandonned
    /// let abandonned_monitored_utxos = client.prune_abandoned_monitored_utxos(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn prune_abandoned_monitored_utxos(token: rpc_auth::Token) -> RpcResult<usize>;

    /// Gracious shutdown.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::rpc_server::RPCClient;
    /// # use neptune_cash::rpc_auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // create an rpc client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // Defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : rpc_auth::Token = rpc_auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    ///  // shutdowns the node
    /// let is_shutdown = client.shutdown(context::current(), token).await??;
    /// # Ok(())
    /// # }
    async fn shutdown(token: rpc_auth::Token) -> RpcResult<bool>;
}

#[derive(Clone)]
pub(crate) struct NeptuneRPCServer {
    pub(crate) state: GlobalStateLock,
    pub(crate) rpc_server_to_main_tx: tokio::sync::mpsc::Sender<RPCServerToMain>,

    // copy of DataDirectory for this neptune-core instance.
    data_directory: DataDirectory,

    // list of tokens that are valid.  RPC clients must present a token that
    // matches one of these.  there should only be one of each `Token` variant
    // in the list (dups ignored).
    valid_tokens: Vec<rpc_auth::Token>,
}

impl NeptuneRPCServer {
    /// instantiate a new [NeptuneRPCServer]
    pub fn new(
        state: GlobalStateLock,
        rpc_server_to_main_tx: tokio::sync::mpsc::Sender<RPCServerToMain>,
        data_directory: DataDirectory,
        valid_tokens: Vec<rpc_auth::Token>,
    ) -> Self {
        Self {
            state,
            valid_tokens,
            rpc_server_to_main_tx,
            data_directory,
        }
    }

    async fn confirmations_internal(&self, state: &GlobalState) -> Option<BlockHeight> {
        match state.get_latest_balance_height().await {
            Some(latest_balance_height) => {
                let tip_block_header = state.chain.light_state().header();

                assert!(tip_block_header.height >= latest_balance_height);

                // subtract latest balance height from chain tip.
                //
                // we add 1 to the result because the block that a tx is confirmed
                // in is considered the 1st confirmation.
                //
                // note: BlockHeight is u64 internally and BlockHeight::sub() returns i128.
                //       The subtraction and cast is safe given we passed the above assert.
                let confirmations: BlockHeight =
                    ((tip_block_header.height - latest_balance_height) as u64 + 1).into();
                Some(confirmations)
            }
            None => None,
        }
    }

    /// Return temperature of CPU, if available.
    fn cpu_temp_inner() -> Option<f32> {
        let current_system = System::new();
        current_system.cpu_temp().ok()
    }

    async fn send_to_many_inner_with_mock_proof_option(
        mut self,
        outputs: Vec<(ReceivingAddress, NativeCurrencyAmount)>,
        utxo_notification_media: (UtxoNotificationMedium, UtxoNotificationMedium),
        fee: NativeCurrencyAmount,
        now: Timestamp,
        tx_proving_capability: TxProvingCapability,
        mocked_invalid_proof: Option<TransactionProof>,
    ) -> Result<(Transaction, Vec<PrivateNotificationData>), error::SendError> {
        let (owned_utxo_notification_medium, unowned_utxo_notification_medium) =
            utxo_notification_media;

        // check if this send would exceed the send rate-limit (per block)
        {
            // send rate limiting only applies below height 25000
            // which is approx 5.6 months after launch.
            // after that, the training wheel come off.
            const RATE_LIMIT_UNTIL_HEIGHT: u64 = 25000;
            let state = self.state.lock_guard().await;

            if state.chain.light_state().header().height < RATE_LIMIT_UNTIL_HEIGHT.into() {
                const RATE_LIMIT: usize = 2;
                let tip_digest = state.chain.light_state().hash();
                let send_count_at_tip = state
                    .wallet_state
                    .count_sent_transactions_at_block(tip_digest)
                    .await;
                tracing::debug!(
                    "send-tx rate-limit check:  found {} sent-tx at current tip.  limit = {}",
                    send_count_at_tip,
                    RATE_LIMIT
                );
                if send_count_at_tip >= RATE_LIMIT {
                    let height = state.chain.light_state().header().height;
                    let e = error::SendError::RateLimit {
                        height,
                        tip_digest,
                        max: RATE_LIMIT,
                    };
                    tracing::warn!("{}", e.to_string());
                    return Err(e);
                }
            }
        }

        tracing::debug!("stmi: step 1. get change key. need write-lock");

        // obtain next unused symmetric key for change utxo
        let change_key = {
            let mut s = self.state.lock_guard_mut().await;
            let key = s
                .wallet_state
                .next_unused_spending_key(KeyType::Symmetric)
                .await
                .expect("wallet should be capable of generating symmetric spending keys");

            // write state to disk. create_transaction() may be slow.
            s.persist_wallet().await.expect("flushed");
            key
        };

        tracing::debug!("stmi: step 2. generate outputs. need read-lock");

        let state = self.state.lock_guard().await;
        let tx_outputs = state.generate_tx_outputs(
            outputs,
            owned_utxo_notification_medium,
            unowned_utxo_notification_medium,
        );

        tracing::debug!("stmi: step 3. create tx. have read-lock");

        // Create the transaction
        //
        // Note that create_transaction() does not modify any state and only
        // requires acquiring a read-lock which does not block other tasks.
        // This is important because internally it calls prove() which is a very
        // lengthy operation.
        //
        // note: A change output will be added to tx_outputs if needed.
        let (mut transaction, transaction_details, maybe_change_output) = match state
            .create_transaction_with_prover_capability(
                tx_outputs.clone(),
                change_key,
                owned_utxo_notification_medium,
                fee,
                now,
                tx_proving_capability,
                self.state.vm_job_queue(),
            )
            .await
        {
            Ok(tx) => tx,
            Err(e) => {
                tracing::error!("Could not create transaction: {}", e);
                return Err(e.into());
            }
        };
        drop(state);

        if let Some(invalid_proof) = mocked_invalid_proof {
            transaction.proof = invalid_proof;
        }

        tracing::debug!("stmi: step 4. extract expected utxo. need read-lock");

        let offchain_notifications = tx_outputs.private_notifications(self.state.cli().network);
        tracing::debug!(
            "Generated {} offchain notifications",
            offchain_notifications.len()
        );

        let utxos_sent_to_self = self
            .state
            .lock_guard()
            .await
            .wallet_state
            .extract_expected_utxos(
                tx_outputs.clone().concat_with(maybe_change_output),
                UtxoNotifier::Myself,
            );

        // if the tx created offchain expected_utxos we must inform wallet.
        if !utxos_sent_to_self.is_empty() {
            tracing::debug!("stmi: step 5. add expected utxos. need write-lock");

            // acquire write-lock
            let mut gsm = self.state.lock_guard_mut().await;

            // Inform wallet of any expected incoming utxos.
            // note that this (briefly) mutates self.
            gsm.wallet_state
                .add_expected_utxos(utxos_sent_to_self)
                .await;

            // ensure we write new wallet state out to disk.
            gsm.persist_wallet().await.expect("flushed wallet");
        }

        // write-lock block.
        {
            tracing::debug!("stmi: step 6. add sent-transaction to wallet. with write-lock");

            let mut gsm = self.state.lock_guard_mut().await;
            // inform wallet about the details of this sent transaction, so it can
            // group inputs and outputs together, eg for history purposes.
            let tip_digest = gsm.chain.light_state().hash();
            gsm.wallet_state
                .add_sent_transaction((transaction_details, tip_digest).into())
                .await;

            tracing::debug!("stmi: step 7. flush dbs.  with write-lock");
            gsm.flush_databases().await.expect("flushed DBs");
        }

        tracing::debug!("stmi: step 8. send messges. no lock needed");

        // Send transaction message to main
        let response = self
            .rpc_server_to_main_tx
            .send(RPCServerToMain::BroadcastTx(Box::new(transaction.clone())))
            .await;

        if let Err(e) = response {
            tracing::error!("Could not send Tx to main task: error: {}", e.to_string());
            return Err(error::SendError::NotBroadcast);
        };

        tracing::debug!("stmi: step 8. all done with send_to_many_inner().");

        Ok((transaction, offchain_notifications))
    }

    /// Method to create a transaction with a given timestamp and prover
    /// capability.
    ///
    /// Factored out from [NeptuneRPCServer::send_to_many] in order to generate
    /// deterministic transaction kernels where tests can reuse previously
    /// generated proofs.
    ///
    /// Locking:
    ///   * acquires `global_state_lock` for write
    async fn send_to_many_inner(
        self,
        _ctx: context::Context,
        outputs: Vec<(ReceivingAddress, NativeCurrencyAmount)>,
        utxo_notification_media: (UtxoNotificationMedium, UtxoNotificationMedium),
        fee: NativeCurrencyAmount,
        now: Timestamp,
        tx_proving_capability: TxProvingCapability,
    ) -> Result<(TransactionKernelId, Vec<PrivateNotificationData>), error::SendError> {
        let (owned_utxo_notification_medium, unowned_utxo_notification_medium) =
            utxo_notification_media;
        let ret = self
            .send_to_many_inner_with_mock_proof_option(
                outputs,
                (
                    owned_utxo_notification_medium,
                    unowned_utxo_notification_medium,
                ),
                fee,
                now,
                tx_proving_capability,
                None,
            )
            .await;

        ret.map(|(tx, offchain_notifications)| (tx.kernel.txid(), offchain_notifications))
    }

    /// Like [Self::send_to_many_inner] but without attempting to create a valid
    /// SingleProof, since this is a time-consuming process.
    ///
    /// Also returns the full transaction and not just its kernel ID.
    #[cfg(test)]
    async fn send_to_many_inner_invalid_proof(
        self,
        outputs: Vec<(ReceivingAddress, NativeCurrencyAmount)>,
        owned_utxo_notification_medium: UtxoNotificationMedium,
        unowned_utxo_notification_medium: UtxoNotificationMedium,
        fee: NativeCurrencyAmount,
        now: Timestamp,
    ) -> Option<(Transaction, Vec<PrivateNotificationData>)> {
        self.send_to_many_inner_with_mock_proof_option(
            outputs,
            (
                owned_utxo_notification_medium,
                unowned_utxo_notification_medium,
            ),
            fee,
            now,
            TxProvingCapability::PrimitiveWitness,
            Some(TransactionProof::invalid()),
        )
        .await
        .ok()
    }

    /// Assemble a data for the wallet to register the UTXO. Returns `Ok(None)`
    /// if the UTXO has already been claimed by the wallet.
    ///
    /// `max_search_depth` denotes how many blocks back from tip we attempt
    /// to find the transaction in a block. `None` means unlimited.
    ///
    /// `encrypted_utxo_notification` is expected to hold encrypted data about
    /// a future or past UTXO, which can be claimed by this client.
    async fn claim_utxo_inner(
        &self,
        encrypted_utxo_notification: String,
        max_search_depth: Option<u64>,
    ) -> Result<Option<ClaimUtxoData>, error::ClaimError> {
        let span = tracing::debug_span!("Claim UTXO inner");
        let _enter = span.enter();

        // deserialize UtxoTransferEncrypted from bech32m string.
        let utxo_transfer_encrypted = EncryptedUtxoNotification::from_bech32m(
            &encrypted_utxo_notification,
            self.state.cli().network,
        )?;

        // // acquire global state read lock
        let state = self.state.lock_guard().await;

        // find known spending key by receiver_identifier
        let spending_key = state
            .wallet_state
            .find_known_spending_key_for_receiver_identifier(
                utxo_transfer_encrypted.receiver_identifier,
            )
            .ok_or(error::ClaimError::UtxoUnknown)?;

        // decrypt utxo_transfer_encrypted into UtxoTransfer
        let utxo_notification = utxo_transfer_encrypted
            .decrypt_with_spending_key(&spending_key)
            .expect(
                "spending key should be capable of decryption because it was returned by find_known_spending_key_for_receiver_identifier",
            )?;

        tracing::debug!("claim-utxo: decrypted {:#?}", utxo_notification);

        // search for matching monitored utxo and return early if found.
        if state
            .wallet_state
            .find_monitored_utxo(&utxo_notification.utxo, utxo_notification.sender_randomness)
            .await
            .is_some()
        {
            info!("found monitored utxo. Returning early.");
            return Ok(None);
        }

        // construct an IncomingUtxo
        let incoming_utxo = IncomingUtxo::from_utxo_notification_payload(utxo_notification, spending_key.privacy_preimage().expect("spending key should have associated address and privacy preimage because it was returned by find_known_spending_key_for_receiver_identifier"));

        // Check if we can satisfy typescripts
        if !incoming_utxo.utxo.all_type_script_states_are_valid() {
            let err = error::ClaimError::InvalidTypeScript;
            warn!("{}", err.to_string());
            return Err(err);
        }

        // check if wallet is already expecting this utxo.
        let addition_record = incoming_utxo.addition_record();
        let has_expected_utxo = state.wallet_state.has_expected_utxo(addition_record).await;

        // Check if UTXO has already been mined in a transaction.
        let mined_in_block = state
            .chain
            .archival_state()
            .find_canonical_block_with_output(addition_record, max_search_depth)
            .await;
        let maybe_prepared_mutxo = match mined_in_block {
            Some(block) => {
                let aocl_leaf_index = {
                    // Find matching AOCL leaf index that must be in this block
                    let last_aocl_index_in_block =
                        block.mutator_set_accumulator_after().aocl.num_leafs() - 1;
                    let num_outputs_in_block: u64 = block
                        .mutator_set_update()
                        .additions
                        .len()
                        .try_into()
                        .unwrap();
                    let min_aocl_leaf_index = last_aocl_index_in_block - num_outputs_in_block + 1;
                    let mut haystack = last_aocl_index_in_block;
                    let ams = state.chain.archival_state().archival_mutator_set.ams();
                    while ams.aocl.get_leaf_async(haystack).await
                        != addition_record.canonical_commitment
                    {
                        assert!(haystack > min_aocl_leaf_index);
                        haystack -= 1;
                    }

                    haystack
                };
                let item = Tip5::hash(&incoming_utxo.utxo);
                let ams = state.chain.archival_state().archival_mutator_set.ams();
                let msmp = ams
                    .restore_membership_proof(
                        item,
                        incoming_utxo.sender_randomness,
                        incoming_utxo.receiver_preimage,
                        aocl_leaf_index,
                    )
                    .await
                    .map_err(|x| anyhow!("Could not restore mutator set membership proof. Is archival mutator set corrupted? Got error: {x}"))?;

                let tip_digest = state.chain.light_state().hash();

                let mut monitored_utxo = MonitoredUtxo::new(
                    incoming_utxo.utxo.clone(),
                    self.state.cli().number_of_mps_per_utxo,
                );
                monitored_utxo.confirmed_in_block = Some((
                    block.hash(),
                    block.header().timestamp,
                    block.header().height,
                ));
                monitored_utxo.add_membership_proof_for_tip(tip_digest, msmp.clone());

                // Was UTXO already spent? If so, register it as such.
                let msa = ams.accumulator().await;
                if !msa.verify(item, &msmp) {
                    warn!("Claimed UTXO was already spent. Marking it as such.");

                    if let Some(spending_block) = state
                        .chain
                        .archival_state()
                        .find_canonical_block_with_input(
                            msmp.compute_indices(item),
                            max_search_depth,
                        )
                        .await
                    {
                        warn!(
                            "Claimed UTXO was spent in block {}; which has height {}",
                            spending_block.hash(),
                            spending_block.header().height
                        );
                        monitored_utxo.mark_as_spent(&spending_block);
                    } else {
                        error!("Claimed UTXO's mutator set membership proof was invalid but we could not find the block in which it was spent. This is most likely a bug in the software.");
                    }
                }

                Some(monitored_utxo)
            }
            None => None,
        };

        let expected_utxo = incoming_utxo.into_expected_utxo(UtxoNotifier::Cli);
        Ok(Some(ClaimUtxoData {
            prepared_monitored_utxo: maybe_prepared_mutxo,
            has_expected_utxo,
            expected_utxo,
        }))
    }

    /// get the data_directory for this neptune-core instance
    pub fn data_directory(&self) -> &DataDirectory {
        &self.data_directory
    }
}

impl RPC for NeptuneRPCServer {
    // documented in trait. do not add doc-comment.
    async fn cookie_hint(self, _: context::Context) -> RpcResult<rpc_auth::CookieHint> {
        log_slow_scope!(fn_name!());

        if self.state.cli().disable_cookie_hint {
            Err(error::RpcError::CookieHintDisabled)
        } else {
            Ok(rpc_auth::CookieHint {
                data_directory: self.data_directory().to_owned(),
                network: self.state.cli().network,
            })
        }
    }

    // documented in trait. do not add doc-comment.
    async fn network(self, _: context::Context) -> RpcResult<Network> {
        log_slow_scope!(fn_name!());

        Ok(self.state.cli().network)
    }

    // documented in trait. do not add doc-comment.
    async fn own_listen_address_for_peers(
        self,
        _context: context::Context,
        token: rpc_auth::Token,
    ) -> RpcResult<Option<SocketAddr>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let listen_port = self.state.cli().own_listen_port();
        let listen_for_peers_ip = self.state.cli().listen_addr;
        Ok(listen_port.map(|port| SocketAddr::new(listen_for_peers_ip, port)))
    }

    // documented in trait. do not add doc-comment.
    async fn own_instance_id(
        self,
        _context: context::Context,
        token: rpc_auth::Token,
    ) -> RpcResult<InstanceId> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self.state.lock_guard().await.net.instance_id)
    }

    // documented in trait. do not add doc-comment.
    async fn block_height(
        self,
        _: context::Context,
        token: rpc_auth::Token,
    ) -> RpcResult<BlockHeight> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self
            .state
            .lock_guard()
            .await
            .chain
            .light_state()
            .kernel
            .header
            .height)
    }

    // documented in trait. do not add doc-comment.
    async fn confirmations(
        self,
        _: context::Context,
        token: rpc_auth::Token,
    ) -> RpcResult<Option<BlockHeight>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let guard = self.state.lock_guard().await;
        Ok(self.confirmations_internal(&guard).await)
    }

    // documented in trait. do not add doc-comment.
    async fn utxo_digest(
        self,
        _: context::Context,
        token: rpc_auth::Token,
        leaf_index: u64,
    ) -> RpcResult<Option<Digest>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let state = self.state.lock_guard().await;
        let aocl = &state.chain.archival_state().archival_mutator_set.ams().aocl;

        Ok(
            match leaf_index > 0 && leaf_index < aocl.num_leafs().await {
                true => Some(aocl.get_leaf_async(leaf_index).await),
                false => None,
            },
        )
    }

    // documented in trait. do not add doc-comment.
    async fn block_digest(
        self,
        _: context::Context,
        token: rpc_auth::Token,
        block_selector: BlockSelector,
    ) -> RpcResult<Option<Digest>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let state = self.state.lock_guard().await;
        let archival_state = state.chain.archival_state();
        let digest = match block_selector.as_digest(&state).await {
            Some(d) => d,
            None => return Ok(None),
        };
        // verify the block actually exists
        Ok(archival_state
            .get_block_header(digest)
            .await
            .map(|_| digest))
    }

    // documented in trait. do not add doc-comment.
    async fn block_info(
        self,
        _: context::Context,
        token: rpc_auth::Token,
        block_selector: BlockSelector,
    ) -> RpcResult<Option<BlockInfo>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let state = self.state.lock_guard().await;
        let digest = match block_selector.as_digest(&state).await {
            Some(d) => d,
            None => return Ok(None),
        };
        let tip_digest = state.chain.light_state().hash();
        let archival_state = state.chain.archival_state();

        let block = match archival_state.get_block(digest).await.unwrap() {
            Some(b) => b,
            None => return Ok(None),
        };
        let is_canonical = archival_state
            .block_belongs_to_canonical_chain(digest)
            .await;

        // sibling blocks are those at the same height, with different digest
        let sibling_blocks = archival_state
            .block_height_to_block_digests(block.header().height)
            .await
            .into_iter()
            .filter(|d| *d != digest)
            .collect();

        Ok(Some(BlockInfo::new(
            &block,
            archival_state.genesis_block().hash(),
            tip_digest,
            sibling_blocks,
            is_canonical,
        )))
    }

    // documented in trait. do not add doc-comment.
    async fn block_digests_by_height(
        self,
        _: context::Context,
        token: rpc_auth::Token,
        height: BlockHeight,
    ) -> RpcResult<Vec<Digest>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self
            .state
            .lock_guard()
            .await
            .chain
            .archival_state()
            .block_height_to_block_digests(height)
            .await)
    }

    // documented in trait. do not add doc-comment.
    async fn latest_tip_digests(
        self,
        _context: tarpc::context::Context,
        token: rpc_auth::Token,
        n: usize,
    ) -> RpcResult<Vec<Digest>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let state = self.state.lock_guard().await;

        let latest_block_digest = state.chain.light_state().hash();

        Ok(state
            .chain
            .archival_state()
            .get_ancestor_block_digests(latest_block_digest, n)
            .await)
    }

    // documented in trait. do not add doc-comment.
    async fn peer_info(
        self,
        _: context::Context,
        token: rpc_auth::Token,
    ) -> RpcResult<Vec<PeerInfo>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self
            .state
            .lock_guard()
            .await
            .net
            .peer_map
            .values()
            .cloned()
            .collect())
    }

    // documented in trait. do not add doc-comment.
    async fn all_punished_peers(
        self,
        _context: tarpc::context::Context,
        token: rpc_auth::Token,
    ) -> RpcResult<HashMap<IpAddr, PeerStanding>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let mut sanctions_in_memory = HashMap::default();

        let global_state = self.state.lock_guard().await;

        // Get all connected peers
        for (socket_address, peer_info) in global_state.net.peer_map.iter() {
            if peer_info.standing().is_negative() {
                sanctions_in_memory.insert(socket_address.ip(), peer_info.standing());
            }
        }

        let sanctions_in_db = global_state.net.all_peer_sanctions_in_database().await;

        // Combine result for currently connected peers and previously connected peers but
        // use result for currently connected peer if there is an overlap
        let mut all_sanctions = sanctions_in_memory;
        for (ip_addr, sanction) in sanctions_in_db {
            if sanction.is_negative() {
                all_sanctions.entry(ip_addr).or_insert(sanction);
            }
        }

        Ok(all_sanctions)
    }

    // documented in trait. do not add doc-comment.
    async fn validate_address(
        self,
        _ctx: context::Context,
        token: rpc_auth::Token,
        address_string: String,
        network: Network,
    ) -> RpcResult<Option<ReceivingAddress>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let ret = ReceivingAddress::from_bech32m(&address_string, network).ok();
        tracing::debug!(
            "Responding to address validation request of {address_string}: {}",
            ret.is_some()
        );
        Ok(ret)
    }

    // documented in trait. do not add doc-comment.
    async fn validate_amount(
        self,
        _ctx: context::Context,
        token: rpc_auth::Token,
        amount_string: String,
    ) -> RpcResult<Option<NativeCurrencyAmount>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        // parse string
        if let Ok(amt) = NativeCurrencyAmount::coins_from_str(&amount_string) {
            Ok(Some(amt))
        } else {
            Ok(None)
        }
    }

    // documented in trait. do not add doc-comment.
    async fn amount_leq_confirmed_available_balance(
        self,
        _ctx: context::Context,
        token: rpc_auth::Token,
        amount: NativeCurrencyAmount,
    ) -> RpcResult<bool> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let gs = self.state.lock_guard().await;
        let wallet_status = gs.get_wallet_status_for_tip().await;

        let confirmed_available = gs
            .wallet_state
            .confirmed_available_balance(&wallet_status, Timestamp::now());

        // test inequality
        Ok(amount <= confirmed_available)
    }

    // documented in trait. do not add doc-comment.
    async fn confirmed_available_balance(
        self,
        _context: tarpc::context::Context,
        token: rpc_auth::Token,
    ) -> RpcResult<NativeCurrencyAmount> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let gs = self.state.lock_guard().await;
        let wallet_status = gs.get_wallet_status_for_tip().await;

        let confirmed_available = gs
            .wallet_state
            .confirmed_available_balance(&wallet_status, Timestamp::now());

        Ok(confirmed_available)
    }

    // documented in trait. do not add doc-comment.
    async fn unconfirmed_available_balance(
        self,
        _context: tarpc::context::Context,
        token: rpc_auth::Token,
    ) -> RpcResult<NativeCurrencyAmount> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let gs = self.state.lock_guard().await;
        let wallet_status = gs.get_wallet_status_for_tip().await;

        Ok(gs
            .wallet_state
            .unconfirmed_available_balance(&wallet_status, Timestamp::now()))
    }

    // documented in trait. do not add doc-comment.
    async fn wallet_status(
        self,
        _context: tarpc::context::Context,
        token: rpc_auth::Token,
    ) -> RpcResult<WalletStatus> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self
            .state
            .lock_guard()
            .await
            .get_wallet_status_for_tip()
            .await)
    }

    async fn num_expected_utxos(
        self,
        _context: tarpc::context::Context,
        token: rpc_auth::Token,
    ) -> RpcResult<u64> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self
            .state
            .lock_guard()
            .await
            .wallet_state
            .num_expected_utxos()
            .await)
    }

    // documented in trait. do not add doc-comment.
    async fn header(
        self,
        _context: tarpc::context::Context,
        token: rpc_auth::Token,
        block_selector: BlockSelector,
    ) -> RpcResult<Option<BlockHeader>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let state = self.state.lock_guard().await;
        let block_digest = match block_selector.as_digest(&state).await {
            Some(d) => d,
            None => return Ok(None),
        };
        Ok(state
            .chain
            .archival_state()
            .get_block_header(block_digest)
            .await)
    }

    // documented in trait. do not add doc-comment.
    async fn next_receiving_address(
        mut self,
        _context: tarpc::context::Context,
        token: rpc_auth::Token,
        key_type: KeyType,
    ) -> RpcResult<Option<ReceivingAddress>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let mut global_state_mut = self.state.lock_guard_mut().await;

        let address = global_state_mut
            .wallet_state
            .next_unused_spending_key(key_type)
            .await
            .and_then(|spending_key| spending_key.to_address());

        // persist wallet state to disk
        global_state_mut.persist_wallet().await.expect("flushed");

        Ok(address)
    }

    // documented in trait. do not add doc-comment.
    async fn known_keys(
        self,
        _context: tarpc::context::Context,
        token: rpc_auth::Token,
    ) -> RpcResult<Vec<SpendingKey>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self
            .state
            .lock_guard()
            .await
            .wallet_state
            .get_all_known_spending_keys()
            .collect())
    }

    // documented in trait. do not add doc-comment.
    async fn known_keys_by_keytype(
        self,
        _context: tarpc::context::Context,
        token: rpc_auth::Token,
        key_type: KeyType,
    ) -> RpcResult<Vec<SpendingKey>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self
            .state
            .lock_guard()
            .await
            .wallet_state
            .get_known_spending_keys(key_type)
            .collect())
    }

    // documented in trait. do not add doc-comment.
    async fn mempool_tx_count(
        self,
        _context: tarpc::context::Context,
        token: rpc_auth::Token,
    ) -> RpcResult<usize> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self.state.lock_guard().await.mempool.len())
    }

    // documented in trait. do not add doc-comment.
    async fn mempool_size(
        self,
        _context: tarpc::context::Context,
        token: rpc_auth::Token,
    ) -> RpcResult<usize> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self.state.lock_guard().await.mempool.get_size())
    }

    // documented in trait. do not add doc-comment.
    async fn history(
        self,
        _context: tarpc::context::Context,
        token: rpc_auth::Token,
    ) -> RpcResult<Vec<(Digest, BlockHeight, Timestamp, NativeCurrencyAmount)>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let history = self.state.lock_guard().await.get_balance_history().await;

        // sort
        let mut display_history: Vec<(Digest, BlockHeight, Timestamp, NativeCurrencyAmount)> =
            history
                .iter()
                .map(|(h, t, bh, a)| (*h, *bh, *t, *a))
                .collect::<Vec<_>>();
        display_history.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

        // return
        Ok(display_history)
    }

    // documented in trait. do not add doc-comment.
    async fn dashboard_overview_data(
        self,
        _context: tarpc::context::Context,
        token: rpc_auth::Token,
    ) -> RpcResult<DashBoardOverviewDataFromClient> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let now = Timestamp::now();
        let state = self.state.lock_guard().await;
        let tip_digest = {
            log_slow_scope!(fn_name!() + "::hash() tip digest");
            state.chain.light_state().hash()
        };
        let tip_header = *state.chain.light_state().header();
        let syncing = state.net.sync_anchor.is_some();
        let mempool_size = {
            log_slow_scope!(fn_name!() + "::mempool.get_size()");
            state.mempool.get_size()
        };
        let mempool_total_tx_count = {
            log_slow_scope!(fn_name!() + "::mempool.len()");
            state.mempool.len()
        };
        let mempool_own_tx_count = {
            log_slow_scope!(fn_name!() + "::mempool.num_own_txs()");
            state.mempool.num_own_txs()
        };
        let cpu_temp = None; // disable for now.  call is too slow.
        let proving_capability = self.state.cli().proving_capability();

        info!("proving capability: {proving_capability}");

        let peer_count = Some(state.net.peer_map.len());
        let max_num_peers = self.state.cli().max_num_peers as usize;

        let mining_status = Some(state.mining_status.clone());

        let confirmations = {
            log_slow_scope!(fn_name!() + "::confirmations_internal()");
            self.confirmations_internal(&state).await
        };

        let wallet_status = {
            log_slow_scope!(fn_name!() + "::get_wallet_status_for_tip()");
            state.get_wallet_status_for_tip().await
        };
        let wallet_state = &state.wallet_state;

        let confirmed_available_balance = {
            log_slow_scope!(fn_name!() + "::confirmed_available_balance()");
            wallet_state.confirmed_available_balance(&wallet_status, now)
        };
        let confirmed_total_balance = {
            log_slow_scope!(fn_name!() + "::confirmed_total_balance()");
            wallet_state.confirmed_total_balance(&wallet_status)
        };

        let unconfirmed_available_balance = {
            log_slow_scope!(fn_name!() + "::unconfirmed_available_balance()");
            wallet_state.unconfirmed_available_balance(&wallet_status, now)
        };
        let unconfirmed_total_balance = {
            log_slow_scope!(fn_name!() + "::unconfirmed_total_balance()");
            wallet_state.unconfirmed_total_balance(&wallet_status)
        };

        Ok(DashBoardOverviewDataFromClient {
            tip_digest,
            tip_header,
            syncing,
            confirmed_available_balance,
            confirmed_total_balance,
            unconfirmed_available_balance,
            unconfirmed_total_balance,
            mempool_size,
            mempool_total_tx_count,
            mempool_own_tx_count,
            peer_count,
            max_num_peers,
            mining_status,
            proving_capability,
            confirmations,
            cpu_temp,
        })
    }

    /******** CHANGE THINGS ********/
    // Locking:
    //   * acquires `global_state_lock` for write
    //
    // documented in trait. do not add doc-comment.
    async fn clear_all_standings(
        mut self,
        _: context::Context,
        token: rpc_auth::Token,
    ) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let mut global_state_mut = self.state.lock_guard_mut().await;
        global_state_mut
            .net
            .peer_map
            .iter_mut()
            .for_each(|(_, peerinfo)| {
                peerinfo.standing.clear_standing();
            });

        // iterates and modifies standing field for all connected peers
        global_state_mut.net.clear_all_standings_in_database().await;

        Ok(global_state_mut.flush_databases().await?)
    }

    // Locking:
    //   * acquires `global_state_lock` for write
    //
    // documented in trait. do not add doc-comment.
    async fn clear_standing_by_ip(
        mut self,
        _: context::Context,
        token: rpc_auth::Token,
        ip: IpAddr,
    ) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let mut global_state_mut = self.state.lock_guard_mut().await;
        global_state_mut
            .net
            .peer_map
            .iter_mut()
            .for_each(|(socketaddr, peerinfo)| {
                if socketaddr.ip() == ip {
                    peerinfo.standing.clear_standing();
                }
            });

        //Also clears this IP's standing in database, whether it is connected or not.
        global_state_mut.net.clear_ip_standing_in_database(ip).await;

        Ok(global_state_mut.flush_databases().await?)
    }

    // documented in trait. do not add doc-comment.
    async fn send(
        self,
        ctx: context::Context,
        token: rpc_auth::Token,
        amount: NativeCurrencyAmount,
        address: ReceivingAddress,
        owned_utxo_notify_method: UtxoNotificationMedium,
        unowned_utxo_notify_medium: UtxoNotificationMedium,
        fee: NativeCurrencyAmount,
    ) -> RpcResult<(TransactionKernelId, Vec<PrivateNotificationData>)> {
        log_slow_scope!(fn_name!());

        // note: we do not call token.auth() because send_to_many() does it.

        self.send_to_many(
            ctx,
            token,
            vec![(address, amount)],
            owned_utxo_notify_method,
            unowned_utxo_notify_medium,
            fee,
        )
        .await
    }

    // Locking:
    //   * acquires `global_state_lock` for write
    //
    // TODO: add an endpoint to get recommended fee density.
    //
    // documented in trait. do not add doc-comment.
    async fn send_to_many(
        self,
        ctx: context::Context,
        token: rpc_auth::Token,
        outputs: Vec<(ReceivingAddress, NativeCurrencyAmount)>,
        owned_utxo_notification_medium: UtxoNotificationMedium,
        unowned_utxo_notification_medium: UtxoNotificationMedium,
        fee: NativeCurrencyAmount,
    ) -> RpcResult<(TransactionKernelId, Vec<PrivateNotificationData>)> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        tracing::debug!("stm: entered fn");

        if self.state.cli().no_transaction_initiation {
            warn!("Cannot initiate transaction because `--no-transaction-initiation` flag is set.");
            return Err(error::SendError::Unsupported.into());
        }

        // abort early on negative fee
        if fee.is_negative() {
            warn!("Cannot send negative-fee transaction.");
            return Err(error::SendError::NegativeFee.into());
        }

        match self.state.cli().proving_capability() {
            TxProvingCapability::LockScript | TxProvingCapability::PrimitiveWitness => {
                warn!("Cannot initiate transaction because transaction proving capability is too weak.");
                return Err(error::SendError::TooWeak.into());
            }
            TxProvingCapability::ProofCollection | TxProvingCapability::SingleProof => (),
        };

        // The proving capability is set to the lowest possible value here,
        // since we don't want the client (CLI or dashboard) to hang while
        // producing proofs. Instead, we let (a task started by) main loop
        // handle the proving.
        let tx_proving_capability = TxProvingCapability::PrimitiveWitness;
        Ok(self
            .send_to_many_inner(
                ctx,
                outputs,
                (
                    owned_utxo_notification_medium,
                    unowned_utxo_notification_medium,
                ),
                fee,
                Timestamp::now(),
                tx_proving_capability,
            )
            .await?)
    }

    // // documented in trait. do not add doc-comment.
    async fn claim_utxo(
        mut self,
        _ctx: context::Context,
        token: rpc_auth::Token,
        encrypted_utxo_notification: String,
        max_search_depth: Option<u64>,
    ) -> RpcResult<bool> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let claim_data = self
            .claim_utxo_inner(encrypted_utxo_notification, max_search_depth)
            .await?;

        let Some(claim_data) = claim_data else {
            // UTXO has already been claimed by wallet
            warn!("UTXO notification of amount was already received. Not adding again.");
            return Ok(false);
        };

        let expected_utxo_was_new = !claim_data.has_expected_utxo;
        self.state
            .lock_guard_mut()
            .await
            .wallet_state
            .claim_utxo(claim_data)
            .await
            .map_err(error::ClaimError::from)?;

        Ok(expected_utxo_was_new)
    }

    // documented in trait. do not add doc-comment.
    async fn shutdown(self, _: context::Context, token: rpc_auth::Token) -> RpcResult<bool> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        // 1. Send shutdown message to main
        let response = self
            .rpc_server_to_main_tx
            .send(RPCServerToMain::Shutdown)
            .await;

        // 2. Send acknowledgement to client.
        Ok(response.is_ok())
    }

    // documented in trait. do not add doc-comment.
    async fn pause_miner(
        self,
        _context: tarpc::context::Context,
        token: rpc_auth::Token,
    ) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        if self.state.cli().mine() {
            let _ = self
                .rpc_server_to_main_tx
                .send(RPCServerToMain::PauseMiner)
                .await;
        } else {
            info!("Cannot pause miner since it was never started");
        }
        Ok(())
    }

    // documented in trait. do not add doc-comment.
    async fn restart_miner(
        self,
        _context: tarpc::context::Context,
        token: rpc_auth::Token,
    ) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        if self.state.cli().mine() {
            let _ = self
                .rpc_server_to_main_tx
                .send(RPCServerToMain::RestartMiner)
                .await;
        } else {
            info!("Cannot restart miner since it was never started");
        }
        Ok(())
    }

    // documented in trait. do not add doc-comment.
    async fn prune_abandoned_monitored_utxos(
        mut self,
        _context: tarpc::context::Context,
        token: rpc_auth::Token,
    ) -> RpcResult<usize> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let mut global_state_mut = self.state.lock_guard_mut().await;
        const DEFAULT_MUTXO_PRUNE_DEPTH: usize = 200;

        let prune_count_res = global_state_mut
            .prune_abandoned_monitored_utxos(DEFAULT_MUTXO_PRUNE_DEPTH)
            .await;

        global_state_mut
            .flush_databases()
            .await
            .expect("flushed DBs");

        match prune_count_res {
            Ok(prune_count) => {
                info!("Marked {prune_count} monitored UTXOs as abandoned");
                Ok(prune_count)
            }
            Err(err) => {
                error!("Pruning monitored UTXOs failed with error: {err}");
                Ok(0)
            }
        }
    }

    // documented in trait. do not add doc-comment.
    async fn list_own_coins(
        self,
        _context: ::tarpc::context::Context,
        token: rpc_auth::Token,
    ) -> RpcResult<Vec<CoinWithPossibleTimeLock>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let state = self.state.lock_guard().await;
        let tip = state.chain.light_state();
        let tip_hash = tip.hash();
        let tip_msa = tip.mutator_set_accumulator_after();

        Ok(state
            .wallet_state
            .get_all_own_coins_with_possible_timelocks(&tip_msa, tip_hash)
            .await)
    }

    // documented in trait. do not add doc-comment.
    async fn cpu_temp(
        self,
        _context: tarpc::context::Context,
        token: rpc_auth::Token,
    ) -> RpcResult<Option<f32>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(Self::cpu_temp_inner())
    }

    // documented in trait. do not add doc-comment.
    async fn block_intervals(
        self,
        _context: tarpc::context::Context,
        token: rpc_auth::Token,
        last_block: BlockSelector,
        max_num_blocks: Option<usize>,
    ) -> RpcResult<Option<Vec<(u64, u64)>>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let state = self.state.lock_guard().await;
        let last_block = match last_block.as_digest(&state).await {
            Some(d) => d,
            None => return Ok(None),
        };
        let mut intervals = vec![];
        let mut current = state
            .chain
            .archival_state()
            .get_block_header(last_block)
            .await
            .expect("If digest can be found, block header should also be known");
        let mut parent = state
            .chain
            .archival_state()
            .get_block_header(current.prev_block_digest)
            .await;

        // Exclude genesis since it was not mined. So block interval 0-->1
        // is not included.
        while parent.is_some()
            && !parent.unwrap().height.is_genesis()
            && max_num_blocks.is_none_or(|max_num| max_num > intervals.len())
        {
            let parent_ = parent.unwrap();
            let interval = current.timestamp.to_millis() - parent_.timestamp.to_millis();
            let block_height: u64 = current.height.into();
            intervals.push((block_height, interval));
            current = parent_;
            parent = state
                .chain
                .archival_state()
                .get_block_header(current.prev_block_digest)
                .await;
        }

        Ok(Some(intervals))
    }

    async fn block_difficulties(
        self,
        _context: tarpc::context::Context,
        token: rpc_auth::Token,
        last_block: BlockSelector,
        max_num_blocks: Option<usize>,
    ) -> RpcResult<Vec<(u64, Difficulty)>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let state = self.state.lock_guard().await;
        let last_block = last_block.as_digest(&state).await;
        let Some(last_block) = last_block else {
            return Ok(vec![]);
        };

        let mut difficulties = vec![];

        let mut current = state
            .chain
            .archival_state()
            .get_block_header(last_block)
            .await;
        while current.is_some()
            && max_num_blocks.is_none_or(|max_num| max_num >= difficulties.len())
        {
            let current_ = current.unwrap();
            let height: u64 = current_.height.into();
            difficulties.push((height, current_.difficulty));
            current = state
                .chain
                .archival_state()
                .get_block_header(current_.prev_block_digest)
                .await;
        }

        Ok(difficulties)
    }

    // documented in trait. do not add doc-comment.
    async fn mempool_overview(
        self,
        _context: ::tarpc::context::Context,
        token: rpc_auth::Token,
        start_index: usize,
        number: usize,
    ) -> RpcResult<Vec<MempoolTransactionInfo>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let global_state = self.state.lock_guard().await;
        let mempool_txkids = global_state
            .mempool
            .get_sorted_iter()
            .skip(start_index)
            .take(number)
            .map(|(txkid, _)| txkid)
            .collect_vec();

        let (incoming, outgoing): (HashMap<_, _>, HashMap<_, _>) = {
            let (incoming_iter, outgoing_iter) =
                global_state.wallet_state.mempool_balance_updates();
            (incoming_iter.collect(), outgoing_iter.collect())
        };

        let tip_msah = global_state
            .chain
            .light_state()
            .mutator_set_accumulator_after()
            .hash();

        let mempool_transactions = mempool_txkids
            .iter()
            .filter_map(|id| {
                let mut mptxi = global_state
                    .mempool
                    .get(*id)
                    .map(|tx| (MempoolTransactionInfo::from(tx), tx.kernel.mutator_set_hash))
                    .map(|(mptxi, tx_msah)| {
                        if tx_msah == tip_msah {
                            mptxi.synced()
                        } else {
                            mptxi
                        }
                    });
                if mptxi.is_some() {
                    if let Some(pos_effect) = incoming.get(id) {
                        mptxi = Some(mptxi.unwrap().with_positive_effect_on_balance(*pos_effect));
                    }
                    if let Some(neg_effect) = outgoing.get(id) {
                        mptxi = Some(mptxi.unwrap().with_negative_effect_on_balance(*neg_effect));
                    }
                }

                mptxi
            })
            .collect_vec();

        Ok(mempool_transactions)
    }
}

pub mod error {
    use super::*;

    /// enumerates possible rpc api errors
    #[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
    #[non_exhaustive]
    pub enum RpcError {
        // auth error
        #[error(transparent)]
        Auth(#[from] rpc_auth::error::AuthError),

        // catch-all error, eg for anyhow errors
        #[error("rpc call failed")]
        Failed(String),

        // API specific error variants.
        #[error("cookie hints are disabled on this node")]
        CookieHintDisabled,

        #[error(transparent)]
        SendError(#[from] SendError),

        #[error(transparent)]
        ClaimError(#[from] ClaimError),
    }

    // convert anyhow::Error to an RpcError::Failed.
    // note that anyhow Error is not serializable.
    impl From<anyhow::Error> for RpcError {
        fn from(e: anyhow::Error) -> Self {
            Self::Failed(e.to_string())
        }
    }

    /// enumerates possible transaction send errors
    #[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
    #[non_exhaustive]
    pub enum SendError {
        #[error("send() is not supported by this node")]
        Unsupported,

        #[error("transaction could not be broadcast.")]
        NotBroadcast,

        // catch-all error, eg for anyhow errors
        #[error("transaction could not be sent.  reason: {0}")]
        Failed(String),

        #[error("Transaction with negative fees not allowed")]
        NegativeFee,

        #[error("machine too weak to initiate transactions")]
        TooWeak,

        #[error("Send rate limit reached for block height {height} ({digest}). A maximum of {max} tx may be sent per block.", digest = tip_digest.to_hex())]
        RateLimit {
            height: BlockHeight,
            tip_digest: Digest,
            max: usize,
        },
    }

    // convert anyhow::Error to a SendError::Failed.
    // note that anyhow Error is not serializable.
    impl From<anyhow::Error> for SendError {
        fn from(e: anyhow::Error) -> Self {
            Self::Failed(e.to_string())
        }
    }

    /// enumerates possible transaction send errors
    #[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
    #[non_exhaustive]
    pub enum ClaimError {
        #[error("utxo does not match any known wallet key")]
        UtxoUnknown,

        #[error("invalid type script in claim utxo")]
        InvalidTypeScript,

        // catch-all error, eg for anyhow errors
        #[error("claim unsuccessful")]
        Failed(String),
    }

    // convert anyhow::Error to a ClaimError::Failed.
    // note that anyhow Error is not serializable.
    impl From<anyhow::Error> for ClaimError {
        fn from(e: anyhow::Error) -> Self {
            Self::Failed(e.to_string())
        }
    }
}

#[cfg(test)]
mod rpc_server_tests {
    use anyhow::Result;
    use num_traits::One;
    use num_traits::Zero;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use strum::IntoEnumIterator;
    use tracing_test::traced_test;

    use super::*;
    use crate::config_models::cli_args;
    use crate::config_models::network::Network;
    use crate::database::storage::storage_vec::traits::*;
    use crate::models::peer::NegativePeerSanction;
    use crate::models::peer::PeerSanction;
    use crate::models::state::wallet::address::generation_address::GenerationSpendingKey;
    use crate::models::state::wallet::WalletSecret;
    use crate::rpc_server::NeptuneRPCServer;
    use crate::tests::shared::make_mock_block;
    use crate::tests::shared::mock_genesis_global_state;
    use crate::tests::shared::unit_test_data_directory;
    use crate::Block;
    use crate::RPC_CHANNEL_CAPACITY;

    async fn test_rpc_server(
        network: Network,
        wallet_secret: WalletSecret,
        peer_count: u8,
        cli: cli_args::Args,
    ) -> NeptuneRPCServer {
        let global_state_lock =
            mock_genesis_global_state(network, peer_count, wallet_secret, cli).await;
        let (dummy_tx, mut dummy_rx) =
            tokio::sync::mpsc::channel::<RPCServerToMain>(RPC_CHANNEL_CAPACITY);

        tokio::spawn(async move {
            while let Some(i) = dummy_rx.recv().await {
                tracing::trace!("mock Main got message = {:?}", i);
            }
        });

        let data_directory = unit_test_data_directory(network).unwrap();

        let valid_tokens: Vec<rpc_auth::Token> = vec![rpc_auth::Cookie::try_new(&data_directory)
            .await
            .unwrap()
            .into()];

        NeptuneRPCServer::new(global_state_lock, dummy_tx, data_directory, valid_tokens)
    }

    async fn cookie_token(server: &NeptuneRPCServer) -> rpc_auth::Token {
        rpc_auth::Cookie::try_load(server.data_directory())
            .await
            .unwrap()
            .into()
    }

    #[tokio::test]
    async fn network_response_is_consistent() -> Result<()> {
        // Verify that a wallet not receiving a premine is empty at startup
        for network in Network::iter() {
            let rpc_server = test_rpc_server(
                network,
                WalletSecret::new_random(),
                2,
                cli_args::Args {
                    network,
                    ..Default::default()
                },
            )
            .await;
            assert_eq!(network, rpc_server.network(context::current()).await?);
        }

        Ok(())
    }

    #[tokio::test]
    async fn verify_that_all_requests_leave_server_running() -> Result<()> {
        // Got through *all* request types and verify that server does not crash.
        // We don't care about the actual response data in this test, just that the
        // requests do not crash the server.

        let network = Network::Main;
        let mut rng = StdRng::seed_from_u64(123456789088u64);

        let rpc_server = test_rpc_server(
            network,
            WalletSecret::new_pseudorandom(rng.random()),
            2,
            cli_args::Args::default(),
        )
        .await;
        let token = cookie_token(&rpc_server).await;
        let ctx = context::current();
        let _ = rpc_server.clone().network(ctx).await;
        let _ = rpc_server
            .clone()
            .own_listen_address_for_peers(ctx, token)
            .await;
        let _ = rpc_server.clone().own_instance_id(ctx, token).await;
        let _ = rpc_server.clone().block_height(ctx, token).await;
        let _ = rpc_server.clone().peer_info(ctx, token).await;
        let _ = rpc_server
            .clone()
            .block_digests_by_height(ctx, token, 42u64.into())
            .await;
        let _ = rpc_server
            .clone()
            .block_digests_by_height(ctx, token, 0u64.into())
            .await;
        let _ = rpc_server.clone().all_punished_peers(ctx, token).await;
        let _ = rpc_server.clone().latest_tip_digests(ctx, token, 2).await;
        let _ = rpc_server
            .clone()
            .header(ctx, token, BlockSelector::Digest(Digest::default()))
            .await;
        let _ = rpc_server
            .clone()
            .block_info(ctx, token, BlockSelector::Digest(Digest::default()))
            .await;
        let _ = rpc_server
            .clone()
            .block_digest(ctx, token, BlockSelector::Digest(Digest::default()))
            .await;
        let _ = rpc_server.clone().utxo_digest(ctx, token, 0).await;
        let _ = rpc_server
            .clone()
            .confirmed_available_balance(ctx, token)
            .await;
        let _ = rpc_server.clone().history(ctx, token).await;
        let _ = rpc_server.clone().wallet_status(ctx, token).await;
        let own_receiving_address = rpc_server
            .clone()
            .next_receiving_address(ctx, token, KeyType::Generation)
            .await?
            .unwrap();
        let _ = rpc_server.clone().mempool_tx_count(ctx, token).await;
        let _ = rpc_server.clone().mempool_size(ctx, token).await;
        let _ = rpc_server.clone().dashboard_overview_data(ctx, token).await;
        let _ = rpc_server
            .clone()
            .validate_address(
                ctx,
                token,
                "Not a valid address".to_owned(),
                Network::Testnet,
            )
            .await;
        let _ = rpc_server
            .clone()
            .block_intervals(ctx, token, BlockSelector::Tip, None)
            .await;
        let _ = rpc_server
            .clone()
            .block_difficulties(ctx, token, BlockSelector::Tip, None)
            .await;
        let _ = rpc_server.clone().mempool_overview(ctx, token, 0, 20).await;
        let _ = rpc_server.clone().clear_all_standings(ctx, token).await;
        let _ = rpc_server
            .clone()
            .clear_standing_by_ip(ctx, token, "127.0.0.1".parse().unwrap())
            .await;
        let _ = rpc_server
            .clone()
            .send(
                ctx,
                token,
                NativeCurrencyAmount::one(),
                own_receiving_address.clone(),
                UtxoNotificationMedium::OffChain,
                UtxoNotificationMedium::OffChain,
                NativeCurrencyAmount::one(),
            )
            .await;

        let transaction_timestamp = network.launch_date();
        let proving_capability = rpc_server.state.cli().proving_capability();
        let _ = rpc_server
            .clone()
            .send_to_many_inner(
                ctx,
                vec![(own_receiving_address, NativeCurrencyAmount::one())],
                (
                    UtxoNotificationMedium::OffChain,
                    UtxoNotificationMedium::OffChain,
                ),
                NativeCurrencyAmount::one(),
                transaction_timestamp,
                proving_capability,
            )
            .await;
        let _ = rpc_server.clone().pause_miner(ctx, token).await;
        let _ = rpc_server.clone().restart_miner(ctx, token).await;
        let _ = rpc_server
            .clone()
            .prune_abandoned_monitored_utxos(ctx, token)
            .await;
        let _ = rpc_server.shutdown(ctx, token).await;

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn balance_is_zero_at_init() -> Result<()> {
        // Verify that a wallet not receiving a premine is empty at startup
        let rpc_server = test_rpc_server(
            Network::Alpha,
            WalletSecret::new_random(),
            2,
            cli_args::Args::default(),
        )
        .await;
        let token = cookie_token(&rpc_server).await;
        let balance = rpc_server
            .confirmed_available_balance(context::current(), token)
            .await?;
        assert!(balance.is_zero());

        Ok(())
    }

    #[allow(clippy::shadow_unrelated)]
    #[traced_test]
    #[tokio::test]
    async fn clear_ip_standing_test() -> Result<()> {
        let mut rpc_server = test_rpc_server(
            Network::Alpha,
            WalletSecret::new_random(),
            2,
            cli_args::Args::default(),
        )
        .await;
        let token = cookie_token(&rpc_server).await;
        let rpc_request_context = context::current();
        let (peer_address0, peer_address1) = {
            let global_state = rpc_server.state.lock_guard().await;

            (
                global_state.net.peer_map.values().collect::<Vec<_>>()[0].connected_address(),
                global_state.net.peer_map.values().collect::<Vec<_>>()[1].connected_address(),
            )
        };

        // Verify that sanctions list is empty
        let punished_peers_startup = rpc_server
            .clone()
            .all_punished_peers(rpc_request_context, token)
            .await?;
        assert!(
            punished_peers_startup.is_empty(),
            "Sanctions list must be empty at startup"
        );

        // sanction both
        let (standing0, standing1) = {
            let mut global_state_mut = rpc_server.state.lock_guard_mut().await;

            global_state_mut
                .net
                .peer_map
                .entry(peer_address0)
                .and_modify(|p| {
                    p.standing
                        .sanction(PeerSanction::Negative(
                            NegativePeerSanction::DifferentGenesis,
                        ))
                        .unwrap_err();
                });
            global_state_mut
                .net
                .peer_map
                .entry(peer_address1)
                .and_modify(|p| {
                    p.standing
                        .sanction(PeerSanction::Negative(
                            NegativePeerSanction::DifferentGenesis,
                        ))
                        .unwrap_err();
                });
            let standing_0 = global_state_mut.net.peer_map[&peer_address0].standing;
            let standing_1 = global_state_mut.net.peer_map[&peer_address1].standing;
            (standing_0, standing_1)
        };

        // Verify expected sanctions reading
        let punished_peers_from_memory = rpc_server
            .clone()
            .all_punished_peers(rpc_request_context, token)
            .await?;
        assert_eq!(
            2,
            punished_peers_from_memory.len(),
            "Punished list must have two elements after sanctionings"
        );

        {
            let mut global_state_mut = rpc_server.state.lock_guard_mut().await;

            global_state_mut
                .net
                .write_peer_standing_on_decrease(peer_address0.ip(), standing0)
                .await;
            global_state_mut
                .net
                .write_peer_standing_on_decrease(peer_address1.ip(), standing1)
                .await;
        }

        // Verify expected sanctions reading, after DB-write
        let punished_peers_from_memory_and_db = rpc_server
            .clone()
            .all_punished_peers(rpc_request_context, token)
            .await?;
        assert_eq!(
            2,
            punished_peers_from_memory_and_db.len(),
            "Punished list must have to elements after sanctionings and after DB write"
        );

        // Verify expected initial conditions
        {
            let global_state = rpc_server.state.lock_guard().await;
            let standing0 = global_state
                .net
                .get_peer_standing_from_database(peer_address0.ip())
                .await;
            assert_ne!(0, standing0.unwrap().standing);
            assert_ne!(None, standing0.unwrap().latest_punishment);
            let peer_standing_1 = global_state
                .net
                .get_peer_standing_from_database(peer_address1.ip())
                .await;
            assert_ne!(0, peer_standing_1.unwrap().standing);
            assert_ne!(None, peer_standing_1.unwrap().latest_punishment);
            drop(global_state);

            // Clear standing of #0
            rpc_server
                .clone()
                .clear_standing_by_ip(rpc_request_context, token, peer_address0.ip())
                .await?;
        }

        // Verify expected resulting conditions in database
        {
            let global_state = rpc_server.state.lock_guard().await;
            let standing0 = global_state
                .net
                .get_peer_standing_from_database(peer_address0.ip())
                .await;
            assert_eq!(0, standing0.unwrap().standing);
            assert_eq!(None, standing0.unwrap().latest_punishment);
            let standing1 = global_state
                .net
                .get_peer_standing_from_database(peer_address1.ip())
                .await;
            assert_ne!(0, standing1.unwrap().standing);
            assert_ne!(None, standing1.unwrap().latest_punishment);

            // Verify expected resulting conditions in peer map
            let standing0_from_memory = global_state.net.peer_map[&peer_address0].clone();
            assert_eq!(0, standing0_from_memory.standing.standing);
            let standing1_from_memory = global_state.net.peer_map[&peer_address1].clone();
            assert_ne!(0, standing1_from_memory.standing.standing);
        }

        // Verify expected sanctions reading, after one forgiveness
        let punished_list_after_one_clear = rpc_server
            .clone()
            .all_punished_peers(rpc_request_context, token)
            .await?;
        assert!(
            punished_list_after_one_clear.len().is_one(),
            "Punished list must have to elements after sanctionings and after DB write"
        );

        Ok(())
    }

    #[allow(clippy::shadow_unrelated)]
    #[traced_test]
    #[tokio::test]
    async fn clear_all_standings_test() -> Result<()> {
        // Create initial conditions
        let mut rpc_server = test_rpc_server(
            Network::Alpha,
            WalletSecret::new_random(),
            2,
            cli_args::Args::default(),
        )
        .await;
        let token = cookie_token(&rpc_server).await;
        let mut state = rpc_server.state.lock_guard_mut().await;
        let peer_address0 = state.net.peer_map.values().collect::<Vec<_>>()[0].connected_address();
        let peer_address1 = state.net.peer_map.values().collect::<Vec<_>>()[1].connected_address();

        // sanction both peers
        let (standing0, standing1) = {
            state.net.peer_map.entry(peer_address0).and_modify(|p| {
                p.standing
                    .sanction(PeerSanction::Negative(
                        NegativePeerSanction::DifferentGenesis,
                    ))
                    .unwrap_err();
            });
            state.net.peer_map.entry(peer_address1).and_modify(|p| {
                p.standing
                    .sanction(PeerSanction::Negative(
                        NegativePeerSanction::DifferentGenesis,
                    ))
                    .unwrap_err();
            });
            (
                state.net.peer_map[&peer_address0].standing,
                state.net.peer_map[&peer_address1].standing,
            )
        };

        state
            .net
            .write_peer_standing_on_decrease(peer_address0.ip(), standing0)
            .await;
        state
            .net
            .write_peer_standing_on_decrease(peer_address1.ip(), standing1)
            .await;

        drop(state);

        // Verify expected initial conditions
        {
            let peer_standing0 = rpc_server
                .state
                .lock_guard_mut()
                .await
                .net
                .get_peer_standing_from_database(peer_address0.ip())
                .await;
            assert_ne!(0, peer_standing0.unwrap().standing);
            assert_ne!(None, peer_standing0.unwrap().latest_punishment);
        }

        {
            let peer_standing1 = rpc_server
                .state
                .lock_guard_mut()
                .await
                .net
                .get_peer_standing_from_database(peer_address1.ip())
                .await;
            assert_ne!(0, peer_standing1.unwrap().standing);
            assert_ne!(None, peer_standing1.unwrap().latest_punishment);
        }

        // Verify expected reading through an RPC call
        let rpc_request_context = context::current();
        let after_two_sanctions = rpc_server
            .clone()
            .all_punished_peers(rpc_request_context, token)
            .await?;
        assert_eq!(2, after_two_sanctions.len());

        // Clear standing of both by clearing all standings
        rpc_server
            .clone()
            .clear_all_standings(rpc_request_context, token)
            .await?;

        let state = rpc_server.state.lock_guard().await;

        // Verify expected resulting conditions in database
        {
            let peer_standing_0 = state
                .net
                .get_peer_standing_from_database(peer_address0.ip())
                .await;
            assert_eq!(0, peer_standing_0.unwrap().standing);
            assert_eq!(None, peer_standing_0.unwrap().latest_punishment);
        }

        {
            let peer_still_standing_1 = state
                .net
                .get_peer_standing_from_database(peer_address1.ip())
                .await;
            assert_eq!(0, peer_still_standing_1.unwrap().standing);
            assert_eq!(None, peer_still_standing_1.unwrap().latest_punishment);
        }

        // Verify expected resulting conditions in peer map
        {
            let peer_standing_0_from_memory = state.net.peer_map[&peer_address0].clone();
            assert_eq!(0, peer_standing_0_from_memory.standing.standing);
        }

        {
            let peer_still_standing_1_from_memory = state.net.peer_map[&peer_address1].clone();
            assert_eq!(0, peer_still_standing_1_from_memory.standing.standing);
        }

        // Verify expected reading through an RPC call
        let after_global_forgiveness = rpc_server
            .clone()
            .all_punished_peers(rpc_request_context, token)
            .await?;
        assert!(after_global_forgiveness.is_empty());

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn utxo_digest_test() {
        let rpc_server = test_rpc_server(
            Network::Alpha,
            WalletSecret::new_random(),
            2,
            cli_args::Args::default(),
        )
        .await;
        let token = cookie_token(&rpc_server).await;
        let aocl_leaves = rpc_server
            .state
            .lock_guard()
            .await
            .chain
            .archival_state()
            .archival_mutator_set
            .ams()
            .aocl
            .num_leafs()
            .await;

        debug_assert!(aocl_leaves > 0);

        assert!(rpc_server
            .clone()
            .utxo_digest(context::current(), token, aocl_leaves - 1)
            .await
            .unwrap()
            .is_some());

        assert!(rpc_server
            .utxo_digest(context::current(), token, aocl_leaves)
            .await
            .unwrap()
            .is_none());
    }

    #[traced_test]
    #[tokio::test]
    async fn block_info_test() {
        let network = Network::RegTest;
        let rpc_server = test_rpc_server(
            network,
            WalletSecret::new_random(),
            2,
            cli_args::Args::default(),
        )
        .await;
        let token = cookie_token(&rpc_server).await;
        let global_state = rpc_server.state.lock_guard().await;
        let ctx = context::current();

        let genesis_hash = global_state.chain.archival_state().genesis_block().hash();
        let tip_hash = global_state.chain.light_state().hash();

        let genesis_block_info = BlockInfo::new(
            global_state.chain.archival_state().genesis_block(),
            genesis_hash,
            tip_hash,
            vec![],
            global_state
                .chain
                .archival_state()
                .block_belongs_to_canonical_chain(genesis_hash)
                .await,
        );

        let tip_block_info = BlockInfo::new(
            global_state.chain.light_state(),
            genesis_hash,
            tip_hash,
            vec![],
            global_state
                .chain
                .archival_state()
                .block_belongs_to_canonical_chain(tip_hash)
                .await,
        );

        // should find genesis block by Genesis selector
        assert_eq!(
            genesis_block_info,
            rpc_server
                .clone()
                .block_info(ctx, token, BlockSelector::Genesis)
                .await
                .unwrap()
                .unwrap()
        );

        // should find latest/tip block by Tip selector
        assert_eq!(
            tip_block_info,
            rpc_server
                .clone()
                .block_info(ctx, token, BlockSelector::Tip)
                .await
                .unwrap()
                .unwrap()
        );

        // should find genesis block by Height selector
        assert_eq!(
            genesis_block_info,
            rpc_server
                .clone()
                .block_info(ctx, token, BlockSelector::Height(BlockHeight::from(0u64)))
                .await
                .unwrap()
                .unwrap()
        );

        // should find genesis block by Digest selector
        assert_eq!(
            genesis_block_info,
            rpc_server
                .clone()
                .block_info(ctx, token, BlockSelector::Digest(genesis_hash))
                .await
                .unwrap()
                .unwrap()
        );

        // should not find any block when Height selector is u64::Max
        assert!(rpc_server
            .clone()
            .block_info(
                ctx,
                token,
                BlockSelector::Height(BlockHeight::from(u64::MAX))
            )
            .await
            .unwrap()
            .is_none());

        // should not find any block when Digest selector is Digest::default()
        assert!(rpc_server
            .clone()
            .block_info(ctx, token, BlockSelector::Digest(Digest::default()))
            .await
            .unwrap()
            .is_none());
    }

    #[traced_test]
    #[tokio::test]
    async fn block_digest_test() {
        let network = Network::RegTest;
        let rpc_server = test_rpc_server(
            network,
            WalletSecret::new_random(),
            2,
            cli_args::Args::default(),
        )
        .await;
        let token = cookie_token(&rpc_server).await;
        let global_state = rpc_server.state.lock_guard().await;
        let ctx = context::current();

        let genesis_hash = Block::genesis(network).hash();

        // should find genesis block by Genesis selector
        assert_eq!(
            genesis_hash,
            rpc_server
                .clone()
                .block_digest(ctx, token, BlockSelector::Genesis)
                .await
                .unwrap()
                .unwrap()
        );

        // should find latest/tip block by Tip selector
        assert_eq!(
            global_state.chain.light_state().hash(),
            rpc_server
                .clone()
                .block_digest(ctx, token, BlockSelector::Tip)
                .await
                .unwrap()
                .unwrap()
        );

        // should find genesis block by Height selector
        assert_eq!(
            genesis_hash,
            rpc_server
                .clone()
                .block_digest(ctx, token, BlockSelector::Height(BlockHeight::from(0u64)))
                .await
                .unwrap()
                .unwrap()
        );

        // should find genesis block by Digest selector
        assert_eq!(
            genesis_hash,
            rpc_server
                .clone()
                .block_digest(ctx, token, BlockSelector::Digest(genesis_hash))
                .await
                .unwrap()
                .unwrap()
        );

        // should not find any block when Height selector is u64::Max
        assert!(rpc_server
            .clone()
            .block_digest(
                ctx,
                token,
                BlockSelector::Height(BlockHeight::from(u64::MAX))
            )
            .await
            .unwrap()
            .is_none());

        // should not find any block when Digest selector is Digest::default()
        assert!(rpc_server
            .clone()
            .block_digest(ctx, token, BlockSelector::Digest(Digest::default()))
            .await
            .unwrap()
            .is_none());
    }

    #[traced_test]
    #[tokio::test]
    async fn getting_temperature_doesnt_crash_test() {
        // On your local machine, this should return a temperature but in CI,
        // the RPC call returns `None`, so we only verify that the call doesn't
        // crash the host machine, we don't verify that any value is returned.
        let rpc_server = test_rpc_server(
            Network::Alpha,
            WalletSecret::new_random(),
            2,
            cli_args::Args::default(),
        )
        .await;
        let token = cookie_token(&rpc_server).await;
        let _current_server_temperature = rpc_server
            .cpu_temp(context::current(), token)
            .await
            .unwrap();
    }

    #[traced_test]
    #[tokio::test]
    async fn cannot_initiate_transaction_if_notx_flag_is_set() {
        let network = Network::Main;
        let ctx = context::current();
        let mut rng = rand::rng();
        let address = GenerationSpendingKey::derive_from_seed(rng.random()).to_address();
        let amount = NativeCurrencyAmount::coins(rng.random_range(0..10));

        // set flag on, verify non-initiation
        let cli_on = cli_args::Args {
            no_transaction_initiation: true,
            ..Default::default()
        };

        let rpc_server = test_rpc_server(network, WalletSecret::new_random(), 2, cli_on).await;
        let token = cookie_token(&rpc_server).await;

        assert!(rpc_server
            .clone()
            .send(
                ctx,
                token,
                amount,
                address.into(),
                UtxoNotificationMedium::OffChain,
                UtxoNotificationMedium::OffChain,
                NativeCurrencyAmount::zero()
            )
            .await
            .is_err());
        assert!(rpc_server
            .clone()
            .send_to_many(
                ctx,
                token,
                vec![(address.into(), amount)],
                UtxoNotificationMedium::OffChain,
                UtxoNotificationMedium::OffChain,
                NativeCurrencyAmount::zero()
            )
            .await
            .is_err());
    }

    mod claim_utxo_tests {
        use super::*;

        #[traced_test]
        #[allow(clippy::needless_return)]
        #[tokio::test]
        async fn claim_utxo_owned_before_confirmed() -> Result<()> {
            worker::claim_utxo_owned(false, false).await
        }

        #[traced_test]
        #[allow(clippy::needless_return)]
        #[tokio::test]
        async fn claim_utxo_owned_after_confirmed() -> Result<()> {
            worker::claim_utxo_owned(true, false).await
        }

        #[traced_test]
        #[allow(clippy::needless_return)]
        #[tokio::test]
        async fn claim_utxo_owned_after_confirmed_and_after_spent() -> Result<()> {
            worker::claim_utxo_owned(true, true).await
        }

        #[traced_test]
        #[allow(clippy::needless_return)]
        #[tokio::test]
        async fn claim_utxo_unowned_before_confirmed() -> Result<()> {
            worker::claim_utxo_unowned(false).await
        }

        #[traced_test]
        #[allow(clippy::needless_return)]
        #[tokio::test]
        async fn claim_utxo_unowned_after_confirmed() -> Result<()> {
            worker::claim_utxo_unowned(true).await
        }

        mod worker {
            use cli_args::Args;

            use super::*;
            use crate::tests::shared::invalid_block_with_transaction;
            use crate::tests::shared::invalid_empty_block;

            pub(super) async fn claim_utxo_unowned(claim_after_confirmed: bool) -> Result<()> {
                let network = Network::Main;

                // bob's node
                let (pay_to_bob_outputs, bob_rpc_server, bob_token) = {
                    let rpc_server =
                        test_rpc_server(network, WalletSecret::new_random(), 2, Args::default())
                            .await;
                    let token = cookie_token(&rpc_server).await;

                    let receiving_address_generation = rpc_server
                        .clone()
                        .next_receiving_address(context::current(), token, KeyType::Generation)
                        .await?
                        .unwrap();
                    let receiving_address_symmetric = rpc_server
                        .clone()
                        .next_receiving_address(context::current(), token, KeyType::Symmetric)
                        .await?
                        .unwrap();

                    let pay_to_bob_outputs = vec![
                        (receiving_address_generation, NativeCurrencyAmount::coins(1)),
                        (receiving_address_symmetric, NativeCurrencyAmount::coins(2)),
                    ];

                    (pay_to_bob_outputs, rpc_server, token)
                };

                // alice's node
                let (blocks, alice_to_bob_utxo_notifications, bob_amount) = {
                    let wallet_secret = WalletSecret::new_random();
                    let mut rpc_server =
                        test_rpc_server(network, wallet_secret.clone(), 2, Args::default()).await;

                    let genesis_block = Block::genesis(network);
                    let mut blocks = vec![];
                    let in_seven_months = genesis_block.header().timestamp + Timestamp::months(7);

                    let fee = NativeCurrencyAmount::zero();
                    let bob_amount: NativeCurrencyAmount =
                        pay_to_bob_outputs.iter().map(|(_, amt)| *amt).sum();

                    // Mine block 1 to get some coins

                    let cb_key = wallet_secret.nth_generation_spending_key(0);
                    let (block1, composer_expected_utxos) =
                        make_mock_block(&genesis_block, None, cb_key, Default::default()).await;
                    blocks.push(block1.clone());

                    rpc_server
                        .state
                        .set_new_self_composed_tip(block1.clone(), composer_expected_utxos)
                        .await
                        .unwrap();

                    let (tx, offchain_notifications) = rpc_server
                        .clone()
                        .send_to_many_inner_invalid_proof(
                            pay_to_bob_outputs,
                            UtxoNotificationMedium::OffChain,
                            UtxoNotificationMedium::OffChain,
                            fee,
                            in_seven_months,
                        )
                        .await
                        .unwrap();

                    let block2 = invalid_block_with_transaction(&block1, tx);
                    let block3 = invalid_empty_block(&block2);

                    // mine two blocks, the first will include the transaction
                    blocks.push(block2);
                    blocks.push(block3);

                    (blocks, offchain_notifications, bob_amount)
                };

                // bob's node claims each utxo
                {
                    let mut state = bob_rpc_server.state.clone();

                    state.set_new_tip(blocks[0].clone()).await?;

                    if claim_after_confirmed {
                        state.set_new_tip(blocks[1].clone()).await?;
                        state.set_new_tip(blocks[2].clone()).await?;
                    }

                    for utxo_notification in alice_to_bob_utxo_notifications.into_iter() {
                        // Register the same UTXO multiple times to ensure that this does not
                        // change the balance.
                        let claim_was_new0 = bob_rpc_server
                            .clone()
                            .claim_utxo(
                                context::current(),
                                bob_token,
                                utxo_notification.ciphertext.clone(),
                                None,
                            )
                            .await
                            .unwrap();
                        assert!(claim_was_new0);
                        let claim_was_new1 = bob_rpc_server
                            .clone()
                            .claim_utxo(
                                context::current(),
                                bob_token,
                                utxo_notification.ciphertext,
                                None,
                            )
                            .await
                            .unwrap();
                        assert!(!claim_was_new1);
                    }

                    assert_eq!(
                        vec![
                            NativeCurrencyAmount::coins(1), // claimed via generation addr
                            NativeCurrencyAmount::coins(2), // claimed via symmetric addr
                        ],
                        state
                            .lock_guard()
                            .await
                            .wallet_state
                            .wallet_db
                            .expected_utxos()
                            .get_all()
                            .await
                            .iter()
                            .map(|eu| eu.utxo.get_native_currency_amount())
                            .collect_vec()
                    );

                    if !claim_after_confirmed {
                        assert_eq!(
                            NativeCurrencyAmount::zero(),
                            bob_rpc_server
                                .clone()
                                .confirmed_available_balance(context::current(), bob_token)
                                .await?,
                        );
                        state.set_new_tip(blocks[1].clone()).await?;
                        state.set_new_tip(blocks[2].clone()).await?;
                    }

                    assert_eq!(
                        bob_amount,
                        bob_rpc_server
                            .confirmed_available_balance(context::current(), bob_token)
                            .await?,
                    );
                }

                Ok(())
            }

            pub(super) async fn claim_utxo_owned(
                claim_after_mined: bool,
                spent: bool,
            ) -> Result<()> {
                assert!(
                    !spent || claim_after_mined,
                    "If UTXO is spent, it must also be mined"
                );
                let network = Network::Main;
                let bob_wallet = WalletSecret::new_random();
                let mut bob =
                    test_rpc_server(network, bob_wallet.clone(), 2, Args::default()).await;
                let bob_token = cookie_token(&bob).await;

                let in_seven_months =
                    Block::genesis(network).header().timestamp + Timestamp::months(7);
                let in_eight_months = in_seven_months + Timestamp::months(1);

                let bob_key = bob_wallet.nth_generation_spending_key(0);
                let genesis_block = Block::genesis(network);
                let (block1, composer_expected_utxos) =
                    make_mock_block(&genesis_block, None, bob_key, Default::default()).await;

                bob.state
                    .set_new_self_composed_tip(block1.clone(), composer_expected_utxos)
                    .await
                    .unwrap();

                let bob_gen_addr = bob
                    .clone()
                    .next_receiving_address(context::current(), bob_token, KeyType::Generation)
                    .await?
                    .unwrap();
                let bob_sym_addr = bob
                    .clone()
                    .next_receiving_address(context::current(), bob_token, KeyType::Symmetric)
                    .await?
                    .unwrap();

                let pay_to_self_outputs = vec![
                    (bob_gen_addr, NativeCurrencyAmount::coins(5)),
                    (bob_sym_addr, NativeCurrencyAmount::coins(6)),
                ];

                let fee = NativeCurrencyAmount::coins(2);
                let (tx, offchain_notifications) = bob
                    .clone()
                    .send_to_many_inner_invalid_proof(
                        pay_to_self_outputs.clone(),
                        UtxoNotificationMedium::OffChain,
                        UtxoNotificationMedium::OffChain,
                        fee,
                        in_eight_months,
                    )
                    .await
                    .unwrap();

                // alice mines 2 more blocks.  block2 confirms the sent tx.
                let block2 = invalid_block_with_transaction(&block1, tx);
                let block3 = invalid_empty_block(&block2);

                if claim_after_mined {
                    // bob applies the blocks before claiming utxos.
                    bob.state.set_new_tip(block2.clone()).await?;
                    bob.state.set_new_tip(block3.clone()).await?;

                    if spent {
                        // Send entire liquid balance somewhere else
                        let another_address = WalletSecret::new_random()
                            .nth_generation_spending_key(0)
                            .to_address();
                        let (spending_tx, _) = bob
                            .clone()
                            .send_to_many_inner_invalid_proof(
                                vec![(another_address.into(), NativeCurrencyAmount::coins(62))],
                                UtxoNotificationMedium::OffChain,
                                UtxoNotificationMedium::OffChain,
                                NativeCurrencyAmount::zero(),
                                in_eight_months,
                            )
                            .await
                            .unwrap();
                        let block4 = invalid_block_with_transaction(&block3, spending_tx);
                        bob.state.set_new_tip(block4.clone()).await?;
                    }
                }

                for offchain_notification in offchain_notifications {
                    bob.clone()
                        .claim_utxo(
                            context::current(),
                            bob_token,
                            offchain_notification.ciphertext,
                            None,
                        )
                        .await?;
                }

                assert_eq!(
                    vec![
                        NativeCurrencyAmount::coins(64), // liquid composer reward, block 1
                        NativeCurrencyAmount::coins(64), // illiquid composer reward, block 1
                        NativeCurrencyAmount::coins(5),  // claimed via generation addr
                        NativeCurrencyAmount::coins(6),  // claimed via symmetric addr
                        // 51 = (64 - 5 - 6 - 2 (fee))
                        NativeCurrencyAmount::coins(51) // change (symmetric addr)
                    ],
                    bob.state
                        .lock_guard()
                        .await
                        .wallet_state
                        .wallet_db
                        .expected_utxos()
                        .get_all()
                        .await
                        .iter()
                        .map(|eu| eu.utxo.get_native_currency_amount())
                        .collect_vec()
                );

                if !claim_after_mined {
                    // bob hasn't applied blocks 2,3. liquid balance should be 64
                    assert_eq!(
                        NativeCurrencyAmount::coins(64),
                        bob.clone()
                            .confirmed_available_balance(context::current(), bob_token)
                            .await?,
                    );
                    // bob applies the blocks after claiming utxos.
                    bob.state.set_new_tip(block2).await?;
                    bob.state.set_new_tip(block3).await?;
                }

                if spent {
                    assert!(bob
                        .confirmed_available_balance(context::current(), bob_token)
                        .await?
                        .is_zero(),);
                } else {
                    // final liquid balance should be 62.
                    // +64 composer liquid
                    // +64 composer timelocked (not counted)
                    // -64 composer liquid spent
                    // +5 self-send via Generation
                    // +6 self-send via Symmetric
                    // +51   change (less fee == 2)
                    assert_eq!(
                        NativeCurrencyAmount::coins(62),
                        bob.confirmed_available_balance(context::current(), bob_token)
                            .await?,
                    );
                }
                Ok(())
            }
        }
    }

    mod send_tests {
        use super::*;

        #[traced_test]
        #[tokio::test]
        async fn send_to_many_n_outputs() {
            let mut rng = StdRng::seed_from_u64(1815);
            let network = Network::Main;
            let rpc_server = test_rpc_server(
                network,
                WalletSecret::new_pseudorandom(rng.random()),
                2,
                cli_args::Args::default(),
            )
            .await;
            let token = cookie_token(&rpc_server).await;

            let ctx = context::current();
            let timestamp = network.launch_date() + Timestamp::days(1);
            let own_address = rpc_server
                .clone()
                .next_receiving_address(ctx, token, KeyType::Generation)
                .await
                .unwrap()
                .unwrap();
            let elem = (own_address.clone(), NativeCurrencyAmount::zero());
            let outputs = std::iter::repeat(elem);
            let fee = NativeCurrencyAmount::zero();

            // note: we can only perform 2 iters, else we bump into send rate-limit (per block)
            for i in 5..7 {
                let result = rpc_server
                    .clone()
                    .send_to_many_inner(
                        ctx,
                        outputs.clone().take(i).collect(),
                        (
                            UtxoNotificationMedium::OffChain,
                            UtxoNotificationMedium::OffChain,
                        ),
                        fee,
                        timestamp,
                        TxProvingCapability::PrimitiveWitness,
                    )
                    .await;
                assert!(result.is_ok());
            }
        }

        /// sends a tx with two outputs: one self, one external, for each key type
        /// that accepts incoming UTXOs.
        #[traced_test]
        #[tokio::test]
        #[allow(clippy::needless_return)]
        async fn send_to_many_test() -> Result<()> {
            for recipient_key_type in KeyType::all_types_for_receiving() {
                worker::send_to_many(recipient_key_type).await?;
            }
            Ok(())
        }

        /// checks that the sending rate limit kicks in after 2 tx are sent.
        /// note: rate-limit only applies below block 25000
        #[traced_test]
        #[tokio::test]
        #[allow(clippy::needless_return)]
        async fn send_rate_limit() -> Result<()> {
            let mut rng = StdRng::seed_from_u64(1815);
            let network = Network::Main;
            let rpc_server = test_rpc_server(
                network,
                WalletSecret::devnet_wallet(),
                2,
                cli_args::Args::default(),
            )
            .await;

            let ctx = context::current();
            let timestamp = network.launch_date() + Timestamp::months(7);

            let address: ReceivingAddress = GenerationSpendingKey::derive_from_seed(rng.random())
                .to_address()
                .into();
            let amount = NativeCurrencyAmount::coins(rng.random_range(0..10));
            let fee = NativeCurrencyAmount::coins(1);

            let outputs = vec![(address, amount)];

            for i in 0..10 {
                let result = rpc_server
                    .clone()
                    .send_to_many_inner(
                        ctx,
                        outputs.clone(),
                        (
                            UtxoNotificationMedium::OnChain,
                            UtxoNotificationMedium::OnChain,
                        ),
                        fee,
                        timestamp,
                        TxProvingCapability::PrimitiveWitness,
                    )
                    .await;

                // any attempts after the 2nd send should result in RateLimit error.
                match i {
                    0..2 => assert!(result.is_ok()),
                    _ => assert!(matches!(result, Err(error::SendError::RateLimit { .. }))),
                }
            }

            Ok(())
        }

        mod worker {
            use super::*;
            use crate::models::state::wallet::address::generation_address::GenerationReceivingAddress;
            use crate::models::state::wallet::address::symmetric_key::SymmetricKey;

            // sends a tx with two outputs: one self, one external.
            //
            // input: recipient_key_type: can be symmetric or generation.
            //
            // Steps:
            // --- Init.  Basics ---
            // --- Init.  get wallet spending key ---
            // --- Init.  generate a block, with coinbase going to our wallet ---
            // --- Init.  append the block to blockchain ---
            // --- Setup. generate an output that our wallet cannot claim. ---
            // --- Setup. generate an output that our wallet can claim. ---
            // --- Setup. assemble outputs and fee ---
            // --- Store: store num expected utxo before spend ---
            // --- Operation: perform send_to_many
            // --- Test: bech32m serialize/deserialize roundtrip.
            // --- Test: verify op returns a value.
            // --- Test: verify expected_utxos.len() has increased by 2.
            pub(super) async fn send_to_many(recipient_key_type: KeyType) -> Result<()> {
                info!("recipient_key_type: {}", recipient_key_type);

                // --- Init.  Basics ---
                let mut rng = StdRng::seed_from_u64(1814);
                let network = Network::Main;
                let mut rpc_server = test_rpc_server(
                    network,
                    WalletSecret::new_pseudorandom(rng.random()),
                    2,
                    cli_args::Args::default(),
                )
                .await;
                let ctx = context::current();

                // --- Init.  get wallet spending key ---
                let genesis_block = Block::genesis(network);
                let wallet_spending_key = rpc_server
                    .state
                    .lock_guard_mut()
                    .await
                    .wallet_state
                    .next_unused_spending_key(KeyType::Generation)
                    .await
                    .unwrap();
                let SpendingKey::Generation(wallet_spending_key) = wallet_spending_key else {
                    panic!("Expected generation key")
                };

                // --- Init.  generate a block, with composer fee going to our
                // wallet ---
                let timestamp = network.launch_date() + Timestamp::days(1);
                let (block_1, composer_utxos) = make_mock_block(
                    &genesis_block,
                    Some(timestamp),
                    wallet_spending_key,
                    rng.random(),
                )
                .await;

                {
                    let state_lock = rpc_server.state.lock_guard().await;
                    let wallet_status = state_lock.get_wallet_status_for_tip().await;
                    let original_balance = state_lock
                        .wallet_state
                        .confirmed_available_balance(&wallet_status, timestamp);
                    assert!(original_balance.is_zero(), "Original balance assumed zero");
                };

                // --- Init.  append the block to blockchain ---
                rpc_server
                    .state
                    .set_new_self_composed_tip(block_1.clone(), composer_utxos)
                    .await?;

                {
                    let state_lock = rpc_server.state.lock_guard().await;
                    let wallet_status = state_lock.get_wallet_status_for_tip().await;
                    let new_balance = state_lock
                        .wallet_state
                        .confirmed_available_balance(&wallet_status, timestamp);
                    let mut expected_balance = Block::block_subsidy(block_1.header().height);
                    expected_balance.div_two();
                    assert_eq!(
                        expected_balance, new_balance,
                        "New balance must be exactly 1/2 mining reward bc timelock"
                    );
                };

                // --- Setup. generate an output that our wallet cannot claim. ---
                let external_receiving_address: ReceivingAddress = match recipient_key_type {
                    KeyType::Generation => {
                        GenerationReceivingAddress::derive_from_seed(rng.random()).into()
                    }
                    KeyType::Symmetric => SymmetricKey::from_seed(rng.random()).into(),
                    KeyType::RawHashLock => panic!("hash lock key not supported"),
                };
                let output1 = (
                    external_receiving_address.clone(),
                    NativeCurrencyAmount::coins(5),
                );

                // --- Setup. generate an output that our wallet can claim. ---
                let output2 = {
                    let spending_key = rpc_server
                        .state
                        .lock_guard_mut()
                        .await
                        .wallet_state
                        .next_unused_spending_key(recipient_key_type)
                        .await
                        .unwrap();
                    (
                        spending_key.to_address().unwrap(),
                        NativeCurrencyAmount::coins(25),
                    )
                };

                // --- Setup. assemble outputs and fee ---
                let outputs = vec![output1, output2];
                let fee = NativeCurrencyAmount::coins(1);

                // --- Store: store num expected utxo before spend ---
                let num_expected_utxo = rpc_server
                    .state
                    .lock_guard()
                    .await
                    .wallet_state
                    .wallet_db
                    .expected_utxos()
                    .len()
                    .await;

                // --- Operation: perform send_to_many
                // It's important to call a method where you get to inject the
                // timestamp. Otherwise, proofs cannot be reused, and CI will
                // fail. CI might also fail if you don't set an explicit proving
                // capability.
                let result = rpc_server
                    .clone()
                    .send_to_many_inner(
                        ctx,
                        outputs,
                        (
                            UtxoNotificationMedium::OffChain,
                            UtxoNotificationMedium::OffChain,
                        ),
                        fee,
                        timestamp,
                        TxProvingCapability::ProofCollection,
                    )
                    .await;

                // --- Test: bech32m serialize/deserialize roundtrip.
                assert_eq!(
                    external_receiving_address,
                    ReceivingAddress::from_bech32m(
                        &external_receiving_address.to_bech32m(network)?,
                        network,
                    )?
                );

                // --- Test: verify op returns a value.
                assert!(result.is_ok());

                // --- Test: verify expected_utxos.len() has increased by 2.
                //           (one off-chain utxo + one change utxo)
                assert_eq!(
                    rpc_server
                        .state
                        .lock_guard()
                        .await
                        .wallet_state
                        .wallet_db
                        .expected_utxos()
                        .len()
                        .await,
                    num_expected_utxo + 2
                );

                Ok(())
            }
        }
    }
}
