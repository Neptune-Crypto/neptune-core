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
//! use neptune_cash::application::rpc::server::RPCClient;
//! use neptune_cash::application::rpc::auth;
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
//! let token: auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
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
//! See [auth] for descriptions of the authentication mechanisms.
//!
//! Every RPC method returns an [RpcResult] which is wrapped inside a
//! [tarpc::Response] by the rpc server.
pub mod coinbase_output_readable;
pub mod mempool_transaction_info;
pub mod overview_data;
pub mod proof_of_work_puzzle;
pub mod ui_utxo;

use std::collections::HashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;

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
use tasm_lib::twenty_first::tip5::digest::Digest;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use super::auth;
use crate::api;
use crate::api::tx_initiation;
use crate::api::tx_initiation::builder::tx_input_list_builder::InputSelectionPolicy;
use crate::api::tx_initiation::builder::tx_output_list_builder::OutputFormat;
use crate::application::config::network::Network;
use crate::application::database::storage::storage_vec::traits::StorageVecBase;
use crate::application::loops::channel::ClaimUtxoData;
use crate::application::loops::channel::RPCServerToMain;
use crate::application::loops::main_loop::proof_upgrader::UpgradeJob;
use crate::application::loops::mine_loop::coinbase_distribution::CoinbaseDistribution;
use crate::application::rpc::server::coinbase_output_readable::CoinbaseOutputReadable;
use crate::application::rpc::server::error::RpcError;
use crate::application::rpc::server::mempool_transaction_info::MempoolTransactionInfo;
use crate::application::rpc::server::overview_data::OverviewData;
use crate::application::rpc::server::proof_of_work_puzzle::ProofOfWorkPuzzle;
use crate::application::rpc::server::ui_utxo::UiUtxo;
use crate::application::rpc::server::ui_utxo::UtxoStatusEvent;
use crate::macros::fn_name;
use crate::macros::log_slow_scope;
use crate::protocol::consensus::block::block_header::BlockHeader;
use crate::protocol::consensus::block::block_header::BlockPow;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::block_info::BlockInfo;
use crate::protocol::consensus::block::block_kernel::BlockKernel;
use crate::protocol::consensus::block::block_selector::BlockSelector;
use crate::protocol::consensus::block::difficulty_control::Difficulty;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::transaction::announcement::Announcement;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::transaction_proof::TransactionProofType;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::consensus::transaction::TransactionProof;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::peer::peer_info::PeerInfo;
use crate::protocol::peer::InstanceId;
use crate::protocol::peer::PeerStanding;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::state::mining::mining_state::MAX_NUM_EXPORTED_BLOCK_PROPOSAL_STORED;
use crate::state::transaction::transaction_details::TransactionDetails;
use crate::state::transaction::transaction_kernel_id::TransactionKernelId;
use crate::state::transaction::tx_creation_artifacts::TxCreationArtifacts;
use crate::state::wallet::address::encrypted_utxo_notification::EncryptedUtxoNotification;
use crate::state::wallet::address::KeyType;
use crate::state::wallet::address::ReceivingAddress;
use crate::state::wallet::address::SpendingKey;
use crate::state::wallet::change_policy::ChangePolicy;
use crate::state::wallet::coin_with_possible_timelock::CoinWithPossibleTimeLock;
use crate::state::wallet::expected_utxo::UtxoNotifier;
use crate::state::wallet::incoming_utxo::IncomingUtxo;
use crate::state::wallet::monitored_utxo::MonitoredUtxo;
use crate::state::wallet::transaction_input::TxInputList;
use crate::state::wallet::transaction_output::TxOutputList;
use crate::state::wallet::wallet_status::WalletStatus;
use crate::state::GlobalState;
use crate::state::GlobalStateLock;
use crate::twenty_first::prelude::Tip5;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::archival_mutator_set::ResponseMsMembershipProofPrivacyPreserving;
use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use crate::DataDirectory;

/// result returned by RPC methods
pub type RpcResult<T> = Result<T, error::RpcError>;

#[tarpc::service]
pub trait RPC {
    /******** READ DATA ********/
    // Place all methods that only read here
    /// Returns a [auth::CookieHint] for purposes of zero-conf authentication
    ///
    /// The CookieHint provides a location for the cookie file used by this
    /// neptune-core instance as well as the [Network].
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    async fn cookie_hint() -> RpcResult<auth::CookieHint>;

    /// Return the network this neptune-core instance is running
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get local socket used for incoming peer-connections.
    /// let own_listen_address = client.own_listen_address_for_peers(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn own_listen_address_for_peers(token: auth::Token) -> RpcResult<Option<SocketAddr>>;

    /// Return the node's instance-ID which is a globally unique random generated number
    /// set at startup used to ensure that the node does not connect to itself, or the
    /// same peer twice.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get own instance ID.
    /// let own_instance_id = client.own_instance_id(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn own_instance_id(token: auth::Token) -> RpcResult<InstanceId>;

    /// Returns the current block height.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get the block height.
    /// let block_height = client.block_height(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn block_height(token: auth::Token) -> RpcResult<BlockHeight>;

    /// Return the guesser reward of the most favorable block proposal
    ///
    /// Returns None if no proposal is known building on the current tip.
    async fn best_proposal(token: auth::Token) -> RpcResult<Option<BlockInfo>>;

    /// Returns the number of blocks (confirmations) since wallet balance last changed.
    ///
    /// returns `Option<BlockHeight>`
    ///
    /// return value will be None if wallet has not received any incoming funds.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get the blocks since wallet balance changed.
    /// let block_height = client.confirmations(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn confirmations(token: auth::Token) -> RpcResult<Option<BlockHeight>>;

    /// Return the most recently generated address of the specified type. Does
    /// not add a new key to the wallet, and does not change the derivation
    /// index.
    async fn latest_address(token: auth::Token, key_type: KeyType) -> RpcResult<ReceivingAddress>;

    /// Returns info about the peers we are connected to
    ///
    /// return value will be None if wallet has not received any incoming funds.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get the info about the peers we are connected to
    /// let peers = client.peer_info(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn peer_info(token: auth::Token) -> RpcResult<Vec<PeerInfo>>;

    /// Return info about all peers that have been negatively sanctioned.
    ///
    /// return value will be None if wallet has not received any incoming funds.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get the info about the peers that are negatively sanctioned
    /// let punished_peers = client.all_punished_peers(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn all_punished_peers(token: auth::Token) -> RpcResult<HashMap<IpAddr, PeerStanding>>;

    /// Returns the digest of the latest n blocks
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // number of latest blocks digests you want to get
    /// let n : usize = 10;
    ///
    /// // query neptune-core server to get the digests of the n latest blocks
    /// let latest_tip_digests = client.latest_tip_digests(context::current(), token, n).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn latest_tip_digests(token: auth::Token, n: usize) -> RpcResult<Vec<Digest>>;

    /// Returns information about the specified block if found
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// use neptune_cash::protocol::consensus::block::block_selector::BlockSelector;
    /// use neptune_cash::protocol::consensus::block::block_selector::BlockSelectorLiteral;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // set the way to look up for a block : it can be `Digest`, `Height`, `Genesis`, `Tip`
    /// let block_selector : BlockSelector = BlockSelector::Special(BlockSelectorLiteral::Genesis);
    ///
    /// // query neptune-core server to get block info
    /// let latest_tip_digests = client.block_info(context::current(), token, block_selector).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn block_info(
        token: auth::Token,
        block_selector: BlockSelector,
    ) -> RpcResult<Option<BlockInfo>>;

    /// Return the block kernel if block is known.
    async fn block_kernel(
        token: auth::Token,
        block_selector: BlockSelector,
    ) -> RpcResult<Option<BlockKernel>>;

    /// Return a hash map of [`AdditionRecord`]s to AOCL leaf indices for the
    /// outputs of a block, if it is known.
    async fn addition_record_indices_for_block(
        token: auth::Token,
        block_selector: BlockSelector,
    ) -> RpcResult<Vec<(AdditionRecord, Option<u64>)>>;

    /// Restore a mutator set membership proof in a privacy-preserving manner.
    ///
    /// Caller only reveals the absolute index set, which ends up on the
    /// blockchain anyway, and callee returns all possible MMR authentication
    /// paths into the AOCL MMR as well as all requested cryptographic data from
    /// the Bloom filter MMR.
    async fn restore_membership_proof_privacy_preserving(
        token: auth::Token,
        index_sets: Vec<AbsoluteIndexSet>,
    ) -> RpcResult<ResponseMsMembershipProofPrivacyPreserving>;

    /// Return the announements contained in a specified block.
    ///
    /// Returns `None` if the selected block could not be found, otherwise
    /// returns `Some(announcements)`.
    ///
    /// Does not attempt to decode the announcements.
    async fn announcements_in_block(
        token: auth::Token,
        block_selector: BlockSelector,
    ) -> RpcResult<Option<Vec<Announcement>>>;

    /// Return the digests of known blocks with specified height.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// use neptune_cash::protocol::consensus::block::block_selector::BlockSelector;
    /// use neptune_cash::protocol::consensus::block::block_height::BlockHeight;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
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
        token: auth::Token,
        height: BlockHeight,
    ) -> RpcResult<Vec<Digest>>;

    /// Return the digest for the specified block if found
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// use neptune_cash::protocol::consensus::block::block_selector::BlockSelector;
    /// use neptune_cash::protocol::consensus::block::block_selector::BlockSelectorLiteral;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // set the way to look up for a block : it can be `Digest`, `Height`, `Genesis`, `Tip`
    /// let block_selector : BlockSelector = BlockSelector::Special(BlockSelectorLiteral::Tip);
    ///
    /// // query neptune-core server to get block digest
    /// let block_digest = client.block_digest(context::current(), token, block_selector).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn block_digest(
        token: auth::Token,
        block_selector: BlockSelector,
    ) -> RpcResult<Option<Digest>>;

    /// Return the digest for the specified UTXO leaf index if found
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// use neptune_cash::protocol::consensus::block::block_selector::BlockSelector;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // leaf index is set to 5
    /// let leaf_index : u64 = 5;
    ///
    /// // query neptune-core server to get utxo digest
    /// let block_digest = client.utxo_digest(context::current(), token, leaf_index).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn utxo_digest(token: auth::Token, leaf_index: u64) -> RpcResult<Option<Digest>>;

    /// Returns the block digest in which the specified UTXO was created, if available
    async fn utxo_origin_block(
        token: auth::Token,
        addition_record: AdditionRecord,
        max_search_depth: Option<u64>,
    ) -> RpcResult<Option<Digest>>;

    /// Return the block header for the specified block
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// use neptune_cash::protocol::consensus::block::block_selector::BlockSelector;
    /// use neptune_cash::protocol::consensus::block::block_selector::BlockSelectorLiteral;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // set the way to look up for a block : it can be `Digest`, `Height`, `Genesis`, `Tip`
    /// let block_selector : BlockSelector = BlockSelector::Special(BlockSelectorLiteral::Genesis);
    ///
    /// // query neptune-core server to get block header
    /// let block_header = client.header(context::current(), token, block_selector).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn header(
        token: auth::Token,
        block_selector: BlockSelector,
    ) -> RpcResult<Option<BlockHeader>>;

    /// Get sum of confirmed, unspent, available UTXOs
    /// excludes time-locked utxos
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get sum of confirmed unspent UTXO
    /// let confirmed_available_balance = client.confirmed_available_balance(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn confirmed_available_balance(token: auth::Token) -> RpcResult<NativeCurrencyAmount>;

    /// Get sum of unconfirmed, unspent available UTXOs
    /// includes mempool transactions, excludes time-locked utxos
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get sum of unconfirmed unspent UTXOs
    /// let unconfirmed_available_balance = client.unconfirmed_available_balance(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn unconfirmed_available_balance(token: auth::Token) -> RpcResult<NativeCurrencyAmount>;

    /// Get the client's wallet transaction history
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get history of transactions, a vec containing digest, block height, timestamp and neptune coins tuples.
    /// let history_transactions = client.history(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn history(
        token: auth::Token,
    ) -> RpcResult<Vec<(Digest, BlockHeight, Timestamp, NativeCurrencyAmount)>>;

    /// Return information about funds in the wallet
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get the funds in the wallet
    /// let wallet_status = client.wallet_status(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn wallet_status(token: auth::Token) -> RpcResult<WalletStatus>;

    /// Return the number of expected UTXOs, including already received UTXOs.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get the number of expected utxos including already received ones.
    /// let wallet_status = client.num_expected_utxos(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn num_expected_utxos(token: auth::Token) -> RpcResult<u64>;

    /// generate a new receiving address of the specified type
    ///
    /// a payment recipient (payee) should call this method to obtain a
    /// an address which can be provided to the payment sender (payer).
    ///
    /// # important! read or risk losing funds!!!
    ///
    /// for most transactions, use [KeyType::Generation].
    ///
    /// [KeyType::Symmetric] must *only* be used if the payer and
    /// payee are the same party, ie the payer is sending to a wallet
    /// under their control.
    ///
    /// This is because when `KeyType::Symmetric` is specified the returned
    /// "address" is also the spending key.  Anyone who received this "address"
    /// can spend the funds.  So never give it out!
    ///
    /// `KeyType::Symmetric` is provided as an option for self-owned payments
    /// because it requires much less space on the blockchain, which can also
    /// potentially lessen fees.
    ///
    /// Note that by default `KeyType::Symmetric` is used for change outputs
    /// and block rewards.
    ///
    /// If in any doubt, just use [KeyType::Generation].
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// use neptune_cash::state::wallet::address::KeyType;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // set cryptographic key type for receiving funds
    /// let key_type = KeyType::Generation;
    ///
    /// // query neptune-core server to get a receiving address
    /// let wallet_status = client.next_receiving_address(context::current(), token, key_type).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn next_receiving_address(
        token: auth::Token,
        key_type: KeyType,
    ) -> RpcResult<ReceivingAddress>;

    /// Return all known keys, for every [KeyType]
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get all known keys for every [KeyType]
    /// let known_keys = client.known_keys(context::current(), token ).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn known_keys(token: auth::Token) -> RpcResult<Vec<SpendingKey>>;

    /// Return known keys for the provided [KeyType]
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// use neptune_cash::state::wallet::address::KeyType;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
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
        token: auth::Token,
        key_type: KeyType,
    ) -> RpcResult<Vec<SpendingKey>>;

    /// Return the number of transactions in the mempool
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get the number of transactions in the mempool
    /// let mempool_tx_count = client.mempool_tx_count(context::current(), token ).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn mempool_tx_count(token: auth::Token) -> RpcResult<usize>;

    // TODO: Change to return current size and max size
    async fn mempool_size(token: auth::Token) -> RpcResult<usize>;

    async fn mempool_tx_ids(token: auth::Token) -> RpcResult<Vec<TransactionKernelId>>;

    /// Return info about the transactions in the mempool
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
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
        token: auth::Token,
        start_index: usize,
        number: usize,
    ) -> RpcResult<Vec<MempoolTransactionInfo>>;

    /// Return transaction kernel by id if found in mempool.
    async fn mempool_tx_kernel(
        token: auth::Token,
        tx_kernel_id: TransactionKernelId,
    ) -> RpcResult<Option<TransactionKernel>>;

    /// Return the information used on the dashboard's overview tab
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get the info used on dashboard overview tab
    /// let dashboard_data = client.dashboard_overview_data(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn dashboard_overview_data(token: auth::Token) -> RpcResult<OverviewData>;

    /// Determine whether the user-supplied string is a valid address
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// use neptune_cash::application::config::network::Network;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
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
        token: auth::Token,
        address: String,
        network: Network,
    ) -> RpcResult<Option<ReceivingAddress>>;

    /// Determine whether the user-supplied string is a valid amount
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
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
        token: auth::Token,
        amount: String,
    ) -> RpcResult<Option<NativeCurrencyAmount>>;

    /// Determine whether the given amount is less than (or equal to) the balance
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// use neptune_cash::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
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
        token: auth::Token,
        amount: NativeCurrencyAmount,
    ) -> RpcResult<bool>;

    /// Generate a report of all owned and unspent coins, whether time-locked or not.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get the list of owned and unspent coins
    /// let own_coins = client.list_own_coins(context::current(), token ).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn list_own_coins(token: auth::Token) -> RpcResult<Vec<CoinWithPossibleTimeLock>>;

    /// Generate a list of all UTXOs, currently owned, historical, time-locked,
    /// not, abandoned.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server to get the list of UTXOs
    /// let own_coins = client.list_utxos(context::current(), token ).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn list_utxos(token: auth::Token) -> RpcResult<Vec<UiUtxo>>;

    /// Get CPU temperature.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // query neptune-core server instance to get its CPU temperature
    /// let cpu_temperature = client.cpu_temp(context::current(), token ).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn cpu_temp(token: auth::Token) -> RpcResult<Option<f32>>;

    /// Get the proof-of-work puzzle for the current block proposal. Uses the
    /// node's secret key to populate the guesser digest.
    ///
    /// Returns `None` if no block proposal for the next block is known yet.
    async fn pow_puzzle_internal_key(token: auth::Token) -> RpcResult<Option<ProofOfWorkPuzzle>>;

    /// Get the proof-of-work puzzle for the current block proposal. Like
    /// [Self::pow_puzzle_internal_key] but returned puzzle uses an externally
    /// provided digest to populate the guesser digest field in the block
    /// header, meaning that this client cannot claim the reward in case a
    /// valid PoW-solution is found. This endpoint allows for "cold" guessing
    /// where the node does not hold the key to spend the guesser reward.
    ///
    /// Returns `None` if no block proposal for the next block is known yet.
    async fn pow_puzzle_external_key(
        token: auth::Token,
        guesser_fee_address: ReceivingAddress,
    ) -> RpcResult<Option<ProofOfWorkPuzzle>>;

    /// Get the proof-of-work puzzle for the current block proposal, along with
    /// the block proposal itself. Works like [`Self::pow_puzzle_external_key`]
    /// but does not task the node with remembering the proposal, meaning that
    /// another node can receive the solution if one is found. If a solution is
    /// found, the endpoint [`Self::provide_new_tip()`] can be used to pass the
    /// solution onto a node.
    async fn full_pow_puzzle_external_key(
        token: auth::Token,
        guesser_fee_address: ReceivingAddress,
    ) -> RpcResult<Option<(Block, ProofOfWorkPuzzle)>>;

    /// todo: docs.
    ///
    /// meanwhile see [tx_initiation::initiator::TransactionInitiator::spendable_inputs()]
    async fn spendable_inputs(token: auth::Token) -> RpcResult<TxInputList>;

    /// retrieve spendable inputs sufficient to cover spend_amount by applying selection policy.
    ///
    /// see [InputSelectionPolicy]
    ///
    /// pub enum InputSelectionPolicy {
    ///     Random,
    ///     ByNativeCoinAmount(SortOrder),
    ///     ByUtxoSize(SortOrder),
    /// }
    ///
    /// todo: docs.
    ///
    /// meanwhile see [tx_initiation::initiator::TransactionInitiator::select_spendable_inputs()]
    async fn select_spendable_inputs(
        token: auth::Token,
        policy: InputSelectionPolicy,
        spend_amount: NativeCurrencyAmount,
    ) -> RpcResult<TxInputList>;

    /// generate tx outputs from list of OutputFormat.
    ///
    /// OutputFormat can be address:amount, address:amount:medium, address:utxo,
    /// address:utxo:medium, tx_output, etc.
    ///
    /// todo: docs.
    ///
    /// meanwhile see [tx_initiation::initiator::TransactionInitiator::generate_tx_outputs()]
    async fn generate_tx_outputs(
        token: auth::Token,
        outputs: Vec<OutputFormat>,
    ) -> RpcResult<TxOutputList>;

    /// Helper endpoint for constructing a transaction. Can be used in
    /// connection with other endpoints, e.g. endpoints that select inputs and
    /// outputs to a transaction.
    ///
    /// meanwhile see [tx_initiation::initiator::TransactionInitiator::generate_tx_details()]
    async fn generate_tx_details(
        token: auth::Token,
        tx_inputs: TxInputList,
        tx_outputs: TxOutputList,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
    ) -> RpcResult<TransactionDetails>;

    /// todo: docs.
    ///
    /// meanwhile see [tx_initiation::initiator::TransactionInitiator::generate_witness_proof()]
    async fn generate_witness_proof(
        token: auth::Token,
        tx_details: TransactionDetails,
    ) -> RpcResult<TransactionProof>;

    /// assemble a transaction from TransactionDetails and a TransactionProof.
    ///
    /// todo: docs.
    ///
    /// meanwhile see [tx_initiation::initiator::TransactionInitiator::assemble_transaction()]
    async fn assemble_transaction(
        token: auth::Token,
        transaction_details: TransactionDetails,
        transaction_proof: TransactionProof,
    ) -> RpcResult<Transaction>;

    /// assemble transaction artifacts from TransactionDetails and a TransactionProof.
    ///
    /// todo: docs.
    ///
    /// meanwhile see [tx_initiation::initiator::TransactionInitiator::assemble_transaction_artifacts()]
    async fn assemble_transaction_artifacts(
        token: auth::Token,
        transaction_details: TransactionDetails,
        transaction_proof: TransactionProof,
    ) -> RpcResult<TxCreationArtifacts>;

    /// todo: docs.
    ///
    /// meanwhile see [tx_initiation::initiator::TransactionInitiator::proof_type()]
    async fn proof_type(
        token: auth::Token,
        txid: TransactionKernelId,
    ) -> RpcResult<TransactionProofType>;

    /******** BLOCKCHAIN STATISTICS ********/
    // Place all endpoints that relate to statistics of the blockchain here

    /// Return the block intervals of a range of blocks. Return value is the
    /// number of milliseconds it took to mine the (canonical) block with the
    /// specified height. Does not include the interval between genesis block
    /// and block 1 since genesis block was not actually mined and its timestamp
    /// doesn't carry the same meaning as those of later blocks.
    async fn block_intervals(
        token: auth::Token,
        last_block: BlockSelector,
        max_num_blocks: Option<usize>,
    ) -> RpcResult<Option<Vec<(u64, u64)>>>;

    /// Return the difficulties of a range of blocks.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// use neptune_cash::protocol::consensus::block::block_selector::BlockSelector;
    /// use neptune_cash::protocol::consensus::block::block_selector::BlockSelectorLiteral;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // sets the last block
    /// let last_block : BlockSelector = BlockSelector::Special(BlockSelectorLiteral::Genesis);
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
        token: auth::Token,
        last_block: BlockSelector,
        max_num_blocks: Option<usize>,
    ) -> RpcResult<Vec<(u64, Difficulty)>>;

    /******** PEER INTERACTIONS ********/

    /// Broadcast transaction notifications for all transactions in this node's
    /// mempool.
    async fn broadcast_all_mempool_txs(token: auth::Token) -> RpcResult<()>;

    /// Broadcast running node's current favorable block proposal.
    async fn broadcast_block_proposal(token: auth::Token) -> RpcResult<()>;

    /******** CHANGE THINGS ********/
    // Place all things that change state here

    /// Clears standing for all peers, connected or not
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // neptune-core server clears standing for all peers that are connected or not
    /// let _ = client.clear_all_standings(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn clear_all_standings(token: auth::Token) -> RpcResult<()>;

    /// Clears standing for ip, whether connected or not
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    ///
    /// // IP address 87.23.90.12 to clear standing
    /// let ip = IpAddr::V4(Ipv4Addr::new(87, 23, 90, 12));
    ///
    /// // neptune-core server clears standing for all peers that are connected or not
    /// let _ = client.clear_standing_by_ip(context::current(), token, ip).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn clear_standing_by_ip(token: auth::Token, ip: IpAddr) -> RpcResult<()>;

    /// record transaction and initiate broadcast to peers
    ///
    /// todo: docs.
    ///
    /// meanwhile see [tx_initiation::initiator::TransactionInitiator::record_and_broadcast_transaction()]
    async fn record_and_broadcast_transaction(
        token: auth::Token,
        tx_artifacts: TxCreationArtifacts,
    ) -> RpcResult<()>;

    /// Send coins to one or more recipients
    ///
    /// note: sending is rate-limited to 2 sends per block until block
    /// 25000 is reached.
    ///
    /// `outputs` is a list of transaction outputs in any format supported by [OutputFormat].
    ///
    /// `change_policy` specifies how to handle change in the typical case that
    /// the transaction input amount exceeds the output amount.
    ///
    /// `fee` represents the fee in native coins to pay the miner who mines
    /// the block that initially confirms the resulting transaction.
    ///
    /// a [Digest] of the resulting [Transaction](crate::protocol::consensus::transaction::Transaction) is returned on success, else [None].
    ///
    /// A list of the encoded transaction notifications is also returned. The
    /// relevant notifications should be sent to the transaction receiver(s) in
    /// case `Offchain` notification is used for any output(s).
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::config::network::Network;
    /// # use neptune_cash::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
    /// # use neptune_cash::state::wallet::address::ReceivingAddress;
    /// # use neptune_cash::state::wallet::utxo_notification::UtxoNotificationMedium;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
    /// # use neptune_cash::api::export::ChangePolicy;
    /// # use neptune_cash::api::export::OutputFormat;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // List of receiving addresses and the amounts to send
    /// let outputs: Vec<OutputFormat> = vec![
    ///     (ReceivingAddress::from_bech32m("nolgam1lf8vc5xpa4jf9vjakts632fct5q80d4m6tax39nrl8c55dta2h7n7lnkh9pmwckl0ndwc7897xwfgx5vv02xdt3099z62222wazz7tjl6umzewla9xzxyqefh2w47v4eh0xzvfsxjk6kq5u84rwwlflq7cs726ljttl6ls860te04cwpy5kk8n40qqjnps0gdp46namhsa3cqt0uc0s5e34h6s5rw2kl77uvvs4rlnn5t8wtuefsduuccwsxmk27r8d48g49swgafhj6wmvu5cx3lweqhnxgdgm7mmdq7ck6wkurw2jzl64k9u34kzgu9stgd47ljzte0hz0n2lcng83vtpf0u9f4hggw4llqsz2fqpe4096d9v5fzg7xvxg6zvr7gksq4yqgn8shepg5xsczmzz256m9c6r8zqdkzy4tk9he59ndtdkrrr8u5v6ztnvkvmy4sed7p7plm2y09sgksw6zcjayls4wl9fnqu97kyx9cdknksar7h8jetygur979rt5arcwmvp2dy3ynt6arna2yjpevt9209v9g2p5cvp6gjp9850w3w6afeg8yuhp6u447hrudcssyjauqa2p7jk4tz37wg70yrdhsgn35sc0hdkclvpapu75dgtmswk0vtgadx44mqdps6ry6005xqups9dpc93u66qj9j7lfaqgdqrrfg9pkxhjl99ge387rh257x2phfvjvc8y66p22wax8myyhm7mgmlxu9gug0km3lmn4lzcyj32mduy6msy4kfn5z2tr67zfxadnj6wc0av27mk0j90pf67uzp9ps8aekr24kpv5n3qeczfznen9vj67ft95s93t26l8uh87qr6kp8lsyuzm4h36de830h6rr3lhg5ac995nrsu6h0p56t5tnglvx0s02mr0ts95fgcevveky5kkw6zgj6jd5m3n5ljhw862km8sedr30xvg8t9vh409ufuxdnfuypvqdq49z6mp46p936pjzwwqjda6yy5wuxx9lffrxwcmfqzch6nz2l4mwd2vlsdr58vhygppy6nm6tduyemw4clwj9uac4v990xt6jt7e2al7m6sjlq4qgxfjf4ytx8f5j460vvr7yac9hsvlsat2vh5gl55mt4wr7v5p3m6k5ya5442xdarastxlmpf2vqz5lusp8tlglxkj0jksgwqgtj6j0kxwmw40egpzs5rr996xpv8wwqyja4tmw599n9fh77f5ruxk69vtpwl9z5ezmdn92cpyyhwff59ypp0z5rv98vdvm67umqzt0ljjan30u3a8nga35fdy450ht9gef24mveucxqwv5aflge5r3amxsvd7l30j9kcqm7alq0ks2wqpde7pdct2gmvafxvjg3ad0a3h58assjaszvmykl3k5tn238gstm2shlvad4a53mm5ztvp5q2zt4pdzj0ssevlkumwhc0g5cxnxc9u7rh9gffkq7h9ufcxkgtghe32sv3vwzkessr52mcmajt83lvz45wqru9hht8cytfedtjlv7z7en6pp0guja85ft3rv6hzf2e02e7wfu38s0nyfzkc2qy2k298qtmxgrpduntejtvenr80csnckajnhu44399tkm0a7wdldalf678n9prd54twwlw24xhppxqlquatfztllkeejlkfxuayddwagh6uzx040tqlcs7hcflnu0ywynmz0chz48qcx7dsc4gpseu0dqvmmezpuv0tawm78nleju2vp4lkehua56hrnuj2wuc5lqvxlnskvp53vu7e2399pgp7xcwe3ww23qcd9pywladq34nk6cwcvtj3vdfgwf6r7s6vq46y2x05e043nj6tu8am2und8z3ftf3he5ccjxamtnmxfd79m04ph36kzx6e789dhqrwmwcfrn9ulsedeplk3dvrmad6f20y9qfl6n6kzaxkmmmaq4d6s5rl4kmhc7fcdkrkandw2jxdjckuscu56syly8rtjatj4j2ug23cwvep3dgcdvmtr32296nf9vdl3rcu0r7hge23ydt83k5nhtnexuqrnamveacz6c43eay9nz4pjjwjatkgp80lg9tnf5kdr2eel8s2fk6v338x4hu00htemm5pq6qlucqqq5tchhtekjzdu50erqd2fkdu9th3wl0mqxz5u7wnpgwgpammv2yqpa5znljegyhke0dz9vg27uh5t5x6qdgf7vu54lqssejekwzfxchjyq2s8frm9fmt688w76aug56v6n3w5xdre78xplfsdw3e4j6dc5w7tf83r25re0duq6h8z54wnkqr9yh2k0skjqea4elgcr4aw7hks9m8w3tx8w9xlxpqqll2zeql55ew7e90dyuynkqxfuqzv45t22ljamdll3udvqrllprdltthzm866jdaxkkrnryj4cmc2m7sk99clgql3ynrhe9kynqn4mh3tepk8dtq7cndtc2hma29s4cuylsvg04s70uyr53w5656su5rjem5egss08zrfaef0mww6t8pr26uph2n8a2cs55ydx4xhasjqk7xs0akh6f26j2ec4d8pd0kdf4jya6p9jl48wmy5autdpw2q8mehrq6kypt573genj66l5zkq6xvrdqugmfczxa2gj9ylx3pgpjqnhuem9udfkj9qr2y8lh728sr7uaedu5wwmfa72ykh395jqh7f7f9p2gskn6u7k844kpnwe3eqv84pl53r6x9af88a8ey7298njdg03h8mxqz2x6z8ys3qpuxq768tjq0zhrnjgns8d78euzwsvx6vn4f9tftrp68zcch3h75mc9drpt7tpvnyyqfjuqclxhdwhdwtsakecv04p9r3jx90htql9a3ht5mxrj4ercv4cd52wk4qhu7dn4tqe7yclqx2l36gcsrzmdlv440qls7qjpq6k95mst485vpennnur8h62a7d7syvyer89qtyfzlfhz8a5a0x5tuwhc9mah0e944xzhsc6uvpv8vat44w7r3xyw8q85y77jux8zhndrhdn36swryffqmpkxgcw4g29q40sul4fl5vrfru08a5j3rd3jl8799srpf2xqpxq38wwvhr4mxqf5wwdqfqq7harshggvufzlgn0l9fq0j76dyuge75jmzy8celvw6wesfs82n4jw2k8jnus2zds5a67my339uuzka4w72tau6j7wyu0lla0mcjpaflphsuy7f2phev6tr8vc9nj2mczkeg4vy3n5jkgecwgrvwu3vw9x5knpkxzv8kw3dpzzxy3rvrs56vxw8ugmyz2vdj6dakjyq3feym4290l7hgdt0ac5u49sekezzf0ghwmlek4h75fkzpvuly9zupw32dd3l9my282nekgk78fe6ayjyhczetxf8r82yd2askl52kmupr9xaxw0jd08dsd3523ea6ge48384rlmt4mu4w4x0q9s", Network::Main)?, NativeCurrencyAmount::coins(20)).into(),
    ///     (ReceivingAddress::from_bech32m("nolgam1ld9vc5xpa4jf9vjakts632fct5q80d4m6tax39nrl8c55dta2h7n7lnkh9pmwckl0ndwc7897xwfgx5vv02xdt3099z62222wazz7tjl6umzewla9xzxyqefh2w47v4eh0xzvfsxjk6kq5u84rwwlflq7cs726ljttl6ls860te04cwpy5kk8n40qqjnps0gdp46namhsa3cqt0uc0s5e34h6s5rw2kl77uvvs4rlnn5t8wtuefsduuccwsxmk27r8d48g49swgafhj6wmvu5cx3lweqhnxgdgm7mmdq7ck6wkurw2jzl64k9u34kzgu9stgd47ljzte0hz0n2lcng83vtpf0u9f4hggw4llqsz2fqpe4096d9v5fzg7xvxg6zvr7gksq4yqgn8shepg5xsczmzz256m9c6r8zqdkzy4tk9he59ndtdkrrr8u5v6ztnvkvmy4sed7p7plm2y09sgksw6zcjayls4wl9fnqu97kyx9cdknksar7h8jetygur979rt5arcwmvp2dy3ynt6arna2yjpevt9209v9g2p5cvp6gjp9850w3w6afeg8yuhp6u447hrudcssyjauqa2p7jk4tz37wg70yrdhsgn35sc0hdkclvpapu75dgtmswk0vtgadx44mqdps6ry6005xqups9dpc93u66qj9j7lfaqgdqrrfg9pkxhjl99ge387rh257x2phfvjvc8y66p22wax8myyhm7mgmlxu9gug0km3lmn4lzcyj32mduy6msy4kfn5z2tr67zfxadnj6wc0av27mk0j90pf67uzp9ps8aekr24kpv5n3qeczfznen9vj67ft95s93t26l8uh87qr6kp8lsyuzm4h36de830h6rr3lhg5ac995nrsu6h0p56t5tnglvx0s02mr0ts95fgcevveky5kkw6zgj6jd5m3n5ljhw862km8sedr30xvg8t9vh409ufuxdnfuypvqdq49z6mp46p936pjzwwqjda6yy5wuxx9lffrxwcmfqzch6nz2l4mwd2vlsdr58vhygppy6nm6tduyemw4clwj9uac4v990xt6jt7e2al7m6sjlq4qgxfjf4ytx8f5j460vvr7yac9hsvlsat2vh5gl55mt4wr7v5p3m6k5ya5442xdarastxlmpf2vqz5lusp8tlglxkj0jksgwqgtj6j0kxwmw40egpzs5rr996xpv8wwqyja4tmw599n9fh77f5ruxk69vtpwl9z5ezmdn92cpyyhwff59ypp0z5rv98vdvm67umqzt0ljjan30u3a8nga35fdy450ht9gef24mveucxqwv5aflge5r3amxsvd7l30j9kcqm7alq0ks2wqpde7pdct2gmvafxvjg3ad0a3h58assjaszvmykl3k5tn238gstm2shlvad4a53mm5ztvp5q2zt4pdzj0ssevlkumwhc0g5cxnxc9u7rh9gffkq7h9ufcxkgtghe32sv3vwzkessr52mcmajt83lvz45wqru9hht8cytfedtjlv7z7en6pp0guja85ft3rv6hzf2e02e7wfu38s0nyfzkc2qy2k298qtmxgrpduntejtvenr80csnckajnhu44399tkm0a7wdldalf678n9prd54twwlw24xhppxqlquatfztllkeejlkfxuayddwagh6uzx040tqlcs7hcflnu0ywynmz0chz48qcx7dsc4gpseu0dqvmmezpuv0tawm78nleju2vp4lkehua56hrnuj2wuc5lqvxlnskvp53vu7e2399pgp7xcwe3ww23qcd9pywladq34nk6cwcvtj3vdfgwf6r7s6vq46y2x05e043nj6tu8am2und8z3ftf3he5ccjxamtnmxfd79m04ph36kzx6e789dhqrwmwcfrn9ulsedeplk3dvrmad6f20y9qfl6n6kzaxkmmmaq4d6s5rl4kmhc7fcdkrkandw2jxdjckuscu56syly8rtjatj4j2ug23cwvep3dgcdvmtr32296nf9vdl3rcu0r7hge23ydt83k5nhtnexuqrnamveacz6c43eay9nz4pjjwjatkgp80lg9tnf5kdr2eel8s2fk6v338x4hu00htemm5pq6qlucqqq5tchhtekjzdu50erqd2fkdu9th3wl0mqxz5u7wnpgwgpammv2yqpa5znljegyhke0dz9vg27uh5t5x6qdgf7vu54lqssejekwzfxchjyq2s8frm9fmt688w76aug56v6n3w5xdre78xplfsdw3e4j6dc5w7tf83r25re0duq6h8z54wnkqr9yh2k0skjqea4elgcr4aw7hks9m8w3tx8w9xlxpqqll2zeql55ew7e90dyuynkqxfuqzv45t22ljamdll3udvqrllprdltthzm866jdaxkkrnryj4cmc2m7sk99clgql3ynrhe9kynqn4mh3tepk8dtq7cndtc2hma29s4cuylsvg04s70uyr53w5656su5rjem5egss08zrfaef0mww6t8pr26uph2n8a2cs55ydx4xhasjqk7xs0akh6f26j2ec4d8pd0kdf4jya6p9jl48wmy5autdpw2q8mehrq6kypt573genj66l5zkq6xvrdqugmfczxa2gj9ylx3pgpjqnhuem9udfkj9qr2y8lh728sr7uaedu5wwmfa72ykh395jqh7f7f9p2gskn6u7k844kpnwe3eqv84pl53r6x9af88a8ey7298njdg03h8mxqz2x6z8ys3qpuxq768tjq0zhrnjgns8d78euzwsvx6vn4f9tftrp68zcch3h75mc9drpt7tpvnyyqfjuqclxhdwhdwtsakecv04p9r3jx90htql9a3ht5mxrj4ercv4cd52wk4qhu7dn4tqe7yclqx2l36gcsrzmdlv440qls7qjpq6k95mst485vpennnur8h62a7d7syvyer89qtyfzlfhz8a5a0x5tuwhc9mah0e944xzhsc6uvpv8vat44w7r3xyw8q85y77jux8zhndrhdn36swryffqmpkxgcw4g29q40sul4fl5vrfru08a5j3rd3jl8799srpf2xqpxq38wwvhr4mxqf5wwdqfqq7harshggvufzlgn0l9fq0j76dyuge75jmzy8celvw6wesfs82n4jw2k8jnus2zds5a67my339uuzka4w72tau6j7wyu0lla0mcjpaflphsuy7f2phev6tr8vc9nj2mczkeg4vy3n5jkgecwgrvwu3vw9x5knpkxzv8kw3dpzzxy3rvrs56vxw8ugmyz2vdj6dakjyq3feym4290l7hgdt0ac5u49sekezzf0ghwmlek4h75fkzpvuly9zupw32dd3l9my282nekgk78fe6ayjyhczetxf8r82yd2askl52kmupr9xaxw0jd08dsd3523ea6ge48384rlmt4mu4w4x0q9s", Network::Main)?, NativeCurrencyAmount::coins(57)).into(),
    /// ];
    ///
    /// // change policy.
    /// // default is recover to next unused key, via onchain notification
    /// let change_policy = ChangePolicy::default();
    /// #
    /// // Max fee
    /// let fee : NativeCurrencyAmount = NativeCurrencyAmount::coins(10);
    /// #
    /// // neptune-core server sends token to a single recipient
    /// let send_result = client.send(context::current(), token, outputs, change_policy, fee).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn send(
        token: auth::Token,
        outputs: Vec<OutputFormat>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
    ) -> RpcResult<TxCreationArtifacts>;

    /// Like `send` but the resulting transaction is *transparent*. No privacy.
    ///
    /// Specifically, the resulting transaction contains announcements that
    /// themselves contain the raw UTXOs and commitment randomnesses. This
    /// info suffices to derive the addition records and removal records,
    /// thereby exposing not just the amounts but also the origins and
    /// destinations of the transfer.
    async fn send_transparent(
        token: auth::Token,
        outputs: Vec<OutputFormat>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
    ) -> RpcResult<TxCreationArtifacts>;

    /// Upgrade a proof for a transaction found in the mempool. If the
    /// transaction cannot be in the mempool, or the transaction is not in need
    /// of upgrading because it is already single proof-backed and synced, then
    /// false is returned. Otherwise true is returned.
    ///
    /// No fees will be collected from the proof upgrading.
    ///
    /// Returns Ok(true) if a transaction for upgrading was found
    /// Returns Ok(false) if no transaction for upgrading was found
    /// Returns an error if something else failed.
    async fn upgrade(token: auth::Token, tx_kernel_id: TransactionKernelId) -> RpcResult<bool>;

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
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
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
        token: auth::Token,
        utxo_transfer_encrypted: String,
        max_search_depth: Option<u64>,
    ) -> RpcResult<bool>;

    /// Delete all transactions from the mempool.
    async fn clear_mempool(token: auth::Token) -> RpcResult<()>;

    /// Pause receiving of blocks, block proposals, and transactions. If
    /// activated, no new blocks will be received. Transactions, blocks, and
    /// block proposals originating locally will not be shared with peers.
    /// Mining should be paused when this is activated. Cannot be called if the
    /// client is currently syncing.
    ///
    /// Can be used to build a big transaction through the merge of multiple
    /// smaller transactions without risking that the smaller, unmerged
    /// transactions are mined.
    async fn freeze(token: auth::Token) -> RpcResult<()>;

    /// Resume state updates. If state updates were paused, start receiving and
    /// transmitting blocks, block proposals, and transactions again. Otherwise,
    /// does nothing.
    async fn unfreeze(token: auth::Token) -> RpcResult<()>;

    /// Stop miner if running
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    ///  // stops miner if running
    /// let _ = client.pause_miner(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn pause_miner(token: auth::Token) -> RpcResult<()>;

    /// Start miner if not running
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    ///  // start miner if not running
    /// let _ = client.restart_miner(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn restart_miner(token: auth::Token) -> RpcResult<()>;

    /// Set coinbase distribution for this node's block proposals. This
    /// distribution will be in effect until it is overwritted or manually
    /// unset. The value set through this command stays in effect regardless of
    /// whether the block's proposals are mined or not. Only by overwriting this
    /// value by calling this function again, or by unsetting this value through
    /// [`RPC::unset_coinbase_distribution()`] can this effect be overturned.
    ///
    /// To guarantee that the set coinbase distribution is applied to the *next*
    /// locally produced block proposal, this function call can be followed up
    /// by a call to first [`RPC::pause_miner()`] and then
    /// [`RPC::restart_miner()`]. If this is not done, the node may continue
    /// working on an already started block proposal with another distribution.
    async fn set_coinbase_distribution(
        token: auth::Token,
        coinbase_distribution: Vec<CoinbaseOutputReadable>,
    ) -> RpcResult<()>;

    /// Remove a coinbase distribution from state, thus defaulting back to
    /// rewarding the node's own wallet with the composer's coinbase outputs.
    ///
    /// Can be used to delete coinbase distributions set through
    /// [`RPC::set_coinbase_distribution()`].
    async fn unset_coinbase_distribution(token: auth::Token) -> RpcResult<()>;

    /// mine a series of blocks to the node's wallet.
    ///
    /// Can be used only if the network uses mock blocks.
    /// (presently only the regtest network)
    ///
    /// these blocks can be generated quickly because they do not have
    /// a real ZK proof.  they have a witness "proof" and will validate correctly.
    /// witness proofs contain secrets that must not be shared, so this is
    /// allowed only on the regtest network, for development purposes.
    ///
    /// The timestamp of each block will be the current system time, meaning
    /// that they will be temporally very close to eachother.
    ///
    /// see [api::regtest::RegTest::mine_blocks_to_wallet()]
    async fn mine_blocks_to_wallet(token: auth::Token, n_blocks: u32) -> RpcResult<()>;

    /// Provide a PoW-solution to the current block proposal.
    ///
    /// If the solution is considered valid by the running node, the new block
    /// is broadcast to all peers on the network, and `true` is returned.
    /// Otherwise the provided solution is ignored, and `false` is returned.
    async fn provide_pow_solution(
        token: auth::Token,
        pow: BlockPow,
        proposal_id: Digest,
    ) -> RpcResult<bool>;

    /// Provide a PoW solution along with a valid block proposal. Caller must
    /// provide both the block proposal and the pow solution.
    ///
    /// Works like [`Self::provide_pow_solution()`] except that it takes a full
    /// block proposal rather than a proposal ID. This allows for the provision
    /// of a block without the node having to know the associated block proposal
    /// since proposal is provided by the caller. Can be used in conjuction with
    /// [`Self::full_pow_puzzle_external_key`].
    async fn provide_new_tip(
        token: auth::Token,
        pow: BlockPow,
        block_proposal: Block,
    ) -> RpcResult<bool>;

    /// mark MUTXOs as abandoned
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    ///  // marks mutxos as abandoned
    /// let abandoned_monitored_utxos = client.prune_abandoned_monitored_utxos(context::current(), token).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn prune_abandoned_monitored_utxos(token: auth::Token) -> RpcResult<usize>;

    /// Set the tip of the blockchain state to a given block, identified by its
    /// hash. The block must be stored, but it does not need to live on the
    /// canonical chain.
    async fn set_tip(token: auth::Token, indicated_tip: Digest) -> RpcResult<()>;

    /// Gracious shutdown.
    ///
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
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
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    ///  // shutdowns the node
    /// let is_shutdown = client.shutdown(context::current(), token).await??;
    /// # Ok(())
    /// # }
    async fn shutdown(token: auth::Token) -> RpcResult<bool>;
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
    valid_tokens: Vec<auth::Token>,
}

impl NeptuneRPCServer {
    /// instantiate a new [NeptuneRPCServer]
    pub fn new(
        state: GlobalStateLock,
        rpc_server_to_main_tx: tokio::sync::mpsc::Sender<RPCServerToMain>,
        data_directory: DataDirectory,
        valid_tokens: Vec<auth::Token>,
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
        let network = self.state.cli().network;
        let utxo_transfer_encrypted =
            EncryptedUtxoNotification::from_bech32m(&encrypted_utxo_notification, network)?;

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
        let utxo_notification = utxo_transfer_encrypted.decrypt_with_spending_key(&spending_key)?;

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
        let incoming_utxo = IncomingUtxo::from_utxo_notification_payload(
            utxo_notification,
            spending_key.privacy_preimage(),
        );

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
                    let last_aocl_index_in_block = block
                        .mutator_set_accumulator_after()
                        .expect("Block from state must have mutator set after")
                        .aocl
                        .num_leafs()
                        - 1;
                    let num_outputs_in_block: u64 = block
                        .mutator_set_update()
                        .expect("Block from state must have mutator set update")
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
                            "Claimed UTXO was spent in block {:x}; which has height {}",
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

    /// Return a PoW puzzle with the provided guesser address.
    async fn pow_puzzle_inner(
        mut self,
        guesser_address: ReceivingAddress,
        mut proposal: Block,
    ) -> RpcResult<Option<ProofOfWorkPuzzle>> {
        let latest_block_header = *self.state.lock_guard().await.chain.light_state().header();

        proposal.set_header_guesser_address(guesser_address);
        let puzzle = ProofOfWorkPuzzle::new(proposal.clone(), latest_block_header);

        // Record block proposal in case of guesser-success, for later
        // retrieval. But limit number of blocks stored this way.
        let mut state = self.state.lock_guard_mut().await;
        if state.mining_state.exported_block_proposals.len()
            >= MAX_NUM_EXPORTED_BLOCK_PROPOSAL_STORED
        {
            return Err(error::RpcError::ExportedBlockProposalStorageCapacityExceeded);
        }

        state
            .mining_state
            .exported_block_proposals
            .insert(puzzle.id, proposal);

        Ok(Some(puzzle))
    }

    /// Verify a pow solution and send it to main loop if it is valid.
    async fn pow_solution_inner(&self, mut proposal: Block, pow: BlockPow) -> RpcResult<bool> {
        // Check if solution works.
        let latest_block_header = *self.state.lock_guard().await.chain.light_state().header();

        proposal.set_header_pow(pow);

        if !proposal.has_proof_of_work(self.state.cli().network, &latest_block_header) {
            warn!("Got claimed PoW solution but PoW solution is not valid.");
            return Ok(false);
        }

        // No time to waste! Inform main_loop!
        let solution = Box::new(proposal);
        let _ = self
            .rpc_server_to_main_tx
            .send(RPCServerToMain::ProofOfWorkSolution(solution))
            .await;

        Ok(true)
    }

    /// get the data_directory for this neptune-core instance
    pub fn data_directory(&self) -> &DataDirectory {
        &self.data_directory
    }
}

impl RPC for NeptuneRPCServer {
    // documented in trait. do not add doc-comment.
    async fn cookie_hint(self, _: context::Context) -> RpcResult<auth::CookieHint> {
        log_slow_scope!(fn_name!());

        if self.state.cli().disable_cookie_hint {
            Err(error::RpcError::CookieHintDisabled)
        } else {
            Ok(auth::CookieHint {
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
        token: auth::Token,
    ) -> RpcResult<Option<SocketAddr>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let listen_port = self.state.cli().own_listen_port();
        let listen_for_peers_ip = self.state.cli().peer_listen_addr;
        Ok(listen_port.map(|port| SocketAddr::new(listen_for_peers_ip, port)))
    }

    // documented in trait. do not add doc-comment.
    async fn own_instance_id(
        self,
        _context: context::Context,
        token: auth::Token,
    ) -> RpcResult<InstanceId> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self.state.lock_guard().await.net.instance_id)
    }

    // documented in trait. do not add doc-comment.
    async fn block_height(self, _: context::Context, token: auth::Token) -> RpcResult<BlockHeight> {
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

    async fn best_proposal(
        self,
        _: context::Context,
        token: auth::Token,
    ) -> RpcResult<Option<BlockInfo>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let state = self.state.lock_guard().await;
        let tip_digest = state.chain.light_state().hash();
        let proposal = &state.mining_state.block_proposal;

        // Returning BlockInfo here is not completely kosher since a few fields
        // don't make sense in this context. But it's a close fit.
        Ok(proposal.map(|block| {
            BlockInfo::new(
                block,
                state.chain.archival_state().genesis_block().hash(),
                tip_digest,
                vec![],
                false,
            )
        }))
    }

    // documented in trait. do not add doc-comment.
    async fn confirmations(
        self,
        _: context::Context,
        token: auth::Token,
    ) -> RpcResult<Option<BlockHeight>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let guard = self.state.lock_guard().await;
        Ok(self.confirmations_internal(&guard).await)
    }

    // documented in trait. do not add doc-comment.
    async fn latest_address(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
        key_type: KeyType,
    ) -> RpcResult<ReceivingAddress> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let state = self.state.lock_guard().await;

        let current_counter = state.wallet_state.spending_key_counter(key_type);
        let index = current_counter.checked_sub(1);
        let Some(index) = index else {
            return Err(RpcError::WalletKeyCounterIsZero);
        };

        Ok(state
            .wallet_state
            .nth_spending_key(key_type, index)
            .to_address())
    }

    // documented in trait. do not add doc-comment.
    async fn utxo_digest(
        self,
        _: context::Context,
        token: auth::Token,
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
    async fn utxo_origin_block(
        self,
        _: context::Context,
        token: auth::Token,
        addition_record: AdditionRecord,
        max_search_depth: Option<u64>,
    ) -> RpcResult<Option<Digest>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let state = self.state.lock_guard().await;
        let block = state
            .chain
            .archival_state()
            .find_canonical_block_with_output(addition_record, max_search_depth)
            .await;

        Ok(block.map(|block| block.hash()))
    }

    // documented in trait. do not add doc-comment.
    async fn block_digest(
        self,
        _: context::Context,
        token: auth::Token,
        block_selector: BlockSelector,
    ) -> RpcResult<Option<Digest>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let state = self.state.lock_guard().await;
        let archival_state = state.chain.archival_state();
        let Some(digest) = block_selector.as_digest(&state).await else {
            return Ok(None);
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
        token: auth::Token,
        block_selector: BlockSelector,
    ) -> RpcResult<Option<BlockInfo>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let state = self.state.lock_guard().await;
        let Some(digest) = block_selector.as_digest(&state).await else {
            return Ok(None);
        };
        let tip_digest = state.chain.light_state().hash();
        let archival_state = state.chain.archival_state();

        let Some(block) = archival_state.get_block(digest).await.unwrap() else {
            return Ok(None);
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
    async fn block_kernel(
        self,
        _: context::Context,
        token: auth::Token,
        block_selector: BlockSelector,
    ) -> RpcResult<Option<BlockKernel>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let state = self.state.lock_guard().await;
        let Some(digest) = block_selector.as_digest(&state).await else {
            return Ok(None);
        };

        let block = state
            .chain
            .archival_state()
            .get_block(digest)
            .await
            .expect("Program must be able to read archival state data.");
        let block_kernel = block.map(|block| block.kernel.clone());

        Ok(block_kernel)
    }

    // documented in trait. do not add doc-comment.
    async fn addition_record_indices_for_block(
        self,
        _: context::Context,
        token: auth::Token,
        block_selector: BlockSelector,
    ) -> RpcResult<Vec<(AdditionRecord, Option<u64>)>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let state = self.state.lock_guard().await;
        let Some(digest) = block_selector.as_digest(&state).await else {
            return Ok(vec![]);
        };

        let addition_records_dictionary = state
            .chain
            .archival_state()
            .get_addition_record_indices_for_block(digest)
            .await
            .into_iter()
            .flatten()
            .collect_vec();

        Ok(addition_records_dictionary)
    }

    async fn restore_membership_proof_privacy_preserving(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
        requests: Vec<AbsoluteIndexSet>,
    ) -> RpcResult<ResponseMsMembershipProofPrivacyPreserving> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let state = self.state.lock_guard().await;
        let ams = state.chain.archival_state().archival_mutator_set.ams();

        let mut membership_proofs = Vec::with_capacity(requests.len());
        for request in requests {
            match ams
                .restore_membership_proof_privacy_preserving(request)
                .await
            {
                Ok(msmp) => membership_proofs.push(msmp),
                Err(err) => {
                    debug!("Failed to restore MSMP: {err}");
                    return Err(RpcError::CannotRestoreMembershipProofs(err.to_string()));
                }
            }
        }

        debug!("Restored {} msmps", membership_proofs.len());
        debug!(
            "AOCL MMR lengths: [{}]",
            membership_proofs
                .iter()
                .map(|x| x.aocl_auth_paths.len().to_string())
                .join(", ")
        );

        let cur_block = state.chain.light_state();
        let tip_height = cur_block.header().height;
        let tip_hash = cur_block.hash();
        let tip_mutator_set = cur_block
            .mutator_set_accumulator_after()
            .expect("Tip must have valid MSA after");

        Ok(ResponseMsMembershipProofPrivacyPreserving {
            tip_height,
            tip_hash,
            membership_proofs,
            tip_mutator_set,
        })
    }

    // documented in trait. do not add doc-comment.
    async fn announcements_in_block(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
        block_selector: BlockSelector,
    ) -> RpcResult<Option<Vec<Announcement>>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let state = self.state.lock_guard().await;
        let Some(digest) = block_selector.as_digest(&state).await else {
            return Ok(None);
        };
        let archival_state = state.chain.archival_state();
        let Some(block) = archival_state.get_block(digest).await.unwrap() else {
            return Ok(None);
        };

        Ok(Some(block.body().transaction_kernel.announcements.clone()))
    }

    // documented in trait. do not add doc-comment.
    async fn block_digests_by_height(
        self,
        _: context::Context,
        token: auth::Token,
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
        token: auth::Token,
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
    async fn peer_info(self, _: context::Context, token: auth::Token) -> RpcResult<Vec<PeerInfo>> {
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
        token: auth::Token,
    ) -> RpcResult<HashMap<IpAddr, PeerStanding>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let mut sanctions_in_memory = HashMap::default();

        let global_state = self.state.lock_guard().await;

        // Get all connected peers
        for (socket_address, peer_info) in &global_state.net.peer_map {
            if peer_info.standing().is_negative() {
                sanctions_in_memory.insert(socket_address.ip(), peer_info.standing());
            }
        }

        let sanctions_in_db = global_state.net.all_peer_sanctions_in_database();

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
        token: auth::Token,
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
        token: auth::Token,
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
        token: auth::Token,
        amount: NativeCurrencyAmount,
    ) -> RpcResult<bool> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let gs = self.state.lock_guard().await;
        let wallet_status = gs.get_wallet_status_for_tip().await;

        let confirmed_available = wallet_status.available_confirmed(Timestamp::now());

        // test inequality
        Ok(amount <= confirmed_available)
    }

    // documented in trait. do not add doc-comment.
    async fn confirmed_available_balance(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
    ) -> RpcResult<NativeCurrencyAmount> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let gs = self.state.lock_guard().await;
        let wallet_status = gs.get_wallet_status_for_tip().await;

        let confirmed_available = wallet_status.available_confirmed(Timestamp::now());

        Ok(confirmed_available)
    }

    // documented in trait. do not add doc-comment.
    async fn unconfirmed_available_balance(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
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
        token: auth::Token,
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
        token: auth::Token,
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
        token: auth::Token,
        block_selector: BlockSelector,
    ) -> RpcResult<Option<BlockHeader>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let state = self.state.lock_guard().await;
        let Some(block_digest) = block_selector.as_digest(&state).await else {
            return Ok(None);
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
        token: auth::Token,
        key_type: KeyType,
    ) -> RpcResult<ReceivingAddress> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self
            .state
            .api_mut()
            .wallet_mut()
            .next_receiving_address(key_type)
            .await?)
    }

    // documented in trait. do not add doc-comment.
    async fn known_keys(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
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
        token: auth::Token,
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
        token: auth::Token,
    ) -> RpcResult<usize> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self.state.lock_guard().await.mempool.len())
    }

    // documented in trait. do not add doc-comment.
    async fn mempool_size(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
    ) -> RpcResult<usize> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self.state.lock_guard().await.mempool.get_size())
    }

    async fn mempool_tx_ids(
        self,
        _context: ::tarpc::context::Context,
        token: auth::Token,
    ) -> RpcResult<Vec<TransactionKernelId>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;
        let txids: Vec<_> = self
            .state
            .lock_guard()
            .await
            .mempool
            .fee_density_iter()
            .map(|(kernel_id, _)| kernel_id)
            .collect();

        Ok(txids)
    }

    // documented in trait. do not add doc-comment.
    async fn history(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
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
        token: auth::Token,
    ) -> RpcResult<OverviewData> {
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

        let peer_count = Some(state.net.peer_map.len());
        let max_num_peers = self.state.cli().max_num_peers;

        let mining_status = Some(state.mining_state.mining_status);

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
            wallet_status.available_confirmed(now)
        };
        let confirmed_total_balance = {
            log_slow_scope!(fn_name!() + "::confirmed_total_balance()");
            wallet_status.total_confirmed()
        };

        let unconfirmed_available_balance = {
            log_slow_scope!(fn_name!() + "::unconfirmed_available_balance()");
            wallet_state.unconfirmed_available_balance(&wallet_status, now)
        };
        let unconfirmed_total_balance = {
            log_slow_scope!(fn_name!() + "::unconfirmed_total_balance()");
            wallet_state.unconfirmed_total_balance(&wallet_status)
        };

        Ok(OverviewData {
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
        token: auth::Token,
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
        token: auth::Token,
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
    async fn record_and_broadcast_transaction(
        mut self,
        _: context::Context,
        token: auth::Token,
        tx_artifacts: TxCreationArtifacts,
    ) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self
            .state
            .api_mut()
            .tx_initiator_mut()
            .record_and_broadcast_transaction(&tx_artifacts)
            .await?)
    }

    // documented in trait. do not add doc-comment.
    async fn send(
        mut self,
        _ctx: context::Context,
        token: auth::Token,
        outputs: Vec<OutputFormat>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
    ) -> RpcResult<TxCreationArtifacts> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self
            .state
            .api_mut()
            .tx_sender_mut()
            .send(outputs, change_policy, fee, Timestamp::now())
            .await?)
    }

    // documented in trait. do not add doc-commtn.
    async fn send_transparent(
        mut self,
        _ctx: context::Context,
        token: auth::Token,
        outputs: Vec<OutputFormat>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
    ) -> RpcResult<TxCreationArtifacts> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self
            .state
            .api_mut()
            .tx_initiator_mut()
            .send_transparent(outputs, change_policy, fee, Timestamp::now())
            .await?)
    }

    async fn upgrade(
        mut self,
        _ctx: context::Context,
        token: auth::Token,
        tx_kernel_id: TransactionKernelId,
    ) -> RpcResult<bool> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        // Does transaction exist and is it in need of upgrading?
        let Some((tx, upgrade_priority)) = self
            .state
            .lock_guard()
            .await
            .mempool
            .get_with_priority(tx_kernel_id)
            .map(|(x, y)| (x.to_owned(), y))
        else {
            return Ok(false);
        };

        let current_msa = self
            .state
            .lock_guard()
            .await
            .chain
            .light_state()
            .mutator_set_accumulator_after()
            .expect("mutator set of tip must exist");
        let is_synced = tx.kernel.mutator_set_hash == current_msa.hash();

        let upgrade_job = match (&tx.proof, is_synced) {
            (TransactionProof::SingleProof(_), true) => return Ok(false),
            (TransactionProof::SingleProof(neptune_proof), false) => {
                let gobbling_potential = NativeCurrencyAmount::zero();
                let update_job = self
                    .state
                    .lock_guard_mut()
                    .await
                    .update_single_proof_job(
                        tx.kernel,
                        neptune_proof.to_owned(),
                        upgrade_priority.incentive_given_gobble_potential(gobbling_potential),
                    )
                    .await?;
                UpgradeJob::UpdateMutatorSetData(update_job)
            }
            (TransactionProof::ProofCollection(proof_collection), _) => {
                // It doesn't matter if the proof collection is updated or not,
                // since the later call to upgrade the transaction handles the
                // case of unsynced single proof backed transactions.
                let gobbling_potential = NativeCurrencyAmount::zero();
                let raise_job = self
                    .state
                    .lock_guard_mut()
                    .await
                    .upgrade_proof_collection_job(
                        tx.kernel,
                        proof_collection.to_owned(),
                        upgrade_priority.incentive_given_gobble_potential(gobbling_potential),
                    )
                    .await?;
                UpgradeJob::ProofCollectionToSingleProof(raise_job)
            }

            // This implementation is not done because local transaction initiation
            // should always produce proof collections or single proofs, and
            // primitive witnesses may never be shared on the network. So it seems
            // there is no use case for implementing this.
            (TransactionProof::Witness(_), _) => {
                error!("Can't upgrade primitive witnesses through this command.");
                return Ok(false);
            }
        };

        let _ = self
            .rpc_server_to_main_tx
            .send(RPCServerToMain::PerformTxProofUpgrade(Box::new(
                upgrade_job,
            )))
            .await;

        Ok(true)
    }

    // // documented in trait. do not add doc-comment.
    async fn claim_utxo(
        mut self,
        _ctx: context::Context,
        token: auth::Token,
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
    async fn shutdown(self, _: context::Context, token: auth::Token) -> RpcResult<bool> {
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
    async fn clear_mempool(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
    ) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let _ = self
            .rpc_server_to_main_tx
            .send(RPCServerToMain::ClearMempool)
            .await;
        Ok(())
    }

    // documented in trait. do not add doc-comment.
    async fn freeze(
        mut self,
        _context: tarpc::context::Context,
        token: auth::Token,
    ) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let mut state = self.state.lock_guard_mut().await;

        if state.net.sync_anchor.is_some() {
            error!("Cannot pause state updates when syncing.");
            return Err(error::RpcError::CannotPauseWhileSyncing);
        }

        state.net.freeze = true;

        Ok(())
    }

    // documented in trait. do not add doc-comment.
    async fn unfreeze(
        mut self,
        _context: tarpc::context::Context,
        token: auth::Token,
    ) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        self.state.lock_mut(|state| state.net.freeze = false).await;

        Ok(())
    }

    async fn pause_miner(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
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
        token: auth::Token,
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
    async fn set_coinbase_distribution(
        mut self,
        _context: tarpc::context::Context,
        token: auth::Token,
        coinbase_distribution_readable: Vec<CoinbaseOutputReadable>,
    ) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let network = self.state.cli().network;
        let mut coinbase_distribution = vec![];
        for output in coinbase_distribution_readable {
            let output = match output.into_coinbase_output(network) {
                Ok(cbo) => cbo,
                Err(err) => return Err(RpcError::InvalidCoinbaseDistribution(err.to_string())),
            };
            coinbase_distribution.push(output);
        }

        let coinbase_distribution = match CoinbaseDistribution::try_new(coinbase_distribution) {
            Ok(cd) => cd,
            Err(err) => return Err(RpcError::InvalidCoinbaseDistribution(err.to_string())),
        };

        if !self.state.cli().compose {
            warn!("Cannot set coinbase distribution as node is not composing");
            return Err(RpcError::NotComposing);
        }

        let mut state = self.state.lock_guard_mut().await;
        state
            .mining_state
            .set_coinbase_distribution(coinbase_distribution);

        Ok(())
    }

    // documented in trait. do not add doc-comment.
    async fn unset_coinbase_distribution(
        mut self,
        _context: tarpc::context::Context,
        token: auth::Token,
    ) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        if self.state.cli().mine() {
            let mut state = self.state.lock_guard_mut().await;
            state.mining_state.unset_coinbase_distribution();
        } else {
            warn!("Cannot unset coinbase distribution as node is not mining");
        }

        Ok(())
    }

    // documented in trait. do not add doc-comment.
    async fn mine_blocks_to_wallet(
        mut self,
        _context: tarpc::context::Context,
        token: auth::Token,
        n_blocks: u32,
    ) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let include_mempool_txs = true;
        Ok(self
            .state
            .api_mut()
            .regtest_mut()
            .mine_blocks_to_wallet(n_blocks, include_mempool_txs)
            .await?)
    }

    // documented in trait. do not add doc-comment.
    async fn provide_pow_solution(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
        pow: BlockPow,
        proposal_id: Digest,
    ) -> RpcResult<bool> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        // Find proposal from list of exported proposals.
        let Some(proposal) = self
            .state
            .lock_guard()
            .await
            .mining_state
            .exported_block_proposals
            .get(&proposal_id)
            .map(|x| x.to_owned())
        else {
            warn!(
                "Got claimed PoW solution but no challenge was known. \
                Did solution come in too late?"
            );
            return Ok(false);
        };

        self.pow_solution_inner(proposal, pow).await
    }

    // documented in trait. do not add doc-comment.
    async fn provide_new_tip(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
        pow: BlockPow,
        proposal: Block,
    ) -> RpcResult<bool> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        // Since block comes from external source, we need to check validity.
        let current_tip = self.state.lock_guard().await.chain.light_state().clone();
        if !proposal
            .is_valid(&current_tip, Timestamp::now(), self.state.cli().network)
            .await
        {
            warn!("Got claimed new block that was not valid");
            return Ok(false);
        }

        self.pow_solution_inner(proposal, pow).await
    }

    // documented in trait. do not add doc-comment.
    async fn prune_abandoned_monitored_utxos(
        mut self,
        _context: tarpc::context::Context,
        token: auth::Token,
    ) -> RpcResult<usize> {
        const DEFAULT_MUTXO_PRUNE_DEPTH: usize = 200;

        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let mut global_state_mut = self.state.lock_guard_mut().await;

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

    // Documented in trait. Do not add doc-comment.
    async fn set_tip(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
        indicated_tip: Digest,
    ) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        // Set tip asynchronously -- avoid RPC timeout.
        self.rpc_server_to_main_tx
            .send(RPCServerToMain::SetTipToStoredBlock(indicated_tip))
            .await
            .map_err(|e| RpcError::Failed(format!("could not send message to main loop: {e}")))?;

        Ok(())
    }

    // documented in trait. do not add doc-comment.
    async fn list_own_coins(
        self,
        _context: ::tarpc::context::Context,
        token: auth::Token,
    ) -> RpcResult<Vec<CoinWithPossibleTimeLock>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let state = self.state.lock_guard().await;
        let tip = state.chain.light_state();
        let tip_hash = tip.hash();
        let tip_msa = tip
            .mutator_set_accumulator_after()
            .expect("Block from state must have mutator set after");

        Ok(state
            .wallet_state
            .get_all_own_coins_with_possible_timelocks(&tip_msa, tip_hash)
            .await)
    }

    /// Get [`UiUtxo`] from three sources:
    /// 1) the wallet database for monitored UTXOs (these are confirmed);
    /// 2) the mempool (these are pending); and
    /// 3) the wallet database for expected UTXOs (expected).
    ///
    /// The assembled list of [`UiUtxo`] is deduplicated based on addition record, which is
    /// collected separately in a hash set. Note that this order is important because it
    /// implicitly resolves duplicate conflicts. A duplicate [`UiUtxo`] cannot be inserted again,
    /// so the first stage that applies determines the "received" label --
    /// confirmed / pending / expected.
    async fn list_utxos(
        self,
        _context: ::tarpc::context::Context,
        token: auth::Token,
    ) -> RpcResult<Vec<UiUtxo>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        // get owned UTXOs
        let mut ui_utxos = vec![];
        let mut present_addition_records = HashSet::new();
        let state = self.state.lock_guard().await;
        for monitored_utxo in state
            .wallet_state
            .wallet_db
            .monitored_utxos()
            .get_all()
            .await
        {
            let received =
                if let Some((_, timestamp, block_height)) = monitored_utxo.confirmed_in_block {
                    UtxoStatusEvent::Confirmed {
                        block_height,
                        timestamp,
                    }
                } else {
                    UtxoStatusEvent::Abandoned
                };
            let spent = if let Some((_, timestamp, block_height)) = monitored_utxo.spent_in_block {
                UtxoStatusEvent::Confirmed {
                    block_height,
                    timestamp,
                }
            } else {
                UtxoStatusEvent::None
            };

            if present_addition_records.insert(monitored_utxo.addition_record()) {
                ui_utxos.push(UiUtxo {
                    received,
                    spent,
                    aocl_leaf_index: Some(monitored_utxo.aocl_index()),
                    amount: monitored_utxo.utxo.get_native_currency_amount(),
                    release_date: monitored_utxo.utxo.release_date(),
                });
            }
        }

        // get unconfirmed incoming UTXOs
        for (incoming_utxo, addition_record) in state.wallet_state.mempool_unspent_utxos_iter() {
            if present_addition_records.insert(addition_record) {
                ui_utxos.push(UiUtxo {
                    received: UtxoStatusEvent::Pending,
                    aocl_leaf_index: None,
                    spent: UtxoStatusEvent::None,
                    amount: incoming_utxo.get_native_currency_amount(),
                    release_date: incoming_utxo.release_date(),
                });
            }
        }

        // get expected UTXOs
        for expected_utxo in state
            .wallet_state
            .wallet_db
            .expected_utxos()
            .get_all()
            .await
        {
            if present_addition_records.insert(expected_utxo.addition_record) {
                ui_utxos.push(UiUtxo {
                    received: UtxoStatusEvent::Expected,
                    aocl_leaf_index: None,
                    spent: UtxoStatusEvent::None,
                    amount: expected_utxo.utxo.get_native_currency_amount(),
                    release_date: expected_utxo.utxo.release_date(),
                });
            }
        }

        // mark "spent" label on unconfirmed outgoing UTXOs as "pending"
        let mut markable_indices = HashSet::new();
        for (_outgoing_utxo, aocl_leaf_index) in state.wallet_state.mempool_spent_utxos_iter() {
            markable_indices.insert(aocl_leaf_index);
        }
        for ui_utxo in &mut ui_utxos {
            if let Some(aocl_leaf_index) = ui_utxo.aocl_leaf_index {
                if markable_indices.contains(&aocl_leaf_index) {
                    ui_utxo.spent = UtxoStatusEvent::Pending;
                }
            }
        }

        Ok(ui_utxos)
    }

    // documented in trait. do not add doc-comment.
    async fn cpu_temp(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
    ) -> RpcResult<Option<f32>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(Self::cpu_temp_inner())
    }

    // documented in trait. do not add doc-comment.
    async fn pow_puzzle_internal_key(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
    ) -> RpcResult<Option<ProofOfWorkPuzzle>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let Some(proposal) = self
            .state
            .lock_guard()
            .await
            .mining_state
            .block_proposal
            .map(|x| x.to_owned())
        else {
            return Ok(None);
        };

        let guesser_key = self
            .state
            .lock_guard()
            .await
            .wallet_state
            .wallet_entropy
            .guesser_fee_key();

        self.pow_puzzle_inner(guesser_key.to_address().into(), proposal)
            .await
    }

    // documented in trait. do not add doc-comment.
    async fn pow_puzzle_external_key(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
        guesser_fee_address: ReceivingAddress,
    ) -> RpcResult<Option<ProofOfWorkPuzzle>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let Some(proposal) = self
            .state
            .lock_guard()
            .await
            .mining_state
            .block_proposal
            .map(|x| x.to_owned())
        else {
            return Ok(None);
        };

        self.pow_puzzle_inner(guesser_fee_address, proposal).await
    }

    // documented in trait. do not add doc-comment.
    async fn full_pow_puzzle_external_key(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
        guesser_fee_address: ReceivingAddress,
    ) -> RpcResult<Option<(Block, ProofOfWorkPuzzle)>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let (mut proposal, latest_block_header) = {
            let global_state = self.state.lock_guard().await;
            let Some(proposal) = global_state
                .mining_state
                .block_proposal
                .map(|x| x.to_owned())
            else {
                return Ok(None);
            };

            let latest_block_header = *global_state.chain.light_state().header();
            (proposal, latest_block_header)
        };

        proposal.set_header_guesser_address(guesser_fee_address);
        let puzzle = ProofOfWorkPuzzle::new(proposal.clone(), latest_block_header);

        Ok(Some((proposal, puzzle)))
    }

    // documented in trait. do not add doc-comment.
    async fn spendable_inputs(
        self,
        _: context::Context,
        token: auth::Token,
    ) -> RpcResult<TxInputList> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self
            .state
            .api()
            .tx_initiator()
            .spendable_inputs(Timestamp::now())
            .await)
    }

    // documented in trait. do not add doc-comment.
    async fn select_spendable_inputs(
        self,
        _: context::Context,
        token: auth::Token,
        policy: InputSelectionPolicy,
        spend_amount: NativeCurrencyAmount,
    ) -> RpcResult<TxInputList> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self
            .state
            .api()
            .tx_initiator()
            .select_spendable_inputs(policy, spend_amount, Timestamp::now())
            .await
            .into())
    }

    // documented in trait. do not add doc-comment.
    async fn generate_tx_outputs(
        self,
        _: context::Context,
        token: auth::Token,
        outputs: Vec<OutputFormat>,
    ) -> RpcResult<TxOutputList> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self
            .state
            .api()
            .tx_initiator()
            .generate_tx_outputs(outputs)
            .await)
    }

    // documented in trait. do not add doc-comment.
    async fn generate_tx_details(
        self,
        _: context::Context,
        token: auth::Token,
        tx_inputs: TxInputList,
        tx_outputs: TxOutputList,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
    ) -> RpcResult<TransactionDetails> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self
            .state
            .api()
            .tx_initiator()
            .generate_tx_details(tx_inputs, tx_outputs, change_policy, fee)
            .await?)
    }

    // documented in trait. do not add doc-comment.
    async fn generate_witness_proof(
        self,
        _: context::Context,
        token: auth::Token,
        tx_details: TransactionDetails,
    ) -> RpcResult<TransactionProof> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self
            .state
            .api()
            .tx_initiator()
            .generate_witness_proof(Arc::new(tx_details)))
    }

    // documented in trait. do not add doc-comment.
    async fn assemble_transaction(
        self,
        _: context::Context,
        token: auth::Token,
        transaction_details: TransactionDetails,
        transaction_proof: TransactionProof,
    ) -> RpcResult<Transaction> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self
            .state
            .api()
            .tx_initiator()
            .assemble_transaction(&transaction_details, transaction_proof)?)
    }

    // documented in trait. do not add doc-comment.
    async fn assemble_transaction_artifacts(
        self,
        _: context::Context,
        token: auth::Token,
        transaction_details: TransactionDetails,
        transaction_proof: TransactionProof,
    ) -> RpcResult<TxCreationArtifacts> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self
            .state
            .api()
            .tx_initiator()
            .assemble_transaction_artifacts(transaction_details, transaction_proof)?)
    }

    // documented in trait. do not add doc-comment.
    async fn proof_type(
        self,
        _ctx: context::Context,
        token: auth::Token,
        txid: TransactionKernelId,
    ) -> RpcResult<TransactionProofType> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self.state.api().tx_initiator().proof_type(txid).await?)
    }

    // documented in trait. do not add doc-comment.
    async fn block_intervals(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
        last_block: BlockSelector,
        max_num_blocks: Option<usize>,
    ) -> RpcResult<Option<Vec<(u64, u64)>>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let state = self.state.lock_guard().await;
        let Some(last_block) = last_block.as_digest(&state).await else {
            return Ok(None);
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
        token: auth::Token,
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
    async fn broadcast_all_mempool_txs(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
    ) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        // If this sending fails, it means `main_loop` is no longer running,
        // and node is crashed. No reason to log anything additional.
        let _ = self
            .rpc_server_to_main_tx
            .send(RPCServerToMain::BroadcastMempoolTransactions)
            .await;

        Ok(())
    }

    async fn broadcast_block_proposal(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
    ) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let _ = self
            .rpc_server_to_main_tx
            .send(RPCServerToMain::BroadcastBlockProposal)
            .await;

        Ok(())
    }

    // documented in trait. do not add doc-comment.
    async fn mempool_overview(
        self,
        _context: ::tarpc::context::Context,
        token: auth::Token,
        start_index: usize,
        number: usize,
    ) -> RpcResult<Vec<MempoolTransactionInfo>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let global_state = self.state.lock_guard().await;
        let mempool_txkids = global_state
            .mempool
            .fee_density_iter()
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
            .expect("Block from state must have mutator set after")
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

    // documented in trait. do not add doc-comment.
    async fn mempool_tx_kernel(
        self,
        _context: ::tarpc::context::Context,
        token: auth::Token,
        tx_kernel_id: TransactionKernelId,
    ) -> RpcResult<Option<TransactionKernel>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self
            .state
            .lock_guard()
            .await
            .mempool
            .get(tx_kernel_id)
            .map(|tx| &tx.kernel)
            .cloned())
    }
}

pub mod error {
    use super::*;

    /// enumerates possible rpc api errors
    #[derive(Debug, thiserror::Error, Serialize, Deserialize)]
    #[non_exhaustive]
    pub enum RpcError {
        // auth error
        #[error("auth error: {0}")]
        Auth(#[from] auth::error::AuthError),

        // catch-all error, eg for anyhow errors
        #[error("rpc call failed: {0}")]
        Failed(String),

        // API specific error variants.
        #[error("cookie hints are disabled on this node")]
        CookieHintDisabled,

        #[error("capacity to store exported block proposals exceeded")]
        ExportedBlockProposalStorageCapacityExceeded,

        #[error("create transaction error: {0}")]
        CreateTxError(String),

        #[error("upgrade proof error: {0}")]
        UpgradeProofError(String),

        #[error("send error: {0}")]
        SendError(String),

        #[error("regtest error: {0}")]
        RegTestError(String),

        #[error("wallet error: {0}")]
        WalletError(String),

        #[error("claim error: {0}")]
        ClaimError(String),

        #[error("Cannot pause state updates while client is syncing")]
        CannotPauseWhileSyncing,

        #[error("Invalid coinbase distribution: {0}")]
        InvalidCoinbaseDistribution(String),

        #[error("Node is not setup to compose")]
        NotComposing,

        #[error("Cannot restore membership proofs: {0}")]
        CannotRestoreMembershipProofs(String),

        #[error("Wallet key counter is zero. Must be positive after init")]
        WalletKeyCounterIsZero,
    }

    impl From<tx_initiation::error::CreateTxError> for RpcError {
        fn from(err: tx_initiation::error::CreateTxError) -> Self {
            RpcError::CreateTxError(err.to_string())
        }
    }

    impl From<tx_initiation::error::UpgradeProofError> for RpcError {
        fn from(err: tx_initiation::error::UpgradeProofError) -> Self {
            RpcError::UpgradeProofError(err.to_string())
        }
    }

    impl From<tx_initiation::error::SendError> for RpcError {
        fn from(err: tx_initiation::error::SendError) -> Self {
            RpcError::SendError(err.to_string())
        }
    }

    impl From<api::regtest::error::RegTestError> for RpcError {
        fn from(err: api::regtest::error::RegTestError) -> Self {
            RpcError::RegTestError(err.to_string())
        }
    }

    impl From<api::wallet::error::WalletError> for RpcError {
        fn from(err: api::wallet::error::WalletError) -> Self {
            RpcError::WalletError(err.to_string())
        }
    }

    impl From<ClaimError> for RpcError {
        fn from(err: ClaimError) -> Self {
            RpcError::ClaimError(err.to_string())
        }
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
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use anyhow::Result;
    use macro_rules_attr::apply;
    use num_traits::One;
    use num_traits::Zero;
    use proptest::prop_assume;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use strum::IntoEnumIterator;
    use tracing_test::traced_test;

    use super::*;
    use crate::application::config::cli_args;
    use crate::application::config::network::Network;
    use crate::application::database::storage::storage_vec::traits::*;
    use crate::application::rpc::server::NeptuneRPCServer;
    use crate::protocol::consensus::block::block_selector::BlockSelectorLiteral;
    use crate::protocol::peer::NegativePeerSanction;
    use crate::protocol::peer::PeerSanction;
    use crate::protocol::proof_abstractions::mast_hash::MastHash;
    use crate::state::wallet::address::generation_address::GenerationReceivingAddress;
    use crate::state::wallet::address::generation_address::GenerationSpendingKey;
    use crate::state::wallet::utxo_notification::UtxoNotificationMedium;
    use crate::state::wallet::wallet_entropy::WalletEntropy;
    use crate::tests::shared::blocks::invalid_block_with_transaction;
    use crate::tests::shared::blocks::make_mock_block;
    use crate::tests::shared::files::unit_test_data_directory;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared::strategies::txkernel;
    use crate::tests::shared_tokio_runtime;
    use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
    use crate::Block;

    const NUM_ANNOUNCEMENTS_BLOCK1: usize = 7;

    async fn test_rpc_server(
        wallet_entropy: WalletEntropy,
        peer_count: u8,
        cli: cli_args::Args,
    ) -> NeptuneRPCServer {
        let global_state_lock =
            mock_genesis_global_state(peer_count, wallet_entropy, cli.clone()).await;

        let data_directory = unit_test_data_directory(cli.network).unwrap();

        let valid_tokens: Vec<auth::Token> =
            vec![auth::Cookie::try_new(&data_directory).await.unwrap().into()];

        let rpc_to_main_tx = global_state_lock.rpc_server_to_main_tx();

        NeptuneRPCServer::new(
            global_state_lock,
            rpc_to_main_tx,
            data_directory,
            valid_tokens,
        )
    }

    async fn cookie_token(server: &NeptuneRPCServer) -> auth::Token {
        auth::Cookie::try_load(server.data_directory())
            .await
            .unwrap()
            .into()
    }

    #[apply(shared_tokio_runtime)]
    async fn network_response_is_consistent() -> Result<()> {
        for network in [Network::Main, Network::Testnet(0)] {
            let rpc_server = test_rpc_server(
                WalletEntropy::new_random(),
                2,
                cli_args::Args::default_with_network(network),
            )
            .await;
            assert_eq!(network, rpc_server.network(context::current()).await?);
        }

        Ok(())
    }

    #[apply(shared_tokio_runtime)]
    async fn verify_that_all_requests_leave_server_running() -> Result<()> {
        // Got through *all* request types and verify that server does not crash.
        // We don't care about the actual response data in this test, just that the
        // requests do not crash the server.

        let network = Network::Main;
        let mut rng = StdRng::seed_from_u64(123456789088u64);

        let rpc_server = test_rpc_server(
            WalletEntropy::new_pseudorandom(rng.random()),
            2,
            cli_args::Args::default_with_network(network),
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
        let _ = rpc_server.clone().best_proposal(ctx, token).await;
        let _ = rpc_server
            .clone()
            .latest_address(ctx, token, KeyType::Generation)
            .await
            .unwrap();
        let _ = rpc_server
            .clone()
            .latest_address(ctx, token, KeyType::Symmetric)
            .await
            .unwrap();
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
            .block_kernel(ctx, token, BlockSelector::Digest(Digest::default()))
            .await;
        let _ = rpc_server
            .clone()
            .addition_record_indices_for_block(ctx, token, BlockSelector::Digest(Digest::default()))
            .await;
        let _ = rpc_server
            .clone()
            .restore_membership_proof_privacy_preserving(
                ctx,
                token,
                vec![AbsoluteIndexSet::compute(
                    Digest::default(),
                    Digest::default(),
                    Digest::default(),
                    444,
                )],
            )
            .await;
        let _ = rpc_server
            .clone()
            .announcements_in_block(ctx, token, BlockSelector::Digest(Digest::default()))
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
            .await?;
        let _ = rpc_server.clone().mempool_tx_count(ctx, token).await;
        let _ = rpc_server.clone().mempool_size(ctx, token).await;
        let _ = rpc_server.clone().dashboard_overview_data(ctx, token).await;
        let _ = rpc_server
            .clone()
            .validate_address(
                ctx,
                token,
                "Not a valid address".to_owned(),
                Network::Testnet(0),
            )
            .await;
        let _ = rpc_server.clone().pow_puzzle_internal_key(ctx, token).await;
        let _ = rpc_server
            .clone()
            .pow_puzzle_external_key(ctx, token, own_receiving_address.clone())
            .await;
        let _ = rpc_server
            .clone()
            .provide_pow_solution(ctx, token, rng.random(), rng.random())
            .await;
        let _ = rpc_server
            .clone()
            .full_pow_puzzle_external_key(ctx, token, own_receiving_address.clone())
            .await
            .unwrap();
        let _ = rpc_server
            .clone()
            .spendable_inputs(ctx, token)
            .await
            .unwrap();
        let _ = rpc_server
            .clone()
            .select_spendable_inputs(
                ctx,
                token,
                InputSelectionPolicy::Random,
                NativeCurrencyAmount::coins(5),
            )
            .await;
        let _ = rpc_server
            .clone()
            .generate_tx_outputs(ctx, token, vec![])
            .await
            .unwrap();
        let tx_details = rpc_server
            .clone()
            .generate_tx_details(
                ctx,
                token,
                TxInputList::default(),
                TxOutputList::default(),
                ChangePolicy::default(),
                NativeCurrencyAmount::zero(),
            )
            .await
            .unwrap();
        let tx_proof = rpc_server
            .clone()
            .generate_witness_proof(ctx, token, tx_details.clone())
            .await
            .unwrap();
        let _ = rpc_server
            .clone()
            .assemble_transaction(ctx, token, tx_details, tx_proof)
            .await
            .unwrap();
        let _ = rpc_server
            .clone()
            .provide_new_tip(ctx, token, rng.random(), Block::genesis(network))
            .await
            .unwrap();
        let _ = rpc_server
            .clone()
            .block_intervals(
                ctx,
                token,
                BlockSelector::Special(BlockSelectorLiteral::Tip),
                None,
            )
            .await;
        let _ = rpc_server
            .clone()
            .block_difficulties(
                ctx,
                token,
                BlockSelector::Special(BlockSelectorLiteral::Tip),
                None,
            )
            .await;
        let _ = rpc_server
            .clone()
            .broadcast_all_mempool_txs(ctx, token)
            .await;
        let _ = rpc_server.clone().mempool_overview(ctx, token, 0, 20).await;
        let _ = rpc_server
            .clone()
            .mempool_tx_kernel(ctx, token, Default::default())
            .await;
        let _ = rpc_server.clone().clear_all_standings(ctx, token).await;
        let _ = rpc_server
            .clone()
            .clear_standing_by_ip(ctx, token, "127.0.0.1".parse().unwrap())
            .await;
        let output: OutputFormat = (
            own_receiving_address.clone(),
            NativeCurrencyAmount::one_nau(),
        )
            .into();
        let _ = rpc_server
            .clone()
            .send(
                ctx,
                token,
                vec![output],
                ChangePolicy::ExactChange,
                NativeCurrencyAmount::one_nau(),
            )
            .await;
        let _ = rpc_server
            .clone()
            .upgrade(ctx, token, TransactionKernelId::default())
            .await;
        let _ = rpc_server.clone().mempool_tx_ids(ctx, token).await;

        let my_output: OutputFormat =
            (own_receiving_address, NativeCurrencyAmount::one_nau()).into();
        let _ = rpc_server
            .clone()
            .send(
                ctx,
                token,
                vec![my_output],
                ChangePolicy::ExactChange,
                NativeCurrencyAmount::one_nau(),
            )
            .await;

        let _ = rpc_server.clone().pause_miner(ctx, token).await;
        let _ = rpc_server.clone().restart_miner(ctx, token).await;
        let _ = rpc_server
            .clone()
            .set_coinbase_distribution(ctx, token, vec![])
            .await;
        let _ = rpc_server
            .clone()
            .unset_coinbase_distribution(ctx, token)
            .await;
        let _ = rpc_server
            .clone()
            .prune_abandoned_monitored_utxos(ctx, token)
            .await;
        let _ = rpc_server.shutdown(ctx, token).await;

        Ok(())
    }

    #[apply(shared_tokio_runtime)]
    async fn latest_address_and_get_new_address_are_consistent() {
        let rpc_server = test_rpc_server(
            WalletEntropy::new_random(),
            2,
            cli_args::Args::default_with_network(Network::Main),
        )
        .await;
        let token = cookie_token(&rpc_server).await;

        for key_type in KeyType::iter() {
            let addr0 = rpc_server
                .clone()
                .latest_address(context::current(), token, key_type)
                .await
                .unwrap();
            let addr1 = rpc_server
                .clone()
                .next_receiving_address(context::current(), token, key_type)
                .await
                .unwrap();
            assert_ne!(addr0, addr1);

            let addr1_again = rpc_server
                .clone()
                .latest_address(context::current(), token, key_type)
                .await
                .unwrap();
            assert_eq!(addr1, addr1_again);

            let addr2 = rpc_server
                .clone()
                .next_receiving_address(context::current(), token, key_type)
                .await
                .unwrap();
            let addr2_again = rpc_server
                .clone()
                .latest_address(context::current(), token, key_type)
                .await
                .unwrap();
            assert_eq!(addr2, addr2_again);

            // Ensure endpoint is idempotent
            let addr2_again_again = rpc_server
                .clone()
                .latest_address(context::current(), token, key_type)
                .await
                .unwrap();
            assert_eq!(addr2, addr2_again_again);
        }
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn balance_is_zero_at_init() -> Result<()> {
        // Verify that a wallet not receiving a premine is empty at startup
        let rpc_server = test_rpc_server(
            WalletEntropy::new_random(),
            2,
            cli_args::Args::default_with_network(Network::Main),
        )
        .await;
        let token = cookie_token(&rpc_server).await;
        let balance = rpc_server
            .confirmed_available_balance(context::current(), token)
            .await?;
        assert!(balance.is_zero());

        Ok(())
    }

    #[apply(shared_tokio_runtime)]
    async fn create_and_broadcast_valid_tx_through_rpc_endpoints() {
        // Go through a list of endpoints resulting in a valid
        // PrimitiveWitness-backed transaction. Uses the devnet premine UTXO to
        // fund the transaction.
        let network = Network::Main;
        let rpc_server = test_rpc_server(
            WalletEntropy::devnet_wallet(),
            2,
            cli_args::Args::default_with_network(network),
        )
        .await;
        let token = cookie_token(&rpc_server).await;
        let ctx = context::current();
        let spendable_inputs = rpc_server
            .clone()
            .spendable_inputs(ctx, token)
            .await
            .unwrap();
        assert_eq!(
            1,
            spendable_inputs.len(),
            "Devnet wallet on genesis block must have one spendable input (since timelock has passed)."
        );

        let third_party_address = GenerationReceivingAddress::derive_from_seed(Default::default());
        let inputs = rpc_server
            .clone()
            .select_spendable_inputs(
                ctx,
                token,
                InputSelectionPolicy::Random,
                NativeCurrencyAmount::coins(19),
            )
            .await
            .unwrap();

        let send_amt = NativeCurrencyAmount::coins(17);
        let outputs = rpc_server
            .clone()
            .generate_tx_outputs(
                ctx,
                token,
                vec![OutputFormat::AddressAndAmount(
                    third_party_address.into(),
                    send_amt,
                )],
            )
            .await
            .unwrap();
        let fee = NativeCurrencyAmount::coins(2);
        let tx_details = rpc_server
            .clone()
            .generate_tx_details(ctx, token, inputs, outputs, ChangePolicy::default(), fee)
            .await
            .unwrap();
        assert_eq!(1, tx_details.tx_inputs.len());
        assert_eq!(
            2,
            tx_details.tx_outputs.len(),
            "Must have recipient and change output"
        );
        assert_eq!(
            NativeCurrencyAmount::coins(18),
            tx_details.tx_outputs.total_native_coins(),
            "Total output must be balance - fee = 20 - 2 = 18 coins."
        );

        let tx_proof = rpc_server
            .clone()
            .generate_witness_proof(ctx, token, tx_details.clone())
            .await
            .unwrap();
        let tx = rpc_server
            .clone()
            .assemble_transaction(ctx, token, tx_details.clone(), tx_proof.clone())
            .await
            .unwrap();

        let consensus_rule_set = rpc_server.state.lock_guard().await.consensus_rule_set();
        assert!(
            tx.is_valid(network, consensus_rule_set).await,
            "Constructed tx must be valid"
        );

        assert_eq!(1, tx.kernel.inputs.len());
        assert_eq!(2, tx.kernel.outputs.len());
        assert_eq!(fee, tx.kernel.fee);

        let tx_artifacts = rpc_server
            .clone()
            .assemble_transaction_artifacts(ctx, token, tx_details.clone(), tx_proof.clone())
            .await
            .unwrap();
        let output_amount = tx_artifacts.details.tx_outputs.total_native_coins();
        assert_eq!(
            NativeCurrencyAmount::coins(18),
            output_amount,
            "Total output must be balance - fee = 20 - 2 = 18 coins. Got: {output_amount}"
        );

        // Broadcast transaction and verify insertion into mempool
        assert_eq!(0, rpc_server.state.lock_guard().await.mempool.len());
        rpc_server
            .clone()
            .record_and_broadcast_transaction(ctx, token, tx_artifacts)
            .await
            .unwrap();
        assert_eq!(1, rpc_server.state.lock_guard().await.mempool.len());
        assert!(rpc_server
            .state
            .lock_guard()
            .await
            .mempool
            .contains(tx.txid()));

        // Ensure `proof_type` endpoint finds the transaction in the mempool
        rpc_server.proof_type(ctx, token, tx.txid()).await.unwrap();
    }

    #[expect(clippy::shadow_unrelated)]
    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn clear_ip_standing_test() -> Result<()> {
        let mut rpc_server = test_rpc_server(
            WalletEntropy::new_random(),
            2,
            cli_args::Args::default_with_network(Network::Main),
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

    #[expect(clippy::shadow_unrelated)]
    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn clear_all_standings_test() -> Result<()> {
        // Create initial conditions
        let mut rpc_server = test_rpc_server(
            WalletEntropy::new_random(),
            2,
            cli_args::Args::default_with_network(Network::Main),
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
    #[apply(shared_tokio_runtime)]
    async fn utxo_digest_test() {
        let rpc_server = test_rpc_server(
            WalletEntropy::new_random(),
            2,
            cli_args::Args::default_with_network(Network::Main),
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
    #[test_strategy::proptest(async = "tokio", cases = 5)]
    async fn utxo_origin_block_test(
        #[strategy(txkernel::with_lengths(0usize, 1usize, 0usize, false))]
        transaction_kernel: crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel,
    ) {
        prop_assume!(!transaction_kernel.fee.is_negative());

        let network = Network::Main;
        let mut rpc_server = test_rpc_server(
            WalletEntropy::new_random(),
            2,
            cli_args::Args::default_with_network(network),
        )
        .await;
        let transaction = Transaction {
            kernel: transaction_kernel,
            proof: TransactionProof::invalid(),
        };
        let block = invalid_block_with_transaction(&Block::genesis(network), transaction);
        rpc_server.state.set_new_tip(block.clone()).await.unwrap();

        let token = cookie_token(&rpc_server).await;
        let output = block.body().transaction_kernel().outputs[0];
        let origin_block = rpc_server
            .utxo_origin_block(context::current(), token, output, None)
            .await
            .unwrap();

        assert!(
            origin_block.is_some(),
            "Expected origin block for included UTXO"
        );
        assert_eq!(
            origin_block.unwrap(),
            block.hash(),
            "UTXOs inclusion digest should match the origin block"
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn block_kernel_test() {
        let network = Network::Main;
        let rpc_server = test_rpc_server(
            WalletEntropy::new_random(),
            2,
            cli_args::Args::default_with_network(network),
        )
        .await;
        let token = cookie_token(&rpc_server).await;
        let ctx = context::current();

        assert!(
            rpc_server
                .clone()
                .block_kernel(ctx, token, BlockSelector::Digest(Digest::default()))
                .await
                .unwrap()
                .is_none(),
            "Must return none on bad digest"
        );
        assert_eq!(
            Block::genesis(network).kernel.mast_hash(),
            rpc_server
                .block_kernel(
                    ctx,
                    token,
                    BlockSelector::Special(BlockSelectorLiteral::Genesis)
                )
                .await
                .expect("RPC call must pass")
                .expect("Must find genesis block")
                .mast_hash(),
            "Must know genesis block and must match genesis hash"
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn block_info_test() {
        let network = Network::RegTest;
        let rpc_server = test_rpc_server(
            WalletEntropy::new_random(),
            2,
            cli_args::Args::default_with_network(network),
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

        assert!(
            genesis_block_info.num_announcements.is_zero(),
            "Genesis block contains no announcements. Block info must reflect that."
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
                .block_info(
                    ctx,
                    token,
                    BlockSelector::Special(BlockSelectorLiteral::Genesis)
                )
                .await
                .unwrap()
                .unwrap()
        );

        // should find latest/tip block by Tip selector
        assert_eq!(
            tip_block_info,
            rpc_server
                .clone()
                .block_info(
                    ctx,
                    token,
                    BlockSelector::Special(BlockSelectorLiteral::Tip)
                )
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
    #[test_strategy::proptest(async = "tokio", cases = 5)]
    async fn announcements_in_block_test(
        #[strategy(txkernel::with_lengths(0usize, 2usize, NUM_ANNOUNCEMENTS_BLOCK1, false))]
        tx_block1: crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel,
    ) {
        let network = Network::Main;
        let mut rpc_server = test_rpc_server(
            WalletEntropy::new_random(),
            2,
            cli_args::Args::default_with_network(network),
        )
        .await;
        let tx_block1 = Transaction {
            kernel: tx_block1,
            proof: TransactionProof::invalid(),
        };
        let fee = tx_block1.kernel.fee;
        let block1 = invalid_block_with_transaction(&Block::genesis(network), tx_block1);
        let set_new_tip_result = rpc_server.state.set_new_tip(block1.clone()).await;
        assert!(fee.is_negative() == set_new_tip_result.is_err());

        let token = cookie_token(&rpc_server).await;
        let ctx = context::current();

        let Some(block1_announcements) = rpc_server
            .clone()
            .announcements_in_block(ctx, token, BlockSelector::Height(1u64.into()))
            .await
            .unwrap()
        else {
            // If the fee was negative, the block was invalid and not stored.
            // So the RPC should return None.
            assert!(fee.is_negative());

            // And in this case we cannot proceed with the test.
            return Ok(());
        };

        assert_eq!(
            block1.body().transaction_kernel.announcements,
            block1_announcements,
            "Must return expected announcements"
        );
        assert_eq!(
            NUM_ANNOUNCEMENTS_BLOCK1,
            block1_announcements.len(),
            "Must return expected number of announcements"
        );

        let genesis_block_announcements = rpc_server
            .clone()
            .announcements_in_block(ctx, token, BlockSelector::Height(0u64.into()))
            .await
            .unwrap()
            .unwrap();
        assert!(
            genesis_block_announcements.is_empty(),
            "Genesis block has no announements"
        );

        assert!(
            rpc_server
                .announcements_in_block(ctx, token, BlockSelector::Height(2u64.into()))
                .await
                .unwrap()
                .is_none(),
            "announcements in unknown block must return None"
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn block_digest_test() {
        let network = Network::RegTest;
        let rpc_server = test_rpc_server(
            WalletEntropy::new_random(),
            2,
            cli_args::Args::default_with_network(network),
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
                .block_digest(
                    ctx,
                    token,
                    BlockSelector::Special(BlockSelectorLiteral::Genesis)
                )
                .await
                .unwrap()
                .unwrap()
        );

        // should find latest/tip block by Tip selector
        assert_eq!(
            global_state.chain.light_state().hash(),
            rpc_server
                .clone()
                .block_digest(
                    ctx,
                    token,
                    BlockSelector::Special(BlockSelectorLiteral::Tip)
                )
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
    #[apply(shared_tokio_runtime)]
    async fn getting_temperature_doesnt_crash_test() {
        // On your local machine, this should return a temperature but in CI,
        // the RPC call returns `None`, so we only verify that the call doesn't
        // crash the host machine, we don't verify that any value is returned.
        let rpc_server = test_rpc_server(
            WalletEntropy::new_random(),
            2,
            cli_args::Args::default_with_network(Network::Main),
        )
        .await;
        let token = cookie_token(&rpc_server).await;
        let _current_server_temperature = rpc_server
            .cpu_temp(context::current(), token)
            .await
            .unwrap();
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn cannot_initiate_transaction_if_notx_flag_is_set() {
        let network = Network::Main;
        let ctx = context::current();
        let mut rng = rand::rng();
        let address = GenerationSpendingKey::derive_from_seed(rng.random()).to_address();
        let amount = NativeCurrencyAmount::coins(rng.random_range(0..10));

        // set flag on, verify non-initiation
        let cli_on = cli_args::Args {
            no_transaction_initiation: true,
            network,
            ..Default::default()
        };

        let rpc_server = test_rpc_server(WalletEntropy::new_random(), 2, cli_on).await;
        let token = cookie_token(&rpc_server).await;

        let output: OutputFormat = (address.into(), amount).into();
        assert!(rpc_server
            .clone()
            .send(
                ctx,
                token,
                vec![output],
                ChangePolicy::ExactChange,
                NativeCurrencyAmount::zero()
            )
            .await
            .is_err());
    }

    #[apply(shared_tokio_runtime)]
    async fn coinbase_distribution_happy_path() {
        let network = Network::Main;
        let ctx = context::current();
        let mut rng = rand::rng();
        let address0 = GenerationSpendingKey::derive_from_seed(rng.random()).to_address();
        let output0 = CoinbaseOutputReadable::new(205, address0.to_bech32m(network).unwrap(), true);

        let address1 = GenerationSpendingKey::derive_from_seed(rng.random()).to_address();
        let output1 = CoinbaseOutputReadable::new(300, address1.to_bech32m(network).unwrap(), true);

        let address2 = GenerationSpendingKey::derive_from_seed(rng.random()).to_address();
        let output2 =
            CoinbaseOutputReadable::new(495, address2.to_bech32m(network).unwrap(), false);

        let cli = cli_args::Args {
            network,
            compose: true,
            ..Default::default()
        };
        let rpc_server = test_rpc_server(WalletEntropy::new_random(), 2, cli).await;
        let token = cookie_token(&rpc_server).await;
        assert!(rpc_server
            .state
            .lock_guard()
            .await
            .mining_state
            .overridden_coinbase_distribution()
            .is_none());
        assert!(rpc_server
            .clone()
            .set_coinbase_distribution(ctx, token, vec![output0, output1, output2])
            .await
            .is_ok());
        assert!(rpc_server
            .state
            .lock_guard()
            .await
            .mining_state
            .overridden_coinbase_distribution()
            .is_some());
        assert!(rpc_server
            .clone()
            .unset_coinbase_distribution(ctx, token)
            .await
            .is_ok());
        assert!(rpc_server
            .state
            .lock_guard()
            .await
            .mining_state
            .overridden_coinbase_distribution()
            .is_none());
    }

    #[apply(shared_tokio_runtime)]
    async fn restore_membership_proof_privacy_preserving_devnet_wallet() {
        let network = Network::Main;
        let ctx = context::current();
        let rpc_server =
            test_rpc_server(WalletEntropy::devnet_wallet(), 2, cli_args::Args::default()).await;
        let token = cookie_token(&rpc_server).await;

        let utxo = rpc_server
            .state
            .lock_guard()
            .await
            .wallet_spendable_inputs(Timestamp::now())
            .await
            .into_iter()
            .collect_vec()[0]
            .clone();
        let msmp = utxo.mutator_set_mp().clone();

        let resp = rpc_server
            .clone()
            .restore_membership_proof_privacy_preserving(
                ctx,
                token,
                vec![msmp.compute_indices(Tip5::hash(&utxo.utxo))],
            )
            .await
            .unwrap();

        let genesis_block = Block::genesis(network);
        assert_eq!(BlockHeight::genesis(), resp.tip_height);
        assert_eq!(genesis_block.hash(), resp.tip_hash);
        assert_eq!(
            genesis_block.mutator_set_accumulator_after().unwrap(),
            resp.tip_mutator_set
        );
        assert_eq!(1, resp.membership_proofs.len());
        let restored_msmp_resp = resp.membership_proofs[0].clone();
        assert_eq!(
            msmp,
            restored_msmp_resp
                .extract_ms_membership_proof(
                    msmp.aocl_leaf_index,
                    msmp.sender_randomness,
                    msmp.receiver_preimage
                )
                .unwrap()
        );

        // Ensure no crash on future AOCL items
        assert!(rpc_server
            .restore_membership_proof_privacy_preserving(
                ctx,
                token,
                vec![AbsoluteIndexSet::compute(
                    Digest::default(),
                    Digest::default(),
                    Digest::default(),
                    u64::from(u32::MAX)
                )],
            )
            .await
            .is_err());
    }

    mod pow_puzzle_tests {
        use rand::random;

        use super::*;
        use crate::protocol::consensus::block::block_header::BlockPow;
        use crate::protocol::consensus::block::pow::Pow;
        use crate::protocol::consensus::block::BlockProof;
        use crate::protocol::consensus::transaction::validity::neptune_proof::NeptuneProof;
        use crate::state::mining::block_proposal::BlockProposal;
        use crate::state::wallet::address::generation_address::GenerationReceivingAddress;
        use crate::state::wallet::address::KeyType;
        use crate::tests::shared::blocks::fake_valid_deterministic_successor;
        use crate::tests::shared::blocks::invalid_empty_block;

        #[test]
        fn pow_puzzle_is_consistent_with_block_hash() {
            let network = Network::Main;
            let genesis = Block::genesis(network);
            let mut block1 = invalid_empty_block(&genesis, network);
            let mut rng = StdRng::seed_from_u64(3409875378456);
            let guesser_address = GenerationReceivingAddress::derive_from_seed(rng.random());
            block1.set_header_guesser_address(guesser_address.into());

            let guess_challenge = ProofOfWorkPuzzle::new(block1.clone(), *genesis.header());
            assert_eq!(guess_challenge.prev_block, genesis.hash());

            let pow: BlockPow = random();
            block1.set_header_pow(pow);

            let resulting_block_hash = block1.pow_mast_paths().fast_mast_hash(pow);

            assert_eq!(block1.hash(), resulting_block_hash);
        }

        #[apply(shared_tokio_runtime)]
        async fn provide_solution_when_no_proposal_known() {
            let network = Network::Main;
            let bob = test_rpc_server(
                WalletEntropy::new_random(),
                2,
                cli_args::Args::default_with_network(network),
            )
            .await;
            let bob_token = cookie_token(&bob).await;
            assert!(
                matches!(
                    bob.state.lock_guard().await.mining_state.block_proposal,
                    BlockProposal::None
                ),
                "Test assumption: no block proposal known"
            );
            let accepted = bob
                .clone()
                .provide_pow_solution(context::current(), bob_token, random(), random())
                .await
                .unwrap();
            assert!(
                !accepted,
                "Must reject PoW solution when no proposal exists"
            );
        }

        #[apply(shared_tokio_runtime)]
        async fn full_pow_puzzle_test() {
            let network = Network::Main;
            let bob = WalletEntropy::new_random();
            let mut bob = test_rpc_server(
                bob.clone(),
                2,
                cli_args::Args::default_with_network(network),
            )
            .await;

            let genesis = Block::genesis(network);
            let block1 = fake_valid_deterministic_successor(&genesis, network).await;
            bob.state
                .lock_mut(|x| {
                    x.mining_state.block_proposal =
                        BlockProposal::ForeignComposition(block1.clone())
                })
                .await;
            let guesser_address = bob
                .state
                .lock_guard_mut()
                .await
                .wallet_state
                .next_unused_spending_key(KeyType::Generation)
                .await
                .to_address();
            let bob_token = cookie_token(&bob).await;

            let (proposal, puzzle) = bob
                .clone()
                .full_pow_puzzle_external_key(context::current(), bob_token, guesser_address)
                .await
                .unwrap()
                .unwrap();

            assert!(
                !bob.clone()
                    .provide_new_tip(
                        context::current(),
                        bob_token,
                        Default::default(),
                        proposal.clone()
                    )
                    .await
                    .unwrap(),
                "Node must reject new tip with invalid PoW solution."
            );

            let solution = puzzle.solve();
            assert!(
                bob.clone()
                    .provide_new_tip(context::current(), bob_token, solution, proposal.clone())
                    .await
                    .unwrap(),
                "Node must accept valid new tip."
            );

            let mut bad_proposal = proposal;
            bad_proposal.set_proof(BlockProof::SingleProof(NeptuneProof::invalid()));
            assert!(
                !bob.clone()
                    .provide_new_tip(
                        context::current(),
                        bob_token,
                        Default::default(),
                        bad_proposal
                    )
                    .await
                    .unwrap(),
                "Node must reject new tip with invalid proof."
            );
        }

        #[apply(shared_tokio_runtime)]
        async fn cached_exported_proposals_are_stored_correctly() {
            let network = Network::Main;
            let bob = WalletEntropy::new_random();
            let mut bob = test_rpc_server(
                bob.clone(),
                2,
                cli_args::Args::default_with_network(network),
            )
            .await;

            let genesis = Block::genesis(network);
            let block1 = invalid_empty_block(&genesis, network);
            bob.state
                .lock_mut(|x| {
                    x.mining_state.block_proposal =
                        BlockProposal::ForeignComposition(block1.clone())
                })
                .await;
            let bob_token = cookie_token(&bob).await;

            let num_exported_block_proposals = 6;

            let mut addresses = vec![];
            for _ in 0..num_exported_block_proposals {
                let address = bob
                    .state
                    .lock_guard_mut()
                    .await
                    .wallet_state
                    .next_unused_spending_key(KeyType::Generation)
                    .await
                    .to_address();
                addresses.push(address);
            }

            let mut pow_puzzle_ids = vec![];
            for guesser_address in addresses.clone() {
                let pow_puzzle = bob
                    .clone()
                    .pow_puzzle_external_key(context::current(), bob_token, guesser_address)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(!pow_puzzle_ids.contains(&pow_puzzle.id));
                pow_puzzle_ids.push(pow_puzzle.id);
            }

            assert_eq!(
                num_exported_block_proposals,
                bob.state
                    .lock_guard()
                    .await
                    .mining_state
                    .exported_block_proposals
                    .len()
            );

            // Verify that the same exported puzzle is not added twice.
            for guesser_address in addresses {
                bob.clone()
                    .pow_puzzle_external_key(context::current(), bob_token, guesser_address)
                    .await
                    .unwrap()
                    .unwrap();
            }
            assert_eq!(
                num_exported_block_proposals,
                bob.state
                    .lock_guard()
                    .await
                    .mining_state
                    .exported_block_proposals
                    .len()
            );
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn exported_pow_puzzle_is_consistent_with_block_hash() {
            let network = Network::Main;
            let bob = WalletEntropy::new_random();
            let mut bob = test_rpc_server(
                bob.clone(),
                2,
                cli_args::Args::default_with_network(network),
            )
            .await;
            let bob_token = cookie_token(&bob).await;

            let genesis = Block::genesis(network);
            let mut block1 = invalid_empty_block(&genesis, network);
            bob.state
                .lock_mut(|x| {
                    x.mining_state.block_proposal =
                        BlockProposal::ForeignComposition(block1.clone())
                })
                .await;

            let entropy_for_external_key = WalletEntropy::new_random();
            let external_guesser_key = entropy_for_external_key.guesser_fee_key();
            let external_guesser_address = external_guesser_key.to_address();
            let internal_guesser_address = bob
                .state
                .lock(|x| x.wallet_state.wallet_entropy.guesser_fee_key())
                .await
                .to_address();

            for use_internal_key in [true, false] {
                println!("use_internal_key: {use_internal_key}");
                let pow_puzzle = if use_internal_key {
                    bob.clone()
                        .pow_puzzle_internal_key(context::current(), bob_token)
                        .await
                        .unwrap()
                        .unwrap()
                } else {
                    bob.clone()
                        .pow_puzzle_external_key(
                            context::current(),
                            bob_token,
                            external_guesser_address.into(),
                        )
                        .await
                        .unwrap()
                        .unwrap()
                };

                let guesser_address = if use_internal_key {
                    internal_guesser_address
                } else {
                    external_guesser_address
                };

                assert!(
                    bob.state
                        .lock_guard()
                        .await
                        .mining_state
                        .exported_block_proposals
                        .contains_key(&pow_puzzle.id),
                    "Must have stored exported block proposal"
                );

                let pow: BlockPow = random();
                let resulting_block_hash = pow_puzzle.auth_paths.fast_mast_hash(pow);

                block1.set_header_pow(pow);
                block1.set_header_guesser_address(guesser_address.into());
                assert_eq!(block1.hash(), resulting_block_hash);
                assert_eq!(
                    block1.body().total_guesser_reward().unwrap(),
                    pow_puzzle.total_guesser_reward
                );

                // Check that succesful guess is accepted by endpoint.
                let guesser_buffer = block1.guess_preprocess(None, None);
                let target = genesis.header().difficulty.target();
                let valid_pow = loop {
                    if let Some(valid_pow) = Pow::guess(&guesser_buffer, random(), target) {
                        break valid_pow;
                    }
                };

                block1.set_header_pow(valid_pow);
                let good_is_accepted = bob
                    .clone()
                    .provide_pow_solution(context::current(), bob_token, valid_pow, pow_puzzle.id)
                    .await
                    .unwrap();
                assert!(
                    good_is_accepted,
                    "Actual PoW-puzzle solution must be accepted by RPC endpoint."
                );

                // Check that bad guess is rejected by endpoint.
                let bad_pow: BlockPow = random();
                let bad_is_accepted = bob
                    .clone()
                    .provide_pow_solution(context::current(), bob_token, bad_pow, pow_puzzle.id)
                    .await
                    .unwrap();
                assert!(
                    !bad_is_accepted,
                    "Bad PoW solution must be rejected by RPC endpoint."
                );
            }
        }
    }

    mod claim_utxo_tests {
        use super::*;

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn claim_utxo_owned_before_confirmed() -> Result<()> {
            worker::claim_utxo_owned(false, false).await
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn claim_utxo_owned_after_confirmed() -> Result<()> {
            worker::claim_utxo_owned(true, false).await
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn claim_utxo_owned_after_confirmed_and_after_spent() -> Result<()> {
            worker::claim_utxo_owned(true, true).await
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn claim_utxo_unowned_before_confirmed() -> Result<()> {
            worker::claim_utxo_unowned(false).await
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn claim_utxo_unowned_after_confirmed() -> Result<()> {
            worker::claim_utxo_unowned(true).await
        }

        mod worker {
            use cli_args::Args;

            use super::*;
            use crate::state::transaction::tx_proving_capability::TxProvingCapability;
            use crate::tests::shared::blocks::invalid_block_with_transaction;
            use crate::tests::shared::blocks::invalid_empty_block;

            pub(super) async fn claim_utxo_unowned(claim_after_confirmed: bool) -> Result<()> {
                let network = Network::Main;

                // bob's node
                let (pay_to_bob_outputs, bob_rpc_server, bob_token) = {
                    let rpc_server = test_rpc_server(
                        WalletEntropy::new_random(),
                        2,
                        Args::default_with_network(network),
                    )
                    .await;
                    let token = cookie_token(&rpc_server).await;

                    let receiving_address_generation = rpc_server
                        .clone()
                        .next_receiving_address(context::current(), token, KeyType::Generation)
                        .await?;
                    let receiving_address_symmetric = rpc_server
                        .clone()
                        .next_receiving_address(context::current(), token, KeyType::Symmetric)
                        .await?;

                    let pay_to_bob_outputs: Vec<OutputFormat> = [
                        (
                            receiving_address_generation,
                            NativeCurrencyAmount::coins(1),
                            UtxoNotificationMedium::OffChain,
                        ),
                        (
                            receiving_address_symmetric,
                            NativeCurrencyAmount::coins(2),
                            UtxoNotificationMedium::OffChain,
                        ),
                    ]
                    .into_iter()
                    .map(|o| o.into())
                    .collect();

                    (pay_to_bob_outputs, rpc_server, token)
                };

                // alice's node
                let (blocks, alice_to_bob_utxo_notifications, bob_amount) = {
                    let wallet_entropy = WalletEntropy::new_random();
                    let cli_args = cli_args::Args {
                        tx_proving_capability: Some(TxProvingCapability::ProofCollection),
                        network,
                        ..Default::default()
                    };
                    let mut rpc_server = test_rpc_server(wallet_entropy.clone(), 2, cli_args).await;
                    let token = cookie_token(&rpc_server).await;

                    let genesis_block = Block::genesis(network);
                    let mut blocks = vec![];

                    let fee = NativeCurrencyAmount::zero();
                    let bob_amount: NativeCurrencyAmount = pay_to_bob_outputs
                        .iter()
                        .map(|o| o.native_currency_amount())
                        .sum();

                    // Mine block 1 to get some coins

                    let cb_key = wallet_entropy.nth_generation_spending_key(0);
                    let (block1, composer_expected_utxos) =
                        make_mock_block(&genesis_block, None, cb_key, Default::default(), network)
                            .await;
                    blocks.push(block1.clone());

                    rpc_server
                        .state
                        .set_new_self_composed_tip(block1.clone(), composer_expected_utxos)
                        .await
                        .unwrap();

                    let tx_artifacts = rpc_server
                        .clone()
                        .send(
                            context::current(),
                            token,
                            pay_to_bob_outputs,
                            ChangePolicy::recover_to_next_unused_key(
                                KeyType::Symmetric,
                                UtxoNotificationMedium::OffChain,
                            ),
                            fee,
                        )
                        .await
                        .unwrap();

                    let block2 = invalid_block_with_transaction(
                        &block1,
                        tx_artifacts.transaction.clone().into(),
                    );
                    let block3 = invalid_empty_block(&block2, network);

                    // mine two blocks, the first will include the transaction
                    blocks.push(block2);
                    blocks.push(block3);

                    // note: change-policy uses off-chain, so alice will have an
                    // off-chain notificatin also.  So it is important to use
                    // unowned_offchain_notifications() when retrieving those
                    // intended for bob.

                    (
                        blocks,
                        tx_artifacts.unowned_offchain_notifications(),
                        bob_amount,
                    )
                };

                // bob's node claims each utxo
                {
                    let mut state = bob_rpc_server.state.clone();

                    state.set_new_tip(blocks[0].clone()).await?;

                    if claim_after_confirmed {
                        state.set_new_tip(blocks[1].clone()).await?;
                        state.set_new_tip(blocks[2].clone()).await?;
                    }

                    for utxo_notification in alice_to_bob_utxo_notifications {
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
                let bob_wallet = WalletEntropy::new_random();
                let cli_args = cli_args::Args {
                    tx_proving_capability: Some(TxProvingCapability::ProofCollection),
                    network,
                    ..Default::default()
                };
                let mut bob = test_rpc_server(bob_wallet.clone(), 2, cli_args).await;
                let bob_token = cookie_token(&bob).await;

                let bob_key = bob_wallet.nth_generation_spending_key(0);
                let genesis_block = Block::genesis(network);
                let (block1, composer_expected_utxos) =
                    make_mock_block(&genesis_block, None, bob_key, Default::default(), network)
                        .await;

                bob.state
                    .set_new_self_composed_tip(block1.clone(), composer_expected_utxos)
                    .await
                    .unwrap();

                let bob_gen_addr = bob
                    .clone()
                    .next_receiving_address(context::current(), bob_token, KeyType::Generation)
                    .await?;
                let bob_sym_addr = bob
                    .clone()
                    .next_receiving_address(context::current(), bob_token, KeyType::Symmetric)
                    .await?;

                let pay_to_self_outputs: Vec<OutputFormat> = [
                    (
                        bob_gen_addr,
                        NativeCurrencyAmount::coins(5),
                        UtxoNotificationMedium::OffChain,
                    ),
                    (
                        bob_sym_addr,
                        NativeCurrencyAmount::coins(6),
                        UtxoNotificationMedium::OffChain,
                    ),
                ]
                .into_iter()
                .map(|o| o.into())
                .collect();

                let fee = NativeCurrencyAmount::coins(2);
                let tx_artifacts = bob
                    .clone()
                    .send(
                        context::current(),
                        bob_token,
                        pay_to_self_outputs.clone(),
                        ChangePolicy::recover_to_next_unused_key(
                            KeyType::Symmetric,
                            UtxoNotificationMedium::OffChain,
                        ),
                        fee,
                    )
                    .await
                    .unwrap();

                // alice mines 2 more blocks.  block2 confirms the sent tx.
                let block2 = invalid_block_with_transaction(
                    &block1,
                    tx_artifacts.transaction.clone().into(),
                );
                let block3 = invalid_empty_block(&block2, network);

                if claim_after_mined {
                    // bob applies the blocks before claiming utxos.
                    bob.state.set_new_tip(block2.clone()).await?;
                    bob.state.set_new_tip(block3.clone()).await?;

                    if spent {
                        // Send entire liquid balance somewhere else
                        let another_address = WalletEntropy::new_random()
                            .nth_generation_spending_key(0)
                            .to_address();
                        let output: OutputFormat = (
                            another_address.into(),
                            NativeCurrencyAmount::coins(62),
                            UtxoNotificationMedium::OffChain,
                        )
                            .into();
                        let spending_tx_artifacts = bob
                            .clone()
                            .send(
                                context::current(),
                                bob_token,
                                vec![output],
                                ChangePolicy::exact_change(),
                                NativeCurrencyAmount::zero(),
                            )
                            .await
                            .unwrap();
                        let block4 = invalid_block_with_transaction(
                            &block3,
                            spending_tx_artifacts.transaction.clone().into(),
                        );
                        bob.state.set_new_tip(block4.clone()).await?;
                    }
                }

                for offchain_notification in tx_artifacts.owned_offchain_notifications() {
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
        use crate::api::export::TxProvingCapability;
        use crate::application::rpc::server::error::RpcError;
        use crate::tests::shared::blocks::mine_block_to_wallet_invalid_block_proof;

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn send_to_many_n_outputs() {
            let mut rng = StdRng::seed_from_u64(1815);
            let network = Network::Main;
            let cli_args = cli_args::Args {
                tx_proving_capability: Some(TxProvingCapability::ProofCollection),
                network,
                ..Default::default()
            };
            let rpc_server =
                test_rpc_server(WalletEntropy::new_pseudorandom(rng.random()), 2, cli_args).await;
            let token = cookie_token(&rpc_server).await;

            let ctx = context::current();
            // let timestamp = network.launch_date() + Timestamp::days(1);
            let own_address = rpc_server
                .clone()
                .next_receiving_address(ctx, token, KeyType::Generation)
                .await
                .unwrap();
            let elem: OutputFormat = (
                own_address.clone(),
                NativeCurrencyAmount::zero(),
                UtxoNotificationMedium::OffChain,
            )
                .into();
            let outputs = std::iter::repeat(elem);
            let fee = NativeCurrencyAmount::zero();

            // note: we can only perform 2 iters, else we bump into send rate-limit (per block)
            for i in 5..7 {
                let result = rpc_server
                    .clone()
                    .send(
                        ctx,
                        token,
                        outputs.clone().take(i).collect(),
                        ChangePolicy::ExactChange,
                        fee,
                    )
                    .await;
                assert!(result.is_ok());
            }
        }

        /// sends a tx with two outputs: one self, one external, for each key type
        /// that accepts incoming UTXOs.
        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn send_to_many_test() -> Result<()> {
            for recipient_key_type in KeyType::all_types() {
                worker::send_to_many(recipient_key_type).await?;
            }
            Ok(())
        }

        /// checks that the sending rate limit kicks in after 2 tx are sent.
        /// note: rate-limit only applies below block 25000
        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn send_rate_limit() -> Result<()> {
            let mut rng = StdRng::seed_from_u64(1815);
            let network = Network::Main;
            let cli_args = cli_args::Args {
                tx_proving_capability: Some(TxProvingCapability::SingleProof),
                network,
                ..Default::default()
            };
            let mut rpc_server = test_rpc_server(WalletEntropy::devnet_wallet(), 2, cli_args).await;

            let ctx = context::current();
            let token = cookie_token(&rpc_server).await;
            let timestamp = network.launch_date() + Timestamp::months(7);

            // obtain some funds, so we have two inputs available.
            mine_block_to_wallet_invalid_block_proof(&mut rpc_server.state, Some(timestamp))
                .await?;

            let address: ReceivingAddress = GenerationSpendingKey::derive_from_seed(rng.random())
                .to_address()
                .into();
            let amount = NativeCurrencyAmount::coins(rng.random_range(0..2));
            let fee = NativeCurrencyAmount::coins(1);

            let output: OutputFormat = (address, amount, UtxoNotificationMedium::OnChain).into();
            let outputs = vec![output];

            for i in 0..10 {
                let result = rpc_server
                    .clone()
                    .send(ctx, token, outputs.clone(), ChangePolicy::Burn, fee)
                    .await;

                // any attempts after the 2nd send should result in RateLimit error.
                match i {
                    0..2 => assert!(result.is_ok()),
                    _ => assert!(matches!(
                        result,
                        Err(RpcError::SendError(s)) if s.contains("Send rate limit reached")
                    )),
                }
            }

            Ok(())
        }

        mod worker {
            use super::*;
            use crate::state::wallet::address::generation_address::GenerationReceivingAddress;
            use crate::state::wallet::address::symmetric_key::SymmetricKey;
            use crate::state::wallet::address::SpendingKey;

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
                let cli_args = cli_args::Args {
                    tx_proving_capability: Some(TxProvingCapability::ProofCollection),
                    network,
                    ..Default::default()
                };
                let mut rpc_server =
                    test_rpc_server(WalletEntropy::new_pseudorandom(rng.random()), 2, cli_args)
                        .await;
                let token = cookie_token(&rpc_server).await;

                // --- Init.  get wallet spending key ---
                let genesis_block = Block::genesis(network);
                let wallet_spending_key = rpc_server
                    .state
                    .lock_guard_mut()
                    .await
                    .wallet_state
                    .next_unused_spending_key(KeyType::Generation)
                    .await;

                let SpendingKey::Generation(key) = wallet_spending_key else {
                    // todo: make_mock_block should accept a SpendingKey.
                    panic!("must be generation key");
                };

                // --- Init.  generate a block, with composer fee going to our
                // wallet ---
                let timestamp = network.launch_date() + Timestamp::days(1);
                let (block_1, composer_utxos) =
                    make_mock_block(&genesis_block, Some(timestamp), key, rng.random(), network)
                        .await;

                {
                    let state_lock = rpc_server.state.lock_guard().await;
                    let wallet_status = state_lock.get_wallet_status_for_tip().await;
                    let original_balance = wallet_status.available_confirmed(timestamp);
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
                    let new_balance = wallet_status.available_confirmed(timestamp);
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
                };
                let output1: OutputFormat = (
                    external_receiving_address.clone(),
                    NativeCurrencyAmount::coins(5),
                    UtxoNotificationMedium::OffChain,
                )
                    .into();

                // --- Setup. generate an output that our wallet can claim. ---
                let output2: OutputFormat = {
                    let spending_key = rpc_server
                        .state
                        .lock_guard_mut()
                        .await
                        .wallet_state
                        .next_unused_spending_key(recipient_key_type)
                        .await;
                    (
                        spending_key.to_address(),
                        NativeCurrencyAmount::coins(25),
                        UtxoNotificationMedium::OffChain,
                    )
                }
                .into();

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
                    .send(
                        context::current(),
                        token,
                        outputs,
                        ChangePolicy::recover_to_next_unused_key(
                            KeyType::Symmetric,
                            UtxoNotificationMedium::OffChain,
                        ),
                        fee,
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
