//! implements an RPC server and client based on [tarpc]
//!
//! Request and response data is JSON-serialized.
//!
//! It is presently easiest to create a `tarpc` client in Rust.
//! To do so, one should add `neptune-cash` as a dependency and
//! then do something like the following.
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
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
pub mod ui_utxo;

use std::collections::HashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use get_size2::GetSize;
use itertools::Itertools;
use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;
use systemstat::Platform;
use systemstat::System;
use tarpc::context;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::twenty_first::prelude::Mmr;
use tasm_lib::twenty_first::tip5::digest::Digest;
use tokio::sync::oneshot;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use super::auth;
use crate::api;
use crate::api::export::AnnouncementFlag;
use crate::api::export::ConsolidationError;
use crate::api::export::NeptuneProof;
use crate::api::tx_initiation;
use crate::api::tx_initiation::builder::tx_input_list_builder::InputSelectionPolicy;
use crate::api::tx_initiation::builder::tx_output_list_builder::OutputFormat;
use crate::application::config::network::Network;
use crate::application::database::storage::storage_vec::traits::StorageVecBase;
use crate::application::loops::channel::RPCServerToMain;
use crate::application::loops::main_loop::proof_upgrader::UpgradeJob;
use crate::application::loops::mine_loop::coinbase_distribution::CoinbaseDistribution;
use crate::application::network::overview::NetworkOverview;
use crate::application::rpc::server::coinbase_output_readable::CoinbaseOutputReadable;
use crate::application::rpc::server::error::RpcError;
use crate::application::rpc::server::mempool_transaction_info::MempoolTransactionInfo;
use crate::application::rpc::server::overview_data::OverviewData;
use crate::application::rpc::server::proof_of_work_puzzle::ProofOfWorkPuzzle;
use crate::application::rpc::server::ui_utxo::UiUtxo;
use crate::application::rpc::server::ui_utxo::UtxoStatusEvent;
use crate::application::util_proof::sent;
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
use crate::state::claim_error::ClaimError;
use crate::protocol::proof_abstractions::SecretWitness;
use crate::state::mining::mining_state::MAX_NUM_EXPORTED_BLOCK_PROPOSAL_STORED;
use crate::state::transaction::transaction_details::TransactionDetails;
use crate::state::transaction::transaction_kernel_id::TransactionKernelId;
use crate::state::transaction::tx_creation_artifacts::TxCreationArtifacts;
use crate::state::wallet::address::KeyType;
use crate::state::wallet::address::ReceivingAddress;
use crate::state::wallet::address::SpendingKey;
use crate::state::wallet::change_policy::ChangePolicy;
use crate::state::wallet::coin_with_possible_timelock::CoinWithPossibleTimeLock;
use crate::state::wallet::transaction_input::TxInputList;
use crate::state::wallet::transaction_output::TxOutputList;
use crate::state::wallet::wallet_status::WalletStatus;
use crate::state::wallet::MAX_DERIVATION_INDEX_BUMP;
use crate::state::GlobalState;
use crate::state::GlobalStateLock;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::archival_mutator_set::ResponseMsMembershipProofPrivacyPreserving;
use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use crate::DataDirectory;

/// result returned by RPC methods
pub type RpcResult<T> = Result<T, error::RpcError>;

/// Tarpc generates enums `RPCRequest` and `RPCResponse` for each method
/// declared in this trait. These enums are public and not marked
/// `#[non_exhaustive]`. As a result, according to strict semantic versioning,
/// adding new variants is a breaking change mandating a new major version.
///
/// We apply a relaxed rule set where adding new RPC endpoints is not considered
/// a breaking change. Consequently, external users should note: if you match on
/// `RPCRequest` or `RPCResponse`, make sure you match statement has a catch-all
/// branch -- otherwise, minor version bumps might break your code.
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

    /// Return the block heights of blocks with announcements matching the
    /// specified flags. Returns the empty list if no blocks with these flags
    /// are known.
    ///
    /// Only works on nodes that maintain a UTXO index.
    ///
    /// # Warning
    ///
    /// Will not return all block if any key in question has matching
    /// [`AnnouncementFlag`]s in more than
    /// [MAX_NUM_BLOCKS_IN_LOOKUP_LIST] blocks.
    ///
    /// [MAX_NUM_BLOCKS_IN_LOOKUP_LIST]: crate::state::archival_state::rusty_utxo_index::MAX_NUM_BLOCKS_IN_LOOKUP_LIST
    async fn block_heights_by_announcement_flags(
        token: auth::Token,
        announcement_flags: Vec<AnnouncementFlag>,
    ) -> RpcResult<Vec<BlockHeight>>;

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

    /// Get the current derivation index for keys of the given type.
    async fn get_derivation_index(token: auth::Token, key_type: KeyType) -> RpcResult<u64>;

    /// Set the current derivation index for keys of the given type.
    async fn set_derivation_index(
        token: auth::Token,
        key_type: KeyType,
        derivation_index: u64,
    ) -> RpcResult<()>;

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

    /// Upper bound on the total amount of coins spendable now, in particular,
    /// without counting time-locked coins, but with accounting for the premine,
    /// the redemptions, and known burns.
    async fn circulating_supply(token: auth::Token) -> RpcResult<NativeCurrencyAmount>;

    /// Asymptotical limit on the total amount of coins, counting all coins
    /// already mined or to be mined in the future, disregarding all time-locks,
    /// counting the premine and redemptions, and accounting for known burns.
    async fn max_supply(token: auth::Token) -> RpcResult<NativeCurrencyAmount>;

    /// Total amount of coins burned.
    async fn burned_supply(token: auth::Token) -> RpcResult<NativeCurrencyAmount>;

    /******** PEER INTERACTIONS ********/

    /// Broadcast transaction notifications for all transactions in this node's
    /// mempool.
    async fn broadcast_all_mempool_txs(token: auth::Token) -> RpcResult<()>;

    /// Broadcast running node's current favorable block proposal.
    async fn broadcast_block_proposal(token: auth::Token) -> RpcResult<()>;

    /******** CHANGE THINGS ********/
    // Place all things that change state here

    /// Clears standing for all peers, connected or not.
    ///
    /// Legacy command, applies at the peer loop logic level. For the modern
    /// equivalent, see [`RPC::unban_all`].
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

    /// Clears standing for ip, whether connected or not.
    ///
    /// Legacy command, applies at the peer loop logic level. For the modern
    /// equivalent, see [`RPC::unban`].
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

    /// Put the given address on the black list and disconnect if there is a
    /// connection to this peer.
    ///
    /// Requires a connection to the server.
    async fn ban(token: auth::Token, ip: Multiaddr) -> RpcResult<()>;

    /// Remove the given address from black list and clear the corresponding
    /// peer standing.
    ///
    /// Requires a connection to the server.
    async fn unban(token: auth::Token, ip: Multiaddr) -> RpcResult<()>;

    /// Remove all entries from the black list and clear all peer standings.
    ///
    /// Requires a connection to the server.
    async fn unban_all(token: auth::Token) -> RpcResult<()>;

    /// Dial (attempt to initiate a connection to) a [`Multiaddr`].
    async fn dial(token: auth::Token, address: Multiaddr) -> RpcResult<()>;

    /// Probe the NAT status of this node.
    async fn probe_nat(token: auth::Token) -> RpcResult<()>;

    /// Reset this node's relay reservations with its relaying peers.
    async fn reset_relay_reservations(token: auth::Token) -> RpcResult<()>;

    /// Get the network overview data and health statistics.
    async fn get_network_overview(token: auth::Token) -> RpcResult<NetworkOverview>;

    /// record transaction and initiate broadcast to peers
    ///
    /// todo: docs.
    ///
    /// meanwhile see [tx_initiation::initiator::TransactionInitiator::record_and_broadcast_transaction()]
    async fn record_and_broadcast_transaction(
        token: auth::Token,
        tx_artifacts: TxCreationArtifacts,
    ) -> RpcResult<()>;

    /// Rescan the specified range of blocks for incoming UTXOS that were sent
    /// with associated on-chain announements.
    ///
    /// Any found UTXOs are monitored going forward.
    async fn rescan_announced(
        token: auth::Token,
        first: BlockHeight,
        last: BlockHeight,
        derivation_path: Option<(KeyType, u64)>,
    ) -> RpcResult<()>;

    /// Rescan the specified range of blocks for incoming UTXOS that have
    /// been added as expected UTXOs to the node's wallet.
    ///
    /// Any found UTXOs are monitored going forward.
    async fn rescan_expected(
        token: auth::Token,
        first: BlockHeight,
        last: BlockHeight,
    ) -> RpcResult<()>;

    /// Rescan the specified range of blocks for outgoing UTXOs, *i.e.*, UTXOs
    /// spent by the node's wallet.
    ///
    /// Can be used to recreate a transaction history. Requires a UTXO index.
    ///
    /// Any found UTXOs are monitored going forward.
    async fn rescan_outgoing(
        token: auth::Token,
        first: BlockHeight,
        last: BlockHeight,
    ) -> RpcResult<()>;

    /// Rescan the specified range for blocks that were successfully guessed by
    /// this node.
    ///
    /// Any found UTXOs are monitored going forward.
    async fn rescan_guesser_rewards(
        token: auth::Token,
        first: BlockHeight,
        last: BlockHeight,
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

    /// Initiate a transaction that spends a batch of UTXOs to the node's own
    /// wallet, reducing the total number of UTXOs under management.
    ///
    /// # Parameters
    ///
    ///  - `num_inputs` -- set to override the default (4) number of inputs to
    ///    be consolidated.
    ///  - `to_address` -- set to consolidate the UTXOs to the given address as
    ///    opposed to the next symmetric address of the node's own wallet.
    async fn consolidate(
        token: auth::Token,
        num_inputs: Option<usize>,
        to_address: Option<ReceivingAddress>,
    ) -> RpcResult<usize>;

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
    /// Return `true` if a new expected UTXO was added, otherwise `false`.
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
    /// // encryted value of utxo transfer
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

    /// Mine a series of blocks to the node's wallet.
    ///
    /// Can be used only if the network uses mock blocks.
    /// (presently only the regtest network)
    ///
    /// These blocks can be generated quickly because they do not have
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

    /// Mark MUTXOs as abandoned. Does not actually delete any elements in the list.
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

    /// Prove a transfer of the native coin from the current wallet. Discloses
    /// - the amount transferred,
    /// - the sender's address,
    /// - the receiver's address,
    /// - hashed sender randomness to distinguish similar transfers,
    /// - the AOCL of the block used for the argument.
    /// Other info is hidden in the proof, such as the exact UTXO that were spent and the exact block height at which the transfer was
    /// confirmed. The native coin is indicated by `tx_ix` & `utxo_ix` inside it; `block` is any which contains the transfer (the verifier must have this block as canonical).
    /// *Probably you will want to pass `block` along a successfull result so that a verifier won't need to search it by the AOCL digest from `Claim`.*
    ///
    /// For verification see `triton_verify` in this API.
    ///
    /// Wraps [`Wallet::prove_transfer()`]. Returns `Auth` or `CreateProofError` variants of [`RpcError`] on a failure.
    ///
    /// # example
    /// ```no_run
    /// # use anyhow::Result;
    /// # use neptune_cash::application::rpc::server::RPCClient;
    /// # use neptune_cash::application::rpc::auth;
    /// # use tarpc::tokio_serde::formats::Json;
    /// # use tarpc::serde_transport::tcp;
    /// # use tarpc::client;
    /// # use tarpc::context;
    /// # use twenty_first::tip5::digest::Digest;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()>{
    /// #
    /// # // create a serde/json transport over tcp.
    /// # let transport = tcp::connect("127.0.0.1:9799", Json::default).await?;
    /// #
    /// # // Create an RPC-client using the transport.
    /// # let client = RPCClient::new(client::Config::default(), transport).spawn();
    /// #
    /// # // defines cookie hint
    /// # let cookie_hint = client.cookie_hint(context::current()).await??;
    /// #
    /// # // load the cookie file from disk and assign it to a token
    /// # let token : auth::Token = auth::Cookie::try_load(&cookie_hint.data_directory).await?.into();
    /// #
    /// // from the current wallet
    /// // the index of the sent tx containing the transfer to prove
    /// let tx_ix: u64 = 0xAAAAAAA;
    /// // the index of the UTXO with that transfer inside this tx
    /// let utxo_ix = 0xAA;
    /// /* The digest of a block after spending (verifiers must check this block as canonical). For better privacy a recent block can be chosen, if the need is to show
    /// when it was already took place --- choose a block by its timestamp accordingly, up to the block which first confirmed the tx (including). */
    /// let block: Digest = Digest::try_from_hex(0xAAAAAAAA)?;
    /// // get the claim and a proof
    /// let (claim, proof) = client.prove_transfer(context::current(), token, tx_ix, utxo_ix, block).await??;
    /// # Ok(())
    /// # }
    /// ```
    async fn prove_transfer(
        token: auth::Token,
        tx_ix: u64,
        utxo_ix: usize,
        block: Digest,
    ) -> RpcResult<(Claim, NeptuneProof)>;

    /// Triton VM `verify`.
    async fn triton_verify(
        token: auth::Token,
        claim: Claim,
        proof: NeptuneProof,
    ) -> RpcResult<bool>;
}

#[derive(Clone)]
pub(crate) struct NeptuneRPCServer {
    pub(crate) state: GlobalStateLock,
    pub(crate) rpc_server_to_main_tx: tokio::sync::mpsc::Sender<RPCServerToMain>,

    // Copy of `DataDirectory` for this `neptune-core` instance.
    data_directory: DataDirectory,

    // List of tokens that are valid.  RPC clients must present a token that
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

    /// Return a PoW puzzle with the provided guesser address.
    async fn pow_puzzle_inner(
        mut self,
        guesser_address: ReceivingAddress,
        mut proposal: Block,
    ) -> RpcResult<Option<ProofOfWorkPuzzle>> {
        let latest_block_header = *self.state.lock_guard().await.chain.light_state().header();

        proposal.set_header_guesser_address(guesser_address);
        let puzzle = ProofOfWorkPuzzle::new(proposal.clone(), latest_block_header.difficulty);

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

        if proposal.has_proof_of_work(self.state.cli().network, &latest_block_header) {
            // No time to waste! Inform main_loop!
            self.rpc_server_to_main_tx
                .send(RPCServerToMain::ProofOfWorkSolution(Box::new(proposal)))
                .await
                .map_err(|e| RpcError::SendError(e.to_string()))?;

            Ok(true)
        } else {
            warn!("Got claimed PoW solution but PoW solution is not valid.");
            Ok(false)
        }
    }

    /// get the data_directory for this neptune-core instance
    pub fn data_directory(&self) -> &DataDirectory {
        &self.data_directory
    }

    async fn get_network_overview_inner(&self) -> RpcResult<NetworkOverview> {
        // Create one-shot channel.
        let (tx, rx) = oneshot::channel();

        // Send one-shot channel to NetworkActor, via main loop.
        self.rpc_server_to_main_tx
            .send(RPCServerToMain::GetNetworkOverview(tx))
            .await
            .map_err(|e| {
                RpcError::SendError(format!("could not send message to main loop: {e}"))
            })?;

        // Await receipt.
        match tokio::time::timeout(Duration::from_secs(2), rx).await {
            Ok(Ok(overview)) => Ok(overview),
            Ok(Err(e)) => Err(RpcError::SendError(format!("NetworkActor dropped: {e}."))),
            Err(e) => Err(RpcError::Failed(format!(
                "RPC Timeout while waiting for NetworkActor response: {e}."
            ))),
        }
    }
}

impl RPC for NeptuneRPCServer {
    // Documented in trait. Do not add doc-comment.
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

    // Documented in trait. Do not add doc-comment.
    async fn network(self, _: context::Context) -> RpcResult<Network> {
        log_slow_scope!(fn_name!());

        Ok(self.state.cli().network)
    }

    // Documented in trait. Do not add doc-comment.
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

    // Documented in trait. Do not add doc-comment.
    async fn own_instance_id(
        self,
        _context: context::Context,
        token: auth::Token,
    ) -> RpcResult<InstanceId> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self.state.lock_guard().await.net.instance_id)
    }

    // Documented in trait. Do not add doc-comment.
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

        let current_counter = state.wallet_state.key_counter(key_type);
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
    async fn block_heights_by_announcement_flags(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
        announcement_flags: Vec<AnnouncementFlag>,
    ) -> RpcResult<Vec<BlockHeight>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        if !self.state.cli().utxo_index {
            return Err(RpcError::UtxoIndexNotPresent);
        }

        let announcement_flags: HashSet<_> = announcement_flags.into_iter().collect();
        let blocks = self
            .state
            .lock_guard()
            .await
            .chain
            .archival_state()
            .utxo_index
            .as_ref()
            .expect("UTXO index must be present when set in CLI arguments")
            .blocks_by_announcement_flags(&announcement_flags)
            .await;

        Ok(blocks.into_iter().collect())
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

    // Documented in trait. Do not add doc-comment.
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

    // Documented in trait. Do not add doc-comment.
    async fn all_punished_peers(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
    ) -> RpcResult<HashMap<IpAddr, PeerStanding>> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let mut sanctions_in_memory = HashMap::default();

        let global_state = self.state.lock_guard().await;

        // get all connected peers
        for peer_info in global_state.net.peer_map.values() {
            if peer_info.standing().is_negative() {
                let maybe_ip = peer_info
                    .address()
                    .iter()
                    .find_map(|component| match component {
                        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
                        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
                        _ => None,
                    });
                if let Some(ip) = maybe_ip {
                    sanctions_in_memory.insert(ip, peer_info.standing());
                }
            }
        }

        let sanctions_in_db = global_state.net.all_peer_sanctions_in_database();

        // combine result for currently connected peers and previously connected peers but
        // use result for currently connected peer if there is an overlap
        let mut all_sanctions = sanctions_in_memory;
        for (ip_addr, sanction) in sanctions_in_db {
            if sanction.is_negative() {
                all_sanctions.entry(ip_addr).or_insert(sanction);
            }
        }

        Ok(all_sanctions)
    }

    // Documented in trait. Do not add doc-comment.
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
    async fn get_derivation_index(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
        key_type: KeyType,
    ) -> RpcResult<u64> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let counter = match key_type {
            KeyType::Generation => self
                .state
                .lock_guard()
                .await
                .wallet_state
                .wallet_db
                .get_generation_key_counter(),
            KeyType::Symmetric => self
                .state
                .lock_guard()
                .await
                .wallet_state
                .wallet_db
                .get_symmetric_key_counter(),
        };

        let derivation_index = counter
            .checked_sub(1)
            .ok_or(RpcError::WalletKeyCounterIsZero)?;

        Ok(derivation_index)
    }

    // documented in trait. do not add doc-comment.
    async fn set_derivation_index(
        mut self,
        _context: tarpc::context::Context,
        token: auth::Token,
        key_type: KeyType,
        derivation_index: u64,
    ) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let wallet_state = &mut self.state.lock_guard_mut().await.wallet_state;
        let current = wallet_state.key_counter(key_type);
        let max = current + MAX_DERIVATION_INDEX_BUMP;

        if current > derivation_index {
            return Err(RpcError::InvalidDerivationIndexRange(current, max));
        }
        if derivation_index > max {
            return Err(RpcError::InvalidDerivationIndexRange(current, max));
        }

        wallet_state
            .bump_derivation_index(key_type, derivation_index)
            .await;

        Ok(())
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

        // Assemble data.
        let now = Timestamp::now();
        let state = self.state.lock_guard().await;
        let tip_digest = {
            log_slow_scope!(fn_name!() + "::hash() tip digest");
            state.chain.light_state().hash()
        };
        let tip_header = *state.chain.light_state().header();
        let syncing = state.net.sync_status;
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

        let peer_count = state.net.peer_map.len();
        let network_overview = self.get_network_overview_inner().await.ok();

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
            sync_status: syncing,
            confirmed_available_balance,
            confirmed_total_balance,
            unconfirmed_available_balance,
            unconfirmed_total_balance,
            peer_count,
            network_overview,
            mempool_size,
            mempool_total_tx_count,
            mempool_own_tx_count,
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
            .for_each(|(_peer_id, peerinfo)| {
                let maybe_ip = peerinfo
                    .address()
                    .iter()
                    .find_map(|component| match component {
                        libp2p::multiaddr::Protocol::Ip4(ipv4_addr) => Some(IpAddr::V4(ipv4_addr)),
                        libp2p::multiaddr::Protocol::Ip6(ipv6_addr) => Some(IpAddr::V6(ipv6_addr)),
                        _ => None,
                    });
                if maybe_ip.is_some_and(|peer_ip| ip == peer_ip) {
                    peerinfo.standing.clear_standing();
                }
            });

        // Also clears this IP's standing in database, whether it is connected or not.
        global_state_mut.net.clear_ip_standing_in_database(ip).await;

        Ok(global_state_mut.flush_databases().await?)
    }

    // Already documented in trait; do not add docstring.
    async fn ban(
        self,
        _: context::Context,
        token: auth::Token,
        address: Multiaddr,
    ) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        self.rpc_server_to_main_tx
            .try_send(RPCServerToMain::Ban(address))
            .map_err(|e| {
                RpcError::SendError(format!("could not send message to main loop: {e}"))
            })?;

        Ok(())
    }

    // Already documented in trait; do not add docstring.
    async fn unban(
        self,
        _: context::Context,
        token: auth::Token,
        address: Multiaddr,
    ) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        self.rpc_server_to_main_tx
            .try_send(RPCServerToMain::Unban(address))
            .map_err(|e| {
                RpcError::SendError(format!("could not send message to main loop: {e}"))
            })?;

        Ok(())
    }

    // Already documented in trait; do not add docstring.
    async fn unban_all(self, _: context::Context, token: auth::Token) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        self.rpc_server_to_main_tx
            .try_send(RPCServerToMain::UnbanAll)
            .map_err(|e| {
                RpcError::SendError(format!("could not send message to main loop: {e}"))
            })?;

        Ok(())
    }

    // Already documented in trait; do not add docstring.
    async fn dial(
        self,
        _: context::Context,
        token: auth::Token,
        address: Multiaddr,
    ) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        self.rpc_server_to_main_tx
            .try_send(RPCServerToMain::Dial(address))
            .map_err(|e| {
                RpcError::SendError(format!("could not send message to main loop: {e}"))
            })?;

        Ok(())
    }

    // Already documented in trait; do not add docstring.
    async fn probe_nat(self, _: context::Context, token: auth::Token) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        self.rpc_server_to_main_tx
            .try_send(RPCServerToMain::ProbeNat)
            .map_err(|e| {
                RpcError::SendError(format!("could not send message to main loop: {e}"))
            })?;

        Ok(())
    }

    // Already documented in trait; do not add docstring.
    async fn reset_relay_reservations(
        self,
        _: context::Context,
        token: auth::Token,
    ) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        self.rpc_server_to_main_tx
            .try_send(RPCServerToMain::ResetRelayReservations)
            .map_err(|e| {
                RpcError::SendError(format!("could not send message to main loop: {e}"))
            })?;

        Ok(())
    }
    // Already documented in trait; do not add docstring.
    async fn get_network_overview(
        self,
        _: context::Context,
        token: auth::Token,
    ) -> RpcResult<NetworkOverview> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        self.get_network_overview_inner().await
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
    async fn rescan_announced(
        self,
        _: context::Context,
        token: auth::Token,
        first: BlockHeight,
        last: BlockHeight,
        derivation_path: Option<(KeyType, u64)>,
    ) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        if first > last {
            return Err(RpcError::BlockRangeError);
        }

        let keys = if let Some((key_type, derivation_index)) = derivation_path {
            vec![self
                .state
                .lock_guard()
                .await
                .wallet_state
                .nth_spending_key(key_type, derivation_index)]
        } else {
            self.state
                .lock_guard()
                .await
                .wallet_state
                .get_all_known_spending_keys()
                .collect_vec()
        };

        let _ = self
            .rpc_server_to_main_tx
            .send(RPCServerToMain::RescanAnnounced { first, last, keys })
            .await;

        Ok(())
    }

    // documented in trait. do not add doc-comment.
    async fn rescan_expected(
        self,
        _: context::Context,
        token: auth::Token,
        first: BlockHeight,
        last: BlockHeight,
    ) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        if first > last {
            return Err(RpcError::BlockRangeError);
        }

        let _ = self
            .rpc_server_to_main_tx
            .send(RPCServerToMain::RescanExpected { first, last })
            .await;

        Ok(())
    }

    // documented in trait. do not add doc-comment.
    async fn rescan_outgoing(
        self,
        _: context::Context,
        token: auth::Token,
        first: BlockHeight,
        last: BlockHeight,
    ) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        if first > last {
            return Err(RpcError::BlockRangeError);
        }

        if !self.state.cli().utxo_index {
            return Err(RpcError::UtxoIndexNotPresent);
        }

        let _ = self
            .rpc_server_to_main_tx
            .send(RPCServerToMain::RescanOutgoing { first, last })
            .await;

        Ok(())
    }

    // documented in trait. do not add doc-comment.
    async fn rescan_guesser_rewards(
        self,
        _: context::Context,
        token: auth::Token,
        first: BlockHeight,
        last: BlockHeight,
    ) -> RpcResult<()> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        if first > last {
            return Err(RpcError::BlockRangeError);
        }

        let _ = self
            .rpc_server_to_main_tx
            .send(RPCServerToMain::RescanGuesserRewards { first, last })
            .await;

        Ok(())
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

    // Documented in trait. Do not add doc-comment.
    async fn consolidate(
        mut self,
        _ctx: context::Context,
        token: auth::Token,
        num_inputs: Option<usize>,
        to_address: Option<ReceivingAddress>,
    ) -> RpcResult<usize> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self
            .state
            .api_mut()
            .tx_initiator_mut()
            .consolidate(num_inputs, to_address, Timestamp::now())
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
            .state
            .lock_guard()
            .await
            .claim_utxo(encrypted_utxo_notification, max_search_depth)
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
            .map_err(ClaimError::from)?;

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

        Ok(self
            .state
            .lock_guard()
            .await
            .coins_with_possible_timelocks()
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
            let received = UtxoStatusEvent::Confirmed {
                block_height: monitored_utxo.confirmed_in_block.2,
                timestamp: monitored_utxo.confirmed_in_block.1,
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
                    aocl_leaf_index: Some(monitored_utxo.aocl_leaf_index),
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
        for expected_utxo in state.wallet_state.wallet_db.all_expected_utxos().await {
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
        let puzzle = ProofOfWorkPuzzle::new(proposal.clone(), latest_block_header.difficulty);

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
    async fn circulating_supply(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
    ) -> RpcResult<NativeCurrencyAmount> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self
            .state
            .lock_guard()
            .await
            .chain
            .archival_state()
            .circulating_supply()
            .await)
    }

    // documented in trait. do not add doc-comment.
    async fn max_supply(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
    ) -> RpcResult<NativeCurrencyAmount> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self
            .state
            .lock_guard()
            .await
            .chain
            .archival_state()
            .max_supply()
            .await)
    }

    // documented in trait. do not add doc-comment.
    async fn burned_supply(
        self,
        _context: tarpc::context::Context,
        token: auth::Token,
    ) -> RpcResult<NativeCurrencyAmount> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(self
            .state
            .lock_guard()
            .await
            .chain
            .archival_state()
            .burned_supply()
            .await)
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

    // Documented in trait. Do not add doc-comment.
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

    // Documented in trait. Do not add doc-comment.
    async fn prove_transfer(
        self,
        _context: ::tarpc::context::Context,
        token: auth::Token,
        tx_ix: u64,
        utxo_ix: usize,
        block: Digest,
    ) -> RpcResult<(Claim, NeptuneProof)> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        let block = self
            .state
            .lock_async(|s| futures::FutureExt::boxed(s.chain.archival_state().get_block(block)))
            .await?
            .ok_or(RpcError::NoSuchCanonicalBlock)?;

        let tx_output = self
            .state
            .api()
            .wallet()
            .sentoutput_by_indicies(tx_ix, utxo_ix)
            .await?;

        let utxo = tx_output.utxo();
        let sender_randomness = tx_output.sender_randomness();
        let additionrec = tx_output.addition_record();

        let block_aocl = block
            .body()
            .mutator_set_accumulator_without_guesser_fees()
            .aocl;
        let block_aocl_numleafs = block_aocl.num_leafs();

        tracing::info!["Lock the global state for *reading.* Until the membership proof is computed for proving the transfer."];
        let gs_lock = self.state.lock_guard().await;
        let aocl_archival = &gs_lock
            .chain
            .archival_state()
            .archival_mutator_set
            .ams()
            .aocl;

        let aocl_leaf_ix = aocl_archival
            .get_leaf_range_inclusive_async(0..=(block_aocl_numleafs - 1))
            .await
            .iter()
            .position(|leaf| *leaf == additionrec.canonical_commitment)
            .ok_or(RpcError::Failed(
                "Can't find the UTXO in the AOCL of the given block".to_string(),
            ))? as u64;
        let aocl_membership_proof = aocl_archival
            .prove_membership_relative_to_smaller_mmr(aocl_leaf_ix, block_aocl_numleafs)
            .await;

        drop(gs_lock);
        tracing::info!["Unlock the global state from *reading.* Computed the membership proof."];

        let sent = crate::application::util_proof::ProofOfTransfer::new(
            sent::claim_outputs(
                sent::claim_inputs(
                    tasm_lib::triton_vm::proof::Claim::new(sent::hash()),
                    tx_output.receiver_digest(),
                    // TODO `ProofOfTransfer` ignores time locks yet
                    utxo.release_date().unwrap_or_default(),
                ),
                sender_randomness.hash(),
                block_aocl.bag_peaks(),
                utxo.lock_script_hash(),
                tx_output.native_currency_amount(),
            ),
            block_aocl,
            sender_randomness,
            aocl_leaf_ix,
            utxo,
            aocl_membership_proof,
        );

        let claim = sent.claim();

        let proof = crate::protocol::proof_abstractions::tasm::program::TritonProgram::prove(
            &sent,
            claim.clone(),
            sent.nondeterminism(),
            crate::application::triton_vm_job_queue::vm_job_queue(),
            tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder::new()
                .job_priority(crate::api::export::TritonVmJobPriority::Normal)
                .build(),
        )
        .await
        .map_err(|e| RpcError::CreateProofError(e.to_string()))?;

        Ok((claim, proof))
    }

    // Documented in trait. Do not add doc-comment.
    async fn triton_verify(
        self,
        _context: ::tarpc::context::Context,
        token: auth::Token,
        claim: Claim,
        proof: NeptuneProof,
    ) -> RpcResult<bool> {
        log_slow_scope!(fn_name!());
        token.auth(&self.valid_tokens)?;

        Ok(tasm_lib::triton_vm::verify(
            Default::default(),
            &claim,
            &proof,
        ))
    }
}

pub mod error {
    use crate::api::tx_initiation::error::CreateProofError;

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

        #[error("create proof error: {0}")]
        CreateProofError(String),

        #[error("upgrade proof error: {0}")]
        UpgradeProofError(String),

        #[error("send error: {0}")]
        SendError(String),

        #[error("consolidation error: {0}")]
        ConsolidationError(String),

        #[error("regtest error: {0}")]
        RegTestError(String),

        #[error("invalid block range")]
        BlockRangeError,

        #[error("node not started with UTXO index")]
        UtxoIndexNotPresent,

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

        #[error("Access to this endpoint is restricted")]
        RestrictedAccess,

        #[error("Derivation index must be in interval [{0}, {1}]")]
        InvalidDerivationIndexRange(u64, u64),
        #[error("no canonical block with the given digest")]
        NoSuchCanonicalBlock,
    }

    impl From<tx_initiation::error::CreateTxError> for RpcError {
        fn from(err: tx_initiation::error::CreateTxError) -> Self {
            RpcError::CreateTxError(err.to_string())
        }
    }

    impl From<CreateProofError> for RpcError {
        fn from(err: CreateProofError) -> Self {
            RpcError::CreateProofError(err.to_string())
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

    impl From<ConsolidationError> for RpcError {
        fn from(err: ConsolidationError) -> Self {
            RpcError::ConsolidationError(err.to_string())
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

    // convert `anyhow::Error` to an `RpcError::Failed`.
    // note that `anyhow` `Error` is not serializable.
    impl From<anyhow::Error> for RpcError {
        fn from(e: anyhow::Error) -> Self {
            Self::Failed(e.to_string())
        }
    }
}
