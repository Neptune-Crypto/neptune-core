//! implements an RPC server and client based on [tarpc]
//!
//! at present tarpc clients must also be written in rust.
//!
//! In the future we may want to explore adding an rpc layer that is friendly to
//! other languages.

use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;

use anyhow::Result;
use get_size::GetSize;
use serde::Deserialize;
use serde::Serialize;
use systemstat::Platform;
use systemstat::System;
use tarpc::context;
use tokio::sync::mpsc::error::SendError;
use tracing::error;
use tracing::info;
use twenty_first::math::digest::Digest;

use crate::config_models::network::Network;
use crate::models::blockchain::block::block_header::BlockHeader;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::block_info::BlockInfo;
use crate::models::blockchain::block::block_selector::BlockSelector;
use crate::models::blockchain::transaction::transaction_output::UtxoNotificationMedium;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::channel::RPCServerToMain;
use crate::models::peer::InstanceId;
use crate::models::peer::PeerInfo;
use crate::models::peer::PeerStanding;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::transaction_kernel_id::TransactionKernelId;
use crate::models::state::tx_proving_capability::TxProvingCapability;
use crate::models::state::wallet::address::KeyType;
use crate::models::state::wallet::address::ReceivingAddress;
use crate::models::state::wallet::coin_with_possible_timelock::CoinWithPossibleTimeLock;
use crate::models::state::wallet::expected_utxo::UtxoNotifier;
use crate::models::state::wallet::wallet_status::WalletStatus;
use crate::models::state::GlobalStateLock;
use crate::prelude::twenty_first;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DashBoardOverviewDataFromClient {
    pub tip_digest: Digest,
    pub tip_header: BlockHeader,
    pub syncing: bool,
    pub available_balance: NeptuneCoins,
    pub timelocked_balance: NeptuneCoins,
    pub available_unconfirmed_balance: NeptuneCoins,
    pub mempool_size: usize,
    pub mempool_tx_count: usize,

    // `None` symbolizes failure in getting peer count
    pub peer_count: Option<usize>,

    // `None` symbolizes failure to get mining status
    pub is_mining: Option<bool>,

    // # of confirmations since last wallet balance change.
    // `None` indicates that wallet balance has never changed.
    pub confirmations: Option<BlockHeight>,

    /// CPU temperature in degrees Celcius
    pub cpu_temp: Option<f32>,
}

#[tarpc::service]
pub trait RPC {
    /******** READ DATA ********/
    // Place all methods that only read here
    // Return which network the client is running
    async fn network() -> Network;

    /// Returns local socket used for incoming peer-connections. Does not show
    /// the public IP address, as the client does not know this.
    async fn own_listen_address_for_peers() -> Option<SocketAddr>;

    /// Return the node's instance-ID which is a globally unique random generated number
    /// set at startup used to ensure that the node does not connect to itself, or the
    /// same peer twice.
    async fn own_instance_id() -> InstanceId;

    /// Returns the current block height.
    async fn block_height() -> BlockHeight;

    /// Returns the number of blocks (confirmations) since wallet balance last changed.
    ///
    /// returns `Option<BlockHeight>`
    ///
    /// return value will be None if wallet has not received any incoming funds.
    async fn confirmations() -> Option<BlockHeight>;

    /// Returns info about the peers we are connected to
    async fn peer_info() -> Vec<PeerInfo>;

    /// Return info about all peers that have been sanctioned
    async fn all_sanctioned_peers() -> HashMap<IpAddr, PeerStanding>;

    /// Returns the digest of the latest n blocks
    async fn latest_tip_digests(n: usize) -> Vec<Digest>;

    /// Returns information about the specified block if found
    async fn block_info(block_selector: BlockSelector) -> Option<BlockInfo>;

    /// Return the digest for the specified block if found
    async fn block_digest(block_selector: BlockSelector) -> Option<Digest>;

    /// Return the digest for the specified UTXO leaf index if found
    async fn utxo_digest(leaf_index: u64) -> Option<Digest>;

    /// Return the block header for the specified block
    async fn header(block_selector: BlockSelector) -> Option<BlockHeader>;

    /// Get sum of unspent UTXOs.
    async fn synced_balance() -> NeptuneCoins;

    /// Get sum of unspent UTXOs including mempool transactions.
    async fn synced_balance_unconfirmed() -> NeptuneCoins;

    /// Get the client's wallet transaction history
    async fn history() -> Vec<(Digest, BlockHeight, Timestamp, NeptuneCoins)>;

    /// Return information about funds in the wallet
    async fn wallet_status() -> WalletStatus;

    /// Return an address that this client can receive funds on
    async fn next_receiving_address(key_type: KeyType) -> ReceivingAddress;

    /// Return the number of transactions in the mempool
    async fn mempool_tx_count() -> usize;

    // TODO: Change to return current size and max size
    async fn mempool_size() -> usize;

    /// Return the information used on the dashboard's overview tab
    async fn dashboard_overview_data() -> DashBoardOverviewDataFromClient;

    /// Determine whether the user-supplied string is a valid address
    async fn validate_address(address: String, network: Network) -> Option<ReceivingAddress>;

    /// Determine whether the user-supplied string is a valid amount
    async fn validate_amount(amount: String) -> Option<NeptuneCoins>;

    /// Determine whether the given amount is less than (or equal to) the balance
    async fn amount_leq_synced_balance(amount: NeptuneCoins) -> bool;

    /// Generate a report of all owned and unspent coins, whether time-locked or not.
    async fn list_own_coins() -> Vec<CoinWithPossibleTimeLock>;

    /// Get CPU temperature.
    async fn cpu_temp() -> Option<f32>;

    /******** CHANGE THINGS ********/
    // Place all things that change state here

    /// Clears standing for all peers, connected or not
    async fn clear_all_standings();

    /// Clears standing for ip, whether connected or not
    async fn clear_standing_by_ip(ip: IpAddr);

    /// Send coins to a single recipient.
    ///
    /// See docs for [send_to_many()](Self::send_to_many())
    async fn send(
        amount: NeptuneCoins,
        address: ReceivingAddress,
        owned_utxo_notify_method: UtxoNotificationMedium,
        fee: NeptuneCoins,
    ) -> Option<TransactionKernelId>;

    /// Send coins to multiple recipients
    ///
    /// `outputs` is a list of transaction outputs in the format
    /// `[(address:amount)]`.  The address may be any type supported by
    /// [ReceivingAddress].
    ///
    /// `owned_utxo_notify_method` specifies how our wallet will be notified of
    /// any outputs destined for it. This includes the change output if one is
    /// necessary. [UtxoNotifyMethod] defines `OnChain` and `OffChain` delivery
    /// of notifications.
    ///
    /// `OffChain` delivery requires less blockchain space and may result in a
    /// lower fee than `OnChain` delivery however there is more potential of
    /// losing funds should the wallet files become corrupted or lost.
    ///
    /// tip: if using `OnChain` notification use a
    /// [ReceivingAddress::Symmetric] as the receiving address for any
    /// outputs destined for your own wallet.  This happens automatically for
    /// the Change output only.
    ///
    /// `fee` represents the fee in native coins to pay the miner who mines
    /// the block that initially confirms the resulting transaction.
    ///
    /// a [Digest] of the resulting [Transaction](crate::models::blockchain::transaction::Transaction) is returned on success, else [None].
    ///
    /// todo: shouldn't we return `Transaction` instead?
    ///
    /// future work: add `unowned_utxo_notify_medium` param.
    ///   see comment for [TxOutput::auto()](crate::models::blockchain::transaction::TxOutput::auto())
    async fn send_to_many(
        outputs: Vec<(ReceivingAddress, NeptuneCoins)>,
        owned_utxo_notify_medium: UtxoNotificationMedium,
        fee: NeptuneCoins,
    ) -> Option<TransactionKernelId>;

    /// Stop miner if running
    async fn pause_miner();

    /// Start miner if not running
    async fn restart_miner();

    /// mark MUTXOs as abandoned
    async fn prune_abandoned_monitored_utxos() -> usize;

    /// Gracious shutdown.
    async fn shutdown() -> bool;
}

#[derive(Clone)]
pub struct NeptuneRPCServer {
    pub socket_address: SocketAddr,
    pub state: GlobalStateLock,
    pub rpc_server_to_main_tx: tokio::sync::mpsc::Sender<RPCServerToMain>,
}

impl NeptuneRPCServer {
    async fn confirmations_internal(&self) -> Option<BlockHeight> {
        let state = self.state.lock_guard().await;

        match state.get_latest_balance_height().await {
            Some(latest_balance_height) => {
                let tip_block_header = state.chain.light_state().header();

                assert!(tip_block_header.height >= latest_balance_height);

                // subtract latest balance height from chain tip.
                // note: BlockHeight is u64 internally and BlockHeight::sub() returns i128.
                //       The subtraction and cast is safe given we passed the above assert.
                let confirmations: BlockHeight =
                    ((tip_block_header.height - latest_balance_height) as u64).into();
                Some(confirmations)
            }
            None => None,
        }
    }

    /// Return temperature of CPU, if available.
    fn cpu_temp_inner() -> Option<f32> {
        let current_system = System::new();
        match current_system.cpu_temp() {
            Ok(temp) => Some(temp),
            Err(_) => None,
        }
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
        mut self,
        _ctx: context::Context,
        outputs: Vec<(ReceivingAddress, NeptuneCoins)>,
        owned_utxo_notification_medium: UtxoNotificationMedium,
        fee: NeptuneCoins,
        now: Timestamp,
        tx_proving_capability: TxProvingCapability,
    ) -> Option<TransactionKernelId> {
        let span = tracing::debug_span!("Constructing transaction");
        let _enter = span.enter();

        // obtain next unused symmetric key for change utxo
        let change_key = {
            let mut s = self.state.lock_guard_mut().await;
            let key = s.wallet_state.next_unused_spending_key(KeyType::Symmetric);

            // write state to disk. create_transaction() may be slow.
            s.persist_wallet().await.expect("flushed");
            key
        };

        let state = self.state.lock_guard().await;
        let tx_outputs = state.generate_tx_outputs(outputs, owned_utxo_notification_medium);

        // Pause miner if we are mining
        let was_mining = self.state.mining().await;
        if was_mining {
            let _ = self
                .rpc_server_to_main_tx
                .send(RPCServerToMain::PauseMiner)
                .await;
        }

        // Create the transaction
        //
        // Note that create_transaction() does not modify any state and only
        // requires acquiring a read-lock which does not block other tasks.
        // This is important because internally it calls prove() which is a very
        // lengthy operation.
        //
        // note: A change output will be added to tx_outputs if needed.
        let (transaction, maybe_change_output) = match state
            .create_transaction_with_prover_capability(
                tx_outputs.clone(),
                change_key,
                owned_utxo_notification_medium,
                fee,
                now,
                tx_proving_capability,
                &self.state.wait_if_busy(),
            )
            .await
        {
            Ok(tx) => tx,
            Err(err) => {
                tracing::error!("Could not create transaction: {}", err);
                return None;
            }
        };
        drop(state);

        let utxos_sent_to_self = self
            .state
            .lock_guard()
            .await
            .wallet_state
            .extract_expected_utxos(
                tx_outputs.concat_with(maybe_change_output),
                UtxoNotifier::Myself,
            );

        // if the tx created offchain expected_utxos we must inform wallet.
        if !utxos_sent_to_self.is_empty() {
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

        // Send transaction message to main
        let response: Result<(), SendError<RPCServerToMain>> = self
            .rpc_server_to_main_tx
            .send(RPCServerToMain::BroadcastTx(Box::new(transaction.clone())))
            .await;

        // Restart mining if it was paused
        if was_mining {
            let _ = self
                .rpc_server_to_main_tx
                .send(RPCServerToMain::RestartMiner)
                .await;
        }

        self.state.flush_databases().await.expect("flushed DBs");

        match response {
            Ok(_) => Some(transaction.kernel.txid()),
            Err(e) => {
                tracing::error!("Could not send Tx to main task: error: {}", e.to_string());
                None
            }
        }
    }
}

impl RPC for NeptuneRPCServer {
    // documented in trait. do not add doc-comment.
    async fn network(self, _: context::Context) -> Network {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());
        self.state.cli().network
    }

    // documented in trait. do not add doc-comment.
    async fn own_listen_address_for_peers(self, _context: context::Context) -> Option<SocketAddr> {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());
        let listen_port = self.state.cli().own_listen_port();
        let listen_for_peers_ip = self.state.cli().listen_addr;
        listen_port.map(|port| SocketAddr::new(listen_for_peers_ip, port))
    }

    // documented in trait. do not add doc-comment.
    async fn own_instance_id(self, _context: context::Context) -> InstanceId {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());
        self.state.lock_guard().await.net.instance_id
    }

    // documented in trait. do not add doc-comment.
    async fn block_height(self, _: context::Context) -> BlockHeight {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());
        self.state
            .lock_guard()
            .await
            .chain
            .light_state()
            .kernel
            .header
            .height
    }

    // documented in trait. do not add doc-comment.
    async fn confirmations(self, _: context::Context) -> Option<BlockHeight> {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());
        self.confirmations_internal().await
    }

    // documented in trait. do not add doc-comment.
    async fn utxo_digest(self, _: context::Context, leaf_index: u64) -> Option<Digest> {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());
        let state = self.state.lock_guard().await;
        let aocl = &state.chain.archival_state().archival_mutator_set.ams().aocl;

        match leaf_index > 0 && leaf_index < aocl.num_leafs().await {
            true => Some(aocl.get_leaf_async(leaf_index).await),
            false => None,
        }
    }

    // documented in trait. do not add doc-comment.
    async fn block_digest(
        self,
        _: context::Context,
        block_selector: BlockSelector,
    ) -> Option<Digest> {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

        let state = self.state.lock_guard().await;
        let archival_state = state.chain.archival_state();
        let digest = block_selector.as_digest(&state).await?;
        // verify the block actually exists
        archival_state
            .get_block_header(digest)
            .await
            .map(|_| digest)
    }

    // documented in trait. do not add doc-comment.
    async fn block_info(
        self,
        _: context::Context,
        block_selector: BlockSelector,
    ) -> Option<BlockInfo> {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

        let state = self.state.lock_guard().await;
        let digest = block_selector.as_digest(&state).await?;
        let archival_state = state.chain.archival_state();

        let block = archival_state.get_block(digest).await.unwrap()?;
        Some(BlockInfo::from_block_and_digests(
            &block,
            archival_state.genesis_block().hash(),
            state.chain.light_state().hash(),
        ))
    }

    // documented in trait. do not add doc-comment.
    async fn latest_tip_digests(self, _context: tarpc::context::Context, n: usize) -> Vec<Digest> {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

        let state = self.state.lock_guard().await;

        let latest_block_digest = state.chain.light_state().hash();

        state
            .chain
            .archival_state()
            .get_ancestor_block_digests(latest_block_digest, n)
            .await
    }

    // documented in trait. do not add doc-comment.
    async fn peer_info(self, _: context::Context) -> Vec<PeerInfo> {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

        self.state
            .lock_guard()
            .await
            .net
            .peer_map
            .values()
            .cloned()
            .collect()
    }

    // documented in trait. do not add doc-comment.
    async fn all_sanctioned_peers(
        self,
        _context: tarpc::context::Context,
    ) -> HashMap<IpAddr, PeerStanding> {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

        let mut sanctions_in_memory = HashMap::default();

        let global_state = self.state.lock_guard().await;

        // Get all connected peers
        for (socket_address, peer_info) in global_state.net.peer_map.iter() {
            if peer_info.standing.is_negative() {
                sanctions_in_memory.insert(socket_address.ip(), peer_info.standing);
            }
        }

        let sanctions_in_db = global_state.net.all_peer_sanctions_in_database().await;

        // Combine result for currently connected peers and previously connected peers but
        // use result for currently connected peer if there is an overlap
        let mut all_sanctions = sanctions_in_memory;
        for (ip_addr, sanction) in sanctions_in_db {
            all_sanctions.entry(ip_addr).or_insert(sanction);
        }

        all_sanctions
    }

    // documented in trait. do not add doc-comment.
    async fn validate_address(
        self,
        _ctx: context::Context,
        address_string: String,
        network: Network,
    ) -> Option<ReceivingAddress> {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

        let ret = if let Ok(address) = ReceivingAddress::from_bech32m(&address_string, network) {
            Some(address)
        } else {
            None
        };
        tracing::debug!(
            "Responding to address validation request of {address_string}: {}",
            ret.is_some()
        );
        ret
    }

    // documented in trait. do not add doc-comment.
    async fn validate_amount(
        self,
        _ctx: context::Context,
        amount_string: String,
    ) -> Option<NeptuneCoins> {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

        // parse string
        let amount = if let Ok(amt) = NeptuneCoins::from_str(&amount_string) {
            amt
        } else {
            return None;
        };

        // return amount
        Some(amount)
    }

    // documented in trait. do not add doc-comment.
    async fn amount_leq_synced_balance(self, _ctx: context::Context, amount: NeptuneCoins) -> bool {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

        let now = Timestamp::now();
        // test inequality
        let wallet_status = self
            .state
            .lock_guard()
            .await
            .get_wallet_status_for_tip()
            .await;
        amount <= wallet_status.synced_unspent_available_amount(now)
    }

    // documented in trait. do not add doc-comment.
    async fn synced_balance(self, _context: tarpc::context::Context) -> NeptuneCoins {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

        let now = Timestamp::now();
        let wallet_status = self
            .state
            .lock_guard()
            .await
            .get_wallet_status_for_tip()
            .await;
        wallet_status.synced_unspent_available_amount(now)
    }

    // documented in trait. do not add doc-comment.
    async fn synced_balance_unconfirmed(self, _context: tarpc::context::Context) -> NeptuneCoins {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

        let gs = self.state.lock_guard().await;

        gs.wallet_state
            .unconfirmed_balance(gs.chain.light_state().hash(), Timestamp::now())
            .await
    }

    // documented in trait. do not add doc-comment.
    async fn wallet_status(self, _context: tarpc::context::Context) -> WalletStatus {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

        self.state
            .lock_guard()
            .await
            .get_wallet_status_for_tip()
            .await
    }

    // documented in trait. do not add doc-comment.
    async fn header(
        self,
        _context: tarpc::context::Context,
        block_selector: BlockSelector,
    ) -> Option<BlockHeader> {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

        let state = self.state.lock_guard().await;
        let block_digest = block_selector.as_digest(&state).await?;
        state
            .chain
            .archival_state()
            .get_block_header(block_digest)
            .await
    }

    // future: this should perhaps take a param indicating what type
    //         of receiving address.  for now we just use/assume
    //         a Generation address.
    //
    // documented in trait. do not add doc-comment.
    async fn next_receiving_address(
        mut self,
        _context: tarpc::context::Context,
        key_type: KeyType,
    ) -> ReceivingAddress {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

        let mut global_state_mut = self.state.lock_guard_mut().await;

        let address = global_state_mut
            .wallet_state
            .next_unused_spending_key(key_type)
            .to_address();

        // persist wallet state to disk
        global_state_mut.persist_wallet().await.expect("flushed");

        address
    }

    // documented in trait. do not add doc-comment.
    async fn mempool_tx_count(self, _context: tarpc::context::Context) -> usize {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

        self.state.lock_guard().await.mempool.len()
    }

    // documented in trait. do not add doc-comment.
    async fn mempool_size(self, _context: tarpc::context::Context) -> usize {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

        self.state.lock_guard().await.mempool.get_size()
    }

    // documented in trait. do not add doc-comment.
    async fn history(
        self,
        _context: tarpc::context::Context,
    ) -> Vec<(Digest, BlockHeight, Timestamp, NeptuneCoins)> {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

        let history = self.state.lock_guard().await.get_balance_history().await;

        // sort
        let mut display_history: Vec<(Digest, BlockHeight, Timestamp, NeptuneCoins)> = history
            .iter()
            .map(|(h, t, bh, a)| (*h, *bh, *t, *a))
            .collect::<Vec<_>>();
        display_history.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

        // return
        display_history
    }

    // documented in trait. do not add doc-comment.
    async fn dashboard_overview_data(
        self,
        _context: tarpc::context::Context,
    ) -> DashBoardOverviewDataFromClient {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

        let now = Timestamp::now();
        let state = self.state.lock_guard().await;
        let tip_digest = state.chain.light_state().hash();
        let tip_header = state.chain.light_state().header().clone();
        let wallet_status = state.get_wallet_status_for_tip().await;
        let syncing = state.net.syncing;
        let mempool_size = state.mempool.get_size();
        let mempool_tx_count = state.mempool.len();
        let cpu_temp = Self::cpu_temp_inner();
        let unconfirmed_balance = state
            .wallet_state
            .unconfirmed_balance(tip_digest, now)
            .await;

        let peer_count = Some(state.net.peer_map.len());

        let is_mining = Some(state.mining);
        drop(state);

        let confirmations = self.confirmations_internal().await;

        DashBoardOverviewDataFromClient {
            tip_digest,
            tip_header,
            syncing,
            available_balance: wallet_status.synced_unspent_available_amount(now),
            timelocked_balance: wallet_status.synced_unspent_timelocked_amount(now),
            available_unconfirmed_balance: unconfirmed_balance,
            mempool_size,
            mempool_tx_count,
            peer_count,
            is_mining,
            confirmations,
            cpu_temp,
        }
    }

    /******** CHANGE THINGS ********/
    // Locking:
    //   * acquires `global_state_lock` for write
    //
    // documented in trait. do not add doc-comment.
    async fn clear_all_standings(mut self, _: context::Context) {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

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

        global_state_mut
            .flush_databases()
            .await
            .expect("flushed DBs");
    }

    // Locking:
    //   * acquires `global_state_lock` for write
    //
    // documented in trait. do not add doc-comment.
    async fn clear_standing_by_ip(mut self, _: context::Context, ip: IpAddr) {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

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

        global_state_mut
            .flush_databases()
            .await
            .expect("flushed DBs");
    }

    // documented in trait. do not add doc-comment.
    async fn send(
        self,
        ctx: context::Context,
        amount: NeptuneCoins,
        address: ReceivingAddress,
        owned_utxo_notify_method: UtxoNotificationMedium,
        fee: NeptuneCoins,
    ) -> Option<TransactionKernelId> {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

        self.send_to_many(ctx, vec![(address, amount)], owned_utxo_notify_method, fee)
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
        outputs: Vec<(ReceivingAddress, NeptuneCoins)>,
        owned_utxo_notification_medium: UtxoNotificationMedium,
        fee: NeptuneCoins,
    ) -> Option<TransactionKernelId> {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

        // The proving capability is set to the lowest possible value here,
        // since we don't want the client (CLI or dashboard) to hang. Instead,
        // we let (a task started by) main loop handle the proving.
        let tx_proving_capability = TxProvingCapability::PrimitiveWitness;
        self.send_to_many_inner(
            ctx,
            outputs,
            owned_utxo_notification_medium,
            fee,
            Timestamp::now(),
            tx_proving_capability,
        )
        .await
    }

    // documented in trait. do not add doc-comment.
    async fn shutdown(self, _: context::Context) -> bool {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

        // 1. Send shutdown message to main
        let response = self
            .rpc_server_to_main_tx
            .send(RPCServerToMain::Shutdown)
            .await;

        // 2. Send acknowledgement to client.
        response.is_ok()
    }

    // documented in trait. do not add doc-comment.
    async fn pause_miner(self, _context: tarpc::context::Context) {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

        if self.state.cli().mine {
            let _ = self
                .rpc_server_to_main_tx
                .send(RPCServerToMain::PauseMiner)
                .await;
        } else {
            info!("Cannot pause miner since it was never started");
        }
    }

    // documented in trait. do not add doc-comment.
    async fn restart_miner(self, _context: tarpc::context::Context) {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

        if self.state.cli().mine {
            let _ = self
                .rpc_server_to_main_tx
                .send(RPCServerToMain::RestartMiner)
                .await;
        } else {
            info!("Cannot restart miner since it was never started");
        }
    }

    // documented in trait. do not add doc-comment.
    async fn prune_abandoned_monitored_utxos(mut self, _context: tarpc::context::Context) -> usize {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

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
                prune_count
            }
            Err(err) => {
                error!("Pruning monitored UTXOs failed with error: {err}");
                0
            }
        }
    }

    // documented in trait. do not add doc-comment.
    async fn list_own_coins(
        self,
        _context: ::tarpc::context::Context,
    ) -> Vec<CoinWithPossibleTimeLock> {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

        self.state
            .lock_guard()
            .await
            .wallet_state
            .get_all_own_coins_with_possible_timelocks()
            .await
    }

    // documented in trait. do not add doc-comment.
    async fn cpu_temp(self, _context: tarpc::context::Context) -> Option<f32> {
        let _ = crate::ScopeDurationLogger::new(&crate::macros::fn_name!());

        Self::cpu_temp_inner()
    }
}

#[cfg(test)]
mod rpc_server_tests {
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;

    use anyhow::Result;
    use num_traits::One;
    use num_traits::Zero;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use strum::IntoEnumIterator;
    use tracing_test::traced_test;
    use ReceivingAddress;

    use super::*;
    use crate::config_models::network::Network;
    use crate::database::storage::storage_vec::traits::*;
    use crate::models::peer::PeerSanctionReason;
    use crate::models::state::wallet::address::generation_address::GenerationReceivingAddress;
    use crate::models::state::wallet::expected_utxo::ExpectedUtxo;
    use crate::models::state::wallet::expected_utxo::UtxoNotifier;
    use crate::models::state::wallet::WalletSecret;
    use crate::rpc_server::NeptuneRPCServer;
    use crate::tests::shared::make_mock_block;
    use crate::tests::shared::mock_genesis_global_state;
    use crate::Block;
    use crate::RPC_CHANNEL_CAPACITY;

    async fn test_rpc_server(
        network: Network,
        wallet_secret: WalletSecret,
        peer_count: u8,
    ) -> (NeptuneRPCServer, GlobalStateLock) {
        let global_state_lock = mock_genesis_global_state(network, peer_count, wallet_secret).await;
        let (dummy_tx, mut dummy_rx) =
            tokio::sync::mpsc::channel::<RPCServerToMain>(RPC_CHANNEL_CAPACITY);

        tokio::spawn(async move {
            while let Some(i) = dummy_rx.recv().await {
                tracing::trace!("mock Main got message = {:?}", i);
            }
        });

        (
            NeptuneRPCServer {
                socket_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
                state: global_state_lock.clone(),
                rpc_server_to_main_tx: dummy_tx,
            },
            global_state_lock,
        )
    }

    #[tokio::test]
    async fn network_response_is_consistent() -> Result<()> {
        // Verify that a wallet not receiving a premine is empty at startup
        for network in Network::iter() {
            let (rpc_server, _) = test_rpc_server(network, WalletSecret::new_random(), 2).await;
            assert_eq!(network, rpc_server.network(context::current()).await);
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

        let (rpc_server, _) =
            test_rpc_server(network, WalletSecret::new_pseudorandom(rng.gen()), 2).await;
        let ctx = context::current();
        let _ = rpc_server.clone().network(ctx).await;
        let _ = rpc_server.clone().own_listen_address_for_peers(ctx).await;
        let _ = rpc_server.clone().own_instance_id(ctx).await;
        let _ = rpc_server.clone().block_height(ctx).await;
        let _ = rpc_server.clone().peer_info(ctx).await;
        let _ = rpc_server.clone().all_sanctioned_peers(ctx).await;
        let _ = rpc_server.clone().latest_tip_digests(ctx, 2).await;
        let _ = rpc_server
            .clone()
            .header(ctx, BlockSelector::Digest(Digest::default()))
            .await;
        let _ = rpc_server
            .clone()
            .block_info(ctx, BlockSelector::Digest(Digest::default()))
            .await;
        let _ = rpc_server
            .clone()
            .block_digest(ctx, BlockSelector::Digest(Digest::default()))
            .await;
        let _ = rpc_server.clone().utxo_digest(ctx, 0).await;
        let _ = rpc_server.clone().synced_balance(ctx).await;
        let _ = rpc_server.clone().history(ctx).await;
        let _ = rpc_server.clone().wallet_status(ctx).await;
        let own_receiving_address = rpc_server
            .clone()
            .next_receiving_address(ctx, KeyType::Generation)
            .await;
        let _ = rpc_server.clone().mempool_tx_count(ctx).await;
        let _ = rpc_server.clone().mempool_size(ctx).await;
        let _ = rpc_server.clone().dashboard_overview_data(ctx).await;
        let _ = rpc_server
            .clone()
            .validate_address(ctx, "Not a valid address".to_owned(), Network::Testnet)
            .await;
        let _ = rpc_server.clone().clear_all_standings(ctx).await;
        let _ = rpc_server
            .clone()
            .clear_standing_by_ip(ctx, "127.0.0.1".parse().unwrap())
            .await;
        let _ = rpc_server
            .clone()
            .send(
                ctx,
                NeptuneCoins::one(),
                own_receiving_address.clone(),
                UtxoNotificationMedium::OffChain,
                NeptuneCoins::one(),
            )
            .await;

        let transaction_timestamp = network.launch_date();
        let proving_capability = rpc_server
            .state
            .lock_guard()
            .await
            .net
            .tx_proving_capability;
        let _ = rpc_server
            .clone()
            .send_to_many_inner(
                ctx,
                vec![(own_receiving_address, NeptuneCoins::one())],
                UtxoNotificationMedium::OffChain,
                NeptuneCoins::one(),
                transaction_timestamp,
                proving_capability,
            )
            .await;
        let _ = rpc_server.clone().pause_miner(ctx).await;
        let _ = rpc_server.clone().restart_miner(ctx).await;
        let _ = rpc_server
            .clone()
            .prune_abandoned_monitored_utxos(ctx)
            .await;
        let _ = rpc_server.shutdown(ctx).await;

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn balance_is_zero_at_init() -> Result<()> {
        // Verify that a wallet not receiving a premine is empty at startup
        let (rpc_server, _) = test_rpc_server(Network::Alpha, WalletSecret::new_random(), 2).await;
        let balance = rpc_server.synced_balance(context::current()).await;
        assert!(balance.is_zero());

        Ok(())
    }

    #[allow(clippy::shadow_unrelated)]
    #[traced_test]
    #[tokio::test]
    async fn clear_ip_standing_test() -> Result<()> {
        let (rpc_server, mut state_lock) =
            test_rpc_server(Network::Alpha, WalletSecret::new_random(), 2).await;
        let rpc_request_context = context::current();
        let global_state = state_lock.lock_guard().await;
        let peer_address_0 =
            global_state.net.peer_map.values().collect::<Vec<_>>()[0].connected_address;
        let peer_address_1 =
            global_state.net.peer_map.values().collect::<Vec<_>>()[1].connected_address;
        drop(global_state);

        // Verify that sanctions list is empty
        let sanctioned_peers_startup = rpc_server
            .clone()
            .all_sanctioned_peers(rpc_request_context)
            .await;
        assert!(
            sanctioned_peers_startup.is_empty(),
            "Sanctions list must be empty at startup"
        );

        // sanction both
        let (standing_0, standing_1) = {
            let mut global_state_mut = state_lock.lock_guard_mut().await;

            global_state_mut
                .net
                .peer_map
                .entry(peer_address_0)
                .and_modify(|p| {
                    p.standing.sanction(PeerSanctionReason::DifferentGenesis);
                });
            global_state_mut
                .net
                .peer_map
                .entry(peer_address_1)
                .and_modify(|p| {
                    p.standing.sanction(PeerSanctionReason::DifferentGenesis);
                });
            let standing_0 = global_state_mut.net.peer_map[&peer_address_0].standing;
            let standing_1 = global_state_mut.net.peer_map[&peer_address_1].standing;
            (standing_0, standing_1)
        };

        // Verify expected sanctions reading
        let sanction_peers_from_memory = rpc_server
            .clone()
            .all_sanctioned_peers(rpc_request_context)
            .await;
        assert_eq!(
            2,
            sanction_peers_from_memory.len(),
            "Sanctions list must have to elements after sanctionings"
        );

        {
            let mut global_state_mut = state_lock.lock_guard_mut().await;

            global_state_mut
                .net
                .write_peer_standing_on_decrease(peer_address_0.ip(), standing_0)
                .await;
            global_state_mut
                .net
                .write_peer_standing_on_decrease(peer_address_1.ip(), standing_1)
                .await;
        }

        // Verify expected sanctions reading, after DB-write
        let sanction_peers_from_memory_and_db = rpc_server
            .clone()
            .all_sanctioned_peers(rpc_request_context)
            .await;
        assert_eq!(
            2,
            sanction_peers_from_memory_and_db.len(),
            "Sanctions list must have to elements after sanctionings and after DB write"
        );

        // Verify expected initial conditions
        {
            let global_state = state_lock.lock_guard().await;
            let peer_standing_0 = global_state
                .net
                .get_peer_standing_from_database(peer_address_0.ip())
                .await;
            assert_ne!(0, peer_standing_0.unwrap().standing);
            assert_ne!(None, peer_standing_0.unwrap().latest_sanction);
            let peer_standing_1 = global_state
                .net
                .get_peer_standing_from_database(peer_address_1.ip())
                .await;
            assert_ne!(0, peer_standing_1.unwrap().standing);
            assert_ne!(None, peer_standing_1.unwrap().latest_sanction);
            drop(global_state);

            // Clear standing of #0
            rpc_server
                .clone()
                .clear_standing_by_ip(rpc_request_context, peer_address_0.ip())
                .await;
        }

        // Verify expected resulting conditions in database
        {
            let global_state = state_lock.lock_guard().await;
            let peer_standing_0 = global_state
                .net
                .get_peer_standing_from_database(peer_address_0.ip())
                .await;
            assert_eq!(0, peer_standing_0.unwrap().standing);
            assert_eq!(None, peer_standing_0.unwrap().latest_sanction);
            let peer_standing_1 = global_state
                .net
                .get_peer_standing_from_database(peer_address_1.ip())
                .await;
            assert_ne!(0, peer_standing_1.unwrap().standing);
            assert_ne!(None, peer_standing_1.unwrap().latest_sanction);

            // Verify expected resulting conditions in peer map
            let peer_standing_0_from_memory = global_state.net.peer_map[&peer_address_0].clone();
            assert_eq!(0, peer_standing_0_from_memory.standing.standing);
            let peer_standing_1_from_memory = global_state.net.peer_map[&peer_address_1].clone();
            assert_ne!(0, peer_standing_1_from_memory.standing.standing);
        }

        // Verify expected sanctions reading, after one forgiveness
        let sanctions_list_after_one_clear = rpc_server
            .clone()
            .all_sanctioned_peers(rpc_request_context)
            .await;
        assert!(
            sanctions_list_after_one_clear.len().is_one(),
            "Sanctions list must have to elements after sanctionings and after DB write"
        );

        Ok(())
    }

    #[allow(clippy::shadow_unrelated)]
    #[traced_test]
    #[tokio::test]
    async fn clear_all_standings_test() -> Result<()> {
        // Create initial conditions
        let (rpc_server, mut state_lock) =
            test_rpc_server(Network::Alpha, WalletSecret::new_random(), 2).await;
        let mut state = state_lock.lock_guard_mut().await;
        let peer_address_0 = state.net.peer_map.values().collect::<Vec<_>>()[0].connected_address;
        let peer_address_1 = state.net.peer_map.values().collect::<Vec<_>>()[1].connected_address;

        // sanction both peers
        let (standing_0, standing_1) = {
            state.net.peer_map.entry(peer_address_0).and_modify(|p| {
                p.standing.sanction(PeerSanctionReason::DifferentGenesis);
            });
            state.net.peer_map.entry(peer_address_1).and_modify(|p| {
                p.standing.sanction(PeerSanctionReason::DifferentGenesis);
            });
            let standing_0 = state.net.peer_map[&peer_address_0].standing;
            let standing_1 = state.net.peer_map[&peer_address_1].standing;
            (standing_0, standing_1)
        };

        state
            .net
            .write_peer_standing_on_decrease(peer_address_0.ip(), standing_0)
            .await;
        state
            .net
            .write_peer_standing_on_decrease(peer_address_1.ip(), standing_1)
            .await;

        drop(state);

        // Verify expected initial conditions
        {
            let peer_standing_0 = state_lock
                .lock_guard_mut()
                .await
                .net
                .get_peer_standing_from_database(peer_address_0.ip())
                .await;
            assert_ne!(0, peer_standing_0.unwrap().standing);
            assert_ne!(None, peer_standing_0.unwrap().latest_sanction);
        }

        {
            let peer_standing_1 = state_lock
                .lock_guard_mut()
                .await
                .net
                .get_peer_standing_from_database(peer_address_1.ip())
                .await;
            assert_ne!(0, peer_standing_1.unwrap().standing);
            assert_ne!(None, peer_standing_1.unwrap().latest_sanction);
        }

        // Verify expected reading through an RPC call
        let rpc_request_context = context::current();
        let after_two_sanctions = rpc_server
            .clone()
            .all_sanctioned_peers(rpc_request_context)
            .await;
        assert_eq!(2, after_two_sanctions.len());

        // Clear standing of both by clearing all standings
        rpc_server
            .clone()
            .clear_all_standings(rpc_request_context)
            .await;

        let state = state_lock.lock_guard().await;

        // Verify expected resulting conditions in database
        {
            let peer_standing_0 = state
                .net
                .get_peer_standing_from_database(peer_address_0.ip())
                .await;
            assert_eq!(0, peer_standing_0.unwrap().standing);
            assert_eq!(None, peer_standing_0.unwrap().latest_sanction);
        }

        {
            let peer_still_standing_1 = state
                .net
                .get_peer_standing_from_database(peer_address_1.ip())
                .await;
            assert_eq!(0, peer_still_standing_1.unwrap().standing);
            assert_eq!(None, peer_still_standing_1.unwrap().latest_sanction);
        }

        // Verify expected resulting conditions in peer map
        {
            let peer_standing_0_from_memory = state.net.peer_map[&peer_address_0].clone();
            assert_eq!(0, peer_standing_0_from_memory.standing.standing);
        }

        {
            let peer_still_standing_1_from_memory = state.net.peer_map[&peer_address_1].clone();
            assert_eq!(0, peer_still_standing_1_from_memory.standing.standing);
        }

        // Verify expected reading through an RPC call
        let after_global_forgiveness = rpc_server
            .clone()
            .all_sanctioned_peers(rpc_request_context)
            .await;
        assert!(after_global_forgiveness.is_empty());

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn utxo_digest_test() {
        let (rpc_server, state_lock) =
            test_rpc_server(Network::Alpha, WalletSecret::new_random(), 2).await;
        let global_state = state_lock.lock_guard().await;
        let aocl_leaves = global_state
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
            .utxo_digest(context::current(), aocl_leaves - 1)
            .await
            .is_some());

        assert!(rpc_server
            .utxo_digest(context::current(), aocl_leaves)
            .await
            .is_none());
    }

    #[traced_test]
    #[tokio::test]
    async fn block_info_test() {
        let network = Network::RegTest;
        let (rpc_server, state_lock) =
            test_rpc_server(network, WalletSecret::new_random(), 2).await;
        let global_state = state_lock.lock_guard().await;
        let ctx = context::current();

        let genesis_hash = global_state.chain.archival_state().genesis_block().hash();
        let tip_hash = global_state.chain.light_state().hash();

        let genesis_block_info = BlockInfo::from_block_and_digests(
            global_state.chain.archival_state().genesis_block(),
            genesis_hash,
            tip_hash,
        );

        let tip_block_info = BlockInfo::from_block_and_digests(
            global_state.chain.light_state(),
            genesis_hash,
            tip_hash,
        );

        // should find genesis block by Genesis selector
        assert_eq!(
            genesis_block_info,
            rpc_server
                .clone()
                .block_info(ctx, BlockSelector::Genesis)
                .await
                .unwrap()
        );

        // should find latest/tip block by Tip selector
        assert_eq!(
            tip_block_info,
            rpc_server
                .clone()
                .block_info(ctx, BlockSelector::Tip)
                .await
                .unwrap()
        );

        // should find genesis block by Height selector
        assert_eq!(
            genesis_block_info,
            rpc_server
                .clone()
                .block_info(ctx, BlockSelector::Height(BlockHeight::from(0u64)))
                .await
                .unwrap()
        );

        // should find genesis block by Digest selector
        assert_eq!(
            genesis_block_info,
            rpc_server
                .clone()
                .block_info(ctx, BlockSelector::Digest(genesis_hash))
                .await
                .unwrap()
        );

        // should not find any block when Height selector is u64::Max
        assert!(rpc_server
            .clone()
            .block_info(ctx, BlockSelector::Height(BlockHeight::from(u64::MAX)))
            .await
            .is_none());

        // should not find any block when Digest selector is Digest::default()
        assert!(rpc_server
            .clone()
            .block_info(ctx, BlockSelector::Digest(Digest::default()))
            .await
            .is_none());
    }

    #[traced_test]
    #[tokio::test]
    async fn block_digest_test() {
        let network = Network::RegTest;
        let (rpc_server, state_lock) =
            test_rpc_server(network, WalletSecret::new_random(), 2).await;
        let global_state = state_lock.lock_guard().await;
        let ctx = context::current();

        let genesis_hash = Block::genesis_block(network).hash();

        // should find genesis block by Genesis selector
        assert_eq!(
            genesis_hash,
            rpc_server
                .clone()
                .block_digest(ctx, BlockSelector::Genesis)
                .await
                .unwrap()
        );

        // should find latest/tip block by Tip selector
        assert_eq!(
            global_state.chain.light_state().hash(),
            rpc_server
                .clone()
                .block_digest(ctx, BlockSelector::Tip)
                .await
                .unwrap()
        );

        // should find genesis block by Height selector
        assert_eq!(
            genesis_hash,
            rpc_server
                .clone()
                .block_digest(ctx, BlockSelector::Height(BlockHeight::from(0u64)))
                .await
                .unwrap()
        );

        // should find genesis block by Digest selector
        assert_eq!(
            genesis_hash,
            rpc_server
                .clone()
                .block_digest(ctx, BlockSelector::Digest(genesis_hash))
                .await
                .unwrap()
        );

        // should not find any block when Height selector is u64::Max
        assert!(rpc_server
            .clone()
            .block_digest(ctx, BlockSelector::Height(BlockHeight::from(u64::MAX)))
            .await
            .is_none());

        // should not find any block when Digest selector is Digest::default()
        assert!(rpc_server
            .clone()
            .block_digest(ctx, BlockSelector::Digest(Digest::default()))
            .await
            .is_none());
    }

    #[traced_test]
    #[tokio::test]
    async fn getting_temperature_doesnt_crash_test() {
        // On your local machine, this should return a temperature but in CI,
        // the RPC call returns `None`, so we only verify that the call doesn't
        // crash the host machine, we don't verify that any value is returned.
        let (rpc_server, _) = test_rpc_server(Network::Alpha, WalletSecret::new_random(), 2).await;
        let _current_server_temperature = rpc_server.cpu_temp(context::current()).await;
    }

    #[traced_test]
    #[tokio::test]
    async fn send_to_many_test() -> Result<()> {
        // --- Init.  Basics ---
        let mut rng = StdRng::seed_from_u64(1814);
        let network = Network::Main;
        let (rpc_server, mut state_lock) =
            test_rpc_server(network, WalletSecret::new_pseudorandom(rng.gen()), 2).await;
        let ctx = context::current();

        // --- Init.  get wallet spending key ---
        let genesis_block = Block::genesis_block(network);
        let wallet_spending_key = state_lock
            .lock_guard_mut()
            .await
            .wallet_state
            .next_unused_spending_key(KeyType::Generation);

        // --- Init.  generate a block, with coinbase going to our wallet ---
        let timestamp = network.launch_date() + Timestamp::days(1);
        let (block_1, cb_utxo, cb_output_randomness) = make_mock_block(
            &genesis_block,
            Some(timestamp),
            wallet_spending_key.to_address().try_into()?,
            rng.gen(),
        );

        {
            let state_lock = state_lock.lock_guard().await;
            let original_balance = state_lock
                .wallet_state
                .confirmed_balance(genesis_block.hash(), timestamp)
                .await;
            assert!(original_balance.is_zero(), "Original balance assumed zero");
        };

        // --- Init.  append the block to blockchain ---
        let prover_lock = state_lock.proving_lock.clone();
        state_lock
            .lock_guard_mut()
            .await
            .set_new_self_mined_tip(
                block_1.clone(),
                ExpectedUtxo::new(
                    cb_utxo,
                    cb_output_randomness,
                    wallet_spending_key.privacy_preimage(),
                    UtxoNotifier::OwnMiner,
                ),
                &prover_lock,
            )
            .await?;

        {
            let state_lock = state_lock.lock_guard().await;
            let new_balance = state_lock
                .wallet_state
                .confirmed_balance(block_1.hash(), timestamp)
                .await;
            assert_eq!(
                Block::get_mining_reward(block_1.header().height),
                new_balance,
                "New balance must be exactly 1 mining reward"
            );
        };

        // --- Setup. generate an output that our wallet cannot claim. ---
        let output1 = (
            ReceivingAddress::from(GenerationReceivingAddress::derive_from_seed(rng.gen())),
            NeptuneCoins::new(5),
        );

        // --- Setup. generate an output that our wallet can claim. ---
        let output2 = {
            let spending_key = state_lock
                .lock_guard_mut()
                .await
                .wallet_state
                .next_unused_spending_key(KeyType::Generation);
            (spending_key.to_address(), NeptuneCoins::new(25))
        };

        // --- Setup. assemble outputs and fee ---
        let outputs = vec![output1, output2];
        let fee = NeptuneCoins::new(1);

        // --- Store: store num expected utxo before spend ---
        let num_expected_utxo = state_lock
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
                UtxoNotificationMedium::OffChain,
                fee,
                timestamp,
                TxProvingCapability::ProofCollection,
            )
            .await;

        // --- Test: verify op returns a value.
        assert!(result.is_some());

        // --- Test: verify expected_utxos.len() has increased by 2.
        //           (one off-chain utxo + one change utxo)
        assert_eq!(
            state_lock
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
