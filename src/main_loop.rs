use crate::connect_to_peers::{answer_peer_wrapper, call_peer_wrapper};
use crate::database::rusty::RustyLevelDB;
use crate::models::blockchain::block::block_header::{BlockHeader, PROOF_OF_WORK_COUNT_U32_SIZE};
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::Block;
use crate::models::database::{BlockIndexKey, BlockIndexValue};
use crate::models::peer::{
    HandshakeData, PeerInfo, PeerSynchronizationState, TransactionNotification,
};
use crate::models::state::mempool::MempoolInternal;
use crate::models::state::wallet::rusty_wallet_database::RustyWalletDatabase;
use crate::models::state::wallet::utxo_notification_pool::UtxoNotifier;
use crate::models::state::GlobalState;
use anyhow::Result;
use itertools::Itertools;
use rand::prelude::{IteratorRandom, SliceRandom};
use rand::thread_rng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::thread::sleep;
use std::time::{Duration, SystemTime};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::JoinHandle;
use tokio::{select, signal, time};
use tracing::{debug, error, info, warn};
use twenty_first::amount::u32s::U32s;
use twenty_first::util_types::emojihash_trait::Emojihash;
use twenty_first::util_types::storage_schema::StorageWriter;

use crate::models::channel::{
    MainToMiner, MainToPeerThread, MinerToMain, PeerThreadToMain, RPCServerToMain,
};

const PEER_DISCOVERY_INTERVAL_IN_SECONDS: u64 = 120;
const SYNC_REQUEST_INTERVAL_IN_SECONDS: u64 = 10;
const MEMPOOL_PRUNE_INTERVAL_IN_SECS: u64 = 30 * 60; // 30mins
const MP_RESYNC_INTERVAL_IN_SECS: u64 = 59;
const UTXO_NOTIFICATION_POOL_PRUNE_INTERVAL_IN_SECS: u64 = 19 * 60; // 19 mins

const SANCTION_PEER_TIMEOUT_FACTOR: u64 = 4;
const POTENTIAL_PEER_MAX_COUNT_AS_A_FACTOR_OF_MAX_PEERS: usize = 20;
const STANDARD_BATCH_BLOCK_LOOKBEHIND_SIZE: usize = 100;

/// MainLoop is the immutable part of the input for the main loop function
pub struct MainLoopHandler {
    incoming_peer_listener: TcpListener,
    global_state: GlobalState,
    main_to_peer_broadcast_tx: broadcast::Sender<MainToPeerThread>,
    peer_thread_to_main_tx: mpsc::Sender<PeerThreadToMain>,
    main_to_miner_tx: watch::Sender<MainToMiner>,
}

impl MainLoopHandler {
    pub fn new(
        incoming_peer_listener: TcpListener,
        state: GlobalState,
        main_to_peer_broadcast_tx: broadcast::Sender<MainToPeerThread>,
        peer_thread_to_main_tx: mpsc::Sender<PeerThreadToMain>,
        main_to_miner_tx: watch::Sender<MainToMiner>,
    ) -> Self {
        Self {
            incoming_peer_listener,
            global_state: state,
            main_to_miner_tx,
            main_to_peer_broadcast_tx,
            peer_thread_to_main_tx,
        }
    }
}

/// The mutable part of the main loop function
struct MutableMainLoopState {
    sync_state: SyncState,
    potential_peers: PotentialPeersState,
    thread_handles: Vec<JoinHandle<()>>,
}

impl MutableMainLoopState {
    fn new(thread_handles: Vec<JoinHandle<()>>) -> Self {
        Self {
            sync_state: SyncState::default(),
            potential_peers: PotentialPeersState::default(),
            thread_handles,
        }
    }
}

/// handles batch-downloading of blocks if we are more than n blocks behind
struct SyncState {
    peer_sync_states: HashMap<SocketAddr, PeerSynchronizationState>,
    last_sync_request: Option<(SystemTime, BlockHeight, SocketAddr)>,
}

impl SyncState {
    fn default() -> Self {
        Self {
            peer_sync_states: HashMap::new(),
            last_sync_request: None,
        }
    }

    fn record_request(&mut self, requested_block_height: BlockHeight, peer: SocketAddr) {
        self.last_sync_request = Some((SystemTime::now(), requested_block_height, peer));
    }

    /// Return a list of peers that have reported to be in possession of blocks with a PoW family
    /// above a threshold.
    fn get_potential_peers_for_sync_request(
        &self,
        threshold_pow_family: U32s<PROOF_OF_WORK_COUNT_U32_SIZE>,
    ) -> Vec<SocketAddr> {
        self.peer_sync_states
            .iter()
            .filter(|(_sa, sync_state)| sync_state.claimed_max_pow_family > threshold_pow_family)
            .map(|(sa, _)| *sa)
            .collect()
    }

    /// Determine if a peer should be sanctioned for failing to respond to a synchronization
    /// request. Also determine if a new request should be made or the previous one should be
    /// allowed to run for longer.
    fn get_status_of_last_request(
        &self,
        current_block_height: BlockHeight,
    ) -> (Option<SocketAddr>, bool) {
        // A peer is sanctioned if no answer has been received after N times the sync request
        // interval.
        match self.last_sync_request {
            None => {
                // No sync request has been made since startup of program
                (None, true)
            }
            Some((req_time, requested_height, peer_sa)) => {
                if requested_height < current_block_height {
                    // The last sync request updated the state
                    (None, true)
                } else if req_time
                    + Duration::from_secs(
                        SANCTION_PEER_TIMEOUT_FACTOR * SYNC_REQUEST_INTERVAL_IN_SECONDS,
                    )
                    < SystemTime::now()
                {
                    // The last sync request was not answered, sanction peer
                    // and make a new sync request.
                    (Some(peer_sa), true)
                } else {
                    // The last sync request has not yet been answered. But it has
                    // not timed out yet.
                    (None, false)
                }
            }
        }
    }
}

/// holds information about a potential peer in the process of peer discovery
struct PotentialPeerInfo {
    _reported: SystemTime,
    _reported_by: SocketAddr,
    instance_id: u128,
    distance: u8,
}

impl PotentialPeerInfo {
    fn new(reported_by: SocketAddr, instance_id: u128, distance: u8) -> Self {
        Self {
            _reported: SystemTime::now(),
            _reported_by: reported_by,
            instance_id,
            distance,
        }
    }
}

/// holds information about a set of potential peers in the process of peer discovery
struct PotentialPeersState {
    potential_peers: HashMap<SocketAddr, PotentialPeerInfo>,
}

impl PotentialPeersState {
    fn default() -> Self {
        Self {
            potential_peers: HashMap::new(),
        }
    }

    fn add(
        &mut self,
        reported_by: SocketAddr,
        potential_peer: (SocketAddr, u128),
        max_peers: usize,
        distance: u8,
    ) {
        let potential_peer_socket_address = potential_peer.0;
        let potential_peer_instance_id = potential_peer.1;

        // This check *should* make it likely that a potential peer is always
        // registered with the lowest observed distance.
        if self
            .potential_peers
            .contains_key(&potential_peer_socket_address)
        {
            return;
        }

        // If this data structure is full, remove a random entry. Then add this.
        if self.potential_peers.len()
            > max_peers * POTENTIAL_PEER_MAX_COUNT_AS_A_FACTOR_OF_MAX_PEERS
        {
            let mut rng = rand::thread_rng();
            let random_potential_peer = self
                .potential_peers
                .keys()
                .choose(&mut rng)
                .unwrap()
                .to_owned();
            self.potential_peers.remove(&random_potential_peer);
        }

        let insert_value =
            PotentialPeerInfo::new(reported_by, potential_peer_instance_id, distance);
        self.potential_peers
            .insert(potential_peer_socket_address, insert_value);
    }

    /// Return a random peer from the potential peer list that we aren't connected to
    /// and that isn't our own address. Returns (socket address, peer distance)
    fn get_distant_candidate(
        &self,
        connected_clients: &[PeerInfo],
        own_listen_socket: Option<SocketAddr>,
        own_instance_id: u128,
    ) -> Option<(SocketAddr, u8)> {
        let peers_instance_ids: Vec<u128> =
            connected_clients.iter().map(|x| x.instance_id).collect();

        // Only pick those peers that report a listening port
        let peers_listen_addresses: Vec<SocketAddr> = connected_clients
            .iter()
            .filter_map(|x| x.address_for_incoming_connections)
            .collect();

        // Find the appropriate candidates
        let not_connected_peers = self
            .potential_peers
            .iter()
            // Prevent connecting to self
            .filter(|pp| pp.1.instance_id != own_instance_id)
            .filter(|pp| own_listen_socket.is_some() && *pp.0 != own_listen_socket.unwrap())
            // Prevent connecting to peer we already are connected to
            .filter(|potential_peer| !peers_instance_ids.contains(&potential_peer.1.instance_id))
            .filter(|potential_peer| !peers_listen_addresses.contains(potential_peer.0))
            .collect::<Vec<_>>();

        // Get the candidate list with the highest distance
        let max_distance_candidates = not_connected_peers.iter().max_by_key(|pp| pp.1.distance);

        // Pick a random candidate from the appropriate candidates
        let mut rng = rand::thread_rng();
        max_distance_candidates
            .iter()
            .choose(&mut rng)
            .map(|x| (x.0.to_owned(), x.1.distance))
    }
}

/// Return a boolean indicating if synchronization mode should be entered
fn enter_sync_mode(
    own_block_tip_header: BlockHeader,
    peer_synchronization_state: PeerSynchronizationState,
    max_number_of_blocks_before_syncing: usize,
) -> bool {
    own_block_tip_header.proof_of_work_family < peer_synchronization_state.claimed_max_pow_family
        && peer_synchronization_state.claimed_max_height - own_block_tip_header.height
            > max_number_of_blocks_before_syncing as i128
}

/// Return a boolean indicating if synchronization mode should be left
fn stay_in_sync_mode(
    own_block_tip_header: BlockHeader,
    sync_state: &SyncState,
    max_number_of_blocks_before_syncing: usize,
) -> bool {
    let max_claimed_pow = sync_state
        .peer_sync_states
        .values()
        .max_by_key(|x| x.claimed_max_pow_family);
    match max_claimed_pow {
        None => false, // we lost all connections. Can't sync.

        // Synchronization is left when the remaining number of block is half of what has
        // been indicated to fit into RAM
        Some(max_claim) => {
            own_block_tip_header.proof_of_work_family < max_claim.claimed_max_pow_family
                && max_claim.claimed_max_height - own_block_tip_header.height
                    > max_number_of_blocks_before_syncing as i128 / 2
        }
    }
}

impl MainLoopHandler {
    async fn handle_miner_thread_message(&self, msg: MinerToMain) -> Result<()> {
        match msg {
            MinerToMain::NewBlockFound(new_block_info) => {
                // When receiving a block from the miner thread, we assume it is valid
                // and we assume it is the longest chain even though we could have received
                // a block from a peer thread before this event is triggered.
                let new_block = new_block_info.block;
                info!("Miner found new block: {}", new_block.header.height);

                // Store block in database
                // Acquire all locks before updating
                {
                    let mut wallet_state_db: tokio::sync::MutexGuard<RustyWalletDatabase> =
                        self.global_state.wallet_state.wallet_db.lock().await;
                    let mut db_lock: tokio::sync::MutexGuard<
                        RustyLevelDB<BlockIndexKey, BlockIndexValue>,
                    > = self
                        .global_state
                        .chain
                        .archival_state
                        .as_ref()
                        .unwrap()
                        .block_index_db
                        .lock()
                        .await;
                    let mut ams_lock = self
                        .global_state
                        .chain
                        .archival_state
                        .as_ref()
                        .unwrap()
                        .archival_mutator_set
                        .lock()
                        .await;
                    let mut light_state_locked = self
                        .global_state
                        .chain
                        .light_state
                        .latest_block
                        .lock()
                        .await;
                    let mut mempool_write_lock: std::sync::RwLockWriteGuard<MempoolInternal> = self
                        .global_state
                        .mempool
                        .internal
                        .write()
                        .expect("Locking mempool for write must succeed");

                    // If we received a new block from a peer and updated the global state before this message from the miner was handled,
                    // we abort and do not store the newly found block. The newly found block has to be the direct descendant of what this
                    // node considered the most canonical block.
                    let block_is_new = light_state_locked.header.proof_of_work_family
                        < new_block.header.proof_of_work_family
                        && new_block.header.prev_block_digest == light_state_locked.hash;
                    if !block_is_new {
                        warn!("Got new block from miner thread that was not child of tip. Discarding.");
                        return Ok(());
                    }

                    // Apply the updates
                    self.global_state
                        .chain
                        .archival_state
                        .as_ref()
                        .unwrap()
                        .write_block(
                            new_block.clone(),
                            &mut db_lock,
                            Some(light_state_locked.header.proof_of_work_family),
                        )?;

                    // update the mutator set with the UTXOs from this block
                    self.global_state
                        .chain
                        .archival_state
                        .as_ref()
                        .unwrap()
                        .update_mutator_set(&mut db_lock, &mut ams_lock, &new_block)?;

                    // Notify wallet to expect the coinbase UTXO, as we mined this block
                    self.global_state
                        .wallet_state
                        .expected_utxos
                        .write()
                        .unwrap()
                        .add_expected_utxo(
                            new_block_info.coinbase_utxo_info.utxo,
                            new_block_info.coinbase_utxo_info.sender_randomness,
                            new_block_info.coinbase_utxo_info.receiver_preimage,
                            UtxoNotifier::OwnMiner,
                        )
                        .expect("UTXO notification from miner must be accepted");

                    // update wallet state with relevant UTXOs from this block
                    self.global_state
                        .wallet_state
                        .update_wallet_state_with_new_block(&new_block, &mut wallet_state_db)?;

                    // Update mempool with UTXOs from this block. This is done by removing all transaction
                    // that became invalid/was mined by this block.
                    self.global_state
                        .mempool
                        .update_with_block(&new_block, &mut mempool_write_lock);

                    *light_state_locked = *new_block.clone();
                }

                // Flush databases
                self.flush_databases().await?;

                // Inform miner that mempool has been updated and that it is safe
                // to mine the next block
                self.main_to_miner_tx
                    .send(MainToMiner::ReadyToMineNextBlock)?;

                // Share block with peers
                self.main_to_peer_broadcast_tx
                    .send(MainToPeerThread::Block(new_block.clone()))
                    .expect(
                        "Peer handler broadcast channel prematurely closed. This should never happen.",
                    );
            }
        }

        Ok(())
    }

    async fn handle_peer_thread_message(
        &self,
        msg: PeerThreadToMain,
        main_loop_state: &mut MutableMainLoopState,
    ) -> Result<()> {
        debug!("Received {} from a peer thread", msg.get_type());
        match msg {
            PeerThreadToMain::NewBlocks(blocks) => {
                let last_block = blocks.last().unwrap().to_owned();
                {
                    let mut wallet_state_db: tokio::sync::MutexGuard<RustyWalletDatabase> =
                        self.global_state.wallet_state.wallet_db.lock().await;
                    let mut block_db_lock: tokio::sync::MutexGuard<
                        RustyLevelDB<BlockIndexKey, BlockIndexValue>,
                    > = self
                        .global_state
                        .chain
                        .archival_state
                        .as_ref()
                        .unwrap()
                        .block_index_db
                        .lock()
                        .await;
                    let mut ams_lock = self
                        .global_state
                        .chain
                        .archival_state
                        .as_ref()
                        .unwrap()
                        .archival_mutator_set
                        .lock()
                        .await;
                    let mut light_state_locked: tokio::sync::MutexGuard<Block> = self
                        .global_state
                        .chain
                        .light_state
                        .latest_block
                        .lock()
                        .await;
                    let mut mempool_write_lock: std::sync::RwLockWriteGuard<MempoolInternal> = self
                        .global_state
                        .mempool
                        .internal
                        .write()
                        .expect("Locking mempool for write must succeed");

                    // The peer threads also check this condition, if block is more canonical than current
                    // tip, but we have to check it again since the block update might have already been applied
                    // through a message from another peer.
                    // TODO: Is this check right? We might still want to store the blocks even though
                    // they are not more canonical than what we currently have, in the case of deep reorganizations
                    // that is. This check fails to correctly resolve deep reorganizations. Should that be fixed,
                    // or should deep reorganizations simply be fixed by clearing the database?
                    let block_is_new = light_state_locked.header.proof_of_work_family
                        < last_block.header.proof_of_work_family;
                    if !block_is_new {
                        warn!("Blocks were not new. Not storing blocks.");

                        // TODO: Consider fixing deep reorganization problem described above.
                        // Alternatively set the `max_number_of_blocks_before_syncing` value higher
                        // if this problem is encountered.
                        return Ok(());
                    }

                    // Get out of sync mode if needed
                    if self.global_state.net.syncing.read().unwrap().to_owned() {
                        let stay_in_sync_mode = stay_in_sync_mode(
                            last_block.header.clone(),
                            &main_loop_state.sync_state,
                            self.global_state.cli.max_number_of_blocks_before_syncing,
                        );
                        if !stay_in_sync_mode {
                            info!("Exiting sync mode");
                            *self.global_state.net.syncing.write().unwrap() = false;
                        }
                    }

                    for new_block in blocks {
                        debug!(
                            "Storing block {} in database. Height: {}",
                            new_block.hash.emojihash(),
                            new_block.header.height
                        );
                        self.global_state
                            .chain
                            .archival_state
                            .as_ref()
                            .unwrap()
                            .write_block(
                                Box::new(new_block.clone()),
                                &mut block_db_lock,
                                Some(light_state_locked.header.proof_of_work_family),
                            )?;

                        // update the mutator set with the UTXOs from this block
                        self.global_state
                            .chain
                            .archival_state
                            .as_ref()
                            .unwrap()
                            .update_mutator_set(&mut block_db_lock, &mut ams_lock, &new_block)?;

                        // update wallet state with relevant UTXOs from this block
                        self.global_state
                            .wallet_state
                            .update_wallet_state_with_new_block(&new_block, &mut wallet_state_db)?;

                        // Update mempool with UTXOs from this block. This is done by removing all transaction
                        // that became invalid/was mined by this block.
                        self.global_state
                            .mempool
                            .update_with_block(&new_block, &mut mempool_write_lock);
                    }

                    // Update information about latest block
                    *light_state_locked = last_block.clone();
                }

                // Flush databases
                self.flush_databases().await?;

                // Inform miner to work on a new block
                if self.global_state.cli.mine {
                    self.main_to_miner_tx
                        .send(MainToMiner::NewBlock(Box::new(last_block.clone())))?;
                }

                // Inform all peers about new block
                self.main_to_peer_broadcast_tx
                    .send(MainToPeerThread::Block(Box::new(last_block)))
                    .expect("Peer handler broadcast was closed. This should never happen");
            }
            PeerThreadToMain::AddPeerMaxBlockHeight((
                socket_addr,
                claimed_max_height,
                claimed_max_pow_family,
            )) => {
                let claimed_state =
                    PeerSynchronizationState::new(claimed_max_height, claimed_max_pow_family);
                main_loop_state
                    .sync_state
                    .peer_sync_states
                    .insert(socket_addr, claimed_state);

                // Check if synchronization mode should be activated. Synchronization mode is entered if
                // PoW family exceeds our tip and if the height difference is beyond a threshold value.
                // TODO: If we are not checking the PoW claims of the tip this can be abused by forcing
                // the client into synchronization mode.
                let our_block_tip_header: BlockHeader = self
                    .global_state
                    .chain
                    .light_state
                    .get_latest_block_header()
                    .await;
                if enter_sync_mode(
                    our_block_tip_header,
                    claimed_state,
                    self.global_state.cli.max_number_of_blocks_before_syncing / 3,
                ) {
                    info!(
                    "Entering synchronization mode due to peer {} indicating tip height {}; pow family: {:?}",
                    socket_addr, claimed_max_height, claimed_max_pow_family
                );
                    *self.global_state.net.syncing.write().unwrap() = true;
                }
            }
            PeerThreadToMain::RemovePeerMaxBlockHeight(socket_addr) => {
                debug!(
                    "Removing max block height from sync data structure for peer {}",
                    socket_addr
                );
                main_loop_state
                    .sync_state
                    .peer_sync_states
                    .remove(&socket_addr);

                // Get out of sync mode if needed. Note that we do not need to hold
                // a lock on any state, as it's only this thread (main thread) that
                // is allowed to update the `BlockchainState` or the `syncing` state.
                let tip_header: BlockHeader = self
                    .global_state
                    .chain
                    .light_state
                    .get_latest_block_header()
                    .await;

                if self.global_state.net.syncing.read().unwrap().to_owned() {
                    let stay_in_sync_mode = stay_in_sync_mode(
                        tip_header,
                        &main_loop_state.sync_state,
                        self.global_state.cli.max_number_of_blocks_before_syncing,
                    );
                    if !stay_in_sync_mode {
                        info!("Exiting sync mode");
                        *self.global_state.net.syncing.write().unwrap() = false;
                    }
                }
            }
            PeerThreadToMain::PeerDiscoveryAnswer((pot_peers, reported_by, distance)) => {
                let max_peers = self.global_state.cli.max_peers;
                for pot_peer in pot_peers {
                    main_loop_state.potential_peers.add(
                        reported_by,
                        pot_peer,
                        max_peers as usize,
                        distance,
                    );
                }
            }
            PeerThreadToMain::Transaction(pt2m_transaction) => {
                debug!(
                    "`peer_loop` received following transaction from peer. {} inputs, {} outputs. Synced to mutator set hash: {}",
                    pt2m_transaction.transaction.kernel.inputs.len(),
                    pt2m_transaction.transaction.kernel.outputs.len(),
                    pt2m_transaction.transaction.kernel.mutator_set_hash
                );

                if pt2m_transaction.confirmable_for_block
                    != self
                        .global_state
                        .chain
                        .light_state
                        .latest_block
                        .lock()
                        .await
                        .hash
                {
                    warn!("main loop got unmined transaction with bad mutator set data, discarding transaction");
                    return Ok(());
                }

                // Insert into mempool
                self.global_state
                    .mempool
                    .insert(&pt2m_transaction.transaction);

                // send notification to peers
                let transaction_notification: TransactionNotification =
                    pt2m_transaction.transaction.into();
                self.main_to_peer_broadcast_tx
                    .send(MainToPeerThread::TransactionNotification(
                        transaction_notification,
                    ))?;
            }
        }

        Ok(())
    }

    /// Function to perform peer discovery: Finds potential peers from connected peers and attempts
    /// to establish connections with one of those potential peers.
    async fn peer_discovery_and_reconnector(
        &self,
        main_loop_state: &mut MutableMainLoopState,
    ) -> Result<()> {
        let connected_peers: Vec<PeerInfo> = match self.global_state.net.peer_map.try_lock() {
            Ok(pm) => pm.values().cloned().collect(),
            Err(_) => return Ok(()),
        };

        // Check if we are connected to too many peers
        if connected_peers.len() > self.global_state.cli.max_peers as usize {
            // This would indicate a race-condition on the peer map field in the state which
            // we unfortunately cannot exclude. So we just disconnect from a peer that the user
            // didn't request a connection to.
            warn!(
            "Max peer parameter is exceeded. max is {} but we are connected to {}. Attempting to fix.",
            connected_peers.len(),
            self.global_state.cli.max_peers
        );
            let mut rng = thread_rng();

            // pick a peer that was not specified in the CLI arguments to disconnect from
            let peer_to_disconnect = connected_peers
                .iter()
                .filter(|peer| {
                    !self
                        .global_state
                        .cli
                        .peers
                        .contains(&peer.connected_address)
                })
                .choose(&mut rng);
            match peer_to_disconnect {
                Some(peer) => {
                    self.main_to_peer_broadcast_tx
                        .send(MainToPeerThread::Disconnect(peer.connected_address))?;
                }
                None => warn!("Unable to resolve max peer constraint due to manual override."),
            };

            return Ok(());
        }

        // Check if we lost connection to any of the peers specified in the peers CLI list.
        // If we did, attempt to reconnect.
        let connected_peer_addresses = connected_peers
            .iter()
            .map(|x| x.connected_address)
            .collect_vec();
        let peers_with_lost_connection = self
            .global_state
            .cli
            .peers
            .iter()
            .filter(|peer| !connected_peer_addresses.contains(peer))
            .cloned()
            .collect_vec();
        for peer_with_lost_connection in peers_with_lost_connection {
            // Disallow reconnection if peer is in bad standing
            let standing = self
                .global_state
                .get_peer_standing_from_database(peer_with_lost_connection.ip())
                .await;

            if standing.is_some()
                && standing.unwrap().standing < -(self.global_state.cli.peer_tolerance as i32)
            {
                info!("Not reconnecting to peer with lost connection because it was banned: {peer_with_lost_connection}");
            } else {
                info!(
                    "Attempting to reconnect to peer with lost connection: {peer_with_lost_connection}"
                );
            }

            let own_handshake_data: HandshakeData = self.global_state.get_own_handshakedata().await;
            let main_to_peer_broadcast_rx = self.main_to_peer_broadcast_tx.subscribe();
            let state_clone = self.global_state.to_owned();
            let peer_thread_to_main_tx_clone = self.peer_thread_to_main_tx.to_owned();
            let outgoing_connection_thread = tokio::spawn(async move {
                call_peer_wrapper(
                    peer_with_lost_connection,
                    state_clone,
                    main_to_peer_broadcast_rx,
                    peer_thread_to_main_tx_clone,
                    own_handshake_data,
                    1, // All CLI-specified peers have distance 1 by definition
                )
                .await;
            });
            main_loop_state
                .thread_handles
                .push(outgoing_connection_thread);
            main_loop_state
                .thread_handles
                .retain(|th| !th.is_finished());
        }

        // We don't make an outgoing connection if we've reached the peer limit, *or* if we are
        // one below the peer limit as we reserve this last slot for an ingoing connection.
        if connected_peers.len() == self.global_state.cli.max_peers as usize
            || connected_peers.len() > 2
                && connected_peers.len() - 1 == self.global_state.cli.max_peers as usize
        {
            return Ok(());
        }

        info!("Performing peer discovery");
        // Potential procedure for peer discovey:
        // 0) Ask all peers for their peer lists
        // 1) Get peer candidate from these responses
        // 2) Connect to one of those peers, A.
        // 3) Ask this newly connected peer, A, for its peers.
        // 4) Connect to one of those peers
        // 5) Disconnect from A. (not yet implemented)

        // 0)
        self.main_to_peer_broadcast_tx
            .send(MainToPeerThread::MakePeerDiscoveryRequest)?;

        // 1)
        let (peer_candidate, candidate_distance) =
            match main_loop_state.potential_peers.get_distant_candidate(
                &connected_peers,
                self.global_state.cli.get_own_listen_address(),
                self.global_state.net.instance_id,
            ) {
                Some(candidate) => candidate,
                None => return Ok(()),
            };

        // 2)
        info!(
            "Connecting to peer {} with distance {}",
            peer_candidate, candidate_distance
        );
        let own_handshake_data: HandshakeData = self.global_state.get_own_handshakedata().await;
        let main_to_peer_broadcast_rx = self.main_to_peer_broadcast_tx.subscribe();
        let state_clone = self.global_state.to_owned();
        let peer_thread_to_main_tx_clone = self.peer_thread_to_main_tx.to_owned();
        let outgoing_connection_thread = tokio::spawn(async move {
            call_peer_wrapper(
                peer_candidate,
                state_clone,
                main_to_peer_broadcast_rx,
                peer_thread_to_main_tx_clone,
                own_handshake_data,
                candidate_distance,
            )
            .await;
        });
        main_loop_state
            .thread_handles
            .push(outgoing_connection_thread);
        main_loop_state
            .thread_handles
            .retain(|th| !th.is_finished());

        // 3
        self.main_to_peer_broadcast_tx
            .send(MainToPeerThread::MakeSpecificPeerDiscoveryRequest(
                peer_candidate,
            ))?;

        // 4 is completed in the next call to this function provided that the in (3) connected
        // peer responded to the peer list request.

        Ok(())
    }

    /// Logic for requesting the batch-download of blocks from peers
    async fn block_sync(&self, main_loop_state: &mut MutableMainLoopState) -> Result<()> {
        // Check if we are in sync mode
        if !self.global_state.net.syncing.read().unwrap().to_owned() {
            return Ok(());
        }

        info!("Running sync");

        // Check when latest batch of blocks was requested
        let current_block = match self.global_state.chain.light_state.latest_block.try_lock() {
            Ok(lock) => lock.to_owned(),

            // If we can't acquire lock on latest block header, don't block. Just exit and try again next
            // time.
            Err(_) => {
                warn!("Could not read current block. Aborting block synchronization");
                return Ok(());
            }
        };

        let (peer_to_sanction, try_new_request): (Option<SocketAddr>, bool) = main_loop_state
            .sync_state
            .get_status_of_last_request(current_block.header.height);

        // Sanction peer if they failed to respond
        if let Some(peer) = peer_to_sanction {
            self.main_to_peer_broadcast_tx
                .send(MainToPeerThread::PeerSynchronizationTimeout(peer))?;
        }

        if !try_new_request {
            info!("Waiting for last sync to complete.");
            return Ok(());
        }

        // Create the next request from the reported
        info!("Creating new sync request");

        // Pick a random peer that has reported to have relevant blocks
        let candidate_peers = main_loop_state
            .sync_state
            .get_potential_peers_for_sync_request(current_block.header.proof_of_work_family);
        let mut rng = thread_rng();
        let chosen_peer = candidate_peers.choose(&mut rng);
        assert!(
            chosen_peer.is_some(),
            "A synchronization candidate must be available for a request. Otherwise the data structure is in an invalid state and syncing should not be active"
        );

        // Find the blocks to request
        let tip_digest = current_block.hash;
        let most_canonical_digests = self
            .global_state
            .chain
            .archival_state
            .as_ref()
            .unwrap()
            .get_ancestor_block_digests(tip_digest, STANDARD_BATCH_BLOCK_LOOKBEHIND_SIZE)
            .await;

        // List of digests, ordered after which block we would like to find descendents from,
        // from highest to lowest.
        let most_canonical_digests = vec![vec![tip_digest], most_canonical_digests].concat();

        // Send message to the relevant peer loop to request the blocks
        let chosen_peer = chosen_peer.unwrap();
        info!(
            "Sending block batch request to {}\nrequesting blocks descending from {}\n height {}",
            chosen_peer,
            current_block.hash.emojihash(),
            current_block.header.height
        );
        self.main_to_peer_broadcast_tx
            .send(MainToPeerThread::RequestBlockBatch(
                most_canonical_digests,
                *chosen_peer,
            ))
            .expect("Sending message to peers must succeed");

        // Record that this request was sent to the peer
        let requested_block_height = current_block.header.height.next();
        main_loop_state
            .sync_state
            .record_request(requested_block_height, *chosen_peer);

        Ok(())
    }

    pub async fn run(
        &self,
        mut peer_thread_to_main_rx: mpsc::Receiver<PeerThreadToMain>,
        mut miner_to_main_rx: mpsc::Receiver<MinerToMain>,
        mut rpc_server_to_main_rx: mpsc::Receiver<RPCServerToMain>,
        thread_handles: Vec<JoinHandle<()>>,
    ) -> Result<()> {
        // Handle incoming connections, messages from peer threads, and messages from the mining thread
        let mut main_loop_state = MutableMainLoopState::new(thread_handles);

        // Set peer discovery to run every N seconds. The timer must be reset every time it has run.
        let peer_discovery_timer_interval = Duration::from_secs(PEER_DISCOVERY_INTERVAL_IN_SECONDS);
        let peer_discovery_timer = time::sleep(peer_discovery_timer_interval);
        tokio::pin!(peer_discovery_timer);

        // Set synchronization to run every M seconds. The timer must be reset every time it has run.
        let sync_timer_interval = Duration::from_secs(SYNC_REQUEST_INTERVAL_IN_SECONDS);
        let synchronization_timer = time::sleep(sync_timer_interval);
        tokio::pin!(synchronization_timer);

        // Set removal of transactions from mempool that have timed out to run every P seconds
        let mempool_cleanup_timer_interval = Duration::from_secs(MEMPOOL_PRUNE_INTERVAL_IN_SECS);
        let mempool_cleanup_timer = time::sleep(mempool_cleanup_timer_interval);
        tokio::pin!(mempool_cleanup_timer);

        // Set removal of stale notifications for incoming UTXOs
        let utxo_notification_cleanup_timer_interval =
            Duration::from_secs(UTXO_NOTIFICATION_POOL_PRUNE_INTERVAL_IN_SECS);
        let utxo_notification_cleanup_timer = time::sleep(utxo_notification_cleanup_timer_interval);
        tokio::pin!(utxo_notification_cleanup_timer);

        // Set restoration of membership proofs to run every Q seconds
        let mp_resync_timer_interval = Duration::from_secs(MP_RESYNC_INTERVAL_IN_SECS);
        let mp_resync_timer = time::sleep(mp_resync_timer_interval);
        tokio::pin!(mp_resync_timer);

        // Handle SIGTERM and SIGINT signals on Unix systems
        #[cfg(unix)]
        let (sigterm, sigint, sigquit) = {
            use tokio::signal::unix::{signal, SignalKind};
            let sigterm = signal(SignalKind::terminate())?;
            let sigint = signal(SignalKind::interrupt())?;
            let sigquit = signal(SignalKind::quit())?;
            (Some(sigterm), Some(sigint), Some(sigquit))
        };
        #[cfg(not(unix))]
        let (mut sigterm, mut sigint, mut sigquit, mut sighup) = (None, None, None);

        // Spawn threads to monitor for SIGTERM, SIGINT, and SIGQUIT
        let (tx_term, mut rx_term) = tokio::sync::mpsc::channel(2);
        if let Some(mut sigterm_stream) = sigterm {
            tokio::spawn(async move {
                if sigterm_stream.recv().await.is_some() {
                    info!("Received SIGTERM");
                    tx_term.send(()).await.unwrap();
                }
            });
        }
        let (tx_int, mut rx_int) = tokio::sync::mpsc::channel(2);
        if let Some(mut sigint_stream) = sigint {
            tokio::spawn(async move {
                if sigint_stream.recv().await.is_some() {
                    info!("Received SIGINT");
                    tx_int.send(()).await.unwrap();
                }
            });
        }
        let (tx_quit, mut rx_quit) = tokio::sync::mpsc::channel(2);
        if let Some(mut sigquit_stream) = sigquit {
            tokio::spawn(async move {
                if sigquit_stream.recv().await.is_some() {
                    info!("Received SIGQUIT");
                    tx_quit.send(()).await.unwrap();
                }
            });
        }

        loop {
            select! {
                Ok(()) = signal::ctrl_c() => {
                    info!("Detected Ctrl+c signal.");
                    break;
                }

                // Monitor for SIGTERM, SIGINT, and SIGQUIT. SIGHUP is ignored.
                Some(_) = rx_term.recv() => {
                    info!("Detected SIGTERM signal.");
                    break;
                }
                Some(_) = rx_int.recv() => {
                    info!("Detected SIGINT signal.");
                    break;
                }
                Some(_) = rx_quit.recv() => {
                    info!("Detected SIGQUIT signal.");
                    break;
                }

                // Handle incoming connections from peer
                Ok((stream, _)) = self.incoming_peer_listener.accept() => {
                    let state = self.global_state.clone();
                    let main_to_peer_broadcast_rx_clone: broadcast::Receiver<MainToPeerThread> = self.main_to_peer_broadcast_tx.subscribe();
                    let peer_thread_to_main_tx_clone: mpsc::Sender<PeerThreadToMain> = self.peer_thread_to_main_tx.clone();
                    let peer_address = stream.peer_addr().unwrap();
                    let own_handshake_data: HandshakeData = state.get_own_handshakedata().await;
                    let incoming_peer_thread_handle = tokio::spawn(async move {
                        match answer_peer_wrapper(
                            stream,
                            state,
                            peer_address,
                            main_to_peer_broadcast_rx_clone,
                            peer_thread_to_main_tx_clone,
                            own_handshake_data,
                        ).await {
                            Ok(()) => (),
                            Err(err) => error!("Got error: {:?}", err),
                        }
                    });
                    main_loop_state.thread_handles.push(incoming_peer_thread_handle);
                    main_loop_state.thread_handles.retain(|th| !th.is_finished());
                }

                // Handle messages from peer threads
                Some(msg) = peer_thread_to_main_rx.recv() => {
                    debug!("Received message sent to main thread.");
                    self.handle_peer_thread_message(
                        msg,
                        &mut main_loop_state,
                    )
                    .await?
                }

                // Handle messages from miner thread
                Some(main_message) = miner_to_main_rx.recv() => {
                    self.handle_miner_thread_message(main_message).await?
                }

                // Handle messages from rpc server thread
                Some(rpc_server_message) = rpc_server_to_main_rx.recv() => {
                    let shutdown_after_execution = self.handle_rpc_server_message(rpc_server_message.clone()).await?;
                    if shutdown_after_execution {
                        break
                    }
                }

                // Handle peer discovery
                _ = &mut peer_discovery_timer => {
                    // Check number of peers we are connected to and connect to more peers
                    // if needed.
                    debug!("Running peer discovery job");
                    self.peer_discovery_and_reconnector(&mut main_loop_state).await?;

                    // Reset the timer to run this branch again in N seconds
                    peer_discovery_timer.as_mut().reset(tokio::time::Instant::now() + peer_discovery_timer_interval);
                }

                // Handle synchronization (i.e. batch-downloading of blocks)
                _ = &mut synchronization_timer => {
                    debug!("Running block-synchronization job");
                    self.block_sync(&mut main_loop_state).await?;

                    // Reset the timer to run this branch again in M seconds
                    synchronization_timer.as_mut().reset(tokio::time::Instant::now() + sync_timer_interval);
                }

                // Handle mempool cleanup, i.e. removing stale/too old txs from mempool
                _ = &mut mempool_cleanup_timer => {
                    debug!("Running mempool-cleaner job");
                    self.global_state.mempool.prune_stale_transactions();

                    // Reset the timer to run this branch again in P seconds
                    mempool_cleanup_timer.as_mut().reset(tokio::time::Instant::now() + mempool_cleanup_timer_interval);
                }

                // Handle incoming UTXO notification cleanup, i.e. removing stale/too old UTXO notification from pool
                _ = &mut utxo_notification_cleanup_timer => {
                    debug!("Running UTXO notification pool cleanup job");
                    self.global_state.wallet_state.expected_utxos.write().unwrap().prune_stale_utxo_notifications();

                    utxo_notification_cleanup_timer.as_mut().reset(tokio::time::Instant::now() + utxo_notification_cleanup_timer_interval);
                }

                // Handle membership proof resynchronization
                _ = &mut mp_resync_timer => {
                    debug!("Running Membership proof resync job");
                    self.resync_membership_proofs().await?;

                    mp_resync_timer.as_mut().reset(tokio::time::Instant::now() + mp_resync_timer_interval);
                }
            }
        }

        self.graceful_shutdown(main_loop_state.thread_handles)
            .await?;
        info!("Shutdown completed.");

        Ok(())
    }

    async fn resync_membership_proofs(&self) -> Result<()> {
        // Do not fix memberhip proofs if node is in sync mode, as we would otherwise
        // have to sync many times, instead of just *one* time once we have caught up.
        if *self.global_state.net.syncing.read().unwrap() {
            debug!("Not syncing MS membership proofs because we are syncing");
            return Ok(());
        }

        // is it necessary?
        let current_tip_digest = self
            .global_state
            .chain
            .light_state
            .latest_block
            .lock()
            .await
            .hash;
        if self
            .global_state
            .wallet_state
            .is_synced_to(current_tip_digest)
            .await
        {
            debug!("Membership proof syncing not needed");
            return Ok(());
        }

        // do we have blocks?
        let we_have_blocks = self.global_state.chain.archival_state.is_some();
        if we_have_blocks {
            return self
                .global_state
                .resync_membership_proofs_to_tip(current_tip_digest)
                .await;
        }

        // request blocks from peers
        todo!("We don't yet support non-archival nodes");

        // Ok(())
    }

    /// Handle messages from the RPC server. Returns `true` iff the client should shut down
    /// after handling this message.
    async fn handle_rpc_server_message(&self, msg: RPCServerToMain) -> Result<bool> {
        match msg {
            RPCServerToMain::Send(transaction) => {
                debug!(
                    "`main` received following transaction from RPC Server. {} inputs, {} outputs. Synced to mutator set hash: {}",
                    transaction.kernel.inputs.len(),
                    transaction.kernel.outputs.len(),
                    transaction.kernel.mutator_set_hash
                );

                // send notification to peers
                let notification: TransactionNotification = transaction.as_ref().clone().into();
                self.main_to_peer_broadcast_tx
                    .send(MainToPeerThread::TransactionNotification(notification))?;

                // insert transaction into mempool
                self.global_state.mempool.insert(&transaction);

                // do not shut down
                Ok(false)
            }
            RPCServerToMain::PauseMiner => {
                info!("Received RPC request to stop miner");

                self.main_to_miner_tx.send(MainToMiner::StopMining)?;
                Ok(false)
            }
            RPCServerToMain::RestartMiner => {
                info!("Received RPC request to start miner");
                self.main_to_miner_tx.send(MainToMiner::StartMining)?;
                Ok(false)
            }
            RPCServerToMain::Shutdown => {
                info!("Recived RPC shutdown request.");

                // shut down
                Ok(true)
            }
        }
    }

    async fn flush_databases(&self) -> Result<()> {
        // flush wallet databases
        self.global_state
            .wallet_state
            .wallet_db
            .as_ref()
            .lock()
            .await
            .persist();

        // flush block_index database
        self.global_state
            .chain
            .archival_state
            .as_ref()
            .unwrap()
            .block_index_db
            .lock()
            .await
            .flush();

        // persist archival_mutator_set, with sync label
        self.global_state
            .chain
            .archival_state
            .as_ref()
            .unwrap()
            .archival_mutator_set
            .lock()
            .await
            .set_sync_label(
                self.global_state
                    .chain
                    .archival_state
                    .as_ref()
                    .unwrap()
                    .get_latest_block()
                    .await
                    .hash,
            );
        self.global_state
            .chain
            .archival_state
            .as_ref()
            .unwrap()
            .archival_mutator_set
            .lock()
            .await
            .persist();

        // flush peer_standings
        self.global_state
            .net
            .peer_databases
            .as_ref()
            .lock()
            .await
            .peer_standings
            .flush();
        debug!("Flushed all databases");

        Ok(())
    }

    async fn graceful_shutdown(&self, thread_handles: Vec<JoinHandle<()>>) -> Result<()> {
        info!("Shutdown initiated.");

        // Stop mining
        let __result = self.main_to_miner_tx.send(MainToMiner::Shutdown);

        // Send 'bye' message to all peers.
        let _result = self
            .main_to_peer_broadcast_tx
            .send(MainToPeerThread::DisconnectAll());
        debug!("sent bye");

        // Flush all databases
        self.flush_databases().await?;

        // wait 0.5 seconds to ensure that child processes have been shut down
        sleep(Duration::new(0, 500 * 1_000_000));

        // Child processes should have finished by now. If not, abort them violently.
        for jh in thread_handles {
            jh.abort();
        }

        // wait 0.5 seconds to ensure that child processes have been shut down
        sleep(Duration::new(0, 500 * 1_000_000));

        Ok(())
    }
}
