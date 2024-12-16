pub mod proof_upgrader;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::SystemTime;

use anyhow::Result;
use itertools::Itertools;
use proof_upgrader::get_upgrade_task_from_mempool;
use proof_upgrader::UpdateMutatorSetDataJob;
use proof_upgrader::UpgradeJob;
use rand::prelude::IteratorRandom;
use rand::prelude::SliceRandom;
use rand::thread_rng;
use tokio::net::TcpListener;
use tokio::select;
use tokio::signal;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::trace;
use tracing::warn;

use crate::connect_to_peers::answer_peer;
use crate::connect_to_peers::call_peer;
use crate::job_queue::triton_vm::TritonVmJobPriority;
use crate::job_queue::triton_vm::TritonVmJobQueue;
use crate::macros::fn_name;
use crate::macros::log_slow_scope;
use crate::models::blockchain::block::block_header::BlockHeader;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::difficulty_control::ProofOfWork;
use crate::models::blockchain::transaction::Transaction;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::channel::MainToMiner;
use crate::models::channel::MainToPeerTask;
use crate::models::channel::MainToPeerTaskBatchBlockRequest;
use crate::models::channel::MinerToMain;
use crate::models::channel::PeerTaskToMain;
use crate::models::channel::RPCServerToMain;
use crate::models::peer::transaction_notification::TransactionNotification;
use crate::models::peer::HandshakeData;
use crate::models::peer::PeerInfo;
use crate::models::peer::PeerSynchronizationState;
use crate::models::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::models::state::block_proposal::BlockProposal;
use crate::models::state::mempool::TransactionOrigin;
use crate::models::state::tx_proving_capability::TxProvingCapability;
use crate::models::state::GlobalState;
use crate::models::state::GlobalStateLock;

const PEER_DISCOVERY_INTERVAL_IN_SECONDS: u64 = 120;
const SYNC_REQUEST_INTERVAL_IN_SECONDS: u64 = 3;
const MEMPOOL_PRUNE_INTERVAL_IN_SECS: u64 = 30 * 60; // 30mins
const MP_RESYNC_INTERVAL_IN_SECS: u64 = 59;
const EXPECTED_UTXOS_PRUNE_INTERVAL_IN_SECS: u64 = 19 * 60; // 19 mins

/// Interval for when transaction-upgrade checker is run. Note that this does
/// *not* define how often a transaction-proof upgrade is actually performed.
/// Only how often we check if we're ready to perform an upgrade.
const TRANSACTION_UPGRADE_CHECK_INTERVAL_IN_SECONDS: u64 = 60; // 1 minute

const SANCTION_PEER_TIMEOUT_FACTOR: u64 = 40;
const POTENTIAL_PEER_MAX_COUNT_AS_A_FACTOR_OF_MAX_PEERS: usize = 20;
const STANDARD_BATCH_BLOCK_LOOKBEHIND_SIZE: usize = 100;
const TX_UPDATER_CHANNEL_CAPACITY: usize = 1;

/// Wraps a transmission channel.
///
/// To be used for the transmission channel to the miner, because
///  a) the miner might not exist in which case there would be no-one to empty
///     the channel; and
///  b) contrary to other channels, transmission failures here are not critical.
struct MainToMinerChannel(Option<mpsc::Sender<MainToMiner>>);

impl MainToMinerChannel {
    /// Send a message to the miner task (if any).
    fn send(&self, message: MainToMiner) {
        // Do no use the async `send` function because it blocks until there
        // is spare capacity on the channel. Messages to the miner are not
        // critical so if there is no capacity left, just log an error
        // message.
        if let Some(channel) = &self.0 {
            if let Err(e) = channel.try_send(message) {
                error!("Failed to send pause message to miner thread:\n{e}");
            }
        }
    }
}

/// MainLoop is the immutable part of the input for the main loop function
pub struct MainLoopHandler {
    incoming_peer_listener: TcpListener,
    global_state_lock: GlobalStateLock,
    main_to_peer_broadcast_tx: broadcast::Sender<MainToPeerTask>,
    peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,
    main_to_miner_tx: MainToMinerChannel,

    #[cfg(test)]
    mock_now: Option<SystemTime>,
}

/// The mutable part of the main loop function
struct MutableMainLoopState {
    sync_state: SyncState,
    potential_peers: PotentialPeersState,
    task_handles: Vec<JoinHandle<()>>,
    proof_upgrader_task: Option<JoinHandle<()>>,

    /// A joinhandle to a task running the update of the mempool transactions.
    update_mempool_txs_handle: Option<JoinHandle<()>>,

    /// A channel that the task updating mempool transactions can use to
    /// communicate its result.
    update_mempool_receiver: mpsc::Receiver<Vec<Transaction>>,
}

impl MutableMainLoopState {
    fn new(task_handles: Vec<JoinHandle<()>>) -> Self {
        let (_dummy_sender, dummy_receiver) =
            mpsc::channel::<Vec<Transaction>>(TX_UPDATER_CHANNEL_CAPACITY);
        Self {
            sync_state: SyncState::default(),
            potential_peers: PotentialPeersState::default(),
            task_handles,
            proof_upgrader_task: None,
            update_mempool_txs_handle: None,
            update_mempool_receiver: dummy_receiver,
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

    fn record_request(
        &mut self,
        requested_block_height: BlockHeight,
        peer: SocketAddr,
        now: SystemTime,
    ) {
        self.last_sync_request = Some((now, requested_block_height, peer));
    }

    /// Return a list of peers that have reported to be in possession of blocks
    /// with a PoW above a threshold.
    fn get_potential_peers_for_sync_request(&self, threshold_pow: ProofOfWork) -> Vec<SocketAddr> {
        self.peer_sync_states
            .iter()
            .filter(|(_sa, sync_state)| sync_state.claimed_max_pow > threshold_pow)
            .map(|(sa, _)| *sa)
            .collect()
    }

    /// Determine if a peer should be sanctioned for failing to respond to a synchronization
    /// request. Also determine if a new request should be made or the previous one should be
    /// allowed to run for longer.
    fn get_status_of_last_request(
        &self,
        current_block_height: BlockHeight,
        now: SystemTime,
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
                    < now
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
    fn new(reported_by: SocketAddr, instance_id: u128, distance: u8, now: SystemTime) -> Self {
        Self {
            _reported: now,
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
        now: SystemTime,
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
            PotentialPeerInfo::new(reported_by, potential_peer_instance_id, distance, now);
        self.potential_peers
            .insert(potential_peer_socket_address, insert_value);
    }

    /// Return a peer from the potential peer list that we aren't connected to
    /// and  that isn't our own address.
    ///
    /// Favors peers with a high distance and with IPs that we are not already
    /// connected to.
    ///
    /// Returns (socket address, peer distance)
    fn get_candidate(
        &self,
        connected_clients: &[PeerInfo],
        own_instance_id: u128,
    ) -> Option<(SocketAddr, u8)> {
        let peers_instance_ids: Vec<u128> =
            connected_clients.iter().map(|x| x.instance_id()).collect();

        // Only pick those peers that report a listening port
        let peers_listen_addresses: Vec<SocketAddr> = connected_clients
            .iter()
            .filter_map(|x| x.listen_address())
            .collect();

        // Find the appropriate candidates
        let candidates = self
            .potential_peers
            .iter()
            // Prevent connecting to self. Note that we *only* use instance ID to prevent this,
            // meaning this will allow multiple nodes e.g. running on the same computer to form
            // a complete graph.
            .filter(|pp| pp.1.instance_id != own_instance_id)
            // Prevent connecting to peer we already are connected to
            .filter(|potential_peer| !peers_instance_ids.contains(&potential_peer.1.instance_id))
            .filter(|potential_peer| !peers_listen_addresses.contains(potential_peer.0))
            .collect::<Vec<_>>();

        // Prefer candidates with IPs that we are not already connected to but
        // connect to repeated IPs in case we don't have other options, as
        // repeated IPs may just be multiple machines on the same NAT'ed IPv4
        // address.
        let mut connected_ips = peers_listen_addresses.into_iter().map(|x| x.ip());
        let candidates = if candidates
            .iter()
            .any(|candidate| !connected_ips.contains(&candidate.0.ip()))
        {
            candidates
                .into_iter()
                .filter(|candidate| !connected_ips.contains(&candidate.0.ip()))
                .collect()
        } else {
            candidates
        };

        // Get the candidate list with the highest distance
        let max_distance_candidates = candidates.iter().max_by_key(|pp| pp.1.distance);

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
    own_block_tip_header: &BlockHeader,
    peer_synchronization_state: PeerSynchronizationState,
    max_number_of_blocks_before_syncing: usize,
) -> bool {
    own_block_tip_header.cumulative_proof_of_work < peer_synchronization_state.claimed_max_pow
        && peer_synchronization_state.claimed_max_height - own_block_tip_header.height
            > max_number_of_blocks_before_syncing as i128
}

/// Return a boolean indicating if synchronization mode should be left
fn stay_in_sync_mode(
    own_block_tip_header: &BlockHeader,
    sync_state: &SyncState,
    max_number_of_blocks_before_syncing: usize,
) -> bool {
    let max_claimed_pow = sync_state
        .peer_sync_states
        .values()
        .max_by_key(|x| x.claimed_max_pow);
    match max_claimed_pow {
        None => false, // we lost all connections. Can't sync.

        // Synchronization is left when the remaining number of block is half of what has
        // been indicated to fit into RAM
        Some(max_claim) => {
            own_block_tip_header.cumulative_proof_of_work < max_claim.claimed_max_pow
                && max_claim.claimed_max_height - own_block_tip_header.height
                    > max_number_of_blocks_before_syncing as i128 / 2
        }
    }
}

impl MainLoopHandler {
    pub(crate) fn new(
        incoming_peer_listener: TcpListener,
        global_state_lock: GlobalStateLock,
        main_to_peer_broadcast_tx: broadcast::Sender<MainToPeerTask>,
        peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,
        main_to_miner_tx: mpsc::Sender<MainToMiner>,
    ) -> Self {
        let maybe_main_to_miner_tx = if global_state_lock.cli().mine() {
            Some(main_to_miner_tx)
        } else {
            None
        };
        Self {
            incoming_peer_listener,
            global_state_lock,
            main_to_miner_tx: MainToMinerChannel(maybe_main_to_miner_tx),
            main_to_peer_broadcast_tx,
            peer_task_to_main_tx,
            #[cfg(test)]
            mock_now: None,
        }
    }

    /// Allows for mocked timestamps such that time dependencies may be tested.
    #[cfg(test)]
    fn with_mocked_time(mut self, mocked_time: SystemTime) -> Self {
        self.mock_now = Some(mocked_time);
        self
    }

    fn now(&self) -> SystemTime {
        #[cfg(not(test))]
        {
            SystemTime::now()
        }
        #[cfg(test)]
        {
            self.mock_now.unwrap_or(SystemTime::now())
        }
    }

    /// Run a list of Triton VM prover jobs that updates the mutator set state
    /// for transactions.
    ///
    /// Sends the result back through the provided channel.
    async fn update_mempool_jobs(
        update_jobs: Vec<UpdateMutatorSetDataJob>,
        job_queue: &TritonVmJobQueue,
        transcation_update_sender: mpsc::Sender<Vec<Transaction>>,
        proof_job_options: TritonVmProofJobOptions,
    ) {
        debug!(
            "Attempting to update transaction proofs of {} transactions",
            update_jobs.len()
        );
        let mut result = vec![];
        for job in update_jobs {
            // Jobs for updating txs in the mempool have highest priority since
            // they block the composer from continuing.
            // TODO: Handle errors better here.
            let job_result = job.upgrade(job_queue, proof_job_options).await.unwrap();
            result.push(job_result);
        }

        transcation_update_sender
            .send(result)
            .await
            .expect("Receiver for updated txs in main loop must still exist");
    }

    /// Handles a list of transactions whose proof has been updated with new
    /// mutator set data.
    async fn handle_updated_mempool_txs(&mut self, updated_txs: Vec<Transaction>) {
        // Update mempool with updated transactions
        {
            let mut state = self.global_state_lock.lock_guard_mut().await;
            for updated in updated_txs.iter() {
                let txid = updated.kernel.txid();
                if let Some(tx) = state.mempool.get_mut(txid) {
                    *tx = updated.to_owned();
                } else {
                    warn!("Updated transaction which is no longer in mempool");
                }
            }
        }

        // Then notify all peers
        for updated in updated_txs {
            self.main_to_peer_broadcast_tx
                .send(MainToPeerTask::TransactionNotification(
                    (&updated).try_into().unwrap(),
                ))
                .unwrap();
        }

        // Tell miner that it can now start composing next block.
        self.main_to_miner_tx.send(MainToMiner::Continue);
    }

    /// Locking:
    ///   * acquires `global_state_lock` for write
    async fn handle_miner_task_message(
        &mut self,
        msg: MinerToMain,
        main_loop_state: &mut MutableMainLoopState,
    ) -> Result<()> {
        match msg {
            MinerToMain::NewBlockFound(new_block_info) => {
                log_slow_scope!(fn_name!() + "::MinerToMain::NewBlockFound");

                let new_block = new_block_info.block;

                info!("Miner found new block: {}", new_block.kernel.header.height);

                // Store block in database
                // This block spans global state write lock for updating.
                let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;

                if !global_state_mut.incoming_block_is_more_canonical(&new_block) {
                    warn!("Got new block from miner task that was not child of tip. Discarding.");
                    self.main_to_miner_tx.send(MainToMiner::Continue);
                    return Ok(());
                } else {
                    info!(
                        "Block from miner is new canonical tip: {}",
                        new_block.hash(),
                    );
                }

                let update_jobs = global_state_mut
                    .set_new_self_mined_tip(
                        new_block.as_ref().clone(),
                        [
                            new_block_info.composer_utxos,
                            new_block_info.guesser_fee_utxo_infos,
                        ]
                        .concat(),
                    )
                    .await?;
                drop(global_state_mut);

                self.spawn_mempool_txs_update_job(main_loop_state, update_jobs)
                    .await;

                // Share block with peers
                self.main_to_peer_broadcast_tx
                    .send(MainToPeerTask::Block(new_block.clone()))
                    .expect(
                        "Peer handler broadcast channel prematurely closed. This should never happen.",
                    );
            }
            MinerToMain::BlockProposal(boxed_proposal) => {
                let (block, expected_utxos) = *boxed_proposal;

                // If block proposal from miner does not build on current tip,
                // don't broadcast it. This check covers reorgs as well.
                if block.header().prev_block_digest
                    != self
                        .global_state_lock
                        .lock_guard()
                        .await
                        .chain
                        .light_state()
                        .hash()
                {
                    warn!(
                        "Got block proposal from miner that does not build on current tip. \
                           Rejecting. If this happens a lot, then maybe this machine is too \
                           slow to competitively compose blocks. Consider running the client only \
                           with the guesser flag set and not the compose flag."
                    );
                    self.main_to_miner_tx.send(MainToMiner::Continue);
                    return Ok(());
                }

                self.main_to_peer_broadcast_tx
                    .send(MainToPeerTask::BlockProposalNotification((&block).into()))
                    .expect(
                        "Peer handler broadcast channel prematurely closed. This should never happen.",
                    );

                {
                    // Use block proposal and add expected UTXOs from this
                    // proposal.
                    let mut state = self.global_state_lock.lock_guard_mut().await;
                    state.block_proposal =
                        BlockProposal::own_proposal(block.clone(), expected_utxos.clone());
                    state.wallet_state.add_expected_utxos(expected_utxos).await;
                }

                // Indicate to miner that block proposal was successfully
                // received by main-loop.
                self.main_to_miner_tx.send(MainToMiner::Continue);
            }
        }
        Ok(())
    }

    /// Locking:
    ///   * acquires `global_state_lock` for write
    async fn handle_peer_task_message(
        &mut self,
        msg: PeerTaskToMain,
        main_loop_state: &mut MutableMainLoopState,
    ) -> Result<()> {
        debug!("Received {} from a peer task", msg.get_type());
        let cli_args = self.global_state_lock.cli().clone();
        match msg {
            PeerTaskToMain::NewBlocks(blocks) => {
                log_slow_scope!(fn_name!() + "::PeerTaskToMain::NewBlocks");

                let last_block = blocks.last().unwrap().to_owned();
                let update_jobs = {
                    // The peer tasks also check this condition, if block is more canonical than current
                    // tip, but we have to check it again since the block update might have already been applied
                    // through a message from another peer (or from own miner).
                    // TODO: Is this check right? We might still want to store the blocks even though
                    // they are not more canonical than what we currently have, in the case of deep reorganizations
                    // that is. This check fails to correctly resolve deep reorganizations. Should that be fixed,
                    // or should deep reorganizations simply be fixed by clearing the database?
                    let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;

                    if !global_state_mut.incoming_block_is_more_canonical(&last_block) {
                        warn!("Blocks were not new. Not storing blocks.");

                        // TODO: Consider fixing deep reorganization problem described above.
                        // Alternatively set the `max_number_of_blocks_before_syncing` value higher
                        // if this problem is encountered.
                        return Ok(());
                    }

                    info!(
                        "Last block from peer is new canonical tip: {}; height: {}",
                        last_block.hash(),
                        last_block.header().height
                    );

                    // Ask miner to stop work until state update is completed
                    self.main_to_miner_tx.send(MainToMiner::WaitForContinue);

                    // Get out of sync mode if needed
                    if global_state_mut.net.syncing {
                        let stay_in_sync_mode = stay_in_sync_mode(
                            &last_block.kernel.header,
                            &main_loop_state.sync_state,
                            cli_args.max_number_of_blocks_before_syncing,
                        );
                        if !stay_in_sync_mode {
                            info!("Exiting sync mode");
                            global_state_mut.net.syncing = false;
                            self.main_to_miner_tx.send(MainToMiner::StopSyncing);
                        }
                    }

                    let mut update_jobs: Vec<UpdateMutatorSetDataJob> = vec![];
                    for new_block in blocks {
                        debug!(
                            "Storing block {} in database. Height: {}, Mined: {}",
                            new_block.hash(),
                            new_block.kernel.header.height,
                            new_block.kernel.header.timestamp.standard_format()
                        );

                        // Potential race condition here.
                        // What if last block is new and canonical, but first
                        // block is already known then we'll store the same block
                        // twice. That should be OK though, as the appropriate
                        // database entries are simply overwritten with the new
                        // block info. See the
                        // [GlobalState::test::setting_same_tip_twice_is_allowed]
                        // test for a test of this phenomenon.

                        let update_jobs_ = global_state_mut.set_new_tip(new_block).await?;
                        update_jobs.extend(update_jobs_);
                    }

                    update_jobs
                };

                // Inform all peers about new block
                self.main_to_peer_broadcast_tx
                    .send(MainToPeerTask::Block(Box::new(last_block.clone())))
                    .expect("Peer handler broadcast was closed. This should never happen");

                // Spawn task to handle mempool tx-updating after new blocks.
                // TODO: Do clever trick to collapse all jobs relating to the same transaction,
                //       identified by transaction-ID, into *one* update job.
                self.spawn_mempool_txs_update_job(main_loop_state, update_jobs)
                    .await;

                // Inform miner about new block.
                self.main_to_miner_tx
                    .send(MainToMiner::NewBlock(Box::new(last_block)));
            }
            PeerTaskToMain::AddPeerMaxBlockHeight((
                socket_addr,
                claimed_max_height,
                claimed_max_pow_family,
            )) => {
                log_slow_scope!(fn_name!() + "::PeerTaskToMain::AddPeerMaxBlockHeight");

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
                let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;
                if enter_sync_mode(
                    global_state_mut.chain.light_state().header(),
                    claimed_state,
                    cli_args.max_number_of_blocks_before_syncing / 3,
                ) {
                    info!(
                    "Entering synchronization mode due to peer {} indicating tip height {}; pow family: {:?}",
                    socket_addr, claimed_max_height, claimed_max_pow_family
                );
                    global_state_mut.net.syncing = true;
                    self.main_to_miner_tx.send(MainToMiner::StartSyncing);
                }
            }
            PeerTaskToMain::RemovePeerMaxBlockHeight(socket_addr) => {
                log_slow_scope!(fn_name!() + "::PeerTaskToMain::RemovePeerMaxBlockHeight");

                debug!(
                    "Removing max block height from sync data structure for peer {}",
                    socket_addr
                );
                main_loop_state
                    .sync_state
                    .peer_sync_states
                    .remove(&socket_addr);

                // Get out of sync mode if needed.
                let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;

                if global_state_mut.net.syncing {
                    let stay_in_sync_mode = stay_in_sync_mode(
                        global_state_mut.chain.light_state().header(),
                        &main_loop_state.sync_state,
                        cli_args.max_number_of_blocks_before_syncing,
                    );
                    if !stay_in_sync_mode {
                        info!("Exiting sync mode");
                        global_state_mut.net.syncing = false;
                    }
                }
            }
            PeerTaskToMain::PeerDiscoveryAnswer((pot_peers, reported_by, distance)) => {
                log_slow_scope!(fn_name!() + "::PeerTaskToMain::PeerDiscoveryAnswer");

                let max_peers = self.global_state_lock.cli().max_num_peers;
                for pot_peer in pot_peers {
                    main_loop_state.potential_peers.add(
                        reported_by,
                        pot_peer,
                        max_peers as usize,
                        distance,
                        self.now(),
                    );
                }
            }
            PeerTaskToMain::Transaction(pt2m_transaction) => {
                log_slow_scope!(fn_name!() + "::PeerTaskToMain::Transaction");

                debug!(
                    "`peer_loop` received following transaction from peer. {} inputs, {} outputs. Synced to mutator set hash: {}",
                    pt2m_transaction.transaction.kernel.inputs.len(),
                    pt2m_transaction.transaction.kernel.outputs.len(),
                    pt2m_transaction.transaction.kernel.mutator_set_hash
                );

                let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;
                if pt2m_transaction.confirmable_for_block
                    != global_state_mut.chain.light_state().hash()
                {
                    warn!("main loop got unmined transaction with bad mutator set data, discarding transaction");
                    return Ok(());
                }

                // Insert into mempool
                global_state_mut
                    .mempool_insert(
                        pt2m_transaction.transaction.to_owned(),
                        TransactionOrigin::Foreign,
                    )
                    .await;

                // send notification to peers
                let transaction_notification: TransactionNotification =
                    (&pt2m_transaction.transaction).try_into()?;
                self.main_to_peer_broadcast_tx
                    .send(MainToPeerTask::TransactionNotification(
                        transaction_notification,
                    ))?;
            }
            PeerTaskToMain::BlockProposal(block) => {
                log_slow_scope!(fn_name!() + "::PeerTaskToMain::BlockProposal");

                debug!("main loop received block proposal from peer loop");

                // Due to race-conditions, we need to verify that this
                // block proposal is still the immediate child of tip. If it is,
                // and it has a higher guesser fee than what we're currently
                // working on, then we switch to this, and notify the miner to
                // mine on this new block. We don't need to verify the block's
                // validity, since that was done in peer loop.
                // To ensure atomicity, a write-lock must be held over global
                // state while we check if this proposal is favorable.
                {
                    info!("Received new favorable block proposal for mining operation.");
                    let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;
                    let verdict = global_state_mut.favor_incoming_block_proposal(
                        block.header().height,
                        block.total_guesser_reward(),
                    );
                    if let Err(reject_reason) = verdict {
                        warn!("main loop got unfavorable block proposal. Reason: {reject_reason}");
                        return Ok(());
                    }

                    global_state_mut.block_proposal =
                        BlockProposal::foreign_proposal(*block.clone());
                }

                // Notify all peers of the block proposal we just accepted
                self.main_to_peer_broadcast_tx
                    .send(MainToPeerTask::BlockProposalNotification((&*block).into()))?;

                self.main_to_miner_tx.send(MainToMiner::NewBlockProposal);
            }
            PeerTaskToMain::DisconnectFromLongestLivedPeer => {
                let global_state = self.global_state_lock.lock_guard().await;

                // get all peers
                let all_peers = global_state.net.peer_map.iter();

                // filter out CLI peers
                let disconnect_candidates =
                    all_peers.filter(|p| !global_state.cli_peers().contains(p.0));

                // find the one with the oldest connection
                let longest_lived_peer = disconnect_candidates.min_by(
                    |(_socket_address_left, peer_info_left),
                     (_socket_address_right, peer_info_right)| {
                        peer_info_left
                            .connection_established()
                            .cmp(&peer_info_right.connection_established())
                    },
                );

                // tell to disconnect
                if let Some((peer_socket, _peer_info)) = longest_lived_peer {
                    self.main_to_peer_broadcast_tx
                        .send(MainToPeerTask::Disconnect(peer_socket.to_owned()))?;
                }
            }
        }

        Ok(())
    }

    /// Perform peer discovery and (if necessary) reconnect to the peers listed
    /// as CLI arguments. Peer discovery involves finding potential peers from
    /// connected peers and attempts to establish connections with one of them.
    ///
    /// Locking:
    ///   * acquires `global_state_lock` for read
    async fn peer_discovery_and_reconnector(
        &self,
        main_loop_state: &mut MutableMainLoopState,
    ) -> Result<()> {
        let cli_args = self.global_state_lock.cli().clone();
        let global_state = self.global_state_lock.lock_guard().await;

        let connected_peers: Vec<PeerInfo> = global_state.net.peer_map.values().cloned().collect();

        // Check if we are connected to too many peers
        if connected_peers.len() > cli_args.max_num_peers as usize {
            // If *all* peer connections were outgoing, then it's OK to exceed
            // the max-peer count. But in that case we don't want to connect to
            // more peers, so we should just stop execution of this scheduled
            // task here.
            if connected_peers.iter().all(|x| !x.connection_is_inbound()) {
                return Ok(());
            }

            // This would indicate a race-condition on the peer map field in the state which
            // we unfortunately cannot exclude. So we just disconnect from a peer that the user
            // didn't request a connection to.
            warn!(
                "Max peer parameter is exceeded. max is {} but we are connected to {}. Attempting to fix.",
                connected_peers.len(),
                self.global_state_lock.cli().max_num_peers
            );
            let mut rng = thread_rng();

            // pick a peer that was not specified in the CLI arguments to disconnect from
            let peer_to_disconnect = connected_peers
                .iter()
                .filter(|peer| {
                    !self
                        .global_state_lock
                        .cli()
                        .peers
                        .contains(&peer.connected_address())
                })
                .choose(&mut rng);
            match peer_to_disconnect {
                Some(peer) => {
                    self.main_to_peer_broadcast_tx
                        .send(MainToPeerTask::Disconnect(peer.connected_address()))?;
                }
                None => warn!("Unable to resolve max peer constraint due to manual override."),
            };

            return Ok(());
        }

        // Check if we lost connection to any of the peers specified in the peers CLI list.
        // If we did, attempt to reconnect.
        let connected_peer_addresses = connected_peers
            .iter()
            .map(|x| x.connected_address())
            .collect_vec();
        let peers_with_lost_connection = cli_args
            .peers
            .iter()
            .filter(|peer| !connected_peer_addresses.contains(peer))
            .cloned()
            .collect_vec();
        for peer_with_lost_connection in peers_with_lost_connection {
            // Disallow reconnection if peer is in bad standing
            let standing = global_state
                .net
                .get_peer_standing_from_database(peer_with_lost_connection.ip())
                .await;

            if standing.is_some()
                && standing.unwrap().standing
                    < -(self.global_state_lock.cli().peer_tolerance as i32)
            {
                info!("Not reconnecting to peer with lost connection because it was banned: {peer_with_lost_connection}");
            } else {
                info!(
                    "Attempting to reconnect to peer with lost connection: {peer_with_lost_connection}"
                );
            }

            let own_handshake_data: HandshakeData = global_state.get_own_handshakedata().await;
            let main_to_peer_broadcast_rx = self.main_to_peer_broadcast_tx.subscribe();
            let global_state_lock_clone = self.global_state_lock.clone();
            let peer_task_to_main_tx_clone = self.peer_task_to_main_tx.to_owned();

            let outgoing_connection_task = tokio::task::Builder::new()
                .name("call_peer_wrapper_1")
                .spawn(async move {
                    call_peer(
                        peer_with_lost_connection,
                        global_state_lock_clone,
                        main_to_peer_broadcast_rx,
                        peer_task_to_main_tx_clone,
                        own_handshake_data,
                        1, // All CLI-specified peers have distance 1 by definition
                    )
                    .await;
                })?;
            main_loop_state.task_handles.push(outgoing_connection_task);
            main_loop_state.task_handles.retain(|th| !th.is_finished());
        }

        // We don't make an outgoing connection if we've reached the peer limit, *or* if we are
        // one below the peer limit as we reserve this last slot for an ingoing connection.
        if connected_peers.len() == cli_args.max_num_peers as usize
            || connected_peers.len() > 2
                && connected_peers.len() - 1 == cli_args.max_num_peers as usize
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
            .send(MainToPeerTask::MakePeerDiscoveryRequest)?;

        // 1)
        let (peer_candidate, candidate_distance) = match main_loop_state
            .potential_peers
            .get_candidate(&connected_peers, global_state.net.instance_id)
        {
            Some(candidate) => candidate,
            None => return Ok(()),
        };

        // 2)
        info!(
            "Connecting to peer {} with distance {}",
            peer_candidate, candidate_distance
        );
        let own_handshake_data: HandshakeData = global_state.get_own_handshakedata().await;
        let main_to_peer_broadcast_rx = self.main_to_peer_broadcast_tx.subscribe();
        let global_state_lock_clone = self.global_state_lock.clone();
        let peer_task_to_main_tx_clone = self.peer_task_to_main_tx.to_owned();
        let outgoing_connection_task = tokio::task::Builder::new()
            .name("call_peer_wrapper_2")
            .spawn(async move {
                call_peer(
                    peer_candidate,
                    global_state_lock_clone,
                    main_to_peer_broadcast_rx,
                    peer_task_to_main_tx_clone,
                    own_handshake_data,
                    candidate_distance,
                )
                .await;
            })?;
        main_loop_state.task_handles.push(outgoing_connection_task);
        main_loop_state.task_handles.retain(|th| !th.is_finished());

        // 3
        self.main_to_peer_broadcast_tx
            .send(MainToPeerTask::MakeSpecificPeerDiscoveryRequest(
                peer_candidate,
            ))?;

        // 4 is completed in the next call to this function provided that the in (3) connected
        // peer responded to the peer list request.

        Ok(())
    }

    /// Logic for requesting the batch-download of blocks from peers
    ///
    /// Locking:
    ///   * acquires `global_state_lock` for read
    async fn block_sync(&self, main_loop_state: &mut MutableMainLoopState) -> Result<()> {
        let global_state = self.global_state_lock.lock_guard().await;

        // Check if we are in sync mode
        if !global_state.net.syncing {
            return Ok(());
        }

        info!("Running sync");

        // Check when latest batch of blocks was requested
        let (current_block_hash, current_block_height, current_block_proof_of_work_family) = (
            global_state.chain.light_state().hash(),
            global_state.chain.light_state().kernel.header.height,
            global_state
                .chain
                .light_state()
                .kernel
                .header
                .cumulative_proof_of_work,
        );

        let (peer_to_sanction, try_new_request): (Option<SocketAddr>, bool) = main_loop_state
            .sync_state
            .get_status_of_last_request(current_block_height, self.now());

        // Sanction peer if they failed to respond
        if let Some(peer) = peer_to_sanction {
            self.main_to_peer_broadcast_tx
                .send(MainToPeerTask::PeerSynchronizationTimeout(peer))?;
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
            .get_potential_peers_for_sync_request(current_block_proof_of_work_family);
        let mut rng = thread_rng();
        let chosen_peer = candidate_peers.choose(&mut rng);
        assert!(
            chosen_peer.is_some(),
            "A synchronization candidate must be available for a request. Otherwise the data structure is in an invalid state and syncing should not be active"
        );

        // Find the blocks to request
        let tip_digest = current_block_hash;
        let most_canonical_digests = global_state
            .chain
            .archival_state()
            .get_ancestor_block_digests(tip_digest, STANDARD_BATCH_BLOCK_LOOKBEHIND_SIZE)
            .await;

        // List of digests, ordered after which block we would like to find descendents from,
        // from highest to lowest.
        let most_canonical_digests = [vec![tip_digest], most_canonical_digests].concat();

        // Send message to the relevant peer loop to request the blocks
        let chosen_peer = chosen_peer.unwrap();
        info!(
            "Sending block batch request to {}\nrequesting blocks descending from {}\n height {}",
            chosen_peer, current_block_hash, current_block_height
        );
        self.main_to_peer_broadcast_tx
            .send(MainToPeerTask::RequestBlockBatch(
                MainToPeerTaskBatchBlockRequest {
                    peer_addr_target: *chosen_peer,
                    known_blocks: most_canonical_digests,
                },
            ))
            .expect("Sending message to peers must succeed");

        // Record that this request was sent to the peer
        let requested_block_height = current_block_height.next();
        main_loop_state
            .sync_state
            .record_request(requested_block_height, *chosen_peer, self.now());

        Ok(())
    }

    /// Scheduled task for upgrading the proofs of transactions in the mempool.
    ///
    /// Will either perform a merge of two transactions supported with single
    /// proofs, or will upgrade a transaction proof of the type
    /// `ProofCollection` to `SingleProof`.
    ///
    /// All proving takes place in a spawned task such that it doesn't block
    /// the main loop. The MutableMainLoopState gets the JoinHandle of the
    /// spawned upgrade task such that its status can be expected.
    async fn proof_upgrader(&mut self, main_loop_state: &mut MutableMainLoopState) -> Result<()> {
        fn attempt_upgrade(
            global_state: &GlobalState,
            now: SystemTime,
            tx_upgrade_interval: Option<Duration>,
            main_loop_state: &MutableMainLoopState,
        ) -> Result<bool> {
            let duration_since_last_upgrade =
                now.duration_since(global_state.net.last_tx_proof_upgrade_attempt)?;
            let previous_upgrade_task_is_still_running = main_loop_state
                .proof_upgrader_task
                .as_ref()
                .is_some_and(|x| !x.is_finished());
            Ok(!global_state.net.syncing
                && global_state.proving_capability() == TxProvingCapability::SingleProof
                && !previous_upgrade_task_is_still_running
                && tx_upgrade_interval
                    .is_some_and(|upgrade_interval| duration_since_last_upgrade > upgrade_interval))
        }

        trace!("Running proof upgrader scheduled task");

        // Check if it's time to run the proof-upgrader, and if we're capable
        // of upgrading a transaction proof.
        let tx_upgrade_interval = self.global_state_lock.cli().tx_upgrade_interval();
        let (upgrade_candidate, tx_origin) = {
            let global_state = self.global_state_lock.lock_guard().await;
            let now = self.now();
            if !attempt_upgrade(&global_state, now, tx_upgrade_interval, main_loop_state)? {
                trace!("Not attempting upgrade.");
                return Ok(());
            }

            debug!("Attempting to run transaction-proof-upgrade");

            // Find a candidate for proof upgrade
            let Some((upgrade_candidate, tx_origin)) = get_upgrade_task_from_mempool(&global_state)
            else {
                debug!("Found no transaction-proof to upgrade");
                return Ok(());
            };

            (upgrade_candidate, tx_origin)
        };

        info!(
            "Attempting to upgrade transaction proofs of: {}",
            upgrade_candidate.affected_txids().iter().join("; ")
        );

        // Perform the upgrade, if we're not using the prover for anything else,
        // like mining, or proving our own transaction. Running the prover takes
        // a long time (minutes), so we spawn a task for this such that we do
        // not block the main loop.
        let vm_job_queue = self.global_state_lock.vm_job_queue().clone();
        let perform_ms_update_if_needed =
            self.global_state_lock.cli().proving_capability() == TxProvingCapability::SingleProof;

        let global_state_lock_clone = self.global_state_lock.clone();
        let main_to_peer_broadcast_tx_clone = self.main_to_peer_broadcast_tx.clone();
        let proof_upgrader_task =
            tokio::task::Builder::new()
                .name("proof_upgrader")
                .spawn(async move {
                    upgrade_candidate
                        .handle_upgrade(
                            &vm_job_queue,
                            tx_origin,
                            perform_ms_update_if_needed,
                            global_state_lock_clone,
                            main_to_peer_broadcast_tx_clone,
                        )
                        .await
                })?;

        main_loop_state.proof_upgrader_task = Some(proof_upgrader_task);

        Ok(())
    }

    /// Post-processing when new block has arrived. Spawn a task to update
    /// transactions in the mempool. Only when the spawned task has completed,
    /// should the miner continue.
    async fn spawn_mempool_txs_update_job(
        &self,
        main_loop_state: &mut MutableMainLoopState,
        update_jobs: Vec<UpdateMutatorSetDataJob>,
    ) {
        // job completion of the spawned task is communicated through the
        // `update_mempool_txs_handle` channel.
        let vm_job_queue = self.global_state_lock.vm_job_queue().clone();
        if let Some(handle) = main_loop_state.update_mempool_txs_handle.as_ref() {
            handle.abort();
        }
        let (update_sender, update_receiver) =
            mpsc::channel::<Vec<Transaction>>(TX_UPDATER_CHANNEL_CAPACITY);
        let job_options = self
            .global_state_lock
            .cli()
            .proof_job_options(TritonVmJobPriority::Highest);
        main_loop_state.update_mempool_txs_handle = Some(
            tokio::task::Builder::new()
                .name("mempool tx ms-updater")
                .spawn(async move {
                    Self::update_mempool_jobs(
                        update_jobs,
                        &vm_job_queue,
                        update_sender,
                        job_options,
                    )
                    .await
                })
                .unwrap(),
        );
        main_loop_state.update_mempool_receiver = update_receiver;
    }

    pub(crate) async fn run(
        &mut self,
        mut peer_task_to_main_rx: mpsc::Receiver<PeerTaskToMain>,
        mut miner_to_main_rx: mpsc::Receiver<MinerToMain>,
        mut rpc_server_to_main_rx: mpsc::Receiver<RPCServerToMain>,
        task_handles: Vec<JoinHandle<()>>,
    ) -> Result<()> {
        // Handle incoming connections, messages from peer tasks, and messages from the mining task
        let mut main_loop_state = MutableMainLoopState::new(task_handles);

        // Set peer discovery to run every N seconds. All timers must be reset
        // every time they have run.
        let peer_discovery_timer_interval = Duration::from_secs(PEER_DISCOVERY_INTERVAL_IN_SECONDS);
        let peer_discovery_timer = time::sleep(peer_discovery_timer_interval);
        tokio::pin!(peer_discovery_timer);

        // Set synchronization to run every M seconds.
        let block_sync_interval = Duration::from_secs(SYNC_REQUEST_INTERVAL_IN_SECONDS);
        let block_sync_timer = time::sleep(block_sync_interval);
        tokio::pin!(block_sync_timer);

        // Set removal of transactions from mempool.
        let mempool_cleanup_interval = Duration::from_secs(MEMPOOL_PRUNE_INTERVAL_IN_SECS);
        let mempool_cleanup_timer = time::sleep(mempool_cleanup_interval);
        tokio::pin!(mempool_cleanup_timer);

        // Set removal of stale notifications for incoming UTXOs.
        let utxo_notification_cleanup_interval =
            Duration::from_secs(EXPECTED_UTXOS_PRUNE_INTERVAL_IN_SECS);
        let utxo_notification_cleanup_timer = time::sleep(utxo_notification_cleanup_interval);
        tokio::pin!(utxo_notification_cleanup_timer);

        // Set restoration of membership proofs to run every Q seconds.
        let mp_resync_interval = Duration::from_secs(MP_RESYNC_INTERVAL_IN_SECS);
        let mp_resync_timer = time::sleep(mp_resync_interval);
        tokio::pin!(mp_resync_timer);

        // Set transasction-proof-upgrade-checker to run every R secnods.
        let tx_proof_upgrade_interval =
            Duration::from_secs(TRANSACTION_UPGRADE_CHECK_INTERVAL_IN_SECONDS);
        let tx_proof_upgrade_timer = time::sleep(tx_proof_upgrade_interval);
        tokio::pin!(tx_proof_upgrade_timer);

        // Spawn tasks to monitor for SIGTERM, SIGINT, and SIGQUIT. These
        // signals are only used on Unix systems.
        let (_tx_term, mut rx_term): (mpsc::Sender<()>, mpsc::Receiver<()>) =
            tokio::sync::mpsc::channel(2);
        let (_tx_int, mut rx_int): (mpsc::Sender<()>, mpsc::Receiver<()>) =
            tokio::sync::mpsc::channel(2);
        let (_tx_quit, mut rx_quit): (mpsc::Sender<()>, mpsc::Receiver<()>) =
            tokio::sync::mpsc::channel(2);
        #[cfg(unix)]
        {
            use tokio::signal::unix::signal;
            use tokio::signal::unix::SignalKind;

            // Monitor for SIGTERM
            let mut sigterm = signal(SignalKind::terminate())?;
            tokio::task::Builder::new()
                .name("sigterm_handler")
                .spawn(async move {
                    if sigterm.recv().await.is_some() {
                        info!("Received SIGTERM");
                        _tx_term.send(()).await.unwrap();
                    }
                })?;

            // Monitor for SIGINT
            let mut sigint = signal(SignalKind::interrupt())?;
            tokio::task::Builder::new()
                .name("sigint_handler")
                .spawn(async move {
                    if sigint.recv().await.is_some() {
                        info!("Received SIGINT");
                        _tx_int.send(()).await.unwrap();
                    }
                })?;

            // Monitor for SIGQUIT
            let mut sigquit = signal(SignalKind::quit())?;
            tokio::task::Builder::new()
                .name("sigquit_handler")
                .spawn(async move {
                    if sigquit.recv().await.is_some() {
                        info!("Received SIGQUIT");
                        _tx_quit.send(()).await.unwrap();
                    }
                })?;
        }

        loop {
            select! {
                Ok(()) = signal::ctrl_c() => {
                    info!("Detected Ctrl+c signal.");
                    break;
                }

                // Monitor for SIGTERM, SIGINT, and SIGQUIT.
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
                Ok((stream, peer_address)) = self.incoming_peer_listener.accept() => {
                    // Return early if no incoming connections are accepted. Do
                    // not send application-handshake.
                    if self.global_state_lock.cli().disallow_all_incoming_peer_connections() {
                        warn!("Got incoming connection despite not accepting any. Ignoring");
                        continue;
                    }

                    let state = self.global_state_lock.lock_guard().await;
                    let main_to_peer_broadcast_rx_clone: broadcast::Receiver<MainToPeerTask> = self.main_to_peer_broadcast_tx.subscribe();
                    let peer_task_to_main_tx_clone: mpsc::Sender<PeerTaskToMain> = self.peer_task_to_main_tx.clone();
                    let own_handshake_data: HandshakeData = state.get_own_handshakedata().await;
                    let global_state_lock = self.global_state_lock.clone(); // bump arc refcount.
                    let incoming_peer_task_handle = tokio::task::Builder::new()
                        .name("answer_peer_wrapper")
                        .spawn(async move {
                        match answer_peer(
                            stream,
                            global_state_lock,
                            peer_address,
                            main_to_peer_broadcast_rx_clone,
                            peer_task_to_main_tx_clone,
                            own_handshake_data,
                        ).await {
                            Ok(()) => (),
                            Err(err) => error!("Got error: {:?}", err),
                        }
                    })?;
                    main_loop_state.task_handles.push(incoming_peer_task_handle);
                    main_loop_state.task_handles.retain(|th| !th.is_finished());
                }

                // Handle messages from peer tasks
                Some(msg) = peer_task_to_main_rx.recv() => {
                    debug!("Received message sent to main task.");
                    self.handle_peer_task_message(
                        msg,
                        &mut main_loop_state,
                    )
                    .await?
                }

                // Handle messages from miner task
                Some(main_message) = miner_to_main_rx.recv() => {
                    self.handle_miner_task_message(main_message, &mut main_loop_state).await?
                }

                // Handle the completion of mempool tx-update jobs after new block.
                Some(ms_updated_transactions) = main_loop_state.update_mempool_receiver.recv() => {
                    self.handle_updated_mempool_txs(ms_updated_transactions).await;
                }

                // Handle messages from rpc server task
                Some(rpc_server_message) = rpc_server_to_main_rx.recv() => {
                    let shutdown_after_execution = self.handle_rpc_server_message(rpc_server_message.clone()).await?;
                    if shutdown_after_execution {
                        break
                    }
                }

                // Handle peer discovery
                _ = &mut peer_discovery_timer => {
                    log_slow_scope!(fn_name!() + "::select::peer_discovery_timer");

                    // Check number of peers we are connected to and connect to more peers
                    // if needed.
                    debug!("Timer: peer discovery job");
                    self.peer_discovery_and_reconnector(&mut main_loop_state).await?;

                    // Reset the timer to run this branch again in N seconds
                    peer_discovery_timer.as_mut().reset(tokio::time::Instant::now() + peer_discovery_timer_interval);
                }

                // Handle synchronization (i.e. batch-downloading of blocks)
                _ = &mut block_sync_timer => {
                    log_slow_scope!(fn_name!() + "::select::block_sync_timer");

                    trace!("Timer: block-synchronization job");
                    self.block_sync(&mut main_loop_state).await?;

                    // Reset the timer to run this branch again in M seconds
                    block_sync_timer.as_mut().reset(tokio::time::Instant::now() + block_sync_interval);
                }

                // Handle mempool cleanup, i.e. removing stale/too old txs from mempool
                _ = &mut mempool_cleanup_timer => {
                    log_slow_scope!(fn_name!() + "::select::mempool_cleanup_timer");

                    debug!("Timer: mempool-cleaner job");
                    self.global_state_lock.lock_guard_mut().await.mempool_prune_stale_transactions().await;

                    // Reset the timer to run this branch again in P seconds
                    mempool_cleanup_timer.as_mut().reset(tokio::time::Instant::now() + mempool_cleanup_interval);
                }

                // Handle incoming UTXO notification cleanup, i.e. removing stale/too old UTXO notification from pool
                _ = &mut utxo_notification_cleanup_timer => {
                    log_slow_scope!(fn_name!() + "::select::utxo_notification_cleanup_timer");

                    debug!("Timer: UTXO notification pool cleanup job");

                    // Danger: possible loss of funds.
                    //
                    // See description of prune_stale_expected_utxos().
                    //
                    // This call is disabled until such time as a thorough
                    // evaluation and perhaps reimplementation determines that
                    // it can be called safely without possible loss of funds.
                    // self.global_state_lock.lock_mut(|s| s.wallet_state.prune_stale_expected_utxos()).await;

                    utxo_notification_cleanup_timer.as_mut().reset(tokio::time::Instant::now() + utxo_notification_cleanup_interval);
                }

                // Handle membership proof resynchronization
                _ = &mut mp_resync_timer => {
                    log_slow_scope!(fn_name!() + "::select::mp_resync_timer");

                    debug!("Timer: Membership proof resync job");
                    self.global_state_lock.resync_membership_proofs().await?;

                    mp_resync_timer.as_mut().reset(tokio::time::Instant::now() + mp_resync_interval);
                }

                // Check if it's time to run the proof upgrader
                _ = &mut tx_proof_upgrade_timer => {
                    log_slow_scope!(fn_name!() + "::select::tx_upgrade_proof_timer");

                    trace!("Timer: tx-proof-upgrader");
                    self.proof_upgrader(&mut main_loop_state).await?;

                    tx_proof_upgrade_timer.as_mut().reset(tokio::time::Instant::now() + tx_proof_upgrade_interval);
                }

            }
        }

        self.graceful_shutdown(main_loop_state.task_handles).await?;
        info!("Shutdown completed.");
        Ok(())
    }

    /// Handle messages from the RPC server. Returns `true` iff the client should shut down
    /// after handling this message.
    async fn handle_rpc_server_message(&mut self, msg: RPCServerToMain) -> Result<bool> {
        match msg {
            RPCServerToMain::BroadcastTx(transaction) => {
                debug!(
                    "`main` received following transaction from RPC Server. {} inputs, {} outputs. Synced to mutator set hash: {}",
                    transaction.kernel.inputs.len(),
                    transaction.kernel.outputs.len(),
                    transaction.kernel.mutator_set_hash
                );

                // insert transaction into mempool
                self.global_state_lock
                    .lock_guard_mut()
                    .await
                    .mempool_insert(*transaction.clone(), TransactionOrigin::Own)
                    .await;

                // Is this a transaction we can share with peers? If so, share
                // it immediately.
                if let Ok(notification) = transaction.as_ref().try_into() {
                    self.main_to_peer_broadcast_tx
                        .send(MainToPeerTask::TransactionNotification(notification))?;
                } else {
                    // Otherwise upgrade its proof quality, and share it by
                    // spinning up the proof upgrader.
                    let TransactionProof::Witness(primitive_witness) = transaction.proof else {
                        panic!("Expected Primitive witness. Got: {:?}", transaction.proof);
                    };

                    let vm_job_queue = self.global_state_lock.vm_job_queue().clone();

                    let proving_capability = self.global_state_lock.cli().proving_capability();
                    let upgrade_job =
                        UpgradeJob::from_primitive_witness(proving_capability, primitive_witness);

                    // note: handle_upgrade() hands off proving to the
                    //       triton-vm job queue and waits for job completion.
                    // note: handle_upgrade() broadcasts to peers on success.

                    let global_state_lock_clone = self.global_state_lock.clone();
                    let main_to_peer_broadcast_tx_clone = self.main_to_peer_broadcast_tx.clone();
                    let _proof_upgrader_task = tokio::task::Builder::new()
                        .name("proof_upgrader")
                        .spawn(async move {
                        upgrade_job
                            .handle_upgrade(
                                &vm_job_queue,
                                TransactionOrigin::Own,
                                true,
                                global_state_lock_clone,
                                main_to_peer_broadcast_tx_clone,
                            )
                            .await
                    })?;

                    // main_loop_state.proof_upgrader_task = Some(proof_upgrader_task);
                    // If transaction could not be shared immediately because
                    // it contains secret data, upgrade its proof-type.
                }

                // do not shut down
                Ok(false)
            }
            RPCServerToMain::PauseMiner => {
                info!("Received RPC request to stop miner");

                self.main_to_miner_tx.send(MainToMiner::StopMining);
                Ok(false)
            }
            RPCServerToMain::RestartMiner => {
                info!("Received RPC request to start miner");
                self.main_to_miner_tx.send(MainToMiner::StartMining);
                Ok(false)
            }
            RPCServerToMain::Shutdown => {
                info!("Recived RPC shutdown request.");

                // shut down
                Ok(true)
            }
        }
    }

    async fn graceful_shutdown(&mut self, task_handles: Vec<JoinHandle<()>>) -> Result<()> {
        info!("Shutdown initiated.");

        // Stop mining
        self.main_to_miner_tx.send(MainToMiner::Shutdown);

        // Send 'bye' message to all peers.
        let _result = self
            .main_to_peer_broadcast_tx
            .send(MainToPeerTask::DisconnectAll());
        debug!("sent bye");

        // Flush all databases
        self.global_state_lock.flush_databases().await?;

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Child processes should have finished by now. If not, abort them violently.
        task_handles.iter().for_each(|jh| jh.abort());

        // wait for all to finish.
        futures::future::join_all(task_handles).await;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::time::UNIX_EPOCH;

    use tracing_test::traced_test;

    use super::*;
    use crate::config_models::cli_args;
    use crate::config_models::network::Network;
    use crate::tests::shared::get_test_genesis_setup;
    use crate::MINER_CHANNEL_CAPACITY;

    struct TestSetup {
        peer_to_main_rx: mpsc::Receiver<PeerTaskToMain>,
        miner_to_main_rx: mpsc::Receiver<MinerToMain>,
        rpc_server_to_main_rx: mpsc::Receiver<RPCServerToMain>,
        task_join_handles: Vec<JoinHandle<()>>,
        main_loop_handler: MainLoopHandler,
        main_to_peer_rx: broadcast::Receiver<MainToPeerTask>,
    }

    async fn setup(num_init_peers_outgoing: u8) -> TestSetup {
        let network = Network::Main;
        let (
            main_to_peer_tx,
            main_to_peer_rx,
            peer_to_main_tx,
            peer_to_main_rx,
            state,
            _own_handshake_data,
        ) = get_test_genesis_setup(network, num_init_peers_outgoing)
            .await
            .unwrap();
        assert!(
            state
                .lock_guard()
                .await
                .net
                .peer_map
                .iter()
                .all(|(_addr, peer)| !peer.connection_is_inbound()),
            "Test assumption: All initial peers must represent outgoing connections."
        );

        let incoming_peer_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

        const CHANNEL_CAPACITY: usize = 10;
        let (main_to_miner_tx, _main_to_miner_rx) =
            mpsc::channel::<MainToMiner>(MINER_CHANNEL_CAPACITY);
        let (_miner_to_main_tx, miner_to_main_rx) = mpsc::channel::<MinerToMain>(CHANNEL_CAPACITY);
        let (_rpc_server_to_main_tx, rpc_server_to_main_rx) =
            mpsc::channel::<RPCServerToMain>(CHANNEL_CAPACITY);

        let main_loop_handler = MainLoopHandler::new(
            incoming_peer_listener,
            state,
            main_to_peer_tx,
            peer_to_main_tx,
            main_to_miner_tx,
        );

        let task_join_handles = vec![];

        TestSetup {
            miner_to_main_rx,
            peer_to_main_rx,
            rpc_server_to_main_rx,
            task_join_handles,
            main_loop_handler,
            main_to_peer_rx,
        }
    }

    mod proof_upgrader {
        use super::*;
        use crate::job_queue::triton_vm::TritonVmJobQueue;
        use crate::models::blockchain::transaction::Transaction;
        use crate::models::blockchain::transaction::TransactionProof;
        use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
        use crate::models::peer::transfer_transaction::TransactionProofQuality;
        use crate::models::proof_abstractions::timestamp::Timestamp;
        use crate::models::state::wallet::utxo_notification::UtxoNotificationMedium;

        async fn tx_no_outputs(
            global_state_lock: &GlobalStateLock,
            tx_proof_type: TxProvingCapability,
            fee: NeptuneCoins,
        ) -> Transaction {
            let change_key = global_state_lock
                .lock_guard()
                .await
                .wallet_state
                .wallet_secret
                .nth_generation_spending_key_for_tests(0);
            let in_seven_months = global_state_lock
                .lock_guard()
                .await
                .chain
                .light_state()
                .header()
                .timestamp
                + Timestamp::months(7);

            let global_state = global_state_lock.lock_guard().await;
            global_state
                .create_transaction_with_prover_capability(
                    vec![].into(),
                    change_key.into(),
                    UtxoNotificationMedium::OffChain,
                    fee,
                    in_seven_months,
                    tx_proof_type,
                    &TritonVmJobQueue::dummy(),
                )
                .await
                .unwrap()
                .0
        }

        #[tokio::test]
        #[traced_test]
        async fn upgrade_proof_collection_to_single_proof_foreign_tx() {
            let test_setup = setup(0).await;
            let TestSetup {
                peer_to_main_rx,
                miner_to_main_rx,
                rpc_server_to_main_rx,
                task_join_handles,
                mut main_loop_handler,
                mut main_to_peer_rx,
            } = test_setup;

            // Force instance to create SingleProofs, otherwise CI and other
            // weak machines fail.
            let mocked_cli = cli_args::Args {
                tx_proving_capability: Some(TxProvingCapability::SingleProof),
                tx_proof_upgrade_interval: 100, // seconds
                ..Default::default()
            };

            main_loop_handler
                .global_state_lock
                .set_cli(mocked_cli)
                .await;
            let mut main_loop_handler = main_loop_handler.with_mocked_time(SystemTime::now());
            let mut mutable_main_loop_state = MutableMainLoopState::new(task_join_handles);

            assert!(
                main_loop_handler
                    .proof_upgrader(&mut mutable_main_loop_state)
                    .await
                    .is_ok(),
                "Scheduled task returns OK when run on empty mempool"
            );

            let fee = NeptuneCoins::new(1);
            let proof_collection_tx = tx_no_outputs(
                &main_loop_handler.global_state_lock,
                TxProvingCapability::ProofCollection,
                fee,
            )
            .await;

            main_loop_handler
                .global_state_lock
                .lock_guard_mut()
                .await
                .mempool_insert(proof_collection_tx.clone(), TransactionOrigin::Foreign)
                .await;

            assert!(
                main_loop_handler
                    .proof_upgrader(&mut mutable_main_loop_state)
                    .await
                    .is_ok(),
                "Scheduled task returns OK when it's not yet time to upgrade"
            );

            assert!(
                matches!(
                    main_loop_handler
                        .global_state_lock
                        .lock_guard()
                        .await
                        .mempool
                        .get(proof_collection_tx.kernel.txid())
                        .unwrap()
                        .proof,
                    TransactionProof::ProofCollection(_)
                ),
                "Proof in mempool must still be of type proof collection"
            );

            // Mock that enough time has passed to perform the upgrade. Then
            // perform the upgrade.
            let mut main_loop_handler =
                main_loop_handler.with_mocked_time(SystemTime::now() + Duration::from_secs(300));
            assert!(
                main_loop_handler
                    .proof_upgrader(&mut mutable_main_loop_state)
                    .await
                    .is_ok(),
                "Scheduled task must return OK when it's time to upgrade"
            );

            // Wait for upgrade task to finish.
            let handle = mutable_main_loop_state.proof_upgrader_task.unwrap().await;
            assert!(
                handle.is_ok(),
                "Proof-upgrade task must finish successfully."
            );

            // At this point there should be one transaction in the mempool,
            // which is (if all is well) the merger of the ProofCollection
            // transaction inserted above and one of the upgrader's fee
            // gobblers. The point is that this transaction is a SingleProof
            // transaction, so test that.

            let (merged_txid, _) = main_loop_handler
                .global_state_lock
                .lock_guard()
                .await
                .mempool
                .get_sorted_iter()
                .last()
                .expect("mempool should contain one item here");

            assert!(
                matches!(
                    main_loop_handler
                        .global_state_lock
                        .lock_guard()
                        .await
                        .mempool
                        .get(merged_txid)
                        .unwrap()
                        .proof,
                    TransactionProof::SingleProof(_)
                ),
                "Proof in mempool must now be of type single proof"
            );

            match main_to_peer_rx.recv().await {
                Ok(MainToPeerTask::TransactionNotification(tx_noti)) => {
                    assert_eq!(merged_txid, tx_noti.txid);
                    assert_eq!(TransactionProofQuality::SingleProof, tx_noti.proof_quality);
                },
                other => panic!("Must have sent transaction notification to peer loop after successful proof upgrade. Got:\n{other:?}"),
            }

            // These values are kept alive as the transmission-counterpart will
            // otherwise fail on `send`.
            drop(peer_to_main_rx);
            drop(miner_to_main_rx);
            drop(rpc_server_to_main_rx);
            drop(main_to_peer_rx);
        }
    }

    mod peer_discovery {
        use super::*;

        #[tokio::test]
        #[traced_test]
        async fn no_warning_on_peer_exceeding_limit_if_connections_are_outgoing() {
            let num_init_peers_outgoing = 2;
            let test_setup = setup(num_init_peers_outgoing).await;
            let TestSetup {
                peer_to_main_rx,
                miner_to_main_rx,
                rpc_server_to_main_rx,
                task_join_handles,
                mut main_loop_handler,
                main_to_peer_rx,
            } = test_setup;

            // Set CLI to ban incoming connections and all outgoing peer-discovery-
            // initiated connections.
            let mocked_cli = cli_args::Args {
                max_num_peers: 0,
                ..Default::default()
            };
            main_loop_handler
                .global_state_lock
                .set_cli(mocked_cli)
                .await;

            let mut mutable_main_loop_state = MutableMainLoopState::new(task_join_handles);

            main_loop_handler
                .peer_discovery_and_reconnector(&mut mutable_main_loop_state)
                .await
                .unwrap();

            logs_assert(|lines: &[&str]| {
                if lines.iter().any(|line| line.contains("WARN"))
                    || lines.iter().any(|line| line.contains("Max peer"))
                {
                    Err(format!(
                        "No warnings allowed in situation where incoming connections are banned. Got:\n{}",
                        lines.join("\n"),
                    ))
                } else if lines
                    .iter()
                    .any(|line| line.contains("Performing peer discovery"))
                {
                    Err("May not perform peer discovery when `max_peers` = 0.".to_owned())
                } else {
                    Ok(())
                }
            });

            // These values are kept alive as the transmission-counterpart will
            // otherwise fail on `send`.
            drop(peer_to_main_rx);
            drop(miner_to_main_rx);
            drop(rpc_server_to_main_rx);
            drop(main_to_peer_rx);
        }

        #[tokio::test]
        #[traced_test]
        async fn performs_peer_discovery_on_few_connections() {
            let num_init_peers_outgoing = 2;
            let test_setup = setup(num_init_peers_outgoing).await;
            let TestSetup {
                peer_to_main_rx,
                miner_to_main_rx,
                rpc_server_to_main_rx,
                task_join_handles,
                mut main_loop_handler,
                mut main_to_peer_rx,
            } = test_setup;

            // Set CLI to attempt to make more connections
            let mocked_cli = cli_args::Args {
                max_num_peers: 10,
                ..Default::default()
            };
            main_loop_handler
                .global_state_lock
                .set_cli(mocked_cli)
                .await;

            let mut mutable_main_loop_state = MutableMainLoopState::new(task_join_handles);

            main_loop_handler
                .peer_discovery_and_reconnector(&mut mutable_main_loop_state)
                .await
                .unwrap();

            logs_assert(|lines: &[&str]| {
                if lines
                    .iter()
                    .any(|line| line.contains("Performing peer discovery"))
                {
                    Ok(())
                } else {
                    Err(format!(
                        "Must log that peer discovery is being performed. Got logs:\n{}",
                        lines.join("\n"),
                    ))
                }
            });

            assert!(
                main_to_peer_rx.try_recv().is_ok(),
                "Peer channel must have received message as part of peer discovery process"
            );

            // These values are kept alive as the transmission-counterpart will
            // otherwise fail on `send`.
            drop(peer_to_main_rx);
            drop(miner_to_main_rx);
            drop(rpc_server_to_main_rx);
            drop(main_to_peer_rx);
        }
    }

    #[test]
    fn older_systemtime_ranks_first() {
        let start = UNIX_EPOCH;
        let other = UNIX_EPOCH + Duration::from_secs(1000);
        let mut instants = [start, other];

        assert_eq!(
            start,
            instants.iter().copied().min_by(|l, r| l.cmp(r)).unwrap()
        );

        instants.reverse();

        assert_eq!(
            start,
            instants.iter().copied().min_by(|l, r| l.cmp(r)).unwrap()
        );
    }
    mod bootstrapper_mode {

        use rand::Rng;

        use super::*;
        use crate::models::peer::PeerMessage;
        use crate::models::peer::TransferConnectionStatus;
        use crate::tests::shared::get_dummy_peer_connection_data_genesis;
        use crate::tests::shared::to_bytes;

        #[tokio::test]
        #[traced_test]
        async fn disconnect_from_oldest_peer_upon_connection_request() {
            // Set up a node in bootstrapper mode and connected to a given
            // number of peers, which is one less than the maximum. Initiate a
            // connection request. Verify that the oldest of the existing
            // connections is dropped.

            let network = Network::Main;
            let num_init_peers_outgoing = 5;
            let test_setup = setup(num_init_peers_outgoing).await;
            let TestSetup {
                mut peer_to_main_rx,
                miner_to_main_rx: _,
                rpc_server_to_main_rx: _,
                task_join_handles,
                mut main_loop_handler,
                mut main_to_peer_rx,
            } = test_setup;

            let mocked_cli = cli_args::Args {
                max_num_peers: num_init_peers_outgoing as u16 + 1,
                bootstrap: true,
                network,
                ..Default::default()
            };
            main_loop_handler
                .global_state_lock
                .set_cli(mocked_cli)
                .await;

            let mut mutable_main_loop_state = MutableMainLoopState::new(task_join_handles);

            // check sanity: at startup, we are connected to the initial number of peers
            assert_eq!(
                num_init_peers_outgoing as usize,
                main_loop_handler
                    .global_state_lock
                    .lock_guard()
                    .await
                    .net
                    .peer_map
                    .len()
            );

            // randomize "connection established" timestamps
            let mut rng = thread_rng();
            let now = SystemTime::now();
            let now_as_unix_timestamp = now.duration_since(UNIX_EPOCH).unwrap();
            main_loop_handler
                .global_state_lock
                .lock_guard_mut()
                .await
                .net
                .peer_map
                .iter_mut()
                .for_each(|(_socket_address, peer_info)| {
                    peer_info.set_connection_established(
                        UNIX_EPOCH
                            + Duration::from_millis(
                                rng.gen_range(0..(now_as_unix_timestamp.as_millis() as u64)),
                            ),
                    );
                });

            // compute which peer will be dropped, for later reference
            let expected_drop_peer_socket_address = main_loop_handler
                .global_state_lock
                .lock_guard()
                .await
                .net
                .peer_map
                .iter()
                .min_by(|l, r| {
                    l.1.connection_established()
                        .cmp(&r.1.connection_established())
                })
                .map(|(socket_address, _peer_info)| socket_address)
                .cloned()
                .unwrap();

            // simulate incoming connection
            let (peer_handshake_data, peer_socket_address) =
                get_dummy_peer_connection_data_genesis(network, 1).await;
            let own_handshake_data = main_loop_handler
                .global_state_lock
                .lock_guard()
                .await
                .get_own_handshakedata()
                .await;
            assert_eq!(peer_handshake_data.network, own_handshake_data.network,);
            assert_eq!(peer_handshake_data.version, own_handshake_data.version,);
            let mock_stream = tokio_test::io::Builder::new()
                .read(
                    &to_bytes(&PeerMessage::Handshake(Box::new((
                        crate::MAGIC_STRING_REQUEST.to_vec(),
                        peer_handshake_data.clone(),
                    ))))
                    .unwrap(),
                )
                .write(
                    &to_bytes(&PeerMessage::Handshake(Box::new((
                        crate::MAGIC_STRING_RESPONSE.to_vec(),
                        own_handshake_data.clone(),
                    ))))
                    .unwrap(),
                )
                .write(
                    &to_bytes(&PeerMessage::ConnectionStatus(
                        TransferConnectionStatus::Accepted,
                    ))
                    .unwrap(),
                )
                .build();
            let peer_to_main_tx_clone = main_loop_handler.peer_task_to_main_tx.clone();
            let global_state_lock_clone = main_loop_handler.global_state_lock.clone();
            let (_main_to_peer_tx_mock, main_to_peer_rx_mock) = tokio::sync::broadcast::channel(10);
            let incoming_peer_task_handle = tokio::task::Builder::new()
                .name("answer_peer_wrapper")
                .spawn(async move {
                    match answer_peer(
                        mock_stream,
                        global_state_lock_clone,
                        peer_socket_address,
                        main_to_peer_rx_mock,
                        peer_to_main_tx_clone,
                        own_handshake_data,
                    )
                    .await
                    {
                        Ok(()) => (),
                        Err(err) => error!("Got error: {:?}", err),
                    }
                })
                .unwrap();

            // `answer_peer_wrapper` should send a
            // `DisconnectFromLongestLivedPeer` message to main
            let peer_to_main_message = peer_to_main_rx.recv().await.unwrap();
            assert!(matches!(
                peer_to_main_message,
                PeerTaskToMain::DisconnectFromLongestLivedPeer,
            ));

            // process this message
            main_loop_handler
                .handle_peer_task_message(peer_to_main_message, &mut mutable_main_loop_state)
                .await
                .unwrap();

            // main loop should send a `Disconnect` message
            let main_to_peers_message = main_to_peer_rx.recv().await.unwrap();
            assert!(matches!(
                main_to_peers_message,
                MainToPeerTask::Disconnect(_)
            ));
            let MainToPeerTask::Disconnect(observed_drop_peer_socket_address) =
                main_to_peers_message
            else {
                unreachable!()
            };

            // matched observed droppee against expectation
            assert_eq!(
                expected_drop_peer_socket_address,
                observed_drop_peer_socket_address
            );

            println!(
                "Dropped connection with {}.",
                expected_drop_peer_socket_address
            );

            // don't forget to terminate the peer task, which is still running
            incoming_peer_task_handle.abort();
        }
    }
}
