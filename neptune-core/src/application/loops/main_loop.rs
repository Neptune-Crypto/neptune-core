pub mod proof_upgrader;
pub(crate) mod upgrade_incentive;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;

use anyhow::Result;
use itertools::Itertools;
use proof_upgrader::get_upgrade_task_from_mempool;
use proof_upgrader::UpgradeJob;
use rand::prelude::IteratorRandom;
use rand::seq::IndexedRandom;
use tasm_lib::prelude::Digest;
use tokio::net::TcpListener;
use tokio::select;
use tokio::signal;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time;
use tokio::time::Instant;
use tokio::time::MissedTickBehavior;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::trace;
use tracing::warn;

use crate::application::loops::channel::MainToMiner;
use crate::application::loops::channel::MainToPeerTask;
use crate::application::loops::channel::MainToPeerTaskBatchBlockRequest;
use crate::application::loops::channel::MinerToMain;
use crate::application::loops::channel::PeerTaskToMain;
use crate::application::loops::channel::RPCServerToMain;
use crate::application::loops::connect_to_peers::answer_peer;
use crate::application::loops::connect_to_peers::call_peer;
use crate::application::loops::connect_to_peers::precheck_incoming_connection_is_allowed;
use crate::application::loops::main_loop::proof_upgrader::PrimitiveWitnessToProofCollection;
use crate::application::loops::main_loop::proof_upgrader::SEARCH_DEPTH_FOR_BLOCKS_FOR_MS_UPDATE;
use crate::application::loops::main_loop::upgrade_incentive::UpgradeIncentive;
use crate::application::triton_vm_job_queue::vm_job_queue;
use crate::application::triton_vm_job_queue::TritonVmJobPriority;
use crate::application::triton_vm_job_queue::TritonVmJobQueue;
use crate::macros::fn_name;
use crate::macros::log_slow_scope;
use crate::protocol::consensus::block::block_header::BlockHeader;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::difficulty_control::ProofOfWork;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::consensus::transaction::TransactionProof;
use crate::protocol::peer::handshake_data::HandshakeData;
use crate::protocol::peer::peer_info::PeerInfo;
use crate::protocol::peer::transaction_notification::TransactionNotification;
use crate::protocol::peer::PeerSynchronizationState;
use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::state::mempool::mempool_update_job::MempoolUpdateJob;
use crate::state::mempool::mempool_update_job_result::MempoolUpdateJobResult;
use crate::state::mempool::upgrade_priority::UpgradePriority;
use crate::state::mining::block_proposal::BlockProposal;
use crate::state::networking_state::SyncAnchor;
use crate::state::transaction::tx_proving_capability::TxProvingCapability;
use crate::state::GlobalState;
use crate::state::GlobalStateLock;
use crate::SUCCESS_EXIT_CODE;

const PEER_DISCOVERY_INTERVAL: Duration = Duration::from_secs(2 * 60);
const SYNC_REQUEST_INTERVAL: Duration = Duration::from_secs(3);
const MEMPOOL_PRUNE_INTERVAL: Duration = Duration::from_secs(30 * 60);
const MP_RESYNC_INTERVAL: Duration = Duration::from_secs(59);
const PROOF_UPGRADE_INTERVAL: Duration = Duration::from_secs(10);
const EXPECTED_UTXOS_PRUNE_INTERVAL: Duration = Duration::from_secs(19 * 60);

const SANCTION_PEER_TIMEOUT_FACTOR: u64 = 40;

/// Number of seconds within which an individual peer is expected to respond
/// to a synchronization request.
const INDIVIDUAL_PEER_SYNCHRONIZATION_TIMEOUT: Duration =
    Duration::from_secs(SYNC_REQUEST_INTERVAL.as_secs() * SANCTION_PEER_TIMEOUT_FACTOR);

/// Number of seconds that a synchronization may run without any progress.
const GLOBAL_SYNCHRONIZATION_TIMEOUT: Duration =
    Duration::from_secs(INDIVIDUAL_PEER_SYNCHRONIZATION_TIMEOUT.as_secs() * 4);

const POTENTIAL_PEER_MAX_COUNT_AS_A_FACTOR_OF_MAX_PEERS: usize = 20;
pub(crate) const MAX_NUM_DIGESTS_IN_BATCH_REQUEST: usize = 200;
const TX_UPDATER_CHANNEL_CAPACITY: usize = 1;

/// Wraps a transmission channel.
///
/// To be used for the transmission channel to the miner, because
///  a) the miner might not exist in which case there would be no-one to empty
///     the channel; and
///  b) contrary to other channels, transmission failures here are not critical.
#[derive(Debug)]
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
#[derive(Debug)]
pub struct MainLoopHandler {
    incoming_peer_listener: TcpListener,
    global_state_lock: GlobalStateLock,

    // note: broadcast::Sender::send() does not block
    main_to_peer_broadcast_tx: broadcast::Sender<MainToPeerTask>,

    // note: mpsc::Sender::send() blocks if channel full.
    // locks should not be held across it.
    peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,

    // note: MainToMinerChannel::send() does not block.  might log error.
    main_to_miner_tx: MainToMinerChannel,

    peer_task_to_main_rx: mpsc::Receiver<PeerTaskToMain>,
    miner_to_main_rx: mpsc::Receiver<MinerToMain>,
    rpc_server_to_main_rx: mpsc::Receiver<RPCServerToMain>,
    task_handles: Vec<JoinHandle<()>>,

    #[cfg(test)]
    mock_now: Option<SystemTime>,
}

/// The mutable part of the main loop function
struct MutableMainLoopState {
    /// Information used to batch-download blocks.
    sync_state: SyncState,

    /// Information about potential peers for new connections.
    potential_peers: PotentialPeersState,

    /// A list of join-handles to spawned tasks.
    task_handles: Vec<JoinHandle<()>>,

    /// A join-handle to a task performing transaction-proof upgrades.
    proof_upgrader_task: Option<JoinHandle<()>>,

    /// A join-handle to a task running the update of the mempool transactions.
    update_mempool_txs_handle: Option<JoinHandle<()>>,

    /// A channel that the task updating mempool transactions can use to
    /// communicate its result.
    update_mempool_receiver: mpsc::Receiver<Vec<MempoolUpdateJobResult>>,
}

impl MutableMainLoopState {
    fn new(task_handles: Vec<JoinHandle<()>>) -> Self {
        let (_dummy_sender, dummy_receiver) =
            mpsc::channel::<Vec<MempoolUpdateJobResult>>(TX_UPDATER_CHANNEL_CAPACITY);
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
#[derive(Default, Debug)]
struct SyncState {
    peer_sync_states: HashMap<SocketAddr, PeerSynchronizationState>,
    last_sync_request: Option<(SystemTime, BlockHeight, SocketAddr)>,
}

impl SyncState {
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

    /// Determine if a peer should be sanctioned for failing to respond to a
    /// synchronization request fast enough. Also determine if a new request
    /// should be made or the previous one should be allowed to run for longer.
    ///
    /// Returns (peer to be sanctioned, attempt new request).
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
                } else if req_time + INDIVIDUAL_PEER_SYNCHRONIZATION_TIMEOUT < now {
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
            let mut rng = rand::rng();
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
        let mut rng = rand::rng();
        max_distance_candidates
            .iter()
            .choose(&mut rng)
            .map(|x| (x.0.to_owned(), x.1.distance))
    }
}

/// Return a boolean indicating if synchronization mode should be left
fn stay_in_sync_mode(
    own_block_tip_header: &BlockHeader,
    sync_state: &SyncState,
    sync_mode_threshold: usize,
) -> bool {
    let max_claimed_pow = sync_state
        .peer_sync_states
        .values()
        .max_by_key(|x| x.claimed_max_pow);
    match max_claimed_pow {
        None => false, // No peer have passed the sync challenge phase.

        // Synchronization is left when the remaining number of block is half of what has
        // been indicated to fit into RAM
        Some(max_claim) => {
            own_block_tip_header.cumulative_proof_of_work < max_claim.claimed_max_pow
                && max_claim.claimed_max_height - own_block_tip_header.height
                    > sync_mode_threshold as i128 / 2
        }
    }
}

impl MainLoopHandler {
    // todo: find a way to avoid triggering lint
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        incoming_peer_listener: TcpListener,
        global_state_lock: GlobalStateLock,
        main_to_peer_broadcast_tx: broadcast::Sender<MainToPeerTask>,
        peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,
        main_to_miner_tx: mpsc::Sender<MainToMiner>,

        peer_task_to_main_rx: mpsc::Receiver<PeerTaskToMain>,
        miner_to_main_rx: mpsc::Receiver<MinerToMain>,
        rpc_server_to_main_rx: mpsc::Receiver<RPCServerToMain>,
        task_handles: Vec<JoinHandle<()>>,
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

            peer_task_to_main_rx,
            miner_to_main_rx,
            rpc_server_to_main_rx,
            task_handles,

            #[cfg(test)]
            mock_now: None,
        }
    }

    pub fn global_state_lock(&mut self) -> GlobalStateLock {
        self.global_state_lock.clone()
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

    /// Update the mutator set data for a list of mempool transactions. Will
    /// produce transactions with the same proof quality as what was present in
    /// the mempool, so a primitive witness backed transaction will be updated
    /// to a new primitive witness backed transaction, a proof-collection to
    /// proof-collection, and single proof to single proof.
    ///
    /// In the case of proof collection, it is not possible to update the
    /// transaction, so the primitive witness is instead used to accomplish
    /// this.
    ///
    /// Sends the result back through the provided channel.
    async fn update_mempool_jobs(
        mut global_state_lock: GlobalStateLock,
        update_jobs: Vec<MempoolUpdateJob>,
        job_queue: Arc<TritonVmJobQueue>,
        transaction_update_sender: mpsc::Sender<Vec<MempoolUpdateJobResult>>,
        proof_job_options: TritonVmProofJobOptions,
    ) {
        debug!(
            "Attempting to update transaction witnesses of {} transactions",
            update_jobs.len()
        );
        let mut result = vec![];
        for job in update_jobs {
            let txid = job.txid();
            match &job {
                MempoolUpdateJob::PrimitiveWitness(pw_update)
                | MempoolUpdateJob::ProofCollection(pw_update) => {
                    let old_msa = &pw_update.old_primitive_witness.mutator_set_accumulator;

                    // Acquire lock, and drop it immediately.
                    let msa_update = global_state_lock
                        .lock_guard_mut()
                        .await
                        .chain
                        .archival_state_mut()
                        .get_mutator_set_update_to_tip(
                            old_msa,
                            SEARCH_DEPTH_FOR_BLOCKS_FOR_MS_UPDATE,
                        )
                        .await;
                    let Some(msa_update) = msa_update else {
                        result.push(MempoolUpdateJobResult::Failure(txid));
                        continue;
                    };
                    let new_pw = pw_update
                        .old_primitive_witness
                        .clone()
                        .update_with_new_ms_data(msa_update);
                    let upgraded_tx = match &job {
                        MempoolUpdateJob::PrimitiveWitness(_) => Transaction {
                            kernel: new_pw.kernel.clone(),
                            proof: TransactionProof::Witness(new_pw.clone()),
                        },
                        MempoolUpdateJob::ProofCollection(_) => {
                            let pc_job = PrimitiveWitnessToProofCollection {
                                primitive_witness: new_pw.clone(),
                            };

                            // No locks may be held here!
                            let upgrade_result =
                                pc_job.upgrade(job_queue.clone(), &proof_job_options).await;
                            match upgrade_result {
                                Ok(upgraded) => upgraded,
                                Err(_) => {
                                    result.push(MempoolUpdateJobResult::Failure(txid));
                                    continue;
                                }
                            }
                        }
                        MempoolUpdateJob::SingleProof { .. } => unreachable!(),
                    };

                    result.push(MempoolUpdateJobResult::Success {
                        new_primitive_witness: Some(Box::new(new_pw)),
                        new_transaction: Box::new(upgraded_tx),
                    });
                }
                MempoolUpdateJob::SingleProof {
                    old_kernel,
                    old_single_proof,
                } => {
                    let upgrade_incentive = UpgradeIncentive::Critical;
                    let Ok(update_job) = global_state_lock
                        .lock_guard_mut()
                        .await
                        .update_single_proof_job(
                            old_kernel.to_owned(),
                            old_single_proof.to_owned(),
                            upgrade_incentive,
                        )
                        .await
                    else {
                        result.push(MempoolUpdateJobResult::Failure(txid));
                        continue;
                    };

                    // No locks may be held here!
                    let upgrade_result = update_job
                        .upgrade(job_queue.clone(), proof_job_options.clone())
                        .await;
                    let Ok(updated_tx) = upgrade_result else {
                        result.push(MempoolUpdateJobResult::Failure(txid));
                        continue;
                    };

                    result.push(MempoolUpdateJobResult::Success {
                        new_primitive_witness: None,
                        new_transaction: Box::new(updated_tx),
                    });
                }
            }
        }

        transaction_update_sender
            .send(result)
            .await
            .expect("Receiver for updated txs in main loop must still exist");
    }

    /// Handles a list of transactions whose witness data has been updated to be
    /// valid under a new mutator set.
    async fn handle_updated_mempool_txs(&mut self, update_results: Vec<MempoolUpdateJobResult>) {
        {
            let mut state = self.global_state_lock.lock_guard_mut().await;
            for update_result in &update_results {
                match update_result {
                    MempoolUpdateJobResult::Failure(txkid) => {
                        warn!(
                            "Failed to update transaction {txkid} to be valid under new mutator \
                        set. Removing from the mempool."
                        );
                        state.mempool_remove(*txkid).await
                    }
                    MempoolUpdateJobResult::Success {
                        new_primitive_witness,
                        new_transaction,
                    } => {
                        let txid = new_transaction.kernel.txid();
                        info!("Updated transaction {txid} to be valid under new mutator set");

                        // First update the primitive-witness data associated with the transaction,
                        // then insert the new transaction into the mempool. This ensures that the
                        // primitive-witness is as up-to-date as possible in case it has to be
                        // updated again later.
                        if let Some(new_pw) = new_primitive_witness {
                            state
                                .mempool_update_primitive_witness(txid, *new_pw.to_owned())
                                .await;
                        }
                        state
                            .mempool_insert(*new_transaction.to_owned(), UpgradePriority::Critical)
                            .await;
                    }
                }
            }
        }

        // Then notify all peers about shareable transactions.
        for updated in update_results {
            if let MempoolUpdateJobResult::Success {
                new_transaction, ..
            } = updated
            {
                if let Ok(pmsg) = new_transaction.as_ref().try_into() {
                    let pmsg = MainToPeerTask::TransactionNotification(pmsg);
                    self.main_to_peer_broadcast(pmsg);
                }
            }
        }

        // Tell miner that it can now continue either composing or guessing.
        self.main_to_miner_tx.send(MainToMiner::Continue);
    }

    /// Invoke the external program that runs whenever the tip changes, if one
    /// such is set.
    ///
    /// Halts the entire application if the declared program could not be
    /// started but does not wait for the program to finish and does thus not
    /// check the exit code of the spawned process. Programs are guaranteed to
    /// spawned in the order that the new tips are set. So in the case of a
    /// reorganization, the block height will fall compared to the previous
    /// invocation.
    fn spawn_block_notify_command(block_notify: &Option<String>, block_hash: Digest) {
        if let Some(block_notify) = block_notify {
            let cmd = block_notify.to_owned();
            let cmd = cmd.replace("%s", &block_hash.to_hex());

            debug!("Invoking block notify cmd:\"{cmd}\"");
            let args = cmd.split(' ').collect_vec();
            trace!("args[0]=\"{}\"", args[0]);
            trace!("args[1..]=[{}]", args[1..].iter().join(","));
            let child = Command::new(args[0])
                .args(&args[1..])
                .stdin(Stdio::null()) // detach from our stdin
                .stdout(Stdio::null()) // discard output
                .stderr(Stdio::null()) // discard errors
                .spawn()
                .unwrap_or_else(|e| {
                    error!("Failed to start external program \"{cmd}\": {e}");
                    std::process::exit(1);
                });

            // Don't wait on `child`, just drop it:
            drop(child);
        }
    }

    /// Process a block whose PoW solution was solved by this client (or an
    /// external program) and has not been seen by the rest of the network yet.
    ///
    /// Shares block with all connected peers, updates own state, and updates
    /// any mempool transactions to be valid under this new block.
    ///
    /// Caller is responsible for both block validity and that the provided
    /// block has a valid PoW solution. Otherwise, the new state will be
    /// invalid.
    ///
    /// Locking:
    ///  * acquires `global_state_lock` for read and write
    async fn handle_self_guessed_block(
        &mut self,
        main_loop_state: &mut MutableMainLoopState,
        new_block: Box<Block>,
    ) -> Result<()> {
        let new_block_hash = new_block.hash();

        // clone block in advance, so lock is held less time.
        let new_block_clone = (*new_block).clone();

        // important!  the is_canonical check and set_new_tip() need to be an
        // atomic operation, ie called within the same write-lock acquisition.
        //
        // this avoids a race condition where block B and C are both more
        // canonical than A, but B is more than C, yet C replaces B because it
        // was only checked against A.
        //
        // we release the lock as quickly as possible.
        let update_jobs = {
            let mut gsm = self.global_state_lock.lock_guard_mut().await;

            // bail out if incoming block is not more canonical than present tip.
            if !gsm.incoming_block_is_more_canonical(&new_block) {
                drop(gsm); // drop lock right away before send.
                warn!("Got new block from miner that was not child of tip. Discarding.");
                self.main_to_miner_tx.send(MainToMiner::Continue);
                return Ok(());
            }

            let update_jobs = gsm.set_new_tip(new_block_clone).await?;
            gsm.flush_databases().await?;
            update_jobs
        };

        // Share block with peers right away.
        let pmsg = MainToPeerTask::Block(new_block);
        self.main_to_peer_broadcast(pmsg);

        Self::spawn_block_notify_command(
            &self.global_state_lock.cli().block_notify,
            new_block_hash,
        );

        info!("Locally-mined block is new tip: {new_block_hash:x}");
        info!("broadcasting new block to peers");

        self.spawn_mempool_txs_update_job(main_loop_state, update_jobs);

        Ok(())
    }

    /// Locking:
    ///   * acquires `global_state_lock` for write
    async fn handle_miner_task_message(
        &mut self,
        msg: MinerToMain,
        main_loop_state: &mut MutableMainLoopState,
    ) -> Result<Option<i32>> {
        match msg {
            MinerToMain::NewBlockFound(new_block_info) => {
                log_slow_scope!(fn_name!() + "::MinerToMain::NewBlockFound");

                let new_block = new_block_info.block;

                info!("Miner found new block: {}", new_block.kernel.header.height);
                self.handle_self_guessed_block(main_loop_state, new_block)
                    .await?;
            }
            MinerToMain::BlockProposal(boxed_proposal) => {
                let (block, expected_utxos) = *boxed_proposal;

                // If block proposal from miner does not build on current tip,
                // don't broadcast it. This check covers reorgs as well.
                let current_tip = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .chain
                    .light_state()
                    .clone();
                if block.header().prev_block_digest != current_tip.hash() {
                    warn!(
                        "Got block proposal from miner that does not build on current tip. \
                           Rejecting. If this happens a lot, then maybe this machine is too \
                           slow to competitively compose blocks. Consider running the client only \
                           with the guesser flag set and not the compose flag."
                    );
                    self.main_to_miner_tx.send(MainToMiner::Continue);
                    return Ok(None);
                }

                // Ensure proposal validity before sharing
                if !block
                    .is_valid(
                        &current_tip,
                        block.header().timestamp,
                        self.global_state_lock.cli().network,
                    )
                    .await
                {
                    error!("Own block proposal invalid. This should not happen.");
                    self.main_to_miner_tx.send(MainToMiner::Continue);
                    return Ok(None);
                }

                if !self.global_state_lock.cli().secret_compositions {
                    let pmsg = MainToPeerTask::BlockProposalNotification((&block).into());
                    self.main_to_peer_broadcast(pmsg);
                }

                {
                    // Use block proposal and add expected UTXOs from this
                    // proposal.
                    let mut state = self.global_state_lock.lock_guard_mut().await;
                    state.mining_state.block_proposal =
                        BlockProposal::own_proposal(block.clone(), expected_utxos.clone());
                    state.wallet_state.add_expected_utxos(expected_utxos).await;
                }

                // Indicate to miner that block proposal was successfully
                // received by main-loop.
                self.main_to_miner_tx.send(MainToMiner::Continue);
            }
            MinerToMain::Shutdown(exit_code) => {
                return Ok(Some(exit_code));
            }
        }

        Ok(None)
    }

    /// Locking:
    ///   * acquires `global_state_lock` for write
    async fn handle_peer_task_message(
        &mut self,
        msg: PeerTaskToMain,
        main_loop_state: &mut MutableMainLoopState,
    ) -> Result<()> {
        debug!("Received {} from a peer task", msg.get_type());
        match msg {
            PeerTaskToMain::NewBlocks(blocks) => {
                log_slow_scope!(fn_name!() + "::PeerTaskToMain::NewBlocks");

                let block_hashes = blocks.iter().map(|x| x.hash()).collect_vec();
                let last_block = blocks.last().unwrap().to_owned();
                let update_jobs = {
                    // The peer tasks also check this condition, if block is more canonical than current
                    // tip, but we have to check it again since the block update might have already been applied
                    // through a message from another peer (or from own miner).
                    let sync_mode_threshold = self.global_state_lock.cli().sync_mode_threshold;
                    let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;
                    let new_canonical =
                        global_state_mut.incoming_block_is_more_canonical(&last_block);

                    if !new_canonical {
                        // The blocks are not canonical, but: if we are in sync
                        // mode and these blocks beat our current champion, then
                        // we store them anyway, without marking them as tip.
                        let Some(sync_anchor) = global_state_mut.net.sync_anchor.as_mut() else {
                            warn!(
                                "Blocks were not new, and we're not syncing. Not storing blocks."
                            );
                            return Ok(());
                        };
                        if sync_anchor
                            .champion
                            .is_some_and(|(height, _)| height >= last_block.header().height)
                        {
                            warn!("Repeated blocks received in sync mode, not storing");
                            return Ok(());
                        }

                        sync_anchor.catch_up(last_block.header().height, last_block.hash());

                        for block in blocks {
                            global_state_mut.store_block_not_tip(block).await?;
                        }

                        global_state_mut.flush_databases().await?;

                        return Ok(());
                    }

                    info!(
                        "Last block from peer is new canonical tip: {:x}; height: {}",
                        last_block.hash(),
                        last_block.header().height
                    );

                    // Ask miner to stop work until state update is completed
                    self.main_to_miner_tx.send(MainToMiner::WaitForContinue);

                    // Get out of sync mode if needed
                    if global_state_mut.net.sync_anchor.is_some() {
                        let stay_in_sync_mode = stay_in_sync_mode(
                            &last_block.kernel.header,
                            &main_loop_state.sync_state,
                            sync_mode_threshold,
                        );
                        if !stay_in_sync_mode {
                            info!("Exiting sync mode");
                            global_state_mut.net.sync_anchor = None;
                            self.main_to_miner_tx.send(MainToMiner::StopSyncing);
                        }
                    }

                    let mut update_jobs: Vec<MempoolUpdateJob> = vec![];
                    for new_block in blocks {
                        debug!(
                            "Storing block {:x} in database. Height: {}, Mined: {}",
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
                        // [GlobalState::tests::setting_same_tip_twice_is_allowed]
                        // test for a test of this phenomenon.

                        let update_jobs_ = global_state_mut.set_new_tip(new_block).await?;

                        update_jobs.extend(update_jobs_);
                    }

                    global_state_mut.flush_databases().await?;

                    update_jobs
                };

                // Inform all peers about new block
                let pmsg = MainToPeerTask::Block(Box::new(last_block.clone()));
                self.main_to_peer_broadcast(pmsg);

                for block_hash in block_hashes {
                    Self::spawn_block_notify_command(
                        &self.global_state_lock.cli().block_notify,
                        block_hash,
                    );
                }

                // Spawn task to handle mempool tx-updating after new blocks.
                // TODO: Do clever trick to collapse all jobs relating to the same transaction,
                //       identified by transaction-ID, into *one* update job.
                self.spawn_mempool_txs_update_job(main_loop_state, update_jobs);

                // Inform miner about new block.
                self.main_to_miner_tx.send(MainToMiner::NewBlock);
            }
            PeerTaskToMain::AddPeerMaxBlockHeight {
                peer_address,
                claimed_height,
                claimed_cumulative_pow,
                claimed_block_mmra,
            } => {
                log_slow_scope!(fn_name!() + "::PeerTaskToMain::AddPeerMaxBlockHeight");

                let claimed_state =
                    PeerSynchronizationState::new(claimed_height, claimed_cumulative_pow);
                main_loop_state
                    .sync_state
                    .peer_sync_states
                    .insert(peer_address, claimed_state);

                // Check if synchronization mode should be activated.
                // Synchronization mode is entered if accumulated PoW exceeds
                // our tip and if the height difference is positive and beyond
                // a threshold value.
                let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;
                if global_state_mut.sync_mode_criterion(claimed_height, claimed_cumulative_pow)
                    && global_state_mut
                        .net
                        .sync_anchor
                        .as_ref()
                        .is_none_or(|sa| sa.cumulative_proof_of_work < claimed_cumulative_pow)
                {
                    info!(
                        "Entering synchronization mode due to peer {} indicating tip height {}; cumulative pow: {:?}",
                        peer_address, claimed_height, claimed_cumulative_pow
                    );
                    global_state_mut.net.sync_anchor =
                        Some(SyncAnchor::new(claimed_cumulative_pow, claimed_block_mmra));
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
                let sync_mode_threshold = self.global_state_lock.cli().sync_mode_threshold;
                let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;

                if global_state_mut.net.sync_anchor.is_some() {
                    let stay_in_sync_mode = stay_in_sync_mode(
                        global_state_mut.chain.light_state().header(),
                        &main_loop_state.sync_state,
                        sync_mode_threshold,
                    );
                    if !stay_in_sync_mode {
                        info!("Exiting sync mode");
                        global_state_mut.net.sync_anchor = None;
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
                        max_peers,
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

                {
                    let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;
                    if pt2m_transaction.confirmable_for_block
                        != global_state_mut.chain.light_state().hash()
                    {
                        warn!("main loop got unmined transaction with bad mutator set data, discarding transaction");
                        return Ok(());
                    }

                    global_state_mut
                        .mempool_insert(
                            pt2m_transaction.transaction.to_owned(),
                            UpgradePriority::Irrelevant,
                        )
                        .await;
                }

                let is_nop = pt2m_transaction.transaction.kernel.inputs.is_empty()
                    && pt2m_transaction.transaction.kernel.outputs.is_empty()
                    && pt2m_transaction.transaction.kernel.announcements.is_empty();
                if !is_nop {
                    // if meaningful, send notification to peers
                    let transaction_notification: TransactionNotification =
                        (&pt2m_transaction.transaction).try_into()?;

                    let pmsg = MainToPeerTask::TransactionNotification(transaction_notification);
                    self.main_to_peer_broadcast(pmsg);
                }
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
                let should_inform_own_miner = {
                    let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;
                    let verdict = global_state_mut.favor_incoming_block_proposal(
                        block.header().prev_block_digest,
                        block
                            .body()
                            .total_guesser_reward()
                            .expect("block received by main loop must have guesser reward"),
                    );
                    if let Err(reject_reason) = verdict {
                        warn!("main loop got unfavorable block proposal. Reason: {reject_reason}");
                        return Ok(());
                    }

                    global_state_mut.mining_state.block_proposal =
                        BlockProposal::foreign_proposal(*block.clone());

                    global_state_mut.block_proposal_warrants_guess_restart(&block)
                };

                // Notify all peers of the block proposal we just accepted. Do
                // this regardless of the difference in guesser fee relative to
                // the previous proposal (as long as it is positive).
                let pmsg = MainToPeerTask::BlockProposalNotification((&*block).into());
                self.main_to_peer_broadcast(pmsg);

                if should_inform_own_miner {
                    if self.global_state_lock.cli().guess {
                        info!("Received new favorable block proposal for mining operation.");
                    } else {
                        debug!("Received new favorable block proposal");
                    }
                    self.main_to_miner_tx.send(MainToMiner::NewBlockProposal);
                }
            }
            PeerTaskToMain::DisconnectFromLongestLivedPeer => {
                let global_state = self.global_state_lock.lock_guard().await;

                // get all peers
                let all_peers = global_state.net.peer_map.iter();

                // filter out CLI peers
                let disconnect_candidates =
                    all_peers.filter(|p| !global_state.cli().peers.contains(p.0));

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
                    let pmsg = MainToPeerTask::Disconnect(peer_socket.to_owned());
                    self.main_to_peer_broadcast(pmsg);
                }
            }
        }

        Ok(())
    }

    /// If necessary, disconnect from peers.
    ///
    /// While a reasonable effort is made to never have more connections than
    /// [`max_num_peers`](crate::application::config::cli_args::Args::max_num_peers),
    /// this is not guaranteed. For example, bootstrap nodes temporarily allow a
    /// surplus of incoming connections to provide their service more reliably.
    ///
    /// Never disconnects peers listed as CLI arguments.
    ///
    /// Locking:
    ///   * acquires `global_state_lock` for read
    async fn prune_peers(&self) -> Result<()> {
        // fetch all relevant info from global state; don't hold the lock
        let cli_args = self.global_state_lock.cli();
        let connected_peers = self
            .global_state_lock
            .lock_guard()
            .await
            .net
            .peer_map
            .values()
            .cloned()
            .collect_vec();

        let num_peers = connected_peers.len();
        let max_num_peers = cli_args.max_num_peers;
        if num_peers <= max_num_peers {
            debug!("No need to prune any peer connections.");
            return Ok(());
        }
        warn!("Connected to {num_peers} peers, which exceeds the maximum ({max_num_peers}).");

        // If all connections are outbound, it's OK to exceed the max.
        if connected_peers.iter().all(|p| p.connection_is_outbound()) {
            warn!("Not disconnecting from any peer because all connections are outbound.");
            return Ok(());
        }

        let num_peers_to_disconnect = num_peers - max_num_peers;
        let peers_to_disconnect = connected_peers
            .into_iter()
            .filter(|peer| !cli_args.peers.contains(&peer.connected_address()))
            .choose_multiple(&mut rand::rng(), num_peers_to_disconnect);
        match peers_to_disconnect.len() {
            0 => warn!("Not disconnecting from any peer because of manual override."),
            i => info!("Disconnecting from {i} peers."),
        }
        for peer in peers_to_disconnect {
            let pmsg = MainToPeerTask::Disconnect(peer.connected_address());
            self.main_to_peer_broadcast(pmsg);
        }

        Ok(())
    }

    /// If necessary, reconnect to the peers listed as CLI arguments.
    ///
    /// Locking:
    ///   * acquires `global_state_lock` for read
    async fn reconnect(&self, main_loop_state: &mut MutableMainLoopState) -> Result<()> {
        let connected_peers = self
            .global_state_lock
            .lock_guard()
            .await
            .net
            .peer_map
            .keys()
            .copied()
            .collect_vec();
        let peers_with_lost_connection = self
            .global_state_lock
            .cli()
            .peers
            .iter()
            .filter(|peer| !connected_peers.contains(peer));

        // If no connection was lost, there's nothing to do.
        if peers_with_lost_connection.clone().count() == 0 {
            return Ok(());
        }

        // Else, try to reconnect.
        let own_handshake_data = self
            .global_state_lock
            .lock_guard()
            .await
            .get_own_handshakedata();
        for &peer_with_lost_connection in peers_with_lost_connection {
            // Disallow reconnection if peer is in bad standing
            let peer_standing = self
                .global_state_lock
                .lock_guard()
                .await
                .net
                .get_peer_standing_from_database(peer_with_lost_connection.ip())
                .await;
            if peer_standing.is_some_and(|standing| standing.is_bad()) {
                debug!("Not reconnecting to peer in bad standing: {peer_with_lost_connection}");
                continue;
            }

            debug!("Attempting to reconnect to peer: {peer_with_lost_connection}");
            let global_state_lock = self.global_state_lock.clone();
            let main_to_peer_broadcast_rx = self.main_to_peer_broadcast_tx.subscribe();
            let peer_task_to_main_tx = self.peer_task_to_main_tx.to_owned();
            let outgoing_connection_task = tokio::task::spawn(async move {
                call_peer(
                    peer_with_lost_connection,
                    global_state_lock,
                    main_to_peer_broadcast_rx,
                    peer_task_to_main_tx,
                    own_handshake_data,
                    1, // All CLI-specified peers have distance 1
                )
                .await;
            });
            main_loop_state.task_handles.push(outgoing_connection_task);
            main_loop_state.task_handles.retain(|th| !th.is_finished());
        }

        Ok(())
    }

    /// Perform peer discovery.
    ///
    /// Peer discovery involves finding potential peers from connected peers
    /// and attempts to establish a connection with one of them.
    ///
    /// Locking:
    ///   * acquires `global_state_lock` for read
    async fn discover_peers(&self, main_loop_state: &mut MutableMainLoopState) -> Result<()> {
        // fetch all relevant info from global state, then release the lock
        let cli_args = self.global_state_lock.cli();
        let global_state = self.global_state_lock.lock_guard().await;
        let connected_peers = global_state.net.peer_map.values().cloned().collect_vec();
        let own_instance_id = global_state.net.instance_id;
        let own_handshake_data = global_state.get_own_handshakedata();
        drop(global_state);

        let num_peers = connected_peers.len();
        let max_num_peers = cli_args.max_num_peers;

        // Don't make an outgoing connection if
        // - the peer limit is reached (or exceeded), or
        // - the peer limit is _almost_ reached; reserve the last slot for an
        //   incoming connection.
        if num_peers >= max_num_peers || num_peers > 2 && num_peers - 1 == max_num_peers {
            debug!("Connected to {num_peers} peers. The configured max is {max_num_peers} peers.");
            debug!("Skipping peer discovery.");
            return Ok(());
        }

        debug!("Performing peer discovery");

        // Ask all peers for their peer lists. This will eventually – once the
        // responses have come in – update the list of potential peers.
        let pmsg = MainToPeerTask::MakePeerDiscoveryRequest;
        self.main_to_peer_broadcast(pmsg);

        // Get a peer candidate from the list of potential peers. Generally,
        // the peer lists requested in the previous step will not have come in
        // yet. Therefore, the new candidate is selected based on somewhat
        // (but not overly) old information.
        let Some((peer_candidate, candidate_distance)) = main_loop_state
            .potential_peers
            .get_candidate(&connected_peers, own_instance_id)
        else {
            debug!("Found no peer candidate to connect to. Not making new connection.");
            return Ok(());
        };

        // Try to connect to the selected candidate.
        debug!("Connecting to peer {peer_candidate} with distance {candidate_distance}");
        let global_state_lock = self.global_state_lock.clone();
        let main_to_peer_broadcast_rx = self.main_to_peer_broadcast_tx.subscribe();
        let peer_task_to_main_tx = self.peer_task_to_main_tx.to_owned();
        let outgoing_connection_task = tokio::task::spawn(async move {
            call_peer(
                peer_candidate,
                global_state_lock,
                main_to_peer_broadcast_rx,
                peer_task_to_main_tx,
                own_handshake_data,
                candidate_distance,
            )
            .await;
        });
        main_loop_state.task_handles.push(outgoing_connection_task);
        main_loop_state.task_handles.retain(|th| !th.is_finished());

        // Immediately request the new peer's peer list. This allows
        // incorporating the new peer's peers into the list of potential peers,
        // to be used in the next round of peer discovery.
        let m2pmsg = MainToPeerTask::MakeSpecificPeerDiscoveryRequest(peer_candidate);
        self.main_to_peer_broadcast(m2pmsg);

        Ok(())
    }

    /// Return a list of block heights for a block-batch request.
    ///
    /// Returns an ordered list of the heights of *most preferred block*
    /// to build on, where current tip is always the most preferred block.
    ///
    /// Uses a factor to ensure that the peer will always have something to
    /// build on top of by providing potential starting points all the way
    /// back to genesis.
    fn batch_request_uca_candidate_heights(own_tip_height: BlockHeight) -> Vec<BlockHeight> {
        const FACTOR: f64 = 1.07f64;

        let mut look_behind = 0;
        let mut ret = vec![];

        // A factor of 1.07 can look back ~1m blocks in 200 digests.
        while ret.len() < MAX_NUM_DIGESTS_IN_BATCH_REQUEST - 1 {
            let height = match own_tip_height.checked_sub(look_behind) {
                None => break,
                Some(height) if height.is_genesis() => break,
                Some(height) => height,
            };

            ret.push(height);
            look_behind = ((look_behind as f64 + 1.0) * FACTOR).floor() as u64;
        }

        ret.push(BlockHeight::genesis());

        ret
    }

    /// Logic for requesting the batch-download of blocks from peers
    ///
    /// Locking:
    ///   * acquires `global_state_lock` for read
    async fn block_sync(&mut self, main_loop_state: &mut MutableMainLoopState) -> Result<()> {
        let global_state = self.global_state_lock.lock_guard().await;

        // Check if we are in sync mode
        let Some(anchor) = &global_state.net.sync_anchor else {
            return Ok(());
        };

        debug!("Running sync");

        let (own_tip_hash, own_tip_height, own_cumulative_pow) = (
            global_state.chain.light_state().hash(),
            global_state.chain.light_state().kernel.header.height,
            global_state
                .chain
                .light_state()
                .kernel
                .header
                .cumulative_proof_of_work,
        );

        // Check if sync mode has timed out entirely, in which case it should
        // be abandoned.
        let anchor = anchor.to_owned();
        if self.now().duration_since(anchor.updated)? > GLOBAL_SYNCHRONIZATION_TIMEOUT {
            warn!("Sync mode has timed out. Abandoning sync mode.");

            // Abandon attempt, and punish all peers claiming to serve these
            // blocks.
            drop(global_state);
            self.global_state_lock
                .lock_guard_mut()
                .await
                .net
                .sync_anchor = None;

            let peers_to_punish = main_loop_state
                .sync_state
                .get_potential_peers_for_sync_request(own_cumulative_pow);

            for peer in peers_to_punish {
                let pmsg = MainToPeerTask::PeerSynchronizationTimeout(peer);
                self.main_to_peer_broadcast(pmsg);
            }

            return Ok(());
        }

        let (peer_to_sanction, try_new_request): (Option<SocketAddr>, bool) = main_loop_state
            .sync_state
            .get_status_of_last_request(own_tip_height, self.now());

        // Sanction peer if they failed to respond
        if let Some(peer) = peer_to_sanction {
            let pmsg = MainToPeerTask::PeerSynchronizationTimeout(peer);
            self.main_to_peer_broadcast(pmsg);
        }

        if !try_new_request {
            debug!("Waiting for last sync to complete.");
            return Ok(());
        }

        // Create the next request from the reported
        info!("Creating new sync request");

        // Pick a random peer that has reported to have relevant blocks
        let candidate_peers = main_loop_state
            .sync_state
            .get_potential_peers_for_sync_request(own_cumulative_pow);
        let chosen_peer = candidate_peers.choose(&mut rand::rng());
        assert!(
            chosen_peer.is_some(),
            "A synchronization candidate must be available for a request. \
            Otherwise, the data structure is in an invalid state and syncing should not be active"
        );

        let ordered_preferred_block_digests = match anchor.champion {
            Some((_height, digest)) => vec![digest],
            None => {
                // Find candidate-UCA digests based on a sparse distribution of
                // block heights skewed towards own tip height
                let request_heights = Self::batch_request_uca_candidate_heights(own_tip_height);
                let mut ordered_preferred_block_digests = vec![];
                for height in request_heights {
                    let digest = global_state
                        .chain
                        .archival_state()
                        .archival_block_mmr
                        .ammr()
                        .get_leaf_async(height.into())
                        .await;
                    ordered_preferred_block_digests.push(digest);
                }
                ordered_preferred_block_digests
            }
        };

        // Send message to the relevant peer loop to request the blocks
        let chosen_peer = chosen_peer.unwrap();
        info!(
            "Sending block batch request to {}\nrequesting blocks descending from {:x}\n height {}",
            chosen_peer, own_tip_hash, own_tip_height
        );
        let pmsg = MainToPeerTask::RequestBlockBatch(MainToPeerTaskBatchBlockRequest {
            peer_addr_target: *chosen_peer,
            known_blocks: ordered_preferred_block_digests,
            anchor_mmr: anchor.block_mmr.clone(),
        });
        self.main_to_peer_broadcast(pmsg);

        // Record that this request was sent to the peer
        let requested_block_height = own_tip_height.next();
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
            main_loop_state: &MutableMainLoopState,
        ) -> bool {
            let previous_upgrade_task_is_still_running = main_loop_state
                .proof_upgrader_task
                .as_ref()
                .is_some_and(|x| !x.is_finished());
            global_state.cli().tx_proof_upgrading
                && global_state.net.sync_anchor.is_none()
                && global_state.proving_capability() == TxProvingCapability::SingleProof
                && !previous_upgrade_task_is_still_running
        }

        trace!("Running proof upgrader scheduled task");

        // Check if it's time to run the proof-upgrader, and if we're capable
        // of upgrading a transaction proof.
        let upgrade_candidate = {
            let mut global_state = self.global_state_lock.lock_guard_mut().await;
            if !attempt_upgrade(&global_state, main_loop_state) {
                trace!("Not attempting upgrade.");
                return Ok(());
            }

            debug!("Attempting to run transaction-proof-upgrade");

            // Find a candidate for proof upgrade
            let Some(upgrade_candidate) = get_upgrade_task_from_mempool(&mut global_state).await
            else {
                debug!("Found no transaction-proof to upgrade");
                return Ok(());
            };

            upgrade_candidate
        };

        info!(
            "Attempting to upgrade transaction proofs of: {}",
            upgrade_candidate.affected_txids().iter().join("; ")
        );

        // Perform the upgrade, if we're not using the prover for anything else,
        // like mining, or proving our own transaction. Running the prover takes
        // a long time (minutes), so we spawn a task for this such that we do
        // not block the main loop.
        let vm_job_queue = vm_job_queue();

        let global_state_lock_clone = self.global_state_lock.clone();
        let main_to_peer_broadcast_tx_clone = self.main_to_peer_broadcast_tx.clone();
        let proof_upgrader_task = tokio::task::spawn(async move {
            upgrade_candidate
                .handle_upgrade(
                    vm_job_queue,
                    global_state_lock_clone,
                    main_to_peer_broadcast_tx_clone,
                )
                .await
        });

        main_loop_state.proof_upgrader_task = Some(proof_upgrader_task);

        Ok(())
    }

    /// Post-processing when new block has arrived. Spawn a task to update
    /// transactions in the mempool. Only when the spawned task has completed,
    /// should the miner continue.
    fn spawn_mempool_txs_update_job(
        &self,
        main_loop_state: &mut MutableMainLoopState,
        update_jobs: Vec<MempoolUpdateJob>,
    ) {
        // job completion of the spawned task is communicated through the
        // `update_mempool_txs_handle` channel.
        let vm_job_queue = vm_job_queue();
        if let Some(handle) = main_loop_state.update_mempool_txs_handle.as_ref() {
            handle.abort();
        }
        let (update_sender, update_receiver) =
            mpsc::channel::<Vec<MempoolUpdateJobResult>>(TX_UPDATER_CHANNEL_CAPACITY);

        // note: if this task is cancelled, the job will continue
        // because TritonVmJobOptions::cancel_job_rx is None.
        // see how compose_task handles cancellation in mine_loop.
        let job_options = self
            .global_state_lock
            .cli()
            .proof_job_options(TritonVmJobPriority::Highest);
        let global_state_lock = self.global_state_lock.clone();
        main_loop_state.update_mempool_txs_handle = Some(tokio::task::spawn(async move {
            Self::update_mempool_jobs(
                global_state_lock,
                update_jobs,
                vm_job_queue.clone(),
                update_sender,
                job_options,
            )
            .await
        }));
        main_loop_state.update_mempool_receiver = update_receiver;
    }

    pub async fn run(&mut self) -> Result<i32> {
        info!("Starting main loop");

        let task_handles = std::mem::take(&mut self.task_handles);

        // Handle incoming connections, messages from peer tasks, and messages from the mining task
        let mut main_loop_state = MutableMainLoopState::new(task_handles);

        // Set up various timers.
        //
        // The `MissedTickBehavior::Delay` is appropriate for tasks that don't
        // do anything meaningful if executed in quick succession. For example,
        // pruning stale information immediately after pruning stale information
        // is almost certainly a no-op.
        // Similarly, tasks performing network operations (e.g., peer discovery)
        // should probably not try to “catch up” if some ticks were missed.

        // Don't run peer discovery immediately at startup since outgoing
        // connections started from lib.rs may not have finished yet.
        let mut peer_discovery_interval = time::interval_at(
            Instant::now() + PEER_DISCOVERY_INTERVAL,
            PEER_DISCOVERY_INTERVAL,
        );
        peer_discovery_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let mut block_sync_interval = time::interval(SYNC_REQUEST_INTERVAL);
        block_sync_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let mut mempool_cleanup_interval = time::interval(MEMPOOL_PRUNE_INTERVAL);
        mempool_cleanup_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let mut utxo_notification_cleanup_interval = time::interval(EXPECTED_UTXOS_PRUNE_INTERVAL);
        utxo_notification_cleanup_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let mut mp_resync_interval = time::interval(MP_RESYNC_INTERVAL);
        mp_resync_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let mut tx_proof_upgrade_interval = time::interval(PROOF_UPGRADE_INTERVAL);
        tx_proof_upgrade_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        // Spawn tasks to monitor for SIGTERM, SIGINT, and SIGQUIT. These
        // signals are only used on Unix systems.
        let (tx_term, mut rx_term) = mpsc::channel::<()>(2);
        let (tx_int, mut rx_int) = mpsc::channel::<()>(2);
        let (tx_quit, mut rx_quit) = mpsc::channel::<()>(2);
        #[cfg(unix)]
        {
            use tokio::signal::unix::signal;
            use tokio::signal::unix::SignalKind;

            // Monitor for SIGTERM
            let mut sigterm = signal(SignalKind::terminate())?;
            tokio::task::spawn(async move {
                if sigterm.recv().await.is_some() {
                    info!("Received SIGTERM");
                    tx_term.send(()).await.unwrap();
                }
            });

            // Monitor for SIGINT
            let mut sigint = signal(SignalKind::interrupt())?;
            tokio::task::spawn(async move {
                if sigint.recv().await.is_some() {
                    info!("Received SIGINT");
                    tx_int.send(()).await.unwrap();
                }
            });

            // Monitor for SIGQUIT
            let mut sigquit = signal(SignalKind::quit())?;
            tokio::task::spawn(async move {
                if sigquit.recv().await.is_some() {
                    info!("Received SIGQUIT");
                    tx_quit.send(()).await.unwrap();
                }
            });
        }

        #[cfg(not(unix))]
        drop((tx_term, tx_int, tx_quit));

        // Use a semaphore to limit number of incoming connections. Should only be
        // relevant as a countermeasure against a DOS. Each incoming connection
        // must acquire a permit. If none is free, the below call to `acquire_owned`
        // will only be resolved when an incoming connection is closed. This
        // value is set much higher than the configured max number of peers since it's
        // only intended to be used in case of heavy DOS.
        let incoming_connections_limit = Arc::new(Semaphore::new(
            self.global_state_lock.cli().max_num_peers * 2 + 4,
        ));

        let exit_code: i32 = loop {
            select! {
                Ok(()) = signal::ctrl_c() => {
                    info!("Detected Ctrl+c signal.");
                    break SUCCESS_EXIT_CODE;
                }

                // Monitor for SIGTERM, SIGINT, and SIGQUIT.
                Some(_) = rx_term.recv() => {
                    info!("Detected SIGTERM signal.");
                    break SUCCESS_EXIT_CODE;
                }
                Some(_) = rx_int.recv() => {
                    info!("Detected SIGINT signal.");
                    break SUCCESS_EXIT_CODE;
                }
                Some(_) = rx_quit.recv() => {
                    info!("Detected SIGQUIT signal.");
                    break SUCCESS_EXIT_CODE;
                }

                // Handle incoming connections from peer
                Ok((stream, peer_address)) = self.incoming_peer_listener.accept() => {
                    let ip = peer_address.ip();
                    if !precheck_incoming_connection_is_allowed(self.global_state_lock.cli(), ip) {
                        continue;
                    }

                    // Is this IP banned through database entry?
                    let peer_banned = self.global_state_lock.lock_guard().await.net.peer_databases.peer_standings.get(ip).await.is_some_and(|x| x.is_bad());
                    if peer_banned {
                        debug!("Banned peer {ip} attempted incoming connection. Hanging up.");
                        continue;
                    }

                    // Bump semaphore counter for incoming connections. Should
                    // be done after the precheck to prevent unnecessary
                    // acquisitions.
                    let timeout = Duration::from_secs(self.global_state_lock.cli().handshake_timeout.into());
                    let permit = time::timeout(timeout, incoming_connections_limit.clone().acquire_owned()).await;
                    let Ok(permit) = permit else {
                        warn!("Too many incoming connections to handle. Dropping incoming connection from {ip}.");
                        continue;
                    };

                    let permit = permit?;

                    let state = self.global_state_lock.lock_guard().await;
                    let main_to_peer_broadcast_rx_clone: broadcast::Receiver<MainToPeerTask> = self.main_to_peer_broadcast_tx.subscribe();
                    let peer_task_to_main_tx_clone: mpsc::Sender<PeerTaskToMain> = self.peer_task_to_main_tx.clone();
                    let own_handshake_data: HandshakeData = state.get_own_handshakedata();
                    let global_state_lock = self.global_state_lock.clone(); // bump arc refcount.
                    let incoming_peer_task_handle = tokio::task::spawn(async move {
                        // permit gets dropped at end of scope, to release slot.
                        let _permit = permit;

                        match answer_peer(
                            stream,
                            global_state_lock,
                            peer_address,
                            main_to_peer_broadcast_rx_clone,
                            peer_task_to_main_tx_clone,
                            own_handshake_data,
                        ).await {
                            Ok(()) => (),
                            Err(err) => debug!("Got result: {:?}", err),
                        }
                    });
                    main_loop_state.task_handles.push(incoming_peer_task_handle);
                    main_loop_state.task_handles.retain(|th| !th.is_finished());
                }

                // Handle messages from peer tasks
                Some(msg) = self.peer_task_to_main_rx.recv() => {
                    debug!("Received message sent to main task.");
                    self.handle_peer_task_message(
                        msg,
                        &mut main_loop_state,
                    )
                    .await?
                }

                // Handle messages from miner task
                Some(main_message) = self.miner_to_main_rx.recv() => {
                    let exit_code = self.handle_miner_task_message(main_message, &mut main_loop_state).await?;

                    if let Some(exit_code) = exit_code {
                        break exit_code;
                    }

                }

                // Handle the completion of mempool tx-update jobs after new block.
                Some(ms_updated_transactions) = main_loop_state.update_mempool_receiver.recv() => {
                    self.handle_updated_mempool_txs(ms_updated_transactions).await;
                }

                // Handle messages from rpc server task
                Some(rpc_server_message) = self.rpc_server_to_main_rx.recv() => {
                    let shutdown_after_execution = self.handle_rpc_server_message(rpc_server_message.clone(), &mut main_loop_state).await?;
                    if shutdown_after_execution {
                        break SUCCESS_EXIT_CODE
                    }
                }

                // Handle peer discovery
                _ = peer_discovery_interval.tick() => {
                    log_slow_scope!(fn_name!() + "::select::peer_discovery_interval");

                    // Check number of peers we are connected to and connect to
                    // more peers if needed.
                    debug!("Timer: peer discovery job");

                    let perform_discovery = if !self.global_state_lock.cli().network.performs_peer_discovery() {
                        // this makes regtest mode behave in a local, controlled way
                        // because no regtest nodes attempt to discover eachother, so the only
                        // peers are those that are manually added.
                        // see: https://github.com/Neptune-Crypto/neptune-core/issues/539#issuecomment-2764701027
                        debug!("peer discovery disabled for network {}", self.global_state_lock.cli().network);
                        false
                    } else if self.global_state_lock.cli().restrict_peers_to_list {
                        debug!("peer discovery disabled due to --restrict-peers-to-list");
                        false
                    } else {
                        true
                    };

                    if perform_discovery {
                        self.prune_peers().await?;
                        self.reconnect(&mut main_loop_state).await?;
                        self.discover_peers(&mut main_loop_state).await?;
                    }
                }

                // Handle synchronization (i.e. batch-downloading of blocks)
                _ = block_sync_interval.tick() => {
                    log_slow_scope!(fn_name!() + "::select::block_sync_interval");

                    trace!("Timer: block-synchronization job");
                    self.block_sync(&mut main_loop_state).await?;
                }

                // Clean up mempool: remove stale / too old transactions
                _ = mempool_cleanup_interval.tick() => {
                    log_slow_scope!(fn_name!() + "::select::mempool_cleanup_interval");

                    debug!("Timer: mempool-cleaner job");
                    self
                        .global_state_lock
                        .lock_guard_mut()
                        .await
                        .mempool_prune_stale_transactions()
                        .await;
                }

                // Clean up incoming UTXO notifications: remove stale / too old
                // UTXO notifications from pool
                _ = utxo_notification_cleanup_interval.tick() => {
                    log_slow_scope!(fn_name!() + "::select::utxo_notification_cleanup_interval");

                    debug!("Timer: UTXO notification pool cleanup job");

                    // Danger: possible loss of funds.
                    //
                    // See description of prune_stale_expected_utxos().
                    //
                    // This call is disabled until such time as a thorough
                    // evaluation and perhaps reimplementation determines that
                    // it can be called safely without possible loss of funds.
                    // self.global_state_lock.lock_mut(|s| s.wallet_state.prune_stale_expected_utxos()).await;
                }

                // Handle membership proof resynchronization
                _ = mp_resync_interval.tick() => {
                    log_slow_scope!(fn_name!() + "::select::mp_resync_interval");

                    debug!("Timer: Membership proof resync job");
                    self.global_state_lock.resync_membership_proofs().await?;
                }

                // run the proof upgrader. The callee checks if proof upgrading
                // should be done.
                _ = tx_proof_upgrade_interval.tick() => {
                    log_slow_scope!(fn_name!() + "::select::tx_proof_upgrade_interval");

                    trace!("Timer: tx-proof-upgrader");
                    self.proof_upgrader(&mut main_loop_state).await?;
                }

            }
        };

        self.graceful_shutdown(main_loop_state.task_handles).await?;
        info!("Shutdown completed.");

        Ok(exit_code)
    }

    /// Handle messages from the RPC server. Returns `true` iff the client should shut down
    /// after handling this message.
    async fn handle_rpc_server_message(
        &mut self,
        msg: RPCServerToMain,
        main_loop_state: &mut MutableMainLoopState,
    ) -> Result<bool> {
        match msg {
            RPCServerToMain::BroadcastTx(transaction) => {
                debug!(
                            "`main` received following transaction from RPC Server. {} inputs, {} outputs. Synced to mutator set hash: {}",
                            transaction.kernel.inputs.len(),
                            transaction.kernel.outputs.len(),
                            transaction.kernel.mutator_set_hash
                        );

                // note: this Tx must already have been added to the mempool by
                // sender.  This occurs in GlobalStateLock::record_transaction().

                // Is this a transaction we can share with peers? If so, share
                // it immediately.
                if let Ok(notification) = transaction.as_ref().try_into() {
                    let pmsg = MainToPeerTask::TransactionNotification(notification);
                    self.main_to_peer_broadcast(pmsg);
                } else {
                    // Otherwise, upgrade its proof quality, and share it by
                    // spinning up the proof upgrader.
                    let primitive_witness = transaction.proof.clone().into_primitive_witness();

                    let vm_job_queue = vm_job_queue();

                    let proving_capability = self.global_state_lock.cli().proving_capability();
                    let network = self.global_state_lock.cli().network;
                    let upgrade_job = UpgradeJob::from_primitive_witness(
                        network,
                        proving_capability,
                        primitive_witness,
                    );

                    // note: handle_upgrade() hands off proving to the
                    //       triton-vm job queue and waits for job completion.
                    // note: handle_upgrade() broadcasts to peers on success.

                    let global_state_lock_clone = self.global_state_lock.clone();
                    let main_to_peer_broadcast_tx_clone = self.main_to_peer_broadcast_tx.clone();
                    let _proof_upgrader_task = tokio::task::spawn(async move {
                        upgrade_job
                            .handle_upgrade(
                                vm_job_queue.clone(),
                                global_state_lock_clone,
                                main_to_peer_broadcast_tx_clone,
                            )
                            .await
                    });

                    // main_loop_state.proof_upgrader_task = Some(proof_upgrader_task);
                    // If transaction could not be shared immediately because
                    // it contains secret data, upgrade its proof-type.
                }

                // do not shut down
                Ok(false)
            }
            RPCServerToMain::PerformTxProofUpgrade(upgrade_job) => {
                let vm_job_queue = vm_job_queue();
                let global_state_lock_clone = self.global_state_lock.clone();
                let main_to_peer_broadcast_tx_clone = self.main_to_peer_broadcast_tx.clone();
                info!(
                    "Attempting to upgrade transactions: {}",
                    upgrade_job.affected_txids().iter().join(", ")
                );
                tokio::task::spawn(async move {
                    upgrade_job
                        .handle_upgrade(
                            vm_job_queue,
                            global_state_lock_clone,
                            main_to_peer_broadcast_tx_clone,
                        )
                        .await
                });

                Ok(false)
            }

            RPCServerToMain::BroadcastMempoolTransactions => {
                info!("Broadcasting transaction notifications for all shareable transactions in mempool");

                let mut notifications = vec![];
                {
                    let state = self.global_state_lock.lock_guard().await;
                    for (txid, _) in state.mempool.fee_density_iter() {
                        // Since a read-lock is held over global state, the
                        // transaction must exist in the mempool.
                        let tx = state
                            .mempool
                            .get(txid)
                            .expect("Transaction from iter must exist in mempool");
                        let notification = TransactionNotification::try_from(tx);
                        match notification {
                            Ok(notification) => {
                                let pmsg = MainToPeerTask::TransactionNotification(notification);
                                notifications.push(pmsg);
                            }
                            Err(error) => {
                                warn!("{error}");
                            }
                        };
                    }
                }

                for notification in notifications {
                    self.main_to_peer_broadcast(notification);
                }

                Ok(false)
            }
            RPCServerToMain::SetTipToStoredBlock(digest) => {
                info!("setting tip to {digest:x}");

                let block_notify = self.global_state_lock.cli().block_notify.clone();
                let res = self
                    .global_state_lock()
                    .lock_guard_mut()
                    .await
                    .set_tip_to_stored_block(digest)
                    .await;
                match res {
                    Ok(_) => Self::spawn_block_notify_command(&block_notify, digest),
                    Err(e) => error!("Failed to set tip to {digest:x}: {e}"),
                };

                Ok(false)
            }
            RPCServerToMain::BroadcastBlockProposal => {
                let pmsg = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .mining_state
                    .block_proposal
                    .map(|proposal| MainToPeerTask::BlockProposalNotification(proposal.into()));
                if let Some(pmsg) = pmsg {
                    info!("Broadcasting block proposal notification to all peers.");
                    self.main_to_peer_broadcast(pmsg);
                } else {
                    info!("Was asked to broadcast block proposal but none is known.");
                }

                Ok(false)
            }
            RPCServerToMain::ClearMempool => {
                info!("Clearing mempool");
                self.global_state_lock
                    .lock_guard_mut()
                    .await
                    .mempool_clear()
                    .await;

                Ok(false)
            }
            RPCServerToMain::ProofOfWorkSolution(new_block) => {
                info!("Handling PoW solution from RPC call");

                self.handle_self_guessed_block(main_loop_state, new_block)
                    .await?;
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
                info!("Received RPC shutdown request.");

                // shut down
                Ok(true)
            }
        }
    }

    async fn graceful_shutdown(&mut self, join_handles: Vec<JoinHandle<()>>) -> Result<()> {
        info!("Shutdown initiated.");

        // Stop mining
        self.main_to_miner_tx.send(MainToMiner::Shutdown);

        // Send 'bye' message to all peers.
        let pmsg = MainToPeerTask::DisconnectAll();
        self.main_to_peer_broadcast(pmsg);
        debug!("sent bye");

        // Flush all databases
        self.global_state_lock.flush_databases().await?;

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Child tasks should have finished by now. If not, abort them.
        for jh in &join_handles {
            jh.abort();
        }

        // wait for all to finish.
        futures::future::join_all(join_handles).await;

        Ok(())
    }

    // broadcasts message to peers (if any connected)
    //
    // panics if broadcast failed and channel receiver_count is non-zero
    // indicating we have peer connections.
    fn main_to_peer_broadcast(&self, msg: MainToPeerTask) {
        if let Err(e) = self.main_to_peer_broadcast_tx.send(msg) {
            // tbd: maybe we should just log an error and ignore rather
            // than panic.  but for now this preserves prior behavior
            let receiver_count = self.main_to_peer_broadcast_tx.receiver_count();
            assert_eq!(
                receiver_count, 0,
                "failed to broadcast message from main to {} peer loops: {:?}",
                receiver_count, e
            );
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::str::FromStr;
    use std::time::UNIX_EPOCH;

    use macro_rules_attr::apply;
    use tracing_test::traced_test;

    use super::*;
    use crate::application::config::cli_args;
    use crate::application::config::network::Network;
    use crate::tests::shared::blocks::invalid_empty_block;
    use crate::tests::shared::blocks::invalid_empty_block1_with_guesser_fraction;
    use crate::tests::shared::globalstate::get_dummy_peer_incoming;
    use crate::tests::shared::globalstate::get_test_genesis_setup;
    use crate::tests::shared_tokio_runtime;
    use crate::MINER_CHANNEL_CAPACITY;

    impl MainLoopHandler {
        fn mutable(&mut self) -> MutableMainLoopState {
            MutableMainLoopState::new(std::mem::take(&mut self.task_handles))
        }
    }

    struct TestSetup {
        main_loop_handler: MainLoopHandler,
        main_to_peer_rx: broadcast::Receiver<MainToPeerTask>,
        main_to_miner_rx: mpsc::Receiver<MainToMiner>,
    }

    async fn setup(
        num_init_peers_outgoing: u8,
        num_peers_incoming: u8,
        cli: cli_args::Args,
    ) -> TestSetup {
        const CHANNEL_CAPACITY_MINER_TO_MAIN: usize = 10;

        let network = Network::Main;
        let (
            main_to_peer_tx,
            main_to_peer_rx,
            peer_to_main_tx,
            peer_to_main_rx,
            mut state,
            _own_handshake_data,
        ) = get_test_genesis_setup(network, num_init_peers_outgoing, cli)
            .await
            .unwrap();
        assert!(
            state
                .lock_guard()
                .await
                .net
                .peer_map
                .iter()
                .all(|(_addr, peer)| peer.connection_is_outbound()),
            "Test assumption: All initial peers must represent outgoing connections."
        );

        for i in 0..num_peers_incoming {
            let peer_address = SocketAddr::from_str(&format!("255.254.253.{i}:8080")).unwrap();
            state
                .lock_guard_mut()
                .await
                .net
                .peer_map
                .insert(peer_address, get_dummy_peer_incoming(peer_address));
        }

        let incoming_peer_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

        let (main_to_miner_tx, main_to_miner_rx) =
            mpsc::channel::<MainToMiner>(MINER_CHANNEL_CAPACITY);
        let (_miner_to_main_tx, miner_to_main_rx) =
            mpsc::channel::<MinerToMain>(CHANNEL_CAPACITY_MINER_TO_MAIN);
        let (_rpc_server_to_main_tx, rpc_server_to_main_rx) =
            mpsc::channel::<RPCServerToMain>(CHANNEL_CAPACITY_MINER_TO_MAIN);

        let task_join_handles = vec![];

        let main_loop_handler = MainLoopHandler::new(
            incoming_peer_listener,
            state,
            main_to_peer_tx,
            peer_to_main_tx,
            main_to_miner_tx,
            peer_to_main_rx,
            miner_to_main_rx,
            rpc_server_to_main_rx,
            task_join_handles,
        );
        TestSetup {
            main_loop_handler,
            main_to_peer_rx,
            main_to_miner_rx,
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn handle_self_guessed_block_new_tip() {
        // A new tip is registered by main_loop. Verify correct state update.
        let TestSetup {
            mut main_loop_handler,
            mut main_to_peer_rx,
            ..
        } = setup(1, 0, cli_args::Args::default()).await;
        let network = main_loop_handler.global_state_lock.cli().network;
        let mut mutable_main_loop_state = main_loop_handler.mutable();

        let block1 = invalid_empty_block(&Block::genesis(network), network);

        assert!(
            main_loop_handler
                .global_state_lock
                .lock_guard()
                .await
                .chain
                .light_state()
                .header()
                .height
                .is_genesis(),
            "Tip must be genesis prior to handling of new block"
        );

        let block1 = Box::new(block1);
        main_loop_handler
            .handle_self_guessed_block(&mut mutable_main_loop_state, block1.clone())
            .await
            .unwrap();
        let new_block_height: u64 = main_loop_handler
            .global_state_lock
            .lock_guard()
            .await
            .chain
            .light_state()
            .header()
            .height
            .into();
        assert_eq!(
            1u64, new_block_height,
            "Tip height must be 1 after handling of new block"
        );
        let msg_to_peer_loops = main_to_peer_rx.recv().await.unwrap();
        if let MainToPeerTask::Block(block_to_peers) = msg_to_peer_loops {
            assert_eq!(
                block1, block_to_peers,
                "Peer loops must have received block 1"
            );
        } else {
            panic!("Must have sent block notification to peer loops")
        }
    }

    mod update_mempool_txs {
        use super::*;
        use crate::api::export::NativeCurrencyAmount;
        use crate::tests::shared::blocks::fake_valid_deterministic_successor;
        use crate::tests::shared::mock_tx::genesis_tx_with_proof_type;

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn tx_ms_updating() {
            // Create a transaction, and insert it into the mempool. Receive a
            // block that does not include the transaction. Verify that the
            // transaction is updated to be valid under the new mutator set
            // after the application of the block and the invocation of the
            // relevant functions.
            let network = Network::Main;
            let fee = NativeCurrencyAmount::coins(1);

            let genesis_block = Block::genesis(network);
            let block1 = fake_valid_deterministic_successor(&genesis_block, network).await;
            let cli = cli_args::Args {
                tx_proving_capability: Some(TxProvingCapability::SingleProof),
                ..Default::default()
            };
            for tx_proving_capability in [
                TxProvingCapability::PrimitiveWitness,
                TxProvingCapability::ProofCollection,
                TxProvingCapability::SingleProof,
            ] {
                let num_outgoing_connections = 0;
                let num_incoming_connections = 0;
                let TestSetup {
                    mut main_loop_handler,
                    mut main_to_peer_rx,
                    ..
                } = setup(
                    num_outgoing_connections,
                    num_incoming_connections,
                    cli.clone(),
                )
                .await;

                // First insert a PW backed transaction to ensure PW is
                // present, as this determines what MS-data updating jobs are
                // returned.
                let pw_tx =
                    genesis_tx_with_proof_type(TxProvingCapability::PrimitiveWitness, network, fee)
                        .await;
                let tx = genesis_tx_with_proof_type(tx_proving_capability, network, fee).await;
                let update_jobs = {
                    let mut gsl = main_loop_handler.global_state_lock.lock_guard_mut().await;
                    gsl.mempool_insert(pw_tx.into(), UpgradePriority::Critical)
                        .await;
                    gsl.mempool_insert(tx.clone().into(), UpgradePriority::Critical)
                        .await;
                    gsl.set_new_tip(block1.clone()).await.unwrap()
                };

                assert_eq!(1, update_jobs.len(), "Must return 1 job for MS-updating");

                let (update_sender, mut update_receiver) =
                    mpsc::channel::<Vec<MempoolUpdateJobResult>>(TX_UPDATER_CHANNEL_CAPACITY);
                MainLoopHandler::update_mempool_jobs(
                    main_loop_handler.global_state_lock.clone(),
                    update_jobs,
                    vm_job_queue(),
                    update_sender,
                    TritonVmProofJobOptions::default(),
                )
                .await;

                let msg = update_receiver.recv().await.unwrap();
                assert_eq!(1, msg.len(), "Must return exactly one update result");
                assert!(
                    matches!(msg[0], MempoolUpdateJobResult::Success { .. }),
                    "Update must be a success"
                );

                main_loop_handler.handle_updated_mempool_txs(msg).await;

                // Verify that
                // a) mempool contains the updated transaction, and
                // b) that peers were informed of the new transaction, if the
                //    transaction is shareable, i.e. is not only backed by a
                //    primitive witness.
                let txid = tx.txid();
                let block1_msa = block1.mutator_set_accumulator_after().unwrap();
                assert!(
                    main_loop_handler
                        .global_state_lock
                        .lock_guard()
                        .await
                        .mempool
                        .get(txid)
                        .unwrap()
                        .clone()
                        .is_confirmable_relative_to(&block1_msa),
                    "transaction must be updatable"
                );

                if tx_proving_capability != TxProvingCapability::PrimitiveWitness {
                    let peer_msg = main_to_peer_rx.recv().await.unwrap();
                    let MainToPeerTask::TransactionNotification(tx_notification) = peer_msg else {
                        panic!("Outgoing peer message must be tx notification");
                    };
                    assert_eq!(txid, tx_notification.txid);
                    assert_eq!(block1_msa.hash(), tx_notification.mutator_set_hash);
                }
            }
        }
    }

    mod sync_mode {
        use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
        use test_strategy::proptest;

        use super::*;
        use crate::tests::shared::globalstate::get_dummy_socket_address;

        #[proptest]
        fn batch_request_heights_prop(#[strategy(0u64..100_000_000_000)] own_height: u64) {
            batch_request_heights_sanity(own_height);
        }

        #[test]
        fn batch_request_heights_unit() {
            let own_height = 1_000_000u64;
            batch_request_heights_sanity(own_height);
        }

        fn batch_request_heights_sanity(own_height: u64) {
            let heights = MainLoopHandler::batch_request_uca_candidate_heights(own_height.into());

            let mut heights_rev = heights.clone();
            heights_rev.reverse();
            assert!(
                heights_rev.is_sorted(),
                "Heights must be sorted from high-to-low"
            );

            heights_rev.dedup();
            assert_eq!(heights_rev.len(), heights.len(), "duplicates");

            assert_eq!(heights[0], own_height.into(), "starts with own tip height");
            assert!(
                heights.last().unwrap().is_genesis(),
                "ends with genesis block"
            );
        }

        #[apply(shared_tokio_runtime)]
        #[traced_test]
        async fn sync_mode_abandoned_on_global_timeout() {
            let num_outgoing_connections = 0;
            let num_incoming_connections = 0;
            let TestSetup {
                mut main_loop_handler,
                main_to_peer_rx: _main_to_peer_rx,
                ..
            } = setup(
                num_outgoing_connections,
                num_incoming_connections,
                cli_args::Args::default(),
            )
            .await;
            let mut mutable_main_loop_state = main_loop_handler.mutable();

            main_loop_handler
                .block_sync(&mut mutable_main_loop_state)
                .await
                .expect("Must return OK when no sync mode is set");

            // Mock that we are in a valid sync state
            let claimed_max_height = 1_000u64.into();
            let claimed_max_pow = ProofOfWork::new([100; 6]);
            main_loop_handler
                .global_state_lock
                .lock_guard_mut()
                .await
                .net
                .sync_anchor = Some(SyncAnchor::new(
                claimed_max_pow,
                MmrAccumulator::new_from_leafs(vec![]),
            ));
            mutable_main_loop_state.sync_state.peer_sync_states.insert(
                get_dummy_socket_address(0),
                PeerSynchronizationState::new(claimed_max_height, claimed_max_pow),
            );

            let sync_start_time = main_loop_handler
                .global_state_lock
                .lock_guard()
                .await
                .net
                .sync_anchor
                .as_ref()
                .unwrap()
                .updated;
            main_loop_handler
                .block_sync(&mut mutable_main_loop_state)
                .await
                .expect("Must return OK when sync mode has not timed out yet");
            assert!(
                main_loop_handler
                    .global_state_lock
                    .lock_guard()
                    .await
                    .net
                    .sync_anchor
                    .is_some(),
                "Sync mode must still be set before timeout has occurred"
            );

            assert_eq!(
                sync_start_time,
                main_loop_handler
                    .global_state_lock
                    .lock_guard()
                    .await
                    .net
                    .sync_anchor
                    .as_ref()
                    .unwrap()
                    .updated,
                "timestamp may not be updated without state change"
            );

            // Mock that sync-mode has timed out
            main_loop_handler = main_loop_handler.with_mocked_time(
                SystemTime::now() + GLOBAL_SYNCHRONIZATION_TIMEOUT + Duration::from_secs(1),
            );

            main_loop_handler
                .block_sync(&mut mutable_main_loop_state)
                .await
                .expect("Must return OK when sync mode has timed out");
            assert!(
                main_loop_handler
                    .global_state_lock
                    .lock_guard()
                    .await
                    .net
                    .sync_anchor
                    .is_none(),
                "Sync mode must be unset on timeout"
            );
        }
    }

    mod proof_upgrader {
        use super::*;
        use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
        use crate::protocol::consensus::transaction::Transaction;
        use crate::protocol::consensus::transaction::TransactionProof;
        use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
        use crate::protocol::peer::transfer_transaction::TransactionProofQuality;
        use crate::protocol::proof_abstractions::timestamp::Timestamp;
        use crate::state::transaction::tx_creation_config::TxCreationConfig;
        use crate::state::wallet::transaction_output::TxOutput;

        async fn tx_no_outputs(
            global_state_lock: &mut GlobalStateLock,
            tx_proof_type: TxProvingCapability,
            fee: NativeCurrencyAmount,
            consensus_rule_set: ConsensusRuleSet,
        ) -> Arc<Transaction> {
            let change_key = global_state_lock
                .lock_guard()
                .await
                .wallet_state
                .wallet_entropy
                .nth_generation_spending_key_for_tests(0);
            let in_seven_months = global_state_lock
                .lock_guard()
                .await
                .chain
                .light_state()
                .header()
                .timestamp
                + Timestamp::months(7);

            let config = TxCreationConfig::default()
                .recover_change_off_chain(change_key.into())
                .with_prover_capability(tx_proof_type);
            global_state_lock
                .api()
                .tx_initiator_internal()
                .create_transaction(
                    Vec::<TxOutput>::new().into(),
                    fee,
                    in_seven_months,
                    config,
                    consensus_rule_set,
                )
                .await
                .unwrap()
                .transaction
        }

        #[apply(shared_tokio_runtime)]
        #[traced_test]
        async fn upgrade_proof_collection_to_single_proof_foreign_tx() {
            let num_outgoing_connections = 0;
            let num_incoming_connections = 0;

            let TestSetup {
                mut main_loop_handler,
                mut main_to_peer_rx,
                ..
            } = setup(
                num_outgoing_connections,
                num_incoming_connections,
                cli_args::Args::default(),
            )
            .await;

            // Force instance to create SingleProofs, otherwise CI and other
            // weak machines fail.
            let mocked_cli = cli_args::Args {
                tx_proving_capability: Some(TxProvingCapability::SingleProof),
                tx_proof_upgrading: true,
                ..Default::default()
            };

            main_loop_handler
                .global_state_lock
                .set_cli(mocked_cli.clone())
                .await;
            let mut main_loop_handler = main_loop_handler.with_mocked_time(SystemTime::now());
            let mut mutable_main_loop_state = main_loop_handler.mutable();

            assert!(
                main_loop_handler
                    .proof_upgrader(&mut mutable_main_loop_state)
                    .await
                    .is_ok(),
                "Scheduled task returns OK when run on empty mempool"
            );

            let consensus_rule_set =
                ConsensusRuleSet::infer_from(mocked_cli.network, BlockHeight::genesis());
            let fee = NativeCurrencyAmount::coins(1);
            let proof_collection_tx = tx_no_outputs(
                &mut main_loop_handler.global_state_lock,
                TxProvingCapability::ProofCollection,
                fee,
                consensus_rule_set,
            )
            .await;

            main_loop_handler
                .global_state_lock
                .lock_guard_mut()
                .await
                .mempool_insert((*proof_collection_tx).clone(), UpgradePriority::Irrelevant)
                .await;
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
                .fee_density_iter()
                .next_back()
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
        }
    }

    mod peer_discovery {
        use super::*;

        #[apply(shared_tokio_runtime)]
        #[traced_test]
        async fn prune_peers_too_many_connections() {
            let num_init_peers_outgoing = 10;
            let num_init_peers_incoming = 4;
            let TestSetup {
                mut main_loop_handler,
                mut main_to_peer_rx,
                ..
            } = setup(
                num_init_peers_outgoing,
                num_init_peers_incoming,
                cli_args::Args::default(),
            )
            .await;

            let mocked_cli = cli_args::Args {
                max_num_peers: num_init_peers_outgoing as usize,
                ..Default::default()
            };

            main_loop_handler
                .global_state_lock
                .set_cli(mocked_cli)
                .await;

            main_loop_handler.prune_peers().await.unwrap();
            assert_eq!(4, main_to_peer_rx.len());
            for _ in 0..4 {
                let peer_msg = main_to_peer_rx.recv().await.unwrap();
                assert!(matches!(peer_msg, MainToPeerTask::Disconnect(_)))
            }
        }

        #[apply(shared_tokio_runtime)]
        #[traced_test]
        async fn prune_peers_not_too_many_connections() {
            let num_init_peers_outgoing = 10;
            let num_init_peers_incoming = 1;
            let TestSetup {
                mut main_loop_handler,
                main_to_peer_rx,
                ..
            } = setup(
                num_init_peers_outgoing,
                num_init_peers_incoming,
                cli_args::Args::default(),
            )
            .await;

            let mocked_cli = cli_args::Args {
                max_num_peers: 200,
                ..Default::default()
            };

            main_loop_handler
                .global_state_lock
                .set_cli(mocked_cli)
                .await;

            main_loop_handler.prune_peers().await.unwrap();
            assert!(main_to_peer_rx.is_empty());
        }

        #[apply(shared_tokio_runtime)]
        #[traced_test]
        async fn skip_peer_discovery_if_peer_limit_is_exceeded() {
            let num_init_peers_outgoing = 2;
            let num_init_peers_incoming = 0;
            let TestSetup {
                mut main_loop_handler,
                ..
            } = setup(
                num_init_peers_outgoing,
                num_init_peers_incoming,
                cli_args::Args::default(),
            )
            .await;

            let mocked_cli = cli_args::Args {
                max_num_peers: 0,
                ..Default::default()
            };
            main_loop_handler
                .global_state_lock
                .set_cli(mocked_cli)
                .await;
            let mut mutable_state = main_loop_handler.mutable();
            main_loop_handler
                .discover_peers(&mut mutable_state)
                .await
                .unwrap();

            assert!(logs_contain("Skipping peer discovery."));
        }

        #[apply(shared_tokio_runtime)]
        #[traced_test]
        async fn performs_peer_discovery_on_few_connections() {
            let num_init_peers_outgoing = 2;
            let num_init_peers_incoming = 0;
            let TestSetup {
                mut main_loop_handler,
                mut main_to_peer_rx,
                ..
            } = setup(
                num_init_peers_outgoing,
                num_init_peers_incoming,
                cli_args::Args::default(),
            )
            .await;

            // Set CLI to attempt to make more connections
            let mocked_cli = cli_args::Args {
                max_num_peers: 10,
                ..Default::default()
            };
            main_loop_handler
                .global_state_lock
                .set_cli(mocked_cli)
                .await;
            let mut mutable_state = main_loop_handler.mutable();
            main_loop_handler
                .discover_peers(&mut mutable_state)
                .await
                .unwrap();

            let peer_discovery_sent_messages_on_peer_channel = main_to_peer_rx.try_recv().is_ok();
            assert!(peer_discovery_sent_messages_on_peer_channel);
            assert!(logs_contain("Performing peer discovery"));
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

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn should_switch_guessing_proposal_iff_sufficient_delta() {
        let network = Network::Main;
        let cli = cli_args::Args {
            network,
            guess: true,
            minimum_guesser_improvement_fraction: 0.2f64,
            ..Default::default()
        };

        let TestSetup {
            mut main_loop_handler,
            mut main_to_miner_rx,
            ..
        } = setup(1, 0, cli).await;
        let mut mutable_main_loop_state = main_loop_handler.mutable();

        let proposal_0_5 = invalid_empty_block1_with_guesser_fraction(network, 0.5).await;
        let proposal_0_55 = invalid_empty_block1_with_guesser_fraction(network, 0.55).await;
        let proposal_0_61 = invalid_empty_block1_with_guesser_fraction(network, 0.61).await;

        // New proposal when none is known: must inform mine loop
        main_loop_handler
            .handle_peer_task_message(
                PeerTaskToMain::BlockProposal(Box::new(proposal_0_5.clone())),
                &mut mutable_main_loop_state,
            )
            .await
            .unwrap();
        let MainToMiner::NewBlockProposal = main_to_miner_rx
            .try_recv()
            .expect("Block proposal warrants miner message")
        else {
            panic!("Expected new block proposal message");
        };
        let BlockProposal::ForeignComposition(best_known_proposal0) = main_loop_handler
            .global_state_lock
            .lock_guard()
            .await
            .mining_state
            .block_proposal
            .clone()
        else {
            panic!("Block proposal must be known and foreign")
        };
        assert_eq!(
            proposal_0_5.pow_mast_paths(),
            best_known_proposal0.pow_mast_paths(),
            "Best known proposal must be set to expected value"
        );

        // Mock that the mine loop updates its guessing status to work on this
        // proposal, since mine-loop is not running in this test.
        main_loop_handler
            .global_state_lock
            .set_mining_status_to_guessing(&proposal_0_5)
            .await;

        // Too small delta, don't inform mine loop.
        main_loop_handler
            .handle_peer_task_message(
                PeerTaskToMain::BlockProposal(Box::new(proposal_0_55.clone())),
                &mut mutable_main_loop_state,
            )
            .await
            .unwrap();
        assert!(
            main_to_miner_rx.try_recv().is_err(),
            "No message may be sent when delta is too small"
        );
        let BlockProposal::ForeignComposition(best_known_proposal1) = main_loop_handler
            .global_state_lock
            .lock_guard()
            .await
            .mining_state
            .block_proposal
            .clone()
        else {
            panic!("Block proposal must be known and foreign")
        };
        assert_eq!(
            proposal_0_55.pow_mast_paths(),
            best_known_proposal1.pow_mast_paths(),
            "Best known proposal must be set despite mine loop not informed"
        );

        // Sufficient delta, must inform mine loop.
        main_loop_handler
            .handle_peer_task_message(
                PeerTaskToMain::BlockProposal(Box::new(proposal_0_61.clone())),
                &mut mutable_main_loop_state,
            )
            .await
            .unwrap();
        let MainToMiner::NewBlockProposal = main_to_miner_rx
            .try_recv()
            .expect("Block proposal warrants miner message")
        else {
            panic!("Expected new block proposal message bc delta is sufficient");
        };
        let BlockProposal::ForeignComposition(best_known_proposal2) = main_loop_handler
            .global_state_lock
            .lock_guard()
            .await
            .mining_state
            .block_proposal
            .clone()
        else {
            panic!("Block proposal must be known and foreign")
        };
        assert_eq!(
            proposal_0_61.pow_mast_paths(),
            best_known_proposal2.pow_mast_paths(),
            "Best known proposal must be set to best-known value"
        );

        drop(main_loop_handler);
        drop(main_to_miner_rx);
    }

    mod bootstrapper_mode {

        use rand::Rng;

        use super::*;
        use crate::protocol::peer::PeerMessage;
        use crate::protocol::peer::TransferConnectionStatus;
        use crate::tests::shared::globalstate::get_dummy_peer_connection_data_genesis;
        use crate::tests::shared::to_bytes;

        #[apply(shared_tokio_runtime)]
        #[traced_test]
        async fn disconnect_from_oldest_peer_upon_connection_request() {
            // Set up a node in bootstrapper mode and connected to a given
            // number of peers, which is one less than the maximum. Initiate a
            // connection request. Verify that the oldest of the existing
            // connections is dropped.

            let network = Network::Main;
            let num_init_peers_outgoing = 5;
            let num_init_peers_incoming = 0;
            let TestSetup {
                mut main_loop_handler,
                mut main_to_peer_rx,
                ..
            } = setup(
                num_init_peers_outgoing,
                num_init_peers_incoming,
                cli_args::Args::default(),
            )
            .await;

            let mocked_cli = cli_args::Args {
                max_num_peers: usize::from(num_init_peers_outgoing) + 1,
                bootstrap: true,
                network,
                ..Default::default()
            };
            main_loop_handler
                .global_state_lock
                .set_cli(mocked_cli)
                .await;

            let mut mutable_main_loop_state = main_loop_handler.mutable();

            // check sanity: at startup, we are connected to the initial number of peers
            assert_eq!(
                usize::from(num_init_peers_outgoing),
                main_loop_handler
                    .global_state_lock
                    .lock_guard()
                    .await
                    .net
                    .peer_map
                    .len()
            );

            // randomize "connection established" timestamps
            let mut rng = rand::rng();
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
                                rng.random_range(0..(now_as_unix_timestamp.as_millis() as u64)),
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
                .copied()
                .unwrap();

            // simulate incoming connection
            let (peer_handshake, peer_socket_address) =
                get_dummy_peer_connection_data_genesis(network, 1);
            let own_handshake = main_loop_handler
                .global_state_lock
                .lock_guard()
                .await
                .get_own_handshakedata();
            assert_eq!(peer_handshake.network, own_handshake.network,);
            assert_eq!(peer_handshake.version, own_handshake.version,);
            let mock_stream = tokio_test::io::Builder::new()
                .read(
                    &to_bytes(&PeerMessage::Handshake {
                        magic_value: *crate::MAGIC_STRING_REQUEST,
                        data: Box::new(peer_handshake),
                    })
                    .unwrap(),
                )
                .write(
                    &to_bytes(&PeerMessage::Handshake {
                        magic_value: *crate::MAGIC_STRING_RESPONSE,
                        data: Box::new(own_handshake),
                    })
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
            let incoming_peer_task_handle = tokio::task::spawn(async move {
                match answer_peer(
                    mock_stream,
                    global_state_lock_clone,
                    peer_socket_address,
                    main_to_peer_rx_mock,
                    peer_to_main_tx_clone,
                    own_handshake,
                )
                .await
                {
                    Ok(()) => (),
                    Err(err) => debug!("Got result: {:?}", err),
                }
            });

            // `answer_peer_wrapper` should send a
            // `DisconnectFromLongestLivedPeer` message to main
            let peer_to_main_message = main_loop_handler.peer_task_to_main_rx.recv().await.unwrap();
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
            let MainToPeerTask::Disconnect(observed_drop_peer_socket_address) =
                main_to_peers_message
            else {
                panic!("Expected disconnect, got {main_to_peers_message:?}");
            };

            // matched observed droppee against expectation
            assert_eq!(
                expected_drop_peer_socket_address,
                observed_drop_peer_socket_address,
            );
            println!("Dropped connection with {expected_drop_peer_socket_address}.");

            // don't forget to terminate the peer task, which is still running
            incoming_peer_task_handle.abort();
        }
    }

    mod peer_messages {
        use super::*;

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn main_loop_does_not_do_verification() {
            // Ensure that the main loop does no validation of block validity
            // or PoW, as these checks belong in the peer loop, or elsewhere.
            let network = Network::Main;
            let cli = cli_args::Args::default_with_network(network);
            let TestSetup {
                mut main_loop_handler,
                ..
            } = setup(1, 1, cli).await;
            let mut main_loop_state = main_loop_handler.mutable();

            let genesis = Block::genesis(network);
            let block1 = invalid_empty_block(&genesis, network);
            assert!(
                !block1
                    .is_valid(&genesis, block1.header().timestamp, network)
                    .await
            );
            assert!(!block1.has_proof_of_work(network, genesis.header()));

            let block2 = invalid_empty_block(&block1, network);
            assert!(
                !block2
                    .is_valid(&genesis, block2.header().timestamp, network)
                    .await
            );
            assert!(!block2.has_proof_of_work(network, block1.header()));

            assert_eq!(
                BlockHeight::genesis(),
                main_loop_handler
                    .global_state_lock
                    .lock_guard()
                    .await
                    .chain
                    .light_state()
                    .header()
                    .height
            );
            main_loop_handler
                .handle_peer_task_message(
                    PeerTaskToMain::NewBlocks(vec![block1.clone()]),
                    &mut main_loop_state,
                )
                .await
                .unwrap();
            assert_eq!(
                block1.header().height,
                main_loop_handler
                    .global_state_lock
                    .lock_guard()
                    .await
                    .chain
                    .light_state()
                    .header()
                    .height
            );

            main_loop_handler
                .handle_peer_task_message(
                    PeerTaskToMain::NewBlocks(vec![block1.clone(), block2.clone()]),
                    &mut main_loop_state,
                )
                .await
                .unwrap();
            assert_eq!(
                block2.header().height,
                main_loop_handler
                    .global_state_lock
                    .lock_guard()
                    .await
                    .chain
                    .light_state()
                    .header()
                    .height
            );
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn new_block_from_peer_invokes_block_notify() {
            use std::fs;

            use crate::tests::shared::files::test_helper_data_dir;
            use crate::tests::shared::files::unit_test_data_directory;
            use crate::tests::shared::files::wait_for_file_to_exist;

            #[cfg(not(windows))]
            const BLOCK_NOTIFY_SHELL_SCRIPT_NAME: &str = "block_notify_dummy.py";
            #[cfg(windows)]
            const BLOCK_NOTIFY_SHELL_SCRIPT_NAME: &str = "block_notify_dummy.bat";

            let network = Network::Main;
            let dummy_block = invalid_empty_block(&Block::genesis(network), network);
            let block_hash = dummy_block.hash();
            let tmp_dir = unit_test_data_directory(network).unwrap().root_dir_path();
            let mut expected_file_location = tmp_dir.clone();
            expected_file_location.push(block_hash.to_hex());
            expected_file_location.set_extension("block");

            // On receival of a new block: Call a script creating an empty file
            // using the block hash as the file name. The test data directory
            // must contain this shell script for this test to work.
            let test_data_directory = test_helper_data_dir();
            let cli = cli_args::Args {
                block_notify: Some(format!(
                    "{}{BLOCK_NOTIFY_SHELL_SCRIPT_NAME} %s {}",
                    test_data_directory.to_string_lossy(),
                    tmp_dir.to_string_lossy()
                )),
                network,
                ..Default::default()
            };

            let incoming_connections = 0;
            let outgoing_connections = 0;
            let TestSetup {
                mut main_loop_handler,
                ..
            } = setup(incoming_connections, outgoing_connections, cli).await;
            let mut mutable_main_loop_state = main_loop_handler.mutable();

            let msg = PeerTaskToMain::NewBlocks(vec![dummy_block]);
            main_loop_handler
                .handle_peer_task_message(msg, &mut mutable_main_loop_state)
                .await
                .unwrap();

            wait_for_file_to_exist(&expected_file_location)
                .await
                .unwrap();
            let _ = fs::remove_file(&expected_file_location);
        }
    }
}
