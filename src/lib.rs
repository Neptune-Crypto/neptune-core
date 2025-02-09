// recursion limit for macros (e.g. triton_asm!)
#![recursion_limit = "2048"]
#![deny(clippy::shadow_unrelated)]
// enables nightly feature async_fn_track_caller for crate feature log-slow-write-lock
// log-slow-write-lock logs warning when a write-lock is held longer than 100 millis.
// to enable: cargo +nightly build --features log-slow-write-lock
#![cfg_attr(feature = "track-lock-location", feature(async_fn_track_caller))]

// danda: making all of these pub for now, so docs are generated.
// later maybe we ought to split some stuff out into re-usable crate(s)...?
pub mod config_models;
pub mod connect_to_peers;
pub mod database;
pub mod job_queue;
pub mod locks;
pub mod macros;
pub mod main_loop;
pub mod mine_loop;
pub mod models;
pub mod peer_loop;
pub mod prelude;
pub mod rpc_auth;
#[allow(clippy::too_many_arguments)]
// clippy  + tarpc workaround.  see https://github.com/google/tarpc/issues/502
pub mod rpc_server;
pub mod util_types;

#[cfg(test)]
pub mod tests;

use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;

use anyhow::Context;
use anyhow::Result;
use chrono::DateTime;
use chrono::Local;
use chrono::NaiveDateTime;
use chrono::Utc;
use config_models::cli_args;
use futures::future;
use futures::Future;
use futures::StreamExt;
use models::blockchain::block::Block;
use models::blockchain::shared::Hash;
use models::peer::handshake_data::HandshakeData;
use models::peer::peer_info::PeerInfo;
use prelude::tasm_lib;
use prelude::triton_vm;
use prelude::twenty_first;
use tarpc::server;
use tarpc::server::incoming::Incoming;
use tarpc::server::Channel;
use tarpc::tokio_serde::formats::*;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::info;
use triton_vm::prelude::BFieldElement;

use crate::config_models::data_directory::DataDirectory;
use crate::connect_to_peers::call_peer;
use crate::locks::tokio as sync_tokio;
use crate::main_loop::MainLoopHandler;
use crate::models::channel::MainToMiner;
use crate::models::channel::MainToPeerTask;
use crate::models::channel::MinerToMain;
use crate::models::channel::PeerTaskToMain;
use crate::models::channel::RPCServerToMain;
use crate::models::state::archival_state::ArchivalState;
use crate::models::state::blockchain_state::BlockchainArchivalState;
use crate::models::state::blockchain_state::BlockchainState;
use crate::models::state::light_state::LightState;
use crate::models::state::mempool::Mempool;
use crate::models::state::networking_state::NetworkingState;
use crate::models::state::wallet::wallet_state::WalletState;
use crate::models::state::wallet::WalletSecret;
use crate::models::state::GlobalStateLock;
use crate::rpc_server::RPC;

pub const SUCCESS_EXIT_CODE: i32 = 0;
pub const COMPOSITION_FAILED_EXIT_CODE: i32 = 159;

/// Magic string to ensure other program is Neptune Core
pub const MAGIC_STRING_REQUEST: &[u8] = b"EDE8991A9C599BE908A759B6BF3279CD";
pub const MAGIC_STRING_RESPONSE: &[u8] = b"Hello Neptune!\n";
const PEER_CHANNEL_CAPACITY: usize = 1000;
const MINER_CHANNEL_CAPACITY: usize = 10;
const RPC_CHANNEL_CAPACITY: usize = 1000;
const VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn initialize(cli_args: cli_args::Args) -> Result<i32> {
    info!("Starting client on {}.", cli_args.network);

    // Get data directory (wallet, block database), create one if none exists
    let data_directory = DataDirectory::get(cli_args.data_dir.clone(), cli_args.network)?;
    DataDirectory::create_dir_if_not_exists(&data_directory.root_dir_path()).await?;
    info!("Data directory is {}", data_directory);

    // Get wallet object, create various wallet secret files
    let wallet_dir = data_directory.wallet_directory_path();
    DataDirectory::create_dir_if_not_exists(&wallet_dir).await?;
    let (wallet_secret, _) =
        WalletSecret::read_from_file_or_create(&data_directory.wallet_directory_path())?;
    info!("Now getting wallet state. This may take a while if the database needs pruning.");
    let wallet_state =
        WalletState::new_from_wallet_secret(&data_directory, wallet_secret, &cli_args).await;
    info!("Got wallet state.");

    // Connect to or create databases for block index, peers, mutator set, block sync
    let block_index_db = ArchivalState::initialize_block_index_database(&data_directory).await?;
    info!("Got block index database");

    let peer_databases = NetworkingState::initialize_peer_databases(&data_directory).await?;
    info!("Got peer database");

    let archival_mutator_set = ArchivalState::initialize_mutator_set(&data_directory).await?;
    info!("Got archival mutator set");

    let archival_block_mmr = ArchivalState::initialize_archival_block_mmr(&data_directory).await?;
    info!("Got archival block MMR");

    let archival_state = ArchivalState::new(
        data_directory.clone(),
        block_index_db,
        archival_mutator_set,
        archival_block_mmr,
        cli_args.network,
    )
    .await;

    // Get latest block. Use hardcoded genesis block if nothing is in database.
    let latest_block: Block = archival_state.get_tip().await;

    // Bind socket to port on this machine, to handle incoming connections from peers
    let incoming_peer_listener = if let Some(incoming_peer_listener) = cli_args.own_listen_port() {
        let ret = TcpListener::bind((cli_args.listen_addr, incoming_peer_listener))
           .await
           .with_context(|| format!("Failed to bind to local TCP port {}:{}. Is an instance of this program already running?", cli_args.listen_addr, incoming_peer_listener))?;
        info!("Now listening for incoming peer-connections");
        ret
    } else {
        info!("Not accepting incoming peer-connections");
        TcpListener::bind("127.0.0.1:0").await?
    };

    let peer_map: HashMap<SocketAddr, PeerInfo> = HashMap::new();

    // Construct the broadcast channel to communicate from the main task to peer tasks
    let (main_to_peer_broadcast_tx, _main_to_peer_broadcast_rx) =
        broadcast::channel::<MainToPeerTask>(PEER_CHANNEL_CAPACITY);

    // Add the MPSC (multi-producer, single consumer) channel for peer-task-to-main communication
    let (peer_task_to_main_tx, peer_task_to_main_rx) =
        mpsc::channel::<PeerTaskToMain>(PEER_CHANNEL_CAPACITY);

    let networking_state = NetworkingState::new(peer_map, peer_databases);

    let light_state: LightState = LightState::from(latest_block.clone());
    let blockchain_archival_state = BlockchainArchivalState {
        light_state,
        archival_state,
    };
    let blockchain_state = BlockchainState::Archival(blockchain_archival_state);
    let mempool = Mempool::new(
        cli_args.max_mempool_size,
        cli_args.max_mempool_num_tx,
        latest_block.hash(),
    );
    let mut global_state_lock = GlobalStateLock::new(
        wallet_state,
        blockchain_state,
        networking_state,
        cli_args,
        mempool,
    );

    // See #239.  <https://github.com/Neptune-Crypto/neptune-core/issues/239>
    //
    // We set a panic hook in order to catch all panics, including those that
    // would ordinarily be swallowed by the tokio runtime.
    //
    // If a panic occurs, we must flush the databases to prevent any possible
    // corruption before exiting.
    let global_state_lock_hook = global_state_lock.clone();
    std::panic::set_hook(Box::new(move |panic_info| {
        let mut msg = "Caught panic.\n".to_string();

        // Print the stack trace
        if let Some(location) = panic_info.location() {
            msg += &format!("  location: {}\n", location);
        }

        if let Some(payload) = panic_info.payload().downcast_ref::<&str>() {
            msg += &format!("  message: {}\n", payload);
        }

        msg += &format!("  backtrace:\n{}", std::backtrace::Backtrace::capture());

        tracing::error!("{}", msg);

        // we need to flush databases, which is async call. So we spawn a new task.
        let mut global_state_lock_panic = global_state_lock_hook.clone();
        let handle = tokio::spawn(async move {
            tracing::info!("Flushing Database...");
            let _ = global_state_lock_panic.flush_databases().await;
            tracing::info!("*** DB flush complete. now exiting.  Bye! ****");

            std::process::exit(1);
        });
        // wait for spawned task to complete.
        while !handle.is_finished() {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }));

    // Check if we need to restore the wallet database, and if so, do it.
    info!("Checking if we need to restore UTXOs");
    global_state_lock
        .lock_guard_mut()
        .await
        .restore_monitored_utxos_from_recovery_data()
        .await?;
    info!("UTXO restoration check complete");

    // Connect to peers, and provide each peer task with a thread-safe copy of the state
    let own_handshake_data: HandshakeData = global_state_lock
        .lock_guard()
        .await
        .get_own_handshakedata()
        .await;
    info!(
        "Most known canonical block has height {}",
        own_handshake_data.tip_header.height
    );
    let mut task_join_handles = vec![];
    for peer_address in global_state_lock.cli().peers.clone() {
        let peer_state_var = global_state_lock.clone(); // bump arc refcount
        let main_to_peer_broadcast_rx_clone: broadcast::Receiver<MainToPeerTask> =
            main_to_peer_broadcast_tx.subscribe();
        let peer_task_to_main_tx_clone: mpsc::Sender<PeerTaskToMain> = peer_task_to_main_tx.clone();
        let own_handshake_data_clone = own_handshake_data.clone();
        let peer_join_handle = tokio::task::Builder::new()
            .name("call_peer_wrapper_3")
            .spawn(async move {
                call_peer(
                    peer_address,
                    peer_state_var.clone(),
                    main_to_peer_broadcast_rx_clone,
                    peer_task_to_main_tx_clone,
                    own_handshake_data_clone,
                    1, // All outgoing connections have distance 1
                )
                .await;
            })?;
        task_join_handles.push(peer_join_handle);
    }
    info!("Made outgoing connections to peers");

    // Start mining tasks if requested
    let (miner_to_main_tx, miner_to_main_rx) = mpsc::channel::<MinerToMain>(MINER_CHANNEL_CAPACITY);
    let (main_to_miner_tx, main_to_miner_rx) = mpsc::channel::<MainToMiner>(MINER_CHANNEL_CAPACITY);
    let miner_state_lock = global_state_lock.clone(); // bump arc refcount.
    if global_state_lock.cli().mine() {
        let miner_join_handle = tokio::task::Builder::new()
            .name("miner")
            .spawn(async move {
                mine_loop::mine(main_to_miner_rx, miner_to_main_tx, miner_state_lock)
                    .await
                    .expect("Error in mining task");
            })?;
        task_join_handles.push(miner_join_handle);
        info!("Started mining task");
    }

    // Start RPC server for CLI request and more. It's important that this is done as late
    // as possible, so requests do not hang while initialization code runs.
    let (rpc_server_to_main_tx, rpc_server_to_main_rx) =
        mpsc::channel::<RPCServerToMain>(RPC_CHANNEL_CAPACITY);
    let mut rpc_listener = tarpc::serde_transport::tcp::listen(
        format!("127.0.0.1:{}", global_state_lock.cli().rpc_port),
        Json::default,
    )
    .await?;
    rpc_listener.config_mut().max_frame_length(usize::MAX);

    let rpc_state_lock = global_state_lock.clone();

    async fn spawn(fut: impl Future<Output = ()> + Send + 'static) {
        tokio::spawn(fut);
    }

    // each time we start neptune-core a new RPC cookie is generated.
    let valid_tokens: Vec<rpc_auth::Token> =
        vec![crate::rpc_auth::Cookie::try_new(&data_directory)
            .await?
            .into()];

    let rpc_join_handle = tokio::spawn(async move {
        rpc_listener
            // Ignore accept errors.
            .filter_map(|r| future::ready(r.ok()))
            .map(server::BaseChannel::with_defaults)
            // Limit channels to 5 per IP. 1 for dashboard and a few more for CLI interactions
            .max_channels_per_key(5, |t| t.transport().peer_addr().unwrap().ip())
            // serve is generated by the service attribute. It takes as input any type implementing
            // the generated RPC trait.
            .map(move |channel| {
                let server = rpc_server::NeptuneRPCServer::new(
                    rpc_state_lock.clone(),
                    rpc_server_to_main_tx.clone(),
                    data_directory.clone(),
                    valid_tokens.clone(),
                );

                channel.execute(server.serve()).for_each(spawn)
            })
            // Max 10 channels.
            .buffer_unordered(10)
            .for_each(|_| async {})
            .await;
    });
    task_join_handles.push(rpc_join_handle);
    info!("Started RPC server");

    // Handle incoming connections, messages from peer tasks, and messages from the mining task
    info!("Starting main loop");
    let mut main_loop_handler = MainLoopHandler::new(
        incoming_peer_listener,
        global_state_lock,
        main_to_peer_broadcast_tx,
        peer_task_to_main_tx,
        main_to_miner_tx,
    );
    main_loop_handler
        .run(
            peer_task_to_main_rx,
            miner_to_main_rx,
            rpc_server_to_main_rx,
            task_join_handles,
        )
        .await
}

/// Time a fn call.  Duration is returned as a float in seconds.
pub fn time_fn_call<O>(f: impl FnOnce() -> O) -> (O, f64) {
    let start = Instant::now();
    let output = f();
    let elapsed = start.elapsed();
    let total_time = elapsed.as_secs() as f64 + elapsed.subsec_nanos() as f64 / 1e9;
    (output, total_time)
}

/// Time an async fn call.  Duration is returned as a float in seconds.
pub async fn time_fn_call_async<F, O>(f: F) -> (O, f64)
where
    F: std::future::Future<Output = O>,
{
    let start = Instant::now();
    let output = f.await;
    let elapsed = start.elapsed();
    let total_time = elapsed.as_secs() as f64 + elapsed.subsec_nanos() as f64 / 1e9;
    (output, total_time)
}

/// Converts a UTC millisecond timestamp (millis since 1970 UTC) into
/// a `DateTime<Local>`, ie local-time.
pub fn utc_timestamp_to_localtime<T>(timestamp: T) -> DateTime<Local>
where
    T: TryInto<i64>,
    <T as TryInto<i64>>::Error: std::fmt::Debug,
{
    let naive = NaiveDateTime::from_timestamp_millis(timestamp.try_into().unwrap()).unwrap();
    let utc: DateTime<Utc> = DateTime::from_naive_utc_and_offset(naive, *Utc::now().offset());
    DateTime::from(utc)
}

#[cfg(feature = "log-lock_events")]
pub(crate) fn current_thread_id() -> u64 {
    // workaround: parse thread_id debug output into a u64.
    // (because ThreadId::as_u64() is unstable)
    let thread_id_dbg: String = format!("{:?}", std::thread::current().id());
    let nums_u8 = &thread_id_dbg
        .chars()
        .filter_map(|c| {
            if c.is_ascii_digit() {
                Some(c as u8)
            } else {
                None
            }
        })
        .collect::<Vec<u8>>();
    let nums = String::from_utf8_lossy(nums_u8).to_string();

    nums.parse::<u64>().unwrap()
}

// This is a callback fn passed to AtomicRw, AtomicMutex
// and called when a lock event occurs.  This way
// we can track which threads+tasks are acquiring
// which locks for reads and/or mutations.
pub(crate) fn log_tokio_lock_event_cb(lock_event: sync_tokio::LockEvent) {
    #[cfg(feature = "log-lock_events")]
    log_tokio_lock_event(&lock_event);

    match lock_event.acquisition() {
        #[cfg(feature = "log-slow-read-lock")]
        sync_tokio::LockAcquisition::Read => log_slow_locks(&lock_event, "read"),
        #[cfg(feature = "log-slow-write-lock")]
        sync_tokio::LockAcquisition::Write => log_slow_locks(&lock_event, "write"),

        _ => {}
    }
}

// notes:
//   1. this feature is very verbose in the logs.
//   2. It's not really needed except when debugging lock acquisitions
//   3. tracing-tests causes a big mem-leak for tests with this.
#[cfg(feature = "log-lock_events")]
pub(crate) fn log_tokio_lock_event(lock_event: &sync_tokio::LockEvent) {
    use std::ops::Sub;

    let tokio_id = match tokio::task::try_id() {
        Some(id) => format!("{}", id),
        None => "?".to_string(),
    };

    let location_str = match lock_event.location() {
        Some(l) => format!("\n\t|-- acquirer: {}", l),
        None => String::default(),
    };
    let waited_for_acquire_str = match (lock_event.try_acquire_at(), lock_event.acquire_at()) {
        (Some(t), Some(a)) => format!(
            "\n\t|-- waited for acquire: {} secs",
            a.sub(t).as_secs_f32()
        ),
        _ => String::default(),
    };
    let held_str = match lock_event.acquire_at() {
        Some(t) if matches!(lock_event, sync_tokio::LockEvent::Release { .. }) => {
            format!("\n\t|-- held: {} secs", t.elapsed().as_secs_f32())
        }
        _ => String::default(),
    };

    let info = lock_event.info();

    tracing::trace!(
            ?lock_event,
            "{} tokio lock `{}` of type `{}` for `{}` by\n\t|-- thread {}, (`{}`)\n\t|-- tokio task {}{}{}{}\n\t|--",
            lock_event.event_type_name(),
            info.name().unwrap_or("?"),
            info.lock_type(),
            lock_event.acquisition(),
            current_thread_id(),
            std::thread::current().name().unwrap_or("?"),
            tokio_id,
            location_str,
            waited_for_acquire_str,
            held_str,
    );
}

#[cfg(any(feature = "log-slow-read-lock", feature = "log-slow-write-lock"))]
pub(crate) fn log_slow_locks(event: &sync_tokio::LockEvent, read_or_write: &str) {
    use std::ops::Sub;
    if matches!(event, sync_tokio::LockEvent::Acquire { .. }) {
        if let (Some(try_acquire_at), Some(acquire_at), Some(location)) =
            (event.try_acquire_at(), event.acquire_at(), event.location())
        {
            let duration = acquire_at.sub(try_acquire_at);
            let env_var = format!(
                "LOG_SLOW_{}_LOCK_ACQUIRE_THRESHOLD",
                read_or_write.to_uppercase()
            );
            let max_duration_secs = match std::env::var(env_var) {
                Ok(t) => t.parse().unwrap(),
                Err(_) => 0.1,
            };

            if duration.as_secs_f32() > max_duration_secs {
                tracing::warn!(
                    "{}-lock held for {} seconds. (exceeds max: {} secs)  location: {}",
                    read_or_write,
                    duration.as_secs_f32(),
                    max_duration_secs,
                    location
                );
            }
        }
    }

    if let (Some(acquired_at), Some(location)) = (event.acquire_at(), event.location()) {
        let duration = acquired_at.elapsed();
        let env_var = format!("LOG_SLOW_{}_LOCK_THRESHOLD", read_or_write.to_uppercase());
        let max_duration_secs = match std::env::var(env_var) {
            Ok(t) => t.parse().unwrap(),
            Err(_) => 0.1,
        };

        if duration.as_secs_f32() > max_duration_secs {
            tracing::warn!(
                "{}-lock held for {} seconds. (exceeds max: {} secs)  location: {}",
                read_or_write,
                duration.as_secs_f32(),
                max_duration_secs,
                location
            );
        }
    }
}

const LOG_TOKIO_LOCK_EVENT_CB: sync_tokio::LockCallbackFn = log_tokio_lock_event_cb;

/// for logging how long a scope takes to execute.
///
/// If an optional threshold value is provided then nothing will be
/// logged unless execution duration exceeds the threshold.
/// In that case a tracing::warn!() is logged.
///
/// If no threshold value is provided then a tracing::debug!()
/// is always logged with the duration.
///
/// for convenience see macros:
///  crate::macros::log_slow_scope,
///  crate::macros::log_scope_duration,
pub struct ScopeDurationLogger<'a> {
    start: Instant,
    description: &'a str,
    log_slow_fn_threshold: Option<f64>,
    location: &'static std::panic::Location<'static>,
}
impl<'a> ScopeDurationLogger<'a> {
    #[track_caller]
    pub fn new(description: &'a str, log_slow_fn_threshold: Option<f64>) -> Self {
        Self {
            start: Instant::now(),
            description,
            log_slow_fn_threshold,
            location: std::panic::Location::caller(),
        }
    }

    #[track_caller]
    pub fn new_with_threshold(description: &'a str, log_slow_fn_threshold: f64) -> Self {
        Self::new(description, Some(log_slow_fn_threshold))
    }

    #[track_caller]
    pub fn new_default_threshold(description: &'a str) -> Self {
        Self::new_with_threshold(
            description,
            match env::var("LOG_SLOW_SCOPE_THRESHOLD") {
                Ok(t) => t.parse().unwrap(),
                Err(_) => 0.001,
            },
        )
    }

    #[track_caller]
    pub fn new_without_threshold(description: &'a str) -> Self {
        Self::new(description, None)
    }
}

impl Drop for ScopeDurationLogger<'_> {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed();
        let duration = elapsed.as_secs_f64();

        if let Some(threshold) = self.log_slow_fn_threshold {
            if duration >= threshold {
                let msg = format!(
                    "executed {} in {} secs.  exceeds slow fn threshold of {} secs.  location: {}",
                    self.description, duration, threshold, self.location,
                );

                tracing::debug!("{}", msg);
            }
        } else {
            let msg = format!(
                "executed {} in {} secs.  location: {}",
                self.description, duration, self.location,
            );

            tracing::debug!("{}", msg);
        }
    }
}
