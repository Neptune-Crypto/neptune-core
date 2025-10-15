pub mod archival_state;
pub mod blockchain_state;
pub mod database;
pub mod light_state;
pub mod mempool;
pub mod mining;
pub mod networking_state;
pub mod shared;
pub mod transaction;
pub mod wallet;

use std::cmp::max;
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::ops::Deref;
use std::ops::DerefMut;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::bail;
use anyhow::ensure;
use anyhow::Result;
use blockchain_state::BlockchainArchivalState;
use blockchain_state::BlockchainState;
use itertools::Itertools;
use light_state::LightState;
use mempool::Mempool;
use mining::block_proposal::BlockProposal;
use mining::mining_state::MiningState;
use mining::mining_status::ComposingWorkInfo;
use mining::mining_status::GuessingWorkInfo;
use mining::mining_status::MiningStatus;
use networking_state::NetworkingState;
use num_traits::CheckedSub;
use num_traits::Zero;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::tip5::digest::Digest;
use tracing::debug;
use tracing::info;
use tracing::trace;
use tracing::warn;
use transaction::transaction_kernel_id::TransactionKernelId;
use transaction::tx_creation_artifacts::TxCreationArtifacts;
use transaction::tx_creation_artifacts::TxCreationArtifactsError;
use transaction::tx_proving_capability::TxProvingCapability;
use wallet::wallet_state::WalletState;
use wallet::wallet_status::WalletStatus;

use crate::api;
use crate::api::export::NeptuneProof;
use crate::application::config::cli_args;
use crate::application::config::data_directory::DataDirectory;
use crate::application::config::tx_upgrade_filter::TxUpgradeFilter;
use crate::application::database::storage::storage_schema::traits::StorageWriter as SW;
use crate::application::database::storage::storage_vec::traits::*;
use crate::application::database::storage::storage_vec::Index;
use crate::application::locks::tokio as sync_tokio;
use crate::application::locks::tokio::AtomicRwReadGuard;
use crate::application::locks::tokio::AtomicRwWriteGuard;
use crate::application::loops::main_loop::proof_upgrader::ProofCollectionToSingleProof;
use crate::application::loops::main_loop::proof_upgrader::UpdateMutatorSetDataJob;
use crate::application::loops::main_loop::proof_upgrader::SEARCH_DEPTH_FOR_BLOCKS_FOR_MS_UPDATE;
use crate::application::loops::main_loop::upgrade_incentive::UpgradeIncentive;
use crate::application::loops::mine_loop::composer_parameters::ComposerParameters;
use crate::protocol::consensus::block::block_header::BlockHeader;
use crate::protocol::consensus::block::block_header::BlockHeaderWithBlockHashWitness;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::difficulty_control::ProofOfWork;
use crate::protocol::consensus::block::mutator_set_update::MutatorSetUpdate;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::validity::proof_collection::ProofCollection;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::peer::handshake_data::HandshakeData;
use crate::protocol::peer::handshake_data::VersionString;
use crate::protocol::peer::peer_info::PeerInfo;
use crate::protocol::peer::transfer_block::TransferBlock;
use crate::protocol::peer::SyncChallenge;
use crate::protocol::peer::SyncChallengeResponse;
use crate::protocol::peer::SYNC_CHALLENGE_POW_WITNESS_LENGTH;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::state::mempool::mempool_update_job::MempoolUpdateJob;
use crate::state::mempool::upgrade_priority::UpgradePriority;
use crate::state::mining::block_proposal::BlockProposalRejectError;
use crate::state::wallet::expected_utxo::ExpectedUtxo;
use crate::state::wallet::expected_utxo::UtxoNotifier;
use crate::state::wallet::monitored_utxo::MonitoredUtxo;
use crate::state::wallet::sent_transaction::SentTransaction;
use crate::state::wallet::transaction_input::TxInput;
use crate::state::wallet::wallet_state::IncomingUtxoRecoveryData;
use crate::time_fn_call_async;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::removal_record::RemovalRecord;
use crate::ArchivalState;
use crate::RPCServerToMain;
use crate::WalletFileContext;
use crate::VERSION;

/// `GlobalStateLock` holds a
/// [`tokio::AtomicRw`](crate::application::locks::tokio::AtomicRw)
/// ([`RwLock`](tokio::sync::RwLock)) over [`GlobalState`].
///
/// Conceptually** all reads and writes of application state
/// require acquiring this lock.
///
/// Having a single lock is useful for a few reasons:
///  1. Enables write serialization over all application state.
///     (blockchain, mempool, wallet, global flags)
///  2. Readers see a consistent view of data.
///  3. makes it easy to reason about locking.
///  4. simplifies the codebase.
///
/// The primary drawback is that long write operations can
/// block readers.  As such, every effort should be made to keep
/// write operations as short as possible, though
/// correctness/atomicity have first priority.
///
/// Using an `RwLock` is beneficial for concurrency vs using a `Mutex`.
/// Readers do not block eachother.  Only a writer blocks readers.
/// See [`RwLock`](std::sync::RwLock) docs for details.
///
/// ** unless some type uses interior mutability.  We have made
/// efforts to eradicate interior mutability in this crate.
///
/// Usage conventions:
///
/// ```text
///
/// // property naming:
/// struct Foo {
///     global_state_lock: GlobalStateLock
/// }
///
/// // read guard naming:
/// let global_state = foo.global_state_lock.lock_guard().await;
///
/// // write guard naming:
/// let global_state_mut = foo.global_state_lock.lock_guard_mut().await;
/// ```
///
/// These conventions make it easy to distinguish read access from write
/// access when reading and reviewing code.
///
/// When using a read-guard or write-guard, always drop it as soon as possible.
/// Failure to do so can result in poor concurrency or deadlock.
///
/// Deadlocks are generally not hard to track down.  Lock events are traced.
/// The app log records each `TryAcquire`, `Acquire` and `Release` event
/// when run with `RUST_LOG='info,neptune_cash=trace'`.
///
/// If a deadlock has occurred, the log will end with a `TryAcquire` event
/// (read or write) and just scroll up to find the previous `Acquire` for
/// write event to see which thread is holding the lock.
#[derive(Debug, Clone)]
pub struct GlobalStateLock {
    global_state_lock: sync_tokio::AtomicRw<GlobalState>,

    /// The `cli_args::Args` are read-only and accessible by all tasks/threads.
    cli: cli_args::Args,

    // holding this sender here enables it be used by the tx_initiator rust API
    // for broadcasting Tx as well as the RPC API.
    // (we might consider renaming the channel.)
    rpc_server_to_main_tx: tokio::sync::mpsc::Sender<RPCServerToMain>,
}

impl GlobalStateLock {
    pub fn from_global_state(
        global_state: GlobalState,
        rpc_server_to_main_tx: tokio::sync::mpsc::Sender<RPCServerToMain>,
    ) -> Self {
        let cli = global_state.cli.clone();
        let global_state_lock = sync_tokio::AtomicRw::from((
            global_state,
            Some("GlobalState"),
            Some(crate::LOG_TOKIO_LOCK_EVENT_CB),
        ));

        Self {
            global_state_lock,
            cli,
            rpc_server_to_main_tx,
        }
    }

    // check if mining
    pub async fn mining(&self) -> bool {
        self.lock(|s| match s.mining_state.mining_status {
            MiningStatus::Guessing(_) => true,
            MiningStatus::Composing(_) => true,
            MiningStatus::Inactive => false,
        })
        .await
    }

    pub async fn set_mining_status_to_inactive(&mut self) {
        self.lock_guard_mut().await.mining_state.mining_status = MiningStatus::Inactive;
        tracing::debug!("set mining status: inactive");
    }

    /// Indicate if we are guessing
    pub async fn set_mining_status_to_guessing(&mut self, block: &Block) {
        let now = SystemTime::now();
        let block_info = GuessingWorkInfo::new(now, block);
        self.lock_guard_mut().await.mining_state.mining_status = MiningStatus::Guessing(block_info);
        tracing::debug!("set mining status: guessing");
    }

    /// Indicate if we are composing
    pub async fn set_mining_status_to_composing(&mut self) {
        let now = SystemTime::now();
        let work_info = ComposingWorkInfo::new(now);
        self.lock_guard_mut().await.mining_state.mining_status = MiningStatus::Composing(work_info);
        tracing::debug!("set mining status: composing");
    }

    // persist wallet state to disk
    pub async fn persist_wallet(&mut self) -> Result<()> {
        self.lock_guard_mut().await.persist_wallet().await
    }

    // flush databases (persist to disk)
    pub async fn flush_databases(&mut self) -> Result<()> {
        self.lock_guard_mut().await.flush_databases().await
    }

    /// access the public Api in mutable context
    pub fn api_mut(&mut self) -> api::Api {
        self.clone().into()
    }

    /// access the public Api type in immutable context
    pub fn api(&self) -> api::Api {
        self.clone().into()
    }

    /// Set tip to a block that we composed.
    #[cfg(test)]
    pub async fn set_new_self_composed_tip(
        &mut self,
        new_block: Block,
        composer_reward_utxo_infos: Vec<ExpectedUtxo>,
    ) -> Result<Vec<MempoolUpdateJob>> {
        let mut state = self.lock_guard_mut().await;
        state
            .wallet_state
            .add_expected_utxos(composer_reward_utxo_infos)
            .await;
        state.set_new_tip(new_block).await
    }

    /// store a block (non coinbase)
    pub async fn set_new_tip(&mut self, new_block: Block) -> Result<Vec<MempoolUpdateJob>> {
        self.lock_guard_mut().await.set_new_tip(new_block).await
    }

    /// resync membership proofs
    pub async fn resync_membership_proofs(&mut self) -> Result<()> {
        self.lock_guard_mut().await.resync_membership_proofs().await
    }

    pub async fn prune_abandoned_monitored_utxos(
        &mut self,
        block_depth_threshold: usize,
    ) -> Result<usize> {
        self.lock_guard_mut()
            .await
            .prune_abandoned_monitored_utxos(block_depth_threshold)
            .await
    }

    /// Return the read-only arguments set at startup.
    #[inline]
    pub fn cli(&self) -> &cli_args::Args {
        &self.cli
    }

    /// retrieve sender for channel from RPC to main loop
    ///
    /// note that the tx_initiator API now uses this sender also.
    pub fn rpc_server_to_main_tx(&self) -> tokio::sync::mpsc::Sender<RPCServerToMain> {
        self.rpc_server_to_main_tx.clone()
    }

    /// Test helper function for fine control of CLI parameters.
    #[cfg(test)]
    pub async fn set_cli(&mut self, cli: cli_args::Args) {
        self.lock_guard_mut().await.cli = cli.clone();
        self.cli = cli;
    }

    /// stores/records a locally-initiated transaction into the global state.
    pub async fn record_own_transaction(
        &mut self,
        tx_artifacts: &TxCreationArtifacts,
    ) -> std::result::Result<(), RecordTransactionError> {
        //
        // verifies that:
        //  1. Self::network matches provided Network.
        //  2. Transaction and TransactionDetails match.
        //  3. Transaction proof is valid, and thus the Tx itself is valid.

        // acquire write-lock
        let mut gsm = self.lock_guard_mut().await;
        let block_height = gsm.chain.light_state().header().height;
        let network = gsm.cli().network;
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);
        tx_artifacts
            .verify(gsm.cli().network, consensus_rule_set)
            .await?;

        // clone is cheap as fields are Arc<T>
        let transaction = tx_artifacts.transaction.clone();
        let details = tx_artifacts.details.clone();

        let utxos_sent_to_self = gsm
            .wallet_state
            .extract_expected_utxos(details.tx_outputs.iter(), UtxoNotifier::Myself);

        // if the tx created offchain expected_utxos we must inform wallet.
        if !utxos_sent_to_self.is_empty() {
            tracing::debug!("add expected utxos");

            // Inform wallet of any expected incoming utxos.  note that this
            // mutates global state.
            gsm.wallet_state
                .add_expected_utxos(utxos_sent_to_self)
                .await;
        }

        tracing::debug!("add sent-transaction to wallet.");

        // inform wallet about the details of this sent transaction, so it
        // can group inputs and outputs together, eg for history purposes.
        let tip_digest = gsm.chain.light_state().hash();
        gsm.wallet_state
            .add_sent_transaction(SentTransaction::new(details.as_ref(), tip_digest))
            .await;

        // insert transaction into mempool
        gsm.mempool_insert((*transaction).clone(), UpgradePriority::Critical)
            .await;

        tracing::debug!("flush dbs");
        gsm.flush_databases().await.expect("flushed DBs");

        Ok(())
    }
}

impl Deref for GlobalStateLock {
    type Target = sync_tokio::AtomicRw<GlobalState>;

    fn deref(&self) -> &Self::Target {
        &self.global_state_lock
    }
}

impl DerefMut for GlobalStateLock {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.global_state_lock
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum RecordTransactionError {
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(#[from] TxCreationArtifactsError),
}

/// abstracts over lock acquisition types for [GlobalStateLock]
///
/// this enables methods to be written that can accept whatever
/// the caller has.
///
/// such generic methods can be called in series to share an already
/// acquired lock-guard, or to each acquire its own lock-guard
/// in the case of `Lock` variant.
///
/// Example usage:
///
/// ```rust
/// use neptune_cash::state::GlobalState;
/// use neptune_cash::state::GlobalStateLock;
/// use neptune_cash::api::export::StateLock;
/// fn worker(gs: &GlobalState, truth: bool) {
///    // do something with gs and truth.
/// }
///
/// // a callee that accepts &StateLock
/// async fn callee(state_lock: &StateLock<'_>, truth: bool) {
///     match state_lock {
///        StateLock::Lock(gsl) => worker(&*gsl.lock_guard().await, truth),
///        StateLock::ReadGuard(gs) => worker(&gs, truth),
///        StateLock::WriteGuard(gs) => worker(&gs, truth),
///    }
/// }
///
/// // a caller that uses `Lock` variant
/// async fn caller_1(gsl: GlobalStateLock) {
///     // read-lock will be acquired each call.
///     callee(&gsl.clone().into(), true).await;
///     callee(&gsl.clone().into(), false).await;
/// }
///
/// // a caller that uses `ReadLock` variant
/// async fn caller_2(gsl: GlobalStateLock) {
///     // read-lock is acquired only once.
///     let sl = StateLock::from(gsl.lock_guard().await);
///     callee(&sl, true).await;
///     callee(&sl, false).await;
/// }
///
/// // a caller that uses `WriteLock` variant
/// async fn caller_3(mut gsl: GlobalStateLock) {
///     // write-lock is acquired only once.
///     let sl = StateLock::from(gsl.lock_guard_mut().await);
///     callee(&sl, true).await;
///     callee(&sl, false).await;
/// }
///
/// // a caller that uses `ReadLock` variant and calls fn that accept `&GlobalState`
/// async fn caller_4(gsl: GlobalStateLock) {
///     // read-lock is acquired only once.
///     let sl = StateLock::from(gsl.lock_guard().await);
///     callee(&sl, true).await;
///     callee(&sl, false).await;
///
///     // we can pass &GlobalState directly.
///     worker(sl.gs(), true);
///
///     // convert back into a read-guard
///     let gs = sl.into_read_guard();
///     worker(&gs, false);
/// }
/// ```
///
/// example usage as callee: see source of [TxOutputListBuilder::build()](crate::api::tx_initiation::builder::tx_output_list_builder::TxOutputListBuilder::build())
///
/// advanced usage as caller: see source of [TransactionSender::send()](crate::api::tx_initiation::send::TransactionSender::send())
#[derive(Debug)]
pub enum StateLock<'a> {
    /// holds an instance GlobalStateLock. can be used to
    Lock(Box<GlobalStateLock>),
    ReadGuard(AtomicRwReadGuard<'a, GlobalState>),
    WriteGuard(AtomicRwWriteGuard<'a, GlobalState>),
}

impl From<GlobalStateLock> for StateLock<'_> {
    fn from(g: GlobalStateLock) -> Self {
        Self::Lock(Box::new(g))
    }
}

impl From<&GlobalStateLock> for StateLock<'_> {
    fn from(g: &GlobalStateLock) -> Self {
        Self::Lock(Box::new(g.clone())) // cheap Arc clone.
    }
}

impl<'a> From<AtomicRwReadGuard<'a, GlobalState>> for StateLock<'a> {
    fn from(g: AtomicRwReadGuard<'a, GlobalState>) -> Self {
        Self::ReadGuard(g)
    }
}

impl<'a> From<AtomicRwWriteGuard<'a, GlobalState>> for StateLock<'a> {
    fn from(g: AtomicRwWriteGuard<'a, GlobalState>) -> Self {
        Self::WriteGuard(g)
    }
}

impl<'a> StateLock<'a> {
    /// instantiates a `StateLock::ReadGuard`
    pub async fn read_guard(gsl: &'a GlobalStateLock) -> Self {
        Self::ReadGuard(gsl.lock_guard().await)
    }

    /// instantiates a `StateLock::WriteGuard`
    pub async fn write_guard(gsl: &'a mut GlobalStateLock) -> Self {
        Self::WriteGuard(gsl.lock_guard_mut().await)
    }

    /// returns a `GlobalState` reference.
    ///
    /// panics: it is wrong-usage to call this method on a
    /// `Lock` variant, and a panic will occur if this happens.
    pub fn gs(&self) -> &GlobalState {
        match self {
            Self::ReadGuard(g) => g,
            Self::WriteGuard(g) => g,
            Self::Lock(_) => panic!("wrong usage: not a guard"),
        }
    }

    /// converts back into `GlobalStateLock`
    ///
    /// panics: it is wrong-usage to call this method on a
    /// variant other than `Lock`. A panic will occur if this happens.
    pub fn into_lock(self) -> GlobalStateLock {
        match self {
            Self::Lock(g) => *g,
            _ => panic!("wrong usage: not a lock"),
        }
    }

    /// converts back into `AtomicRwReadGuard`
    ///
    /// panics: it is wrong-usage to call this method on a
    /// variant other than `ReadGuard`. A panic will occur if this happens.
    pub fn into_read_guard(self) -> AtomicRwReadGuard<'a, GlobalState> {
        match self {
            Self::ReadGuard(g) => g,
            _ => panic!("wrong usage: not a read guard"),
        }
    }

    /// converts back into `AtomicRwWriteGuard`
    ///
    /// panics: it is wrong-usage to call this method on a
    /// variant other than `WriteGuard`. A panic will occur if this happens.
    pub fn into_write_guard(self) -> AtomicRwWriteGuard<'a, GlobalState> {
        match self {
            Self::WriteGuard(g) => g,
            _ => panic!("wrong usage: not a write guard"),
        }
    }

    /// returns present blockchain tip block.
    pub async fn tip(&self) -> Arc<Block> {
        match self {
            Self::Lock(gsl) => gsl.lock_guard().await.chain.light_state_clone(),
            Self::WriteGuard(gsm) => gsm.chain.light_state_clone(),
            Self::ReadGuard(gs) => gs.chain.light_state_clone(),
        }
    }

    /// returns present blockchain tip block.
    pub fn cli(&self) -> &cli_args::Args {
        match self {
            Self::Lock(gsl) => gsl.cli(),
            Self::WriteGuard(gsm) => gsm.cli(),
            Self::ReadGuard(gs) => gs.cli(),
        }
    }

    pub async fn with<F, R, Args>(&self, func: F, args: Args) -> R
    where
        F: FnOnce(&GlobalState, Args) -> R,
    {
        match self {
            StateLock::Lock(gsl) => {
                let gs = gsl.lock_guard().await;
                func(&gs, args)
            }
            StateLock::ReadGuard(guard) => func(guard, args),
            StateLock::WriteGuard(guard) => func(guard, args),
        }
    }

    pub async fn with_mut<F, R, Args>(&mut self, func: F, args: Args) -> R
    where
        F: FnOnce(&mut GlobalState, Args) -> R,
    {
        match self {
            StateLock::Lock(gsl) => {
                let mut gsm = gsl.lock_guard_mut().await;
                func(&mut gsm, args)
            }
            StateLock::WriteGuard(guard) => func(&mut *guard, args),
            StateLock::ReadGuard(_) => {
                panic!("with_mut can only be used on Lock or WriteGuard variants.")
            }
        }
    }

    // for calling async callbacks, see macros:
    //  state_lock_call_async
    //  state_lock_call_mut_async
}

/// `GlobalState` handles all state of a Neptune node that is shared across its tasks.
///
/// Some fields are only written to by certain tasks.
#[derive(Debug)]
pub struct GlobalState {
    /// The `WalletState` may be updated by the main task and the RPC server.
    pub wallet_state: WalletState,

    /// The `BlockchainState` may only be updated by the main task.
    pub chain: BlockchainState,

    /// The `NetworkingState` may be updated by both the main task, peer tasks,
    /// and RPC server.
    pub net: NetworkingState,

    /// The `cli_args::Args` are read-only and accessible by all tasks.
    cli: cli_args::Args,

    /// The `Mempool` may only be updated by the main task.
    pub mempool: Mempool,

    /// The `mining_state` can be updated by main task, mining task, or RPC server.
    pub mining_state: MiningState,

    /// Force wallet to maintain its own membership proofs. These membership
    /// proofs will otherwise be read from the archival mutator set.
    #[cfg(test)]
    force_wallet_membership_proof_maintance: bool,
}

impl Drop for GlobalState {
    fn drop(&mut self) {
        tracing::debug!("spawning flush db thread");
        std::thread::scope(|s| {
            s.spawn(|| {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    tracing::info!("GlobalState is dropping. flushing database");
                    self.flush_databases().await
                })
                .unwrap();
            });
        });
    }
}

impl GlobalState {
    pub async fn try_new(
        data_directory: DataDirectory,
        genesis: Block,
        cli: cli_args::Args,
    ) -> Result<Self> {
        // Get wallet object, create various wallet secret files
        let wallet_dir = data_directory.wallet_directory_path();
        DataDirectory::create_dir_if_not_exists(&wallet_dir).await?;
        let wallet_file_context =
            WalletFileContext::read_from_file_or_create(&data_directory.wallet_directory_path())?;
        debug!("Now getting wallet state. This may take a while if the database needs pruning.");
        let wallet_state =
            WalletState::try_new_from_context(&data_directory, wallet_file_context, &cli, &genesis)
                .await?;
        debug!("Got wallet state.");

        Self::try_new_with_wallet_state(data_directory, genesis, cli, wallet_state).await
    }

    /// Initialize a global state with a supplied wallet state.
    ///
    /// This function is required for benchmarks, but is not part of the public API.
    #[doc(hidden)]
    pub async fn try_new_with_wallet_state(
        data_directory: DataDirectory,
        genesis: Block,
        cli: cli_args::Args,
        wallet_state: WalletState,
    ) -> Result<Self> {
        let archival_state = ArchivalState::new(data_directory.clone(), genesis, cli.network).await;
        debug!("Got archival state");

        // Get latest block. Use hardcoded genesis block if nothing is in database.
        let latest_block: Block = archival_state.get_tip().await;

        let peer_map: HashMap<SocketAddr, PeerInfo> = HashMap::new();
        let peer_databases = NetworkingState::initialize_peer_databases(&data_directory).await?;
        debug!("Got peer databases");

        let net = NetworkingState::new(peer_map, peer_databases);

        let light_state: LightState = LightState::from(latest_block);
        let chain = BlockchainArchivalState {
            light_state,
            archival_state,
        };
        let chain = BlockchainState::Archival(Box::new(chain));
        let mempool = Mempool::new(
            cli.max_mempool_size,
            cli.proving_capability(),
            chain.light_state(),
        );

        Ok(Self::new(wallet_state, chain, net, cli, mempool))
    }

    pub fn new(
        wallet_state: WalletState,
        chain: BlockchainState,
        net: NetworkingState,
        cli: cli_args::Args,
        mempool: Mempool,
    ) -> Self {
        Self {
            wallet_state,
            chain,
            net,
            cli,
            mempool,
            mining_state: MiningState::default(),
            #[cfg(test)]
            force_wallet_membership_proof_maintance: false,
        }
    }

    /// Return a seed used to randomize shuffling.
    pub(crate) fn shuffle_seed(&self) -> [u8; 32] {
        let next_block_height = self.chain.light_state().header().height.next();
        self.wallet_state
            .wallet_entropy
            .shuffle_seed(next_block_height)
    }

    pub async fn get_wallet_status_for_tip(&self) -> WalletStatus {
        let tip_digest = self.chain.light_state().hash();
        let mutator_set_accumulator = self
            .chain
            .light_state()
            .mutator_set_accumulator_after()
            .expect("block in state must have mutator set after");
        self.wallet_state
            .get_wallet_status(tip_digest, &mutator_set_accumulator)
            .await
    }

    pub(crate) fn consensus_rule_set(&self) -> ConsensusRuleSet {
        let tip_height = self.chain.light_state().header().height;
        ConsensusRuleSet::infer_from(self.cli().network, tip_height)
    }

    /// The block height in which the latest UTXO was either spent or received.
    /// `None` if this wallet never received a UTXO.
    pub async fn get_latest_balance_height(&self) -> Option<BlockHeight> {
        let (height, time_secs) =
            time_fn_call_async(self.get_latest_balance_height_internal()).await;

        debug!("call to get_latest_balance_height() took {time_secs} seconds");

        height
    }

    /// Determine whether the conditions are met to enter into sync mode.
    ///
    /// Specifically, compute a boolean value based on
    ///  - whether the foreign cumulative proof-of-work exceeds that of our own;
    ///  - whether the foreign block has a bigger block height and the height
    ///    difference exceeds the threshold set by the CLI.
    ///
    /// The main loop relies on this criterion to decide whether to enter sync
    /// mode. If the main loop activates sync mode, it affects the entire
    /// application.
    pub(crate) fn sync_mode_threshold_stateless(
        own_block_tip_header: &BlockHeader,
        claimed_height: BlockHeight,
        claimed_cumulative_pow: ProofOfWork,
        sync_mode_threshold: usize,
    ) -> bool {
        own_block_tip_header.cumulative_proof_of_work < claimed_cumulative_pow
            && claimed_height - own_block_tip_header.height > sync_mode_threshold as i128
    }

    /// Determine whether the conditions are met to enter into sync mode.
    ///
    /// Specifically, compute a boolean value based on
    ///  - whether the foreign cumulative proof-of-work exceeds that of our own;
    ///  - whether the foreign block has a bigger block height and the height
    ///    difference exceeds the threshold set by the CLI.
    ///
    /// The main loop relies on this criterion to decide whether to enter sync
    /// mode. If the main loop activates sync mode, it affects the entire
    /// application.
    pub(crate) fn sync_mode_criterion(
        &self,
        claimed_max_height: BlockHeight,
        claimed_cumulative_pow: ProofOfWork,
    ) -> bool {
        let own_block_tip_header = self.chain.light_state().header();
        Self::sync_mode_threshold_stateless(
            own_block_tip_header,
            claimed_max_height,
            claimed_cumulative_pow,
            self.cli().sync_mode_threshold,
        )
    }

    /// Automatically assemble the composer parameters for composing the next
    /// block from the state.
    ///
    /// The next block height is passed as an argument as opposed to being read
    /// from state since the caller needs to declare it to resolve race
    /// conditions.
    ///
    /// # Panics
    ///
    ///  - If `next_block_height` is genesis.
    pub(crate) fn composer_parameters(&self, next_block_height: BlockHeight) -> ComposerParameters {
        assert!(!next_block_height.is_genesis());

        let coinbase_distribution = self.mining_state.overridden_coinbase_distribution();

        self.wallet_state.composer_parameters(
            next_block_height,
            self.cli.guesser_fraction,
            self.cli.fee_notification,
            coinbase_distribution,
        )
    }

    /// Returns true iff the incoming block proposal is more favorable than the
    /// one we're currently working on. Returns false if peer is either not
    /// whitelisted, or if all foreign block proposals should be rejected.
    ///
    /// Favor [`Self::favor_incoming_block_proposal`] whenever the digests are
    /// available, as this function can return false positives in case of a
    /// reorganization.
    pub(crate) fn favor_incoming_block_proposal_legacy(
        &self,
        incoming_block_height: BlockHeight,
        incoming_guesser_fee: NativeCurrencyAmount,
    ) -> Result<(), BlockProposalRejectError> {
        let expected_height = self.chain.light_state().header().height.next();
        if incoming_block_height != expected_height {
            return Err(BlockProposalRejectError::WrongHeight {
                received: incoming_block_height,
                expected: expected_height,
            });
        }

        if self.mining_state.block_proposal.has_own() {
            return Err(BlockProposalRejectError::HasOwnBlockProposal);
        }

        let maybe_existing_fee = self.mining_state.block_proposal.map(|x| {
            x.body()
                .total_guesser_reward()
                .expect("block in state must be valid")
        });
        if maybe_existing_fee.is_some_and(|current| current >= incoming_guesser_fee)
            || incoming_guesser_fee.is_zero()
        {
            Err(BlockProposalRejectError::InsufficientFee {
                current: maybe_existing_fee,
                received: incoming_guesser_fee,
            })
        } else {
            Ok(())
        }
    }

    /// Returns true iff the incoming block proposal is more favorable than the
    /// one we're currently working on. Returns false if block proposal does not
    /// have expected parent.
    pub(crate) fn favor_incoming_block_proposal(
        &self,
        incoming_proposal_prev_block_digest: Digest,
        incoming_guesser_fee: NativeCurrencyAmount,
    ) -> Result<(), BlockProposalRejectError> {
        let current_tip_digest = self.chain.light_state().hash();
        if incoming_proposal_prev_block_digest != current_tip_digest {
            return Err(BlockProposalRejectError::WrongParent {
                received: incoming_proposal_prev_block_digest,
                expected: current_tip_digest,
            });
        }

        if self.mining_state.block_proposal.has_own() {
            return Err(BlockProposalRejectError::HasOwnBlockProposal);
        }

        let maybe_existing_fee = self.mining_state.block_proposal.map(|x| {
            x.body()
                .total_guesser_reward()
                .expect("block in state must be valid")
        });
        if maybe_existing_fee.is_some_and(|current| current >= incoming_guesser_fee)
            || incoming_guesser_fee.is_zero()
        {
            Err(BlockProposalRejectError::InsufficientFee {
                current: maybe_existing_fee,
                received: incoming_guesser_fee,
            })
        } else {
            Ok(())
        }
    }

    /// Returns true iff the block proposal exceeds the previous proposal with
    /// enough guesser reward to warrant a restart of the guesser with the
    /// overhead that that brings.
    ///
    /// Caller must have validated the new block proposal before calling this
    /// function.
    ///
    /// # Panics
    ///
    /// - If the new block proposal has a negative fee.
    pub(crate) fn block_proposal_warrants_guess_restart(&self, new_proposal: &Block) -> bool {
        match self.mining_state.mining_status {
            // If a proposal is already being worked on, check if a
            // re-calculation of the preprocess-data is worth it.
            MiningStatus::Guessing(guessing_work_info) => {
                let old_guesser_reward = guessing_work_info.total_guesser_fee;
                let new_guesser_reward = new_proposal
                    .body()
                    .total_guesser_reward()
                    .expect("New proposal must be valid");
                let Some(delta) = new_guesser_reward.checked_sub(&old_guesser_reward) else {
                    return false;
                };

                let relative_delta = delta.to_nau_f64() / old_guesser_reward.to_nau_f64();
                relative_delta >= self.cli.minimum_guesser_improvement_fraction
            }

            // If currently composing, don't interrupt this process
            MiningStatus::Composing(_) => false,

            // If no proposal is being worked on, get started on one.
            MiningStatus::Inactive => true,
        }
    }

    /// Returns true iff the current block proposal is present and has a high
    /// enough guesser fee to be worth guessing on. Always  returns true if
    /// proposal was made locally.
    pub(crate) fn current_block_proposal_meets_threshold(&self) -> bool {
        match &self.mining_state.block_proposal {
            BlockProposal::OwnComposition(_) => true,
            BlockProposal::ForeignComposition(block) => block
                .relative_guesser_reward()
                .is_ok_and(|x| x >= self.cli.minimum_guesser_fraction),
            BlockProposal::None => false,
        }
    }

    /// Determine whether the incoming block is more canonical than the current
    /// tip, *i.e.*, wins the fork choice rule.
    ///
    /// If the incoming block equals the current tip, this function returns
    /// false.
    pub fn incoming_block_is_more_canonical(&self, incoming_block: &Block) -> bool {
        let winner = Block::fork_choice_rule(self.chain.light_state(), incoming_block);
        winner.hash() != self.chain.light_state().hash()
    }

    /// Retrieve block height of last change to wallet balance.
    ///
    /// note: this fn could be implemented as:
    ///   1. get_balance_history()
    ///   2. sort by height
    ///   3. return height of last entry.
    ///
    /// this implementation is a bit more efficient as it avoids
    ///   the sort and some minor work looking up amount and confirmation
    ///   height of each utxo.
    ///
    /// Presently this is o(n) with the number of monitored utxos.
    /// if storage could keep track of latest spend utxo for the active
    /// tip, then this could be o(1).
    async fn get_latest_balance_height_internal(&self) -> Option<BlockHeight> {
        let current_tip_digest = self.chain.light_state().hash();
        let monitored_utxos = self.wallet_state.wallet_db.monitored_utxos();

        if monitored_utxos.is_empty().await {
            return None;
        }

        let mut max_spent_in_block: Option<BlockHeight> = None;
        let mut max_confirmed_in_block: Option<BlockHeight> = None;

        // monitored_utxos are ordered by confirmed_in_block ascending.
        // To efficiently find max(confirmed_in_block) we can start at the end
        // and work backward until we find the first utxo with a valid
        // membership proof for current tip.
        //
        // We then continue working backward through all entries to
        // determine max(spent_in_block)

        // note: Stream trait does not have a way to reverse, so instead
        // of stream_values() we use stream_many_values() and supply
        // an iterator of indexes that are already reversed.

        let stream = monitored_utxos.stream_many_values((0..monitored_utxos.len().await).rev());
        pin_mut!(stream); // needed for iteration

        while let Some(mutxo) = stream.next().await {
            if max_confirmed_in_block.is_none() {
                if let Some((.., confirmed_in_block)) = mutxo.confirmed_in_block {
                    if mutxo
                        .get_membership_proof_for_block(current_tip_digest)
                        .is_some()
                    {
                        max_confirmed_in_block = Some(confirmed_in_block);
                    }
                }
            }

            if let Some((.., spent_in_block)) = mutxo.spent_in_block {
                if mutxo
                    .get_membership_proof_for_block(current_tip_digest)
                    .is_some()
                    && (max_spent_in_block.is_none()
                        || max_spent_in_block.is_some_and(|x| x < spent_in_block))
                {
                    max_spent_in_block = Some(spent_in_block);
                }
            }
        }

        max(max_confirmed_in_block, max_spent_in_block)
    }

    /// Retrieve wallet balance history
    pub async fn get_balance_history(
        &self,
    ) -> Vec<(Digest, Timestamp, BlockHeight, NativeCurrencyAmount)> {
        let current_tip_digest = self.chain.light_state().hash();
        let current_msa = self
            .chain
            .light_state()
            .mutator_set_accumulator_after()
            .expect("block from state must have mutator set after");

        let monitored_utxos = self.wallet_state.wallet_db.monitored_utxos();

        let mut history = vec![];

        let stream = monitored_utxos.stream_values().await;
        pin_mut!(stream); // needed for iteration
        while let Some(monitored_utxo) = stream.next().await {
            let Some(msmp) = monitored_utxo.membership_proof_ref_for_block(current_tip_digest)
            else {
                continue;
            };

            if let Some((confirming_block, confirmation_timestamp, confirmation_height)) =
                monitored_utxo.confirmed_in_block
            {
                let amount = monitored_utxo.utxo.get_native_currency_amount();
                history.push((
                    confirming_block,
                    confirmation_timestamp,
                    confirmation_height,
                    amount,
                ));

                if let Some((spending_block, spending_timestamp, spending_height)) =
                    monitored_utxo.spent_in_block
                {
                    let actually_spent =
                        !current_msa.verify(Tip5::hash(&monitored_utxo.utxo), msmp);
                    if actually_spent {
                        history.push((
                            spending_block,
                            spending_timestamp,
                            spending_height,
                            -amount,
                        ));
                    }
                }
            }
        }

        history
    }

    /// retrieves all spendable inputs in the wallet as of the present tip.
    ///
    /// excludes utxos:
    ///   + that are timelocked in the future
    ///   + that are unspendable (no spending key)
    ///   + that are already spent in the mempool
    ///
    /// note: ordering of the returned `TxInput` is insertion order into the
    /// wallet.
    pub async fn wallet_spendable_inputs(
        &self,
        timestamp: Timestamp,
    ) -> impl IntoIterator<Item = TxInput> + use<'_> {
        let wallet_status = self.get_wallet_status_for_tip().await;
        self.wallet_state.spendable_inputs(wallet_status, timestamp)
    }

    pub(crate) fn get_own_handshakedata(&self) -> HandshakeData {
        let listen_port = self.cli().own_listen_port();
        HandshakeData {
            tip_header: *self.chain.light_state().header(),
            listen_port,
            network: self.cli().network,
            instance_id: self.net.instance_id,
            version: VersionString::try_from_str(VERSION).unwrap_or_else(|_| {
                panic!(
                "Must be able to convert own version number to fixed-size string. Got {VERSION}")
            }),
            // For now, all nodes are archival nodes
            is_archival_node: self.chain.is_archival_node(),
            is_bootstrapper_node: self.cli().bootstrap,
            timestamp: SystemTime::now(),
            extra_data: Default::default(),
        }
    }

    /// In case the wallet database is corrupted or deleted, this method will restore
    /// monitored UTXO data structures from recovery data. This method should only be
    /// called on startup, not while the program is running, since it will only restore
    /// a wallet state, if the monitored UTXOs have been deleted. Not merely if they
    /// are not synced with a valid mutator set membership proof. And this corruption
    /// can only happen if the wallet database is deleted or corrupted.
    ///
    /// # Panics
    ///
    /// Panics if the mutator set is not synced to current tip.
    pub(crate) async fn restore_monitored_utxos_from_recovery_data(&mut self) -> Result<()> {
        let tip_hash = self.chain.light_state().hash();
        let ams_ref = &self.chain.archival_state().archival_mutator_set;

        let asm_sync_label = ams_ref.get_sync_label();
        assert_eq!(
            tip_hash, asm_sync_label,
            "Error: sync label in archival mutator set database disagrees with \
            block tip. Archival mutator set must be synced to tip for successful \
            MUTXO recovery.\n\
            Possible causes: different or new genesis block; corrupt file system.\n\
            Possible solution: try deleting the database at `DATA_DIR/databases/`. \
            Get the value of `DATA_DIR` from the first message in the log, and \
            *do not* delete the wallet file or directory.\n\n\
            Tip:\n{tip_hash:x};\nsync label:\n{asm_sync_label:x}"
        );

        // Fetch all incoming UTXOs from recovery data. Then make a HashMap for
        // fast lookup.
        let incoming_utxos = self.wallet_state.read_utxo_ms_recovery_data().await?;
        let incoming_utxo_count = incoming_utxos.len();
        info!("Checking {} incoming UTXOs", incoming_utxo_count);

        let mut recovery_data_for_missing_mutxos = vec![];
        {
            // Two UTXOs are considered the same iff their AOCL index and
            // their addition record agree. Otherwise, they are different.
            let mutxos: HashMap<(u64, AdditionRecord), MonitoredUtxo> = self
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .stream_values()
                .await
                .map(|x| ((x.aocl_index(), x.addition_record()), x))
                .collect()
                .await;
            let mut seen_recovery_entries = HashSet::<Digest>::default();

            for incoming_utxo in incoming_utxos {
                let new_value = seen_recovery_entries.insert(Tip5::hash(&incoming_utxo));

                // Ensure duplicated entries are filtered out.
                if !new_value {
                    warn!(
                        "Recovery data contains duplicated entries. Entry with AOCL index {} \
                     was duplicated.",
                        incoming_utxo.aocl_index
                    );
                    continue;
                }

                if mutxos
                    .get(&(incoming_utxo.aocl_index, incoming_utxo.addition_record()))
                    .map(|x| x.get_latest_membership_proof_entry())
                    .is_some()
                {
                    continue;
                }

                // If no match is found, add the UTXO to the list of missing UTXOs
                recovery_data_for_missing_mutxos.push(incoming_utxo);
            }
        }

        if recovery_data_for_missing_mutxos.is_empty() {
            info!(
                "No missing monitored UTXOs found in wallet database. Wallet database looks good."
            );
            return Ok(());
        }

        // For all recovery data where we did not find a matching monitored UTXO,
        // recover the MS membership proof, and insert a new monitored UTXO into the
        // wallet database.
        info!(
            "Attempting to restore {} missing monitored UTXOs to wallet database",
            recovery_data_for_missing_mutxos.len()
        );
        let current_aocl_leaf_count = ams_ref.ams().aocl.num_leafs().await;
        let mut restored_mutxos = 0;
        for incoming_utxo in recovery_data_for_missing_mutxos {
            // If the referenced UTXO is in the future from our tip, do not attempt to recover it. Instead: warn the user of this.
            if current_aocl_leaf_count <= incoming_utxo.aocl_index {
                warn!("Cannot restore UTXO with AOCL index {} because it is in the future from our tip. Current AOCL leaf count is {current_aocl_leaf_count}. Maybe this UTXO can be recovered once more blocks are downloaded from peers?", incoming_utxo.aocl_index);
                continue;
            }

            let ms_item = Tip5::hash(&incoming_utxo.utxo);
            let restored_msmp_res = ams_ref
                .ams()
                .restore_membership_proof(
                    ms_item,
                    incoming_utxo.sender_randomness,
                    incoming_utxo.receiver_preimage,
                    incoming_utxo.aocl_index,
                )
                .await;
            let restored_msmp = match restored_msmp_res {
                Ok(msmp) => {
                    // Verify that the restored MSMP is valid
                    if !ams_ref.ams().verify(ms_item, &msmp).await {
                        warn!("Restored MSMP is invalid. Skipping restoration of UTXO with AOCL index {}. Maybe this UTXO is on an abandoned chain? Or maybe it was spent?", incoming_utxo.aocl_index);
                        continue;
                    }

                    msmp
                }
                Err(err) => bail!("Could not restore MS membership proof. Got: {err}"),
            };

            let mut restored_mutxo = MonitoredUtxo::new(
                incoming_utxo.utxo,
                self.wallet_state.configuration.num_mps_per_utxo,
            );
            restored_mutxo.add_membership_proof_for_tip(tip_hash, restored_msmp);

            // Add block info for restored MUTXO
            let confirming_block_digest = self
                .chain
                .archival_state()
                .canonical_block_digest_of_aocl_index(incoming_utxo.aocl_index)
                .await?
                .expect("Confirming block must exist");
            let confirming_block_header = self
                .chain
                .archival_state()
                .get_block_header(confirming_block_digest)
                .await
                .expect("Confirming block header must exist");
            restored_mutxo.confirmed_in_block = Some((
                confirming_block_digest,
                confirming_block_header.timestamp,
                confirming_block_header.height,
            ));

            self.wallet_state
                .wallet_db
                .monitored_utxos_mut()
                .push(restored_mutxo)
                .await;
            restored_mutxos += 1;
        }

        self.wallet_state.wallet_db.persist().await;
        info!("Successfully restored {restored_mutxos} monitored UTXOs to wallet database");

        Ok(())
    }

    /// Restore mutator set membership proofs of all monitored UTXOs from an
    /// archival mutator set.
    ///
    /// If some monitored UTXOs in the wallet don't have any mutator set
    /// membership proofs (synced or not), then they must have an associated
    /// element in `new_utxos` argument. The order of the monitored UTXO with a
    /// missing membership proofs must match the order of the `new_utxos` input.
    ///
    /// # Panics
    ///
    ///  - If the archival mutator set is not synced to the current state tip.
    ///  - If recovery data is provided but out-of-order to the monitored UTXOs
    ///    that don't have any membership proofs.
    pub async fn restore_monitored_utxos_from_archival_mutator_set(
        &mut self,
        mut new_utxos: Option<Vec<IncomingUtxoRecoveryData>>,
    ) {
        let tip_hash = self.chain.light_state().hash();
        let ams_ref = &self.chain.archival_state().archival_mutator_set;

        // Assert that archival mutator set is synced to current tip.
        // Otherwise, the function could proceed successfully but the resulting
        // membership proofs would be synced to some wrong block which is not
        // the tip.
        let asm_sync_label = ams_ref.get_sync_label();
        assert_eq!(
            tip_hash,
            asm_sync_label,
            "Error: sync label in archival mutator set database disagrees with \
            block tip. Archival mutator set must be synced to tip for successful \
            MUTXO recovery.\n\
            Possible causes: different or new genesis block; corrupt file system.\n\
            Possible solution: try deleting the database at `DATA_DIR/databases/`. \
            Get the value of `DATA_DIR` from the first message in the log, and \
            *do not* delete the wallet file or directory.\n\n\
            Tip:\n{};\nsync label:\n{}",
            tip_hash.to_hex(),
            asm_sync_label.to_hex()
        );

        let monitored_utxos = self.wallet_state.wallet_db.monitored_utxos_mut();
        let num_mutxos = monitored_utxos.len().await;
        trace!("monitored_utxos.len() = {num_mutxos}");
        for i in 0..num_mutxos {
            let mut monitored_utxo = monitored_utxos.get(i).await;

            if monitored_utxo.is_synced_to(tip_hash) {
                trace!("Not restoring because UTXO is marked as synced");
                continue;
            }

            // monitored UTXO does not have a valid membership proof. Fetch it
            // from the archival mutator set.
            let (sender_randomness, receiver_preimage, aocl_leaf_index) = match monitored_utxo
                .get_latest_membership_proof_entry()
            {
                Some((_, msmp)) => (
                    msmp.sender_randomness,
                    msmp.receiver_preimage,
                    msmp.aocl_leaf_index,
                ),
                None => {
                    // TODO: Fix this ugly hack. We probably need AOCL leaf index on the monitored
                    // UTXO structure to do that. And that requires a DB migration :(
                    let Some(new_utxos) = new_utxos.as_mut() else {
                        warn!("Monitored UTXO has no membership proof and no recovery data was provided.");
                        continue;
                    };
                    let Some((index, _)) = new_utxos
                        .iter()
                        .find_position(|x| x.utxo == monitored_utxo.utxo)
                    else {
                        warn!("Monitored UTXO has no membership proof recovery data for this UTXO was not provided.");
                        continue;
                    };

                    assert!(
                        index.is_zero(),
                        "Order of recovery data must match MUTXO order"
                    );

                    let recovery_data = new_utxos.remove(index);

                    debug!("Setting MUTXO membership proof for the 1st time");
                    (
                        recovery_data.sender_randomness,
                        recovery_data.receiver_preimage,
                        recovery_data.aocl_index,
                    )
                }
            };

            let ms_item = Tip5::hash(&monitored_utxo.utxo);
            let Ok(restored_msmp) = ams_ref
                .ams()
                .restore_membership_proof(
                    ms_item,
                    sender_randomness,
                    receiver_preimage,
                    aocl_leaf_index,
                )
                .await
            else {
                warn!(
                    "Failed to restore mutator set membership proof for UTXO \
                with leaf index {aocl_leaf_index}."
                );
                continue;
            };

            if monitored_utxo.spent_in_block.is_none()
                && !ams_ref.ams().verify(ms_item, &restored_msmp).await
            {
                // If the UTXO was spent *and* its membership proof is invalid
                // after attempting to resync, then that expenditure must still
                // be canonical.
                // On the contrary, if the UTXO was spent and resync succeeded,
                // then the expenditure was reverted. This is the reason why
                // we do not filter out UTXOs that were marked as spent before
                // attempting to resync the membership proof. However, if we
                // get here, then we know that the resulting membership proof is
                // invalid.
                // So instead, we use the information that the UTXO was spent
                // only for suppressing the following log message, which would
                // be rather noisy otherwise.
                warn!("Restored MSMP is invalid. Skipping restoration of UTXO with AOCL index {}. Maybe this UTXO is on an abandoned chain?", aocl_leaf_index);
                continue;
            }

            monitored_utxo.add_membership_proof_for_tip(tip_hash, restored_msmp);

            // update storage.
            monitored_utxos.set(i, monitored_utxo).await;
        }

        self.wallet_state.wallet_db.set_sync_label(tip_hash).await;
    }

    /// Fix mutator set membership proofs that are unsynced.
    ///
    /// This method fixes membership proofs that are synced to an old block,
    /// possibly even a block that lives on an abandoned chain. It does not work
    /// for corrupted membership proofs. It assumes that the node stores all
    /// historical blocks; it does not assume that the node stores an archival
    /// mutator set.
    ///
    /// The algorithm works as follows. For each unsynced monitored UTXO, start
    /// by finding a path connecting the block it is synced to, to the current
    /// tip. This path may involve some blocks to revert ("backwards"),
    /// certainly involves a latest universal common ancestor ("LUCA"), and
    /// probably involves some blocks to apply ("forwards"). As we walk this
    /// path, the mutator set membership proof of the monitored UTXO is modified
    /// in accordance with the mutator set update induced by the block in
    /// question, which could be a revert (backwards) or a regular apply
    /// (forwards).
    ///
    ///  Locking:
    ///   * acquires `monitored_utxos_lock` for write
    pub async fn resync_membership_proofs_from_stored_blocks(
        &mut self,
        tip_hash: Digest,
    ) -> Result<()> {
        // loop over all monitored utxos
        let monitored_utxos = self.wallet_state.wallet_db.monitored_utxos_mut();

        'outer: for i in 0..monitored_utxos.len().await {
            let i = i as Index;
            let monitored_utxo = monitored_utxos.get(i).await;

            // Ignore those MUTXOs that were marked as abandoned
            if monitored_utxo.abandoned_at.is_some() {
                continue;
            }

            // ignore synced ones
            if monitored_utxo.is_synced_to(tip_hash) {
                continue;
            }

            debug!(
                "Resyncing monitored UTXO number {}, with hash {}",
                i,
                Tip5::hash(&monitored_utxo.utxo)
            );

            // If the UTXO was not confirmed yet, there is no
            // point in synchronizing its membership proof.
            let Some((confirming_block_digest, _, confirming_block_height)) =
                monitored_utxo.confirmed_in_block
            else {
                continue;
            };

            // try latest (block hash, membership proof) entry
            let (block_hash, mut membership_proof) = monitored_utxo
                .get_latest_membership_proof_entry()
                .expect("Database not in consistent state. Monitored UTXO must have at least one membership proof.");

            // request path-to-tip
            let (backwards, _luca, forwards) = self
                .chain
                .archival_state()
                .find_path(block_hash, tip_hash)
                .await;

            // after this point, we may be modifying it.
            let mut monitored_utxo = monitored_utxo.clone();

            // walk backwards, reverting
            for revert_block_hash in backwards {
                // Was the UTXO confirmed in this block? If so, there
                // is nothing we can do except orphan the UTXO: that
                // is, leave it without a synced membership proof.
                // Whenever current owned UTXOs are queried, one
                // should take care to filter for UTXOs that have a
                // membership proof synced to the current block tip.
                if confirming_block_digest == revert_block_hash {
                    warn!(
                        "Could not recover MSMP as transaction appears to be on an abandoned chain"
                    );
                    break 'outer;
                }

                let revert_block = self
                    .chain
                    .archival_state()
                    .get_block(revert_block_hash)
                    .await?
                    .unwrap();
                let revert_block_parent = self
                    .chain
                    .archival_state()
                    .get_block(revert_block.kernel.header.prev_block_digest)
                    .await?
                    .expect("All blocks that are reverted must have a parent, since genesis block can never be reverted.");
                let previous_mutator_set = revert_block_parent
                    .mutator_set_accumulator_after()
                    .expect("block from state must have mutator set after")
                    .clone();

                debug!("MUTXO confirmed at height {confirming_block_height}, reverting for height {} on abandoned chain", revert_block.kernel.header.height);

                // revert removals
                for removal_record in revert_block
                    .mutator_set_update()
                    .expect("Stored block must have mutator set update")
                    .removals
                    .iter()
                    .rev()
                {
                    membership_proof.revert_update_from_remove(removal_record);
                }

                // revert additions
                membership_proof.revert_update_from_batch_addition(&previous_mutator_set);

                // unset spent_in_block field if the UTXO was spent in this block
                if let Some((spent_block_hash, _, _)) = monitored_utxo.spent_in_block {
                    if spent_block_hash == revert_block_hash {
                        monitored_utxo.spent_in_block = None;
                    }
                }

                // assert valid (if unspent)
                assert!(monitored_utxo.spent_in_block.is_some() || previous_mutator_set
                    .verify(Tip5::hash(&monitored_utxo.utxo), &membership_proof), "Failed to verify monitored UTXO {monitored_utxo:?}\n against previous MSA in block {revert_block:?}");
            }

            // walk forwards, applying
            for apply_block_hash in forwards {
                // Was the UTXO confirmed in this block?
                // This can occur in some edge cases of forward-only
                // resynchronization. In this case, assume the
                // membership proof is already synced to this block.
                if confirming_block_digest == apply_block_hash {
                    continue;
                }

                let apply_block = self
                    .chain
                    .archival_state()
                    .get_block(apply_block_hash)
                    .await?
                    .unwrap();
                let predecessor_block = self
                    .chain
                    .archival_state()
                    .get_block(apply_block.kernel.header.prev_block_digest)
                    .await?;
                let mut block_msa = match &predecessor_block {
                    Some(block) => block
                        .mutator_set_accumulator_after()
                        .expect("block from archival state must have mutator set after")
                        .clone(),
                    None => MutatorSetAccumulator::default(),
                };
                let MutatorSetUpdate {
                    additions,
                    mut removals,
                } = apply_block
                    .mutator_set_update()
                    .expect("block from archival state must have mutator set update");

                // apply additions
                for addition_record in &additions {
                    // keep removal records up-to-date
                    RemovalRecord::batch_update_from_addition(
                        &mut removals.iter_mut().collect_vec(),
                        &block_msa,
                    );

                    membership_proof
                        .update_from_addition(
                            Tip5::hash(&monitored_utxo.utxo),
                            &block_msa,
                            addition_record,
                        )
                        .expect("Could not update membership proof with addition record.");
                    block_msa.add(addition_record);
                }

                // apply removals
                let mut remaining_removal_records = removals;
                remaining_removal_records.reverse();
                while let Some(current_removal_record) = remaining_removal_records.pop() {
                    // keep removal records in sync
                    RemovalRecord::batch_update_from_remove(
                        &mut remaining_removal_records.iter_mut().collect_vec(),
                        &current_removal_record,
                    );

                    membership_proof.update_from_remove(&current_removal_record);
                    block_msa.remove(&current_removal_record);
                }

                assert_eq!(
                    block_msa.hash(),
                    apply_block.mutator_set_accumulator_after().unwrap().hash()
                );
            }

            // store updated membership proof
            monitored_utxo.add_membership_proof_for_tip(tip_hash, membership_proof);

            // update storage.
            monitored_utxos.set(i, monitored_utxo).await
        }

        // Update sync label and persist
        self.wallet_state.wallet_db.set_sync_label(tip_hash).await;
        self.wallet_state.wallet_db.persist().await;

        Ok(())
    }

    /// Delete from the database all monitored UTXOs from abandoned chains with a depth deeper than
    /// `block_depth_threshold`. Use `prune_mutxos_of_unknown_depth = true` to remove MUTXOs from
    /// abandoned chains of unknown depth.
    /// Returns the number of monitored UTXOs that were marked as abandoned.
    ///
    /// Locking:
    ///  * acquires `monitored_utxos` lock for write
    pub async fn prune_abandoned_monitored_utxos(
        &mut self,
        block_depth_threshold: usize,
    ) -> Result<usize> {
        const MIN_BLOCK_DEPTH_FOR_MUTXO_PRUNING: usize = 10;
        ensure!(
            block_depth_threshold >= MIN_BLOCK_DEPTH_FOR_MUTXO_PRUNING,
            "Cannot prune monitored UTXOs with a depth threshold less than \
            {MIN_BLOCK_DEPTH_FOR_MUTXO_PRUNING}. Got threshold {block_depth_threshold}"
        );

        // Find monitored_utxo for updating
        let current_tip_header = self.chain.light_state().header();
        let current_tip_digest = self.chain.light_state().hash();
        let current_tip_info: (Digest, Timestamp, BlockHeight) = (
            current_tip_digest,
            current_tip_header.timestamp,
            current_tip_header.height,
        );
        let monitored_utxos = self.wallet_state.wallet_db.monitored_utxos_mut();
        let mut removed_count = 0;
        for i in 0..monitored_utxos.len().await {
            let mut mutxo = monitored_utxos.get(i).await;

            // 1. Spent MUTXOs are not marked as abandoned, as there's no reason to maintain them
            //    once the spending block is buried sufficiently deep
            // 2. If synced to current tip, there is nothing more to do with this MUTXO
            // 3. If already marked as abandoned, we don't do that again
            if mutxo.spent_in_block.is_some()
                || mutxo.is_synced_to(current_tip_info.0)
                || mutxo.abandoned_at.is_some()
            {
                continue;
            }

            // MUTXO is neither spent nor synced. Mark as abandoned
            // if it was confirmed in block that is now abandoned,
            // and if that block is older than threshold.
            if let Some((_, _, block_height_confirmed)) = mutxo.confirmed_in_block {
                let depth = current_tip_header.height - block_height_confirmed + 1;

                let abandoned = depth >= block_depth_threshold as i128
                    && mutxo.was_abandoned(self.chain.archival_state()).await;

                if abandoned {
                    mutxo.abandoned_at = Some(current_tip_info);
                    monitored_utxos.set(i, mutxo).await;
                    removed_count += 1;
                }
            }
        }

        Ok(removed_count)
    }

    pub async fn persist_wallet(&mut self) -> Result<()> {
        // flush wallet databases
        self.wallet_state.wallet_db.persist().await;
        Ok(())
    }

    pub async fn flush_databases(&mut self) -> Result<()> {
        // flush wallet databases
        self.wallet_state.wallet_db.persist().await;

        // flush block_index database
        self.chain.archival_state_mut().block_index_db.flush().await;

        // persist archival_mutator_set, with sync label
        let hash = self.chain.archival_state().get_tip().await.hash();
        self.chain
            .archival_state_mut()
            .archival_mutator_set
            .set_sync_label(hash)
            .await;

        self.chain
            .archival_state_mut()
            .archival_mutator_set
            .persist()
            .await;

        self.chain
            .archival_state_mut()
            .archival_block_mmr
            .persist()
            .await;

        // flush peer_standings
        self.net.peer_databases.peer_standings.flush().await;

        debug!("Flushed all databases");

        Ok(())
    }

    /// Set the current tip to a stored block, identified by block hash.
    ///
    /// Assumes the block was stored (or is the genesis block), and if it is
    /// not canonical that there is a connecting path. Assumes furthermore that
    /// the node is archival. If any of these assumptions are not met then this
    /// function returns an error.
    ///
    /// # Panics
    ///
    /// - If the stored block is found but does not have a mutator set update.
    pub(crate) async fn set_tip_to_stored_block(&mut self, block_digest: Digest) -> Result<()> {
        // If the node not archival, it cannot sync the wallet. So in this case,
        // abort early.
        ensure!(
            self.chain.is_archival_node(),
            "node must be archival in order to set tip to stored block"
        );

        // Read the block.
        let block = self
            .chain
            .archival_state()
            .get_block(block_digest)
            .await?
            .ok_or(anyhow::Error::msg(format!("unknown block {block_digest}")))?;

        let _ = self.set_new_tip_internal(block).await?;

        Ok(())
    }

    /// Update client's state with a new block.
    ///
    /// The new block is assumed to be valid, also wrt. to proof-of-work.
    /// The new block will be set as the new tip, regardless of its
    /// cumulative proof-of-work number.
    ///
    /// Returns a list of update-jobs that should be
    /// performed by this client.
    pub async fn set_new_tip(&mut self, new_block: Block) -> Result<Vec<MempoolUpdateJob>> {
        self.set_new_tip_internal(new_block).await
    }

    /// Store a block to client's state *without* marking this block as a new
    /// tip. No validation of block happens, as this is the caller's
    /// responsibility.
    pub(crate) async fn store_block_not_tip(&mut self, block: Block) -> Result<()> {
        crate::macros::log_scope_duration!();

        self.chain
            .archival_state_mut()
            .write_block_not_tip(&block)
            .await?;

        // Mempool is not updated, as it's only defined relative to the tip.
        // Wallet is not updated, as it can be synced to tip at any point.

        Ok(())
    }

    /// Update client's state with a new block. Block is assumed to be valid,
    /// also wrt. to PoW. The received block will be set as the new tip,
    /// regardless of its accumulated PoW. or its validity.
    ///
    /// May also be used to set the tip back to any earlier block, including the
    /// genesis block. However, a path from the current tip to the new tip must
    /// be known.
    ///
    /// Returns a list of update-jobs that should be performed by this client.
    ///
    /// # Panics
    ///
    /// - If the new tip does not have a mutator set update.
    async fn set_new_tip_internal(&mut self, new_tip: Block) -> Result<Vec<MempoolUpdateJob>> {
        crate::macros::log_scope_duration!();

        // Update archival state
        self.chain
            .archival_state_mut()
            .write_block_as_tip(&new_tip)
            .await?;

        self.chain
            .archival_state_mut()
            .append_to_archival_block_mmr(&new_tip)
            .await;

        // update the mutator set with the UTXOs from this block
        self.chain
            .archival_state_mut()
            .update_mutator_set(&new_tip)
            .await?;

        *self.chain.light_state_mut() = std::sync::Arc::new(new_tip.clone());

        // Update mempool with UTXOs from this block. This is done by
        // removing all transaction that became invalid/was mined by this
        // block. Also returns the list of update-jobs that should be
        // performed by this client.
        let (mempool_events, update_jobs) = self.mempool.update_with_block(&new_tip)?;

        let parent_ms_accumulator =
            self.chain
                .archival_state()
                .get_tip_parent()
                .await
                .map(|parent| {
                    parent
                        .mutator_set_accumulator_after()
                        .expect("block from archival state must have mutator set after")
                });

        // Sanity check: If no parent is known, new block must be the genesis
        // block.
        if parent_ms_accumulator.is_none() {
            assert_eq!(
                self.chain.archival_state().genesis_block().hash(),
                new_tip.hash(),
                "If no parent is known, new tip must be the genesis block"
            );
        }

        // update wallet state with relevant UTXOs from this block. If we can
        // avoid it, we don't maintain the membership proofs in the wallet
        // since this is very slow. It's faster to read them from the archival
        // mutator set that we already updated above.
        let maintain_mps_in_wallet = {
            #[cfg(not(test))]
            {
                // always false, unless block is genesis
                parent_ms_accumulator.is_none()
            }
            #[cfg(test)]
            {
                // Tests are allowed to initialize the state at an arbitrary
                // block height. If this first block is not genesis, the wallet
                // must maintain its own membership proofs, since no valid
                // archival mutator set is known.
                !self
                    .chain
                    .archival_state()
                    .genesis_block
                    .header()
                    .height
                    .is_genesis()
                    || self.force_wallet_membership_proof_maintance
            }
        };
        let received_utxos = self
            .wallet_state
            .update_wallet_state_with_new_block(
                &parent_ms_accumulator.unwrap_or_default(),
                &new_tip,
                maintain_mps_in_wallet,
            )
            .await?;

        // Get new membership proofs from mutator set accumulator, in case
        // wallet didn't set these from block data.
        if !maintain_mps_in_wallet {
            self.restore_monitored_utxos_from_archival_mutator_set(Some(received_utxos))
                .await;
        }

        self.wallet_state
            .handle_mempool_events(mempool_events)
            .await;

        // Reset block proposal, as that field pertains to the block that
        // was just set as new tip. Also reset set of exported block proposals.
        self.mining_state.block_proposal = BlockProposal::none();
        self.mining_state.exported_block_proposals.clear();

        Ok(update_jobs)
    }

    /// resync membership proofs
    pub async fn resync_membership_proofs(&mut self) -> Result<()> {
        // Do not fix memberhip proofs if node is in sync mode, as we would otherwise
        // have to sync many times, instead of just *one* time once we have caught up.
        if self.net.sync_anchor.is_some() {
            debug!("Not syncing MS membership proofs because we are syncing");
            return Ok(());
        }

        // is it necessary?
        let current_tip_digest = self.chain.light_state().hash();
        if self.wallet_state.is_synced_to(current_tip_digest).await {
            debug!("Membership proof syncing not needed");
            return Ok(());
        }

        // do we have an archival mutator set?
        if self.chain.is_archival_node() {
            self.restore_monitored_utxos_from_archival_mutator_set(None)
                .await;
            return Ok(());
        }

        // do we have blocks?
        // This code is now dead, because we restore from the archival mutator
        // set, but we keep it for now since we want to preserve the way of
        // restoring membership proofs from blocks for a future light client.
        if self.chain.is_archival_node() {
            return self
                .resync_membership_proofs_from_stored_blocks(current_tip_digest)
                .await;
        }

        // request blocks from peers
        todo!("We don't yet support non-archival nodes");
    }

    pub(crate) async fn response_to_sync_challenge(
        &self,
        sync_challenge: SyncChallenge,
    ) -> Result<SyncChallengeResponse> {
        async fn fetch_block_pair(
            state: &GlobalState,
            child_digest: Digest,
        ) -> Option<(Block, Block)> {
            let child = state
                .chain
                .archival_state()
                .get_block(child_digest)
                .await
                .expect("fetching block from archival state should work.");
            let Some(child) = child else {
                warn!("Got sync challenge for unknown tip");

                return None;
            };
            if child.header().height < 2.into() {
                warn!("Got sync challenge for tip of too low height; cannot send genesis block");

                return None;
            }

            let parent_digest = child.header().prev_block_digest;
            let parent = state
                .chain
                .archival_state()
                .get_block(parent_digest)
                .await
                .expect("fetching block from archival state should work.")
                .expect(
                    "parent of known block from archival state must exist, if height exceeds 1.",
                );

            Some((parent, child))
        }

        let Some((tip_parent, tip)) = fetch_block_pair(self, sync_challenge.tip_digest).await
        else {
            bail!("could not fetch tip and tip predecessor");
        };

        let tip_height = tip.header().height;
        ensure!(
            tip_height >= (SYNC_CHALLENGE_POW_WITNESS_LENGTH as u64).into(),
            "tip height {tip_height} is too small for sync mode",
        );

        let mut block_pairs: Vec<(TransferBlock, TransferBlock)> = vec![];
        let mut block_mmr_mps = vec![];
        for child_height in sync_challenge.challenges {
            ensure!(
                child_height >= 2u64.into(),
                "challenge asks for genesis block",
            );
            ensure!(
                child_height < tip.header().height,
                "challenge asks for height that's not ancestor to tip.",
            );

            let Some(child_digest) = self
                .chain
                .archival_state()
                .archival_block_mmr
                .ammr()
                .try_get_leaf(child_height.into())
                .await
            else {
                bail!("could not get leaf from archival block mmr");
            };
            let Some((p, c)) = fetch_block_pair(self, child_digest).await else {
                bail!("could not fetch indicated block pair");
            };

            // Notice that the MMR membership proofs are relative to an MMR
            // where the tip digest *has* been added. So it is not relative to
            // the block MMR accumulator present in the tip block, as it only
            // refers to its ancestors. Rather, it's relative to the block MMR
            // accumulator present in the tip's child.
            block_mmr_mps.push(
                self.chain
                    .archival_state()
                    .archival_block_mmr
                    .ammr()
                    .prove_membership_relative_to_smaller_mmr(
                        child_height.into(),
                        tip_height.next().into(),
                    )
                    .await,
            );
            block_pairs.push((
                p.try_into()
                    .expect("blocks from archive must be transferable"),
                c.try_into()
                    .expect("blocks from archive must be transferable"),
            ));
        }

        let mut pow_witnesses: Vec<BlockHeaderWithBlockHashWitness> = vec![];
        let mut block_hash = tip.hash();
        while pow_witnesses.len() < SYNC_CHALLENGE_POW_WITNESS_LENGTH {
            let pow_witness = self
                .chain
                .archival_state()
                .block_header_with_hash_witness(block_hash)
                .await
                .unwrap_or_else(|| {
                    panic!("Pow-witness for block with hash {block_hash} must exist")
                });
            block_hash = pow_witness.header.prev_block_digest;
            pow_witnesses.push(pow_witness);
        }

        let response = SyncChallengeResponse {
            tip: tip
                .try_into()
                .expect("All blocks from archival state should be transferable."),
            tip_parent: tip_parent
                .try_into()
                .expect("All blocks from archival state should be transferable."),
            blocks: block_pairs.try_into().unwrap(),
            membership_proofs: block_mmr_mps.try_into().unwrap(),
            pow_witnesses: pow_witnesses.try_into().unwrap(),
        };

        Ok(response)
    }

    #[inline]
    pub fn cli(&self) -> &cli_args::Args {
        &self.cli
    }

    pub(crate) fn proving_capability(&self) -> TxProvingCapability {
        self.cli().proving_capability()
    }

    pub(crate) fn min_gobbling_fee(&self) -> NativeCurrencyAmount {
        self.cli().min_gobbling_fee
    }

    pub(crate) fn gobbling_fraction(&self) -> f64 {
        self.cli().gobbling_fraction
    }

    pub(crate) fn max_num_proofs(&self) -> usize {
        self.cli().max_num_proofs
    }

    /// Returns the most favorable transaction for proof updating from the
    /// mempool. Returns an upgrade job for a transaction that is not synced.
    /// Does not perform the actual upgrade, only collects witness data required
    /// to execute it.
    ///
    /// Favors transactions based on upgrade priority first, fee density
    /// second.
    ///
    /// Needs mutable state access because of how the mutator set update value
    /// is calculated. Does not actually mutate any state.
    ///
    /// Returns none if no transaction in the mempool is in need of upgrading
    /// or if transaction in need of upgrading does not provide enough
    /// incentive.
    pub(crate) async fn preferred_update_job_from_mempool(
        &mut self,
        min_gobbling_fee: NativeCurrencyAmount,
        tx_upgrade_filter: TxUpgradeFilter,
    ) -> Option<UpdateMutatorSetDataJob> {
        let (old_kernel, old_proof, upgrade_priority) =
            self.mempool.preferred_update(tx_upgrade_filter)?;

        let gobbling_potential = NativeCurrencyAmount::zero();
        let upgrade_incentive =
            upgrade_priority.incentive_given_gobble_potential(gobbling_potential);
        if !upgrade_incentive.upgrade_is_worth_it(min_gobbling_fee) {
            return None;
        }

        self.update_single_proof_job(
            old_kernel.to_owned(),
            old_proof.to_owned(),
            upgrade_incentive,
        )
        .await
        .ok()
    }

    /// Remove one transaction from the mempool and notify wallet of changes.
    pub(crate) async fn mempool_remove(&mut self, transaction_id: TransactionKernelId) {
        let events = self.mempool.remove(transaction_id);
        self.wallet_state.handle_mempool_events(events).await;
    }

    /// clears all Tx from mempool and notifies wallet of changes.
    pub async fn mempool_clear(&mut self) {
        let events = self.mempool.clear();
        self.wallet_state.handle_mempool_events(events).await
    }

    /// adds Tx to mempool and notifies wallet of change. value represents
    /// the value that the transaction has to caller.
    pub async fn mempool_insert(&mut self, transaction: Transaction, priority: UpgradePriority) {
        let events = self.mempool.insert(transaction, priority);
        self.wallet_state.handle_mempool_events(events).await
    }

    /// prunes stale tx in mempool and notifies wallet of changes.
    pub async fn mempool_prune_stale_transactions(&mut self) {
        let events = self.mempool.prune_stale_transactions();
        self.wallet_state.handle_mempool_events(events).await
    }

    /// Update the primitive witness of a mempool transaction. Inserts the
    /// transaction into the mempool if it's not already there.
    pub(crate) async fn mempool_update_primitive_witness(
        &mut self,
        transaction_id: TransactionKernelId,
        new_primitive_witness: PrimitiveWitness,
    ) {
        let events = self
            .mempool
            .update_primitive_witness(transaction_id, new_primitive_witness);
        self.wallet_state.handle_mempool_events(events).await
    }

    pub(crate) async fn upgrade_proof_collection_job(
        &mut self,
        kernel: TransactionKernel,
        proof: ProofCollection,
        upgrade_incentive: UpgradeIncentive,
    ) -> Result<ProofCollectionToSingleProof> {
        let msa_lookup_result = self
            .chain
            .archival_state_mut()
            .old_mutator_set_and_mutator_set_update_to_tip(
                kernel.mutator_set_hash,
                SEARCH_DEPTH_FOR_BLOCKS_FOR_MS_UPDATE,
            )
            .await;

        let Some((transaction_msa, _)) = msa_lookup_result else {
            bail!("Could not find mutator set update for update job");
        };

        Ok(ProofCollectionToSingleProof::new(
            kernel,
            proof,
            transaction_msa,
            upgrade_incentive,
        ))
    }

    /// Return the update job for the single proof-backed transaction that is
    /// required to get the transaction back into a synced state.
    ///
    /// Does not perform any proof upgrading, only returns the witness data
    /// required to construct a synced single proof.
    pub(crate) async fn update_single_proof_job(
        &mut self,
        old_kernel: TransactionKernel,
        old_proof: NeptuneProof,
        upgrade_incentive: UpgradeIncentive,
    ) -> Result<UpdateMutatorSetDataJob> {
        let msa_lookup_result = self
            .chain
            .archival_state_mut()
            .old_mutator_set_and_mutator_set_update_to_tip(
                old_kernel.mutator_set_hash,
                SEARCH_DEPTH_FOR_BLOCKS_FOR_MS_UPDATE,
            )
            .await;

        let Some((old_msa, mutator_set_update)) = msa_lookup_result else {
            bail!("Could not find mutator set update for update job");
        };

        ensure!(!mutator_set_update.is_empty(), "No update needed");

        let consensus_rule_set = self.consensus_rule_set();
        Ok(UpdateMutatorSetDataJob::new(
            old_kernel,
            old_proof,
            old_msa,
            mutator_set_update,
            upgrade_incentive,
            consensus_rule_set,
        ))
    }

    /// Read all blocks contained in the specified directory and store these to
    /// the archival state.
    ///
    /// Will ignore blocks that are already known to this node but logs a
    /// warning when such blocks are encountered. Will return an error if any
    /// processed block is either invalid or does not have sufficient PoW, iff
    /// block validation is specified.
    ///
    /// Can be used to bootstrap the node without having to download all blocks
    /// from a peer. Assumes the same file structure as is created in the
    /// directory of blocks under normal operations of the node software, i.e.
    /// where blocks are mined locally or received from peers.
    ///
    /// Returns the number of blocks read from the directory.
    pub async fn import_blocks_from_directory(
        &mut self,
        directory: &Path,
        flush_period: usize,
        validate_blocks: bool,
    ) -> Result<usize> {
        debug!(
            "Reading all blocks from directory '{}'",
            directory.to_string_lossy()
        );
        let block_file_paths = ArchivalState::read_block_file_names_from_directory(directory)?;
        let mut num_stored_blocks = 0;
        let mut predecessor = self.chain.light_state().clone();
        for block_file_path in block_file_paths {
            let blocks = ArchivalState::blocks_from_file_without_record(&block_file_path).await?;

            // Blocks are assumed to be stored in-order in the file.
            for block in blocks {
                let block_height = block.header().height;

                let block_is_new = self
                    .chain
                    .archival_state()
                    .get_block_header(block.hash())
                    .await
                    .is_none();
                if !block_is_new {
                    warn!(
                        "Attempted to process a block from {} \
                        which was already known. Block height: {block_height}.",
                        block_file_path.to_string_lossy()
                    );
                    continue;
                }

                if validate_blocks {
                    let prev_block_digest = block.header().prev_block_digest;

                    // Ensure we have the right predecessor, in case block data
                    // contains reorganizations.
                    let predecessor = if prev_block_digest == predecessor.hash() {
                        predecessor
                    } else {
                        match self
                            .chain
                            .archival_state()
                            .get_block(prev_block_digest)
                            .await?
                        {
                            Some(pred) => pred,
                            None => {
                                bail!("Failed to find parent of block of height {block_height}");
                            }
                        }
                    };

                    ensure!(
                        block
                            .is_valid(&predecessor, Timestamp::now(), self.cli.network)
                            .await,
                        "Attempted to process a block from {} \
                        which is invalid. Block height: {block_height}.",
                        block_file_path.to_string_lossy()
                    );
                    ensure!(
                        block.has_proof_of_work(self.cli.network, predecessor.header()),
                        "Attempted to process a block from {} \
                        which does not have required PoW amount. \
                        Block height: {block_height}.",
                        block_file_path.to_string_lossy()
                    );
                }

                self.set_new_tip_internal(block.clone()).await.unwrap();
                info!("Updated state with block of height {block_height}.");
                num_stored_blocks += 1;
                predecessor = block;

                if flush_period != 0 && num_stored_blocks % flush_period == 0 {
                    self.flush_databases().await?;
                    info!("Flushed databases after {num_stored_blocks} blocks.");
                }
            }
        }

        self.flush_databases().await?;

        Ok(num_stored_blocks)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use itertools::Itertools;
    use macro_rules_attr::apply;
    use num_traits::CheckedSub;
    use num_traits::Zero;
    use rand::random;
    use rand::rngs::StdRng;
    use rand::seq::SliceRandom;
    use rand::Rng;
    use rand::SeedableRng;
    use tracing_test::traced_test;
    use wallet::address::generation_address::GenerationSpendingKey;
    use wallet::address::KeyType;
    use wallet::expected_utxo::UtxoNotifier;
    use wallet::wallet_entropy::WalletEntropy;

    use super::*;
    use crate::api::export::ChangePolicy;
    use crate::api::export::InputSelectionPolicy;
    use crate::api::export::OutputFormat;
    use crate::api::export::ReceivingAddress;
    use crate::api::export::TxOutputList;
    use crate::application::config::network::Network;
    use crate::application::loops::mine_loop::tests::make_coinbase_transaction_from_state;
    use crate::application::triton_vm_job_queue::TritonVmJobPriority;
    use crate::application::triton_vm_job_queue::TritonVmJobQueue;
    use crate::protocol::consensus::block::block_transaction::BlockTransaction;
    use crate::protocol::consensus::block::Block;
    use crate::protocol::consensus::transaction::lock_script::LockScript;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::protocol::consensus::transaction::utxo::Utxo;
    use crate::state::transaction::tx_creation_config::TxCreationConfig;
    use crate::state::wallet::address::generation_address::GenerationReceivingAddress;
    use crate::state::wallet::transaction_output::TxOutput;
    use crate::state::wallet::utxo_notification::UtxoNotificationMedium;
    use crate::state::wallet::wallet_status::WalletStatusExportFormat;
    use crate::tests::shared::blocks::fake_valid_successor_for_tests;
    use crate::tests::shared::blocks::invalid_block_with_transaction;
    use crate::tests::shared::blocks::invalid_empty_block;
    use crate::tests::shared::blocks::invalid_empty_block_with_timestamp;
    use crate::tests::shared::blocks::make_mock_block;
    use crate::tests::shared::blocks::make_mock_block_with_inputs_and_outputs;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared::globalstate::state_with_premine_and_self_mined_blocks;
    use crate::tests::shared::wallet_state_has_all_valid_mps;
    use crate::tests::shared_tokio_runtime;
    use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
    use crate::util_types::mutator_set::removal_record::RemovalRecord;

    impl GlobalStateLock {
        async fn force_wallet_membership_proof_maintance(&mut self) {
            self.lock_mut(|x| x.force_wallet_membership_proof_maintance = true)
                .await;
        }
    }

    mod helper {

        use futures::future;

        use super::*;
        use crate::api::export::TransactionProof;
        use crate::api::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
        use crate::protocol::consensus::transaction::utxo_triple::UtxoTriple;

        /// Create 3 branches and return them in an array.
        ///
        /// First two branches share common ancestor `first_for_0_1`, last
        /// branch starts from `first_for_2`. All branches have the same length.
        /// All branches are populated with non-trivial inputs and outputs.
        pub(crate) async fn make_3_branches(
            network: Network,
            first_for_0_1: &Block,
            first_for_2: &Block,
            num_blocks_per_branch: usize,
            coinbase_recipient: &GenerationSpendingKey,
        ) -> [Vec<Block>; 3] {
            make_branches(
                network,
                [first_for_0_1, first_for_0_1, first_for_2],
                [num_blocks_per_branch; 3],
                coinbase_recipient,
            )
            .await
        }

        pub(crate) async fn make_one_branch(
            network: Network,
            first_block: &Block,
            branch_length: usize,
            coinbase_recipient: &GenerationSpendingKey,
            seed: [u8; 32],
        ) -> Vec<Block> {
            let mut rng = StdRng::from_seed(seed);
            let mut branch = Vec::with_capacity(branch_length);

            let mut block: Block = first_block.clone();
            let mut spendable_utxos: Vec<(Utxo, MsMembershipProof, AdditionRecord)> = vec![];
            for _ in 0..branch_length {
                let mut mutator_set_accumulator = block.mutator_set_accumulator_after().unwrap();

                // produce removal records
                let num_removal_records = rng.random_range(0..=spendable_utxos.len());
                let mut inputs = vec![];
                for _ in 0..num_removal_records {
                    let index = rng.random_range(0..spendable_utxos.len());
                    let (utxo, ms_membership_proof, _addition_record) =
                        spendable_utxos.swap_remove(index);
                    let item = Tip5::hash(&utxo);
                    assert!(mutator_set_accumulator.verify(item, &ms_membership_proof));

                    let removal_record = mutator_set_accumulator.drop(item, &ms_membership_proof);

                    assert!(mutator_set_accumulator.can_remove(&removal_record));
                    inputs.push(removal_record);
                }

                // produce addition records
                let mut outputs = vec![];
                let mut new_spendable_utxos = vec![];
                let num_outputs = rng.random_range(0..10);
                for _ in 0..num_outputs {
                    let utxo = Utxo::new_native_currency(
                        LockScript::anyone_can_spend().hash(),
                        NativeCurrencyAmount::coins(rng.random_range(0..100)),
                    );
                    let sender_randomness: Digest = rng.random();
                    let receiver_preimage: Digest = rng.random();

                    let utxo_triple = UtxoTriple {
                        utxo: utxo.clone(),
                        sender_randomness,
                        receiver_digest: receiver_preimage.hash(),
                    };
                    let addition_record = utxo_triple.addition_record();
                    outputs.push(addition_record);

                    new_spendable_utxos.push((utxo, sender_randomness, receiver_preimage));
                }

                // produce block
                let (next_block, _) = make_mock_block_with_inputs_and_outputs(
                    &block,
                    inputs.clone(),
                    outputs.clone(),
                    None,
                    coinbase_recipient.to_owned(),
                    rng.random(),
                    network,
                )
                .await;
                branch.push(next_block.clone());
                let mut test_msa = block.mutator_set_accumulator_after().unwrap();
                block = next_block;

                // update membership proofs
                let mutator_set_update = block.mutator_set_update().unwrap();
                let MutatorSetUpdate {
                    additions,
                    mut removals,
                } = mutator_set_update;

                assert_eq!(mutator_set_accumulator, test_msa);

                // ... with addition records
                for addition_record in additions {
                    for (utxo, ms_membership_proof, _addition_record) in &mut spendable_utxos {
                        ms_membership_proof
                            .update_from_addition(
                                Tip5::hash(utxo),
                                &mutator_set_accumulator,
                                &addition_record,
                            )
                            .unwrap();
                    }

                    // if the addition record is our own, collect a membership proof for it
                    if let Some((utxo, sender_randomness, receiver_preimage)) = new_spendable_utxos
                        .iter()
                        .find(|(utxo, sender_randomness, receiver_preimage)| {
                            let utxo_triple = UtxoTriple {
                                utxo: utxo.clone(),
                                sender_randomness: *sender_randomness,
                                receiver_digest: receiver_preimage.hash(),
                            };
                            utxo_triple.addition_record() == addition_record
                        })
                    {
                        let ms_membership_proof = mutator_set_accumulator.prove(
                            Tip5::hash(utxo),
                            *sender_randomness,
                            *receiver_preimage,
                        );

                        let mut new_test_msa = mutator_set_accumulator.clone();
                        new_test_msa.add(&addition_record);
                        assert!(new_test_msa.verify(Tip5::hash(utxo), &ms_membership_proof));

                        spendable_utxos.push((utxo.clone(), ms_membership_proof, addition_record));
                    }

                    RemovalRecord::batch_update_from_addition(
                        &mut removals.iter_mut().collect_vec(),
                        &mutator_set_accumulator,
                    );

                    mutator_set_accumulator.add(&addition_record);
                }

                // ... and with removal records
                removals.reverse();
                while let Some(removal_record) = removals.pop() {
                    for (_utxo, ms_membership_proof, _addition_record) in &mut spendable_utxos {
                        ms_membership_proof.update_from_remove(&removal_record);
                    }

                    RemovalRecord::batch_update_from_remove(
                        &mut removals.iter_mut().collect_vec(),
                        &removal_record,
                    );

                    mutator_set_accumulator.remove(&removal_record);
                }

                block
                    .mutator_set_update()
                    .unwrap()
                    .apply_to_accumulator(&mut test_msa)
                    .unwrap();
                assert_eq!(mutator_set_accumulator, test_msa);
            }
            branch
        }

        /// Create an arbitrary number of branches with given starting blocks.
        ///
        /// This function produces the branches in parallel, using tokio.
        pub(crate) async fn make_branches<const N: usize>(
            network: Network,
            first_blocks: [&Block; N],
            branch_lengths: [usize; N],
            coinbase_recipient: &GenerationSpendingKey,
        ) -> [Vec<Block>; N] {
            let mut rng = rand::rng();
            let all_branches = Arc::new(tokio::sync::Mutex::new([const { None }; N]));
            let mut handles = vec![];

            // for every branch, spawn a new task to produce it
            for (i, (first_block, branch_length)) in first_blocks
                .into_iter()
                .zip(branch_lengths.into_iter())
                .enumerate()
            {
                let seed: [u8; 32] = rng.random();
                let first_block = first_block.clone();
                let coinbase_recipient = *coinbase_recipient;
                let all_branches = all_branches.clone();
                handles.push(tokio::spawn(async move {
                    let branch = make_one_branch(
                        network,
                        &first_block,
                        branch_length,
                        &coinbase_recipient,
                        seed,
                    )
                    .await;

                    all_branches.lock().await[i] = Some(branch);
                }));
            }

            // do not continue unless all tasks spawned above are finished
            let _results = future::join_all(handles).await;

            let all_branches = all_branches.lock().await.clone();
            all_branches.map(std::option::Option::unwrap)
        }

        /// Send coins to somewhere.
        ///
        /// Make the transaction. Update state accordingly. Return the
        /// transaction.
        pub(crate) async fn send_coins(
            sender: &mut GlobalStateLock,
            amount: NativeCurrencyAmount,
            destination: GenerationReceivingAddress,
            timestamp: Timestamp,
        ) -> Transaction {
            let inputs = sender
                .api()
                .tx_initiator()
                .select_spendable_inputs(InputSelectionPolicy::ByProvidedOrder, amount, timestamp)
                .await
                .into_iter()
                .collect_vec();
            let outputs = sender
                .api()
                .tx_initiator()
                .generate_tx_outputs(vec![OutputFormat::AddressAndAmount(
                    destination.into(),
                    amount,
                )])
                .await;
            let transaction_details = TransactionDetailsBuilder::default()
                .inputs(inputs.into())
                .outputs(outputs)
                .change_policy(ChangePolicy::RecoverToNextUnusedKey {
                    key_type: KeyType::Symmetric,
                    medium: UtxoNotificationMedium::OnChain,
                })
                .timestamp(timestamp)
                .build(&mut StateLock::Lock(Box::new(sender.clone())))
                .await
                .unwrap();

            let primitive_witness_proof = sender
                .api()
                .tx_initiator()
                .generate_witness_proof(transaction_details.into());
            let primitive_witness = primitive_witness_proof.into_primitive_witness();

            println!(
                "primitive witness has public announcements? (global state) {}",
                !primitive_witness.kernel.announcements.is_empty()
            );
            let kernel = primitive_witness.kernel;

            Transaction {
                kernel,
                proof: TransactionProof::invalid(),
            }
        }
    }

    mod handshake {

        use super::*;

        #[apply(shared_tokio_runtime)]
        async fn generating_own_handshake_doesnt_crash() {
            mock_genesis_global_state(
                2,
                WalletEntropy::devnet_wallet(),
                cli_args::Args::default_with_network(Network::Main),
            )
            .await
            .lock_guard()
            .await
            .get_own_handshakedata();
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn handshakes_listen_port_is_some_when_max_peers_is_default() {
            let network = Network::Main;
            let bob = mock_genesis_global_state(
                2,
                WalletEntropy::devnet_wallet(),
                cli_args::Args::default_with_network(network),
            )
            .await;

            let handshake_data = bob
                .global_state_lock
                .lock_guard()
                .await
                .get_own_handshakedata();
            assert!(handshake_data.listen_port.is_some());
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn handshakes_listen_port_is_none_when_max_peers_is_zero() {
            let network = Network::Main;
            let mut bob = mock_genesis_global_state(
                2,
                WalletEntropy::devnet_wallet(),
                cli_args::Args::default_with_network(network),
            )
            .await;
            let no_incoming_connections = cli_args::Args {
                max_num_peers: 0,
                ..Default::default()
            };
            bob.set_cli(no_incoming_connections).await;

            let handshake_data = bob
                .global_state_lock
                .lock_guard()
                .await
                .get_own_handshakedata();
            assert!(handshake_data.listen_port.is_none());
        }
    }

    mod set_tip {
        use super::*;

        #[apply(shared_tokio_runtime)]
        async fn set_new_tip_clears_block_proposal_related_data() {
            let network = Network::Main;
            let mut bob = mock_genesis_global_state(
                2,
                WalletEntropy::devnet_wallet(),
                cli_args::Args::default_with_network(network),
            )
            .await;
            let mut bob = bob.global_state_lock.lock_guard_mut().await;
            let block1 = invalid_empty_block(&Block::genesis(network), network);

            bob.mining_state.block_proposal = BlockProposal::ForeignComposition(block1.clone());
            bob.mining_state
                .exported_block_proposals
                .insert(random(), block1.clone());

            bob.set_new_tip(block1).await.unwrap();
            assert!(
                bob.mining_state.block_proposal.is_none(),
                "block proposal must be reset after setting new tip."
            );
            assert!(
                bob.mining_state.exported_block_proposals.is_empty(),
                "Set of exported block proposals must be empty after registering new block"
            );
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn can_use_set_new_tip_to_reset_to_genesis() {
        let network = Network::Main;
        let mut alice = mock_genesis_global_state(
            2,
            WalletEntropy::devnet_wallet(),
            cli_args::Args::default_with_network(network),
        )
        .await;
        let mut alice = alice.lock_guard_mut().await;
        assert!(alice.chain.light_state().header().height.is_genesis());

        let genesis = Block::genesis(network);
        let block1 = invalid_empty_block(&genesis, network);

        alice.set_new_tip(block1.clone()).await.unwrap();
        assert!(!alice.chain.light_state().header().height.is_genesis());
        assert!(alice
            .chain
            .archival_state()
            .get_tip_parent()
            .await
            .is_some());

        alice.set_new_tip(genesis.clone()).await.unwrap();
        assert!(alice
            .chain
            .archival_state()
            .get_tip_parent()
            .await
            .is_none());
        assert!(alice.chain.light_state().header().height.is_genesis());

        alice.set_new_tip(block1.clone()).await.unwrap();
        assert!(alice
            .chain
            .light_state()
            .header()
            .height
            .previous()
            .unwrap()
            .is_genesis());
        assert!(alice
            .chain
            .archival_state()
            .get_tip_parent()
            .await
            .is_some());
    }

    #[apply(shared_tokio_runtime)]
    async fn dont_register_premine_amount_twice() {
        let network = Network::Main;
        let mut alice = mock_genesis_global_state(
            2,
            WalletEntropy::devnet_wallet(),
            cli_args::Args::default_with_network(network),
        )
        .await;
        let mut alice_gsl = alice.lock_guard_mut().await;

        assert_eq!(
            1,
            alice_gsl.get_wallet_status_for_tip().await.num_elements()
        );

        let genesis = Block::genesis(network);
        alice_gsl
            .set_tip_to_stored_block(genesis.hash())
            .await
            .unwrap();
        assert_eq!(
            1,
            alice_gsl.get_wallet_status_for_tip().await.num_elements()
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn test_set_tip_to_stored_block() {
        let network = Network::Main;
        let mut rng = StdRng::seed_from_u64(43579293874);
        let mut alice = mock_genesis_global_state(
            2,
            WalletEntropy::devnet_wallet(),
            cli_args::Args::default_with_network(network),
        )
        .await;

        let mut alice_gsl = alice.lock_guard_mut().await;
        let alice_key = alice_gsl
            .wallet_state
            .wallet_entropy
            .nth_generation_spending_key(0);
        let bob_secret = WalletEntropy::new_random();
        let bob_key = bob_secret.nth_generation_spending_key(0);

        // alice mines 3 blocks
        let genesis = Block::genesis(network);
        let mut current_block = genesis.clone();
        for _ in 0..3 {
            let (block, alice_composer_expected_utxos) =
                make_mock_block(&current_block, None, alice_key, rng.random(), network).await;
            alice_gsl
                .wallet_state
                .add_expected_utxos(alice_composer_expected_utxos)
                .await;
            alice_gsl.set_new_tip(block.clone()).await.unwrap();
            current_block = block;
        }
        const LIQUID_BLOCK_SUBSIDY: NativeCurrencyAmount = NativeCurrencyAmount::coins(64);
        let wallet_status_1 = alice_gsl.get_wallet_status_for_tip().await;
        let timestamp_1 = current_block.header().timestamp;
        assert_eq!(
            wallet_status_1.available_confirmed(timestamp_1),
            LIQUID_BLOCK_SUBSIDY.scalar_mul(3)
        );

        // prepare two branches with 3*|a| = |b|
        let branch_length = 60;
        let [mut a_blocks, mut b_blocks] = helper::make_branches(
            network,
            [&current_block, &current_block],
            [branch_length / 3, branch_length],
            &bob_key,
        )
        .await;

        // apply branch a
        for block in &a_blocks {
            alice_gsl.set_new_tip(block.clone()).await.unwrap();
        }
        current_block = a_blocks.last().unwrap().clone();
        let wallet_status_2 = alice_gsl.get_wallet_status_for_tip().await;
        let timestamp_2 = current_block.header().timestamp;
        let alice_balance_2 = wallet_status_2.available_confirmed(timestamp_2);
        let expected_balance_2 = LIQUID_BLOCK_SUBSIDY.scalar_mul(3);
        assert_eq!(
            expected_balance_2, alice_balance_2,
            "wallet balance: {alice_balance_2}\nexpected: {expected_balance_2}",
        );

        // initiate transaction to rando
        let rando = GenerationReceivingAddress::derive_from_seed(rng.random());
        drop(alice_gsl); // drop lock to free up api
        let tx_a = helper::send_coins(
            &mut alice,
            NativeCurrencyAmount::coins(10),
            rando,
            timestamp_2,
        )
        .await;
        alice_gsl = alice.lock_guard_mut().await; //re-acquire lock
        let block_middle_of_a = invalid_block_with_transaction(&current_block, tx_a);
        a_blocks.push(block_middle_of_a.clone());
        current_block = block_middle_of_a;
        alice_gsl.set_new_tip(current_block.clone()).await.unwrap();

        let wallet_status_3 = alice_gsl.get_wallet_status_for_tip().await;
        let timestamp_3 = current_block.header().timestamp;
        let wallet_balance_3 = wallet_status_3.available_confirmed(timestamp_3);
        let expected_branch_a_liquid_balance = (LIQUID_BLOCK_SUBSIDY.scalar_mul(3))
            .checked_sub(&NativeCurrencyAmount::coins(10))
            .unwrap();
        assert_eq!(
            expected_branch_a_liquid_balance, wallet_balance_3,
            "wallet balance: {wallet_balance_3}\nexpected balance: {expected_branch_a_liquid_balance}"
        );

        // continue for a while
        let more_a_blocks = helper::make_one_branch(
            network,
            &current_block,
            2 * branch_length / 3,
            &bob_key,
            rng.random(),
        )
        .await;
        for block in more_a_blocks {
            alice_gsl.set_new_tip(block.clone()).await.unwrap();
            a_blocks.push(block);
        }
        current_block = a_blocks.last().unwrap().clone();

        let wallet_status_4 = alice_gsl.get_wallet_status_for_tip().await;
        let timestamp_4 = current_block.header().timestamp;
        assert_eq!(
            expected_branch_a_liquid_balance,
            wallet_status_4.available_confirmed(timestamp_4)
        );

        // resolve fork: apply all of branch b
        for block in &b_blocks {
            alice_gsl.set_new_tip(block.clone()).await.unwrap();
        }
        current_block = b_blocks.last().unwrap().clone();

        let _ = alice_gsl.resync_membership_proofs().await;

        let wallet_status_5 = alice_gsl.get_wallet_status_for_tip().await;
        println!(
            "wallet_status_5: {}",
            WalletStatusExportFormat::Table.export(&wallet_status_5)
        );
        let timestamp_5 = current_block.header().timestamp;
        let wallet_balance_5 = wallet_status_5.available_confirmed(timestamp_5);
        assert_eq!(
            wallet_balance_5,
            LIQUID_BLOCK_SUBSIDY.scalar_mul(3),
            "wallet balance: {wallet_balance_5}"
        );

        // make transaction
        drop(alice_gsl); // drop lock to free up api
        let tx_b = helper::send_coins(
            &mut alice,
            NativeCurrencyAmount::coins(5),
            rando,
            timestamp_5,
        )
        .await;
        alice_gsl = alice.lock_guard_mut().await; //re-acquire lock
        let block_end_of_b = invalid_block_with_transaction(&current_block, tx_b);
        b_blocks.push(block_end_of_b.clone());
        current_block = block_end_of_b;
        alice_gsl.set_new_tip(current_block.clone()).await.unwrap();

        let wallet_status_6 = alice_gsl.get_wallet_status_for_tip().await;
        let timestamp_6 = current_block.header().timestamp;
        assert_eq!(
            wallet_status_6.available_confirmed(timestamp_6),
            (LIQUID_BLOCK_SUBSIDY.scalar_mul(3))
                .checked_sub(&NativeCurrencyAmount::coins(5))
                .unwrap()
        );

        // set tip to half-way in branch a and verify balance
        let target_block = a_blocks[branch_length / 2].clone();
        alice_gsl
            .set_tip_to_stored_block(target_block.hash())
            .await
            .unwrap();

        assert_eq!(alice_gsl.chain.light_state().hash(), target_block.hash());

        let wallet_status_7 = alice_gsl.get_wallet_status_for_tip().await;
        let timestamp_7 = current_block.header().timestamp;
        assert_eq!(
            expected_branch_a_liquid_balance,
            wallet_status_7.available_confirmed(timestamp_7),
        );

        // Can set tip to genesis
        let premine_amount = NativeCurrencyAmount::coins(20);
        alice_gsl
            .set_tip_to_stored_block(genesis.hash())
            .await
            .unwrap();
        let wallet_status_8 = alice_gsl.get_wallet_status_for_tip().await;
        let timestamp_8 = genesis.header().timestamp;
        assert!(wallet_status_8.available_confirmed(timestamp_8).is_zero(),);
        assert_eq!(premine_amount, wallet_status_8.total_confirmed());
        assert_eq!(alice_gsl.chain.light_state().hash(), genesis.hash());

        // State updates work when tip is genesis
        let block_c_timestamp = genesis.header().timestamp + Timestamp::seconds(556);
        let block_c = invalid_empty_block_with_timestamp(&genesis, block_c_timestamp, network);
        alice_gsl.set_new_tip(block_c.clone()).await.unwrap();
        assert_eq!(alice_gsl.chain.light_state().hash(), block_c.hash());

        // Can set back and restore balance, with backwards walk (from c to a)
        alice_gsl
            .set_tip_to_stored_block(target_block.hash())
            .await
            .unwrap();
        let wallet_status_9 = alice_gsl.get_wallet_status_for_tip().await;
        let timestamp_9 = current_block.header().timestamp;
        assert_eq!(
            expected_branch_a_liquid_balance,
            wallet_status_9.available_confirmed(timestamp_9)
        );

        let expected_branch_a_total_balance = (LIQUID_BLOCK_SUBSIDY.scalar_mul(6))
            .checked_sub(&NativeCurrencyAmount::coins(10))
            .unwrap()
            + premine_amount;
        assert_eq!(
            expected_branch_a_total_balance,
            wallet_status_9.total_confirmed()
        );

        // Set tip to genesis again, then to target some place on the a-chain.
        alice_gsl
            .set_tip_to_stored_block(genesis.hash())
            .await
            .unwrap();

        a_blocks.shuffle(&mut rng);
        for block in a_blocks {
            alice_gsl
                .set_tip_to_stored_block(block.hash())
                .await
                .unwrap();
            assert_eq!(
                expected_branch_a_total_balance,
                wallet_status_9.total_confirmed()
            );
            assert_eq!(
                expected_branch_a_liquid_balance,
                wallet_status_9.available_confirmed(timestamp_9)
            );
        }
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn premine_recipient_cannot_spend_premine_before_and_can_after_release_date() {
        let network = Network::Main;
        let mut rng = StdRng::seed_from_u64(u64::from_str_radix("3014221", 6).unwrap());

        let alice = WalletEntropy::new_pseudorandom(rng.random());
        let bob = mock_genesis_global_state(
            2,
            WalletEntropy::devnet_wallet(),
            cli_args::Args::default_with_network(network),
        )
        .await;

        let bob_spending_key = bob
            .lock_guard()
            .await
            .wallet_state
            .wallet_entropy
            .nth_generation_spending_key_for_tests(0);

        let alice_address = alice.nth_generation_spending_key_for_tests(0).to_address();
        let nine_money_output = TxOutput::offchain_native_currency(
            NativeCurrencyAmount::coins(9),
            rng.random(),
            alice_address.into(),
            false,
        );
        let tx_outputs: TxOutputList = vec![nine_money_output].into();

        // two days before release date, we should not be able to create the transaction.
        // August 11, 2025, noon UTC.
        let premine_release_data = Timestamp(bfe!(1754913600000u64));
        let two_days = Timestamp::days(2);
        let config = TxCreationConfig::default()
            .recover_change_off_chain(bob_spending_key.into())
            .with_prover_capability(TxProvingCapability::ProofCollection);
        let block_height = BlockHeight::genesis();
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);
        assert!(bob
            .api()
            .tx_initiator_internal()
            .create_transaction(
                tx_outputs.clone(),
                NativeCurrencyAmount::coins(1),
                premine_release_data - two_days,
                config.clone(),
                consensus_rule_set,
            )
            .await
            .is_err());

        // two days though, we should be
        let tx = bob
            .api()
            .tx_initiator_internal()
            .create_transaction(
                tx_outputs,
                NativeCurrencyAmount::coins(1),
                premine_release_data + two_days,
                config.clone(),
                consensus_rule_set,
            )
            .await
            .unwrap()
            .transaction;
        assert!(tx.is_valid(network, consensus_rule_set).await);

        assert_eq!(
            2,
            tx.kernel.outputs.len(),
            "tx must have a send output and a change output"
        );
        assert_eq!(
            1,
            tx.kernel.inputs.len(),
            "tx must have exactly one input, a genesis UTXO"
        );

        // Test with a transaction with three outputs and one (premine) input
        let mut output_utxos = vec![];
        for i in 2..5 {
            let that_much_money: NativeCurrencyAmount = NativeCurrencyAmount::coins(i);
            let output_utxo = TxOutput::offchain_native_currency(
                that_much_money,
                rng.random(),
                alice_address.into(),
                false,
            );
            output_utxos.push(output_utxo);
        }

        let new_tx = bob
            .api()
            .tx_initiator_internal()
            .create_transaction(
                output_utxos.into(),
                NativeCurrencyAmount::coins(1),
                premine_release_data + two_days,
                config,
                consensus_rule_set,
            )
            .await
            .unwrap()
            .transaction;
        assert!(new_tx.is_valid(network, consensus_rule_set).await);
        assert_eq!(
            4,
            new_tx.kernel.outputs.len(),
            "tx must have three send outputs and a change output"
        );
        assert_eq!(
            1,
            new_tx.kernel.inputs.len(),
            "tx must have exactly one input, a genesis UTXO"
        );
    }

    mod restore_monitored_utxo_data {

        use super::*;

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn restore_monitored_utxos_from_recovery_data_duplicated_entries() {
            // Verify that duplicated entries in `incoming_randomness.dat` are
            // handled correctly.
            let network = Network::Main;
            let cli_args = cli_args::Args::default_with_network(network);
            let mut state =
                state_with_premine_and_self_mined_blocks(cli_args, [rand::rng().random()]).await;
            let mut state = state.lock_guard_mut().await;
            let orignal_mutxos = state
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .get_all()
                .await;
            assert_eq!(
                5,
                orignal_mutxos.len(),
                "Expected one premine, four mining rewards"
            );

            // Clear databases, to verify recovery works.
            state
                .wallet_state
                .wallet_db
                .monitored_utxos_mut()
                .clear()
                .await;
            state
                .wallet_state
                .wallet_db
                .expected_utxos_mut()
                .clear()
                .await;

            let recovery_data = state
                .wallet_state
                .read_utxo_ms_recovery_data()
                .await
                .unwrap();
            assert_eq!(
                5,
                recovery_data.len(),
                "Expected five entries in recovery data"
            );

            // Add duplicated entries to recovery data
            for recovery_element in recovery_data {
                state
                    .wallet_state
                    .store_utxo_ms_recovery_data(recovery_element)
                    .await
                    .unwrap();
            }
            assert_eq!(
                10,
                state
                    .wallet_state
                    .read_utxo_ms_recovery_data()
                    .await
                    .unwrap()
                    .len(),
                "Expected ten entries in recovery data"
            );
            assert!(
                state
                    .wallet_state
                    .wallet_db
                    .monitored_utxos()
                    .is_empty()
                    .await,
                "List of monitored UTXOs must be empty before attempting recovery"
            );

            // Perform this recovery, with duplicated entries. And verify that
            // the original list of monitored UTXOs is recovered.
            state
                .restore_monitored_utxos_from_recovery_data()
                .await
                .unwrap();
            let recovered_mutxos = state
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .get_all()
                .await;
            for (original, recovered) in orignal_mutxos.into_iter().zip_eq(recovered_mutxos) {
                assert_eq!(original.utxo, recovered.utxo);
                assert_eq!(
                    original.get_latest_membership_proof_entry().unwrap(),
                    recovered.get_latest_membership_proof_entry().unwrap()
                );
            }
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn restore_monitored_utxos_from_recovery_data_test() {
            let network = Network::Main;
            let cli_args = cli_args::Args::default_with_network(network);
            let mut global_state_lock =
                state_with_premine_and_self_mined_blocks(cli_args, [rand::rng().random()]).await;

            // Delete everything from monitored UTXO and from raw-hash keys.
            let mut global_state = global_state_lock.lock_guard_mut().await;
            {
                let monitored_utxos = global_state.wallet_state.wallet_db.monitored_utxos_mut();
                assert_eq!(
                    5,
                    monitored_utxos.len().await,
                    "MUTXO must have genesis element, composer rewards, and guesser rewards"
                );
                monitored_utxos.pop().await;
                monitored_utxos.pop().await;
                monitored_utxos.pop().await;
                monitored_utxos.pop().await;
                monitored_utxos.pop().await;

                global_state
                    .wallet_state
                    .wallet_db
                    .expected_utxos_mut()
                    .clear()
                    .await;

                assert!(
                    global_state
                        .wallet_state
                        .wallet_db
                        .monitored_utxos()
                        .is_empty()
                        .await
                );
                assert!(
                    global_state
                        .wallet_state
                        .wallet_db
                        .expected_utxos()
                        .is_empty()
                        .await
                );
            }

            // Recover the MUTXO from the recovery data, and verify that MUTXOs are restored
            // Also verify that this operation is idempotent by running it multiple times.
            let genesis_block = Block::genesis(network);
            let block1 = global_state.chain.archival_state().get_tip().await;
            for _ in 0..3 {
                global_state
                    .restore_monitored_utxos_from_recovery_data()
                    .await
                    .unwrap();
                let monitored_utxos = global_state.wallet_state.wallet_db.monitored_utxos();
                assert_eq!(
                    5,
                    monitored_utxos.len().await,
                    "MUTXO must have genesis elements and premine after recovery"
                );

                let mutxos = monitored_utxos.get_all().await;
                assert_eq!(
                    Some((
                        genesis_block.hash(),
                        genesis_block.header().timestamp,
                        genesis_block.header().height
                    )),
                    mutxos[0].confirmed_in_block,
                    "Historical information must be restored for premine UTXO"
                );

                for (i, mutxo) in mutxos.iter().enumerate().skip(1).take((1..=4).count()) {
                    assert_eq!(
                    Some((
                        block1.hash(),
                        block1.header().timestamp,
                        block1.header().height
                    )),
                    mutxo.confirmed_in_block,
                    "Historical information must be restored for composer and guesser UTXOs, i={i}"
                );
                }

                // Verify that the restored MUTXOs have MSMPs, and that they're
                // valid.
                for mutxo in mutxos {
                    let ms_item = Tip5::hash(&mutxo.utxo);
                    assert!(global_state
                        .chain
                        .light_state()
                        .mutator_set_accumulator_after()
                        .unwrap()
                        .verify(
                            ms_item,
                            &mutxo.get_latest_membership_proof_entry().unwrap().1,
                        ));
                    assert_eq!(
                        block1.hash(),
                        mutxo.get_latest_membership_proof_entry().unwrap().0,
                        "MUTXO must have the correct latest block digest value"
                    );
                }
            }
        }

        #[derive(Debug, Clone)]
        enum RestoreMsMpMethod {
            Blocks,
            ArchivalMutatorSet,
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn resync_ms_membership_proofs_simple_test() {
            for restore_method in [
                RestoreMsMpMethod::Blocks,
                RestoreMsMpMethod::ArchivalMutatorSet,
            ] {
                let mut rng = rand::rng();
                let network = Network::RegTest;
                let mut alice_state_lock = mock_genesis_global_state(
                    2,
                    WalletEntropy::devnet_wallet(),
                    cli_args::Args::default_with_network(network),
                )
                .await;
                let mut alice = alice_state_lock.lock_guard_mut().await;

                // Verify that Alice has a monitored UTXO (from genesis)
                let genesis_block = Block::genesis(network);
                let seven_months = Timestamp::months(7);
                let launch = genesis_block.kernel.header.timestamp;
                assert!(!alice
                    .get_wallet_status_for_tip()
                    .await
                    .available_confirmed(launch + seven_months)
                    .is_zero());
                assert!(!alice.get_balance_history().await.is_empty());

                let bob_wallet_secret = WalletEntropy::new_random();
                let bob_key = bob_wallet_secret.nth_generation_spending_key(0);

                // 1. Create new block 1 and store it, but do not update wallet
                // with the new block.
                let (mock_block_1a, _) =
                    make_mock_block(&genesis_block, None, bob_key, rng.random(), network).await;
                {
                    alice
                        .chain
                        .archival_state_mut()
                        .write_block_as_tip(&mock_block_1a)
                        .await
                        .unwrap();
                    alice
                        .chain
                        .archival_state_mut()
                        .update_mutator_set(&mock_block_1a)
                        .await
                        .expect("Updating mutator set must succeed");
                    *alice.chain.light_state_mut() = std::sync::Arc::new(mock_block_1a.clone());
                }

                // Verify that wallet is unsynced with mock_block_1a
                assert!(alice.wallet_state.is_synced_to(genesis_block.hash()).await);
                assert!(!alice.wallet_state.is_synced_to(mock_block_1a.hash()).await);

                // Call resync
                match restore_method {
                    RestoreMsMpMethod::Blocks => alice
                        .resync_membership_proofs_from_stored_blocks(mock_block_1a.hash())
                        .await
                        .unwrap(),
                    RestoreMsMpMethod::ArchivalMutatorSet => {
                        alice
                            .restore_monitored_utxos_from_archival_mutator_set(None)
                            .await
                    }
                };

                // Verify that MPs are valid
                assert!(wallet_state_has_all_valid_mps(&alice.wallet_state, &mock_block_1a).await, "All monitored UTXOs must have valid MPs after restoration. restore_method: {restore_method:?}");

                // Verify that wallet is marked as synced
                assert!(
                    alice.wallet_state.is_synced_to(mock_block_1a.hash()).await,
                    "Wallet must be marked as synced after restoration."
                );
            }
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn resync_ms_membership_proofs_fork_test() {
            let network = Network::Main;
            let mut rng = rand::rng();

            for restore_method in [
                RestoreMsMpMethod::Blocks,
                RestoreMsMpMethod::ArchivalMutatorSet,
            ] {
                let mut alice = mock_genesis_global_state(
                    2,
                    WalletEntropy::devnet_wallet(),
                    cli_args::Args::default_with_network(network),
                )
                .await;
                let mut alice = alice.lock_guard_mut().await;
                let alice_key = alice
                    .wallet_state
                    .wallet_entropy
                    .nth_generation_spending_key(0);

                // 1. Create new block 1a where we receive a coinbase UTXO, store it
                let genesis_block = alice.chain.archival_state().get_tip().await;
                let (mock_block_1a, composer_expected_utxos_1a) =
                    make_mock_block(&genesis_block, None, alice_key, rng.random(), network).await;
                alice
                    .wallet_state
                    .add_expected_utxos(composer_expected_utxos_1a)
                    .await;
                alice.set_new_tip(mock_block_1a.clone()).await.unwrap();

                // Verify that wallet has monitored UTXOs, 1 from genesis, 2 from
                // block 1a.
                assert_eq!(
                    3,
                    alice
                        .wallet_state
                        .get_wallet_status(
                            mock_block_1a.hash(),
                            &mock_block_1a.mutator_set_accumulator_after().unwrap()
                        )
                        .await
                        .synced_unspent
                        .len()
                );
                assert_eq!(3, alice.get_balance_history().await.len());

                // Make a new fork from genesis that makes us lose the composer UTXOs
                // of block 1a.
                let bob_wallet_secret = WalletEntropy::new_random();
                let bob_key = bob_wallet_secret.nth_generation_spending_key(0);
                let mut parent_block = genesis_block;
                for _ in 0..5 {
                    let (next_block, _) =
                        make_mock_block(&parent_block, None, bob_key, rng.random(), network).await;
                    alice.set_new_tip(next_block.clone()).await.unwrap();
                    parent_block = next_block;
                }

                // Call resync which fails to sync the UTXO that was abandoned when block 1a was abandoned
                match restore_method {
                    RestoreMsMpMethod::Blocks => alice
                        .resync_membership_proofs_from_stored_blocks(parent_block.hash())
                        .await
                        .unwrap(),
                    RestoreMsMpMethod::ArchivalMutatorSet => {
                        alice
                            .restore_monitored_utxos_from_archival_mutator_set(None)
                            .await
                    }
                }

                // Verify that two MUTXOs are unsynced, and that 1 (from genesis) is synced
                let alice_wallet_status_after_reorg = alice
                    .wallet_state
                    .get_wallet_status(
                        parent_block.hash(),
                        &parent_block.mutator_set_accumulator_after().unwrap(),
                    )
                    .await;
                assert_eq!(1, alice_wallet_status_after_reorg.synced_unspent.len());
                assert_eq!(2, alice_wallet_status_after_reorg.unsynced.len());

                // Verify that the MUTXO from block 1a is considered abandoned, and that the one from
                // genesis block is not.
                let monitored_utxos = alice.wallet_state.wallet_db.monitored_utxos();
                assert!(
                    !monitored_utxos
                        .get(0)
                        .await
                        .was_abandoned(alice.chain.archival_state())
                        .await
                );
                assert!(
                    monitored_utxos
                        .get(1)
                        .await
                        .was_abandoned(alice.chain.archival_state())
                        .await
                );
            }
        }

        #[apply(shared_tokio_runtime)]
        async fn resync_ms_membership_proofs_across_stale_fork() {
            let network = Network::Main;
            let mut rng = rand::rng();

            for restore_method in [
                RestoreMsMpMethod::Blocks,
                RestoreMsMpMethod::ArchivalMutatorSet,
            ] {
                let mut alice = mock_genesis_global_state(
                    2,
                    WalletEntropy::devnet_wallet(),
                    cli_args::Args::default_with_network(network),
                )
                .await;
                alice.force_wallet_membership_proof_maintance().await;

                let mut alice = alice.lock_guard_mut().await;
                let alice_key = alice
                    .wallet_state
                    .wallet_entropy
                    .nth_generation_spending_key(0);
                let bob_secret = WalletEntropy::new_random();
                let bob_key = bob_secret.nth_generation_spending_key(0);

                // 1. Create new block 1 where Alice receives two composer UTXOs, store it.
                let genesis_block = alice.chain.archival_state().get_tip().await;
                let (block_1, alice_composer_expected_utxos_1) =
                    make_mock_block(&genesis_block, None, alice_key, rng.random(), network).await;
                {
                    alice
                        .wallet_state
                        .add_expected_utxos(alice_composer_expected_utxos_1)
                        .await;
                    alice.set_new_tip(block_1.clone()).await.unwrap();

                    // Verify that composer UTXOs were recorded
                    assert_eq!(
                        3,
                        alice
                            .wallet_state
                            .get_wallet_status(
                                block_1.hash(),
                                &block_1.mutator_set_accumulator_after().unwrap()
                            )
                            .await
                            .synced_unspent
                            .len()
                    );
                }

                let [a_blocks, b_blocks, c_blocks] =
                    helper::make_3_branches(network, &block_1, &genesis_block, 60, &bob_key).await;

                println!(
                    "a_blocks put counts: {}",
                    a_blocks
                        .iter()
                        .map(|block| format!(
                            "{}/{}",
                            block.body().transaction_kernel.inputs.len(),
                            block.body().transaction_kernel.outputs.len()
                        ))
                        .join(", ")
                );
                println!(
                    "b_blocks put counts: {}",
                    b_blocks
                        .iter()
                        .map(|block| format!(
                            "{}/{}",
                            block.body().transaction_kernel.inputs.len(),
                            block.body().transaction_kernel.outputs.len()
                        ))
                        .join(", ")
                );
                println!(
                    "c_blocks put counts: {}",
                    c_blocks
                        .iter()
                        .map(|block| format!(
                            "{}/{}",
                            block.body().transaction_kernel.inputs.len(),
                            block.body().transaction_kernel.outputs.len()
                        ))
                        .join(", ")
                );

                // Add 60 blocks on top of 1, *not* mined by Alice
                let fork_a_block = a_blocks.last().unwrap().to_owned();
                for branch_block in a_blocks {
                    alice.set_new_tip(branch_block).await.unwrap();
                }

                // Verify that all both MUTXOs have synced MPs
                let wallet_status_on_a_fork = alice
                    .wallet_state
                    .get_wallet_status(
                        fork_a_block.hash(),
                        &fork_a_block.mutator_set_accumulator_after().unwrap(),
                    )
                    .await;

                assert_eq!(3, wallet_status_on_a_fork.synced_unspent.len());

                // Fork away from the "a" chain to the "b" chain, with block 1 as LUCA
                let fork_b_block = b_blocks.last().unwrap().to_owned();
                for branch_block in b_blocks {
                    alice.set_new_tip(branch_block).await.unwrap();
                }

                // Verify that there are zero MUTXOs with synced MPs
                let alice_wallet_status_on_b_fork_before_resync = alice
                    .wallet_state
                    .get_wallet_status(
                        fork_b_block.hash(),
                        &fork_b_block.mutator_set_accumulator_after().unwrap(),
                    )
                    .await;
                assert_eq!(
                    0,
                    alice_wallet_status_on_b_fork_before_resync
                        .synced_unspent
                        .len()
                );
                assert_eq!(
                    3,
                    alice_wallet_status_on_b_fork_before_resync.unsynced.len()
                );

                // Run the resync and verify that MPs are synced
                match restore_method {
                    RestoreMsMpMethod::Blocks => alice
                        .resync_membership_proofs_from_stored_blocks(fork_b_block.hash())
                        .await
                        .unwrap(),
                    RestoreMsMpMethod::ArchivalMutatorSet => {
                        alice
                            .restore_monitored_utxos_from_archival_mutator_set(None)
                            .await
                    }
                };

                let wallet_status_on_b_fork_after_resync = alice
                    .wallet_state
                    .get_wallet_status(
                        fork_b_block.hash(),
                        &fork_b_block.mutator_set_accumulator_after().unwrap(),
                    )
                    .await;
                assert_eq!(
                    3,
                    wallet_status_on_b_fork_after_resync.synced_unspent.len(),
                    "Expected 3 synced UTXOs, restore_method: {restore_method:?}"
                );
                assert_eq!(
                    0,
                    wallet_status_on_b_fork_after_resync.unsynced.len(),
                    "Expected 0 unsynced UTXOs, restore_method: {restore_method:?}"
                );

                // Make a new chain c with genesis block as LUCA. Verify that the genesis UTXO can be synced
                // to this new chain
                let fork_c_block = c_blocks.last().unwrap().to_owned();
                for branch_block in c_blocks {
                    alice.set_new_tip(branch_block).await.unwrap();
                }

                // Verify that there are zero MUTXOs with synced MPs
                let alice_wallet_status_on_c_fork_before_resync = alice
                    .wallet_state
                    .get_wallet_status(
                        fork_c_block.hash(),
                        &fork_c_block.mutator_set_accumulator_after().unwrap(),
                    )
                    .await;
                assert_eq!(
                    0,
                    alice_wallet_status_on_c_fork_before_resync
                        .synced_unspent
                        .len()
                );
                assert_eq!(
                    3,
                    alice_wallet_status_on_c_fork_before_resync.unsynced.len()
                );

                // Run the resync and verify that UTXO from genesis is synced, but that
                // UTXO from 1a is not synced.
                match restore_method {
                    RestoreMsMpMethod::Blocks => alice
                        .resync_membership_proofs_from_stored_blocks(fork_c_block.hash())
                        .await
                        .unwrap(),
                    RestoreMsMpMethod::ArchivalMutatorSet => {
                        alice
                            .restore_monitored_utxos_from_archival_mutator_set(None)
                            .await
                    }
                };

                let alice_ws_c_after_resync = alice
                    .wallet_state
                    .get_wallet_status(
                        fork_c_block.hash(),
                        &fork_c_block.mutator_set_accumulator_after().unwrap(),
                    )
                    .await;
                assert_eq!(1, alice_ws_c_after_resync.synced_unspent.len());
                assert_eq!(2, alice_ws_c_after_resync.unsynced.len());

                // Also check that UTXO from 1a is considered abandoned
                let alice_mutxos = alice.wallet_state.wallet_db.monitored_utxos();
                assert!(
                    !alice_mutxos
                        .get(0)
                        .await
                        .was_abandoned(alice.chain.archival_state())
                        .await
                );
                for i in 1..=2 {
                    assert!(
                        alice_mutxos
                            .get(i)
                            .await
                            .was_abandoned(alice.chain.archival_state())
                            .await
                    );
                }
            }
        }
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn flaky_mutator_set_test() {
        // Test various parts of the state update when a block contains multiple inputs and outputs
        // Scenario: Three parties: Alice, Bob, and Premine Receiver, mine blocks and pass coins
        // around.

        let mut rng: StdRng = StdRng::seed_from_u64(0x03ce12210c467f93u64);
        let network = Network::Main;

        let cli_args = cli_args::Args {
            guesser_fraction: 0.0,
            network,
            ..Default::default()
        };
        let mut premine_receiver =
            mock_genesis_global_state(3, WalletEntropy::devnet_wallet(), cli_args.clone()).await;
        let genesis_spending_key = premine_receiver
            .lock_guard()
            .await
            .wallet_state
            .wallet_entropy
            .nth_generation_spending_key_for_tests(0);

        let wallet_secret_alice = WalletEntropy::new_pseudorandom(rng.random());
        let alice_spending_key = wallet_secret_alice.nth_generation_spending_key_for_tests(0);
        let mut alice = mock_genesis_global_state(3, wallet_secret_alice, cli_args.clone()).await;

        let wallet_secret_bob = WalletEntropy::new_pseudorandom(rng.random());
        let bob_spending_key = wallet_secret_bob.nth_generation_spending_key_for_tests(0);
        let mut bob = mock_genesis_global_state(3, wallet_secret_bob, cli_args.clone()).await;

        let genesis_block = Block::genesis(network);
        let in_seven_months = genesis_block.kernel.header.timestamp + Timestamp::months(7);
        let in_eight_months = in_seven_months + Timestamp::months(1);

        let (coinbase_transaction, coinbase_expected_utxos) = make_coinbase_transaction_from_state(
            &genesis_block,
            &premine_receiver,
            in_seven_months,
            TritonVmJobPriority::Normal.into(),
        )
        .await
        .unwrap();

        let block_height = BlockHeight::genesis();
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);
        assert!(
            coinbase_transaction
                .is_valid(network, consensus_rule_set)
                .await
        );
        assert!(coinbase_transaction
            .is_confirmable_relative_to(&genesis_block.mutator_set_accumulator_after().unwrap(),));

        // Send two outputs each to Alice and Bob, from genesis receiver
        let sender_randomness: Digest = rng.random();
        let tx_outputs = |amts: Vec<NativeCurrencyAmount>, receiver: ReceivingAddress| {
            amts.into_iter()
                .map(|amt| {
                    TxOutput::onchain_native_currency(
                        amt,
                        sender_randomness,
                        receiver.clone(),
                        false,
                    )
                })
                .collect_vec()
        };
        let tx_outputs_for_alice = tx_outputs(
            vec![
                NativeCurrencyAmount::coins(1),
                NativeCurrencyAmount::coins(2),
            ],
            alice_spending_key.to_address().into(),
        );
        let tx_outputs_for_bob = tx_outputs(
            vec![
                NativeCurrencyAmount::coins(3),
                NativeCurrencyAmount::coins(4),
            ],
            bob_spending_key.to_address().into(),
        );

        let fee = NativeCurrencyAmount::one_nau();
        let genesis_key = premine_receiver
            .lock_guard_mut()
            .await
            .wallet_state
            .next_unused_spending_key(KeyType::Generation)
            .await;
        let config_alice_and_bob = TxCreationConfig::default()
            .recover_change_off_chain(genesis_key)
            .with_prover_capability(TxProvingCapability::SingleProof);
        let tx_outputs_for_alice_and_bob =
            [tx_outputs_for_alice.clone(), tx_outputs_for_bob.clone()].concat();

        let artifacts_alice_and_bob = premine_receiver
            .api()
            .tx_initiator_internal()
            .create_transaction(
                tx_outputs_for_alice_and_bob.clone().into(),
                fee,
                in_seven_months,
                config_alice_and_bob,
                consensus_rule_set,
            )
            .await
            .unwrap();
        assert_eq!(
            tx_outputs_for_alice_and_bob.len() + 1,
            artifacts_alice_and_bob.details.tx_outputs.len(),
            "Expected change output to genesis receiver"
        );

        let tx_to_alice_and_bob: Transaction = artifacts_alice_and_bob.transaction.into();
        assert!(
            tx_to_alice_and_bob
                .is_valid(network, consensus_rule_set)
                .await
        );
        assert!(tx_to_alice_and_bob
            .is_confirmable_relative_to(&genesis_block.mutator_set_accumulator_after().unwrap(),));

        // Expect change output
        let change_output = (*artifacts_alice_and_bob.details.tx_outputs)
            .clone()
            .pop()
            .unwrap();
        premine_receiver
            .global_state_lock
            .lock_guard_mut()
            .await
            .wallet_state
            .add_expected_utxo(ExpectedUtxo::new(
                change_output.utxo(),
                change_output.sender_randomness(),
                genesis_key.privacy_preimage(),
                UtxoNotifier::Myself,
            ))
            .await;

        let block_transaction = BlockTransaction::merge(
            coinbase_transaction.into(),
            tx_to_alice_and_bob,
            Default::default(),
            TritonVmJobQueue::get_instance(),
            TritonVmJobPriority::default().into(),
            consensus_rule_set,
        )
        .await
        .unwrap();

        let block_1 = Block::compose(
            &genesis_block,
            block_transaction,
            in_seven_months,
            TritonVmJobQueue::get_instance(),
            TritonVmJobPriority::default().into(),
        )
        .await
        .unwrap();

        assert!(
            block_1
                .is_valid(&genesis_block, in_seven_months, network)
                .await
        );

        println!("Accumulated transaction into block_1.");
        println!(
            "Transaction has {} inputs (removal records) and {} outputs (addition records)",
            block_1.kernel.body.transaction_kernel.inputs.len(),
            block_1.kernel.body.transaction_kernel.outputs.len()
        );

        // Update states with `block_1`
        let expected_utxos_for_alice = alice
            .lock_guard()
            .await
            .wallet_state
            .extract_expected_utxos(tx_outputs_for_alice.iter(), UtxoNotifier::Cli);
        alice
            .lock_guard_mut()
            .await
            .wallet_state
            .add_expected_utxos(expected_utxos_for_alice)
            .await;

        let expected_utxos_for_bob_1 = bob
            .lock_guard()
            .await
            .wallet_state
            .extract_expected_utxos(tx_outputs_for_bob.iter(), UtxoNotifier::Cli);
        bob.lock_guard_mut()
            .await
            .wallet_state
            .add_expected_utxos(expected_utxos_for_bob_1)
            .await;

        premine_receiver
            .set_new_self_composed_tip(
                block_1.clone(),
                coinbase_expected_utxos
                    .into_iter()
                    .map(|expected_utxo| {
                        ExpectedUtxo::new(
                            expected_utxo.utxo,
                            expected_utxo.sender_randomness,
                            genesis_spending_key.receiver_preimage(),
                            UtxoNotifier::OwnMinerComposeBlock,
                        )
                    })
                    .collect_vec(),
            )
            .await
            .unwrap();

        for state_lock in [&mut alice, &mut bob] {
            state_lock.set_new_tip(block_1.clone()).await.unwrap();
        }

        assert_eq!(
            4,
            premine_receiver
                .lock_guard_mut()
                .await
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .len().await, "Premine receiver must have 4 monitored UTXOs after block 1: change from transaction, 2 coinbases from block 1, and premine UTXO"
        );

        assert_eq!(
            NativeCurrencyAmount::coins(3),
            alice
                .lock_guard()
                .await
                .get_wallet_status_for_tip()
                .await
                .available_confirmed(in_seven_months)
        );
        assert_eq!(
            NativeCurrencyAmount::coins(7),
            bob.lock_guard()
                .await
                .get_wallet_status_for_tip()
                .await
                .available_confirmed(in_seven_months)
        );
        // TODO: No idea why this isn't working. It's off by 1 NAU?
        // {
        //     let expected = NativeCurrencyAmount::coins(74);
        //     let got = premine_receiver
        //         .lock_guard()
        //         .await
        //         .get_wallet_status_for_tip()
        //         .await
        //         .synced_unspent_available_amount(in_seven_months);
        //     assert_eq!(
        //         expected, got,
        //         "premine receiver's balance should be 74: mining reward / 2 + premine - sent - fee + fee. Expected: {expected:?}\nGot: {got}"
        //     );
        // }

        // Make two transactions: Alice sends two UTXOs to Genesis and Bob sends three UTXOs to genesis
        let tx_outputs_from_alice = tx_outputs(
            vec![
                NativeCurrencyAmount::coins(1),
                NativeCurrencyAmount::coins(1),
            ],
            genesis_spending_key.to_address().into(),
        );

        let config_alice = TxCreationConfig::default()
            .recover_change_off_chain(alice_spending_key.into())
            .with_prover_capability(TxProvingCapability::SingleProof);
        let artifacts_from_alice = alice
            .api()
            .tx_initiator_internal()
            .create_transaction(
                tx_outputs_from_alice.clone().into(),
                NativeCurrencyAmount::coins(1),
                in_seven_months,
                config_alice,
                consensus_rule_set,
            )
            .await
            .unwrap();
        let tx_from_alice = artifacts_from_alice.transaction;
        assert_eq!(
            tx_outputs_from_alice.len(),
            artifacts_from_alice.details.tx_outputs.len(),
            "No change for Alice as she spent it all"
        );

        assert!(tx_from_alice.is_valid(network, consensus_rule_set).await);
        assert!(tx_from_alice
            .is_confirmable_relative_to(&block_1.mutator_set_accumulator_after().unwrap(),));

        // make bob's transaction
        let tx_outputs_from_bob = tx_outputs(
            vec![
                NativeCurrencyAmount::coins(2),
                NativeCurrencyAmount::coins(2),
                NativeCurrencyAmount::coins(2),
            ],
            genesis_spending_key.to_address().into(),
        );

        let config_bob = TxCreationConfig::default()
            .recover_change_off_chain(bob_spending_key.into())
            .with_prover_capability(TxProvingCapability::SingleProof);
        let artifacts_from_bob = bob
            .api()
            .tx_initiator_internal()
            .create_transaction(
                tx_outputs_from_bob.clone().into(),
                NativeCurrencyAmount::coins(1),
                in_seven_months,
                config_bob,
                consensus_rule_set,
            )
            .await
            .unwrap();
        let tx_from_bob = artifacts_from_bob.transaction;

        assert_eq!(
            tx_outputs_from_bob.len(),
            artifacts_from_bob.details.tx_outputs.len(),
            "No change for Bob as he spent it all"
        );

        assert!(tx_from_bob.is_valid(network, consensus_rule_set).await);
        assert!(tx_from_bob
            .is_confirmable_relative_to(&block_1.mutator_set_accumulator_after().unwrap(),));

        // Make block_2 with tx that contains:
        // - 4 inputs: 2 from Alice and 2 from Bob
        // - 7 outputs: 2 from Alice to Genesis, 3 from Bob to Genesis, and 2 coinbases
        let (coinbase_transaction2, _expected_utxo) = make_coinbase_transaction_from_state(
            &premine_receiver
                .global_state_lock
                .lock_guard()
                .await
                .chain
                .light_state()
                .clone(),
            &premine_receiver,
            in_seven_months,
            TritonVmJobPriority::Normal.into(),
        )
        .await
        .unwrap();
        assert!(
            coinbase_transaction2
                .is_valid(network, consensus_rule_set)
                .await
        );
        assert!(coinbase_transaction2
            .is_confirmable_relative_to(&block_1.mutator_set_accumulator_after().unwrap(),));

        let block_transaction2 = BlockTransaction::merge(
            coinbase_transaction2.into(),
            tx_from_alice.into(),
            Default::default(),
            TritonVmJobQueue::get_instance(),
            TritonVmJobPriority::default().into(),
            consensus_rule_set,
        )
        .await
        .unwrap();
        let block_transaction2 = BlockTransaction::merge(
            block_transaction2.into(),
            tx_from_bob.into(),
            Default::default(),
            TritonVmJobQueue::get_instance(),
            TritonVmJobPriority::default().into(),
            consensus_rule_set,
        )
        .await
        .unwrap();

        assert!(
            Transaction::from(block_transaction2.clone())
                .is_valid(network, consensus_rule_set)
                .await
        );

        // We can't check confirmability of transaction since its records are now packed.
        // So we produce a block instead and validate it.
        let block_2 = Block::compose(
            &block_1,
            block_transaction2,
            in_eight_months,
            TritonVmJobQueue::get_instance(),
            TritonVmJobPriority::default().into(),
        )
        .await
        .unwrap();
        assert!(block_2.is_valid(&block_1, in_eight_months, network).await);

        assert_eq!(4, block_2.kernel.body.transaction_kernel.inputs.len());
        assert_eq!(7, block_2.kernel.body.transaction_kernel.outputs.len());
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn mock_global_state_is_valid() {
        // Verify that the states, not just the blocks, are valid.

        let network = Network::Main;
        let mut global_state_lock = mock_genesis_global_state(
            2,
            WalletEntropy::devnet_wallet(),
            cli_args::Args::default_with_network(network),
        )
        .await;
        let genesis_block = Block::genesis(network);
        let now = genesis_block.kernel.header.timestamp + Timestamp::hours(1);

        let block1 =
            fake_valid_successor_for_tests(&genesis_block, now, Default::default(), network).await;

        global_state_lock.set_new_tip(block1).await.unwrap();

        assert!(
            global_state_lock
                .lock_guard()
                .await
                .chain
                .light_state()
                .is_valid(&genesis_block, now, network)
                .await,
            "light state tip must be a valid block"
        );
        assert!(
            global_state_lock
                .lock_guard()
                .await
                .chain
                .archival_state()
                .get_tip()
                .await
                .is_valid(&genesis_block, now, network)
                .await,
            "archival state tip must be a valid block"
        );
    }

    mod block_proposals {
        use super::*;
        use crate::tests::shared::blocks::invalid_empty_block1_with_guesser_fraction;

        #[apply(shared_tokio_runtime)]
        async fn dont_guess_when_block_proposal_not_known() {
            let gsl = mock_genesis_global_state(
                2,
                WalletEntropy::devnet_wallet(),
                cli_args::Args::default_with_network(Network::Main),
            )
            .await;
            assert!(
                !gsl.lock_guard()
                    .await
                    .current_block_proposal_meets_threshold(),
                "Must return false when no proposal is known"
            );
        }

        #[apply(shared_tokio_runtime)]
        async fn dont_guess_when_block_proposal_too_cheap() {
            let network = Network::Main;
            let mut gsl = mock_genesis_global_state(
                2,
                WalletEntropy::devnet_wallet(),
                cli_args::Args {
                    network,
                    minimum_guesser_fraction: 0.5f64,
                    ..Default::default()
                },
            )
            .await;
            let mut gsl = gsl.lock_guard_mut().await;

            let too_cheap = invalid_empty_block1_with_guesser_fraction(network, 0.1).await;
            gsl.mining_state.block_proposal = BlockProposal::ForeignComposition(too_cheap.clone());
            assert!(
                !gsl.current_block_proposal_meets_threshold(),
                "Must return false when no proposal is too cheap"
            );

            let not_too_cheap = invalid_empty_block1_with_guesser_fraction(network, 0.55).await;
            gsl.mining_state.block_proposal = BlockProposal::ForeignComposition(not_too_cheap);
            assert!(
                gsl.current_block_proposal_meets_threshold(),
                "Must return true when proposal pays enough"
            );

            gsl.mining_state.block_proposal = BlockProposal::OwnComposition((too_cheap, vec![]));
            assert!(
                gsl.current_block_proposal_meets_threshold(),
                "Must return true when proposal is own"
            );
        }

        #[apply(shared_tokio_runtime)]
        async fn favor_incoming_block_proposal_test() {
            let network = Network::Main;
            async fn block1_proposal(
                global_state_lock: &GlobalStateLock,
                network: Network,
            ) -> Block {
                let genesis_block = Block::genesis(global_state_lock.cli().network);
                let timestamp = genesis_block.header().timestamp + Timestamp::hours(1);
                let (cb, _) = make_coinbase_transaction_from_state(
                    &genesis_block,
                    global_state_lock,
                    timestamp,
                    global_state_lock
                        .cli()
                        .proof_job_options_primitive_witness(),
                )
                .await
                .unwrap();

                let coinbase_kernel = TransactionKernelModifier::default()
                    .merge_bit(true)
                    .modify(cb.kernel);
                let coinbase_transaction = Transaction {
                    kernel: coinbase_kernel,
                    proof: cb.proof,
                };

                Block::block_template_invalid_proof(
                    &genesis_block,
                    BlockTransaction::try_from(coinbase_transaction).unwrap(),
                    timestamp,
                    None,
                    network,
                )
            }

            let mut global_state_lock_small = mock_genesis_global_state(
                2,
                WalletEntropy::devnet_wallet(),
                cli_args::Args {
                    network,
                    guesser_fraction: 0.1,
                    ..Default::default()
                },
            )
            .await;
            let global_state_lock_big = mock_genesis_global_state(
                2,
                WalletEntropy::devnet_wallet(),
                cli_args::Args {
                    network,
                    guesser_fraction: 0.5,
                    ..Default::default()
                },
            )
            .await;
            let small_guesser_fraction = block1_proposal(&global_state_lock_small, network).await;
            let small_prev_block_digest = small_guesser_fraction.header().prev_block_digest;
            let big_guesser_fraction = block1_proposal(&global_state_lock_big, network).await;
            let big_prev_block_digest = big_guesser_fraction.header().prev_block_digest;

            let mut state = global_state_lock_small
                .global_state_lock
                .lock_guard_mut()
                .await;
            assert!(
                state
                    .favor_incoming_block_proposal(
                        small_prev_block_digest,
                        small_guesser_fraction
                            .body()
                            .total_guesser_reward()
                            .unwrap()
                    )
                    .is_ok(),
                "Must favor low guesser fee over none"
            );

            state.mining_state.block_proposal =
                BlockProposal::foreign_proposal(small_guesser_fraction.clone());
            assert!(
                state
                    .favor_incoming_block_proposal(
                        big_prev_block_digest,
                        big_guesser_fraction.body().total_guesser_reward().unwrap()
                    )
                    .is_ok(),
                "Must favor big guesser fee over low"
            );

            state.mining_state.block_proposal =
                BlockProposal::foreign_proposal(big_guesser_fraction.clone());
            assert_eq!(
                BlockProposalRejectError::InsufficientFee {
                    current: Some(big_guesser_fraction.body().total_guesser_reward().unwrap()),
                    received: big_guesser_fraction.body().total_guesser_reward().unwrap()
                },
                state
                    .favor_incoming_block_proposal(
                        big_prev_block_digest,
                        big_guesser_fraction.body().total_guesser_reward().unwrap()
                    )
                    .unwrap_err(),
                "Must favor existing over incoming equivalent"
            );
        }
    }

    mod state_update_on_reorganizations {
        use tasm_lib::twenty_first::prelude::Mmr;

        use super::*;

        async fn assert_correct_global_state(
            global_state: &GlobalState,
            expected_tip: Block,
            expected_parent: Option<Block>,
            expected_num_blocks_at_tip_height: usize,
            expected_num_spendable_utxos: usize,
        ) {
            // Verifying light state integrity
            let expected_tip_digest = expected_tip.hash();
            assert_eq!(expected_tip_digest, global_state.chain.light_state().hash());

            // Peeking into archival state
            assert_eq!(
                expected_tip_digest,
                global_state
                    .chain
                    .archival_state()
                    .archival_mutator_set
                    .get_sync_label(),
                "Archival state must have expected sync-label",
            );
            assert_eq!(
                expected_tip.mutator_set_accumulator_after().unwrap(),
                global_state
                    .chain
                    .archival_state()
                    .archival_mutator_set
                    .ams()
                    .accumulator()
                    .await,
                "Archival mutator set must match that in expected tip"
            );

            assert_eq!(
                expected_tip_digest,
                global_state
                    .chain
                    .archival_state()
                    .get_block(expected_tip.hash())
                    .await
                    .unwrap()
                    .unwrap()
                    .hash(),
                "Expected block must be returned"
            );

            assert_eq!(
                expected_tip_digest,
                global_state
                    .chain
                    .archival_state()
                    .archival_block_mmr
                    .ammr()
                    .get_latest_leaf()
                    .await
                    .unwrap(),
                "Latest leaf in archival block MMR must match expected block"
            );

            // Verify that archival-block MMR matches that of block
            {
                let mut expected_archival_block_mmr_value =
                    expected_tip.body().block_mmr_accumulator.clone();
                expected_archival_block_mmr_value.append(expected_tip_digest);
                assert_eq!(
                    expected_archival_block_mmr_value,
                    global_state
                        .chain
                        .archival_state()
                        .archival_block_mmr
                        .ammr()
                        .to_accumulator_async()
                        .await,
                    "archival block-MMR must match that in tip after adding tip digest"
                );
            }

            let tip_height = expected_tip.header().height;
            assert_eq!(
                expected_num_blocks_at_tip_height,
                global_state
                    .chain
                    .archival_state()
                    .block_height_to_block_digests(tip_height)
                    .await
                    .len(),
                "Exactly {expected_num_blocks_at_tip_height} blocks at height must be known"
            );

            if let Some(expected_parent) = expected_parent {
                let expected_parent_digest = expected_parent.hash();
                assert_eq!(
                    expected_parent_digest,
                    global_state
                        .chain
                        .archival_state()
                        .get_tip_parent()
                        .await
                        .unwrap()
                        .hash()
                );
            }

            // Peek into wallet
            let tip_msa = expected_tip
                .mutator_set_accumulator_after()
                .unwrap()
                .clone();
            let mutxos = global_state
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .get_all()
                .await;
            let mut mutxos_on_tip = vec![];
            assert!(
                mutxos.iter().all(|x| x.confirmed_in_block.is_some()),
                "All monitored UTXOs must be mined."
            );
            for mutxo in mutxos {
                if !mutxo
                    .was_abandoned(global_state.chain.archival_state())
                    .await
                {
                    mutxos_on_tip.push(mutxo);
                }
            }

            assert_eq!(
                expected_num_spendable_utxos,
                mutxos_on_tip.len(),
                "Number of monitored UTXOS at height {tip_height} must match expected value of {expected_num_spendable_utxos}"
            );
            assert!(
                mutxos_on_tip.iter().all(|mutxo| tip_msa.verify(
                    Tip5::hash(&mutxo.utxo),
                    &mutxo
                        .get_membership_proof_for_block(expected_tip.hash())
                        .unwrap()
                )),
                "All wallet's membership proofs must still be valid"
            );
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn can_handle_deep_reorganization() {
            // Mine 60 blocks, then switch to a new chain branching off from
            // genesis block. Verify that state is integral after each block.
            let network = Network::Main;
            let mut rng = rand::rng();
            let genesis_block = Block::genesis(network);
            let wallet_secret = WalletEntropy::devnet_wallet();
            let spending_key = wallet_secret.nth_generation_spending_key(0);

            let mut global_state_lock = mock_genesis_global_state(
                2,
                wallet_secret.clone(),
                cli_args::Args::default_with_network(network),
            )
            .await;

            // Branch A
            let mut previous_block = genesis_block.clone();
            for block_height in 1..60 {
                let (next_block, expected) =
                    make_mock_block(&previous_block, None, spending_key, rng.random(), network)
                        .await;
                global_state_lock
                    .set_new_self_composed_tip(next_block.clone(), expected)
                    .await
                    .unwrap();
                let global_state = global_state_lock.lock_guard().await;
                assert_correct_global_state(
                    &global_state,
                    next_block.clone(),
                    Some(previous_block.clone()),
                    1,
                    2 * block_height + 1,
                )
                .await;
                previous_block = next_block;
            }

            // Branch B
            previous_block = genesis_block.clone();
            for block_height in 1..60 {
                let (next_block, expected) =
                    make_mock_block(&previous_block, None, spending_key, rng.random(), network)
                        .await;
                global_state_lock
                    .set_new_self_composed_tip(next_block.clone(), expected)
                    .await
                    .unwrap();

                // Resync membership proofs after block 1 on branch B, otherwise
                // the genesis block's premine UTXO will not have a valid
                // membership proof.
                let mut global_state = global_state_lock.lock_guard_mut().await;
                if block_height == 1 {
                    global_state.resync_membership_proofs().await.unwrap();
                }

                assert_correct_global_state(
                    &global_state,
                    next_block.clone(),
                    Some(previous_block.clone()),
                    2,
                    2 * block_height + 1,
                )
                .await;
                previous_block = next_block;
            }

            // Can roll back to genesis
            let mut global_state = global_state_lock.lock_guard_mut().await;
            global_state
                .set_new_tip(genesis_block.clone())
                .await
                .unwrap();
            assert_correct_global_state(&global_state, genesis_block.clone(), None, 1, 1).await;
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn can_store_block_without_marking_it_as_tip_1_block() {
            // Verify that [GlobalState::store_block_not_tip] stores block
            // correctly, and that [GlobalState::set_new_tip] can be used to
            // build upon blocks stored through the former method.
            let network = Network::Main;
            let mut rng = rand::rng();
            let genesis_block = Block::genesis(network);
            let wallet_secret = WalletEntropy::new_random();

            let mut alice = mock_genesis_global_state(
                2,
                wallet_secret.clone(),
                cli_args::Args::default_with_network(network),
            )
            .await;

            let mut alice = alice.global_state_lock.lock_guard_mut().await;
            assert_eq!(genesis_block.hash(), alice.chain.light_state().hash());

            let cb_key = WalletEntropy::new_random().nth_generation_spending_key(0);
            let (block_1, _) =
                make_mock_block(&genesis_block, None, cb_key, rng.random(), network).await;

            alice.store_block_not_tip(block_1.clone()).await.unwrap();
            assert_eq!(
                genesis_block.hash(),
                alice.chain.light_state().hash(),
                "method may not update light state's tip"
            );
            assert_eq!(
                genesis_block.hash(),
                alice.chain.archival_state().get_tip().await.hash(),
                "method may not update archival state's tip"
            );

            alice.set_new_tip(block_1.clone()).await.unwrap();
            assert_correct_global_state(&alice, block_1.clone(), Some(genesis_block), 1, 0).await;
        }

        /// Return a list of (Block, parent) pairs, of length N.
        async fn chain_of_blocks_and_parents(
            network: Network,
            length: usize,
        ) -> Vec<(Block, Block)> {
            let mut rng = rand::rng();
            let cb_key = WalletEntropy::new_random().nth_generation_spending_key(0);
            let mut parent = Block::genesis(network);
            let mut chain = vec![];
            for _ in 0..length {
                let (block, _) =
                    make_mock_block(&parent, None, cb_key, rng.random(), network).await;
                chain.push((block.clone(), parent.clone()));
                parent = block;
            }

            chain
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn can_jump_to_new_tip_over_blocks_that_were_never_tips() {
            let network = Network::Main;
            let wallet_secret = WalletEntropy::new_random();
            let mut alice = mock_genesis_global_state(
                2,
                wallet_secret.clone(),
                cli_args::Args::default_with_network(network),
            )
            .await;
            let mut alice = alice.global_state_lock.lock_guard_mut().await;

            let a_length = 12;
            let chain_a = chain_of_blocks_and_parents(network, a_length).await;
            for (block, _) in &chain_a {
                alice.set_new_tip(block.to_owned()).await.unwrap();
            }

            let chain_a_tip = &chain_a[a_length - 1].0;
            let chain_a_tip_parent = &chain_a[a_length - 1].1;
            assert_correct_global_state(
                &alice,
                chain_a_tip.to_owned(),
                Some(chain_a_tip_parent.to_owned()),
                1,
                0,
            )
            .await;

            // Store all blocks from a new chain, except the last, without
            // marking any of them as tips.  Verify no change in tip.
            let b_length = 15;
            let chain_b = chain_of_blocks_and_parents(network, b_length).await;
            for (block, _) in chain_b.iter().take(b_length - 1) {
                alice.store_block_not_tip(block.clone()).await.unwrap();
            }
            assert_correct_global_state(
                &alice,
                chain_a_tip.to_owned(),
                Some(chain_a_tip_parent.to_owned()),
                2,
                0,
            )
            .await;

            // Set chain B's last block to tip to verify that all the stored
            // blocks from chain B can be used to connect it to LUCA, which in
            // this case is genesis block.
            let chain_b_tip = &chain_b[b_length - 1].0;
            let chain_b_tip_parent = &chain_b[b_length - 1].1;
            alice.set_new_tip(chain_b_tip.to_owned()).await.unwrap();
            assert_correct_global_state(
                &alice,
                chain_b_tip.to_owned(),
                Some(chain_b_tip_parent.to_owned()),
                1,
                0,
            )
            .await;
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn reorganization_with_blocks_that_were_never_tips_n_blocks_deep() {
            // Verify that [GlobalState::store_block_not_tip] stores block
            // correctly, and that [GlobalState::set_new_tip] can be used to
            // build upon blocks stored through the former method.
            let network = Network::Main;
            let genesis_block = Block::genesis(network);
            let wallet_secret = WalletEntropy::new_random();

            for depth in 1..=4 {
                let mut alice = mock_genesis_global_state(
                    2,
                    wallet_secret.clone(),
                    cli_args::Args::default_with_network(network),
                )
                .await;
                let mut alice = alice.global_state_lock.lock_guard_mut().await;
                assert_eq!(genesis_block.hash(), alice.chain.light_state().hash());
                let chain_a = chain_of_blocks_and_parents(network, depth).await;
                let chain_b = chain_of_blocks_and_parents(network, depth).await;
                let blocks_and_parents = [chain_a, chain_b].concat();
                for (block, _) in &blocks_and_parents {
                    alice.store_block_not_tip(block.clone()).await.unwrap();
                    assert_eq!(
                        genesis_block.hash(),
                        alice.chain.light_state().hash(),
                        "method may not update light state's tip, depth = {depth}"
                    );
                    assert_eq!(
                        genesis_block.hash(),
                        alice.chain.archival_state().get_tip().await.hash(),
                        "method may not update archival state's tip, depth = {depth}"
                    );
                }

                // Loop over all blocks and verify that all can be marked as
                // tip, resulting in a consistent, correct state.
                for (block, parent) in &blocks_and_parents {
                    alice.set_new_tip(block.clone()).await.unwrap();
                    assert_correct_global_state(
                        &alice,
                        block.clone(),
                        Some(parent.to_owned()),
                        2,
                        0,
                    )
                    .await;
                }
            }
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn set_new_tip_can_roll_back() {
            // Verify that [GlobalState::set_new_tip] works for rolling back the
            // blockchain to a previous block.
            let network = Network::Main;
            let mut rng = rand::rng();
            let genesis_block = Block::genesis(network);
            let wallet_secret = WalletEntropy::devnet_wallet();
            let spending_key = wallet_secret.nth_generation_spending_key(0);

            let (block_1a, composer_expected_utxos_1a) =
                make_mock_block(&genesis_block, None, spending_key, rng.random(), network).await;
            let (block_2a, composer_expected_utxos_2a) =
                make_mock_block(&block_1a, None, spending_key, rng.random(), network).await;
            let (block_3a, composer_expected_utxos_3a) =
                make_mock_block(&block_2a, None, spending_key, rng.random(), network).await;

            let cli_args = cli_args::Args {
                number_of_mps_per_utxo: 30,
                network,
                ..Default::default()
            };

            for claim_composer_fees in [false, true] {
                let mut global_state_lock =
                    mock_genesis_global_state(2, wallet_secret.clone(), cli_args.clone()).await;
                let mut global_state = global_state_lock.lock_guard_mut().await;

                if claim_composer_fees {
                    global_state
                        .wallet_state
                        .add_expected_utxos(composer_expected_utxos_1a.clone())
                        .await;
                    global_state.set_new_tip(block_1a.clone()).await.unwrap();
                    global_state
                        .wallet_state
                        .add_expected_utxos(composer_expected_utxos_2a.clone())
                        .await;
                    global_state.set_new_tip(block_2a.clone()).await.unwrap();
                    global_state
                        .wallet_state
                        .add_expected_utxos(composer_expected_utxos_3a.clone())
                        .await;
                    global_state.set_new_tip(block_3a.clone()).await.unwrap();
                    global_state
                        .wallet_state
                        .add_expected_utxos(composer_expected_utxos_1a.clone())
                        .await;
                    global_state.set_new_tip(block_1a.clone()).await.unwrap();
                } else {
                    global_state.set_new_tip(block_1a.clone()).await.unwrap();
                    global_state.set_new_tip(block_2a.clone()).await.unwrap();
                    global_state.set_new_tip(block_3a.clone()).await.unwrap();
                    global_state.set_new_tip(block_1a.clone()).await.unwrap();
                }

                let expected_number_of_mutxos = if claim_composer_fees { 3 } else { 1 };

                assert_correct_global_state(
                    &global_state,
                    block_1a.clone(),
                    Some(genesis_block.clone()),
                    1,
                    expected_number_of_mutxos,
                )
                .await;

                // Verify that we can also reorganize with last shared ancestor being
                // the genesis block.
                let (block_1b, _) =
                    make_mock_block(&genesis_block, None, spending_key, random(), network).await;
                global_state.set_new_tip(block_1b.clone()).await.unwrap();
                assert_correct_global_state(
                    &global_state,
                    block_1b.clone(),
                    Some(genesis_block.clone()),
                    2,
                    1,
                )
                .await;

                // Add many blocks, verify state-validity after each.
                let mut previous_block = block_1b;
                for block_height in 2..60 {
                    let (next_block, composer_expected_utxos) =
                        make_mock_block(&previous_block, None, spending_key, rng.random(), network)
                            .await;
                    global_state
                        .wallet_state
                        .add_expected_utxos(composer_expected_utxos.clone())
                        .await;
                    global_state.set_new_tip(next_block.clone()).await.unwrap();
                    global_state
                        .wallet_state
                        .add_expected_utxos(composer_expected_utxos.clone())
                        .await;
                    global_state.set_new_tip(next_block.clone()).await.unwrap();
                    assert_correct_global_state(
                        &global_state,
                        next_block.clone(),
                        Some(previous_block.clone()),
                        if block_height <= 3 { 2 } else { 1 },
                        2 * (block_height - 1) + 1,
                    )
                    .await;
                    previous_block = next_block;
                }

                // Can roll back to genesis
                global_state
                    .set_new_tip(genesis_block.clone())
                    .await
                    .unwrap();
                assert_correct_global_state(&global_state, genesis_block.clone(), None, 1, 1).await;
            }
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn setting_same_tip_twice_is_allowed() {
            let mut rng = rand::rng();
            let network = Network::Main;
            let wallet_secret = WalletEntropy::devnet_wallet();
            let genesis_block = Block::genesis(network);
            let spend_key = wallet_secret.nth_generation_spending_key(0);

            let (block_1, composer_expected_utxos_1) =
                make_mock_block(&genesis_block, None, spend_key, rng.random(), network).await;

            for claim_cb in [false, true] {
                let expected_num_mutxos = if claim_cb { 3 } else { 1 };
                let mut global_state_lock = mock_genesis_global_state(
                    2,
                    wallet_secret.clone(),
                    cli_args::Args::default_with_network(network),
                )
                .await;
                let mut global_state = global_state_lock.lock_guard_mut().await;

                if claim_cb {
                    global_state
                        .wallet_state
                        .add_expected_utxos(composer_expected_utxos_1.clone())
                        .await;
                    global_state.set_new_tip(block_1.clone()).await.unwrap();
                    global_state
                        .wallet_state
                        .add_expected_utxos(composer_expected_utxos_1.clone())
                        .await;
                    global_state.set_new_tip(block_1.clone()).await.unwrap();
                } else {
                    global_state.set_new_tip(block_1.clone()).await.unwrap();
                    global_state.set_new_tip(block_1.clone()).await.unwrap();
                }

                assert_correct_global_state(
                    &global_state,
                    block_1.clone(),
                    Some(genesis_block.clone()),
                    1,
                    expected_num_mutxos,
                )
                .await;
            }
        }
    }

    mod import_blocks_from_directory {

        use super::*;
        use crate::tests::shared::blocks::invalid_empty_blocks_with_proof_size;

        async fn state_with_three_big_mocked_blocks(network: Network) -> GlobalStateLock {
            // Ensure more than one file is used to store blocks.
            const NUM_BLOCKS: usize = 3;
            const BIG_PROOF_LEN: usize = 6_250_000; // ~= 50MB
            let blocks = invalid_empty_blocks_with_proof_size(
                &Block::genesis(network),
                NUM_BLOCKS,
                network,
                BIG_PROOF_LEN,
            );

            let peer_count = 0;
            let mut state = mock_genesis_global_state(
                peer_count,
                WalletEntropy::devnet_wallet(),
                cli_args::Args::default_with_network(network),
            )
            .await;
            {
                let mut state = state.lock_guard_mut().await;
                for block in blocks {
                    state.set_new_tip_internal(block).await.unwrap();
                }
            }

            state
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn validation_fails_on_invalid_blocks() {
            let network = Network::Main;
            let old_state = state_with_three_big_mocked_blocks(network).await;
            let old_state = old_state.lock_guard().await;

            let mut new_state = mock_genesis_global_state(
                0,
                WalletEntropy::devnet_wallet(),
                cli_args::Args::default_with_network(network),
            )
            .await;
            let mut new_state = new_state.lock_guard_mut().await;

            let block_dir = old_state.chain.archival_state().block_dir_path();
            let validate_blocks = true;
            assert!(new_state
                .import_blocks_from_directory(&block_dir, 0, validate_blocks)
                .await
                .is_err());
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn can_restore_state_from_block_directory() {
            let network = Network::Main;
            let old_state = state_with_three_big_mocked_blocks(network).await;
            let old_state = old_state.lock_guard().await;
            assert!(
                old_state.chain.archival_state().num_block_files().await > 1,
                "Test assumption: More than one file must exist"
            );

            // Build the new state from the block directory of old state.
            let mut new_state = mock_genesis_global_state(
                0,
                WalletEntropy::devnet_wallet(),
                cli_args::Args::default_with_network(network),
            )
            .await;
            let mut new_state = new_state.lock_guard_mut().await;

            let block_dir = old_state.chain.archival_state().block_dir_path();
            let validate_blocks = false;
            new_state
                .import_blocks_from_directory(&block_dir, 0, validate_blocks)
                .await
                .unwrap();

            assert_eq!(old_state.chain.light_state(), new_state.chain.light_state());
            let tip = old_state.chain.light_state();
            assert_eq!(*tip, new_state.chain.archival_state().get_tip().await);
            assert_eq!(*tip, old_state.chain.archival_state().get_tip().await);
            let msa = tip.mutator_set_accumulator_after().unwrap();
            assert_eq!(
                old_state
                    .wallet_state
                    .get_wallet_status(tip.hash(), &msa)
                    .await
                    .synced_unspent,
                new_state
                    .wallet_state
                    .get_wallet_status(tip.hash(), &msa)
                    .await
                    .synced_unspent,
                "Restored wallet state must agree with original state"
            );
        }
    }

    // note: removed test have_to_specify_change_policy()
    // because ChangePolicy::default() now exists, specifically
    // so callers do NOT have to specify change policy unless
    // they want something different.
    //
    // the default is: RecoverToNextUnusedKey
    //    key-type: symmetric, medium: onchain,

    /// tests that pertain to restoring a wallet from seed-phrase
    /// and comparing onchain vs offchain notification methods.
    mod restore_wallet {
        use num_traits::CheckedSub;

        use super::*;
        use crate::application::loops::mine_loop::create_block_transaction_from;
        use crate::application::loops::mine_loop::TxMergeOrigin;

        /// test scenario: onchain/symmetric.
        /// pass outcome: no funds loss
        ///
        /// test described in [change_exists()]
        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn onchain_symmetric_change_exists() {
            change_exists(UtxoNotificationMedium::OnChain, KeyType::Symmetric).await
        }

        /// test scenario: onchain/generation.
        /// pass outcome: no funds loss
        ///
        /// test described in [change_exists()]
        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn onchain_generation_change_exists() {
            change_exists(UtxoNotificationMedium::OnChain, KeyType::Generation).await
        }

        /// test scenario: offchain/symmetric.
        /// pass outcome: all funds lost!
        ///
        /// test described in [change_exists()]
        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn offchain_symmetric_change_exists() {
            change_exists(UtxoNotificationMedium::OffChain, KeyType::Symmetric).await
        }

        /// test scenario: offchain/generation.
        /// pass outcome: all funds lost!
        ///
        /// test described in [change_exists()]
        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn offchain_generation_change_exists() {
            change_exists(UtxoNotificationMedium::OffChain, KeyType::Generation).await
        }

        /// basic scenario:  alice receives 20 coins in the premine.  7 months
        /// after launch she sends 10 coins to bob, plus 1 coin fee.  alice should
        /// receive change of 9.  Sometime after this block is mined alice's
        /// hard drive crashes and she loses her wallet.  She still has her wallet
        /// seed and uses it to create a new wallet and scan blockchain to recover
        /// funds.  At the end alice checks her wallet balance, which should be
        /// 9.
        ///
        /// note: the pre-mine and 7-months aspects are unimportant.  This test
        /// would have same results if alice were a coinbase recipient instead.
        ///
        /// variations:
        ///   change_notify_medium: alice can choose OnChain or OffChain utxo notification.
        ///   change_key_type:    alice's change key can be Symmetric or Generation
        ///
        /// outcomes:
        ///   onchain/symmetric:    balance: 9.  no funds loss.
        ///   onchain/generation:   balance: 9.  no funds loss.
        ///   offchain/symmetric:   balance: 0. all funds lost!
        ///   offchain/generation:  balance: 0. all funds lost!
        ///
        /// this function expects the above possible outcomes.  ie, it passes when
        /// it encounters those outcomes.
        ///
        /// These outcomes highlight the danger of using off-chain notification.
        /// Even though alice stored her seed safely offline she still loses all her
        /// funds.
        ///
        /// It is important to recognize that alice's hard drive may crash (or
        /// device stolen, etc) at any moment after she sends the transaction.  If
        /// it happens 10 minutes after the transaction its unlikely she would have
        /// a wallet backup.  Or it could happen years after the transaction,
        /// demonstrating that alice's wallet needs to be backed up in perpetuity.
        ///
        /// From this, we conclude that the only way alice could really use offchain
        /// notification safely is if her wallet is stored on some kind of redundant
        /// storage media that is expected to exist in perpetuity.
        ///
        /// Since most people do not have home raid arrays and regular backup
        /// schedules it seems that offchain notifications are best suited for
        /// scenarios where the wallet is stored encrypted on some kind of cloud
        /// storage, whether centralized or decentralized.
        ///
        /// It may also be a business opportunity for hardware vendors to sell
        /// redundant-storage-in-a-box to users that want to use offchain
        /// notification but keep their wallets local.
        async fn change_exists(
            change_notification_medium: UtxoNotificationMedium,
            change_key_type: KeyType,
        ) {
            // setup initial conditions
            let network = Network::Main;
            let mut rng = StdRng::seed_from_u64(10001);

            let genesis_block = Block::genesis(network);
            let launch = genesis_block.kernel.header.timestamp;
            let seven_months_post_launch = launch + Timestamp::months(7);

            // amounts used in alice-to-bob transaction.
            let alice_to_bob_amount = NativeCurrencyAmount::coins(10);
            let alice_to_bob_fee = NativeCurrencyAmount::coins(1);

            // init global state for alice bob
            let cli_args = cli_args::Args::default_with_network(network);
            let mut alice_state_lock =
                mock_genesis_global_state(3, WalletEntropy::devnet_wallet(), cli_args.clone())
                    .await;
            let mut bob_state_lock = mock_genesis_global_state(
                3,
                WalletEntropy::new_pseudorandom(rng.random()),
                cli_args.clone(),
            )
            .await;
            let charlie_state_lock = mock_genesis_global_state(
                3,
                WalletEntropy::new_pseudorandom(rng.random()),
                cli_args.clone(),
            )
            .await;

            // in bob wallet: create receiving address for bob
            let bob_address = {
                bob_state_lock
                    .lock_guard_mut()
                    .await
                    .wallet_state
                    .next_unused_spending_key(KeyType::Generation)
                    .await
                    .to_address()
            };

            // in alice wallet: send pre-mined funds to bob
            let block_1 = {
                // store and verify alice's initial balance from pre-mine.
                let alice_initial_balance = alice_state_lock
                    .lock_guard()
                    .await
                    .get_wallet_status_for_tip()
                    .await
                    .available_confirmed(seven_months_post_launch);
                assert_eq!(alice_initial_balance, NativeCurrencyAmount::coins(20));

                // create change key for alice. change_key_type is a test param.
                let alice_change_key = alice_state_lock
                    .lock_guard_mut()
                    .await
                    .wallet_state
                    .next_unused_spending_key(change_key_type)
                    .await;

                // create an output for bob, worth 20.
                let outputs = vec![(
                    bob_address,
                    alice_to_bob_amount,
                    UtxoNotificationMedium::OnChain,
                )];
                let tx_outputs = alice_state_lock
                    .api()
                    .tx_initiator()
                    .generate_tx_outputs(outputs)
                    .await;
                let outputs_len = tx_outputs.len();

                // create tx.  utxo_notify_method is a test param.
                let config = TxCreationConfig::default()
                    .recover_to_provided_key(Arc::new(alice_change_key), change_notification_medium)
                    .with_prover_capability(TxProvingCapability::SingleProof);
                let block_height = BlockHeight::genesis();
                let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);
                let artifacts = alice_state_lock
                    .api()
                    .tx_initiator_internal()
                    .create_transaction(
                        tx_outputs.clone(),
                        alice_to_bob_fee,
                        seven_months_post_launch,
                        config,
                        consensus_rule_set,
                    )
                    .await
                    .unwrap();
                let alice_to_bob_tx = artifacts.transaction;
                assert_eq!(
                    artifacts.details.tx_outputs.len(),
                    outputs_len + 1,
                    "A change Tx-output was expected"
                );

                // Inform alice wallet of any expected incoming utxos.
                // note: no-op when all utxo notifications are sent on-chain.
                let expected_utxo = alice_state_lock
                    .lock_guard()
                    .await
                    .wallet_state
                    .extract_expected_utxos(
                        artifacts.details.tx_outputs.iter(),
                        UtxoNotifier::Myself,
                    );
                alice_state_lock
                    .lock_guard_mut()
                    .await
                    .wallet_state
                    .add_expected_utxos(expected_utxo)
                    .await;

                // the block gets mined.
                // Charlie mines the block so that Alice's wallet is not
                // complicated by composer fees.
                let (block_1_tx, _) = create_block_transaction_from(
                    &genesis_block,
                    charlie_state_lock,
                    seven_months_post_launch,
                    (TritonVmJobPriority::Normal, None).into(),
                    TxMergeOrigin::ExplicitList(vec![Arc::into_inner(alice_to_bob_tx).unwrap()]),
                )
                .await
                .unwrap();
                let block_1 = Block::compose(
                    &genesis_block,
                    block_1_tx,
                    seven_months_post_launch,
                    TritonVmJobQueue::get_instance(),
                    TritonVmJobPriority::default().into(),
                )
                .await
                .unwrap();

                // alice's node learns of the new block.
                alice_state_lock
                    .lock_guard_mut()
                    .await
                    .set_new_tip(block_1.clone())
                    .await
                    .unwrap();

                // alice should have 2 monitored utxos.
                assert_eq!(
                    2,
                    alice_state_lock
                    .lock_guard()
                    .await
                        .wallet_state
                        .wallet_db
                        .monitored_utxos()
                        .len().await, "Alice must have 2 UTXOs after block 1: change from transaction, and the spent premine UTXO"
                );

                // Now alice should have a balance of 9.
                // balance = premine - spent = premine - sent - fee = 20 - 10 - 1
                let alice_calculated_balance = alice_initial_balance
                    .checked_sub(&alice_to_bob_amount)
                    .unwrap()
                    .checked_sub(&alice_to_bob_fee)
                    .unwrap();
                assert_eq!(alice_calculated_balance, NativeCurrencyAmount::coins(9));

                assert_eq!(
                    alice_calculated_balance,
                    alice_state_lock
                        .lock_guard()
                        .await
                        .get_wallet_status_for_tip()
                        .await
                        .available_confirmed(seven_months_post_launch)
                );

                block_1
            };

            // in bob's wallet
            {
                let mut bob_state_mut = bob_state_lock.lock_guard_mut().await;

                // bob's node adds block1 to the chain.
                bob_state_mut.set_new_tip(block_1.clone()).await.unwrap();

                // Now Bob should have a balance of 10, from Alice
                assert_eq!(
                    alice_to_bob_amount, // 10
                    bob_state_mut
                        .get_wallet_status_for_tip()
                        .await
                        .available_confirmed(seven_months_post_launch)
                );
            }

            // some time in the future.  minutes, months, or years...

            // oh no!  alice's hard-drive crashes and she loses her wallet.
            drop(alice_state_lock);

            // Fortunately alice still has her seed that she can restore from.
            {
                // devnet_wallet() stands in for alice's seed.
                let mut alice_restored_state_lock = mock_genesis_global_state(
                    3,
                    WalletEntropy::devnet_wallet(),
                    cli_args::Args::default_with_network(network),
                )
                .await;

                let mut alice_state_mut = alice_restored_state_lock.lock_guard_mut().await;

                // ensure alice's wallet knows about the first key of each type.
                // for a real restore, we should generate perhaps 1000 of each.
                let _ = alice_state_mut
                    .wallet_state
                    .next_unused_spending_key(KeyType::Generation)
                    .await;
                let _ = alice_state_mut
                    .wallet_state
                    .next_unused_spending_key(KeyType::Symmetric)
                    .await;

                // check alice's initial balance after genesis.
                let alice_initial_balance = alice_state_mut
                    .get_wallet_status_for_tip()
                    .await
                    .available_confirmed(seven_months_post_launch);

                // lucky alice's wallet begins with 20 balance from premine.
                assert_eq!(alice_initial_balance, NativeCurrencyAmount::coins(20));

                // now alice must replay old blocks.  (there's only one so far)
                alice_state_mut.set_new_tip(block_1).await.unwrap();

                // Now alice should have a balance of 9.
                // 20 from premine - 11
                let alice_calculated_balance = alice_initial_balance
                    .checked_sub(&alice_to_bob_amount)
                    .unwrap()
                    .checked_sub(&alice_to_bob_fee)
                    .unwrap();

                assert_eq!(alice_calculated_balance, NativeCurrencyAmount::coins(9));

                // For onchain change-notification the balance will be 9.
                // For offchain change-notification, it will be 0.  Funds are lost!!!
                let alice_expected_balance_by_method = match change_notification_medium {
                    UtxoNotificationMedium::OnChain => NativeCurrencyAmount::coins(9),
                    UtxoNotificationMedium::OffChain => NativeCurrencyAmount::coins(0),
                };

                // verify that our on/offchain prediction is correct.
                assert_eq!(
                    alice_expected_balance_by_method,
                    alice_state_mut
                        .get_wallet_status_for_tip()
                        .await
                        .available_confirmed(seven_months_post_launch)
                );
            }
        }
    }
}
