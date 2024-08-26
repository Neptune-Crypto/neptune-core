pub mod archival_state;
pub mod blockchain_state;
pub mod light_state;
pub mod mempool;
pub mod networking_state;
pub mod shared;
pub mod wallet;

use std::cmp::max;
use std::ops::Deref;
use std::ops::DerefMut;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use blockchain_state::BlockchainState;
use itertools::Itertools;
use mempool::Mempool;
use networking_state::NetworkingState;
use num_traits::CheckedSub;
use serde::Deserialize;
use serde::Serialize;
use tracing::debug;
use tracing::info;
use tracing::warn;
use twenty_first::math::digest::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use wallet::address::KeyType;
use wallet::address::ReceivingAddress;
use wallet::address::SpendingKey;
use wallet::expected_utxo::UtxoNotifier;
use wallet::utxo_transfer::UtxoTransferEncrypted;
use wallet::wallet_state::WalletState;
use wallet::wallet_status::WalletStatus;

use crate::config_models::cli_args;
use crate::database::storage::storage_schema::traits::StorageWriter as SW;
use crate::database::storage::storage_vec::traits::*;
use crate::database::storage::storage_vec::Index;
use crate::locks::tokio as sync_tokio;
use crate::models::blockchain::block::block_selector::BlockSelector;
use crate::models::blockchain::transaction::AnnouncedUtxo;
use crate::models::blockchain::transaction::OwnedUtxoNotifyMethod;
use crate::models::blockchain::transaction::UnownedUtxoNotifyMethod;
use crate::models::peer::HandshakeData;
use crate::models::state::wallet::expected_utxo::ExpectedUtxo;
use crate::models::state::wallet::monitored_utxo::MonitoredUtxo;
use crate::prelude::twenty_first;
use crate::time_fn_call_async;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::Hash;
use crate::VERSION;

use super::blockchain::block::block_height::BlockHeight;
use super::blockchain::block::Block;
use super::blockchain::transaction::primitive_witness::PrimitiveWitness;
use super::blockchain::transaction::primitive_witness::SaltedUtxos;
use super::blockchain::transaction::transaction_kernel::TransactionKernel;
use super::blockchain::transaction::validity::TransactionValidationLogic;
use super::blockchain::transaction::Transaction;
use super::blockchain::transaction::TxAddressOutput;
use super::blockchain::transaction::TxInputList;
use super::blockchain::transaction::TxOutput;
use super::blockchain::transaction::TxOutputList;
use super::blockchain::transaction::TxParams;
use super::blockchain::type_scripts::native_currency::NativeCurrency;
use super::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use super::blockchain::type_scripts::time_lock::TimeLock;
use super::blockchain::type_scripts::TypeScript;
use super::consensus::tasm::program::ConsensusProgram;
use super::consensus::timestamp::Timestamp;

/// `GlobalStateLock` holds a [`tokio::AtomicRw`](crate::locks::tokio::AtomicRw)
/// ([`RwLock`](std::sync::RwLock)) over [`GlobalState`].
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
/// when run with `RUST_LOG='info,neptune_core=trace'`.
///
/// If a deadlock has occurred, the log will end with a `TryAcquire` event
/// (read or write) and just scroll up to find the previous `Acquire` for
/// write event to see which thread is holding the lock.
#[derive(Debug, Clone)]
pub struct GlobalStateLock {
    global_state_lock: sync_tokio::AtomicRw<GlobalState>,

    /// The `cli_args::Args` are read-only and accessible by all tasks/threads.
    cli: cli_args::Args,
}

impl GlobalStateLock {
    pub fn new(
        wallet_state: WalletState,
        chain: BlockchainState,
        net: NetworkingState,
        cli: cli_args::Args,
        mempool: Mempool,
        mining: bool,
    ) -> Self {
        let global_state = GlobalState::new(wallet_state, chain, net, cli.clone(), mempool, mining);
        let global_state_lock = sync_tokio::AtomicRw::from((
            global_state,
            Some("GlobalState"),
            Some(crate::LOG_TOKIO_LOCK_EVENT_CB),
        ));

        Self {
            global_state_lock,
            cli,
        }
    }

    // check if mining
    pub async fn mining(&self) -> bool {
        self.lock(|s| s.mining).await
    }

    // enable or disable mining
    pub async fn set_mining(&mut self, mining: bool) {
        self.lock_mut(|s| s.mining = mining).await
    }

    // persist wallet state to disk
    pub async fn persist_wallet(&mut self) -> Result<()> {
        self.lock_guard_mut().await.persist_wallet().await
    }

    // flush databases (persist to disk)
    pub async fn flush_databases(&mut self) -> Result<()> {
        self.lock_guard_mut().await.flush_databases().await
    }

    /// store a coinbase (self-mined) block
    pub async fn store_coinbase_block(
        &mut self,
        new_block: Block,
        coinbase_utxo_info: ExpectedUtxo,
    ) -> Result<()> {
        self.lock_guard_mut()
            .await
            .set_new_self_mined_tip(new_block, coinbase_utxo_info)
            .await
    }

    /// store a block (non coinbase)
    pub async fn store_block(&mut self, new_block: Block) -> Result<()> {
        self.lock_guard_mut().await.set_new_tip(new_block).await
    }

    /// resync membership proofs
    pub async fn resync_membership_proofs(&mut self) -> Result<()> {
        self.lock_guard_mut().await.resync_membership_proofs().await
    }

    /// retrieve wallet status data for tip block
    pub async fn get_wallet_status_for_tip(&self) -> WalletStatus {
        self.lock_guard().await.get_wallet_status_for_tip().await
    }

    pub async fn prune_abandoned_monitored_utxos(
        &mut self,
        block_depth_threshhold: usize,
    ) -> Result<usize> {
        self.lock_guard_mut()
            .await
            .prune_abandoned_monitored_utxos(block_depth_threshhold)
            .await
    }

    #[inline]
    pub fn cli(&self) -> &cli_args::Args {
        &self.cli
    }

    // Only for tests to simulate different CLI params.
    #[cfg(test)]
    pub async fn set_cli(&mut self, cli: cli_args::Args) {
        self.lock_guard_mut().await.cli = cli.clone();
        self.cli = cli;
    }

    /// Generate tx params for use by `create_transaction()` and `send()`
    ///
    /// This method simplifies building [TxParam].  It should be used
    /// when the following are true:
    ///  * each output is sent to a `ReceivingAddress`
    ///  * each output sends a non-zero amount of native coins.
    ///  * all unowned outputs can have the same notification policy
    ///  * all owned outputs can have the same notification policy
    ///  * a change output should be created
    ///  * the change spending key can be a `SymmetricKey`
    ///  * no non-native coins or custom lockscripts are used.
    ///
    /// Otherwise, the [TxParam] must be generated some other way.
    ///
    /// params:
    ///  + outputs: a list of (ReceivingAddress,amount) where amount is > 0.
    ///  + fee: mining fee.  (must be >= 0)
    ///  + owned_utxo_notify_method: notification mechanism for self-owned outputs, including change.
    ///  + unowned_utxo_notify_method: notification mechanism for 3rd party outputs
    ///
    /// returns:
    ///  + [TxParams]: transaction parameters for send() and create_transaction()
    ///  + Vec<[TxOutputMeta]>: list of output metadata, one per output in TxParams::tx_output_list().
    ///
    /// The output metadata is provided to enable the caller to match [TxOutput] in tx_output_list
    /// with the [ReceivingAddress] that were provided as input, as well as an automatically generated
    /// change address.  It is guaranteed that the length and order of the output metadata is the
    /// same as TxOutput::tx_output_list(), so the two can be zip'ed together.
    pub async fn generate_tx_params(
        &mut self,
        outputs: Vec<TxAddressOutput>,
        fee: NeptuneCoins,
        owned_utxo_notify_method: OwnedUtxoNotifyMethod,
        unowned_utxo_notify_method: UnownedUtxoNotifyMethod,
    ) -> Result<(TxParams, Vec<TxOutputMeta>)> {
        // obtain next unused symmetric key for change utxo
        let change_key = {
            let mut s = self.lock_guard_mut().await;
            let key = s.wallet_state.next_unused_spending_key(KeyType::Symmetric);

            // write state to disk. create_transaction() may be slow.
            s.persist_wallet().await.expect("flushed");
            key
        };

        self.lock_guard()
            .await
            .generate_tx_params(
                outputs,
                change_key,
                fee,
                owned_utxo_notify_method,
                unowned_utxo_notify_method,
                Timestamp::now(),
            )
            .await
    }

    /// Send coins to 1 or more recipients
    ///
    /// `tx_params` contains inputs and outputs, typically created
    /// by [Self::generate_tx_params].
    ///
    /// returns: a [Transaction] upon success, else [None].
    pub async fn send(&mut self, tx_params: TxParams) -> Result<Transaction> {
        let tx_output_list = tx_params.tx_output_list().clone();

        // Create the transaction
        //
        // Note that create_transaction() does not modify any state and only
        // requires acquiring a read-lock which does not block other tasks.
        // This is important because internally it calls prove() which is a very
        // lengthy operation.
        //
        // note: A change output will be added to tx_outputs if needed.
        let transaction = self
            .lock_guard()
            .await
            .create_transaction(tx_params)
            .await?;

        // acquire write-lock
        let mut gsm = self.lock_guard_mut().await;

        // insert transaction into mempool
        if gsm.mempool.insert(&transaction).is_some() {
            bail!("the transaction attempts to spend inputs already spent by another transaction in the mempool with a higher fee. try increasing the fee.");
        }

        // if the tx created offchain expected_utxos we must inform wallet.
        if tx_output_list.has_offchain() {
            // Inform wallet of any expected incoming utxos.
            // note that this (briefly) mutates self.
            gsm.add_expected_utxos_to_wallet(tx_output_list.expected_utxos_iter())
                .await?;

            // ensure we write new wallet state out to disk.
            gsm.persist_wallet().await.expect("flushed wallet");
        }

        Ok(transaction)
    }

    /// claim a utxo
    ///
    /// The input string must be a valid bech32m encoded `UtxoTransferEncrypted`
    /// for the current network and the wallet must have the corresponding
    /// `SpendingKey` for decryption.
    ///
    /// upon success, a new `ExpectedUtxo` will be added to the local wallet
    /// state.
    ///
    /// if the utxo has already been claimed, an error will result.
    pub async fn claim_utxo(&mut self, utxo_transfer_encrypted_str: String) -> Result<()> {
        // deserialize UtxoTransferEncrypted from bech32m string.
        let utxo_transfer_encrypted =
            UtxoTransferEncrypted::from_bech32m(&utxo_transfer_encrypted_str, self.cli().network)?;

        // acquire global state read lock
        let state = self.lock_guard().await;

        // find known spending key by receiver_identifier
        let spending_key = state
            .wallet_state
            .find_known_spending_key_for_receiver_identifier(
                utxo_transfer_encrypted.receiver_identifier,
            )
            .ok_or(anyhow!("utxo does not match any known wallet key"))?;

        // decrypt utxo_transfer_encrypted into UtxoTransfer
        let utxo_transfer = utxo_transfer_encrypted.decrypt_with_spending_key(&spending_key)?;

        tracing::debug!("claim-utxo: decrypted {:#?}", utxo_transfer);

        // search for matching monitored utxo and return early if found.
        if state
            .wallet_state
            .find_monitored_utxo(&utxo_transfer.utxo)
            .await
            .is_some()
        {
            info!("found monitored utxo.  returning early.");
            return Ok(());
        }

        // construct an AnnouncedUtxo
        let announced_utxo = AnnouncedUtxo {
            utxo: utxo_transfer.utxo,
            sender_randomness: utxo_transfer.sender_randomness,
            receiver_preimage: spending_key.privacy_preimage(),
        };

        // check if wallet is already expecting this utxo.
        let has_expected_utxo = state
            .wallet_state
            .has_expected_utxo(&(announced_utxo.clone(), UtxoNotifier::Claim).into())
            .await;

        // look for a canonical block that has this utxo as an output
        let maybe_prepared_claim = match state
            .chain
            .archival_state()
            .find_canonical_block_with_output(
                announced_utxo.addition_record(),
                BlockSelector::Genesis,
            )
            .await
        {
            Some(b) => {
                // get a stream for retrieving blocks from parent(b) .. tip.
                // perf: fast. this only returns the stream, it doesn't iterate it.
                let block_stream = state
                    .chain
                    .archival_state()
                    .canonical_block_stream_asc(
                        BlockSelector::Digest(b.header().prev_block_digest),
                        BlockSelector::Tip,
                    )
                    .await;

                // prepare a claim.
                // perf: this is potentially lengthy as it iterates over all blocks
                //       in the stream and also generates utxo membership proofs for each.
                let prepared_claim = state
                    .wallet_state
                    .prepare_claim_utxo_in_block(announced_utxo.clone(), block_stream)
                    .await?;

                Some(prepared_claim)
            }
            None => None,
        };

        // release global state read lock
        drop(state);

        // we only acquire write-lock if the utxo is already confirmed
        // in a block or the wallet does not have the expected_utxo
        if maybe_prepared_claim.is_some() || !has_expected_utxo {
            // acquire global state write-lock
            let mut gsm = self.lock_guard_mut().await;

            // add expected_utxo to wallet if not existing.
            //
            // note: we add it even if block is already confirmed, although not
            //       required for claiming. This is just so that we have it in the
            //       wallet for consistency and backup.
            if !has_expected_utxo {
                gsm.add_expected_utxos_to_wallet([
                    (announced_utxo.clone(), UtxoNotifier::Claim).into()
                ])
                .await?;
            };

            // write prepared claim if utxo was already confirmed in a block.
            if let Some(prepared_claim) = maybe_prepared_claim {
                gsm.wallet_state
                    .finalize_claim_utxo_in_block(prepared_claim)
                    .await?;
            }

            // ensure we write new wallet state out to disk.
            gsm.persist_wallet().await.expect("flushed wallet");
        }

        Ok(())
    }

    pub async fn next_spending_key(&mut self, key_type: KeyType) -> SpendingKey {
        self.lock_guard_mut()
            .await
            .next_spending_key(key_type)
            .await
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

/// `GlobalState` handles all state of a Neptune node that is shared across its tasks.
///
/// Some fields are only written to by certain tasks.
#[derive(Debug)]
pub struct GlobalState {
    /// The `WalletState` may be updated by the main task and the RPC server.
    pub wallet_state: WalletState,

    /// The `BlockchainState` may only be updated by the main task.
    pub chain: BlockchainState,

    /// The `NetworkingState` may be updated by both the main task and peer tasks.
    pub net: NetworkingState,

    /// The `cli_args::Args` are read-only and accessible by all tasks.
    cli: cli_args::Args,

    /// The `Mempool` may only be updated by the main task.
    pub mempool: Mempool,

    // Only the mining task should write to this, anyone can read.
    pub mining: bool,
}

impl GlobalState {
    pub fn new(
        wallet_state: WalletState,
        chain: BlockchainState,
        net: NetworkingState,
        cli: cli_args::Args,
        mempool: Mempool,
        mining: bool,
    ) -> Self {
        Self {
            wallet_state,
            chain,
            net,
            cli,
            mempool,
            mining,
        }
    }

    pub async fn get_wallet_status_for_tip(&self) -> WalletStatus {
        let tip_digest = self.chain.light_state().hash();
        self.wallet_state.get_wallet_status(tip_digest).await
    }

    pub async fn get_latest_balance_height(&self) -> Option<BlockHeight> {
        let (height, time_secs) =
            time_fn_call_async(self.get_latest_balance_height_internal()).await;

        debug!("call to get_latest_balance_height() took {time_secs} seconds");

        height
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

        let stream = monitored_utxos
            .stream_many_values((0..monitored_utxos.len().await).rev())
            .await;
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
    pub async fn get_balance_history(&self) -> Vec<(Digest, Timestamp, BlockHeight, NeptuneCoins)> {
        let current_tip_digest = self.chain.light_state().hash();

        let monitored_utxos = self.wallet_state.wallet_db.monitored_utxos();

        // let num_monitored_utxos = monitored_utxos.len();
        let mut history = vec![];

        let stream = monitored_utxos.stream_values().await;
        pin_mut!(stream); // needed for iteration
        while let Some(monitored_utxo) = stream.next().await {
            if monitored_utxo
                .get_membership_proof_for_block(current_tip_digest)
                .is_none()
            {
                continue;
            }

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
                    history.push((spending_block, spending_timestamp, spending_height, -amount));
                }
            }
        }
        history
    }

    /// Generate a primitive witness for a transaction from various disparate witness data.
    pub fn generate_primitive_witness(
        tx_inputs: &TxInputList,
        tx_outputs: &TxOutputList,
        transaction_kernel: TransactionKernel,
        mutator_set_accumulator: MutatorSetAccumulator,
    ) -> PrimitiveWitness {
        let type_scripts = [NativeCurrency.program(), TimeLock.program()]
            .map(TypeScript::new)
            .to_vec();

        PrimitiveWitness {
            input_utxos: SaltedUtxos::new(tx_inputs.utxos()),
            input_lock_scripts: tx_inputs.lock_scripts(),
            type_scripts,
            lock_script_witnesses: tx_inputs.lock_script_witnesses(),
            input_membership_proofs: tx_inputs.ms_membership_proofs(),
            output_utxos: SaltedUtxos::new(tx_outputs.utxos()),
            mutator_set_accumulator,
            kernel: transaction_kernel,
        }
    }

    /// generates [TxOutputList] from a list of address:amount pairs (outputs).
    ///
    /// This is a helper method for generating the `TxOutputList` that
    /// is required by [Self::create_transaction()] and [Self::create_raw_transaction()].
    ///
    /// Each output may use either `OnChain` or `OffChain` notifications.  See documentation of
    /// of [TxOutput::auto()] for a description of the logic and the
    /// `owned_utxo_notify_method` parameter.
    ///
    /// If a different behavior is desired, the TxOutputList can be
    /// constructed manually.
    ///
    /// future work:
    ///
    /// see future work comment in [TxOutput::auto()]
    pub fn generate_tx_outputs<'a>(
        &self,
        outputs: impl Iterator<Item = &'a (ReceivingAddress, NeptuneCoins)>,
        owned_utxo_notify_method: OwnedUtxoNotifyMethod,
        unowned_utxo_notify_method: UnownedUtxoNotifyMethod,
    ) -> Result<TxOutputList> {
        let block_height = self.chain.light_state().header().height;

        // Convert outputs.  [address:amount] --> TxOutputList
        let tx_outputs: Vec<_> = outputs
            .map(|(address, amount)| {
                let sender_randomness = self
                    .wallet_state
                    .wallet_secret
                    .generate_sender_randomness(block_height, address.privacy_digest());

                // The UtxoNotifyMethod (Onchain or Offchain) is auto-detected
                // based on whether the address belongs to our wallet or not
                TxOutput::auto(
                    &self.wallet_state,
                    address,
                    *amount,
                    sender_randomness,
                    owned_utxo_notify_method,
                    unowned_utxo_notify_method,
                )
            })
            .collect::<Result<_>>()?;

        Ok(tx_outputs.into())
    }

    /// Generates TxParams (including change output) from an
    /// existing TxOutputList that represents all outputs except for the change
    /// output.
    ///
    /// This is useful when ReceivingAddress is not available, such as when
    /// creating output Utxo directly from lockscripts or using non-native
    /// coins/tokens.  Otherwise [generate_tx_params()] is preferred.
    pub async fn generate_tx_params_from_tx_outputs(
        &self,
        mut tx_output_list: TxOutputList,
        change_key: SpendingKey,
        change_utxo_notify_method: OwnedUtxoNotifyMethod,
        fee: NeptuneCoins,
        timestamp: Timestamp,
    ) -> Result<TxParams> {
        let total_spend = tx_output_list.total_native_coins() + fee;
        let tip_hash = self.chain.light_state().hash();

        // collect spendable inputs
        let tx_input_list = self
            .wallet_state
            .allocate_sufficient_input_funds_at_timestamp(total_spend, tip_hash, timestamp)
            .await?;

        let input_amount = tx_input_list.total_native_coins();

        if total_spend < input_amount {
            let change_amount = input_amount.checked_sub(&total_spend).ok_or_else(|| {
                anyhow::anyhow!("underflow subtracting total_spend from input_amount")
            })?;

            let change_outputs = [(change_key.to_address(), change_amount)];
            let mut change_output_list = self.generate_tx_outputs(
                change_outputs.iter(),
                change_utxo_notify_method,
                UnownedUtxoNotifyMethod::OnChain,
            )?;

            assert_eq!(change_output_list.len(), 1);

            tx_output_list.append(&mut change_output_list);
        }

        Ok(TxParams::new(tx_input_list, tx_output_list)?)
    }

    /// see [GlobalStateLock::generate_tx_params()]
    ///
    /// the difference here is that caller must/may supply a change_key.
    pub async fn generate_tx_params(
        &self,
        mut outputs: Vec<TxAddressOutput>,
        change_key: SpendingKey,
        fee: NeptuneCoins,
        owned_utxo_notify_method: OwnedUtxoNotifyMethod,
        unowned_utxo_notify_method: UnownedUtxoNotifyMethod,
        timestamp: Timestamp,
    ) -> Result<(TxParams, Vec<TxOutputMeta>)> {
        let total_spend = outputs
            .iter()
            .map(|(_, amount)| *amount)
            .sum::<NeptuneCoins>()
            + fee;
        let tip_hash = self.chain.light_state().hash();

        // collect spendable inputs
        let tx_input_list = self
            .wallet_state
            .allocate_sufficient_input_funds_at_timestamp(total_spend, tip_hash, timestamp)
            .await?;

        let input_amount = tx_input_list.total_native_coins();

        if total_spend < input_amount {
            let change_amount = input_amount.checked_sub(&total_spend).ok_or_else(|| {
                anyhow::anyhow!("underflow subtracting total_spend from input_amount")
            })?;

            outputs.push((change_key.to_address(), change_amount));
        }

        let tx_output_list = self.generate_tx_outputs(
            outputs.iter(),
            owned_utxo_notify_method,
            unowned_utxo_notify_method,
        )?;

        assert_eq!(tx_output_list.len(), outputs.len());

        let tx_output_meta_list = outputs
            .into_iter()
            .map(|(addr, _)| TxOutputMeta {
                self_owned: self
                    .wallet_state
                    .find_known_spending_key_for_receiving_address(&addr)
                    .is_some(),
                receiving_address: addr,
            })
            .collect_vec();

        let tx_params = TxParams::new_with_timestamp(tx_input_list, tx_output_list, timestamp)?;

        Ok((tx_params, tx_output_meta_list))
    }

    /// creates a Transaction.
    ///
    /// This API provides the caller complete control over selection of inputs
    /// and outputs.
    ///
    /// It is the caller's responsibility to provide inputs and outputs such
    /// that sum(inputs) == sum(outputs) + fee.  Else an error will result.
    ///
    /// Note that this means the caller must calculate the `change` amount if any
    /// and provide an output for the change.
    ///
    /// The `tx_params` parameter should normally be generated with
    /// [Self::generate_tx_params()] which selects inputs and creates change
    /// output
    ///
    /// After this call returns it is the caller's responsibility to inform the
    /// wallet of any returned [ExpectedUtxo] for utxos that match wallet keys.
    /// Failure to do so can result in loss of funds!
    ///
    /// Note that `create_transaction()` does not modify any state and does
    /// not require acquiring write lock.  This is important becauce internally
    /// it calls prove() which is a very lengthy operation.
    ///
    /// Example:
    ///
    /// ```compile_fail
    ///
    /// let addr = ReceivingAddress::from(GenerationReceivingAddress::derive_from_seed(rand::random()));
    /// let outputs = vec![(addr, NeptuneCoins::new(1))];
    ///
    ///    // obtain next unused symmetric key for change utxo
    ///    let change_key = {
    ///        let mut s = global_state_lock.lock_guard_mut().await;
    ///        let key = s.wallet_state.next_unused_spending_key(KeyType::Symmetric);
    ///
    ///        // write state to disk. create_transaction() may be slow.
    ///        s.persist_wallet().await.expect("flushed");
    ///        key
    ///    };
    ///
    ///    let state = global_state_lock.lock_guard().await;
    ///    let (tx_params, _) = state
    ///        .generate_tx_params(
    ///            outputs,
    ///            change_key,
    ///            NeptuneCoins::zero(),    // fee,
    ///            Default::default(),      // owned_utxo_notify_method,
    ///            Default::default(),      // unowned_utxo_notify_method,
    ///            Timestamp::now(),
    ///        )
    ///        .await
    ///        .map_err(|e| e.to_string())
    ///
    ///    let transaction = state
    ///        .create_transaction(tx_params.clone())
    ///        .await
    ///        .map_err(|e| e.to_string())?;
    ///
    ///    drop(state);
    ///
    ///    // write any off-chain notifications to disk
    ///    if tx_params.tx_output_list.has_offchain() {
    ///        // acquire write-lock
    ///        let mut gsm = state_state_lock.lock_guard_mut().await;
    ///
    ///        // Inform wallet of any expected incoming utxos.
    ///        // note that this (briefly) mutates self.
    ///        gsm.add_expected_utxos_to_wallet(tx_output_list.expected_utxos_iter())
    ///            .await
    ///            .map_err(|e| e.to_string())?;
    ///    }
    /// ```
    pub async fn create_transaction(&self, tx_params: TxParams) -> Result<Transaction> {
        let mutator_set_accumulator = self
            .chain
            .light_state()
            .kernel
            .body
            .mutator_set_accumulator
            .clone();
        let privacy = self.cli().privacy;

        // note: this executes the prover which can take a very
        //       long time, perhaps minutes.  As such, we use
        //       spawn_blocking() to execute on tokio's blocking
        //       threadpool and avoid blocking the tokio executor
        //       and other async tasks.
        let transaction = tokio::task::spawn_blocking(move || {
            Self::create_transaction_worker(tx_params, mutator_set_accumulator, privacy)
        })
        .await?;
        Ok(transaction)
    }

    /// This is a simple wrapper around create_transaction
    /// for compatibility with existing tests.
    #[cfg(test)]
    pub async fn create_transaction_test_wrapper(
        &self,
        tx_output_vec: Vec<TxOutput>,
        fee: NeptuneCoins,
        timestamp: Timestamp,
    ) -> Result<(Transaction, Vec<ExpectedUtxo>)> {
        // note: should use next_unused_generation_spending_key()
        // but that requires &mut self.
        let change_key = self
            .wallet_state
            .wallet_secret
            .nth_symmetric_key_for_tests(0);

        let tx_params = self
            .generate_tx_params_from_tx_outputs(
                tx_output_vec.into(),
                change_key.into(),
                OwnedUtxoNotifyMethod::OffChain,
                fee,
                timestamp,
            )
            .await?;

        let transaction = self.create_transaction(tx_params.clone()).await?;

        Ok((transaction, (tx_params.tx_output_list()).into()))
    }

    // note: this executes the prover which can take a very
    //       long time, perhaps minutes. It should never be
    //       called directly.
    //       Use create_transaction_from_data() instead.
    //
    // fixme: why is _privacy param unused?
    fn create_transaction_worker(
        tx_params: TxParams,
        mutator_set_accumulator: MutatorSetAccumulator,
        _privacy: bool,
    ) -> Transaction {
        // complete transaction kernel
        let kernel = TransactionKernel {
            inputs: tx_params
                .tx_input_list()
                .removal_records(&mutator_set_accumulator),
            outputs: tx_params.tx_output_list().addition_records(),
            public_announcements: tx_params.tx_output_list().public_announcements(),
            fee: tx_params.fee(),
            timestamp: *tx_params.timestamp(),
            coinbase: None,
            mutator_set_hash: mutator_set_accumulator.hash(),
        };

        // populate witness
        let primitive_witness = Self::generate_primitive_witness(
            tx_params.tx_input_list(),
            tx_params.tx_output_list(),
            kernel.clone(),
            mutator_set_accumulator,
        );

        // Convert the validity tree into a single proof.
        // Down the line we want to support proving only the lock scripts, or only
        // the lock scripts and removal records integrity, but nothing else.
        // That's a concern for later though.
        let mut transaction_validity_logic = TransactionValidationLogic::from(primitive_witness);
        transaction_validity_logic.vast.prove();
        transaction_validity_logic.maybe_primitive_witness = None;
        Transaction {
            kernel,
            witness: transaction_validity_logic,
        }
    }

    // If any output UTXO(s) are going back to our wallet (eg change utxo)
    // we add them to pool of expected incoming UTXOs so that we can
    // synchronize them after the Tx is confirmed.
    //
    // Discussion: https://github.com/Neptune-Crypto/neptune-core/pull/136
    pub async fn add_expected_utxos_to_wallet(
        &mut self,
        expected_utxos: impl IntoIterator<Item = ExpectedUtxo>,
    ) -> Result<()> {
        for expected_utxo in expected_utxos.into_iter() {
            self.wallet_state.add_expected_utxo(expected_utxo).await;
        }
        Ok(())
    }

    pub async fn get_own_handshakedata(&self) -> HandshakeData {
        HandshakeData {
            tip_header: self.chain.light_state().header().clone(),
            // TODO: Should be `None` if incoming connections are not accepted
            listen_port: Some(self.cli().peer_port),
            network: self.cli().network,
            instance_id: self.net.instance_id,
            version: VERSION.to_string(),
            // For now, all nodes are archival nodes
            is_archival_node: self.chain.is_archival_node(),
        }
    }

    /// In case the wallet database is corrupted or deleted, this method will restore
    /// monitored UTXO data structures from recovery data. This method should only be
    /// called on startup, not while the program is running, since it will only restore
    /// a wallet state, if the monitored UTXOs have been deleted. Not merely if they
    /// are not synced with a valid mutator set membership proof. And this corruption
    /// can only happen if the wallet database is deleted or corrupted.
    pub(crate) async fn restore_monitored_utxos_from_recovery_data(&mut self) -> Result<()> {
        let tip_hash = self.chain.light_state().hash();
        let ams_ref = &self.chain.archival_state().archival_mutator_set;

        assert_eq!(
            tip_hash,
            ams_ref.get_sync_label().await,
            "Archival mutator set must be synced to tip for successful MUTXO recovery"
        );

        // Fetch all incoming UTXOs from recovery data
        let incoming_utxos = self.wallet_state.read_utxo_ms_recovery_data().await?;
        let incoming_utxo_count = incoming_utxos.len();
        info!("Checking {} incoming UTXOs", incoming_utxo_count);

        // Loop over all `incoming_utxos` and check if they have a corresponding
        // monitored UTXO in the database. All monitored UTXOs are fetched outside
        // of the loop to avoid DB access/IO inside the loop.
        let mut recovery_data_for_missing_mutxos = vec![];

        {
            let stream = self
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .stream_values()
                .await;
            pin_mut!(stream); // needed for iteration

            '_outer: for incoming_utxo in incoming_utxos.into_iter() {
                'inner: while let Some(monitored_utxo) = stream.next().await {
                    if monitored_utxo.utxo == incoming_utxo.utxo {
                        let msmp_res = monitored_utxo.get_latest_membership_proof_entry();
                        let msmp = match msmp_res {
                            Some((_blockh_hash, msmp_val)) => msmp_val,
                            None => continue 'inner,
                        };

                        // If UTXO matches, then check if the AOCL index is also a match.
                        // If it is, then the UTXO is already in the wallet database.
                        if msmp.auth_path_aocl.leaf_index == incoming_utxo.aocl_index {
                            continue '_outer;
                        }
                    }
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
        let current_aocl_leaf_count = ams_ref.ams().aocl.count_leaves().await;
        let mut restored_mutxos = 0;
        for incoming_utxo in recovery_data_for_missing_mutxos {
            // If the referenced UTXO is in the future from our tip, do not attempt to recover it. Instead: warn the user of this.
            if current_aocl_leaf_count <= incoming_utxo.aocl_index {
                warn!("Cannot restore UTXO with AOCL index {} because it is in the future from our tip. Current AOCL leaf count is {current_aocl_leaf_count}. Maybe this UTXO can be recovered once more blocks are downloaded from peers?", incoming_utxo.aocl_index);
                continue;
            }
            let ms_item = Hash::hash(&incoming_utxo.utxo);
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
                        warn!("Restored MSMP is invalid. Skipping restoration of UTXO with AOCL index {}. Maybe this UTXO is on an abandoned chain?", incoming_utxo.aocl_index);
                        continue;
                    }

                    msmp
                }
                Err(err) => bail!("Could not restore MS membership proof. Got: {err}"),
            };

            let mut restored_mutxo =
                MonitoredUtxo::new(incoming_utxo.utxo, self.wallet_state.number_of_mps_per_utxo);
            restored_mutxo.add_membership_proof_for_tip(tip_hash, restored_msmp);

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
                Hash::hash(&monitored_utxo.utxo)
            );

            // If the UTXO was not confirmed yet, there is no
            // point in synchronizing its membership proof.
            let (confirming_block_digest, confirming_block_height) =
                match monitored_utxo.confirmed_in_block {
                    Some((confirmed_block_hash, _timestamp, block_height)) => {
                        (confirmed_block_hash, block_height)
                    }
                    None => {
                        continue;
                    }
                };

            // try latest (block hash, membership proof) entry
            let (block_hash, membership_proof_ref) = monitored_utxo
                .get_latest_membership_proof_entry()
                .expect("Database not in consistent state. Monitored UTXO must have at least one membership proof.");

            let mut membership_proof = membership_proof_ref.to_owned();

            // request path-to-tip
            let (backwards, _luca, forwards) = self
                .chain
                .archival_state()
                .find_path(*block_hash, tip_hash)
                .await;

            // after this point, we may be modifying it.
            let mut monitored_utxo = monitored_utxo.clone();

            // walk backwards, reverting
            for revert_block_hash in backwards.into_iter() {
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
                let maybe_revert_block_predecessor = self
                    .chain
                    .archival_state()
                    .get_block(revert_block.kernel.header.prev_block_digest)
                    .await?;
                let previous_mutator_set = match maybe_revert_block_predecessor {
                    Some(block) => block.kernel.body.mutator_set_accumulator.clone(),
                    None => MutatorSetAccumulator::default(),
                };

                debug!("MUTXO confirmed at height {confirming_block_height}, reverting for height {} on abandoned chain", revert_block.kernel.header.height);

                // revert removals
                let removal_records = revert_block.kernel.body.transaction.kernel.inputs.clone();
                for removal_record in removal_records.iter().rev() {
                    // membership_proof.revert_update_from_removal(&removal);
                    membership_proof
                        .revert_update_from_remove(removal_record)
                        .expect("Could not revert membership proof from removal record.");
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
                    .verify(Hash::hash(&monitored_utxo.utxo), &membership_proof), "Failed to verify monitored UTXO {monitored_utxo:?}\n against previous MSA in block {revert_block:?}");
            }

            // walk forwards, applying
            for apply_block_hash in forwards.into_iter() {
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
                let maybe_apply_block_predecessor = self
                    .chain
                    .archival_state()
                    .get_block(apply_block.kernel.header.prev_block_digest)
                    .await?;
                let mut block_msa = match maybe_apply_block_predecessor {
                    Some(block) => block.kernel.body.mutator_set_accumulator.clone(),
                    None => MutatorSetAccumulator::default(),
                };
                let addition_records = apply_block.kernel.body.transaction.kernel.outputs.clone();
                let removal_records = apply_block.kernel.body.transaction.kernel.inputs.clone();

                // apply additions
                for addition_record in addition_records.iter() {
                    membership_proof
                        .update_from_addition(
                            Hash::hash(&monitored_utxo.utxo),
                            &block_msa,
                            addition_record,
                        )
                        .expect("Could not update membership proof with addition record.");
                    block_msa.add(addition_record);
                }

                // apply removals
                for removal_record in removal_records.iter() {
                    membership_proof
                        .update_from_remove(removal_record)
                        .expect("Could not update membership proof from removal record.");
                    block_msa.remove(removal_record);
                }

                assert_eq!(block_msa, apply_block.kernel.body.mutator_set_accumulator);
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
    /// `block_depth_threshhold`. Use `prune_mutxos_of_unknown_depth = true` to remove MUTXOs from
    /// abandoned chains of unknown depth.
    /// Returns the number of monitored UTXOs removed from the database.
    ///
    /// Locking:
    ///  * acquires `monitored_utxos` lock for write
    pub async fn prune_abandoned_monitored_utxos<'a>(
        &mut self,
        block_depth_threshhold: usize,
    ) -> Result<usize> {
        const MIN_BLOCK_DEPTH_FOR_MUTXO_PRUNING: usize = 10;
        if block_depth_threshhold < MIN_BLOCK_DEPTH_FOR_MUTXO_PRUNING {
            bail!(
                "
                Cannot prune monitored UTXOs with a depth threshold less than
                {MIN_BLOCK_DEPTH_FOR_MUTXO_PRUNING}. Got threshold {block_depth_threshhold}"
            )
        }

        let current_tip_header = self.chain.light_state().header();
        let current_tip_digest = self.chain.light_state().hash();

        let current_tip_info: (Digest, Timestamp, BlockHeight) = (
            current_tip_digest,
            current_tip_header.timestamp,
            current_tip_header.height,
        );

        let monitored_utxos = self.wallet_state.wallet_db.monitored_utxos_mut();
        let mut removed_count = 0;

        // Find monitored_utxo for updating
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

                let abandoned = depth >= block_depth_threshhold as i128
                    && mutxo
                        .was_abandoned(current_tip_digest, self.chain.archival_state())
                        .await;

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
        let hash = self.chain.archival_state().tip().hash();
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

        // flush peer_standings
        self.net.peer_databases.peer_standings.flush().await;

        debug!("Flushed all databases");

        Ok(())
    }

    /// Update client's state with a new block. Block is assumed to be valid, also wrt. to PoW.
    /// The received block will be set as the new tip, regardless of its accumulated PoW.
    pub async fn set_new_tip(&mut self, new_block: Block) -> Result<()> {
        self.set_new_tip_internal(new_block, None).await
    }

    /// Update client's state with a new block that was mined locally. Block is assumed to be valid,
    /// also wrt. to PoW. The received block will be set as the new tip, regardless of its
    /// accumulated PoW.
    pub async fn set_new_self_mined_tip(
        &mut self,
        new_block: Block,
        coinbase_utxo_info: ExpectedUtxo,
    ) -> Result<()> {
        self.set_new_tip_internal(new_block, Some(coinbase_utxo_info))
            .await
    }

    /// Update client's state with a new block. Block is assumed to be valid, also wrt. to PoW.
    /// The received block will be set as the new tip, regardless of its accumulated PoW. or its
    /// validity.
    async fn set_new_tip_internal(
        &mut self,
        new_block: Block,
        coinbase_utxo_info: Option<ExpectedUtxo>,
    ) -> Result<()> {
        // note: we make this fn internal so we can log its duration and ensure it will
        // never be called directly by another fn, without the timings.
        async fn set_new_tip_internal_worker(
            myself: &mut GlobalState,
            new_block: Block,
            coinbase_utxo_info: Option<ExpectedUtxo>,
        ) -> Result<()> {
            // log summary.
            info!("Storing block:\n  height {}:\n  digest: {}\n  timestamp: {}\n  difficulty: {}\n  inputs: {}\n  outputs: {}\n",
                new_block.header().height,
                new_block.hash().to_hex(),
                new_block.header().timestamp.standard_format(),
                new_block.header().difficulty,
                new_block.body().transaction.kernel.inputs.len(),
                new_block.body().transaction.kernel.outputs.len(),
            );

            // Apply the updates
            myself
                .chain
                .archival_state_mut()
                .write_block_as_tip(&new_block)
                .await?;

            // update the mutator set with the UTXOs from this block
            myself
                .chain
                .archival_state_mut()
                .update_mutator_set(&new_block)
                .await?;

            if let Some(coinbase_info) = coinbase_utxo_info {
                // Notify wallet to expect the coinbase UTXO, as we mined this block
                myself
                    .wallet_state
                    .add_expected_utxo(ExpectedUtxo::new(
                        coinbase_info.utxo,
                        coinbase_info.sender_randomness,
                        coinbase_info.receiver_preimage,
                        UtxoNotifier::OwnMiner,
                    ))
                    .await;
            }

            // Get parent of tip for mutator-set data needed for various updates. Parent of the
            // stored block will always exist since all blocks except the genesis block have a
            // parent, and the genesis block is considered code, not data, so the genesis block
            // will never be changed or updated through this method.
            let tip_parent = myself
                .chain
                .archival_state()
                .get_tip_parent()
                .await
                .expect("Parent must exist when storing a new block");

            // Sanity check that must always be true for a valid block
            assert_eq!(
                tip_parent.hash(),
                new_block.header().prev_block_digest,
                "Tip parent has must match indicated parent hash"
            );
            let previous_ms_accumulator = tip_parent.body().mutator_set_accumulator.clone();

            // update wallet state with relevant UTXOs from this block
            myself
                .wallet_state
                .update_wallet_state_with_new_block(&previous_ms_accumulator, &new_block)
                .await?;

            // Update mempool with UTXOs from this block. This is done by removing all transaction
            // that became invalid/was mined by this block.
            myself
                .mempool
                .update_with_block(previous_ms_accumulator, &new_block)
                .await;

            myself.chain.light_state_mut().set_block(new_block);

            // Flush databases
            myself.flush_databases().await?;

            Ok(())
        }

        crate::macros::duration_async_info!(set_new_tip_internal_worker(
            self,
            new_block,
            coinbase_utxo_info
        ))
    }

    /// resync membership proofs
    pub async fn resync_membership_proofs(&mut self) -> Result<()> {
        // Do not fix memberhip proofs if node is in sync mode, as we would otherwise
        // have to sync many times, instead of just *one* time once we have caught up.
        if self.net.syncing {
            debug!("Not syncing MS membership proofs because we are syncing");
            return Ok(());
        }

        // is it necessary?
        let current_tip_digest = self.chain.light_state().hash();
        if self.wallet_state.is_synced_to(current_tip_digest).await {
            debug!("Membership proof syncing not needed");
            return Ok(());
        }

        // do we have blocks?
        if self.chain.is_archival_node() {
            return self
                .resync_membership_proofs_from_stored_blocks(current_tip_digest)
                .await;
        }

        // request blocks from peers
        todo!("We don't yet support non-archival nodes");

        // Ok(())
    }

    #[inline]
    pub fn cli(&self) -> &cli_args::Args {
        &self.cli
    }

    pub async fn next_spending_key(&mut self, key_type: KeyType) -> SpendingKey {
        let key = self.wallet_state.next_unused_spending_key(key_type);

        // persist wallet state to disk
        self.persist_wallet().await.expect("flushed");

        key
    }
}

/// This provides some additional metadata about `TxOutput` that are generated
/// by GlobalState::generate_tx_params()
///
/// note that it is possible to have TxOutput with no corresponding ReceivingAddress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOutputMeta {
    pub receiving_address: ReceivingAddress,
    pub self_owned: bool,
}

#[cfg(test)]
mod global_state_tests {
    use num_traits::One;
    use num_traits::Zero;
    use rand::random;
    use rand::rngs::StdRng;
    use rand::thread_rng;
    use rand::Rng;
    use rand::SeedableRng;
    use tracing_test::traced_test;
    use wallet::address::generation_address::GenerationReceivingAddress;
    use wallet::address::KeyType;

    use crate::config_models::network::Network;
    use crate::models::blockchain::block::Block;
    use crate::models::blockchain::transaction::utxo::Utxo;
    use crate::models::state::wallet::expected_utxo::UtxoNotifier;
    use crate::tests::shared::add_block_to_light_state;
    use crate::tests::shared::make_mock_block;
    use crate::tests::shared::make_mock_block_with_valid_pow;
    use crate::tests::shared::mock_genesis_global_state;
    use crate::tests::shared::mock_genesis_wallet_state;

    use super::wallet::WalletSecret;
    use super::*;

    async fn wallet_state_has_all_valid_mps_for(
        wallet_state: &WalletState,
        tip_block: &Block,
    ) -> bool {
        let monitored_utxos = wallet_state.wallet_db.monitored_utxos();
        for monitored_utxo in monitored_utxos.get_all().await.iter() {
            let current_mp = monitored_utxo.get_membership_proof_for_block(tip_block.hash());

            match current_mp {
                Some(mp) => {
                    if !tip_block
                        .kernel
                        .body
                        .mutator_set_accumulator
                        .verify(Hash::hash(&monitored_utxo.utxo), &mp)
                    {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }

    #[traced_test]
    #[tokio::test]
    async fn premine_recipient_cannot_spend_premine_before_and_can_after_release_date() {
        let network = Network::Regtest;
        let other_wallet = WalletSecret::new_random();
        let global_state_lock =
            mock_genesis_global_state(network, 2, WalletSecret::devnet_wallet()).await;
        let genesis_block = Block::genesis_block(network);
        let twenty_neptune: NeptuneCoins = NeptuneCoins::new(20);
        let twenty_coins = twenty_neptune.to_native_coins();
        let recipient_address: ReceivingAddress = other_wallet
            .nth_generation_spending_key_for_tests(0)
            .to_address()
            .into();
        let main_lock_script = recipient_address.lock_script();
        let output_utxo = Utxo {
            coins: twenty_coins,
            lock_script_hash: main_lock_script.hash(),
        };
        let sender_randomness = Digest::default();
        let receiver_privacy_digest = recipient_address.privacy_digest();
        let public_announcement = recipient_address
            .generate_public_announcement(&output_utxo, sender_randomness)
            .unwrap();
        let tx_outputs = vec![TxOutput::onchain(
            output_utxo.clone(),
            sender_randomness,
            receiver_privacy_digest,
            public_announcement,
        )];

        let monitored_utxos = global_state_lock
            .lock_guard()
            .await
            .wallet_state
            .wallet_db
            .monitored_utxos()
            .get_all()
            .await;
        assert_ne!(monitored_utxos.len(), 0);

        // one month before release date, we should not be able to create the transaction
        let launch = genesis_block.kernel.header.timestamp;
        let six_months = Timestamp::months(6);
        let one_month = Timestamp::months(1);
        assert!(global_state_lock
            .lock_guard()
            .await
            .create_transaction_test_wrapper(
                tx_outputs.clone(),
                NeptuneCoins::new(1),
                launch + six_months - one_month,
            )
            .await
            .is_err());

        // one month after though, we should be
        let (mut tx, _) = global_state_lock
            .lock_guard()
            .await
            .create_transaction_test_wrapper(
                tx_outputs,
                NeptuneCoins::new(1),
                launch + six_months + one_month,
            )
            .await
            .unwrap();
        assert!(tx.is_valid());

        // but if we backdate the timestamp two months, not anymore!
        tx.kernel.timestamp = tx.kernel.timestamp - Timestamp::months(2);
        // we can't test this yet; we don't have tasm code for time locks yet!
        // todo: uncomment the next line when we do.
        // assert!(!tx.is_valid());
        tx.kernel.timestamp = tx.kernel.timestamp + Timestamp::months(2);

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
        let mut other_tx_outputs = vec![];
        let mut output_utxos: Vec<Utxo> = vec![];
        for i in 2..5 {
            let amount: NeptuneCoins = NeptuneCoins::new(i);
            let that_many_coins = amount.to_native_coins();
            let receiving_address: ReceivingAddress = other_wallet
                .nth_generation_spending_key_for_tests(0)
                .to_address()
                .into();
            let lock_script = receiving_address.lock_script();
            let utxo = Utxo {
                coins: that_many_coins,
                lock_script_hash: lock_script.hash(),
            };
            let other_sender_randomness = Digest::default();
            let other_receiver_digest = receiving_address.privacy_digest();
            let other_public_announcement = receiving_address
                .generate_public_announcement(&utxo, other_sender_randomness)
                .unwrap();
            output_utxos.push(utxo.clone());
            other_tx_outputs.push(TxOutput::onchain(
                utxo,
                other_sender_randomness,
                other_receiver_digest,
                other_public_announcement,
            ));
        }

        let (new_tx, _) = global_state_lock
            .lock_guard()
            .await
            .create_transaction_test_wrapper(
                other_tx_outputs,
                NeptuneCoins::new(1),
                launch + six_months + one_month,
            )
            .await
            .unwrap();
        assert!(new_tx.is_valid());
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

    #[traced_test]
    #[tokio::test]
    async fn restore_monitored_utxos_from_recovery_data_test() {
        let mut rng = thread_rng();
        let network = Network::Regtest;
        let devnet_wallet = WalletSecret::devnet_wallet();
        let mut global_state_lock = mock_genesis_global_state(network, 2, devnet_wallet).await;
        let mut global_state = global_state_lock.lock_guard_mut().await;
        let other_receiver_address = WalletSecret::new_random()
            .nth_generation_spending_key_for_tests(0)
            .to_address();
        let genesis_block = Block::genesis_block(network);
        let (mock_block_1, _, _) =
            make_mock_block(&genesis_block, None, other_receiver_address, rng.gen());
        crate::tests::shared::add_block_to_archival_state(
            global_state.chain.archival_state_mut(),
            mock_block_1.clone(),
        )
        .await
        .unwrap();
        add_block_to_light_state(global_state.chain.light_state_mut(), mock_block_1.clone())
            .await
            .unwrap();

        // Delete everything from monitored UTXO (the premined UTXO)
        {
            let monitored_utxos = global_state.wallet_state.wallet_db.monitored_utxos_mut();
            assert!(
                monitored_utxos.len().await.is_one(),
                "MUTXO must have genesis element before emptying it"
            );
            monitored_utxos.pop().await;

            assert!(
                monitored_utxos.is_empty().await,
                "MUTXO must be empty after emptying it"
            );
        }

        // Recover the MUTXO from the recovery data, and verify that MUTXOs are restored
        global_state
            .restore_monitored_utxos_from_recovery_data()
            .await
            .unwrap();
        {
            let monitored_utxos = global_state.wallet_state.wallet_db.monitored_utxos();
            assert!(
                monitored_utxos.len().await.is_one(),
                "MUTXO must have genesis element after recovering it"
            );

            // Verify that the restored MUTXO has a valid MSMP
            let own_premine_mutxo = monitored_utxos.get(0).await;
            let ms_item = Hash::hash(&own_premine_mutxo.utxo);
            global_state
                .chain
                .light_state()
                .body()
                .mutator_set_accumulator
                .verify(
                    ms_item,
                    &own_premine_mutxo
                        .get_latest_membership_proof_entry()
                        .unwrap()
                        .1,
                );
            assert_eq!(
                mock_block_1.hash(),
                own_premine_mutxo
                    .get_latest_membership_proof_entry()
                    .unwrap()
                    .0,
                "MUTXO must have the correct latest block digest value"
            );
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn resync_ms_membership_proofs_simple_test() -> Result<()> {
        let mut rng = thread_rng();
        let network = Network::Regtest;
        let mut global_state_lock =
            mock_genesis_global_state(network, 2, WalletSecret::devnet_wallet()).await;
        let mut global_state = global_state_lock.lock_guard_mut().await;

        let other_receiver_wallet_secret = WalletSecret::new_random();
        let other_receiver_address = other_receiver_wallet_secret
            .nth_generation_spending_key_for_tests(0)
            .to_address();

        // 1. Create new block 1 and store it to the DB
        let genesis_block = Block::genesis_block(network);
        let launch = genesis_block.kernel.header.timestamp;
        let seven_months = Timestamp::months(7);
        let (mock_block_1a, _, _) =
            make_mock_block(&genesis_block, None, other_receiver_address, rng.gen());

        // Verify that wallet has a monitored UTXO (from genesis)
        let wallet_status = global_state.get_wallet_status_for_tip().await;

        assert!(!wallet_status
            .synced_unspent_available_amount(launch + seven_months)
            .is_zero());

        global_state
            .chain
            .archival_state_mut()
            .write_block_as_tip(&mock_block_1a)
            .await?;

        // Verify that this is unsynced with mock_block_1a
        assert!(
            global_state
                .wallet_state
                .is_synced_to(genesis_block.hash())
                .await
        );
        assert!(
            !global_state
                .wallet_state
                .is_synced_to(mock_block_1a.hash())
                .await
        );

        // Call resync
        global_state
            .resync_membership_proofs_from_stored_blocks(mock_block_1a.hash())
            .await
            .unwrap();

        // Verify that it is synced
        assert!(
            global_state
                .wallet_state
                .is_synced_to(mock_block_1a.hash())
                .await
        );

        // Verify that MPs are valid
        assert!(
            wallet_state_has_all_valid_mps_for(&global_state.wallet_state, &mock_block_1a).await
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn resync_ms_membership_proofs_fork_test() -> Result<()> {
        let mut rng = thread_rng();
        let network = Network::Regtest;
        let mut global_state_lock =
            mock_genesis_global_state(network, 2, WalletSecret::devnet_wallet()).await;
        let mut global_state = global_state_lock.lock_guard_mut().await;
        let own_spending_key = global_state
            .wallet_state
            .wallet_secret
            .nth_generation_spending_key_for_tests(0);
        let own_receiving_address = own_spending_key.to_address();

        // 1. Create new block 1a where we receive a coinbase UTXO, store it
        let genesis_block = global_state.chain.archival_state().tip().to_owned();
        let (mock_block_1a, coinbase_utxo, coinbase_output_randomness) =
            make_mock_block(&genesis_block, None, own_receiving_address, rng.gen());
        global_state
            .set_new_self_mined_tip(
                mock_block_1a.clone(),
                ExpectedUtxo::new(
                    coinbase_utxo,
                    coinbase_output_randomness,
                    own_spending_key.privacy_preimage,
                    UtxoNotifier::OwnMiner,
                ),
            )
            .await
            .unwrap();

        // Verify that wallet has monitored UTXOs, from genesis and from block_1a
        let wallet_status = global_state
            .wallet_state
            .get_wallet_status(mock_block_1a.hash())
            .await;
        assert_eq!(2, wallet_status.synced_unspent.len());

        // Make a new fork from genesis that makes us lose the coinbase UTXO of block 1a
        let other_wallet_secret = WalletSecret::new_random();
        let other_receiving_address = other_wallet_secret
            .nth_generation_spending_key_for_tests(0)
            .to_address();
        let mut parent_block = genesis_block;
        for _ in 0..5 {
            let (next_block, _, _) =
                make_mock_block(&parent_block, None, other_receiving_address, rng.gen());
            global_state.set_new_tip(next_block.clone()).await.unwrap();
            parent_block = next_block;
        }

        // Call resync which fails to sync the UTXO that was abandoned when block 1a was abandoned
        global_state
            .resync_membership_proofs_from_stored_blocks(parent_block.hash())
            .await
            .unwrap();

        // Verify that one MUTXO is unsynced, and that 1 (from genesis) is synced
        let wallet_status_after_forking = global_state
            .wallet_state
            .get_wallet_status(parent_block.hash())
            .await;
        assert_eq!(1, wallet_status_after_forking.synced_unspent.len());
        assert_eq!(1, wallet_status_after_forking.unsynced_unspent.len());

        // Verify that the MUTXO from block 1a is considered abandoned, and that the one from
        // genesis block is not.
        let monitored_utxos = global_state.wallet_state.wallet_db.monitored_utxos();
        assert!(
            !monitored_utxos
                .get(0)
                .await
                .was_abandoned(parent_block.hash(), global_state.chain.archival_state())
                .await
        );
        assert!(
            monitored_utxos
                .get(1)
                .await
                .was_abandoned(parent_block.hash(), global_state.chain.archival_state())
                .await
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn resync_ms_membership_proofs_across_stale_fork() -> Result<()> {
        let mut rng = thread_rng();
        let network = Network::Regtest;
        let mut global_state_lock =
            mock_genesis_global_state(network, 2, WalletSecret::devnet_wallet()).await;
        let mut global_state = global_state_lock.lock_guard_mut().await;
        let wallet_secret = global_state.wallet_state.wallet_secret.clone();
        let own_spending_key = wallet_secret.nth_generation_spending_key_for_tests(0);
        let own_receiving_address = own_spending_key.to_address();
        let other_wallet_secret = WalletSecret::new_random();
        let other_receiving_address = other_wallet_secret
            .nth_generation_spending_key_for_tests(0)
            .to_address();

        // 1. Create new block 1a where we receive a coinbase UTXO, store it
        let genesis_block = global_state.chain.archival_state().tip().to_owned();
        assert!(genesis_block.kernel.header.height.is_genesis());
        let (mock_block_1a, coinbase_utxo_1a, cb_utxo_output_randomness_1a) =
            make_mock_block(&genesis_block, None, own_receiving_address, rng.gen());
        {
            global_state
                .set_new_self_mined_tip(
                    mock_block_1a.clone(),
                    ExpectedUtxo::new(
                        coinbase_utxo_1a,
                        cb_utxo_output_randomness_1a,
                        own_spending_key.privacy_preimage,
                        UtxoNotifier::OwnMiner,
                    ),
                )
                .await
                .unwrap();

            // Verify that UTXO was recorded
            let wallet_status_after_1a = global_state
                .wallet_state
                .get_wallet_status(mock_block_1a.hash())
                .await;
            assert_eq!(2, wallet_status_after_1a.synced_unspent.len());
        }

        // Add 100 blocks on top of 1a, *not* mined by us
        let mut fork_a_block = mock_block_1a.clone();
        for _ in 0..100 {
            let (next_a_block, _, _) =
                make_mock_block(&fork_a_block, None, other_receiving_address, rng.gen());
            global_state
                .set_new_tip(next_a_block.clone())
                .await
                .unwrap();
            fork_a_block = next_a_block;
        }

        // Verify that all both MUTXOs have synced MPs
        let wallet_status_on_a_fork = global_state
            .wallet_state
            .get_wallet_status(fork_a_block.hash())
            .await;

        assert_eq!(2, wallet_status_on_a_fork.synced_unspent.len());

        // Fork away from the "a" chain to the "b" chain, with block 1a as LUCA
        let mut fork_b_block = mock_block_1a.clone();
        for _ in 0..100 {
            let (next_b_block, _, _) =
                make_mock_block(&fork_b_block, None, other_receiving_address, rng.gen());
            global_state
                .set_new_tip(next_b_block.clone())
                .await
                .unwrap();
            fork_b_block = next_b_block;
        }

        // Verify that there are zero MUTXOs with synced MPs
        let wallet_status_on_b_fork_before_resync = global_state
            .wallet_state
            .get_wallet_status(fork_b_block.hash())
            .await;
        assert_eq!(
            0,
            wallet_status_on_b_fork_before_resync.synced_unspent.len()
        );
        assert_eq!(
            2,
            wallet_status_on_b_fork_before_resync.unsynced_unspent.len()
        );

        // Run the resync and verify that MPs are synced
        global_state
            .resync_membership_proofs_from_stored_blocks(fork_b_block.hash())
            .await
            .unwrap();
        let wallet_status_on_b_fork_after_resync = global_state
            .wallet_state
            .get_wallet_status(fork_b_block.hash())
            .await;
        assert_eq!(2, wallet_status_on_b_fork_after_resync.synced_unspent.len());
        assert_eq!(
            0,
            wallet_status_on_b_fork_after_resync.unsynced_unspent.len()
        );

        // `wallet_state_has_all_valid_mps_for`
        // Make a new chain c with genesis block as LUCA. Verify that the genesis UTXO can be synced
        // to this new chain
        let mut fork_c_block = genesis_block.clone();
        for _ in 0..100 {
            let (next_c_block, _, _) =
                make_mock_block(&fork_c_block, None, other_receiving_address, rng.gen());
            global_state
                .set_new_tip(next_c_block.clone())
                .await
                .unwrap();
            fork_c_block = next_c_block;
        }

        // Verify that there are zero MUTXOs with synced MPs
        let wallet_status_on_c_fork_before_resync = global_state
            .wallet_state
            .get_wallet_status(fork_c_block.hash())
            .await;
        assert_eq!(
            0,
            wallet_status_on_c_fork_before_resync.synced_unspent.len()
        );
        assert_eq!(
            2,
            wallet_status_on_c_fork_before_resync.unsynced_unspent.len()
        );

        // Run the resync and verify that UTXO from genesis is synced, but that
        // UTXO from 1a is not synced.
        global_state
            .resync_membership_proofs_from_stored_blocks(fork_c_block.hash())
            .await
            .unwrap();
        let wallet_status_on_c_fork_after_resync = global_state
            .wallet_state
            .get_wallet_status(fork_c_block.hash())
            .await;
        assert_eq!(1, wallet_status_on_c_fork_after_resync.synced_unspent.len());
        assert_eq!(
            1,
            wallet_status_on_c_fork_after_resync.unsynced_unspent.len()
        );

        // Also check that UTXO from 1a is considered abandoned
        let monitored_utxos = global_state.wallet_state.wallet_db.monitored_utxos();
        assert!(
            !monitored_utxos
                .get(0)
                .await
                .was_abandoned(fork_c_block.hash(), global_state.chain.archival_state())
                .await
        );
        assert!(
            monitored_utxos
                .get(1)
                .await
                .was_abandoned(fork_c_block.hash(), global_state.chain.archival_state())
                .await
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn flaky_mutator_set_test() {
        // Test various parts of the state update when a block contains multiple inputs and outputs
        // Scenario: Three parties: Alice, Bob, and Premine Receiver, mine blocks and pass coins
        // around.

        let seed = {
            let mut rng: StdRng =
                SeedableRng::from_rng(thread_rng()).expect("failure lifting thread_rng to StdRng");
            let seed: [u8; 32] = rng.gen();
            // let seed = [
            //     0xf4, 0xc2, 0x1c, 0xd0, 0x5a, 0xac, 0x99, 0xe7, 0x3a, 0x1e, 0x29, 0x7f, 0x16, 0xc1,
            //     0x50, 0x5e, 0x1e, 0xd, 0x4b, 0x49, 0x51, 0x9c, 0x1b, 0xa0, 0x38, 0x3c, 0xd, 0x83, 0x29,
            //     0xdb, 0xab, 0xe2,
            // ];
            println!(
                "seed: [{}]",
                seed.iter().map(|h| format!("{:#x}", h)).join(", ")
            );
            seed
        };
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let network = Network::Regtest;

        let genesis_wallet_state =
            mock_genesis_wallet_state(WalletSecret::devnet_wallet(), network).await;
        let genesis_spending_key = genesis_wallet_state
            .wallet_secret
            .nth_generation_spending_key_for_tests(0);
        let mut genesis_state_lock =
            mock_genesis_global_state(network, 3, genesis_wallet_state.wallet_secret).await;

        let wallet_secret_alice = WalletSecret::new_pseudorandom(rng.gen());
        let alice_spending_key = wallet_secret_alice.nth_generation_spending_key_for_tests(0);
        let mut alice_state_lock = mock_genesis_global_state(network, 3, wallet_secret_alice).await;

        let wallet_secret_bob = WalletSecret::new_pseudorandom(rng.gen());
        let bob_spending_key = wallet_secret_bob.nth_generation_spending_key_for_tests(0);
        let mut bob_state_lock = mock_genesis_global_state(network, 3, wallet_secret_bob).await;

        let genesis_block = Block::genesis_block(network);
        let launch = genesis_block.kernel.header.timestamp;
        let seven_months = Timestamp::months(7);

        let (mut block_1, cb_utxo, cb_output_randomness) = make_mock_block_with_valid_pow(
            &genesis_block,
            None,
            genesis_spending_key.to_address(),
            rng.gen(),
        );

        // Send two outputs each to Alice and Bob, from genesis receiver
        let fee = NeptuneCoins::one_nau();
        let sender_randomness: Digest = rng.gen();
        let tx_outputs_for_alice = vec![
            TxOutput::fake_address(
                Utxo {
                    lock_script_hash: alice_spending_key.to_address().lock_script().hash(),
                    coins: NeptuneCoins::new(41).to_native_coins(),
                },
                sender_randomness,
                alice_spending_key.to_address().privacy_digest,
            ),
            TxOutput::fake_address(
                Utxo {
                    lock_script_hash: alice_spending_key.to_address().lock_script().hash(),
                    coins: NeptuneCoins::new(59).to_native_coins(),
                },
                sender_randomness,
                alice_spending_key.to_address().privacy_digest,
            ),
        ];

        // Two outputs for Bob
        let tx_outputs_for_bob = vec![
            TxOutput::fake_address(
                Utxo {
                    lock_script_hash: bob_spending_key.to_address().lock_script().hash(),
                    coins: NeptuneCoins::new(141).to_native_coins(),
                },
                sender_randomness,
                bob_spending_key.to_address().privacy_digest,
            ),
            TxOutput::fake_address(
                Utxo {
                    lock_script_hash: bob_spending_key.to_address().lock_script().hash(),
                    coins: NeptuneCoins::new(59).to_native_coins(),
                },
                sender_randomness,
                bob_spending_key.to_address().privacy_digest,
            ),
        ];
        {
            let (tx_to_alice_and_bob, expected_utxos_ab) = genesis_state_lock
                .lock_guard()
                .await
                .create_transaction_test_wrapper(
                    [tx_outputs_for_alice.clone(), tx_outputs_for_bob.clone()].concat(),
                    fee,
                    launch + seven_months,
                )
                .await
                .unwrap();

            // inform wallet of any expected utxos from this tx.
            genesis_state_lock
                .lock_guard_mut()
                .await
                .add_expected_utxos_to_wallet(expected_utxos_ab)
                .await
                .unwrap();

            // Absorb and verify validity
            block_1
                .accumulate_transaction(
                    tx_to_alice_and_bob,
                    &genesis_block.kernel.body.mutator_set_accumulator,
                )
                .await;
            let now = genesis_block.kernel.header.timestamp;
            assert!(block_1.is_valid(&genesis_block, now + seven_months));
        }

        println!("Accumulated transaction into block_1.");
        println!(
            "Transaction has {} inputs (removal records) and {} outputs (addition records)",
            block_1.kernel.body.transaction.kernel.inputs.len(),
            block_1.kernel.body.transaction.kernel.outputs.len()
        );

        // Update states with `block_1`
        for rec_data in tx_outputs_for_alice {
            alice_state_lock
                .lock_guard_mut()
                .await
                .wallet_state
                .add_expected_utxo(ExpectedUtxo::new(
                    rec_data.utxo.clone(),
                    rec_data.sender_randomness,
                    alice_spending_key.privacy_preimage,
                    UtxoNotifier::Cli,
                ))
                .await;
        }

        for rec_data in tx_outputs_for_bob {
            bob_state_lock
                .lock_guard_mut()
                .await
                .wallet_state
                .add_expected_utxo(ExpectedUtxo::new(
                    rec_data.utxo.clone(),
                    rec_data.sender_randomness,
                    bob_spending_key.privacy_preimage,
                    UtxoNotifier::Cli,
                ))
                .await;
        }

        genesis_state_lock
            .lock_guard_mut()
            .await
            .set_new_self_mined_tip(
                block_1.clone(),
                ExpectedUtxo::new(
                    cb_utxo,
                    cb_output_randomness,
                    genesis_spending_key.privacy_preimage,
                    UtxoNotifier::OwnMiner,
                ),
            )
            .await
            .unwrap();

        for state_lock in [&mut alice_state_lock, &mut bob_state_lock] {
            let mut state = state_lock.lock_guard_mut().await;
            state.set_new_tip(block_1.clone()).await.unwrap();
        }

        assert_eq!(
            3,
            genesis_state_lock
                .lock_guard_mut()
                .await
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .len().await, "Genesis receiver must have 3 UTXOs after block 1: change from transaction, coinbase from block 1, and the spent premine UTXO"
        );

        // Now Alice should have a balance of 100 and Bob a balance of 200
        assert_eq!(
            NeptuneCoins::new(100),
            alice_state_lock
                .lock_guard()
                .await
                .get_wallet_status_for_tip()
                .await
                .synced_unspent_available_amount(launch + seven_months)
        );
        assert_eq!(
            NeptuneCoins::new(200),
            bob_state_lock
                .lock_guard()
                .await
                .get_wallet_status_for_tip()
                .await
                .synced_unspent_available_amount(launch + seven_months)
        );

        // Make two transactions: Alice sends two UTXOs to Genesis and Bob sends three UTXOs to genesis
        let tx_outputs_from_alice = vec![
            TxOutput::fake_address(
                Utxo {
                    lock_script_hash: genesis_spending_key.to_address().lock_script().hash(),
                    coins: NeptuneCoins::new(50).to_native_coins(),
                },
                rng.gen(),
                genesis_spending_key.to_address().privacy_digest,
            ),
            TxOutput::fake_address(
                Utxo {
                    lock_script_hash: genesis_spending_key.to_address().lock_script().hash(),
                    coins: NeptuneCoins::new(49).to_native_coins(),
                },
                rng.gen(),
                genesis_spending_key.to_address().privacy_digest,
            ),
        ];
        let now = genesis_block.kernel.header.timestamp;
        let (tx_from_alice, expected_utxos_alice) = alice_state_lock
            .lock_guard()
            .await
            .create_transaction_test_wrapper(
                tx_outputs_from_alice.clone(),
                NeptuneCoins::new(1),
                now,
            )
            .await
            .unwrap();

        // inform wallet of any expected utxos from this tx.
        alice_state_lock
            .lock_guard_mut()
            .await
            .add_expected_utxos_to_wallet(expected_utxos_alice)
            .await
            .unwrap();

        let tx_outputs_from_bob = vec![
            TxOutput::fake_address(
                Utxo {
                    lock_script_hash: genesis_spending_key.to_address().lock_script().hash(),
                    coins: NeptuneCoins::new(50).to_native_coins(),
                },
                rng.gen(),
                genesis_spending_key.to_address().privacy_digest,
            ),
            TxOutput::fake_address(
                Utxo {
                    lock_script_hash: genesis_spending_key.to_address().lock_script().hash(),
                    coins: NeptuneCoins::new(50).to_native_coins(),
                },
                rng.gen(),
                genesis_spending_key.to_address().privacy_digest,
            ),
            TxOutput::fake_address(
                Utxo {
                    lock_script_hash: genesis_spending_key.to_address().lock_script().hash(),
                    coins: NeptuneCoins::new(98).to_native_coins(),
                },
                rng.gen(),
                genesis_spending_key.to_address().privacy_digest,
            ),
        ];
        let (tx_from_bob, expected_utxos_bob) = bob_state_lock
            .lock_guard()
            .await
            .create_transaction_test_wrapper(tx_outputs_from_bob.clone(), NeptuneCoins::new(2), now)
            .await
            .unwrap();

        // inform wallet of any expected utxos from this tx.
        bob_state_lock
            .lock_guard_mut()
            .await
            .add_expected_utxos_to_wallet(expected_utxos_bob)
            .await
            .unwrap();

        // Make block_2 with tx that contains:
        // - 4 inputs: 2 from Alice and 2 from Bob
        // - 6 outputs: 2 from Alice to Genesis, 3 from Bob to Genesis, and 1 coinbase to Genesis
        let (mut block_2, _cb_utxo_block_2, _cb_sender_randomness_block_2) =
            make_mock_block_with_valid_pow(
                &block_1,
                None,
                genesis_spending_key.to_address(),
                rng.gen(),
            );
        block_2
            .accumulate_transaction(tx_from_alice, &block_1.kernel.body.mutator_set_accumulator)
            .await;
        assert_eq!(2, block_2.kernel.body.transaction.kernel.inputs.len());
        assert_eq!(3, block_2.kernel.body.transaction.kernel.outputs.len());

        block_2
            .accumulate_transaction(tx_from_bob, &block_1.kernel.body.mutator_set_accumulator)
            .await;
    }

    #[traced_test]
    #[tokio::test]
    async fn mock_global_state_is_valid() {
        let mut rng = thread_rng();
        let network = Network::Regtest;
        let mut global_state_lock =
            mock_genesis_global_state(network, 2, WalletSecret::devnet_wallet()).await;
        let mut global_state = global_state_lock.lock_guard_mut().await;
        let genesis_block = Block::genesis_block(network);
        let now = genesis_block.kernel.header.timestamp;

        let wallet_secret = WalletSecret::new_random();
        let receiving_address = wallet_secret
            .nth_generation_spending_key_for_tests(0)
            .to_address();
        let (block_1, _cb_utxo, _cb_output_randomness) =
            make_mock_block_with_valid_pow(&genesis_block, None, receiving_address, rng.gen());

        global_state.set_new_tip(block_1).await.unwrap();

        assert!(global_state
            .chain
            .light_state()
            .is_valid(&genesis_block, now));
    }

    /// tests that pertain to restoring a wallet from seed-phrase
    /// and comparing onchain vs offchain notification methods.
    mod restore_wallet {
        use super::*;

        /// test scenario: onchain/symmetric.
        /// pass outcome: no funds loss
        ///
        /// test described in [change_exists()]
        #[traced_test]
        #[tokio::test]
        #[allow(clippy::needless_return)]
        async fn onchain_symmetric_change_exists() -> Result<()> {
            change_exists(OwnedUtxoNotifyMethod::OnChain, KeyType::Symmetric).await
        }

        /// test scenario: onchain/generation.
        /// pass outcome: no funds loss
        ///
        /// test described in [change_exists()]
        #[traced_test]
        #[tokio::test]
        #[allow(clippy::needless_return)]
        async fn onchain_generation_change_exists() -> Result<()> {
            change_exists(OwnedUtxoNotifyMethod::OnChain, KeyType::Generation).await
        }

        /// test scenario: offchain/symmetric.
        /// pass outcome: all funds lost!
        ///
        /// test described in [change_exists()]
        #[traced_test]
        #[tokio::test]
        #[allow(clippy::needless_return)]
        async fn offchain_symmetric_change_exists() -> Result<()> {
            change_exists(OwnedUtxoNotifyMethod::OffChain, KeyType::Symmetric).await
        }

        /// test scenario: offchain/generation.
        /// pass outcome: all funds lost!
        ///
        /// test described in [change_exists()]
        #[traced_test]
        #[tokio::test]
        #[allow(clippy::needless_return)]
        async fn offchain_generation_change_exists() -> Result<()> {
            change_exists(OwnedUtxoNotifyMethod::OffChain, KeyType::Generation).await
        }

        /// basic scenario:  alice receives 20,000 coins in the premine.  7 months
        /// after launch she sends 20 coins to bob, plus 1 coin fee.  alice should
        /// receive change of 19979.  Sometime after this block is mined alice's
        /// hard drive crashes and she loses her wallet.  She still has her wallet
        /// seed and uses it to create a new wallet and scan blockchain to recover
        /// funds.  At the end alice checks her wallet balance, which should be
        /// 19979.
        ///
        /// note: the pre-mine and 7-months aspects are unimportant.  This test
        /// would have same results if alice were a coinbase recipient instead.
        ///
        /// variations:
        ///   utxo_notify_method: alice can choose OnChain or OffChain utxo notification.
        ///   change_key_type:    alice's change key can be Symmetric or Generation
        ///
        /// outcomes:
        ///   onchain/symmetric:    balance: 19979.  no funds loss.
        ///   onchain/generation:   balance: 19979.  no funds loss.
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
            owned_utxo_notify_method: OwnedUtxoNotifyMethod,
            change_key_type: KeyType,
        ) -> Result<()> {
            // setup initial conditions
            let network = Network::Regtest;
            let genesis_block = Block::genesis_block(network);
            let launch = genesis_block.kernel.header.timestamp;
            let seven_months_post_launch = launch + Timestamp::months(7);
            let miner_address = GenerationReceivingAddress::derive_from_seed(random());
            let unowned_utxo_notify_method = UnownedUtxoNotifyMethod::OnChain;

            // amounts used in alice-to-bob transaction.
            let alice_to_bob_amount = NeptuneCoins::new(20);
            let alice_to_bob_fee = NeptuneCoins::new(1);

            // init global state for alice bob
            let mut alice_state_lock =
                mock_genesis_global_state(network, 3, WalletSecret::devnet_wallet()).await;
            let mut bob_state_lock =
                mock_genesis_global_state(network, 3, WalletSecret::new_random()).await;

            // in bob wallet: create receiving address for bob
            let bob_address = {
                bob_state_lock
                    .lock_guard_mut()
                    .await
                    .wallet_state
                    .next_unused_spending_key(KeyType::Generation)
                    .to_address()
            };

            // in alice wallet: send pre-mined funds to bob
            let block_1 = {
                let mut alice_state_mut = alice_state_lock.lock_guard_mut().await;

                // store and verify alice's initial balance from pre-mine.
                let alice_initial_balance = alice_state_mut
                    .get_wallet_status_for_tip()
                    .await
                    .synced_unspent_available_amount(seven_months_post_launch);
                assert_eq!(alice_initial_balance, 20000u32.into());

                // create change key for alice. change_key_type is a test param.
                let alice_change_key = alice_state_mut
                    .wallet_state
                    .next_unused_spending_key(change_key_type);

                // create an output for bob, worth 20.
                // owned_utxo_notify_method is a test param.
                let outputs = vec![(bob_address, alice_to_bob_amount)];
                let (tx_params, _) = alice_state_mut
                    .generate_tx_params(
                        outputs,
                        alice_change_key,
                        alice_to_bob_fee,
                        owned_utxo_notify_method,
                        unowned_utxo_notify_method,
                        seven_months_post_launch,
                    )
                    .await?;

                let tx_output_list = tx_params.tx_output_list().clone();

                // create tx.
                let alice_to_bob_tx = alice_state_mut.create_transaction(tx_params).await?;

                // Inform alice wallet of any expected incoming utxos.
                // note: no-op when owned utxo notifications are sent on-chain.
                alice_state_mut
                    .add_expected_utxos_to_wallet(tx_output_list.expected_utxos_iter())
                    .await?;

                // the block gets mined.
                let (mut block_1, ..) =
                    make_mock_block_with_valid_pow(&genesis_block, None, miner_address, random());

                // add tx to block.  (weird this is allowed after block mined)
                block_1
                    .accumulate_transaction(
                        alice_to_bob_tx,
                        &alice_state_mut
                            .chain
                            .archival_state()
                            .genesis_block()
                            .kernel
                            .body
                            .mutator_set_accumulator,
                    )
                    .await;

                // alice's node learns of the new block.
                alice_state_mut.set_new_tip(block_1.clone()).await?;

                // alice should have 2 monitored utxos.
                assert_eq!(
                    2,
                    alice_state_mut
                        .wallet_state
                        .wallet_db
                        .monitored_utxos()
                        .len().await, "Alice must have 2 UTXOs after block 1: change from transaction, and the spent premine UTXO"
                );

                // Now alice should have a balance of 19979.
                // 20000 from premine - 21 (20 to Bob + 1 fee)
                let alice_calculated_balance = alice_initial_balance
                    .checked_sub(&alice_to_bob_amount)
                    .unwrap()
                    .checked_sub(&alice_to_bob_fee)
                    .unwrap();
                assert_eq!(alice_calculated_balance, 19979u32.into());

                assert_eq!(
                    alice_calculated_balance,
                    alice_state_mut
                        .get_wallet_status_for_tip()
                        .await
                        .synced_unspent_available_amount(seven_months_post_launch)
                );

                block_1
            };

            // in bob's wallet
            {
                let mut bob_state_mut = bob_state_lock.lock_guard_mut().await;

                // bob's node adds block1 to the chain.
                bob_state_mut.set_new_tip(block_1.clone()).await?;

                // Now Bob should have a balance of 20, from Alice
                assert_eq!(
                    alice_to_bob_amount, // 20
                    bob_state_mut
                        .get_wallet_status_for_tip()
                        .await
                        .synced_unspent_available_amount(seven_months_post_launch)
                );
            }

            // some time in the future.  minutes, months, or years...

            // oh no!  alice's hard-drive crashes and she loses her wallet.
            drop(alice_state_lock);

            // Fortunately alice still has her seed that she can restore from.
            {
                // devnet_wallet() stands in for alice's seed.
                let mut alice_restored_state_lock =
                    mock_genesis_global_state(network, 3, WalletSecret::devnet_wallet()).await;

                let mut alice_state_mut = alice_restored_state_lock.lock_guard_mut().await;

                // check alice's initial balance after genesis.
                let alice_initial_balance = alice_state_mut
                    .get_wallet_status_for_tip()
                    .await
                    .synced_unspent_available_amount(seven_months_post_launch);

                // lucky alice's wallet begins with 20000 balance from premine.
                assert_eq!(alice_initial_balance, 20000u32.into());

                // now alice must replay old blocks.  (there's only one so far)
                alice_state_mut.set_new_tip(block_1).await?;

                // Now alice should have a balance of 19979.
                // 20000 from premine - 21 (20 to Bob + 1 fee)
                let alice_calculated_balance = alice_initial_balance
                    .checked_sub(&alice_to_bob_amount)
                    .unwrap()
                    .checked_sub(&alice_to_bob_fee)
                    .unwrap();

                assert_eq!(alice_calculated_balance, 19979u32.into());

                // For onchain notification the balance will be 19979.
                // For offchain notification, it will be 0.  Funds are lost!!!
                // For offchain-serialized notification, it will be 0.  funds may still be claimed.
                let alice_expected_balance_by_method = match owned_utxo_notify_method {
                    OwnedUtxoNotifyMethod::OnChain => NeptuneCoins::new(19979),
                    OwnedUtxoNotifyMethod::OffChain => NeptuneCoins::new(0),
                    OwnedUtxoNotifyMethod::OffChainSerialized => NeptuneCoins::new(0),
                };

                // verify that our on/offchain prediction is correct.
                assert_eq!(
                    alice_expected_balance_by_method,
                    alice_state_mut
                        .get_wallet_status_for_tip()
                        .await
                        .synced_unspent_available_amount(seven_months_post_launch)
                );
            }

            Ok(())
        }
    }
}
