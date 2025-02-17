use std::collections::HashMap;
use std::collections::HashSet;
use std::error::Error;
use std::fmt::Debug;
use std::path::PathBuf;

use anyhow::bail;
use anyhow::Result;
use itertools::Itertools;
use num_traits::CheckedAdd;
use num_traits::CheckedSub;
use num_traits::Zero;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::triton_vm::prelude::Tip5;
use tokio::fs::OpenOptions;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncWriteExt;
use tokio::io::BufReader;
use tokio::io::BufWriter;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::trace;
use tracing::warn;
use twenty_first::math::bfield_codec::BFieldCodec;
use twenty_first::math::digest::Digest;

use super::address::generation_address;
use super::address::symmetric_key;
use super::address::KeyType;
use super::address::SpendingKey;
use super::coin_with_possible_timelock::CoinWithPossibleTimeLock;
use super::expected_utxo::ExpectedUtxo;
use super::expected_utxo::UtxoNotifier;
use super::incoming_utxo::IncomingUtxo;
use super::rusty_wallet_database::RustyWalletDatabase;
use super::sent_transaction::SentTransaction;
use super::unlocked_utxo::UnlockedUtxo;
use super::wallet_status::WalletStatus;
use super::wallet_status::WalletStatusElement;
use super::WalletSecret;
use super::WALLET_INCOMING_SECRETS_FILE_NAME;
use crate::config_models::cli_args::Args;
use crate::config_models::data_directory::DataDirectory;
use crate::database::storage::storage_schema::DbtVec;
use crate::database::storage::storage_vec::traits::*;
use crate::database::storage::storage_vec::Index;
use crate::database::NeptuneLevelDb;
use crate::models::blockchain::block::mutator_set_update::MutatorSetUpdate;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::channel::ClaimUtxoData;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::mempool::MempoolEvent;
use crate::models::state::transaction_kernel_id::TransactionKernelId;
use crate::models::state::wallet::address::hash_lock_key::HashLockKey;
use crate::models::state::wallet::monitored_utxo::MonitoredUtxo;
use crate::models::state::wallet::transaction_output::TxOutputList;
use crate::prelude::twenty_first;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::commit;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::removal_record::AbsoluteIndexSet;
use crate::util_types::mutator_set::removal_record::RemovalRecord;
use crate::Hash;

pub struct WalletState {
    pub wallet_db: RustyWalletDatabase,
    pub wallet_secret: WalletSecret,
    pub number_of_mps_per_utxo: usize,
    wallet_directory_path: PathBuf,

    /// these two fields are for monitoring wallet-affecting utxos in the mempool.
    /// key is Tx hash.  for removing watched utxos when a tx is removed from mempool.
    mempool_spent_utxos: HashMap<TransactionKernelId, Vec<(Utxo, AbsoluteIndexSet, u64)>>,
    mempool_unspent_utxos: HashMap<TransactionKernelId, Vec<IncomingUtxo>>,

    // these fields represent all known keys that have been handed out,
    // ie keys with derivation index in 0..self.spending_key_counter(key_type)
    // derivation order is preserved and each key must be unique.
    known_generation_keys: Vec<SpendingKey>,
    known_symmetric_keys: Vec<SpendingKey>,

    // Cached from the database to avoid async cascades.
    // Contains guesser-preimages from miner PoW-guessing.
    known_raw_hash_lock_keys: Vec<SpendingKey>,
}

/// Contains the cryptographic (non-public) data that is needed to recover the mutator set
/// membership proof of a UTXO.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec)]
pub(crate) struct IncomingUtxoRecoveryData {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
    pub receiver_preimage: Digest,
    pub aocl_index: u64,
}

impl IncomingUtxoRecoveryData {
    pub(crate) fn addition_record(&self) -> AdditionRecord {
        let item = Tip5::hash(&self.utxo);
        commit(item, self.sender_randomness, self.receiver_preimage.hash())
    }

    /// Returns true iff this UTXO is a guesser reward.
    pub(crate) fn is_guesser_fee(&self) -> bool {
        self.utxo
            .is_lockscript_with_preimage(self.receiver_preimage)
    }
}

impl TryFrom<&MonitoredUtxo> for IncomingUtxoRecoveryData {
    type Error = anyhow::Error;

    fn try_from(value: &MonitoredUtxo) -> std::result::Result<Self, Self::Error> {
        let Some((_block_digest, msmp)) = value.get_latest_membership_proof_entry() else {
            bail!("Cannot create recovery data without a membership proof.");
        };

        Ok(Self {
            utxo: value.utxo.clone(),
            sender_randomness: msmp.sender_randomness,
            receiver_preimage: msmp.receiver_preimage,
            aocl_index: msmp.aocl_leaf_index,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct StrongUtxoKey {
    addition_record: AdditionRecord,
    aocl_index: u64,
}

impl StrongUtxoKey {
    fn new(addition_record: AdditionRecord, aocl_index: u64) -> Self {
        Self {
            addition_record,
            aocl_index,
        }
    }
}

impl Debug for WalletState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletState")
            .field("wallet_secret", &self.wallet_secret)
            .field("number_of_mps_per_utxo", &self.number_of_mps_per_utxo)
            .field("wallet_directory_path", &self.wallet_directory_path)
            .finish()
    }
}

impl WalletState {
    fn incoming_secrets_path(&self) -> PathBuf {
        self.wallet_directory_path
            .join(WALLET_INCOMING_SECRETS_FILE_NAME)
    }

    /// Store information needed to recover mutator set membership proof of a UTXO, in case
    /// the wallet database is deleted.
    ///
    /// Uses non-blocking I/O via tokio.
    async fn store_utxo_ms_recovery_data(
        &self,
        utxo_ms_recovery_data: IncomingUtxoRecoveryData,
    ) -> Result<()> {
        #[cfg(test)]
        {
            tokio::fs::create_dir_all(self.wallet_directory_path.clone()).await?;
        }

        // Open file
        let incoming_secrets_file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(self.incoming_secrets_path())
            .await?;
        let mut incoming_secrets_file = BufWriter::new(incoming_secrets_file);

        // Create JSON string ending with a newline as this flushes the write
        #[cfg(windows)]
        const LINE_ENDING: &str = "\r\n";
        #[cfg(not(windows))]
        const LINE_ENDING: &str = "\n";

        let mut json_string = serde_json::to_string(&utxo_ms_recovery_data)?;
        json_string.push_str(LINE_ENDING);
        incoming_secrets_file
            .write_all(json_string.as_bytes())
            .await?;

        // Flush just in case, since this is cryptographic data, you can't be too sure
        incoming_secrets_file.flush().await?;

        Ok(())
    }

    /// Read recovery-information for mutator set membership proof of a UTXO. Returns all lines in the files,
    /// where each line represents an incoming UTXO.
    ///
    /// Uses non-blocking I/O via tokio.
    pub(crate) async fn read_utxo_ms_recovery_data(&self) -> Result<Vec<IncomingUtxoRecoveryData>> {
        // Open file
        let incoming_secrets_file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(self.incoming_secrets_path())
            .await?;

        let file_reader = BufReader::new(incoming_secrets_file);
        let mut ret = vec![];
        let mut lines = file_reader.lines();
        while let Some(line) = lines.next_line().await? {
            let utxo_ms_recovery_data: IncomingUtxoRecoveryData =
                serde_json::from_str(&line).expect("Could not parse JSON string");
            ret.push(utxo_ms_recovery_data);
        }

        Ok(ret)
    }

    pub async fn new_from_wallet_secret(
        data_dir: &DataDirectory,
        wallet_secret: WalletSecret,
        cli_args: &Args,
    ) -> Self {
        // Create or connect to wallet block DB

        DataDirectory::create_dir_if_not_exists(&data_dir.wallet_database_dir_path())
            .await
            .unwrap();
        let wallet_db = NeptuneLevelDb::new(
            &data_dir.wallet_database_dir_path(),
            &crate::database::create_db_if_missing(),
        )
        .await;
        let wallet_db = match wallet_db {
            Ok(wdb) => wdb,
            Err(err) => {
                error!("Could not open wallet database: {err:?}");
                panic!();
            }
        };

        let rusty_wallet_database = RustyWalletDatabase::connect(wallet_db).await;
        let sync_label = rusty_wallet_database.get_sync_label().await;

        // generate and cache all used generation keys
        let known_generation_keys = (0..rusty_wallet_database.get_generation_key_counter().await)
            .map(|idx| wallet_secret.nth_generation_spending_key(idx).into())
            .collect_vec();

        // generate and cache all used symmetric keys
        let known_symmetric_keys = (0..rusty_wallet_database.get_symmetric_key_counter().await)
            .map(|idx| wallet_secret.nth_symmetric_key(idx).into())
            .collect_vec();

        let known_raw_hash_lock_keys = rusty_wallet_database
            .guesser_preimages()
            .get_all()
            .await
            .into_iter()
            .map(HashLockKey::from_preimage)
            .map(SpendingKey::RawHashLock)
            .collect_vec();

        let mut wallet_state = Self {
            wallet_db: rusty_wallet_database,
            wallet_secret,
            number_of_mps_per_utxo: cli_args.number_of_mps_per_utxo,
            wallet_directory_path: data_dir.wallet_directory_path(),
            mempool_spent_utxos: Default::default(),
            mempool_unspent_utxos: Default::default(),
            known_generation_keys,
            known_symmetric_keys,
            known_raw_hash_lock_keys,
        };

        // Generation key 0 is reserved for composing and guessing rewards. The
        // next lines ensure that the key with derivation-index=0 key is known
        // to the wallet, so that claiming these rewards works.
        // See comment in [`mine_loop::make_coinbase_transaction()`] for the
        // rationale why these rewards always go to key 0.
        //
        // Wallets start at key derivation index 1 for all UTXOs that are
        // neither composing rewards, nor guessing rewards, nor premine UTXOs.
        //
        // note: this makes test known_keys_are_unique() pass.
        if wallet_state.known_generation_keys.is_empty() {
            let _ = wallet_state
                .next_unused_spending_key(KeyType::Generation)
                .await;
        }

        // For premine UTXOs there is an additional complication: we do not know
        // the derivation index with which they were derived. So we derive a few
        // keys to have a bit of margin.
        const NUM_PREMINE_KEYS: usize = 10;
        let premine_keys = (0..NUM_PREMINE_KEYS)
            .map(|n| {
                wallet_state
                    .nth_spending_key(KeyType::Generation, n as u64)
                    .expect("wallet should be capable of generating a new generation address spending key")
            })
            .collect_vec();

        // The wallet state has to be initialized with the genesis block, so
        // that it knows about outputs in the genesis block and so that it can
        // spend them. This initialization should only be done *once*, not every
        // time the wallet is loaded from disk. To ensure this initialization
        // happens only once, we condition it on the sync label.
        // This initialization step also ensures that any premine outputs are
        // added to the file containing the incoming randomness such that a
        // wallet-DB recovery will include genesis block outputs.
        if sync_label == Digest::default() {
            // Check if we are premine recipients, and add expected UTXOs if so.
            for premine_key in premine_keys {
                let own_receiving_address = premine_key
                    .to_address()
                    .expect("premine keys should have associated addresses");
                for utxo in Block::premine_utxos(cli_args.network) {
                    if utxo.lock_script_hash() == own_receiving_address.lock_script().hash() {
                        wallet_state
                            .add_expected_utxo(ExpectedUtxo::new(
                                utxo,
                                Block::premine_sender_randomness(cli_args.network),
                                premine_key
                                    .privacy_preimage()
                                    .expect("premine keys should have associated privacy preimage"),
                                UtxoNotifier::Premine,
                            ))
                            .await;
                    }
                }
            }

            wallet_state
                .update_wallet_state_with_new_block(
                    &MutatorSetAccumulator::default(),
                    &Block::genesis(cli_args.network),
                )
                .await
                .expect("Updating wallet state with genesis block must succeed");

            // No db-persisting here, as all of state should preferably be
            // persisted at the same time.
        }

        wallet_state
    }

    /// Extract `ExpectedUtxo`s from the `TxOutputList` that require off-chain
    /// notifications and that are destined for this wallet.
    pub(crate) fn extract_expected_utxos(
        &self,
        tx_outputs: TxOutputList,
        notifier: UtxoNotifier,
    ) -> Vec<ExpectedUtxo> {
        tx_outputs
            .iter()
            .filter(|txo| txo.is_offchain())
            .filter_map(|txo| {
                self.find_spending_key_for_utxo(&txo.utxo())
                    .map(|sk| (txo, sk))
            })
            .map(|(tx_output, spending_key)| {
                ExpectedUtxo::new(
                    tx_output.utxo(),
                    tx_output.sender_randomness(),
                    spending_key.privacy_preimage().unwrap(),
                    notifier,
                )
            })
            .collect_vec()
    }

    /// handles a list of mempool events
    pub(in crate::models::state) async fn handle_mempool_events(
        &mut self,
        events: impl IntoIterator<Item = MempoolEvent>,
    ) {
        for event in events {
            self.handle_mempool_event(event).await;
        }
    }

    /// handles a single mempool event.
    ///
    /// note: the wallet watches the mempool in order to keep track of
    /// unconfirmed utxos sent from or to the wallet. This enables
    /// calculation of unconfirmed balance.  It also lays foundation for
    /// spending unconfirmed utxos. (issue #189)
    pub(in crate::models::state) async fn handle_mempool_event(&mut self, event: MempoolEvent) {
        match event {
            MempoolEvent::AddTx(tx) => {
                debug!(r"handling mempool AddTx event.  details:\n{}", tx.kernel);

                let spent_utxos = self.scan_for_spent_utxos(&tx.kernel).await;

                // scan tx for utxo we can claim because we are expecting them (offchain)
                let own_utxos_from_expected_utxos =
                    self.scan_for_expected_utxos(&tx.kernel.outputs).await;

                // scan tx for utxo with public-announcements we can claim
                let announced_utxos_from_public_announcements =
                    self.scan_for_announced_utxos(&tx.kernel);

                let own_utxos = announced_utxos_from_public_announcements
                    .chain(own_utxos_from_expected_utxos)
                    .collect_vec();

                let tx_id = tx.kernel.txid();

                self.mempool_spent_utxos.insert(tx_id, spent_utxos);
                self.mempool_unspent_utxos.insert(tx_id, own_utxos);
            }
            MempoolEvent::RemoveTx(tx) => {
                let tx_id = tx.kernel.txid();
                debug!("handling mempool RemoveTx event.  tx: {}", tx_id);
                self.mempool_spent_utxos.remove(&tx_id);
                self.mempool_unspent_utxos.remove(&tx_id);
            }
            MempoolEvent::UpdateTxMutatorSet(_tx_hash_pre_update, _tx_post_update) => {
                // Wallet doesn't need to do anything here.
            }
        }
    }

    pub fn mempool_spent_utxos_iter(&self) -> impl Iterator<Item = &Utxo> {
        self.mempool_spent_utxos
            .values()
            .flatten()
            .map(|(utxo, ..)| utxo)
    }

    pub fn mempool_unspent_utxos_iter(&self) -> impl Iterator<Item = &Utxo> {
        self.mempool_unspent_utxos
            .values()
            .flatten()
            .map(|au| &au.utxo)
    }

    pub(crate) fn mempool_balance_updates(
        &self,
    ) -> (
        impl Iterator<Item = (TransactionKernelId, NativeCurrencyAmount)> + '_,
        impl Iterator<Item = (TransactionKernelId, NativeCurrencyAmount)> + '_,
    ) {
        let incoming = self.mempool_spent_utxos.iter().map(|(txkid, sender_data)| {
            (
                *txkid,
                sender_data
                    .iter()
                    .map(|(utxo, _ais, _)| utxo.get_native_currency_amount())
                    .sum::<NativeCurrencyAmount>(),
            )
        });

        let outgoing = self
            .mempool_unspent_utxos
            .iter()
            .map(|(txkid, announced_utxos)| {
                (
                    *txkid,
                    announced_utxos
                        .iter()
                        .map(|au| au.utxo.get_native_currency_amount())
                        .sum::<NativeCurrencyAmount>(),
                )
            });

        (incoming, outgoing)
    }

    /// returns confirmed, total balance (includes timelocked utxos)
    pub fn confirmed_total_balance(&self, wallet_status: &WalletStatus) -> NativeCurrencyAmount {
        wallet_status.synced_unspent_total_amount()
    }

    /// returns confirmed, available balance (excludes timelocked utxos)
    pub fn confirmed_available_balance(
        &self,
        wallet_status: &WalletStatus,
        timestamp: Timestamp,
    ) -> NativeCurrencyAmount {
        wallet_status.synced_unspent_available_amount(timestamp)
    }

    /// returns unconfirmed, available balance (excludes timelocked utxos)
    pub fn unconfirmed_available_balance(
        &self,
        wallet_status: &WalletStatus,
        timestamp: Timestamp,
    ) -> NativeCurrencyAmount {
        let amount_spent_by_mempool_transactions = self
            .mempool_spent_utxos_iter()
            .map(|u| u.get_native_currency_amount())
            .sum();
        let amount_received_from_mempool_transactions = self
            .mempool_unspent_utxos_iter()
            .filter(|utxo| utxo.can_spend_at(timestamp))
            .map(|u| u.get_native_currency_amount())
            .sum();
        self.confirmed_available_balance(wallet_status, timestamp)
            .checked_add(&amount_received_from_mempool_transactions)
            .expect("balance must never overflow")
            .checked_sub(&amount_spent_by_mempool_transactions)
            .unwrap_or(NativeCurrencyAmount::zero())
    }

    /// returns unconfirmed, total balance (includes timelocked utxos)
    pub fn unconfirmed_total_balance(&self, wallet_status: &WalletStatus) -> NativeCurrencyAmount {
        wallet_status
            .synced_unspent_total_amount()
            .checked_sub(
                &self
                    .mempool_spent_utxos_iter()
                    .map(|u| u.get_native_currency_amount())
                    .sum(),
            )
            .expect("balance must never be negative")
            .checked_add(
                &self
                    .mempool_unspent_utxos_iter()
                    .map(|u| u.get_native_currency_amount())
                    .sum(),
            )
            .expect("balance must never overflow")
    }

    /// Returns the number of expected UTXOs in the database.
    pub(crate) async fn num_expected_utxos(&self) -> u64 {
        self.wallet_db.expected_utxos().len().await
    }

    /// adds a [SentTransaction] to the wallet db
    pub(crate) async fn add_sent_transaction(&mut self, sent_transaction: SentTransaction) {
        self.wallet_db
            .sent_transactions_mut()
            .push(sent_transaction)
            .await;
    }

    /// returns a count of transactions this wallet sent at given block.
    ///
    /// note that the block specifies the current tip at the moment the
    /// transactions were sent -- NOT when they were confirmed.
    ///
    /// This fn is provided to facilitate send-rate limiting.
    /// ie to limit how many payments the wallet can send per block.
    ///
    /// once send-rate limiting is disabled, this fn can probably be removed.
    pub(crate) async fn count_sent_transactions_at_block(&self, block: Digest) -> usize {
        let list = self.wallet_db.sent_transactions();
        let len = list.len().await;

        // iterate over list in reverse order (newest blocks first)
        let stream = list.stream_many_values((0..len).rev()).await;
        pin_mut!(stream); // needed for iteration

        let mut count: usize = 0;

        // note; this loop assumes that SentTransaction are ordered such
        // that any elements with the same tip_when_sent (digest) are next
        // to eachother, which should normally be true.
        // that assumption allows us to break early rather than checking the
        // entire list.

        while let Some(stx) = stream.next().await {
            if stx.tip_when_sent == block {
                count += 1;
            } else if count > 0 {
                break;
            }
        }

        count
    }

    // note: does not verify we do not have any dups.
    pub(crate) async fn add_expected_utxo(&mut self, expected_utxo: ExpectedUtxo) {
        if !expected_utxo.utxo.all_type_script_states_are_valid() {
            warn!("adding expected UTXO with unknown type scripts or invalid states to expected UTXOs database");
        }

        self.wallet_db
            .expected_utxos_mut()
            .push(expected_utxo)
            .await;
    }

    // If any output UTXO(s) are going back to our wallet (eg change utxo)
    // we add them to pool of expected incoming UTXOs so that we can
    // synchronize them after the Tx is confirmed.
    //
    // Discussion: https://github.com/Neptune-Crypto/neptune-core/pull/136
    pub(crate) async fn add_expected_utxos(
        &mut self,
        expected_utxos: impl IntoIterator<Item = ExpectedUtxo>,
    ) {
        for expected_utxo in expected_utxos.into_iter() {
            self.add_expected_utxo(ExpectedUtxo::new(
                expected_utxo.utxo,
                expected_utxo.sender_randomness,
                expected_utxo.receiver_preimage,
                expected_utxo.received_from,
            ))
            .await;
        }
    }

    /// Add a RawHashLock key to the wallet's state. If key is already stored,
    /// this is a no-op.
    ///
    /// Assumes that the cache agrees with the database.
    pub(crate) async fn add_raw_hash_key(&mut self, preimage: Digest) {
        let as_key = SpendingKey::RawHashLock(HashLockKey::from_preimage(preimage));
        if self.known_raw_hash_lock_keys.contains(&as_key) {
            return;
        }

        self.wallet_db.guesser_preimages_mut().push(preimage).await;
        self.known_raw_hash_lock_keys.push(as_key)
    }

    /// Return a list of UTXOs spent by this wallet in the transaction
    ///
    /// Returns a list of tuples (utxo, absolute-index-set, index-into-database).
    async fn scan_for_spent_utxos(
        &self,
        transaction_kernel: &TransactionKernel,
    ) -> Vec<(Utxo, AbsoluteIndexSet, u64)> {
        let confirmed_absolute_index_sets = transaction_kernel
            .inputs
            .iter()
            .map(|rr| rr.absolute_indices)
            .collect_vec();

        let monitored_utxos = self.wallet_db.monitored_utxos();
        let mut spent_own_utxos = vec![];

        let stream = monitored_utxos.stream().await;
        pin_mut!(stream); // needed for iteration

        while let Some((i, monitored_utxo)) = stream.next().await {
            let abs_i = match monitored_utxo.get_latest_membership_proof_entry() {
                Some(msmp) => msmp.1.compute_indices(Hash::hash(&monitored_utxo.utxo)),
                None => continue,
            };

            if confirmed_absolute_index_sets.contains(&abs_i) {
                spent_own_utxos.push((monitored_utxo.utxo, abs_i, i));
            }
        }
        spent_own_utxos
    }

    /// Scan the given transaction for announced UTXOs as recognized by owned
    /// `SpendingKey`s, and then verify those announced UTXOs are actually
    /// present.
    fn scan_for_announced_utxos<'a>(
        &'a self,
        tx_kernel: &'a TransactionKernel,
    ) -> impl Iterator<Item = IncomingUtxo> + 'a {
        // scan for announced utxos for every known key of every key type.
        self.get_all_known_spending_keys()
            .flat_map(|key| key.scan_for_announced_utxos(tx_kernel))

            // filter for presence in transaction
            //
            // note: this is a nice sanity check, but probably is un-necessary
            //       work that can eventually be removed.
            .filter(|au| match tx_kernel.outputs.contains(&au.addition_record()) {
                true => true,
                false => {
                    warn!("Transaction does not contain announced UTXO encrypted to own receiving address. Announced UTXO was: {:#?}", au.utxo);
                    false
                }
            })
    }

    /// Scan the given list of addition records for items that match with list
    /// of expected incoming UTXOs, and returns expected UTXOs that are present.
    ///
    /// note: this algorithm is o(n) + o(m) where:
    ///   n = number of ExpectedUtxo in database. (all-time)
    ///   m = number of transaction outputs.
    ///
    /// Returns an iterator of [OwnUtxo], which in turn contains a UTXO, sender
    /// randomness, receiver_preimage, and the addition record can be inferred
    /// from these three fields.
    pub(crate) async fn scan_for_expected_utxos<'a>(
        &'a self,
        addition_records: &'a [AdditionRecord],
    ) -> impl Iterator<Item = IncomingUtxo> + 'a {
        let expected_utxos = self.wallet_db.expected_utxos().get_all().await;
        let eu_map: HashMap<_, _> = expected_utxos
            .into_iter()
            .map(|eu| (eu.addition_record, eu))
            .collect();

        addition_records
            .iter()
            .filter_map(move |a| eu_map.get(a).map(|eu| eu.into()))
    }

    /// check if wallet already has the provided `expected_utxo`
    /// perf:
    ///
    /// this fn is o(n) with the number of ExpectedUtxo stored.  Iteration is
    /// performed from newest to oldest based on expectation that we will most
    /// often be working with recent ExpectedUtxos.
    pub async fn has_expected_utxo(&self, addition_record: AdditionRecord) -> bool {
        let len = self.wallet_db.expected_utxos().len().await;
        self.wallet_db
            .expected_utxos()
            .stream_many_values((0..len).rev())
            .await
            .any(|eu| futures::future::ready(eu.addition_record == addition_record))
            .await
    }

    /// find the `MonitoredUtxo` that matches `utxo` and sender randomness, if
    /// any.
    ///
    /// perf: this fn is o(n) with the number of MonitoredUtxo stored.  Iteration
    ///       is performed from newest to oldest based on expectation that we
    ///       will most often be working with recent MonitoredUtxos.
    pub(crate) async fn find_monitored_utxo(
        &self,
        utxo: &Utxo,
        sender_randomness: Digest,
    ) -> Option<MonitoredUtxo> {
        let len = self.wallet_db.monitored_utxos().len().await;
        let stream = self
            .wallet_db
            .monitored_utxos()
            .stream_many_values((0..len).rev())
            .await;
        pin_mut!(stream); // needed for iteration

        while let Some(mu) = stream.next().await {
            if mu.utxo == *utxo
                && mu
                    .get_latest_membership_proof_entry()
                    .is_some_and(|(_block_digest, msmp)| {
                        msmp.sender_randomness == sender_randomness
                    })
            {
                return Some(mu);
            }
        }
        None
    }

    /// Delete all ExpectedUtxo that exceed a certain age
    ///
    /// note: It is questionable if this method should ever be called
    ///       as presently implemented.
    ///
    /// issues:
    ///   1. expiration does not consider if utxo has been
    ///      claimed by wallet or not.
    ///   2. expiration thresholds are based on time, not
    ///      # of blocks.
    ///   3. what if a deep re-org occurs after ExpectedUtxo
    ///      have been expired?  possible loss of funds.
    ///
    /// Fundamentally, any time we remove an ExpectedUtxo we risk a possible
    /// loss of funds in the future.
    ///
    /// for now, it may be best to simply leave all ExpectedUtxo in the wallet
    /// database forever.  This is the safest way to prevent a possible loss of
    /// funds.
    ///
    /// note: DbtVec does not have a remove().
    ///       So it is implemented by clearing all ExpectedUtxo from DB and
    ///       adding back those that are not stale.
    pub async fn prune_stale_expected_utxos(&mut self) {
        // prune un-received ExpectedUtxo after 28 days in secs
        const UNRECEIVED_UTXO_SECS: u64 = 28 * 24 * 60 * 60;

        // prune received ExpectedUtxo after 3 days in secs.
        const RECEIVED_UTXO_SECS: u64 = 3 * 24 * 60 * 60;

        let cutoff_for_unreceived = Timestamp::now() - Timestamp::seconds(UNRECEIVED_UTXO_SECS);
        let cutoff_for_received = Timestamp::now() - Timestamp::seconds(RECEIVED_UTXO_SECS);

        let expected_utxos = self.wallet_db.expected_utxos().get_all().await;

        let keep_indexes = expected_utxos
            .iter()
            .enumerate()
            .filter(|(_, eu)| match eu.mined_in_block {
                Some((_bh, registered_timestamp)) => registered_timestamp >= cutoff_for_received,
                None => eu.notification_received >= cutoff_for_unreceived,
            })
            .map(|(idx, _)| idx);

        self.wallet_db.expected_utxos_mut().clear().await;

        for idx in keep_indexes.rev() {
            self.wallet_db
                .expected_utxos_mut()
                .push(expected_utxos[idx].clone())
                .await;
        }
    }

    // returns true if the utxo can be unlocked by one of the
    // known wallet keys.
    pub fn can_unlock(&self, utxo: &Utxo) -> bool {
        self.find_spending_key_for_utxo(utxo).is_some()
    }

    // returns Some(SpendingKey) if the utxo can be unlocked by one of the known
    // wallet keys.
    pub fn find_spending_key_for_utxo(&self, utxo: &Utxo) -> Option<SpendingKey> {
        self.get_all_known_spending_keys()
            .find(|k| k.lock_script_hash() == utxo.lock_script_hash())
    }

    // returns Some(SpendingKey) if the utxo can be unlocked by one of the known
    // wallet keys.
    pub(crate) fn find_known_spending_key_for_receiver_identifier(
        &self,
        receiver_identifier: BFieldElement,
    ) -> Option<SpendingKey> {
        self.get_all_known_spending_keys().find(|k| {
            k.receiver_identifier()
                .map(|identifier| identifier == receiver_identifier)
                .unwrap_or(false)
        })
    }

    /// returns all spending keys of all key types with derivation index less than current counter
    pub fn get_all_known_spending_keys(&self) -> impl Iterator<Item = SpendingKey> + '_ {
        KeyType::all_types()
            .into_iter()
            .flat_map(|key_type| self.get_known_spending_keys(key_type))
    }

    /// returns all spending keys of `key_type` with derivation index less than current counter
    pub fn get_known_spending_keys(
        &self,
        key_type: KeyType,
    ) -> Box<dyn Iterator<Item = SpendingKey> + '_> {
        match key_type {
            KeyType::Generation => Box::new(self.get_known_generation_spending_keys()),
            KeyType::Symmetric => Box::new(self.get_known_symmetric_keys()),
            KeyType::RawHashLock => Box::new(self.get_known_raw_hash_lock_keys()),
        }
    }

    pub(crate) fn get_known_raw_hash_lock_keys(&self) -> impl Iterator<Item = SpendingKey> + '_ {
        self.known_raw_hash_lock_keys.iter().copied()
    }

    // TODO: These spending keys should probably be derived dynamically from some
    // state in the wallet.
    //
    // Probably the wallet should keep track of index of latest derived key
    // that has been requested by the user for purpose of receiving
    // funds.  We could also perform a sequential scan at startup (or import)
    // of keys that have received funds, up to some "gap".  In bitcoin/bip32
    // this gap is defined as 20 keys in a row that have never received funds.
    fn get_known_generation_spending_keys(&self) -> impl Iterator<Item = SpendingKey> + '_ {
        self.known_generation_keys.iter().copied()
    }

    // TODO: These spending keys should probably be derived dynamically from some
    // state in the wallet.
    //
    // Probably the wallet should keep track of index of latest derived key
    // that has been requested by the user for purpose of receiving
    // funds.  We could also perform a sequential scan at startup (or import)
    // of keys that have received funds, up to some "gap".  In bitcoin/bip32
    // this gap is defined as 20 keys in a row that have never received funds.
    fn get_known_symmetric_keys(&self) -> impl Iterator<Item = SpendingKey> + '_ {
        self.known_symmetric_keys.iter().copied()
    }

    /// Get the next unused spending key of a given type.
    ///
    /// returns key at present counter (for key_type), and increments the
    /// counter. also the returned key is added to the list of known keys.
    ///
    /// Note that incrementing the counter modifies wallet state.  It is
    /// important to write to disk afterward to avoid possible funds loss.
    pub async fn next_unused_spending_key(&mut self, key_type: KeyType) -> Option<SpendingKey> {
        match key_type {
            KeyType::Generation => Some(self.next_unused_generation_spending_key().await.into()),
            KeyType::Symmetric => Some(self.next_unused_symmetric_key().await.into()),
            KeyType::RawHashLock => None,
        }
    }

    /// Get index of the next unused spending key of a given type.
    pub async fn spending_key_counter(&self, key_type: KeyType) -> Option<u64> {
        match key_type {
            KeyType::Generation => Some(self.wallet_db.get_generation_key_counter().await),
            KeyType::Symmetric => Some(self.wallet_db.get_symmetric_key_counter().await),
            KeyType::RawHashLock => None,
        }
    }

    /// Get the nth derived spending key of a given type.
    pub fn nth_spending_key(&self, key_type: KeyType, index: u64) -> Option<SpendingKey> {
        match key_type {
            KeyType::Generation => {
                Some(self.wallet_secret.nth_generation_spending_key(index).into())
            }
            KeyType::Symmetric => Some(self.wallet_secret.nth_symmetric_key(index).into()),
            KeyType::RawHashLock => None,
        }
    }

    /// Get the next unused generation spending key.
    ///
    /// returns key at present counter, and increments the counter.
    /// also the returned key is added to the list of known keys.
    ///
    /// Note that incrementing the counter modifies wallet state.  It is
    /// important to write to disk afterward to avoid possible funds loss.
    async fn next_unused_generation_spending_key(
        &mut self,
    ) -> generation_address::GenerationSpendingKey {
        let index = self.wallet_db.get_generation_key_counter().await;
        self.wallet_db.set_generation_key_counter(index + 1).await;
        let key = self.wallet_secret.nth_generation_spending_key(index);
        self.known_generation_keys.push(key.into());
        key
    }

    /// Get the next unused symmetric key.
    ///
    /// returns key at present counter, and increments the counter.
    /// also the returned key is added to the list of known keys.
    ///
    /// Note that incrementing the counter modifies wallet state.  It is
    /// important to write to disk afterward to avoid possible funds loss.
    pub async fn next_unused_symmetric_key(&mut self) -> symmetric_key::SymmetricKey {
        let index = self.wallet_db.get_symmetric_key_counter().await;
        self.wallet_db.set_symmetric_key_counter(index + 1).await;
        let key = self.wallet_secret.nth_symmetric_key(index);
        self.known_symmetric_keys.push(key.into());
        key
    }

    pub(crate) async fn claim_utxo(&mut self, utxo_claim_data: ClaimUtxoData) -> Result<()> {
        // add expected_utxo to wallet if not existing.
        //
        // note: we add it even if block is already confirmed, although not
        //       required for claiming. This is just so that we have it in the
        //       wallet for consistency and backup.
        if !utxo_claim_data.has_expected_utxo {
            self.add_expected_utxo(utxo_claim_data.expected_utxo).await;
        };

        // If UTXO was already confirmed in block, add it to monitored UTXOs
        if let Some(prepared_mutxo) = utxo_claim_data.prepared_monitored_utxo {
            self.register_incoming_utxo(prepared_mutxo).await?;
        }

        Ok(())
    }

    /// Update wallet state with new block.
    ///
    /// Assume the given block is valid and that the wallet state is not synced
    /// with the new block yet but is synced with the previous block (if any).
    pub(crate) async fn update_wallet_state_with_new_block(
        &mut self,
        previous_mutator_set_accumulator: &MutatorSetAccumulator,
        new_block: &Block,
    ) -> Result<()> {
        /// Preprocess all own monitored UTXOs prior to processing of the block.
        ///
        /// Returns
        /// - all membership proofs that need to be maintained
        /// - A mapping of all monitored UTXOs (identified by strong keys) to
        ///   their position in the monitored UTXO list in this wallet.
        async fn preprocess_own_mutxos(
            monitored_utxos: &mut DbtVec<MonitoredUtxo>,
            new_block: &Block,
        ) -> (
            HashMap<StrongUtxoKey, (MsMembershipProof, u64, Digest)>,
            HashMap<StrongUtxoKey, u64>,
        ) {
            // Find the membership proofs that were valid at the previous tip. They have
            // to be updated to the mutator set of the new block.
            let mut valid_membership_proofs_and_own_utxo_count: HashMap<
                StrongUtxoKey,
                (MsMembershipProof, u64, Digest),
            > = HashMap::default();
            let mut all_existing_mutxos: HashMap<StrongUtxoKey, u64> = HashMap::default();
            let stream = monitored_utxos.stream().await;
            pin_mut!(stream); // needed for iteration

            while let Some((i, monitored_utxo)) = stream.next().await {
                let addition_record = monitored_utxo.addition_record();
                let strong_key = StrongUtxoKey::new(addition_record, monitored_utxo.aocl_index());
                all_existing_mutxos.insert(strong_key, i);

                let utxo_digest = Hash::hash(&monitored_utxo.utxo);
                match monitored_utxo
                    .get_membership_proof_for_block(new_block.kernel.header.prev_block_digest)
                {
                    Some(ms_mp) => {
                        let aocl_leaf_index = ms_mp.aocl_leaf_index;
                        debug!("Found valid mp for UTXO with leaf index: {aocl_leaf_index}");
                        let replaced = valid_membership_proofs_and_own_utxo_count.insert(
                            StrongUtxoKey::new(addition_record, aocl_leaf_index),
                            (ms_mp, i, utxo_digest),
                        );

                        if let Some(replaced) = replaced {
                            panic!(
                                "Strong key must be unique in wallet DB. addition record: {addition_record:?}; ms_mp.aocl_leaf_index: {}.\n\n Existing value was: {replaced:?}", aocl_leaf_index
                            );
                        }
                    }
                    None => {
                        // Monitored UTXO does not have a synced MS-membership proof.
                        // Was MUTXO marked as abandoned? Then this is fine. Otherwise, log a .
                        // TODO: If MUTXO was spent, maybe we also don't want to maintain it?
                        if monitored_utxo.abandoned_at.is_some() {
                            debug!("Monitored UTXO with addition record {addition_record} was marked as abandoned. Skipping.");
                        } else {
                            let confirmed_in_block_info = match monitored_utxo.confirmed_in_block {
                                Some(mutxo_received_in_block) => format!(
                                    "UTXO was received at block height {}.",
                                    mutxo_received_in_block.2
                                ),
                                None => String::from("No info about when UTXO was confirmed."),
                            };
                            warn!(
                            "Unable to find valid membership proof for UTXO with addition record {addition_record}. {confirmed_in_block_info} Current block height is {}", new_block.kernel.header.height
                        );
                        }
                    }
                }
            }

            (
                valid_membership_proofs_and_own_utxo_count,
                all_existing_mutxos,
            )
        }

        let tx_kernel = new_block.kernel.body.transaction_kernel.clone();

        let spent_inputs: Vec<(Utxo, AbsoluteIndexSet, u64)> =
            self.scan_for_spent_utxos(&tx_kernel).await;

        let onchain_received_outputs = self.scan_for_announced_utxos(&tx_kernel);

        let MutatorSetUpdate {
            additions: addition_records,
            removals: _removal_records,
        } = new_block.mutator_set_update();

        let offchain_received_outputs = self
            .scan_for_expected_utxos(&addition_records)
            .await
            .collect_vec();

        let all_spendable_received_outputs = onchain_received_outputs
            .chain(offchain_received_outputs.iter().cloned())
            .filter(|announced_utxo| announced_utxo.utxo.all_type_script_states_are_valid());

        let incoming: HashMap<AdditionRecord, IncomingUtxo> = all_spendable_received_outputs
            .map(|utxo| (utxo.addition_record(), utxo))
            .collect();

        // Derive the membership proofs for received UTXOs, and in
        // the process update existing membership proofs with
        // updates from this block

        let monitored_utxos = self.wallet_db.monitored_utxos_mut();
        let mut guesser_preimage: Option<Digest> = None;
        let mut incoming_utxo_recovery_data_list = vec![];

        // return early if there are no monitored utxos and this
        // block does not affect our balance
        if spent_inputs.is_empty() && incoming.is_empty() && monitored_utxos.is_empty().await {
            return Ok(());
        }

        // Get membership proofs that should be maintained, and the set of
        // UTXOs that were already added. The latter is empty if the wallet
        // never processed this block, or a sibling-block with the same block
        // proof before.
        let (mut valid_membership_proofs_and_own_utxo_count, all_existing_mutxos) =
            preprocess_own_mutxos(monitored_utxos, new_block).await;

        debug!(
            "handling {} monitored UTXOs",
            valid_membership_proofs_and_own_utxo_count.len()
        );

        // Loop over all input UTXOs, applying all addition records. In each iteration,
        // a) Update all existing MS membership proofs
        // b) Register incoming transactions and derive their membership proofs
        let mut changed_mps = vec![];
        let mut msa_state = previous_mutator_set_accumulator.clone();

        let mut removal_records = tx_kernel.inputs.clone();
        removal_records.reverse();
        let mut removal_records: Vec<&mut RemovalRecord> =
            removal_records.iter_mut().collect::<Vec<_>>();

        for addition_record in &addition_records {
            // Don't pull this declaration out of the for-loop since the hash map can grow
            // within this loop.
            let utxo_digests = valid_membership_proofs_and_own_utxo_count
                .values()
                .map(|(_, _, utxo_digest)| *utxo_digest)
                .collect_vec();

            {
                let updated_mp_indices: Result<Vec<usize>, Box<dyn Error>> =
                    MsMembershipProof::batch_update_from_addition(
                        &mut valid_membership_proofs_and_own_utxo_count
                            .values_mut()
                            .map(|(mp, _index, _)| mp)
                            .collect_vec(),
                        &utxo_digests,
                        &msa_state,
                        addition_record,
                    );
                match updated_mp_indices {
                    Ok(mut indices_of_mutated_mps) => {
                        changed_mps.append(&mut indices_of_mutated_mps)
                    }
                    Err(_) => bail!("Failed to update membership proofs with addition record"),
                };
            }

            // Batch update removal records to keep them valid after next addition
            RemovalRecord::batch_update_from_addition(&mut removal_records, &msa_state);

            // If the output UTXO belongs to us, add it to the list of monitored
            // UTXOs and add its membership proof to the list of managed
            // membership proofs.
            if let Some(incoming_utxo) = incoming.get(addition_record) {
                let IncomingUtxo {
                    utxo,
                    sender_randomness,
                    receiver_preimage,
                } = incoming_utxo.to_owned();
                let is_guesser_fee = incoming_utxo.is_guesser_fee();
                info!(
                    "Received UTXO in block {}, height {}\nvalue = {}\n\
                    is guesser fee: {is_guesser_fee}\n\n",
                    new_block.hash(),
                    new_block.kernel.header.height,
                    utxo.get_native_currency_amount(),
                );
                let utxo_digest = Hash::hash(&utxo);
                let new_own_membership_proof =
                    msa_state.prove(utxo_digest, sender_randomness, receiver_preimage);
                let aocl_index = new_own_membership_proof.aocl_leaf_index;
                let strong_key = StrongUtxoKey::new(*addition_record, aocl_index);

                // Add the new UTXO to the list of monitored UTXOs
                let mut mutxo = MonitoredUtxo::new(utxo.clone(), self.number_of_mps_per_utxo);
                mutxo.confirmed_in_block = Some((
                    new_block.hash(),
                    new_block.kernel.header.timestamp,
                    new_block.kernel.header.height,
                ));

                if let Some(mutxo_index) = all_existing_mutxos.get(&strong_key) {
                    debug!("Repeated monitored UTXO. Not adding new entry to monitored UTXOs");
                    valid_membership_proofs_and_own_utxo_count.insert(
                        strong_key,
                        (new_own_membership_proof, *mutxo_index, utxo_digest),
                    );

                    // Update `confirmed_in_block` data to reflect this reorg.
                    let mut existing_mutxo = monitored_utxos.get(*mutxo_index).await;
                    existing_mutxo.confirmed_in_block = mutxo.confirmed_in_block;
                    monitored_utxos.set(*mutxo_index, existing_mutxo).await;
                } else {
                    let mutxos_len = monitored_utxos.len().await;
                    valid_membership_proofs_and_own_utxo_count.insert(
                        strong_key,
                        (new_own_membership_proof, mutxos_len, utxo_digest),
                    );
                    monitored_utxos.push(mutxo).await;

                    // If this is a guesser-fee UTXO, store the guesser-preimage.
                    if incoming_utxo.is_guesser_fee() {
                        guesser_preimage = Some(receiver_preimage);
                    }

                    // Add the data required to restore the UTXOs membership proof from public
                    // data to the secret's file.
                    let utxo_ms_recovery_data = IncomingUtxoRecoveryData {
                        utxo,
                        sender_randomness,
                        receiver_preimage,
                        aocl_index,
                    };
                    incoming_utxo_recovery_data_list.push(utxo_ms_recovery_data);
                }
            }

            // Update mutator set to bring it to the correct state for the next call to batch-update
            msa_state.add(addition_record);
        }

        // apply all removal records
        debug!("Block has {} removal records", removal_records.len());

        // reversed twice, so matches order in block.
        let mut removal_record_index: usize = 0;
        while let Some(removal_record) = removal_records.pop() {
            let res = MsMembershipProof::batch_update_from_remove(
                &mut valid_membership_proofs_and_own_utxo_count
                    .values_mut()
                    .map(|(mp, _index, _)| mp)
                    .collect_vec(),
                removal_record,
            );
            match res {
                Ok(mut indices_of_mutated_mps) => changed_mps.append(&mut indices_of_mutated_mps),
                Err(_) => bail!("Failed to update membership proofs with removal record"),
            };

            // Batch update removal records to keep them valid after next removal
            RemovalRecord::batch_update_from_remove(&mut removal_records, removal_record);

            // TODO: We mark membership proofs as spent, so they can be deleted. But
            // how do we ensure that we can recover them in case of a fork? For now we maintain
            // them even if the are spent, and then, later, we can add logic to remove these
            // membership proofs of spent UTXOs once they have been spent for M blocks.
            match spent_inputs
                .iter()
                .find(|(_, abs_i, _mutxo_list_index)| *abs_i == removal_record.absolute_indices)
            {
                None => (),
                Some((_spent_utxo, _abs_i, mutxo_list_index)) => {
                    debug!(
                        "Discovered own input at removal record index {}, marking UTXO as spent.",
                        removal_record_index
                    );

                    let mut spent_mutxo = monitored_utxos.get(*mutxo_list_index).await;
                    spent_mutxo.mark_as_spent(new_block);
                    monitored_utxos.set(*mutxo_list_index, spent_mutxo).await;
                }
            }

            msa_state.remove(removal_record);
            removal_record_index += 1;
        }

        // Sanity check that `msa_state` agrees with the mutator set from the applied block
        assert_eq!(
            new_block.mutator_set_accumulator_after().clone().hash(),
            msa_state.hash(),
            "\n\nMutator set in applied block:\n{}\n\nmust agree with that in wallet handler:\n{}\n\n",
            new_block.mutator_set_accumulator_after().clone().hash(),
            msa_state.hash(),
        );

        changed_mps.sort();
        changed_mps.dedup();
        debug!("Number of mutated membership proofs: {}", changed_mps.len());

        for (updated_ms_mp, own_utxo_index, utxo_digest) in
            valid_membership_proofs_and_own_utxo_count.values()
        {
            let mut monitored_utxo = monitored_utxos.get(*own_utxo_index).await;
            trace!(
                "Updating MSMP for MUTXO with wallet-index {own_utxo_index}; with AOCL leaf-index {}. MUTXO:\n{monitored_utxo}",
                updated_ms_mp.aocl_leaf_index
            );
            monitored_utxo.add_membership_proof_for_tip(new_block.hash(), updated_ms_mp.to_owned());

            // Sanity check that membership proofs of non-spent transactions are still valid
            assert!(
                monitored_utxo.spent_in_block.is_some()
                    || msa_state.verify(*utxo_digest, updated_ms_mp)
            );

            monitored_utxos.set(*own_utxo_index, monitored_utxo).await;

            // TODO: What if a newly added transaction replaces a transaction that was in another fork?
            // How do we ensure that this transaction is not counted twice?
            // One option is to only count UTXOs that are synced as valid.
            // Another option is to attempt to mark those abandoned monitored UTXOs as reorganized.
        }

        // write UTXO-recovery data to disk.
        for item in incoming_utxo_recovery_data_list.into_iter() {
            self.store_utxo_ms_recovery_data(item).await?;
        }

        // Write guesser-preimage for guesser fee UTXOs to DB, and cache.
        if let Some(guesser_preimage) = guesser_preimage {
            self.add_raw_hash_key(guesser_preimage).await;
        }

        // Mark all expected UTXOs that were received in this block as received
        let updates = self
            .wallet_db
            .expected_utxos()
            .get_all()
            .await
            .into_iter()
            .enumerate()
            .filter(|(_, eu)| {
                offchain_received_outputs
                    .iter()
                    .any(|au| au.addition_record() == eu.addition_record)
            })
            .map(|(idx, mut eu)| {
                eu.mined_in_block = Some((new_block.hash(), new_block.kernel.header.timestamp));
                (idx as Index, eu)
            });
        self.wallet_db.expected_utxos_mut().set_many(updates).await;

        self.wallet_db.set_sync_label(new_block.hash()).await;

        Ok(())
    }

    /// writes prepared utxo claim data to disk
    ///
    /// Informs wallet of a Utxo *after* parent Tx is confirmed in a block
    ///
    /// no validation. assumes input data is valid/correct.
    ///
    /// The caller should persist wallet DB to disk after this returns.
    pub(crate) async fn register_incoming_utxo(
        &mut self,
        monitored_utxo: MonitoredUtxo,
    ) -> Result<()> {
        // write to disk.
        let recovery_data: IncomingUtxoRecoveryData = (&monitored_utxo).try_into()?;
        self.store_utxo_ms_recovery_data(recovery_data).await?;

        // add monitored_utxo
        self.wallet_db
            .monitored_utxos_mut()
            .push(monitored_utxo)
            .await;

        Ok(())
    }

    pub async fn is_synced_to(&self, tip_hash: Digest) -> bool {
        let db_sync_digest = self.wallet_db.get_sync_label().await;
        if db_sync_digest != tip_hash {
            return false;
        }
        let monitored_utxos = self.wallet_db.monitored_utxos();

        // We assume that the membership proof can only be stored
        // if it is valid for the given block hash, so there is
        // no need to test validity here.
        let stream = monitored_utxos.stream_values().await;
        pin_mut!(stream); // needed for iteration

        stream
            .all(|m| futures::future::ready(m.get_membership_proof_for_block(tip_hash).is_some()))
            .await
    }

    /// see [WalletStatus] for a description
    pub async fn get_wallet_status(
        &self,
        tip_digest: Digest,
        mutator_set_accumulator: &MutatorSetAccumulator,
    ) -> WalletStatus {
        let monitored_utxos = self.wallet_db.monitored_utxos();
        let mut synced_unspent = vec![];
        let mut synced_spent = vec![];

        // note: field WalletStatus::unsynced is presently only used by:
        //  a) unit test(s)
        //  b) indirectly the neptune-cli `wallet-status` command when
        //     it json serializes `WalletStatus` to stdout.
        let mut unsynced = vec![];

        let stream = monitored_utxos.stream().await;
        pin_mut!(stream); // needed for iteration

        while let Some((_i, mutxo)) = stream.next().await {
            let utxo = mutxo.utxo.clone();
            if let Some(mp) = mutxo.get_membership_proof_for_block(tip_digest) {
                // To determine whether the UTXO was spent, we cannot rely on
                // the `spent_in_block` which might be set to blocks that have
                // since been reorganized away.
                let spent = !mutator_set_accumulator.verify(Tip5::hash(&mutxo.utxo), &mp);
                if spent {
                    synced_spent.push(WalletStatusElement::new(mp.aocl_leaf_index, utxo));
                } else {
                    synced_unspent.push((
                        WalletStatusElement::new(mp.aocl_leaf_index, utxo),
                        mp.clone(),
                    ));
                }
            } else {
                let any_mp = &mutxo.blockhash_to_membership_proof.iter().next().unwrap().1;
                unsynced.push(WalletStatusElement::new(any_mp.aocl_leaf_index, utxo));
            }
        }

        WalletStatus {
            synced_unspent,
            synced_spent,
            unsynced,
        }
    }

    /// Allocate sufficient UTXOs to generate a transaction.
    ///
    /// Requested amount `total_spend` must include fees that are paid in the
    /// transaction.
    pub(crate) async fn allocate_sufficient_input_funds(
        &self,
        total_spend: NativeCurrencyAmount,
        tip_digest: Digest,
        mutator_set_accumulator: &MutatorSetAccumulator,
        timestamp: Timestamp,
    ) -> Result<Vec<UnlockedUtxo>> {
        // We only attempt to generate a transaction using those UTXOs that have up-to-date
        // membership proofs.
        let wallet_status = self
            .get_wallet_status(tip_digest, mutator_set_accumulator)
            .await;

        // First check that we have enough. Otherwise, return an error.
        let confirmed_available_amount_without_mempool_spends = self
            .confirmed_available_balance(&wallet_status, timestamp)
            .checked_sub(
                &self
                    .mempool_spent_utxos_iter()
                    .map(|u| u.get_native_currency_amount())
                    .sum(),
            )
            .expect("balance must never be negative");
        if confirmed_available_amount_without_mempool_spends < total_spend {
            bail!(
                "Insufficient funds. Requested: {}, Available: {}",
                total_spend,
                confirmed_available_amount_without_mempool_spends,
            );
        }

        let mut input_funds = vec![];
        let mut allocated_amount = NativeCurrencyAmount::zero();
        let index_sets_of_inputs_in_mempool_txs: HashSet<AbsoluteIndexSet> = self
            .mempool_spent_utxos
            .iter()
            .flat_map(|(_txkid, tx_inputs)| tx_inputs.iter())
            .map(|(_, absi, _)| *absi)
            .collect();
        for (wallet_status_element, membership_proof) in wallet_status.synced_unspent.iter() {
            // Don't allocate more than needed
            if allocated_amount >= total_spend {
                break;
            }

            // Don't attempt to use UTXOs that are still timelocked.
            if !wallet_status_element.utxo.can_spend_at(timestamp) {
                continue;
            }

            // Don't use inputs that are already spent by txs in mempool.
            let absolute_index_set =
                membership_proof.compute_indices(Tip5::hash(&wallet_status_element.utxo));
            if index_sets_of_inputs_in_mempool_txs.contains(&absolute_index_set) {
                continue;
            }

            let spending_key = match self.find_spending_key_for_utxo(&wallet_status_element.utxo) {
                Some(k) => k,
                None => {
                    warn!(
                        "spending key not found for utxo: {:?}",
                        wallet_status_element.utxo
                    );
                    continue;
                }
            };

            input_funds.push(UnlockedUtxo::unlock(
                wallet_status_element.utxo.clone(),
                spending_key,
                membership_proof.clone(),
            ));
            allocated_amount =
                allocated_amount + wallet_status_element.utxo.get_native_currency_amount();
        }

        // Sanity check. Shouldn't be possible to hit because of above balance
        // check that also takes mempool into account.
        assert!(
            allocated_amount >= total_spend,
            "UTXO allocation failed. This should not be possible. Requested: {}, Available: {}",
            total_spend,
            confirmed_available_amount_without_mempool_spends,
        );

        Ok(input_funds)
    }

    pub async fn get_all_own_coins_with_possible_timelocks(
        &self,
        mutator_set_accumulator: &MutatorSetAccumulator,
        tip_digest: Digest,
    ) -> Vec<CoinWithPossibleTimeLock> {
        let monitored_utxos = self.wallet_db.monitored_utxos();
        let mut own_coins = vec![];

        let stream = monitored_utxos.stream_values().await;
        pin_mut!(stream); // needed for iteration

        while let Some(mutxo) = stream.next().await {
            if mutxo.abandoned_at.is_some()
                || mutxo.get_latest_membership_proof_entry().is_none()
                || mutxo.confirmed_in_block.is_none()
            {
                continue;
            }
            let Some(msmp) = mutxo.membership_proof_ref_for_block(tip_digest) else {
                continue;
            };
            let is_spent = !mutator_set_accumulator.verify(Tip5::hash(&mutxo.utxo), msmp);
            if is_spent {
                continue;
            }
            let coin = CoinWithPossibleTimeLock {
                amount: mutxo.utxo.get_native_currency_amount(),
                confirmed: mutxo.confirmed_in_block.unwrap().1,
                release_date: mutxo.utxo.release_date(),
            };
            own_coins.push(coin);
        }
        own_coins
    }
}

#[cfg(test)]
mod tests {
    use generation_address::GenerationSpendingKey;
    use rand::random;
    use rand::Rng;
    use tracing_test::traced_test;

    use super::*;
    use crate::config_models::cli_args;
    use crate::config_models::network::Network;
    use crate::job_queue::triton_vm::TritonVmJobQueue;
    use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::models::blockchain::transaction::utxo::Coin;
    use crate::models::state::tx_proving_capability::TxProvingCapability;
    use crate::models::state::wallet::expected_utxo::ExpectedUtxo;
    use crate::models::state::wallet::transaction_output::TxOutput;
    use crate::models::state::wallet::utxo_notification::UtxoNotificationMedium;
    use crate::models::state::GlobalStateLock;
    use crate::tests::shared::invalid_block_with_transaction;
    use crate::tests::shared::make_mock_block;
    use crate::tests::shared::make_mock_block_guesser_preimage_and_guesser_fraction;
    use crate::tests::shared::mock_genesis_global_state;
    use crate::tests::shared::mock_genesis_wallet_state;
    use crate::tests::shared::wallet_state_has_all_valid_mps;

    impl WalletState {
        /// Delete all guesser-preimage keys from database and cache.
        pub(crate) async fn clear_raw_hash_keys(&mut self) {
            self.known_raw_hash_lock_keys.clear();
            self.wallet_db.guesser_preimages_mut().clear().await;
        }
    }

    #[tokio::test]
    #[traced_test]
    async fn find_monitored_utxo_test() {
        let network = Network::Testnet;
        let alice_global_lock = mock_genesis_global_state(
            network,
            0,
            WalletSecret::devnet_wallet(),
            cli_args::Args::default(),
        )
        .await;

        let premine_utxo = {
            let wallet = &alice_global_lock.lock_guard().await.wallet_state;
            Block::premine_utxos(network)
                .into_iter()
                .find(|premine_utxo| wallet.can_unlock(premine_utxo))
                .or_else(|| panic!())
                .unwrap()
        };
        let premine_sender_randomness = Block::premine_sender_randomness(network);

        let premine_mutxo = alice_global_lock
            .lock_guard()
            .await
            .wallet_state
            .find_monitored_utxo(&premine_utxo, premine_sender_randomness)
            .await
            .expect("Must be able to find premine MUTXO with this method");
        assert_eq!(premine_utxo, premine_mutxo.utxo);

        let genesis_digest = Block::genesis(network).hash();
        assert_eq!(
            premine_sender_randomness,
            premine_mutxo
                .get_membership_proof_for_block(genesis_digest)
                .unwrap()
                .sender_randomness
        );

        // Using another sender randomness returns nothing
        assert!(alice_global_lock
            .lock_guard()
            .await
            .wallet_state
            .find_monitored_utxo(&premine_utxo, random())
            .await
            .is_none());
    }

    #[tokio::test]
    #[traced_test]
    async fn does_not_make_tx_with_timelocked_utxos() {
        // Ensure that timelocked UTXOs are not used when selecting input-UTXOs
        // to a transaction.
        // This test is a regression test for issue:
        // <https://github.com/Neptune-Crypto/neptune-core/issues/207>.

        let network = Network::Main;
        let mut alice_global_lock = mock_genesis_global_state(
            network,
            0,
            WalletSecret::devnet_wallet(),
            cli_args::Args::default(),
        )
        .await;

        let mut alice = alice_global_lock.global_state_lock.lock_guard_mut().await;
        let launch_timestamp = alice.chain.light_state().header().timestamp;
        let released_timestamp = launch_timestamp + Timestamp::months(12);
        let genesis = alice.chain.light_state();
        let genesis_digest = genesis.hash();
        let mutator_set_accumulator_after_genesis = genesis.mutator_set_accumulator_after();
        let alice_ws_genesis = alice
            .wallet_state
            .get_wallet_status(genesis_digest, &mutator_set_accumulator_after_genesis)
            .await;

        // First, check that error is returned, when available balance is not
        // there, as it is timelocked.
        let one_coin = NativeCurrencyAmount::coins(1);
        assert!(alice_ws_genesis
            .synced_unspent_available_amount(launch_timestamp)
            .is_zero());
        assert!(!alice_ws_genesis
            .synced_unspent_available_amount(released_timestamp)
            .is_zero());
        assert!(
            alice
                .wallet_state
                .allocate_sufficient_input_funds(
                    one_coin,
                    genesis_digest,
                    &mutator_set_accumulator_after_genesis,
                    launch_timestamp
                )
                .await
                .is_err(),
            "Disallow allocation of timelocked UTXOs"
        );
        assert!(
            alice
                .wallet_state
                .allocate_sufficient_input_funds(
                    one_coin,
                    genesis_digest,
                    &mutator_set_accumulator_after_genesis,
                    released_timestamp
                )
                .await
                .is_ok(),
            "Allow allocation when timelock is expired"
        );

        // Then check that the timelocked UTXO (from the premine) is not
        // selected even when the necessary balance is there through other UTXOs
        // that are *not* timelocked.
        let block_1_timestamp = launch_timestamp + Timestamp::minutes(2);
        let alice_key = alice
            .wallet_state
            .wallet_secret
            .nth_generation_spending_key_for_tests(0);
        let (block1, composer_expected) = make_mock_block(
            genesis,
            Some(block_1_timestamp),
            alice_key,
            Default::default(),
        )
        .await;

        alice
            .set_new_self_mined_tip(block1.clone(), composer_expected)
            .await
            .unwrap();

        let input_utxos = alice
            .wallet_state
            .allocate_sufficient_input_funds(
                one_coin,
                block1.hash(),
                &block1.mutator_set_accumulator_after(),
                block_1_timestamp,
            )
            .await
            .unwrap();

        assert!(
            input_utxos
                .iter()
                .all(|unlocker| unlocker.utxo.can_spend_at(block_1_timestamp)),
            "All allocated UTXOs must be spendable now"
        );
    }

    /// Test-setup.
    ///
    /// Generate a new wallet and state for Bob, who proceeds to mine one block.
    /// Bob updates his wallet state with this block and as a result has a
    /// nonzero balance.
    ///
    /// Note that this function is probabilistic. Block is invalid, both wrt.
    /// PoW and proof.
    async fn bob_mines_one_block(
        network: Network,
    ) -> (Block, GlobalStateLock, GenerationSpendingKey) {
        let mut rng = rand::rng();
        let cli = cli_args::Args::default();

        let bob_wallet_secret = WalletSecret::new_random();
        let bob_key = bob_wallet_secret.nth_generation_spending_key_for_tests(0);
        let mut bob_global_lock =
            mock_genesis_global_state(network, 0, bob_wallet_secret, cli.clone()).await;

        // `bob` both composes and guesses the PoW solution of this block.
        let (block1, composer_fee_eutxos) =
            make_mock_block(&Block::genesis(network), None, bob_key, rng.random()).await;

        bob_global_lock
            .lock_guard_mut()
            .await
            .set_new_self_mined_tip(block1.clone(), composer_fee_eutxos)
            .await
            .unwrap();

        (block1, bob_global_lock, bob_key)
    }

    #[tokio::test]
    #[traced_test]
    async fn test_update_wallet_state_repeated_addition_records() {
        let network = Network::Main;
        let cli = cli_args::Args::default();

        let alice_wallet_secret = WalletSecret::new_random();
        let alice_key = alice_wallet_secret.nth_generation_spending_key_for_tests(0);
        let mut alice = mock_genesis_global_state(network, 0, alice_wallet_secret, cli).await;

        let (block1, mut bob, bob_key) = bob_mines_one_block(network).await;

        alice
            .lock_guard_mut()
            .await
            .set_new_tip(block1.clone())
            .await
            .unwrap();

        // Bob sends two identical coins (=identical addition records) to Alice.
        let fee = NativeCurrencyAmount::coins(1);
        let txoutput = TxOutput::onchain_native_currency(
            NativeCurrencyAmount::coins(7),
            random(),
            alice_key.to_address().into(),
            false,
        );
        let tx_outputs = vec![txoutput.clone(), txoutput.clone()];
        let (tx_block2, _, _) = bob
            .lock_guard_mut()
            .await
            .create_transaction_with_prover_capability(
                tx_outputs.clone().into(),
                bob_key.into(),
                UtxoNotificationMedium::OnChain,
                fee,
                network.launch_date() + Timestamp::minutes(11),
                TxProvingCapability::PrimitiveWitness,
                &TritonVmJobQueue::dummy(),
            )
            .await
            .unwrap();

        // Make block 2, verify that Alice registers correct balance.
        let block2 = invalid_block_with_transaction(&block1, tx_block2.clone());
        bob.lock_guard_mut()
            .await
            .set_new_tip(block2.clone())
            .await
            .unwrap();
        alice
            .lock_guard_mut()
            .await
            .set_new_tip(block2.clone())
            .await
            .unwrap();
        {
            let ags = alice.lock_guard().await;
            let wallet_status = ags
                .wallet_state
                .get_wallet_status(block2.hash(), &block2.mutator_set_accumulator_after())
                .await;
            assert_eq!(
                NativeCurrencyAmount::coins(14),
                ags.wallet_state
                    .confirmed_available_balance(&wallet_status, tx_block2.kernel.timestamp),
                "Both UTXOs must be registered by wallet and contribute to balance"
            );
        }

        // Repeat the outputs to Alice in block 3 and verify correct new
        // balance.
        let (tx_block3, _, _) = bob
            .lock_guard_mut()
            .await
            .create_transaction_with_prover_capability(
                tx_outputs.into(),
                bob_key.into(),
                UtxoNotificationMedium::OnChain,
                fee,
                network.launch_date() + Timestamp::minutes(22),
                TxProvingCapability::PrimitiveWitness,
                &TritonVmJobQueue::dummy(),
            )
            .await
            .unwrap();
        let block3 = invalid_block_with_transaction(&block2, tx_block3.clone());
        alice
            .lock_guard_mut()
            .await
            .set_new_tip(block3.clone())
            .await
            .unwrap();
        {
            let ags = alice.lock_guard().await;
            let wallet_status = ags
                .wallet_state
                .get_wallet_status(block3.hash(), &block3.mutator_set_accumulator_after())
                .await;
            assert_eq!(
                NativeCurrencyAmount::coins(28),
                ags.wallet_state
                    .confirmed_available_balance(&wallet_status, tx_block2.kernel.timestamp),
                "All four UTXOs must be registered by wallet and contribute to balance"
            );
        }
    }

    #[tokio::test]
    #[traced_test]
    async fn test_invalid_type_script_states() {
        let network = Network::Main;
        let cli = cli_args::Args::default();
        let (block1, mut bob, bob_key) = bob_mines_one_block(network).await;

        let alice_wallet_secret = WalletSecret::new_random();
        let alice_key = alice_wallet_secret.nth_generation_spending_key_for_tests(0);
        let mut alice = mock_genesis_global_state(network, 0, alice_wallet_secret, cli).await;
        alice
            .lock_guard_mut()
            .await
            .set_new_tip(block1.clone())
            .await
            .unwrap();

        let txo = TxOutput::offchain_native_currency(
            NativeCurrencyAmount::coins(3),
            random(),
            alice_key.to_address().into(),
            false,
        );
        let fee = NativeCurrencyAmount::coins(10);
        let (mut tx_block2, _, _) = bob
            .lock_guard_mut()
            .await
            .create_transaction_with_prover_capability(
                vec![txo.clone()].into(),
                bob_key.into(),
                UtxoNotificationMedium::OnChain,
                fee,
                network.launch_date() + Timestamp::minutes(11),
                TxProvingCapability::PrimitiveWitness,
                &TritonVmJobQueue::dummy(),
            )
            .await
            .unwrap();

        let mut bad_utxo = txo.utxo();
        bad_utxo = bad_utxo.append_to_coin_state(0, random());
        let bad_txo = txo.clone().replace_utxo(bad_utxo);
        let expected_bad_utxos = alice
            .lock_guard()
            .await
            .wallet_state
            .extract_expected_utxos(vec![bad_txo.clone()].into(), UtxoNotifier::Cli);
        alice
            .lock_guard_mut()
            .await
            .wallet_state
            .add_expected_utxos(expected_bad_utxos)
            .await;
        let bad_addition_record = commit(
            Tip5::hash(&bad_txo.utxo()),
            txo.sender_randomness(),
            txo.receiver_digest(),
        );
        let bad_kernel = TransactionKernelModifier::default()
            .outputs(vec![bad_addition_record])
            .modify(tx_block2.kernel.clone());
        tx_block2.kernel = bad_kernel;
        let block2 = invalid_block_with_transaction(&block1, tx_block2.clone());

        alice
            .lock_guard_mut()
            .await
            .set_new_tip(block2.clone())
            .await
            .unwrap();
        {
            let ags = alice.lock_guard().await;
            let wallet_status = ags
                .wallet_state
                .get_wallet_status(block2.hash(), &block2.mutator_set_accumulator_after())
                .await;

            assert!(
                ags.wallet_state
                    .confirmed_available_balance(&wallet_status, tx_block2.kernel.timestamp)
                    .is_zero(),
                "UTXO with bad typescript state may not count towards balance"
            );
        }
        assert!(
            alice
                .lock_guard()
                .await
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .len()
                .await
                .is_zero(),
            "UTXO with unknown typescript may not added to MUTXO list"
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn test_unrecognized_type_script() {
        let network = Network::Main;
        let cli = cli_args::Args::default();

        let alice_wallet_secret = WalletSecret::new_random();
        let alice_key = alice_wallet_secret.nth_generation_spending_key_for_tests(0);
        let mut alice = mock_genesis_global_state(network, 0, alice_wallet_secret, cli).await;

        let (block1, mut bob, bob_key) = bob_mines_one_block(network).await;

        alice
            .lock_guard_mut()
            .await
            .set_new_tip(block1.clone())
            .await
            .unwrap();

        let txo = TxOutput::offchain_native_currency(
            NativeCurrencyAmount::coins(3),
            random(),
            alice_key.to_address().into(),
            false,
        );
        let fee = NativeCurrencyAmount::coins(10);
        let (mut tx_block2, _, _) = bob
            .lock_guard_mut()
            .await
            .create_transaction_with_prover_capability(
                vec![txo.clone()].into(),
                bob_key.into(),
                UtxoNotificationMedium::OnChain,
                fee,
                network.launch_date() + Timestamp::minutes(11),
                TxProvingCapability::PrimitiveWitness,
                &TritonVmJobQueue::dummy(),
            )
            .await
            .unwrap();
        let unrecognized_typescript = Coin {
            type_script_hash: random(),
            state: vec![random(), random()],
        };
        let bad_txo = txo.clone().with_coin(unrecognized_typescript);
        let expected_bad_utxos = alice
            .lock_guard()
            .await
            .wallet_state
            .extract_expected_utxos(vec![bad_txo.clone()].into(), UtxoNotifier::Cli);
        alice
            .lock_guard_mut()
            .await
            .wallet_state
            .add_expected_utxos(expected_bad_utxos)
            .await;
        let bad_addition_record = commit(
            Tip5::hash(&bad_txo.utxo()),
            txo.sender_randomness(),
            txo.receiver_digest(),
        );
        let bad_kernel = TransactionKernelModifier::default()
            .outputs(vec![bad_addition_record])
            .modify(tx_block2.kernel.clone());
        tx_block2.kernel = bad_kernel;
        let block2 = invalid_block_with_transaction(&block1, tx_block2.clone());
        alice
            .lock_guard_mut()
            .await
            .set_new_tip(block2.clone())
            .await
            .unwrap();
        {
            let ags = alice.lock_guard().await;
            let wallet_status = ags
                .wallet_state
                .get_wallet_status(block2.hash(), &block2.mutator_set_accumulator_after())
                .await;

            assert!(
                ags.wallet_state
                    .confirmed_available_balance(&wallet_status, tx_block2.kernel.timestamp)
                    .is_zero(),
                "UTXO with unknown typescript may not count towards balance"
            );
        }
        assert!(
            alice
                .lock_guard()
                .await
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .len()
                .await
                .is_zero(),
            "UTXO with unknown typescript may not added to MUTXO list"
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn never_store_same_utxo_twice_different_blocks() {
        let mut rng = rand::rng();
        let network = Network::Main;
        let bob_wallet_secret = WalletSecret::new_random();
        let bob_key = bob_wallet_secret.nth_generation_spending_key_for_tests(0);
        let mut bob_global_lock =
            mock_genesis_global_state(network, 0, bob_wallet_secret, cli_args::Args::default())
                .await;

        let genesis_block = Block::genesis(network);
        let guesser_preimage_1a: Digest = rng.random();
        let mock_block_seed = rng.random();
        let guesser_fraction = 0.5f64;

        // `bob` both composes and guesses the PoW solution of this block.
        let (block_1a, expected_utxos_block_1a) =
            make_mock_block_guesser_preimage_and_guesser_fraction(
                &genesis_block,
                None,
                bob_key,
                mock_block_seed,
                guesser_fraction,
                guesser_preimage_1a,
            )
            .await;
        let guesser_fee_utxo_infos0 = block_1a.guesser_fee_expected_utxos(guesser_preimage_1a);

        let mut bob = bob_global_lock.lock_guard_mut().await;
        let mutxos_1a = bob.wallet_state.wallet_db.monitored_utxos().get_all().await;
        bob.wallet_state
            .add_expected_utxos(expected_utxos_block_1a.clone())
            .await;
        bob.set_new_self_mined_tip(block_1a.clone(), guesser_fee_utxo_infos0)
            .await
            .unwrap();
        assert_eq!(4, bob.wallet_state.wallet_db.monitored_utxos().len().await,);
        assert_eq!(
            4,
            bob.wallet_state
                .read_utxo_ms_recovery_data()
                .await
                .unwrap()
                .len(),
        );
        assert!(wallet_state_has_all_valid_mps(&bob.wallet_state, &block_1a).await);
        assert!(mutxos_1a
            .iter()
            .all(|mutxo| mutxo.confirmed_in_block.unwrap().0 == block_1a.hash()));

        // Add a new block to state as tip, which *only* differs in its PoW
        // solution. `bob` did *not* find the PoW-solution for this block.
        let guesser_preimage_1b: Digest = rng.random();
        let (block_1b, expected_utxos_block_1b) =
            make_mock_block_guesser_preimage_and_guesser_fraction(
                &genesis_block,
                None,
                bob_key,
                mock_block_seed,
                guesser_fraction,
                guesser_preimage_1b,
            )
            .await;

        // Composer UTXOs must agree
        for (expu_1a, expu_1b) in expected_utxos_block_1a
            .iter()
            .zip_eq(expected_utxos_block_1b.iter())
        {
            assert_eq!(expu_1a.addition_record, expu_1b.addition_record);
            assert_eq!(expu_1a.utxo, expu_1b.utxo);
            assert_eq!(expu_1a.sender_randomness, expu_1b.sender_randomness);
            assert_eq!(expu_1a.receiver_preimage, expu_1b.receiver_preimage);
        }

        bob.wallet_state
            .add_expected_utxos(expected_utxos_block_1a.clone())
            .await;
        bob.set_new_tip(block_1b.clone()).await.unwrap();
        let final_mutxos = bob.wallet_state.wallet_db.monitored_utxos().get_all().await;
        assert_eq!(4, final_mutxos.len());
        assert_eq!(
            4,
            bob.wallet_state
                .read_utxo_ms_recovery_data()
                .await
                .unwrap()
                .len(),
        );

        // verify that the two composer MUTXOs are still valid. Notice that the
        // guesser-fee UTXOs will not be valid, so we cannot require that all
        // four MUTXOs have valid MSMPs, since the two guesser-UTXOs were
        // orphaned with block 1b.
        for mutxo in final_mutxos.iter().take((0..=1).count()) {
            let item = Tip5::hash(&mutxo.utxo);
            let (mutxo_sync_block_digest, msmp) =
                mutxo.get_latest_membership_proof_entry().unwrap();
            assert!(block_1b.mutator_set_accumulator_after().verify(item, &msmp));
            assert_eq!(block_1b.hash(), mutxo_sync_block_digest);
            assert_eq!(block_1b.hash(), mutxo.confirmed_in_block.unwrap().0);
        }
    }

    #[tokio::test]
    #[traced_test]
    async fn never_store_same_utxo_twice_same_block() {
        let mut rng = rand::rng();
        let network = Network::Main;
        let bob_wallet_secret = WalletSecret::new_random();
        let bob_key = bob_wallet_secret.nth_generation_spending_key_for_tests(0);
        let mut bob_global_lock =
            mock_genesis_global_state(network, 0, bob_wallet_secret, cli_args::Args::default())
                .await;
        let mut bob = bob_global_lock.lock_guard_mut().await;

        let genesis_block = Block::genesis(network);
        let (block1, composer_utxos) =
            make_mock_block(&genesis_block, None, bob_key, rng.random()).await;

        bob.wallet_state.add_expected_utxos(composer_utxos).await;
        assert!(
            bob.wallet_state
                .wallet_db
                .monitored_utxos()
                .is_empty()
                .await,
            "Monitored UTXO list must be empty at init"
        );
        bob.wallet_state
            .update_wallet_state_with_new_block(
                &genesis_block.mutator_set_accumulator_after(),
                &block1,
            )
            .await
            .unwrap();
        assert_eq!(2, bob.wallet_state.wallet_db.monitored_utxos().len().await,);
        assert_eq!(
            2,
            bob.wallet_state
                .read_utxo_ms_recovery_data()
                .await
                .unwrap()
                .len(),
        );
        let original_mutxo = bob.wallet_state.wallet_db.monitored_utxos().get(0).await;
        let original_recovery_entry =
            &bob.wallet_state.read_utxo_ms_recovery_data().await.unwrap()[0];

        // Apply block again and verify that nothing new is stored.
        bob.wallet_state
            .update_wallet_state_with_new_block(
                &genesis_block.mutator_set_accumulator_after(),
                &block1,
            )
            .await
            .unwrap();
        assert_eq!(2, bob.wallet_state.wallet_db.monitored_utxos().len().await,);
        assert_eq!(
            2,
            bob.wallet_state
                .read_utxo_ms_recovery_data()
                .await
                .unwrap()
                .len(),
        );

        let new_mutxo = bob.wallet_state.wallet_db.monitored_utxos().get(0).await;
        let new_recovery_entry = &bob.wallet_state.read_utxo_ms_recovery_data().await.unwrap()[0];

        assert_eq!(
            original_mutxo, new_mutxo,
            "Adding same block twice may not mutate MUTXOs"
        );
        assert_eq!(original_recovery_entry, new_recovery_entry);

        assert!(wallet_state_has_all_valid_mps(&bob.wallet_state, &block1).await);
    }

    #[tokio::test]
    #[traced_test]
    async fn wallet_state_prune_abandoned_mutxos() {
        // Get genesis block. Verify wallet is empty
        // Add two blocks to state containing no UTXOs for own wallet
        // Add a UTXO (composer) in block 3a (height = 3)
        // Verify that this UTXO was recognized
        // Fork chain with new block of height 3: 3b
        // Run the pruner
        // Verify that MUTXO is *not* marked as abandoned
        // Add 8 blocks
        // Verify that MUTXO is *not* marked as abandoned
        // Add 1 block
        // Verify that MUTXO is *not* marked as abandoned
        // Prune
        // Verify that MUTXO *is* marked as abandoned

        let mut rng = rand::rng();
        let network = Network::RegTest;
        let bob_wallet_secret = WalletSecret::new_random();
        let bob_spending_key = bob_wallet_secret.nth_generation_spending_key_for_tests(0);
        let mut bob_global_lock =
            mock_genesis_global_state(network, 0, bob_wallet_secret, cli_args::Args::default())
                .await;
        let mut bob = bob_global_lock.lock_guard_mut().await;
        let genesis_block = Block::genesis(network);
        let monitored_utxos_count_init = bob.wallet_state.wallet_db.monitored_utxos().len().await;
        assert!(
            monitored_utxos_count_init.is_zero(),
            "Monitored UTXO list must be empty at init"
        );
        assert!(
            bob.get_latest_balance_height().await.is_none(),
            "Latest balance height must be None at init"
        );

        // Add two blocks with no UTXOs for us
        let alice_key = WalletSecret::new_random().nth_generation_spending_key_for_tests(0);
        let mut latest_block = genesis_block;
        for _ in 1..=2 {
            let (new_block, _new_block_coinbase_utxo) =
                make_mock_block(&latest_block, None, alice_key, rng.random()).await;
            bob.wallet_state
                .update_wallet_state_with_new_block(
                    &latest_block.mutator_set_accumulator_after(),
                    &new_block,
                )
                .await
                .unwrap();
            bob.chain
                .archival_state_mut()
                .write_block_as_tip(&new_block)
                .await
                .unwrap();
            bob.chain.light_state_mut().set_block(new_block.clone());

            latest_block = new_block;
        }
        assert!(
            bob.wallet_state
                .wallet_db
                .monitored_utxos()
                .len()
                .await
                .is_zero(),
            "Monitored UTXO list must be empty at height 2"
        );
        assert!(
            bob.get_latest_balance_height().await.is_none(),
            "Latest balance height must be None at height 2"
        );

        // Add block 3a with a coinbase UTXO for us
        let (block_3a, expected_3a) =
            make_mock_block(&latest_block.clone(), None, bob_spending_key, rng.random()).await;
        bob.set_new_self_mined_tip(block_3a, expected_3a)
            .await
            .unwrap();

        assert_eq!(
            2,
            bob.wallet_state.wallet_db.monitored_utxos().len().await,
            "Monitored UTXO list must have length 2 at block 3a"
        );
        assert!(
            bob.wallet_state
                .wallet_db
                .monitored_utxos()
                .get_all()
                .await
                .iter()
                .all(|x| x.abandoned_at.is_none()),
            "MUTXOs may not be marked as abandoned at block 3a"
        );
        assert_eq!(
            Some(3.into()),
            bob.get_latest_balance_height().await,
            "Latest balance height 3 at block 3a"
        );

        // Fork the blockchain with 3b, with no coinbase for us
        let (block_3b, _block_3b_exp) =
            make_mock_block(&latest_block, None, alice_key, rng.random()).await;
        bob.set_new_tip(block_3b.clone()).await.unwrap();

        assert!(
            bob.wallet_state
                .wallet_db
                .monitored_utxos()
                .get_all()
                .await
                .iter()
                .all(|x| x.abandoned_at.is_none()),
            "MUTXOs may not be marked as abandoned at block 3b, as the abandoned chain is not yet old enough and has not been pruned"
        );
        assert!(
            bob.get_latest_balance_height().await.is_none(),
            "Latest balance height must be None at block 3b"
        );
        let prune_count_3b = bob.prune_abandoned_monitored_utxos(10).await.unwrap();
        assert!(prune_count_3b.is_zero());

        // Mine eight blocks on top of 3b, update states
        latest_block = block_3b;
        for _ in 4..=11 {
            let (new_block, _new_block_exp) =
                make_mock_block(&latest_block, None, alice_key, rng.random()).await;
            bob.set_new_tip(new_block.clone()).await.unwrap();

            latest_block = new_block;
        }

        let prune_count_11 = bob.prune_abandoned_monitored_utxos(10).await.unwrap();
        assert!(prune_count_11.is_zero());
        assert!(
            bob.wallet_state
                .wallet_db
                .monitored_utxos()
                .get_all()
                .await
                .iter()
                .all(|x| x.abandoned_at.is_none()),
            "MUTXOs must not be abandoned at height 11"
        );
        assert!(
            bob.get_latest_balance_height().await.is_none(),
            "Latest balance height must be None at height 11"
        );

        // Mine *one* more block. Verify that MUTXO is pruned
        let (block_12, _) = make_mock_block(&latest_block, None, alice_key, rng.random()).await;
        bob.set_new_tip(block_12.clone()).await.unwrap();

        assert!(
            bob.wallet_state
                .wallet_db
                .monitored_utxos()
                .get_all()
                .await
                .iter()
                .all(|x| x.abandoned_at.is_none()),
            "MUTXO must *not* be marked as abandoned at height 12, prior to pruning"
        );
        let prune_count_12 = bob.prune_abandoned_monitored_utxos(10).await.unwrap();
        assert_eq!(2, prune_count_12);

        for i in 0..=1 {
            assert_eq!(
                (
                    block_12.hash(),
                    block_12.kernel.header.timestamp,
                    12u64.into()
                ),
                bob.wallet_state
                    .wallet_db
                    .monitored_utxos()
                    .get(i)
                    .await
                    .abandoned_at
                    .unwrap(),
                "MUTXO must be marked as abandoned at height 12, after pruning"
            );
        }
        assert!(
            bob.get_latest_balance_height().await.is_none(),
            "Latest balance height must be None at height 12"
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn mock_wallet_state_is_synchronized_to_genesis_block() {
        let network = Network::RegTest;
        let wallet = WalletSecret::devnet_wallet();
        let genesis_block = Block::genesis(network);

        let wallet_state = mock_genesis_wallet_state(wallet, network).await;

        // are we synchronized to the genesis block?
        assert_eq!(
            wallet_state.wallet_db.get_sync_label().await,
            genesis_block.hash()
        );

        // Do we have valid membership proofs for all UTXOs received in the genesis block?
        let monitored_utxos = wallet_state.wallet_db.monitored_utxos();
        let num_monitored_utxos = monitored_utxos.len().await;
        assert!(num_monitored_utxos > 0);
        for i in 0..num_monitored_utxos {
            let monitored_utxo: MonitoredUtxo = monitored_utxos.get(i).await;
            if let Some((digest, _duration, _height)) = monitored_utxo.confirmed_in_block {
                assert_eq!(digest, genesis_block.hash());
            } else {
                panic!();
            }
            let utxo = monitored_utxo.utxo;
            let ms_membership_proof = monitored_utxo
                .blockhash_to_membership_proof
                .iter()
                .find(|(bh, _mp)| *bh == genesis_block.hash())
                .unwrap()
                .1
                .clone();
            assert!(genesis_block
                .mutator_set_accumulator_after()
                .verify(Hash::hash(&utxo), &ms_membership_proof));
        }
    }

    mod guesser_fee_utxos {
        use futures::channel::oneshot;
        use guesser_fee_utxos::composer_parameters::ComposerParameters;

        use super::*;
        use crate::mine_loop::composer_parameters;
        use crate::mine_loop::guess_nonce;
        use crate::mine_loop::GuessingConfiguration;
        use crate::models::blockchain::transaction::TransactionProof;
        use crate::models::channel::NewBlockFound;
        use crate::tests::shared::fake_create_block_transaction_for_tests;
        use crate::tests::shared::fake_valid_block_proposal_from_tx;
        use crate::tests::shared::fake_valid_block_proposal_successor_for_test;

        #[traced_test]
        #[tokio::test]
        async fn registers_guesser_fee_utxos_correctly() {
            let network = Network::Main;
            let genesis_block = Block::genesis(network);
            let mut bob = mock_genesis_global_state(
                network,
                3,
                WalletSecret::new_random(),
                cli_args::Args::default_with_network(network),
            )
            .await;
            let block1_timestamp = network.launch_date() + Timestamp::minutes(2);

            // Create a random block proposal.
            let mut rng = rand::rng();
            let block1_proposal = fake_valid_block_proposal_successor_for_test(
                &genesis_block,
                block1_timestamp,
                rng.random(),
            )
            .await;

            // Create the correct guesser key
            let guesser_key = bob
                .lock_guard()
                .await
                .wallet_state
                .wallet_secret
                .guesser_spending_key(genesis_block.hash());

            // Mine it till it has a valid PoW digest
            // Add this block to the wallet through the same pipeline as the
            // mine_loop.
            let claimable_composer_utxos = vec![];
            let sleepy_guessing = false;
            let (guesser_tx, guesser_rx) = oneshot::channel::<NewBlockFound>();
            guess_nonce(
                block1_proposal,
                *genesis_block.header(),
                guesser_tx,
                claimable_composer_utxos,
                guesser_key,
                GuessingConfiguration {
                    sleepy_guessing,
                    num_guesser_threads: Some(2),
                },
                None,
            )
            .await;

            let new_block_found = guesser_rx.await.unwrap();
            let guesser_utxos = new_block_found.guesser_fee_utxo_infos;
            let block1 = new_block_found.block;

            {
                let bgs = bob.global_state_lock.lock_guard().await;
                let wallet_status = bgs
                    .wallet_state
                    .get_wallet_status(block1.hash(), &block1.mutator_set_accumulator_after())
                    .await;

                assert!(
                    !bgs.wallet_state
                        .confirmed_available_balance(&wallet_status, block1_timestamp)
                        .is_positive(),
                    "Must show zero-balance before adding block to state"
                );
            }
            bob.set_new_self_mined_tip(block1.as_ref().clone(), guesser_utxos)
                .await
                .unwrap();

            {
                let bgs = bob.global_state_lock.lock_guard().await;
                let wallet_status = bgs
                    .wallet_state
                    .get_wallet_status(block1.hash(), &block1.mutator_set_accumulator_after())
                    .await;

                assert!(
                    bgs.wallet_state
                        .confirmed_available_balance(&wallet_status, block1_timestamp)
                        .is_positive(),
                    "Must show positive balance after successful PoW-guess"
                );
            }

            // Verify expected qualities of wallet, that:
            // 1. guesser-preimage was added to list(s)
            // 2. expected UTXO contains guesser-fee UTXOs
            // 3. monitored UTXOs-list contains guesser-fee UTXOs.

            // 1.
            let cached_guesser_preimages = bob
                .global_state_lock
                .lock_guard()
                .await
                .wallet_state
                .known_raw_hash_lock_keys
                .clone();
            assert_eq!(
                1,
                cached_guesser_preimages.len(),
                "Cache must know exactly 1 guesser-preimage after adding block to wallet state"
            );
            let preimage =
                if let SpendingKey::RawHashLock(raw_hash_lock) = cached_guesser_preimages[0] {
                    raw_hash_lock.preimage()
                } else {
                    panic!("Stored key must be raw hash lock");
                };
            assert_eq!(
                block1.header().guesser_digest,
                preimage.hash(),
                "Cached guesser preimage must hash to guesser digest in block"
            );

            let guesser_preimages_from_db = bob
                .global_state_lock
                .lock_guard()
                .await
                .wallet_state
                .wallet_db
                .guesser_preimages()
                .get_all()
                .await;
            assert_eq!(
                1,
                guesser_preimages_from_db.len(),
                "DB must know exactly 1 guesser-preimage after adding block to wallet state"
            );
            assert_eq!(
                block1.header().guesser_digest,
                guesser_preimages_from_db[0].hash(),
                "Guesser preimage from DB must hash to guesser digest in block"
            );

            // 2.
            let eus = bob
                .global_state_lock
                .lock_guard()
                .await
                .wallet_state
                .wallet_db
                .expected_utxos()
                .get_all()
                .await;
            assert_eq!(2, eus.len(), "Must expect 2 guesser-fee UTXOs");
            assert_eq!(
                2,
                eus.iter().map(|x| x.addition_record).unique().count(),
                "Addition records from expected UTXOs must be unique"
            );
            let ars_from_block = block1.guesser_fee_addition_records();
            for eu in eus {
                assert!(
                    ars_from_block.contains(&eu.addition_record),
                    "expected UTXO must match guesser-fee addition record"
                );
                assert!(
                    eu.mined_in_block.is_some(),
                    "expected UTXO must be marked as mined"
                )
            }

            // 3.
            let mutxos = bob
                .global_state_lock
                .lock_guard()
                .await
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .get_all()
                .await;
            assert_eq!(
                2,
                mutxos.len(),
                "Must have registered two UTXOs as guesser-reward"
            );
            assert_eq!(
                2,
                mutxos.iter().map(|x| x.addition_record()).unique().count(),
                "Addition records from MUTXOs must be unique"
            );
            assert_eq!(
                1,
                mutxos
                    .iter()
                    .filter(|x| x.utxo.release_date().is_some())
                    .count()
            );
            assert_eq!(
                1,
                mutxos
                    .iter()
                    .filter(|x| x.utxo.release_date().is_none())
                    .count()
            );
            for mutxo in mutxos {
                assert!(
                    ars_from_block.contains(&mutxo.addition_record()),
                    "MUTXO must match guesser-fee addition record"
                );
            }

            // Can make tx with PoW-loot.
            let block2_timestamp = block1.header().timestamp + Timestamp::minutes(2);
            let fee = NativeCurrencyAmount::coins(1);
            let a_key = GenerationSpendingKey::derive_from_seed(rng.random());
            let (mut tx_spending_guesser_fee, _, _) = bob
                .global_state_lock
                .lock_guard()
                .await
                .create_transaction_with_prover_capability(
                    vec![].into(),
                    a_key.into(),
                    UtxoNotificationMedium::OnChain,
                    fee,
                    block2_timestamp,
                    TxProvingCapability::PrimitiveWitness,
                    &TritonVmJobQueue::dummy(),
                )
                .await
                .unwrap();
            assert!(
                tx_spending_guesser_fee.is_valid().await,
                "Tx spending guesser-fee UTXO must be valid."
            );

            // Give tx a fake single proof to allow inclusion in block, through
            // below test function.
            tx_spending_guesser_fee.proof = TransactionProof::invalid();

            let composer_parameters =
                ComposerParameters::new(a_key.to_address().into(), rng.random(), 0.5f64);
            let (block2_tx, _) = fake_create_block_transaction_for_tests(
                &block1,
                composer_parameters,
                block2_timestamp,
                rng.random(),
                vec![tx_spending_guesser_fee],
            )
            .await
            .unwrap();
            let block2 = fake_valid_block_proposal_from_tx(&block1, block2_tx).await;
            assert!(block2.is_valid(&block1, block2_timestamp).await);

            bob.set_new_self_mined_tip(block2.clone(), vec![])
                .await
                .unwrap();
            {
                let bgs = bob.global_state_lock.lock_guard().await;
                let wallet_status = bgs
                    .wallet_state
                    .get_wallet_status(block2.hash(), &block2.mutator_set_accumulator_after())
                    .await;

                assert!(
                    !bgs.wallet_state
                        .confirmed_available_balance(&wallet_status, block2_timestamp)
                        .is_positive(),
                    "Must show zero liquid balance after spending liquid guesser UTXO"
                );
            }
        }
    }

    mod wallet_balance {
        use generation_address::GenerationReceivingAddress;
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        use super::*;
        use crate::config_models::cli_args;
        use crate::job_queue::triton_vm::TritonVmJobQueue;
        use crate::models::blockchain::block::block_height::BlockHeight;
        use crate::models::blockchain::transaction::Transaction;
        use crate::models::state::tx_proving_capability::TxProvingCapability;
        use crate::models::state::wallet::address::ReceivingAddress;
        use crate::models::state::wallet::utxo_notification::UtxoNotificationMedium;
        use crate::models::state::TransactionOrigin;
        use crate::tests::shared::mine_block_to_wallet_invalid_block_proof;

        /// basic test for confirmed and unconfirmed balance.
        ///
        /// This test:
        ///  1. mines a block to self worth `coinbase amt`
        ///  2. sends 5 to a 3rd party, and rest back to self.
        ///  3. verifies that confirmed balance is `coinbase amt`
        ///  4. verifies that unconfirmed balance is `coinbase amt - 5`
        ///  5. empties the mempool (removing our unconfirmed tx)
        ///  6. verifies that unconfirmed balance is `coinbase amt`
        #[traced_test]
        #[tokio::test]
        async fn confirmed_and_unconfirmed_balance() -> Result<()> {
            let network = Network::Main;
            let mut rng = StdRng::seed_from_u64(664505904);
            let mut global_state_lock = mock_genesis_global_state(
                network,
                0,
                WalletSecret::new_pseudorandom(rng.random()),
                cli_args::Args::default(),
            )
            .await;
            let change_key = global_state_lock
                .lock_guard_mut()
                .await
                .wallet_state
                .next_unused_spending_key(KeyType::Generation)
                .await
                .unwrap();

            let coinbase_amt = Block::block_subsidy(BlockHeight::genesis().next());
            let mut half_coinbase_amt = coinbase_amt;
            half_coinbase_amt.div_two();
            let send_amt = NativeCurrencyAmount::coins(5);

            let timestamp = Block::genesis(network).header().timestamp + Timestamp::hours(1);

            // mine a block to our wallet.  we should have 100 coins after.
            let tip_digest =
                mine_block_to_wallet_invalid_block_proof(&mut global_state_lock, timestamp)
                    .await?
                    .hash();

            let tx = {
                // verify that confirmed and unconfirmed balances.
                let gs = global_state_lock.lock_guard().await;
                let msa = gs.chain.light_state().mutator_set_accumulator_after();
                let wallet_status = gs.wallet_state.get_wallet_status(tip_digest, &msa).await;

                assert_eq!(
                    gs.wallet_state
                        .confirmed_available_balance(&wallet_status, timestamp),
                    half_coinbase_amt
                );
                assert_eq!(
                    gs.wallet_state
                        .unconfirmed_available_balance(&wallet_status, timestamp),
                    half_coinbase_amt
                );

                // generate an output that our wallet cannot claim.
                let outputs = vec![(
                    ReceivingAddress::from(GenerationReceivingAddress::derive_from_seed(
                        rng.random(),
                    )),
                    send_amt,
                )];

                let tx_outputs = gs.generate_tx_outputs(
                    outputs,
                    UtxoNotificationMedium::OnChain,
                    UtxoNotificationMedium::OnChain,
                );

                let (tx, _, _change_output) = gs
                    .create_transaction_with_prover_capability(
                        tx_outputs,
                        change_key,
                        UtxoNotificationMedium::OnChain,
                        NativeCurrencyAmount::zero(),
                        timestamp,
                        TxProvingCapability::PrimitiveWitness,
                        &TritonVmJobQueue::dummy(),
                    )
                    .await?;
                tx
            };

            // add the tx to the mempool.
            // note that the wallet should be notified of these changes.
            global_state_lock
                .lock_guard_mut()
                .await
                .mempool_insert(tx, TransactionOrigin::Own)
                .await;

            {
                let gs = global_state_lock.lock_guard().await;
                let msa = gs.chain.light_state().mutator_set_accumulator_after();
                let wallet_status = gs.wallet_state.get_wallet_status(tip_digest, &msa).await;

                assert_eq!(
                    gs.wallet_state
                        .confirmed_available_balance(&wallet_status, timestamp),
                    half_coinbase_amt
                );
                assert_eq!(
                    gs.wallet_state
                        .unconfirmed_available_balance(&wallet_status, timestamp),
                    half_coinbase_amt.checked_sub(&send_amt).unwrap()
                );
            }

            // clear the mempool, which drops our unconfirmed tx.
            global_state_lock
                .lock_guard_mut()
                .await
                .mempool_clear()
                .await;

            {
                // verify that wallet's unconfirmed balance is `coinbase amt` again.
                let msa = global_state_lock
                    .lock(|gs| gs.chain.light_state().mutator_set_accumulator_after())
                    .await;

                let gs = global_state_lock.lock_guard().await;
                let wallet_status = gs.wallet_state.get_wallet_status(tip_digest, &msa).await;

                // verify that wallet's unconfirmed balance is `coinbase amt` again.
                assert_eq!(
                    gs.wallet_state
                        .unconfirmed_available_balance(&wallet_status, timestamp),
                    half_coinbase_amt
                );
            }

            Ok(())
        }

        #[traced_test]
        #[tokio::test]
        async fn do_not_attempt_to_spend_utxos_already_spent_in_mempool_txs() {
            async fn outgoing_transaction(
                alice_global_lock: &GlobalStateLock,
                amount: NativeCurrencyAmount,
                fee: NativeCurrencyAmount,
                timestamp: Timestamp,
                change_key: SpendingKey,
            ) -> Result<Transaction> {
                let mut rng = rand::rng();
                let an_address = GenerationReceivingAddress::derive_from_seed(rng.random());
                let tx_output = TxOutput::onchain_native_currency(
                    amount,
                    rng.random(),
                    an_address.into(),
                    false,
                );
                alice_global_lock
                    .global_state_lock
                    .lock_guard()
                    .await
                    .create_transaction_with_prover_capability(
                        vec![tx_output].into(),
                        change_key,
                        UtxoNotificationMedium::OffChain,
                        fee,
                        timestamp,
                        TxProvingCapability::PrimitiveWitness,
                        &TritonVmJobQueue::dummy(),
                    )
                    .await
                    .map(|x| x.0)
            }

            let network = Network::Main;
            let mut rng = rand::rng();
            let alice_wallet = WalletSecret::new_pseudorandom(rng.random());
            let mut alice = mock_genesis_global_state(
                network,
                0,
                alice_wallet.clone(),
                cli_args::Args::default(),
            )
            .await;

            let genesis = Block::genesis(network);
            let guesser_preimage = rng.random();
            let change_key = alice_wallet.nth_generation_spending_key(0).into();
            let guesser_fraction = 0.5f64;

            // Alice mines a block
            let (block, composer_utxos) = make_mock_block_guesser_preimage_and_guesser_fraction(
                &genesis,
                None,
                alice_wallet.nth_generation_spending_key(0),
                rng.random(),
                guesser_fraction,
                guesser_preimage,
            )
            .await;

            // Alice gets all mining rewards
            let guesser_utxos = block.guesser_fee_expected_utxos(guesser_preimage);
            let all_mine_rewards = [composer_utxos, guesser_utxos].concat();
            alice
                .lock_guard_mut()
                .await
                .set_new_self_mined_tip(block.clone(), all_mine_rewards)
                .await
                .unwrap();

            // Alice now has four UTXOs: two composer, two guesser; of each
            // category one is immediately liquid.
            // So generate two transactions and verify that the inputs are not
            // in conflict.

            // Check assumption made below: Alice has 2 non-timelocked UTXOs.
            let now = block.header().timestamp + Timestamp::seconds(1);
            let wallet_status_1 = alice
                .lock_guard_mut()
                .await
                .wallet_state
                .get_wallet_status(block.hash(), &block.mutator_set_accumulator_after())
                .await;
            assert_eq!(
                2,
                wallet_status_1
                    .synced_unspent
                    .iter()
                    .filter(|(elem, _)| elem.utxo.can_spend_at(now))
                    .count()
            );

            // generate one transaction
            let tx1 = outgoing_transaction(
                &alice,
                NativeCurrencyAmount::coins(1),
                NativeCurrencyAmount::coins(1),
                now,
                change_key,
            )
            .await
            .unwrap();

            // insert into mempool
            alice
                .lock_guard_mut()
                .await
                .mempool_insert(tx1, TransactionOrigin::Own)
                .await;

            // generate a second transaction
            let tx2 = outgoing_transaction(
                &alice,
                NativeCurrencyAmount::coins(1),
                NativeCurrencyAmount::coins(1),
                now,
                change_key,
            )
            .await
            .unwrap();

            // insert that one into the mempool too
            alice
                .lock_guard_mut()
                .await
                .mempool_insert(tx2, TransactionOrigin::Own)
                .await;

            // verify that the mempool contains two transactions
            // ==> did not kick anything out
            assert_eq!(2, alice.lock_guard().await.mempool.len());

            // Verify that one more transaction *cannot* be made, as all the
            // monitored UTXOs now have a transaction that spends them in the
            // mempool.
            assert!(
                outgoing_transaction(
                    &alice,
                    NativeCurrencyAmount::coins(1),
                    NativeCurrencyAmount::coins(1),
                    now,
                    change_key,
                )
                .await
                .is_err(),
                "Must fail to generate a 3rd tx when wallet only has 2 spendable UTXOs"
            );
        }
    }

    mod key_derivation {
        use super::*;

        /// tests that all known keys are unique, for all key types.
        #[traced_test]
        #[tokio::test]
        #[allow(clippy::needless_return)]
        async fn known_keys_are_unique() {
            for key_type in KeyType::all_types_for_receiving() {
                worker::known_keys_are_unique(key_type).await
            }
        }

        /// tests that spending key counter persists across restart for all key types.
        #[traced_test]
        #[tokio::test]
        #[allow(clippy::needless_return)]
        async fn derivation_counter_persists_across_restart() -> Result<()> {
            for key_type in KeyType::all_types_for_receiving() {
                worker::derivation_counter_persists_across_restart(key_type).await?
            }
            Ok(())
        }

        mod worker {
            use super::*;
            use crate::database::storage::storage_schema::traits::StorageWriter;
            use crate::tests::shared::mock_genesis_wallet_state_with_data_dir;
            use crate::tests::shared::unit_test_data_directory;

            /// tests that all known keys are unique for a given key-type
            ///
            /// 1. Generate a mock WalletState
            /// 2. Request 20 spending keys
            /// 3. Verify there are 20 known keys
            /// 4. Verify all keys are unique.
            pub(super) async fn known_keys_are_unique(key_type: KeyType) {
                info!("key_type: {}", key_type);

                // 1. Generate a mock WalletState
                let mut wallet =
                    mock_genesis_wallet_state(WalletSecret::new_random(), Network::RegTest).await;

                let num_known_keys = wallet.get_known_spending_keys(key_type).count();
                let num_to_derive = 20;

                // 2. Request 20 spending keys
                for _ in 0..num_to_derive {
                    let _ = wallet.next_unused_spending_key(key_type).await;
                }

                let expected_num_known_keys = num_known_keys + num_to_derive;
                let known_keys = wallet.get_known_spending_keys(key_type).collect_vec();

                // 3. Verify there are 20 known keys
                assert_eq!(expected_num_known_keys, known_keys.len());

                // 4. Verify all keys are unique.
                assert!(known_keys.iter().all_unique());
            }

            /// tests that spending key counter persists across restart given key type.
            ///
            /// 1. create new wallet and generate 20 keys
            /// 2. record wallet counter and known-keys
            /// 3. persist wallet
            /// 4. forget wallet
            /// 5. instantiate 2nd wallet instance with same data_dir and secret as the first
            /// 6. verify counter persisted between wallet instantiations
            /// 7. verify known-keys persisted between wallet instantiations
            /// 8. verify all keys are unique
            pub(super) async fn derivation_counter_persists_across_restart(
                key_type: KeyType,
            ) -> Result<()> {
                info!("key_type: {}", key_type);

                let network = Network::RegTest;
                let wallet_secret = WalletSecret::new_random();
                let data_dir = unit_test_data_directory(network)?;

                // 1. create new wallet and generate 20 keys
                // 2. record wallet counter and known-keys
                // 3. persist wallet.
                // 4. forget wallet (dropped)
                let (orig_counter, orig_known_keys) = {
                    let mut wallet = mock_genesis_wallet_state_with_data_dir(
                        wallet_secret.clone(),
                        Network::RegTest,
                        &data_dir,
                    )
                    .await;

                    for _ in 0..20 {
                        let _ = wallet.next_unused_spending_key(key_type).await;
                    }

                    wallet.wallet_db.persist().await;

                    (
                        wallet.spending_key_counter(key_type).await,
                        wallet.get_known_spending_keys(key_type).collect_vec(),
                    )
                };

                // 5. instantiate 2nd wallet instance with same data_dir and secret as the first
                let wallet = mock_genesis_wallet_state_with_data_dir(
                    wallet_secret,
                    Network::RegTest,
                    &data_dir,
                )
                .await;

                let persisted_counter = wallet.spending_key_counter(key_type).await;
                let persisted_known_keys = wallet.get_known_spending_keys(key_type).collect_vec();

                // 6. verify counter persisted between wallet instantiations
                assert_eq!(orig_counter, persisted_counter);
                assert_eq!(orig_known_keys.len(), persisted_known_keys.len());

                // 7. verify known-keys persisted between wallet instantiations
                assert_eq!(orig_known_keys, persisted_known_keys);

                // 8. verify all keys are unique.
                assert!(persisted_known_keys.iter().all_unique());

                Ok(())
            }
        }
    }

    mod expected_utxos {
        use super::*;
        use crate::models::blockchain::transaction::lock_script::LockScript;
        use crate::tests::shared::make_mock_transaction;
        use crate::util_types::mutator_set::commit;

        #[traced_test]
        #[tokio::test]
        async fn insert_and_scan() {
            let mut wallet =
                mock_genesis_wallet_state(WalletSecret::new_random(), Network::RegTest).await;

            assert!(wallet.wallet_db.expected_utxos().is_empty().await);
            assert!(wallet.wallet_db.expected_utxos().len().await.is_zero());

            let mock_utxo = Utxo::new_native_currency(
                LockScript::anyone_can_spend(),
                NativeCurrencyAmount::coins(10),
            );

            let sender_randomness: Digest = rand::random();
            let receiver_preimage: Digest = rand::random();
            let expected_addition_record = commit(
                Hash::hash(&mock_utxo),
                sender_randomness,
                receiver_preimage.hash(),
            );
            wallet
                .add_expected_utxo(ExpectedUtxo::new(
                    mock_utxo.clone(),
                    sender_randomness,
                    receiver_preimage,
                    UtxoNotifier::Myself,
                ))
                .await;
            assert!(!wallet.wallet_db.expected_utxos().is_empty().await);
            assert_eq!(1, wallet.wallet_db.expected_utxos().len().await);

            let mock_tx_containing_expected_utxo =
                make_mock_transaction(vec![], vec![expected_addition_record]);

            let ret_with_tx_containing_utxo = wallet
                .scan_for_expected_utxos(&mock_tx_containing_expected_utxo.kernel.outputs)
                .await
                .collect_vec();
            assert_eq!(1, ret_with_tx_containing_utxo.len());

            // Call scan but with another input. Verify that it returns the empty list
            let another_addition_record = commit(
                Hash::hash(&mock_utxo),
                rand::random(),
                receiver_preimage.hash(),
            );
            let tx_without_utxo = make_mock_transaction(vec![], vec![another_addition_record]);
            let ret_with_tx_without_utxo = wallet
                .scan_for_expected_utxos(&tx_without_utxo.kernel.outputs)
                .await
                .collect_vec();
            assert!(ret_with_tx_without_utxo.is_empty());
        }

        #[traced_test]
        #[tokio::test]
        async fn prune_stale() {
            let mut wallet =
                mock_genesis_wallet_state(WalletSecret::new_random(), Network::RegTest).await;

            let mock_utxo = Utxo::new_native_currency(
                LockScript::anyone_can_spend(),
                NativeCurrencyAmount::coins(14),
            );

            // Add a UTXO notification
            let mut addition_records = vec![];
            let ar = wallet
                .add_expected_utxo(ExpectedUtxo::new(
                    mock_utxo.clone(),
                    rand::random(),
                    rand::random(),
                    UtxoNotifier::Myself,
                ))
                .await;
            addition_records.push(ar);

            // Add three more
            for _ in 0..3 {
                let ar_new = wallet
                    .add_expected_utxo(ExpectedUtxo::new(
                        mock_utxo.clone(),
                        rand::random(),
                        rand::random(),
                        UtxoNotifier::Myself,
                    ))
                    .await;
                addition_records.push(ar_new);
            }

            // Test with a UTXO that was received
            // Manipulate the time this entry was inserted
            let two_weeks_as_sec = 60 * 60 * 24 * 7 * 2;
            let eu_idx = 0;
            let mut eu = wallet.wallet_db.expected_utxos().get(eu_idx).await;

            // modify mined_in_block field.
            eu.mined_in_block = Some((
                Digest::default(),
                Timestamp::now() - Timestamp::seconds(two_weeks_as_sec),
            ));

            // update db
            wallet.wallet_db.expected_utxos_mut().set(eu_idx, eu).await;

            assert_eq!(4, wallet.wallet_db.expected_utxos().len().await);
            wallet.prune_stale_expected_utxos().await;
            assert_eq!(3, wallet.wallet_db.expected_utxos().len().await);
        }

        /// demonstrates/tests that if wallet-db is not persisted after an
        /// ExpectedUtxo is added, then the ExpectedUtxo will not exist after
        /// wallet is dropped from RAM and re-created from disk.
        ///
        /// This is a regression test for issue #172.
        ///
        /// https://github.com/Neptune-Crypto/neptune-core/issues/172
        #[traced_test]
        #[tokio::test]
        #[allow(clippy::needless_return)]
        async fn persisted_exists_after_wallet_restored() {
            worker::restore_wallet(true).await
        }

        /// demonstrates/tests that if wallet-db is not persisted after an
        /// ExpectedUtxo is added, then the ExpectedUtxo will not exist after
        /// wallet is dropped from RAM and re-created from disk.
        #[traced_test]
        #[tokio::test]
        #[allow(clippy::needless_return)]
        async fn unpersisted_gone_after_wallet_restored() {
            worker::restore_wallet(false).await
        }

        mod worker {
            use super::*;
            use crate::database::storage::storage_schema::traits::StorageWriter;
            use crate::tests::shared::mock_genesis_wallet_state_with_data_dir;
            use crate::tests::shared::unit_test_data_directory;

            /// implements a test with 2 variations via `persist` param.
            ///
            /// The basic test is to add an ExpectedUtxo to a wallet, drop and
            /// re-create the wallet, and then check if the ExpectedUtxo still
            /// exists.
            ///
            /// Variations:
            ///   persist = true:
            ///    the wallet db is persisted to disk after the ExpectedUtxo
            ///    is added. asserts that the restored wallet has 1 ExpectedUtxo.
            ///
            ///   persist = false:
            ///    the wallet db is NOT persisted to disk after the ExpectedUtxo
            ///    is added. asserts that the restored wallet has 0 ExpectedUtxo.
            pub(super) async fn restore_wallet(persist: bool) {
                let network = Network::RegTest;
                let wallet_secret = WalletSecret::new_random();
                let data_dir = unit_test_data_directory(network).unwrap();

                // create initial wallet in a new directory
                let mut wallet = mock_genesis_wallet_state_with_data_dir(
                    wallet_secret.clone(),
                    network,
                    &data_dir,
                )
                .await;

                let mock_utxo = Utxo::new_native_currency(
                    LockScript::anyone_can_spend(),
                    NativeCurrencyAmount::coins(14),
                );

                assert!(wallet.wallet_db.expected_utxos().is_empty().await);

                // Add an ExpectedUtxo to the wallet.
                wallet
                    .add_expected_utxo(ExpectedUtxo::new(
                        mock_utxo.clone(),
                        rand::random(),
                        rand::random(),
                        UtxoNotifier::Myself,
                    ))
                    .await;

                assert_eq!(1, wallet.wallet_db.expected_utxos().len().await);

                // persist wallet-db to disk, if testing that case.
                if persist {
                    wallet.wallet_db.persist().await;
                }

                // drop wallet state.  this simulates the node being stopped,
                // crashing, power outage, etc.
                drop(wallet);

                // re-create wallet state from same seed and same directory
                let restored_wallet =
                    mock_genesis_wallet_state_with_data_dir(wallet_secret, network, &data_dir)
                        .await;

                // if wallet state was persisted to DB then we should have
                // 1 (restored) ExpectedUtxo, else 0.
                let expect = if persist { 1 } else { 0 };
                assert_eq!(
                    expect,
                    restored_wallet.wallet_db.expected_utxos().len().await
                );
            }
        }
    }

    /// Test wallet state's handling of UTXOs abandoned due to reorganization.
    mod abandoned_mutxos {
        use super::*;
        use crate::models::blockchain::transaction::Transaction;
        use crate::models::state::wallet::address::generation_address::GenerationReceivingAddress;
        use crate::tests::shared::invalid_empty_block;

        #[traced_test]
        #[tokio::test]
        async fn mutxos_spent_in_orphaned_blocks_are_still_spendable() {
            /// Crate an outgoing transaction. Panics on insufficient balance.
            async fn outgoing_transaction(
                alice_global_lock: &GlobalStateLock,
                amount: NativeCurrencyAmount,
                fee: NativeCurrencyAmount,
                timestamp: Timestamp,
                change_key: SpendingKey,
            ) -> Transaction {
                let mut rng = rand::rng();
                let an_address = GenerationReceivingAddress::derive_from_seed(rng.random());
                let tx_output = TxOutput::onchain_native_currency(
                    amount,
                    rng.random(),
                    an_address.into(),
                    false,
                );
                let (spending_tx, _, _) = alice_global_lock
                    .global_state_lock
                    .lock_guard()
                    .await
                    .create_transaction_with_prover_capability(
                        vec![tx_output].into(),
                        change_key,
                        UtxoNotificationMedium::OffChain,
                        fee,
                        timestamp,
                        TxProvingCapability::PrimitiveWitness,
                        &TritonVmJobQueue::dummy(),
                    )
                    .await
                    .unwrap();

                spending_tx
            }

            // Verify that monitored UTXOs spent in blocks that do not belong
            // to the canonical chain are spendable and count towards positive
            // balance.
            // Cf. #328, https://github.com/Neptune-Crypto/neptune-core/issues/328

            // 1. create a genesis state for Alice, who is premine receiver
            // 2. create block_1a where Alice spends her premine
            // 3. Verify zero balance.
            // 4. Reorganize onto a new chain, blocks 1b and 2b.
            // 5. Verify no abandoned/unsynced MUTXOs
            // 6. Verify that Alice can, again, create a transaction spending premine.
            let network = Network::Main;
            let alice_wallet = WalletSecret::devnet_wallet();
            let mut alice_global_lock = mock_genesis_global_state(
                network,
                0,
                alice_wallet.clone(),
                cli_args::Args::default(),
            )
            .await;
            let genesis = Block::genesis(network);
            let init_balance = NativeCurrencyAmount::coins(20);
            assert_eq!(
                init_balance,
                alice_global_lock
                    .lock_guard_mut()
                    .await
                    .wallet_state
                    .get_wallet_status(genesis.hash(), &genesis.mutator_set_accumulator_after())
                    .await
                    .synced_unspent_total_amount(),
                "Alice assumed to be premine recipient"
            );

            // Create a transaction that spends all of Alice's balance.
            let timestamp = network.launch_date() + Timestamp::months(14);
            let change_key = alice_wallet.nth_symmetric_key(0).into();
            let spending_tx_1a = outgoing_transaction(
                &alice_global_lock,
                NativeCurrencyAmount::coins(19),
                NativeCurrencyAmount::coins(1),
                timestamp,
                change_key,
            )
            .await;

            let block_1a = invalid_block_with_transaction(&genesis, spending_tx_1a);
            let block_1b = invalid_empty_block(&genesis);
            let block_2b = invalid_empty_block(&block_1b);
            alice_global_lock
                .global_state_lock
                .lock_guard_mut()
                .await
                .set_new_tip(block_1a.clone())
                .await
                .unwrap();
            let wallet_status_1a = alice_global_lock
                .lock_guard_mut()
                .await
                .wallet_state
                .get_wallet_status(block_1a.hash(), &block_1a.mutator_set_accumulator_after())
                .await;
            assert!(wallet_status_1a.synced_unspent_total_amount().is_zero());

            // Simulate reorganization.
            alice_global_lock
                .lock_guard_mut()
                .await
                .set_new_tip(block_1b.clone())
                .await
                .unwrap();
            alice_global_lock
                .lock_guard_mut()
                .await
                .set_new_tip(block_2b.clone())
                .await
                .unwrap();
            let wallet_status_2b = alice_global_lock
                .lock_guard()
                .await
                .wallet_state
                .get_wallet_status(block_2b.hash(), &block_2b.mutator_set_accumulator_after())
                .await;
            assert_eq!(
                init_balance,
                wallet_status_2b.synced_unspent_total_amount(),
                "Initial balance must be restored when spending-tx was reorganized away."
            );

            // Verify that MUTXOs can be used to create a similar transaction to the one
            // that was reorganized away.
            let _ = outgoing_transaction(
                &alice_global_lock,
                NativeCurrencyAmount::coins(19),
                NativeCurrencyAmount::coins(1),
                timestamp,
                change_key,
            )
            .await;

            // Go back to a-chain and verify that MUTXOs are considered spent again.
            let block_2a = invalid_empty_block(&block_1a);
            alice_global_lock
                .lock_guard_mut()
                .await
                .set_new_tip(block_2a.clone())
                .await
                .unwrap();
            assert!(alice_global_lock
                .lock_guard()
                .await
                .wallet_state
                .get_wallet_status(block_2a.hash(), &block_2a.mutator_set_accumulator_after())
                .await
                .synced_unspent_total_amount()
                .is_zero());
        }

        #[tokio::test]
        async fn abandoned_utxo_is_unsynced() {
            // 1. create a genesis state for Alice
            // 2. create block_1a where Alice gets a guesser-fee UTXO, set as tip
            // 3. Verify expected balance
            // 4. Verify no abandoned/unsynced MUTXOs
            // 5. create block_1b where Alice doesn't get anything, set as tip
            // 6. Verify presence of abandoned/unsynced MUTXOs.
            let network = Network::Main;
            let mut rng = rand::rng();
            let alice_wallet = WalletSecret::new_pseudorandom(rng.random());
            let mut alice_global_lock = mock_genesis_global_state(
                network,
                0,
                alice_wallet.clone(),
                cli_args::Args::default(),
            )
            .await;
            let genesis = Block::genesis(network);
            let guesser_preimage = rng.random();

            let guesser_fraction = 0.6f64;
            let (block_1a, composer_utxos_1a) =
                make_mock_block_guesser_preimage_and_guesser_fraction(
                    &genesis,
                    None,
                    alice_wallet.nth_generation_spending_key(14),
                    rng.random(),
                    guesser_fraction,
                    guesser_preimage,
                )
                .await;
            let guesser_fee_utxos_1a = block_1a.guesser_fee_expected_utxos(guesser_preimage);
            let all_mine_rewards_1a = [composer_utxos_1a, guesser_fee_utxos_1a].concat();

            alice_global_lock
                .lock_guard_mut()
                .await
                .set_new_self_mined_tip(block_1a.clone(), all_mine_rewards_1a)
                .await
                .unwrap();
            let wallet_status_1a = alice_global_lock
                .global_state_lock
                .lock_guard()
                .await
                .wallet_state
                .get_wallet_status(block_1a.hash(), &block_1a.mutator_set_accumulator_after())
                .await;
            assert_eq!(
                Block::block_subsidy(1u64.into()),
                wallet_status_1a.synced_unspent_total_amount()
            );

            assert!(wallet_status_1a.unsynced.is_empty());

            // Set tip to competing block with no reward for Alice.
            let block_1b = invalid_empty_block(&genesis);
            alice_global_lock
                .lock_guard_mut()
                .await
                .set_new_tip(block_1b.clone())
                .await
                .unwrap();
            let wallet_status_1b = alice_global_lock
                .global_state_lock
                .lock_guard()
                .await
                .wallet_state
                .get_wallet_status(block_1b.hash(), &block_1b.mutator_set_accumulator_after())
                .await;
            assert!(wallet_status_1b.synced_unspent_total_amount().is_zero());
            assert!(!wallet_status_1b.unsynced.is_empty());
        }
    }
}
