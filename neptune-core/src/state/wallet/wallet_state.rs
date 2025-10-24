use std::collections::HashMap;
use std::collections::HashSet;
use std::error::Error;
use std::fmt::Debug;
use std::path::Path;
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
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::prelude::Mmr;
use tasm_lib::twenty_first::tip5::digest::Digest;
use tokio::fs::OpenOptions;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncWriteExt;
use tokio::io::BufReader;
use tokio::io::BufWriter;
use tracing::debug;
use tracing::info;
use tracing::trace;
use tracing::warn;

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
use super::wallet_configuration::WalletConfiguration;
use super::wallet_entropy::WalletEntropy;
use super::wallet_file::WalletFileContext;
use super::wallet_status::WalletStatus;
use super::wallet_status::WalletStatusElement;
use crate::application::config::cli_args::Args;
use crate::application::config::data_directory::DataDirectory;
use crate::application::config::fee_notification_policy::FeeNotificationPolicy;
use crate::application::database::storage::storage_schema::DbtVec;
use crate::application::database::storage::storage_schema::RustyKey;
use crate::application::database::storage::storage_schema::RustyValue;
use crate::application::database::storage::storage_vec::traits::*;
use crate::application::database::storage::storage_vec::Index;
use crate::application::database::NeptuneLevelDb;
use crate::application::loops::channel::ClaimUtxoData;
use crate::application::loops::mine_loop::coinbase_distribution::CoinbaseDistribution;
use crate::application::loops::mine_loop::composer_parameters::ComposerParameters;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::mutator_set_update::MutatorSetUpdate;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::state::mempool::mempool_event::MempoolEvent;
use crate::state::transaction::transaction_kernel_id::TransactionKernelId;
use crate::state::wallet::monitored_utxo::MonitoredUtxo;
use crate::state::wallet::rusty_wallet_database::WalletDbConnectError;
use crate::state::wallet::transaction_input::TxInput;
use crate::state::wallet::transaction_output::TxOutput;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::commit;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use crate::util_types::mutator_set::removal_record::RemovalRecord;

pub struct WalletState {
    pub wallet_db: RustyWalletDatabase,
    pub wallet_entropy: WalletEntropy,

    /// these two fields are for monitoring wallet-affecting utxos in the mempool.
    /// key is Tx hash.  for removing watched utxos when a tx is removed from mempool.
    mempool_spent_utxos: HashMap<TransactionKernelId, HashMap<AbsoluteIndexSet, (Utxo, u64)>>,
    mempool_unspent_utxos: HashMap<TransactionKernelId, Vec<IncomingUtxo>>,

    // these fields represent all known keys that have been handed out,
    // ie keys with derivation index in 0..self.spending_key_counter(key_type)
    // derivation order is preserved and each key must be unique.
    known_generation_keys: Vec<SpendingKey>,
    known_symmetric_keys: Vec<SpendingKey>,

    /// Tunable options for configuring how the wallet state operates.
    pub(crate) configuration: WalletConfiguration,
}

/// Contains the cryptographic (non-public) data that is needed to recover the mutator set
/// membership proof of a UTXO.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec)]
pub struct IncomingUtxoRecoveryData {
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
pub(crate) struct StrongUtxoKey {
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

impl From<&UnlockedUtxo> for StrongUtxoKey {
    fn from(unlocked_utxo: &UnlockedUtxo) -> Self {
        Self::new(
            unlocked_utxo.addition_record(),
            unlocked_utxo.mutator_set_mp().aocl_leaf_index,
        )
    }
}

impl Debug for WalletState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletState")
            .field("wallet_entropy", &self.wallet_entropy)
            .field(
                "number_of_mps_per_utxo",
                &self.configuration.num_mps_per_utxo,
            )
            .field(
                "wallet_directory_path",
                &self.configuration.data_directory().wallet_directory_path(),
            )
            .finish()
    }
}

impl WalletState {
    /// Generate [`ComposerParameters`] for composing the next block. If a
    /// coinbase distribution is specified, that will be used. If no coinbase
    /// distribution is specified, the entire coinbase reward goes to an address
    /// of the wallet. If the coinbase distribution *is* set, it is assumed that
    /// the composer reward does not go to the wallet of this node.
    ///
    ///  # Panics
    ///
    ///  - If the `guesser_fraction` is not a fraction contained in \[0;1\].
    pub(crate) fn composer_parameters(
        &self,
        next_block_height: BlockHeight,
        guesser_fraction: f64,
        fee_notification: FeeNotificationPolicy,
        coinbase_distribution: Option<CoinbaseDistribution>,
    ) -> ComposerParameters {
        let reward_address = self.wallet_entropy.prover_fee_address();
        let sender_randomness_for_composer = self
            .wallet_entropy
            .generate_sender_randomness(next_block_height, reward_address.privacy_digest());

        // If coinbase distribution is not set, we assume this wallet does not
        // have the receiver preimage.
        let receiver_preimage = if coinbase_distribution.is_some() {
            None
        } else {
            Some(self.wallet_entropy.composer_fee_key().receiver_preimage())
        };

        // If no coinbase distribution is set, reward this node's wallet.
        let coinbase_distribution =
            coinbase_distribution.unwrap_or(CoinbaseDistribution::solo(reward_address));

        ComposerParameters::new(
            coinbase_distribution,
            sender_randomness_for_composer,
            receiver_preimage,
            guesser_fraction,
            fee_notification,
        )
    }

    /// Store information needed to recover mutator set membership proof of a
    /// UTXO, in case the wallet database is deleted.
    ///
    /// Uses non-blocking I/O via tokio.
    pub(crate) async fn store_utxo_ms_recovery_data(
        &self,
        utxo_ms_recovery_data: IncomingUtxoRecoveryData,
    ) -> Result<()> {
        // Create JSON string ending with a newline as this flushes the write
        #[cfg(windows)]
        const LINE_ENDING: &str = "\r\n";
        #[cfg(not(windows))]
        const LINE_ENDING: &str = "\n";

        #[cfg(test)]
        {
            tokio::fs::create_dir_all(self.configuration.data_directory().wallet_directory_path())
                .await?;
        }

        // Open file
        let incoming_secrets_file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(self.configuration.incoming_secrets_path())
            .await?;
        let mut incoming_secrets_file = BufWriter::new(incoming_secrets_file);

        let mut json_string = serde_json::to_string(&utxo_ms_recovery_data)?;
        json_string.push_str(LINE_ENDING);
        incoming_secrets_file
            .write_all(json_string.as_bytes())
            .await?;

        // Flush just in case, since this is cryptographic data, you can't be too sure
        incoming_secrets_file.flush().await?;

        Ok(())
    }

    /// Read recovery-information for mutator set membership proof of a UTXO.
    /// Returns all lines in the files, where each line represents an incoming
    /// UTXO.
    ///
    /// Uses non-blocking I/O via tokio.
    pub(crate) async fn read_utxo_ms_recovery_data(&self) -> Result<Vec<IncomingUtxoRecoveryData>> {
        // Open file
        let incoming_secrets_file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(self.configuration.incoming_secrets_path())
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

    /// Create a `WalletState` object from related data.
    ///
    /// Convenience method to extract required data prior to calling the
    /// canonical constructor, [Self::try_new()].
    pub(crate) async fn try_new_from_context(
        data_dir: &DataDirectory,
        wallet_file_context: WalletFileContext,
        cli_args: &Args,
        genesis: &Block,
    ) -> Result<Self> {
        let database_is_new = !tokio::fs::try_exists(&data_dir.wallet_database_dir_path()).await?;
        info!(
            "wallet DB directory path is {}. Exists: {}",
            data_dir.wallet_database_dir_path().display(),
            if database_is_new { "no" } else { "yes" }
        );
        let mut configuration = WalletConfiguration::new(data_dir).absorb_options(cli_args);

        let wallet_entropy = wallet_file_context.entropy();

        // if wallet was imported, ensure scan mode is enabled
        if !wallet_file_context.wallet_is_new && database_is_new {
            info!("Wallet file present but database absent; wallet may have been imported.");
            configuration.enable_scan_mode();
        }

        Self::try_new(configuration, wallet_entropy, genesis).await
    }

    /// Construct a `WalletState` object.
    pub(crate) async fn try_new(
        configuration: WalletConfiguration,
        wallet_entropy: WalletEntropy,
        genesis: &Block,
    ) -> anyhow::Result<Self> {
        const NUM_PREMINE_KEYS: usize = 10;

        let wallet_database_path = configuration.data_directory().wallet_database_dir_path();
        DataDirectory::create_dir_if_not_exists(&wallet_database_path).await?;
        let wallet_db = Self::open_wallet_db(&wallet_database_path).await?;

        let rusty_wallet_database = match RustyWalletDatabase::try_connect(wallet_db).await {
            Err(WalletDbConnectError::SchemaVersionTooLow { found, expected: _ }) => {
                // DB schema version is too low, so we need to migrate it.
                // note: wallet_db was moved into try_connect() and is now dropped/closed.

                // safety first! backup wallet DB before migrating schema.
                Self::backup_database(&configuration, found).await?;

                // attempt to connect and migrate the DB to latest version.
                let db = Self::open_wallet_db(&wallet_database_path).await?;
                RustyWalletDatabase::try_connect_and_migrate(db).await
            }
            other => other,
        }?;

        let sync_label = rusty_wallet_database.get_sync_label();

        // generate and cache all used generation keys
        let known_generation_keys = (0..rusty_wallet_database.get_generation_key_counter())
            .map(|idx| wallet_entropy.nth_generation_spending_key(idx).into())
            .collect_vec();

        // generate and cache all used symmetric keys
        let known_symmetric_keys = (0..rusty_wallet_database.get_symmetric_key_counter())
            .map(|idx| wallet_entropy.nth_symmetric_key(idx).into())
            .collect_vec();

        let mut wallet_state = Self {
            wallet_db: rusty_wallet_database,
            wallet_entropy,
            mempool_spent_utxos: Default::default(),
            mempool_unspent_utxos: Default::default(),
            known_generation_keys,
            known_symmetric_keys,
            configuration: configuration.clone(),
        };

        // Generation and Symmetric keys with derivation index 0 are reserved
        // for rewards for composing, upgrading, and guessing. The
        // next lines ensure that the key with derivation-index=0 key is known
        // to the wallet, so that claiming these rewards works.
        //
        // Motivation:
        //  1. If the notifications are transmitted off-chain, there is no
        //     privacy issue because publicly observable data is unlinkable even
        //     if the lock script is the same. (But conversely: there *is* a
        //     privacy issue when on-chain notifications are used: fees to the
        //     same composer can be linked together as such.)
        //  2. If we were to derive a new address for each proving task (compose
        //     or upgrade) then we would have large gaps since an address only
        //     receives funds if that transaction or block actually gets
        //     confirmed.
        //  3. Using derivation-index 0 allows us to avoid modifying
        //     global/wallet state.
        //  4. The singleton of derivation-indices {0} is easier to scan for
        //     than a non-trivial set.
        //
        // Wallets start at key derivation index 1 for all UTXOs that are
        // neither composing rewards, nor proof upgrading rewards, nor premine
        // UTXOs.
        //
        // note: this makes test known_keys_are_unique() pass.
        if wallet_state.known_generation_keys.is_empty() {
            let _ = wallet_state
                .next_unused_spending_key(KeyType::Generation)
                .await;
        }
        if wallet_state.known_symmetric_keys.is_empty() {
            let _ = wallet_state
                .next_unused_spending_key(KeyType::Symmetric)
                .await;
        }

        // For premine UTXOs there is an additional complication: we do not know
        // the derivation index with which they were derived. So we derive a few
        // keys to have a bit of margin.
        let premine_keys = (0..NUM_PREMINE_KEYS)
            .map(|n| wallet_state.nth_spending_key(KeyType::Generation, n as u64))
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
                let own_receiving_address = premine_key.to_address();
                for utxo in Block::premine_utxos() {
                    if utxo.lock_script_hash() == own_receiving_address.lock_script_hash() {
                        wallet_state
                            .add_expected_utxo(ExpectedUtxo::new(
                                utxo,
                                Block::premine_sender_randomness(configuration.network()),
                                premine_key.privacy_preimage(),
                                UtxoNotifier::Premine,
                            ))
                            .await;
                    }
                }
            }

            let maintain_mps = true;
            wallet_state
                .update_wallet_state_with_new_block(
                    &MutatorSetAccumulator::default(),
                    genesis,
                    maintain_mps,
                )
                .await?;

            // No db-persisting here, as all of state should preferably be
            // persisted at the same time.
        }

        Ok(wallet_state)
    }

    async fn open_wallet_db(path: &Path) -> anyhow::Result<NeptuneLevelDb<RustyKey, RustyValue>> {
        NeptuneLevelDb::new(path, &crate::application::database::create_db_if_missing())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to open wallet db at '{}': {}", path.display(), e))
    }

    /// performs backup of DB dir by copying it to a new directory.
    async fn backup_database(
        configuration: &WalletConfiguration,
        schema_version: u16,
    ) -> anyhow::Result<PathBuf> {
        let db_dir = configuration.data_directory().wallet_database_dir_path();
        let backup_dir = configuration
            .data_directory()
            .wallet_db_next_unused_migration_backup_path(schema_version)
            .ok_or_else(|| anyhow::anyhow!("unable to find an unused backup path"))?;

        // ensure backup dir exists
        DataDirectory::create_dir_if_not_exists(&backup_dir).await?;

        // we open DB first so leveldb ensures no-one else can use it meanwhile.
        // not for windows since this causes a "used by another process" os error 32.
        #[cfg(not(target_os = "windows"))]
        let _db = Self::open_wallet_db(&db_dir).await?;
        // dummy await point on Windows to avoid "no await statements" error.
        #[cfg(target_os = "windows")]
        let _ready = futures::future::ready(()).await;

        tracing::info!(
            "backing up wallet database from {} to {}",
            db_dir.display(),
            backup_dir.display()
        );

        // perform the backup.
        crate::copy_dir_recursive(&db_dir, &backup_dir).map_err(|e| {
            anyhow::anyhow!("failed copying wallet database to backup directory. {e}")
        })?;

        tracing::info!("backed up wallet database to {}", backup_dir.display());

        Ok(backup_dir) // _db is dropped/closed
    }

    /// Extract `ExpectedUtxo`s from the `TxOutputList` that require off-chain
    /// notifications and that are destined for this wallet.
    pub(crate) fn extract_expected_utxos<'a>(
        &self,
        tx_outputs: impl Iterator<Item = &'a TxOutput>,
        notifier: UtxoNotifier,
    ) -> Vec<ExpectedUtxo> {
        tx_outputs
            .filter(|txo| txo.is_offchain())
            .filter_map(|txo| {
                self.find_addressable_spending_key_for_utxo(&txo.utxo())
                    .map(|sk| (txo, sk))
            })
            .map(|(tx_output, spending_key)| {
                ExpectedUtxo::new(
                    tx_output.utxo(),
                    tx_output.sender_randomness(),
                    spending_key.privacy_preimage(),
                    notifier,
                )
            })
            .collect_vec()
    }

    /// handles a list of mempool events
    pub(in crate::state) async fn handle_mempool_events(
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
    /// unconfirmed utxos sent from or to the wallet. This enables calculation
    /// of unconfirmed balance and prevents UTXOs in the mempool from being
    /// double spent.
    pub(in crate::state) async fn handle_mempool_event(&mut self, event: MempoolEvent) {
        match event {
            MempoolEvent::AddTx(tx_kernel) => {
                debug!(r"handling mempool AddTx event.  details:\n{}", tx_kernel);

                let spent_utxos = self.scan_for_spent_utxos(&tx_kernel).await;

                // scan tx for utxo we can claim because we are expecting them (offchain)
                let own_utxos_from_expected_utxos =
                    self.scan_for_expected_utxos(&tx_kernel.outputs).await;

                // scan tx for utxo with announcements we can claim
                let announced_utxos_from_announcements =
                    self.scan_for_utxos_announced_to_known_keys(&tx_kernel);

                let own_utxos = announced_utxos_from_announcements
                    .chain(own_utxos_from_expected_utxos)
                    .collect_vec();

                let tx_id = tx_kernel.txid();

                self.mempool_spent_utxos.insert(tx_id, spent_utxos);
                self.mempool_unspent_utxos.insert(tx_id, own_utxos);
            }
            MempoolEvent::RemoveTx(tx_kernel) => {
                let tx_id = tx_kernel.txid();
                debug!("handling mempool RemoveTx event.  tx: {}", tx_id);
                self.mempool_spent_utxos.remove(&tx_id);
                self.mempool_unspent_utxos.remove(&tx_id);
            }
        }
    }

    /// Get an iterator over (utxo, aocl_leaf_index) pairs corresponding to
    /// own inputs into transactions that live in the mempool.
    pub fn mempool_spent_utxos_iter(&self) -> impl Iterator<Item = (&Utxo, &u64)> {
        self.mempool_spent_utxos
            .values()
            .flatten()
            .map(|(_, (utxo, ali))| (utxo, ali))
    }

    /// Get an iterator over (utxo, addition_record) pairs corresponding to
    /// outputs of transactions that live in the mempool.
    pub fn mempool_unspent_utxos_iter(&self) -> impl Iterator<Item = (&Utxo, AdditionRecord)> {
        self.mempool_unspent_utxos
            .values()
            .flatten()
            .map(|iu| (&iu.utxo, iu.addition_record()))
    }

    pub(crate) fn mempool_balance_updates(
        &self,
    ) -> (
        impl Iterator<Item = (TransactionKernelId, NativeCurrencyAmount)> + '_,
        impl Iterator<Item = (TransactionKernelId, NativeCurrencyAmount)> + '_,
    ) {
        let outgoing = self.mempool_spent_utxos.iter().map(|(txkid, sender_data)| {
            (
                *txkid,
                sender_data
                    .values()
                    .map(|(utxo, __)| utxo.get_native_currency_amount())
                    .sum::<NativeCurrencyAmount>(),
            )
        });

        let incoming = self
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

    /// returns unconfirmed, available balance (excludes timelocked utxos)
    pub fn unconfirmed_available_balance(
        &self,
        wallet_status: &WalletStatus,
        timestamp: Timestamp,
    ) -> NativeCurrencyAmount {
        let amount_spent_by_mempool_transactions = self
            .mempool_spent_utxos_iter()
            .map(|(u, _)| u.get_native_currency_amount())
            .sum();
        let amount_received_from_mempool_transactions = self
            .mempool_unspent_utxos_iter()
            .filter(|(utxo, _)| utxo.can_spend_at(timestamp))
            .map(|(u, _)| u.get_native_currency_amount())
            .sum();
        wallet_status
            .available_confirmed(timestamp)
            .checked_add(&amount_received_from_mempool_transactions)
            .expect("balance must never overflow")
            .checked_sub(&amount_spent_by_mempool_transactions)
            .unwrap_or(NativeCurrencyAmount::zero())
    }

    /// returns unconfirmed, total balance (includes timelocked utxos)
    pub fn unconfirmed_total_balance(&self, wallet_status: &WalletStatus) -> NativeCurrencyAmount {
        wallet_status
            .total_confirmed()
            .checked_sub(
                &self
                    .mempool_spent_utxos_iter()
                    .map(|(u, _)| u.get_native_currency_amount())
                    .sum(),
            )
            .expect("balance must never be negative")
            .checked_add(
                &self
                    .mempool_unspent_utxos_iter()
                    .map(|(u, _)| u.get_native_currency_amount())
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
        let stream = list.stream_many_values((0..len).rev());
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
        for expected_utxo in expected_utxos {
            self.add_expected_utxo(ExpectedUtxo::new(
                expected_utxo.utxo,
                expected_utxo.sender_randomness,
                expected_utxo.receiver_preimage,
                expected_utxo.received_from,
            ))
            .await;
        }
    }

    /// Return UTXOs spent by this wallet in the transaction
    async fn scan_for_spent_utxos(
        &self,
        transaction_kernel: &TransactionKernel,
    ) -> HashMap<AbsoluteIndexSet, (Utxo, u64)> {
        let confirmed_absolute_index_sets: HashSet<_> = transaction_kernel
            .inputs
            .iter()
            .map(|rr| rr.absolute_indices)
            .collect();

        let monitored_utxos = self.wallet_db.monitored_utxos();
        let mut spent_own_utxos = HashMap::default();

        let stream = monitored_utxos.stream().await;
        pin_mut!(stream); // needed for iteration

        while let Some((i, monitored_utxo)) = stream.next().await {
            let abs_i = match monitored_utxo.get_latest_membership_proof_entry() {
                Some(msmp) => msmp.1.compute_indices(Tip5::hash(&monitored_utxo.utxo)),
                None => continue,
            };

            if confirmed_absolute_index_sets.contains(&abs_i) {
                spent_own_utxos.insert(abs_i, (monitored_utxo.utxo, i));
            }
        }
        spent_own_utxos
    }

    /// Scan the given transaction for announced UTXOs as recognized by owned
    /// [SpendingKey]s and then verify those announced UTXOs are actually
    /// present.
    ///
    /// Only announced UTXOs actually present in the transaction are returned
    /// here, it's not sufficient that they are announced.
    pub(crate) fn scan_for_utxos_announced_to_known_keys<'a>(
        &'a self,
        tx_kernel: &'a TransactionKernel,
    ) -> impl Iterator<Item = IncomingUtxo> + 'a {
        // scan for announced utxos for every known key of every key type.
        self.get_all_known_spending_keys()
            .flat_map(|key| key.scan_for_announced_utxos(tx_kernel))
            .filter(|au| {
                let transaction_contains_addition_record =
                    tx_kernel.outputs.contains(&au.addition_record());
                if !transaction_contains_addition_record {
                    warn!(
                        "Transaction does not contain announced UTXO encrypted \
                        to own receiving address. Announced UTXO was: {:#?}",
                        au.utxo
                    );
                }
                transaction_contains_addition_record
            })
    }

    /// Scan the given transaction for announced UTXOs as recognized by *future*
    /// keys, *i.e.*, keys that will be derived by the next n derivation
    /// indices.
    ///
    /// Only announced UTXOs actually present in the transaction are returned
    /// here, it's not sufficient that they are announced.
    fn scan_for_utxos_announced_to_future_keys<'a>(
        &'a self,
        num_future_keys: usize,
        tx_kernel: &'a TransactionKernel,
    ) -> impl Iterator<Item = (KeyType, u64, IncomingUtxo)> + 'a {
        self.get_future_spending_keys(num_future_keys).flat_map(
            |(key_type, derivation_index, key)| {
                key.scan_for_announced_utxos(tx_kernel)
                    .into_iter()
                    .filter(|au| {
                        let transaction_contains_addition_record =
                            tx_kernel.outputs.contains(&au.addition_record());
                        if !transaction_contains_addition_record {
                            warn!(
                                "Transaction does not contain announced UTXO \
                                encrypted to own receiving address."
                            );
                            debug!("Announced UTXO was: {:#?}", au.utxo);
                        }
                        transaction_contains_addition_record
                    })
                    .map(move |au| (key_type, derivation_index, au))
            },
        )
    }

    /// Scan the given list of addition records for items that match with list
    /// of expected incoming UTXOs, and returns expected UTXOs that are present.
    ///
    /// note: this algorithm is o(n) + o(m) where:
    ///   n = number of ExpectedUtxo in database. (all-time)
    ///   m = number of transaction outputs.
    ///
    /// Returns an iterator of [IncomingUtxo], which in turn contains a
    /// [`Utxo`], [sender randomness](IncomingUtxo::sender_randomness),
    /// [receiver preimage](IncomingUtxo::receiver_preimage), and the addition
    /// record can be inferred from these three fields.
    pub(crate) async fn scan_for_expected_utxos<'a>(
        &'a self,
        addition_records: &'a [AdditionRecord],
    ) -> impl Iterator<Item = IncomingUtxo> + 'a {
        let expected_utxos = self.wallet_db.expected_utxos().get_all().await;
        let expected_utxos: HashMap<_, _> = expected_utxos
            .into_iter()
            .map(|eu| (eu.addition_record, eu))
            .collect();

        addition_records
            .iter()
            .filter_map(move |a| expected_utxos.get(a).map(|eu| eu.into()))
    }

    /// Scan the block for guesser fee UTXOs that this wallet can unlock.
    ///
    /// Return an iterator over them, which is empty if the block was guessed by
    /// some other wallet.
    pub(crate) fn scan_for_guesser_fee_utxos<'a>(
        &'a self,
        block: &Block,
    ) -> impl Iterator<Item = IncomingUtxo> + 'a {
        let own_guesser_key = self.wallet_entropy.guesser_fee_key();
        let was_guessed_by_us = block
            .header()
            .was_guessed_by(&own_guesser_key.to_address().into());
        let incoming_utxos = if was_guessed_by_us {
            let sender_randomness = block.hash();
            block
                .kernel
                .guesser_fee_utxos()
                .expect("Block argument must have guesser fee UTXOs")
                .into_iter()
                .map(|utxo| IncomingUtxo {
                    utxo,
                    sender_randomness,
                    receiver_preimage: own_guesser_key.receiver_preimage(),
                    is_guesser_fee: true,
                })
                .collect_vec()
        } else {
            vec![]
        };
        incoming_utxos.into_iter()
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
            .stream_many_values((0..len).rev());
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

    /// returns first base-spending-key that can unlock the utxo
    ///
    /// scans only known wallet keys.
    pub fn find_spending_key_for_utxo(&self, utxo: &Utxo) -> Option<SpendingKey> {
        self.get_all_known_spending_keys()
            .find(|k| k.lock_script_hash() == utxo.lock_script_hash())
    }

    /// returns first addressable-spending-key that can unlock the utxo
    ///
    /// scans only known wallet keys.
    pub fn find_addressable_spending_key_for_utxo(&self, utxo: &Utxo) -> Option<SpendingKey> {
        self.get_all_known_addressable_spending_keys()
            .find(|k| k.lock_script_hash() == utxo.lock_script_hash())
    }

    // returns Some(SpendingKey) if the utxo can be unlocked by one of the known
    // wallet keys.
    pub(crate) fn find_known_spending_key_for_receiver_identifier(
        &self,
        receiver_identifier: BFieldElement,
    ) -> Option<SpendingKey> {
        self.get_all_known_addressable_spending_keys()
            .find(|k| k.receiver_identifier() == receiver_identifier)
    }

    /// returns all base-spending-keys with derivation index less than current counter
    pub fn get_all_known_spending_keys(&self) -> impl Iterator<Item = SpendingKey> + '_ {
        KeyType::all_types()
            .into_iter()
            .flat_map(|key_type| self.get_known_spending_keys(key_type))
    }

    /// returns all addressable-spending keys with derivation index less than current counter
    pub fn get_all_known_addressable_spending_keys(
        &self,
    ) -> impl Iterator<Item = SpendingKey> + '_ {
        KeyType::all_types()
            .into_iter()
            .flat_map(|key_type| self.get_known_addressable_spending_keys(key_type))
    }

    /// Return an iterator over the next n spending keys of all applicably key
    /// types, with derivation info.
    ///
    /// Specifically, return an iterator over tuples (key type, derivation
    /// index, spending key) for the next `num_future_keys` to be derived, for
    /// key types "Generation" and "Symmetric Key". This function does **not**
    /// increment the derivation counter.
    pub(crate) fn get_future_spending_keys(
        &self,
        num_future_keys: usize,
    ) -> impl Iterator<Item = (KeyType, u64, SpendingKey)> + '_ {
        let future_generation_keys = self
            .get_future_generation_spending_keys(num_future_keys)
            .map(|(i, gsk)| (KeyType::Generation, i, SpendingKey::from(gsk)));
        let future_symmetric_keys = self
            .get_future_symmetric_keys(num_future_keys)
            .map(|(i, sk)| (KeyType::Symmetric, i, SpendingKey::from(sk)));
        future_generation_keys.chain(future_symmetric_keys)
    }

    /// returns all spending keys of `key_type` with derivation index less than current counter
    pub fn get_known_spending_keys(
        &self,
        key_type: KeyType,
    ) -> Box<dyn Iterator<Item = SpendingKey> + '_> {
        match key_type {
            KeyType::Generation => Box::new(self.get_known_generation_spending_keys()),
            KeyType::Symmetric => Box::new(self.get_known_symmetric_keys()),
        }
    }

    /// returns all spending keys of `key_type` with derivation index less than current counter
    pub fn get_known_addressable_spending_keys(
        &self,
        key_type: KeyType,
    ) -> Box<dyn Iterator<Item = SpendingKey> + '_> {
        match key_type {
            KeyType::Generation => Box::new(self.get_known_generation_spending_keys()),
            KeyType::Symmetric => Box::new(self.get_known_symmetric_keys()),
        }
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
    pub async fn next_unused_spending_key(&mut self, key_type: KeyType) -> SpendingKey {
        match key_type {
            KeyType::Generation => self.next_unused_generation_spending_key().await.into(),
            KeyType::Symmetric => self.next_unused_symmetric_key().await.into(),
        }
    }

    pub(crate) async fn bump_derivation_counter(&mut self, key_type: KeyType, max_used_index: u64) {
        let new_counter = max_used_index + 1;
        let current_counter = self.spending_key_counter(key_type);

        if current_counter < new_counter {
            match key_type {
                KeyType::Generation => {
                    self.wallet_db.set_generation_key_counter(new_counter).await;

                    for idx in current_counter..new_counter {
                        let key = self.wallet_entropy.nth_generation_spending_key(idx).into();
                        self.known_generation_keys.push(key);
                    }
                }
                KeyType::Symmetric => {
                    self.wallet_db.set_symmetric_key_counter(new_counter).await;

                    for idx in current_counter..new_counter {
                        let key = self.wallet_entropy.nth_symmetric_key(idx).into();
                        self.known_symmetric_keys.push(key);
                    }
                }
            }
        }
    }

    /// Get index of the next unused spending key of a given type.
    pub fn spending_key_counter(&self, key_type: KeyType) -> u64 {
        match key_type {
            KeyType::Generation => self.wallet_db.get_generation_key_counter(),
            KeyType::Symmetric => self.wallet_db.get_symmetric_key_counter(),
        }
    }

    /// Get the nth derived spending key of a given type.
    pub fn nth_spending_key(&self, key_type: KeyType, index: u64) -> SpendingKey {
        match key_type {
            KeyType::Generation => self
                .wallet_entropy
                .nth_generation_spending_key(index)
                .into(),
            KeyType::Symmetric => self.wallet_entropy.nth_symmetric_key(index).into(),
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
        let index = self.wallet_db.get_generation_key_counter();
        self.wallet_db.set_generation_key_counter(index + 1).await;
        let key = self.wallet_entropy.nth_generation_spending_key(index);
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
        let index = self.wallet_db.get_symmetric_key_counter();
        self.wallet_db.set_symmetric_key_counter(index + 1).await;
        let key = self.wallet_entropy.nth_symmetric_key(index);
        self.known_symmetric_keys.push(key.into());
        key
    }

    /// Get the next n generation spending keys (with derivation indices)
    /// without modifying the counter.
    pub(crate) fn get_future_generation_spending_keys(
        &self,
        num_future_keys: usize,
    ) -> impl Iterator<Item = (u64, generation_address::GenerationSpendingKey)> + use<'_> {
        let index = self.wallet_db.get_generation_key_counter();
        (index..index + (num_future_keys as u64))
            .map(|i| (i, self.wallet_entropy.nth_generation_spending_key(i)))
    }

    /// Get the next n symmetric spending keys (with derivation indices)
    /// without modifying the counter.
    pub(crate) fn get_future_symmetric_keys(
        &self,
        num_future_keys: usize,
    ) -> impl Iterator<Item = (u64, symmetric_key::SymmetricKey)> + use<'_> {
        let index = self.wallet_db.get_symmetric_key_counter();
        (index..index + (num_future_keys as u64))
            .map(|i| (i, self.wallet_entropy.nth_symmetric_key(i)))
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

    /// Scan the block for UTXOs owned by us.
    ///
    /// Scan with keys that will be derived in the future. Also, try-and-recover
    /// composer UTXOs assuming the block was composed by us.
    ///
    /// The scan is done only if scan mode is active and the block is in range.
    /// If incoming UTXOs are found, the relevant key derivation counters are
    /// updated.
    ///
    /// Only announced UTXOs actually present in the transaction are returned
    /// here, it's not sufficient that they are announced.
    async fn recover_by_scanning(&mut self, new_block: &Block) -> Vec<IncomingUtxo> {
        let Some(scan_mode_configuration) = &self.configuration.scan_mode else {
            return Vec::new();
        };
        if !scan_mode_configuration.block_is_in_range(new_block) {
            return Vec::new();
        }

        let mut recovered_outputs = vec![];

        // try to recover UTXOs spent to future keys
        let mut max_counters = HashMap::<KeyType, u64>::new();
        for (key_type, derivation_index, incoming_utxo) in self
            .scan_for_utxos_announced_to_future_keys(
                scan_mode_configuration.num_future_keys(),
                &new_block.body().transaction_kernel,
            )
        {
            if max_counters
                .get(&key_type)
                .is_none_or(|&current_max_derivation_index| {
                    current_max_derivation_index < derivation_index
                })
            {
                max_counters.insert(key_type, derivation_index);
            }
            recovered_outputs.push(incoming_utxo);
        }

        // try to reproduce composer fee UTXOs, assuming it was our block
        if let Some(guesser_fraction) = scan_mode_configuration.maybe_guesser_fraction() {
            // derive the composer parameters as the own miner would have
            let overriden_coinbase_distribution = None;
            let composer_parameters = self.composer_parameters(
                new_block.header().height,
                guesser_fraction,
                FeeNotificationPolicy::OffChain,
                overriden_coinbase_distribution,
            );

            // if we have the necessary info to claim them
            if let Some(receiver_preimage) = composer_parameters.maybe_receiver_preimage() {
                // derive the composer fee UTXOs as the own miner would have
                let coinbase_amount = Block::block_subsidy(new_block.header().height);
                let composer_txos =
                    composer_parameters.tx_outputs(coinbase_amount, new_block.header().timestamp);

                for composer_output in composer_txos.iter() {
                    // compute what the addition record would have been
                    let incoming_utxo = IncomingUtxo {
                        utxo: composer_output.utxo(),
                        sender_randomness: composer_output.sender_randomness(),
                        receiver_preimage,
                        is_guesser_fee: false,
                    };
                    let addition_record = incoming_utxo.addition_record();

                    // if the addition record is an output in the block,
                    // it is ours!
                    if new_block
                        .body()
                        .transaction_kernel
                        .outputs
                        .contains(&addition_record)
                    {
                        info!(
                            "Found composer fee UTXO worth {}; timelocked? {}",
                            incoming_utxo
                                .utxo
                                .get_native_currency_amount()
                                .display_n_decimals(8),
                            incoming_utxo.utxo.release_date().is_some()
                        );
                        recovered_outputs.push(incoming_utxo);
                    }
                }
            }
        }

        info!(
            "Scan Mode: recovered {} UTXOs in block {}",
            recovered_outputs.len(),
            new_block.header().height
        );

        for (key_type, derivation_index) in max_counters {
            self.bump_derivation_counter(key_type, derivation_index)
                .await;
        }

        recovered_outputs
    }

    /// Process all outputs from a block under the assumption that the node does
    /// *not* have accesss to an archival mutator set. This means that all
    /// membership proofs must be maintained from the outputs and inputs
    /// contained in the block.
    async fn process_inputs_and_outputs_maintain_mps(
        block: &Block,
        incoming: &HashMap<AdditionRecord, IncomingUtxo>,
        spent_inputs: &HashMap<AbsoluteIndexSet, (Utxo, u64)>,
        monitored_utxos: &mut DbtVec<MonitoredUtxo>,
        potential_duplicates: &HashMap<StrongUtxoKey, u64>,
        mut msa_state: MutatorSetAccumulator,
        num_mps_per_utxo: usize,
    ) -> Result<Vec<IncomingUtxoRecoveryData>> {
        /// Preprocess all own monitored UTXOs prior to processing of the block.
        ///
        /// Returns
        /// all membership proofs that need to be maintained
        async fn all_wallet_membership_proofs(
            monitored_utxos: &mut DbtVec<MonitoredUtxo>,
            new_block: &Block,
        ) -> HashMap<StrongUtxoKey, (MsMembershipProof, u64, Digest)> {
            // Find the membership proofs that were valid at the previous tip. They have
            // to be updated to the mutator set of the new block.
            let mut valid_membership_proofs_and_own_utxo_count: HashMap<
                StrongUtxoKey,
                (MsMembershipProof, u64, Digest),
            > = HashMap::default();
            let stream = monitored_utxos.stream().await;
            pin_mut!(stream); // needed for iteration

            while let Some((i, monitored_utxo)) = stream.next().await {
                let addition_record = monitored_utxo.addition_record();
                let utxo_digest = Tip5::hash(&monitored_utxo.utxo);
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
                                "Strong key must be unique in wallet DB. addition record:\
                                {addition_record}; ms_mp.aocl_leaf_index: {aocl_leaf_index}.\n\n
                                 Existing value was: {replaced:?}",
                            );
                        }
                    }
                    None => {
                        // Monitored UTXO does not have a synced MS-membership proof.
                        // Was MUTXO marked as abandoned? Then this is fine. Otherwise, log a
                        // warning.
                        if monitored_utxo.abandoned_at.is_some() {
                            debug!(
                                "Monitored UTXO with addition record {addition_record} was \
                             marked as abandoned. Skipping."
                            );
                        } else {
                            let confirmed_in_block_info = match monitored_utxo.confirmed_in_block {
                                Some(mutxo_received_in_block) => format!(
                                    "UTXO was received at block height {}.",
                                    mutxo_received_in_block.2
                                ),
                                None => String::from("No info about when UTXO was confirmed."),
                            };
                            warn!(
                            "Unable to find valid membership proof for UTXO with addition record \
                            {addition_record}. {confirmed_in_block_info} Current block height is {}",
                            new_block.kernel.header.height
                        );
                        }
                    }
                }
            }

            valid_membership_proofs_and_own_utxo_count
        }

        let MutatorSetUpdate {
            additions: addition_records,
            removals: removal_records,
        } = block
            .mutator_set_update()
            .expect("Block received as argument must have mutator set update");
        let mut removal_records = removal_records;
        removal_records.reverse();
        let mut removal_records: Vec<&mut RemovalRecord> =
            removal_records.iter_mut().collect::<Vec<_>>();

        let mut valid_membership_proofs_and_own_utxo_count =
            all_wallet_membership_proofs(monitored_utxos, block).await;

        debug!(
            "doing maintenance on {}/{} monitored UTXOs",
            valid_membership_proofs_and_own_utxo_count.len(),
            monitored_utxos.len().await
        );

        let mut changed_mps = vec![];
        let mut incoming_utxo_recovery_data_list = vec![];
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
            // The output UTXO belongs to us
            if let Some(incoming_utxo) = incoming.get(addition_record) {
                let IncomingUtxo {
                    utxo,
                    sender_randomness,
                    receiver_preimage,
                    is_guesser_fee,
                } = incoming_utxo.to_owned();
                info!(
                    "Received UTXO in block {:x}, height {}\nvalue = {}\n\
                    is guesser fee: {is_guesser_fee}\ntime-lock: {}\n\n",
                    block.hash(),
                    block.kernel.header.height,
                    utxo.get_native_currency_amount(),
                    utxo.release_date()
                        .map(|t| t.standard_format())
                        .unwrap_or_else(|| "none".into()),
                );
                let utxo_digest = Tip5::hash(&utxo);
                let new_own_membership_proof =
                    msa_state.prove(utxo_digest, sender_randomness, receiver_preimage);
                let aocl_index = new_own_membership_proof.aocl_leaf_index;
                let strong_key = StrongUtxoKey::new(*addition_record, aocl_index);

                // Add the new UTXO to the list of monitored UTXOs
                let mut mutxo = MonitoredUtxo::new(utxo.clone(), num_mps_per_utxo);
                mutxo.confirmed_in_block = Some((
                    block.hash(),
                    block.kernel.header.timestamp,
                    block.kernel.header.height,
                ));

                // Add the membership proof to the list of managed membership
                // proofs.
                if let Some(mutxo_index) = potential_duplicates.get(&strong_key) {
                    // There is already a monitored UTXO with that key in the
                    // database. If this block is confirming that UTXO, then it
                    // must be a reorg. So overwrite the existing entry's
                    // membership proof.
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
                    // The monitored UTXO is new. Push it.
                    let mutxos_len = monitored_utxos.len().await;
                    valid_membership_proofs_and_own_utxo_count.insert(
                        strong_key,
                        (new_own_membership_proof, mutxos_len, utxo_digest),
                    );
                    monitored_utxos.push(mutxo).await;

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

        let all_mutxo = monitored_utxos.get_all().await;
        let mut update_mutxos: Vec<(Index, MonitoredUtxo)> = vec![];

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
            if let Some((_spent_utxo, mutxo_list_index)) =
                spent_inputs.get(&removal_record.absolute_indices)
            {
                debug!(
                    "Discovered own input at removal record index {}, marking UTXO as spent.",
                    removal_record_index
                );

                let mut spent_mutxo = all_mutxo.get(*mutxo_list_index as usize).unwrap().clone();
                spent_mutxo.mark_as_spent(block);
                update_mutxos.push((*mutxo_list_index, spent_mutxo));
            }

            msa_state.remove(removal_record);
            removal_record_index += 1;
        }
        monitored_utxos.set_many(update_mutxos).await;

        // Sanity check that `msa_state` agrees with the mutator set from the applied block
        assert_eq!(
            block.mutator_set_accumulator_after().expect("Block must have mutator set after").clone().hash(),
            msa_state.hash(),
            "\n\nMutator set in applied block:\n{}\n\nmust agree with that in wallet handler:\n{}\n\n",
            block.mutator_set_accumulator_after().expect("Block must have mutator set after").clone().hash(),
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
            monitored_utxo.add_membership_proof_for_tip(block.hash(), updated_ms_mp.to_owned());

            // Sanity check that membership proofs of non-spent transactions are still valid
            assert!(
                monitored_utxo.spent_in_block.is_some()
                    || msa_state.verify(*utxo_digest, updated_ms_mp)
            );

            monitored_utxos.set(*own_utxo_index, monitored_utxo).await;
        }

        Ok(incoming_utxo_recovery_data_list)
    }

    /// Process all outputs in a block under the assumption that the node has
    /// access to an archival mutator set.
    async fn process_outputs_no_maintain_mps(
        block: &Block,
        incoming: &HashMap<AdditionRecord, IncomingUtxo>,
        mut aocl_leaf_count: u64,
        monitored_utxos: &mut DbtVec<MonitoredUtxo>,
        potential_duplicates: &HashMap<StrongUtxoKey, u64>,
        num_mps_per_utxo: usize,
    ) -> Vec<IncomingUtxoRecoveryData> {
        let mut recovery_data = vec![];

        let MutatorSetUpdate { additions, .. } = block
            .mutator_set_update()
            .expect("Block received as argument must have mutator set update");

        for addition_record in additions {
            if let Some(incoming_utxo) = incoming.get(&addition_record) {
                let IncomingUtxo {
                    utxo,
                    sender_randomness,
                    receiver_preimage,
                    ..
                } = incoming_utxo.to_owned();
                let aocl_index = aocl_leaf_count;
                let strong_key = StrongUtxoKey::new(addition_record, aocl_index);
                let mut mutxo = MonitoredUtxo::new(utxo.clone(), num_mps_per_utxo);
                mutxo.confirmed_in_block = Some((
                    block.hash(),
                    block.kernel.header.timestamp,
                    block.kernel.header.height,
                ));

                if let Some(mutxo_index) = potential_duplicates.get(&strong_key) {
                    // Update `confirmed_in_block` data to reflect potential
                    // reorganization.
                    let mut existing_mutxo = monitored_utxos.get(*mutxo_index).await;
                    existing_mutxo.confirmed_in_block = mutxo.confirmed_in_block;
                    monitored_utxos.set(*mutxo_index, existing_mutxo).await;
                } else {
                    monitored_utxos.push(mutxo).await;
                    let utxo_ms_recovery_data = IncomingUtxoRecoveryData {
                        utxo,
                        sender_randomness,
                        receiver_preimage,
                        aocl_index,
                    };
                    recovery_data.push(utxo_ms_recovery_data);
                }
            }

            aocl_leaf_count += 1;
        }

        recovery_data
    }

    /// Process all inputs in a block under the assumption that the node has
    /// access to an archival mutator set.
    async fn process_inputs_no_maintain_mps(
        block: &Block,
        spent_inputs: &HashMap<AbsoluteIndexSet, (Utxo, u64)>,
        monitored_utxos: &mut DbtVec<MonitoredUtxo>,
    ) {
        for (_, mutxo_list_index) in spent_inputs.values() {
            let mut spent_mutxo = monitored_utxos.get(*mutxo_list_index).await;
            spent_mutxo.mark_as_spent(block);
            monitored_utxos.set(*mutxo_list_index, spent_mutxo).await;
        }
    }

    /// Update wallet state with new block.
    ///
    /// Assume the given block is valid and that the wallet state is not synced
    /// with the new block yet but is synced with the previous block (if any).
    ///
    /// If function is called without maintaining membership proofs, the caller
    /// must ensure membership proofs are updated after the call to this
    /// function. The returned recovery data may help with that.
    pub async fn update_wallet_state_with_new_block(
        &mut self,
        previous_mutator_set_accumulator: &MutatorSetAccumulator,
        block: &Block,
        maintain_membership_proofs_in_wallet: bool,
    ) -> Result<Vec<IncomingUtxoRecoveryData>> {
        /// Get potential duplicates, to avoid registering same UTXO twice.
        ///
        /// The set of potential duplicates, UTXOs that have, potentially
        /// already been added by this wallet. Used for a later check to avoid
        /// adding the same UTXO twice. Since we don't know the AOCL leaf
        /// index of the incoming transaction, these are only potential
        /// duplicates, not certain duplicates.
        async fn potential_duplicates(
            monitored_utxos: &mut DbtVec<MonitoredUtxo>,
            incoming: &HashMap<AdditionRecord, IncomingUtxo>,
        ) -> HashMap<StrongUtxoKey, u64> {
            let mut maybe_duplicates: HashMap<StrongUtxoKey, u64> = HashMap::default();
            let stream = monitored_utxos.stream().await;
            pin_mut!(stream); // needed for iteration

            while let Some((i, monitored_utxo)) = stream.next().await {
                let addition_record = monitored_utxo.addition_record();
                let strong_key = StrongUtxoKey::new(addition_record, monitored_utxo.aocl_index());
                if incoming.contains_key(&addition_record) {
                    maybe_duplicates.insert(strong_key, i);
                }
            }

            maybe_duplicates
        }

        let tx_kernel = &block.kernel.body.transaction_kernel;

        let spent_inputs = self.scan_for_spent_utxos(tx_kernel).await;

        let onchain_received_outputs = self
            .scan_for_utxos_announced_to_known_keys(tx_kernel)
            .collect_vec();

        let outputs_recovered_through_scan_mode = self.recover_by_scanning(block).await;

        let MutatorSetUpdate { additions, .. } = block
            .mutator_set_update()
            .expect("Block received as argument must have mutator set update");

        let offchain_received_outputs =
            self.scan_for_expected_utxos(&additions).await.collect_vec();
        let guesser_fee_outputs = self.scan_for_guesser_fee_utxos(block);

        debug!(
            "Scanned block for incoming UTXOs; received {} onchain \
            notifications, {} onchain through scan mode, {} offchain \
            notifications",
            onchain_received_outputs.len(),
            outputs_recovered_through_scan_mode.len(),
            offchain_received_outputs.len()
        );

        // These UTXOs are guaranteed to be present in the block and guaranteed
        // to be spendable by the wallet.
        let incoming = onchain_received_outputs
            .into_iter()
            .chain(outputs_recovered_through_scan_mode)
            .chain(offchain_received_outputs.iter().cloned())
            .filter(|announced_utxo| announced_utxo.utxo.all_type_script_states_are_valid())
            .chain(guesser_fee_outputs);
        let incoming: HashMap<AdditionRecord, IncomingUtxo> = incoming
            .map(|incoming_utxo| (incoming_utxo.addition_record(), incoming_utxo))
            .collect();

        let monitored_utxos = self.wallet_db.monitored_utxos_mut();

        // return early if there are no monitored utxos and this
        // block does not affect our balance
        if spent_inputs.is_empty() && incoming.is_empty() && monitored_utxos.is_empty().await {
            self.wallet_db.set_sync_label(block.hash()).await;
            return Ok(vec![]);
        }

        let potential_duplicates = potential_duplicates(monitored_utxos, &incoming).await;
        let msa_state = previous_mutator_set_accumulator.clone();

        // Mutate the monitored UTXOs to account for this block.
        let incoming_utxo_recovery_data_list = if maintain_membership_proofs_in_wallet {
            Self::process_inputs_and_outputs_maintain_mps(
                block,
                &incoming,
                &spent_inputs,
                monitored_utxos,
                &potential_duplicates,
                msa_state,
                self.configuration.num_mps_per_utxo,
            )
            .await?
        } else {
            let recovery_list = Self::process_outputs_no_maintain_mps(
                block,
                &incoming,
                msa_state.aocl.num_leafs(),
                monitored_utxos,
                &potential_duplicates,
                self.configuration.num_mps_per_utxo,
            )
            .await;
            Self::process_inputs_no_maintain_mps(block, &spent_inputs, monitored_utxos).await;
            recovery_list
        };

        // write UTXO-recovery data to disk.
        for item in incoming_utxo_recovery_data_list.clone() {
            self.store_utxo_ms_recovery_data(item).await?;
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
                eu.mined_in_block = Some((block.hash(), block.kernel.header.timestamp));
                (idx as Index, eu)
            });
        self.wallet_db.expected_utxos_mut().set_many(updates).await;

        self.wallet_db.set_sync_label(block.hash()).await;

        Ok(incoming_utxo_recovery_data_list)
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
        let db_sync_digest = self.wallet_db.get_sync_label();
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

    /// Returns all spendable inputs.
    ///
    /// wallet_status must be current as of present tip.
    ///
    ///   excludes utxos:
    ///     + that are timelocked in the future
    ///     + that are unspendable (no spending key)
    ///     + that are already spent in the mempool
    pub(crate) fn spendable_inputs(
        &self,
        wallet_status: WalletStatus,
        timestamp: Timestamp,
    ) -> impl IntoIterator<Item = TxInput> + use<'_> {
        // Build a hashset of all tx inputs presently in the mempool.
        let index_sets_of_inputs_in_mempool_txs: HashSet<AbsoluteIndexSet> = self
            .mempool_spent_utxos
            .iter()
            .flat_map(|(_txkid, tx_inputs)| tx_inputs.keys())
            .copied()
            .collect();

        // filter spendable inputs.
        wallet_status.synced_unspent.into_iter().filter_map(
            move |(wallet_status_element, membership_proof)| {
                // filter out UTXOs that are still timelocked.
                if !wallet_status_element.utxo.can_spend_at(timestamp) {
                    return None;
                }

                // filter out inputs that are already spent by txs in mempool.
                let absolute_index_set =
                    membership_proof.compute_indices(Tip5::hash(&wallet_status_element.utxo));
                if index_sets_of_inputs_in_mempool_txs.contains(&absolute_index_set) {
                    return None;
                }

                // filter out inputs that we can't spend
                let Some(spending_key) =
                    self.find_spending_key_for_utxo(&wallet_status_element.utxo)
                else {
                    warn!(
                        "spending key not found for utxo: {:?}",
                        wallet_status_element.utxo
                    );
                    return None;
                };

                // Create the transaction input object
                Some(
                    UnlockedUtxo::unlock(
                        wallet_status_element.utxo.clone(),
                        spending_key.lock_script_and_witness(),
                        membership_proof.clone(),
                    )
                    .into(),
                )
            },
        )
    }

    /// Allocate sufficient UTXOs to generate a transaction.
    ///
    /// Requested amount `total_spend` must include fees that are paid in the
    /// transaction.
    ///
    /// note: this fn is replaced by TxInputListBuilder and
    /// TransactionInitiator::select_spendable_inputs().  It can be removed once
    /// tests are updated.
    #[cfg(test)]
    pub(crate) async fn allocate_sufficient_input_funds(
        &self,
        total_spend: NativeCurrencyAmount,
        tip_digest: Digest,
        mutator_set_accumulator: &MutatorSetAccumulator,
        timestamp: Timestamp,
    ) -> Result<Vec<UnlockedUtxo>> {
        let wallet_status = self
            .get_wallet_status(tip_digest, mutator_set_accumulator)
            .await;

        // First check that we have enough. Otherwise, return an error.
        let confirmed_available_amount_without_mempool_spends = wallet_status
            .available_confirmed(timestamp)
            .checked_sub(
                &self
                    .mempool_spent_utxos_iter()
                    .map(|(u, _)| u.get_native_currency_amount())
                    .sum(),
            )
            .expect("balance must never be negative");
        anyhow::ensure!(
            confirmed_available_amount_without_mempool_spends >= total_spend,
            "Insufficient funds. Requested: {total_spend}, \
            Available: {confirmed_available_amount_without_mempool_spends}",
        );

        let mut input_funds = vec![];
        let mut allocated_amount = NativeCurrencyAmount::zero();

        for input in self.spendable_inputs(wallet_status, timestamp) {
            // Don't allocate more than needed
            if allocated_amount >= total_spend {
                break;
            }

            // Select the input
            allocated_amount += input.utxo.get_native_currency_amount();
            input_funds.push(input.into());
        }

        // If there aren't enough funds, catch and report error gracefully
        if allocated_amount < total_spend {
            bail!(
                "UTXO allocation failed.\n\
                Requested: {total_spend}\n\
                Allocated: {allocated_amount}"
            )
        }

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
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use std::sync::Arc;

    use generation_address::GenerationSpendingKey;
    use macro_rules_attr::apply;
    use rand::prelude::*;
    use rand::random;
    use rand::rng;
    use tokio::sync::broadcast;
    use tracing_test::traced_test;

    use super::*;
    use crate::api::export::Transaction;
    use crate::application::config::cli_args;
    use crate::application::config::network::Network;
    use crate::application::triton_vm_job_queue::TritonVmJobQueue;
    use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::protocol::consensus::transaction::utxo::Coin;
    use crate::protocol::consensus::transaction::utxo_triple::UtxoTriple;
    use crate::state::transaction::tx_creation_config::TxCreationConfig;
    use crate::state::transaction::tx_proving_capability::TxProvingCapability;
    use crate::state::wallet::address::generation_address::GenerationReceivingAddress;
    use crate::state::wallet::expected_utxo::ExpectedUtxo;
    use crate::state::wallet::transaction_output::TxOutput;
    use crate::state::wallet::utxo_notification::UtxoNotificationMedium;
    use crate::state::GlobalStateLock;
    use crate::tests::shared::blocks::invalid_block_with_transaction;
    use crate::tests::shared::blocks::make_mock_block;
    use crate::tests::shared::blocks::make_mock_block_with_puts_and_guesser_preimage_and_guesser_fraction;
    use crate::tests::shared::globalstate::mock_genesis_global_state;
    use crate::tests::shared::mock_genesis_wallet_state;
    use crate::tests::shared::wallet_state_has_all_valid_mps;
    use crate::tests::shared_tokio_runtime;

    impl WalletState {
        pub(crate) async fn new_from_wallet_entropy(
            data_dir: &DataDirectory,
            wallet_entropy: WalletEntropy,
            cli_args: &Args,
        ) -> Self {
            let configuration = WalletConfiguration::new(data_dir).absorb_options(cli_args);
            let genesis_block = Block::genesis(configuration.network());
            Self::try_new(configuration, wallet_entropy, &genesis_block)
                .await
                .unwrap()
        }
    }

    /// Create an outgoing transaction. Helper function.
    ///
    /// Panics on insufficient balance.
    async fn outgoing_transaction(
        alice_global_lock: &mut GlobalStateLock,
        amount: NativeCurrencyAmount,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
        change_key: SpendingKey,
    ) -> Result<Arc<Transaction>> {
        let mut rng = rand::rng();
        let an_address = GenerationReceivingAddress::derive_from_seed(rng.random());
        let tx_output =
            TxOutput::onchain_native_currency(amount, rng.random(), an_address.into(), false);

        let config = TxCreationConfig::default()
            .recover_change_off_chain(change_key)
            .with_prover_capability(TxProvingCapability::PrimitiveWitness);
        let block_height = alice_global_lock
            .lock_guard()
            .await
            .chain
            .light_state()
            .header()
            .height;
        let network = alice_global_lock.cli().network;
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);
        alice_global_lock
            .api()
            .tx_initiator_internal()
            .create_transaction(
                vec![tx_output].into(),
                fee,
                timestamp,
                config,
                consensus_rule_set,
            )
            .await
            .map(|tx| tx.transaction)
    }

    #[apply(shared_tokio_runtime)]
    #[traced_test]
    async fn find_monitored_utxo_test() {
        let network = Network::Testnet(0);
        let cli_args = cli_args::Args::default_with_network(network);
        let alice_global_lock =
            mock_genesis_global_state(0, WalletEntropy::devnet_wallet(), cli_args).await;

        let premine_utxo = {
            let wallet = &alice_global_lock.lock_guard().await.wallet_state;
            Block::premine_utxos()
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

    #[apply(shared_tokio_runtime)]
    #[traced_test]
    async fn does_not_make_tx_with_timelocked_utxos() {
        // Ensure that timelocked UTXOs are not used when selecting input-UTXOs
        // to a transaction.
        // This test is a regression test for issue:
        // <https://github.com/Neptune-Crypto/neptune-core/issues/207>.

        let network = Network::Main;
        let mut alice_global_lock = mock_genesis_global_state(
            0,
            WalletEntropy::devnet_wallet(),
            cli_args::Args::default_with_network(network),
        )
        .await;

        let mut alice = alice_global_lock.global_state_lock.lock_guard_mut().await;
        let launch_timestamp = alice.chain.light_state().header().timestamp;
        let released_timestamp = launch_timestamp + Timestamp::months(12);
        let genesis = alice.chain.light_state();
        let genesis_digest = genesis.hash();
        let mutator_set_accumulator_after_genesis =
            genesis.mutator_set_accumulator_after().unwrap();
        let alice_ws_genesis = alice
            .wallet_state
            .get_wallet_status(genesis_digest, &mutator_set_accumulator_after_genesis)
            .await;

        // First, check that error is returned, when available balance is not
        // there, as it is timelocked.
        let one_coin = NativeCurrencyAmount::coins(1);
        assert!(alice_ws_genesis
            .available_confirmed(launch_timestamp)
            .is_zero());
        assert!(!alice_ws_genesis
            .available_confirmed(released_timestamp)
            .is_zero());
        assert!(
            alice
                .wallet_state
                .allocate_sufficient_input_funds(
                    one_coin,
                    genesis_digest,
                    &mutator_set_accumulator_after_genesis,
                    launch_timestamp,
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
                    released_timestamp,
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
            .wallet_entropy
            .nth_generation_spending_key_for_tests(0);
        let (block1, composer_expected_utxos) = make_mock_block(
            genesis,
            Some(block_1_timestamp),
            alice_key,
            Default::default(),
            network,
        )
        .await;

        alice
            .wallet_state
            .add_expected_utxos(composer_expected_utxos.clone())
            .await;
        alice.set_new_tip(block1.clone()).await.unwrap();

        let input_utxos = alice
            .wallet_state
            .allocate_sufficient_input_funds(
                one_coin,
                block1.hash(),
                &block1.mutator_set_accumulator_after().unwrap(),
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
        let cli = cli_args::Args::default_with_network(network);

        let bob_wallet_secret = WalletEntropy::new_random();
        let bob_key = bob_wallet_secret.nth_generation_spending_key_for_tests(0);
        let mut bob_global_lock =
            mock_genesis_global_state(0, bob_wallet_secret, cli.clone()).await;

        // `bob` both composes and guesses the PoW solution of this block.
        let (block1, composer_fee_eutxos) = make_mock_block(
            &Block::genesis(network),
            None,
            bob_key,
            rng.random(),
            network,
        )
        .await;

        bob_global_lock
            .set_new_self_composed_tip(block1.clone(), composer_fee_eutxos)
            .await
            .unwrap();

        (block1, bob_global_lock, bob_key)
    }

    #[apply(shared_tokio_runtime)]
    #[traced_test]
    async fn test_update_wallet_state_repeated_addition_records() {
        let network = Network::Main;
        let cli = cli_args::Args::default_with_network(network);

        let alice_wallet_secret = WalletEntropy::new_random();
        let alice_key = alice_wallet_secret.nth_generation_spending_key_for_tests(0);
        let mut alice = mock_genesis_global_state(0, alice_wallet_secret, cli).await;

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
        let config2 = TxCreationConfig::default()
            .recover_change_on_chain(bob_key.into())
            .with_prover_capability(TxProvingCapability::PrimitiveWitness);
        let block_height_1 = block1.header().height;
        let consensus_rule_set_1 = ConsensusRuleSet::infer_from(network, block_height_1);
        let tx_block2 = bob
            .api()
            .tx_initiator_internal()
            .create_transaction(
                tx_outputs.clone().into(),
                fee,
                network.launch_date() + Timestamp::minutes(11),
                config2,
                consensus_rule_set_1,
            )
            .await
            .unwrap()
            .transaction;

        // Make block 2, verify that Alice registers correct balance.
        let block2 = invalid_block_with_transaction(&block1, tx_block2.clone().into());
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
                .get_wallet_status(
                    block2.hash(),
                    &block2.mutator_set_accumulator_after().unwrap(),
                )
                .await;
            assert_eq!(
                NativeCurrencyAmount::coins(14),
                wallet_status.available_confirmed(tx_block2.kernel.timestamp),
                "Both UTXOs must be registered by wallet and contribute to balance"
            );
        }

        // Repeat the outputs to Alice in block 3 and verify correct new
        // balance.
        let config3 = TxCreationConfig::default()
            .recover_change_on_chain(bob_key.into())
            .with_prover_capability(TxProvingCapability::PrimitiveWitness);
        let consensus_rule_set_2 = ConsensusRuleSet::infer_from(network, block2.header().height);
        let tx_block3 = bob
            .api()
            .tx_initiator_internal()
            .create_transaction(
                tx_outputs.into(),
                fee,
                network.launch_date() + Timestamp::minutes(22),
                config3,
                consensus_rule_set_2,
            )
            .await
            .unwrap()
            .transaction;
        let block3 = invalid_block_with_transaction(&block2, tx_block3.clone().into());
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
                .get_wallet_status(
                    block3.hash(),
                    &block3.mutator_set_accumulator_after().unwrap(),
                )
                .await;
            assert_eq!(
                NativeCurrencyAmount::coins(28),
                wallet_status.available_confirmed(tx_block2.kernel.timestamp),
                "All four UTXOs must be registered by wallet and contribute to balance"
            );
        }
    }

    #[apply(shared_tokio_runtime)]
    #[traced_test]
    async fn test_invalid_type_script_states() {
        let network = Network::Main;
        let cli = cli_args::Args::default_with_network(network);
        let (block1, bob, bob_key) = bob_mines_one_block(network).await;

        let alice_wallet_secret = WalletEntropy::new_random();
        let alice_key = alice_wallet_secret.nth_generation_spending_key_for_tests(0);
        let mut alice = mock_genesis_global_state(0, alice_wallet_secret, cli).await;
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
        let config = TxCreationConfig::default()
            .recover_change_on_chain(bob_key.into())
            .with_prover_capability(TxProvingCapability::PrimitiveWitness);
        let consensus_rule_set_1 = ConsensusRuleSet::infer_from(network, block1.header().height);
        let mut tx_block2: Transaction = bob
            .api()
            .tx_initiator_internal()
            .create_transaction(
                vec![txo.clone()].into(),
                fee,
                network.launch_date() + Timestamp::minutes(11),
                config,
                consensus_rule_set_1,
            )
            .await
            .unwrap()
            .transaction
            .into();

        let mut bad_utxo = txo.utxo();
        bad_utxo = bad_utxo.append_to_coin_state(0, random());
        let bad_txo = txo.clone().replace_utxo(bad_utxo);
        let expected_bad_utxos = alice
            .lock_guard()
            .await
            .wallet_state
            .extract_expected_utxos([bad_txo.clone()].iter(), UtxoNotifier::Cli);
        alice
            .lock_guard_mut()
            .await
            .wallet_state
            .add_expected_utxos(expected_bad_utxos)
            .await;
        let bad_utxo_triple = bad_txo.utxo_triple();
        let bad_addition_record = bad_utxo_triple.addition_record();
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
                .get_wallet_status(
                    block2.hash(),
                    &block2.mutator_set_accumulator_after().unwrap(),
                )
                .await;

            assert!(
                wallet_status
                    .available_confirmed(tx_block2.kernel.timestamp)
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

    #[apply(shared_tokio_runtime)]
    #[traced_test]
    async fn test_unrecognized_type_script() {
        let network = Network::Main;
        let cli = cli_args::Args::default_with_network(network);

        let alice_wallet_secret = WalletEntropy::new_random();
        let alice_key = alice_wallet_secret.nth_generation_spending_key_for_tests(0);
        let mut alice = mock_genesis_global_state(0, alice_wallet_secret, cli).await;

        let (block1, bob, bob_key) = bob_mines_one_block(network).await;

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
        let config = TxCreationConfig::default()
            .recover_change_on_chain(bob_key.into())
            .with_prover_capability(TxProvingCapability::PrimitiveWitness);
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, block1.header().height);
        let mut tx_block2: Transaction = bob
            .api()
            .tx_initiator_internal()
            .create_transaction(
                vec![txo.clone()].into(),
                fee,
                network.launch_date() + Timestamp::minutes(11),
                config,
                consensus_rule_set,
            )
            .await
            .unwrap()
            .transaction
            .into();
        let unrecognized_typescript = Coin {
            type_script_hash: random(),
            state: vec![random(), random()],
        };
        let bad_txo = txo.clone().with_coin(unrecognized_typescript);
        let expected_bad_utxos = alice
            .lock_guard()
            .await
            .wallet_state
            .extract_expected_utxos([bad_txo.clone()].iter(), UtxoNotifier::Cli);
        alice
            .lock_guard_mut()
            .await
            .wallet_state
            .add_expected_utxos(expected_bad_utxos)
            .await;
        let bad_addition_record = bad_txo.addition_record();
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
                .get_wallet_status(
                    block2.hash(),
                    &block2.mutator_set_accumulator_after().unwrap(),
                )
                .await;

            assert!(
                wallet_status
                    .available_confirmed(tx_block2.kernel.timestamp)
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

    #[apply(shared_tokio_runtime)]
    #[traced_test]
    async fn never_store_same_utxo_twice_different_blocks() {
        let mut rng = rand::rng();
        let network = Network::Main;
        let bob_wallet_secret = WalletEntropy::new_random();
        let bob_key = bob_wallet_secret.nth_generation_spending_key_for_tests(0);
        let mut bob_global_lock = mock_genesis_global_state(
            0,
            bob_wallet_secret.clone(),
            cli_args::Args::default_with_network(network),
        )
        .await;

        let genesis_block = Block::genesis(network);
        let mock_block_seed = rng.random();
        let guesser_fraction = 0.5f64;

        // `bob` both composes and guesses the PoW solution of this block.
        let (block_1a, expected_utxos_block_1a) =
            make_mock_block_with_puts_and_guesser_preimage_and_guesser_fraction(
                &genesis_block,
                vec![],
                vec![],
                None,
                bob_key,
                mock_block_seed,
                (guesser_fraction, bob_key.to_address().into()),
                network,
            )
            .await;

        let mut bob = bob_global_lock.lock_guard_mut().await;
        let mutxos_1a = bob.wallet_state.wallet_db.monitored_utxos().get_all().await;
        bob.wallet_state
            .add_expected_utxos(expected_utxos_block_1a.clone())
            .await;
        bob.set_new_tip(block_1a.clone()).await.unwrap();
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
        let random_address = GenerationReceivingAddress::derive_from_seed(rng.random());
        let (block_1b, expected_utxos_block_1b) =
            make_mock_block_with_puts_and_guesser_preimage_and_guesser_fraction(
                &genesis_block,
                vec![],
                vec![],
                None,
                bob_key,
                mock_block_seed,
                (guesser_fraction, random_address.into()),
                network,
            )
            .await;
        assert_ne!(
            block_1a.header().guesser_receiver_data,
            block_1b.header().guesser_receiver_data,
            "Test assumption: Guesser receiver data is different"
        );

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
            assert!(block_1b
                .mutator_set_accumulator_after()
                .unwrap()
                .verify(item, &msmp));
            assert_eq!(block_1b.hash(), mutxo_sync_block_digest);
            assert_eq!(block_1b.hash(), mutxo.confirmed_in_block.unwrap().0);
        }
    }

    #[apply(shared_tokio_runtime)]
    #[traced_test]
    async fn never_store_same_utxo_twice_same_block() {
        let mut rng = rand::rng();
        let network = Network::Main;
        let bob_wallet_secret = WalletEntropy::new_random();
        let bob_key = bob_wallet_secret.nth_generation_spending_key_for_tests(0);

        let mut bob_global_lock = mock_genesis_global_state(
            0,
            bob_wallet_secret.clone(),
            cli_args::Args::default_with_network(network),
        )
        .await;
        let mut bob = bob_global_lock.lock_guard_mut().await;

        let genesis_block = Block::genesis(network);
        let (block1, composer_utxos) =
            make_mock_block(&genesis_block, None, bob_key, rng.random(), network).await;

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
                &genesis_block.mutator_set_accumulator_after().unwrap(),
                &block1,
                true,
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
        for wallet_maintains_mp in [false, true] {
            bob.wallet_state
                .update_wallet_state_with_new_block(
                    &genesis_block.mutator_set_accumulator_after().unwrap(),
                    &block1,
                    wallet_maintains_mp,
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
            let new_recovery_entry =
                &bob.wallet_state.read_utxo_ms_recovery_data().await.unwrap()[0];

            assert_eq!(
                original_mutxo, new_mutxo,
                "Adding same block twice may not mutate MUTXOs"
            );
            assert_eq!(original_recovery_entry, new_recovery_entry);

            if wallet_maintains_mp {
                assert!(wallet_state_has_all_valid_mps(&bob.wallet_state, &block1).await);
            }
        }
    }

    #[apply(shared_tokio_runtime)]
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
        let bob_wallet_secret = WalletEntropy::new_random();
        let bob_spending_key = bob_wallet_secret.nth_generation_spending_key_for_tests(0);
        let mut bob_global_lock = mock_genesis_global_state(
            0,
            bob_wallet_secret,
            cli_args::Args::default_with_network(network),
        )
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
        let alice_key = WalletEntropy::new_random().nth_generation_spending_key_for_tests(0);
        let mut latest_block = genesis_block;
        let maintain_mps = true;
        for _ in 1..=2 {
            let (new_block, _new_block_coinbase_utxo) =
                make_mock_block(&latest_block, None, alice_key, rng.random(), network).await;
            bob.wallet_state
                .update_wallet_state_with_new_block(
                    &latest_block.mutator_set_accumulator_after().unwrap(),
                    &new_block,
                    maintain_mps,
                )
                .await
                .unwrap();
            bob.chain
                .archival_state_mut()
                .write_block_as_tip(&new_block)
                .await
                .unwrap();
            *bob.chain.light_state_mut() = new_block.clone().into();

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
        let (block_3a, composer_expected_utxos_3a) = make_mock_block(
            &latest_block.clone(),
            None,
            bob_spending_key,
            rng.random(),
            network,
        )
        .await;
        bob.wallet_state
            .add_expected_utxos(composer_expected_utxos_3a)
            .await;
        bob.set_new_tip(block_3a).await.unwrap();

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
            make_mock_block(&latest_block, None, alice_key, rng.random(), network).await;
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
                make_mock_block(&latest_block, None, alice_key, rng.random(), network).await;
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
        let (block_12, _) =
            make_mock_block(&latest_block, None, alice_key, rng.random(), network).await;
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
    #[apply(shared_tokio_runtime)]
    async fn mock_wallet_state_is_synchronized_to_genesis_block() {
        let network = Network::RegTest;
        let wallet = WalletEntropy::devnet_wallet();
        let genesis_block = Block::genesis(network);

        let cli_args = cli_args::Args::default_with_network(network);
        let wallet_state = mock_genesis_wallet_state(wallet, &cli_args).await;

        // are we synchronized to the genesis block?
        assert_eq!(
            wallet_state.wallet_db.get_sync_label(),
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
                .unwrap()
                .verify(Tip5::hash(&utxo), &ms_membership_proof));
        }
    }

    mod guesser_fee_utxos {
        use futures::channel::oneshot;
        use guesser_fee_utxos::composer_parameters::ComposerParameters;
        use rand::rng;

        use super::*;
        use crate::application::config::fee_notification_policy::FeeNotificationPolicy;
        use crate::application::loops::channel::NewBlockFound;
        use crate::application::loops::mine_loop::composer_parameters;
        use crate::application::loops::mine_loop::guess_nonce;
        use crate::application::loops::mine_loop::GuessingConfiguration;
        use crate::protocol::consensus::transaction::TransactionProof;
        use crate::tests::shared::blocks::fake_valid_block_proposal_from_tx;
        use crate::tests::shared::blocks::fake_valid_block_proposal_successor_for_test;
        use crate::tests::shared::fake_create_block_transaction_for_tests;

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn registers_guesser_fee_utxos_correctly() {
            let network = Network::Main;
            let genesis_block = Block::genesis(network);
            let mut bob = mock_genesis_global_state(
                3,
                WalletEntropy::new_random(),
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
                network,
            )
            .await;

            let guesser_key = bob
                .lock_guard()
                .await
                .wallet_state
                .wallet_entropy
                .guesser_fee_key();

            // Mine it till it has a valid PoW digest
            // Add this block to the wallet through the same pipeline as the
            // mine_loop.
            let (guesser_tx, guesser_rx) = oneshot::channel::<NewBlockFound>();
            guess_nonce(
                network,
                block1_proposal,
                *genesis_block.header(),
                guesser_tx,
                GuessingConfiguration {
                    num_guesser_threads: Some(2),
                    address: guesser_key.to_address().into(),
                    override_rng: None,
                    override_timestamp: None,
                },
            )
            .await;

            let new_block_found = guesser_rx.await.unwrap();
            let guesser_expected_utxos = vec![];
            let block1 = new_block_found.block;

            {
                let bgs = bob.global_state_lock.lock_guard().await;
                let wallet_status = bgs
                    .wallet_state
                    .get_wallet_status(
                        block1.hash(),
                        &block1.mutator_set_accumulator_after().unwrap(),
                    )
                    .await;

                assert!(
                    !wallet_status
                        .available_confirmed(block1_timestamp)
                        .is_positive(),
                    "Must show zero-balance before adding block to state"
                );
            }
            bob.set_new_self_composed_tip(block1.as_ref().clone(), guesser_expected_utxos.clone())
                .await
                .unwrap();

            {
                let bgs = bob.global_state_lock.lock_guard().await;
                let wallet_status = bgs
                    .wallet_state
                    .get_wallet_status(
                        block1.hash(),
                        &block1.mutator_set_accumulator_after().unwrap(),
                    )
                    .await;

                assert!(
                    wallet_status
                        .available_confirmed(block1_timestamp)
                        .is_positive(),
                    "Must show positive balance after successful PoW-guess"
                );
            }

            // Verify expected qualities of wallet, that:
            // 1. expected UTXO contains guesser-fee UTXOs
            // 2. monitored UTXOs-list contains guesser-fee UTXOs.

            // 1.
            let eus = bob
                .global_state_lock
                .lock_guard()
                .await
                .wallet_state
                .wallet_db
                .expected_utxos()
                .get_all()
                .await;
            assert_eq!(
                guesser_expected_utxos.len(),
                eus.len(),
                "Must expect {} guesser-fee UTXOs",
                guesser_expected_utxos.len()
            );
            assert_eq!(
                guesser_expected_utxos.len(),
                eus.iter().map(|x| x.addition_record).unique().count(),
                "Addition records from expected UTXOs must be unique"
            );
            let ars_from_block = block1.guesser_fee_addition_records().unwrap();
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

            // 2.
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
            let config = TxCreationConfig::default()
                .recover_change_on_chain(a_key.into())
                .with_prover_capability(TxProvingCapability::PrimitiveWitness);
            let consensus_rule_set = ConsensusRuleSet::infer_from(network, block1.header().height);
            let mut tx_spending_guesser_fee: Transaction = bob
                .api()
                .tx_initiator_internal()
                .create_transaction(
                    Vec::<TxOutput>::new().into(),
                    fee,
                    block2_timestamp,
                    config,
                    consensus_rule_set,
                )
                .await
                .unwrap()
                .transaction
                .into();
            assert!(
                tx_spending_guesser_fee
                    .is_valid(network, consensus_rule_set)
                    .await,
                "Tx spending guesser-fee UTXO must be valid."
            );

            // Give tx a fake single proof to allow inclusion in block, through
            // below test function.
            tx_spending_guesser_fee.proof = TransactionProof::invalid();

            let coinbase_distribution = CoinbaseDistribution::solo(a_key.to_address().into());
            let composer_parameters = ComposerParameters::new(
                coinbase_distribution,
                rng.random(),
                Some(a_key.receiver_preimage()),
                0.5f64,
                FeeNotificationPolicy::OffChain,
            );
            let (block2_tx, _) = fake_create_block_transaction_for_tests(
                &block1,
                composer_parameters,
                block2_timestamp,
                rng.random(),
                vec![tx_spending_guesser_fee],
                network,
            )
            .await
            .unwrap();
            let block2 = fake_valid_block_proposal_from_tx(&block1, block2_tx, network).await;
            assert!(block2.is_valid(&block1, block2_timestamp, network).await);

            bob.set_new_self_composed_tip(block2.clone(), vec![])
                .await
                .unwrap();
            {
                let bgs = bob.global_state_lock.lock_guard().await;
                let wallet_status = bgs
                    .wallet_state
                    .get_wallet_status(
                        block2.hash(),
                        &block2.mutator_set_accumulator_after().unwrap(),
                    )
                    .await;

                assert!(
                    !wallet_status
                        .available_confirmed(block2_timestamp)
                        .is_positive(),
                    "Must show zero liquid balance after spending liquid guesser UTXO"
                );
            }
        }

        #[apply(shared_tokio_runtime)]
        async fn guesser_fee_scanner_finds_guesser_fee_iff_present() {
            let network = Network::Main;
            let mut rng = rng();
            let cli_args = cli_args::Args::default_with_network(network);
            let wallet_state =
                mock_genesis_wallet_state(WalletEntropy::new_random(), &cli_args).await;
            let composer_key = wallet_state.wallet_entropy.nth_generation_spending_key(0);
            let genesis_block = Block::genesis(network);
            let (mut incoming_block, _) =
                make_mock_block(&genesis_block, None, composer_key, rng.random(), network).await;

            // other guesser -> no detection
            let rando = GenerationReceivingAddress::derive_from_seed(rng.random());
            incoming_block.set_header_guesser_address(rando.into());
            assert_eq!(
                0,
                wallet_state
                    .scan_for_guesser_fee_utxos(&incoming_block)
                    .count()
            );

            // our lucky guess -> guesser fees detected
            let own = wallet_state.wallet_entropy.guesser_fee_key().to_address();
            incoming_block.set_header_guesser_address(own.into());
            assert_eq!(
                2,
                wallet_state
                    .scan_for_guesser_fee_utxos(&incoming_block)
                    .count()
            );
        }
    }

    mod wallet_balance {
        use generation_address::GenerationReceivingAddress;
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        use super::*;
        use crate::application::config::cli_args;
        use crate::protocol::consensus::block::block_height::BlockHeight;
        use crate::state::mempool::upgrade_priority::UpgradePriority;
        use crate::state::transaction::tx_proving_capability::TxProvingCapability;
        use crate::state::wallet::address::ReceivingAddress;
        use crate::state::wallet::utxo_notification::UtxoNotificationMedium;
        use crate::tests::shared::blocks::mine_block_to_wallet_invalid_block_proof;

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
        #[apply(shared_tokio_runtime)]
        async fn confirmed_and_unconfirmed_balance() -> Result<()> {
            let network = Network::Main;
            let mut rng = StdRng::seed_from_u64(664505904);
            let mut global_state_lock = mock_genesis_global_state(
                0,
                WalletEntropy::new_pseudorandom(rng.random()),
                cli_args::Args::default_with_network(network),
            )
            .await;
            let change_key = global_state_lock
                .lock_guard_mut()
                .await
                .wallet_state
                .next_unused_spending_key(KeyType::Generation)
                .await;

            let coinbase_amt = Block::block_subsidy(BlockHeight::genesis().next());
            let mut half_coinbase_amt = coinbase_amt;
            half_coinbase_amt.div_two();
            let send_amt = NativeCurrencyAmount::coins(5);

            let genesis_block = Block::genesis(network);
            let timestamp = genesis_block.header().timestamp + Timestamp::hours(1);

            // mine a block to our wallet.  we should have 100 coins after.
            let tip_digest =
                mine_block_to_wallet_invalid_block_proof(&mut global_state_lock, Some(timestamp))
                    .await?
                    .hash();

            let tx = {
                // verify that confirmed and unconfirmed balances.
                let gs = global_state_lock.lock_guard().await;
                let msa = gs
                    .chain
                    .light_state()
                    .mutator_set_accumulator_after()
                    .unwrap();
                let wallet_status = gs.wallet_state.get_wallet_status(tip_digest, &msa).await;

                assert_eq!(
                    wallet_status.available_confirmed(timestamp),
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
                    UtxoNotificationMedium::OnChain,
                )];
                drop(gs);

                let tx_outputs = global_state_lock
                    .api()
                    .tx_initiator()
                    .generate_tx_outputs(outputs)
                    .await;

                let config = TxCreationConfig::default()
                    .recover_change_on_chain(change_key)
                    .with_prover_capability(TxProvingCapability::PrimitiveWitness);
                let consensus_rule_set =
                    ConsensusRuleSet::infer_from(network, BlockHeight::genesis().next());
                global_state_lock
                    .api()
                    .tx_initiator_internal()
                    .create_transaction(
                        tx_outputs,
                        NativeCurrencyAmount::zero(),
                        timestamp,
                        config,
                        consensus_rule_set,
                    )
                    .await?
                    .transaction
            };

            // add the tx to the mempool.
            // note that the wallet should be notified of these changes.
            global_state_lock
                .lock_guard_mut()
                .await
                .mempool_insert((*tx).clone(), UpgradePriority::Critical)
                .await;

            {
                let gs = global_state_lock.lock_guard().await;
                let msa = gs
                    .chain
                    .light_state()
                    .mutator_set_accumulator_after()
                    .unwrap();
                let wallet_status = gs.wallet_state.get_wallet_status(tip_digest, &msa).await;

                assert_eq!(
                    wallet_status.available_confirmed(timestamp),
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
                    .lock(|gs| {
                        gs.chain
                            .light_state()
                            .mutator_set_accumulator_after()
                            .unwrap()
                    })
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
        #[apply(shared_tokio_runtime)]
        async fn do_not_attempt_to_spend_utxos_already_spent_in_mempool_txs() {
            let network = Network::Main;
            let mut rng = rand::rng();
            let alice_wallet = WalletEntropy::new_pseudorandom(rng.random());
            let mut alice = mock_genesis_global_state(
                0,
                alice_wallet.clone(),
                cli_args::Args::default_with_network(network),
            )
            .await;

            let genesis = Block::genesis(network);
            let guesser_address = alice_wallet.guesser_fee_key().to_address();
            let change_key = alice_wallet.nth_generation_spending_key(0).into();
            let guesser_fraction = 0.5f64;

            // Alice mines a block
            let (block, composer_expected_utxos) =
                make_mock_block_with_puts_and_guesser_preimage_and_guesser_fraction(
                    &genesis,
                    vec![],
                    vec![],
                    None,
                    alice_wallet.nth_generation_spending_key(0),
                    rng.random(),
                    (guesser_fraction, guesser_address.into()),
                    network,
                )
                .await;

            // Alice gets all mining rewards
            alice
                .set_new_self_composed_tip(block.clone(), composer_expected_utxos)
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
                .get_wallet_status(
                    block.hash(),
                    &block.mutator_set_accumulator_after().unwrap(),
                )
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
            let send_amt1 = NativeCurrencyAmount::coins(1);
            let tx1 = outgoing_transaction(
                &mut alice,
                send_amt1,
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
                .mempool_insert((*tx1).clone(), UpgradePriority::Critical)
                .await;

            // generate a second transaction
            let send_amt2 = NativeCurrencyAmount::coins(1);
            let tx2 = outgoing_transaction(
                &mut alice,
                send_amt2,
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
                .mempool_insert((*tx2).clone(), UpgradePriority::Critical)
                .await;

            // verify that the mempool contains two transactions
            // ==> did not kick anything out
            assert_eq!(2, alice.lock_guard().await.mempool.len());

            // Verify that one more transaction *cannot* be made, as all the
            // monitored UTXOs now have a transaction that spends them in the
            // mempool.
            assert!(
                outgoing_transaction(
                    &mut alice,
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
        #[apply(shared_tokio_runtime)]
        async fn known_keys_are_unique() {
            for key_type in KeyType::all_types() {
                worker::known_keys_are_unique(key_type).await
            }
        }

        /// tests that spending key counter persists across restart for all key types.
        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn derivation_counter_persists_across_restart() -> Result<()> {
            for key_type in KeyType::all_types() {
                worker::derivation_counter_persists_across_restart(key_type).await?
            }
            Ok(())
        }

        mod worker {
            use super::*;
            use crate::application::database::storage::storage_schema::traits::StorageWriter;
            use crate::tests::shared::files::unit_test_data_directory;

            /// tests that all known keys are unique for a given key-type
            ///
            /// 1. Generate a mock WalletState
            /// 2. Request 20 spending keys
            /// 3. Verify there are 20 known keys
            /// 4. Verify all keys are unique.
            pub(super) async fn known_keys_are_unique(key_type: KeyType) {
                info!("key_type: {}", key_type);

                // 1. Generate a mock WalletState
                let network = Network::RegTest;
                let cli_args = cli_args::Args::default_with_network(network);
                let mut wallet =
                    mock_genesis_wallet_state(WalletEntropy::new_random(), &cli_args).await;

                let num_known_keys = wallet.get_known_addressable_spending_keys(key_type).count();
                let num_to_derive = 20;

                // 2. Request 20 spending keys
                for _ in 0..num_to_derive {
                    let _ = wallet.next_unused_spending_key(key_type).await;
                }
                let expected_num_known_keys = num_known_keys + num_to_derive;
                let known_keys = wallet
                    .get_known_addressable_spending_keys(key_type)
                    .collect_vec();

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
                let wallet_secret = WalletEntropy::new_random();
                let data_dir = unit_test_data_directory(network)?;

                // 1. create new wallet and generate 20 keys
                // 2. record wallet counter and known-keys
                // 3. persist wallet.
                // 4. forget wallet (dropped)
                let cli_args = cli_args::Args::default_with_network(network);
                let (orig_counter, orig_known_keys) = {
                    let mut wallet = WalletState::new_from_wallet_entropy(
                        &data_dir,
                        wallet_secret.clone(),
                        &cli_args,
                    )
                    .await;

                    for _ in 0..20 {
                        let _ = wallet.next_unused_spending_key(key_type).await;
                    }

                    wallet.wallet_db.persist().await;

                    (
                        wallet.spending_key_counter(key_type),
                        wallet
                            .get_known_addressable_spending_keys(key_type)
                            .collect_vec(),
                    )
                };

                // 5. instantiate 2nd wallet instance with same data_dir and secret as the first
                let wallet =
                    WalletState::new_from_wallet_entropy(&data_dir, wallet_secret, &cli_args).await;

                let persisted_counter = wallet.spending_key_counter(key_type);
                let persisted_known_keys = wallet
                    .get_known_addressable_spending_keys(key_type)
                    .collect_vec();

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
        use crate::application::loops::mine_loop::coinbase_distribution::CoinbaseOutput;
        use crate::protocol::consensus::transaction::lock_script::LockScript;
        use crate::tests::shared::mock_tx::make_mock_transaction;

        #[apply(shared_tokio_runtime)]
        async fn no_expected_utxos_on_custom_coinbase_distribution_and_offchain_notifications() {
            let network = Network::Main;
            let wallet = WalletEntropy::devnet_wallet();
            let mut cli_args = cli_args::Args::default_with_network(network);
            cli_args.fee_notification = FeeNotificationPolicy::OffChain;

            let wallet_state = mock_genesis_wallet_state(wallet, &cli_args).await;
            let an_address = GenerationReceivingAddress::derive_from_seed(Default::default());
            let coinbase_distribution = vec![
                CoinbaseOutput::liquid(an_address.into(), 400),
                CoinbaseOutput::timelocked(an_address.into(), 550),
                CoinbaseOutput::liquid(an_address.into(), 50),
            ];
            let coinbase_distribution =
                CoinbaseDistribution::try_new(coinbase_distribution).unwrap();

            for cb_distribution in [None, Some(coinbase_distribution)] {
                let composer_parameters = wallet_state.composer_parameters(
                    1u64.into(),
                    cli_args.guesser_fraction,
                    cli_args.fee_notification,
                    cb_distribution.clone(),
                );

                let coinbase = NativeCurrencyAmount::coins(40);
                let composer_outputs = composer_parameters.tx_outputs(coinbase, Timestamp::now());
                let expected_num_outputs = if cb_distribution.is_some() { 3 } else { 2 };
                assert_eq!(expected_num_outputs, composer_outputs.len(),);

                let expected_num_own_outputs = if cb_distribution.is_some() { 0 } else { 2 };
                assert_eq!(
                    expected_num_own_outputs,
                    composer_parameters
                        .extract_expected_utxos(composer_outputs)
                        .len(),
                );
            }
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn insert_and_scan() {
            let network = Network::RegTest;
            let cli_args = cli_args::Args::default_with_network(network);
            let mut wallet =
                mock_genesis_wallet_state(WalletEntropy::new_random(), &cli_args).await;

            assert!(wallet.wallet_db.expected_utxos().is_empty().await);
            assert!(wallet.wallet_db.expected_utxos().len().await.is_zero());

            let mock_utxo = Utxo::new_native_currency(
                LockScript::anyone_can_spend().hash(),
                NativeCurrencyAmount::coins(10),
            );

            let sender_randomness: Digest = rand::random();
            let receiver_preimage: Digest = rand::random();
            let mock_triple = UtxoTriple {
                utxo: mock_utxo.clone(),
                sender_randomness,
                receiver_digest: receiver_preimage.hash(),
            };
            let expected_addition_record = mock_triple.addition_record();
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
            let bad_triple = UtxoTriple {
                utxo: mock_utxo.clone(),
                sender_randomness: rand::random(),
                receiver_digest: receiver_preimage.hash(),
            };
            let another_addition_record = bad_triple.addition_record();
            let tx_without_utxo = make_mock_transaction(vec![], vec![another_addition_record]);
            let ret_with_tx_without_utxo = wallet
                .scan_for_expected_utxos(&tx_without_utxo.kernel.outputs)
                .await
                .collect_vec();
            assert!(ret_with_tx_without_utxo.is_empty());
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn prune_stale() {
            let network = Network::RegTest;
            let cli_args = cli_args::Args::default_with_network(network);
            let mut wallet =
                mock_genesis_wallet_state(WalletEntropy::new_random(), &cli_args).await;

            let mock_utxo = Utxo::new_native_currency(
                LockScript::anyone_can_spend().hash(),
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
        #[apply(shared_tokio_runtime)]
        async fn persisted_exists_after_wallet_restored() {
            worker::restore_wallet(true).await
        }

        /// demonstrates/tests that if wallet-db is not persisted after an
        /// ExpectedUtxo is added, then the ExpectedUtxo will not exist after
        /// wallet is dropped from RAM and re-created from disk.
        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn unpersisted_gone_after_wallet_restored() {
            worker::restore_wallet(false).await
        }

        mod worker {
            use super::*;
            use crate::application::database::storage::storage_schema::traits::StorageWriter;
            use crate::tests::shared::files::unit_test_data_directory;

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
                let wallet_secret = WalletEntropy::new_random();
                let data_dir = unit_test_data_directory(network).unwrap();
                let cli_args = cli_args::Args::default();

                // create initial wallet in a new directory
                let mut wallet = WalletState::new_from_wallet_entropy(
                    &data_dir,
                    wallet_secret.clone(),
                    &cli_args,
                )
                .await;

                let mock_utxo = Utxo::new_native_currency(
                    LockScript::anyone_can_spend().hash(),
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
                    WalletState::new_from_wallet_entropy(&data_dir, wallet_secret, &cli_args).await;

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
        use crate::tests::shared::blocks::invalid_empty_block;

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn mutxos_spent_in_orphaned_blocks_are_still_spendable() {
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
            let alice_wallet = WalletEntropy::devnet_wallet();
            let mut alice_global_lock = mock_genesis_global_state(
                0,
                alice_wallet.clone(),
                cli_args::Args::default_with_network(network),
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
                    .get_wallet_status(
                        genesis.hash(),
                        &genesis.mutator_set_accumulator_after().unwrap()
                    )
                    .await
                    .total_confirmed(),
                "Alice assumed to be premine recipient"
            );

            // Create a transaction that spends all of Alice's balance.
            let timestamp = network.launch_date() + Timestamp::months(14);
            let change_key = alice_wallet.nth_symmetric_key(0).into();
            let spending_tx_1a = outgoing_transaction(
                &mut alice_global_lock,
                NativeCurrencyAmount::coins(19),
                NativeCurrencyAmount::coins(1),
                timestamp,
                change_key,
            )
            .await
            .unwrap();

            let block_1a = invalid_block_with_transaction(&genesis, spending_tx_1a.into());
            let block_1b = invalid_empty_block(&genesis, network);
            let block_2b = invalid_empty_block(&block_1b, network);
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
                .get_wallet_status(
                    block_1a.hash(),
                    &block_1a.mutator_set_accumulator_after().unwrap(),
                )
                .await;
            assert!(wallet_status_1a.total_confirmed().is_zero());

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
                .get_wallet_status(
                    block_2b.hash(),
                    &block_2b.mutator_set_accumulator_after().unwrap(),
                )
                .await;
            assert_eq!(
                init_balance,
                wallet_status_2b.total_confirmed(),
                "Initial balance must be restored when spending-tx was reorganized away."
            );

            // Verify that MUTXOs can be used to create a similar transaction to the one
            // that was reorganized away.
            let _ = outgoing_transaction(
                &mut alice_global_lock,
                NativeCurrencyAmount::coins(19),
                NativeCurrencyAmount::coins(1),
                timestamp,
                change_key,
            )
            .await;

            // Go back to a-chain and verify that MUTXOs are considered spent again.
            let block_2a = invalid_empty_block(&block_1a, network);
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
                .get_wallet_status(
                    block_2a.hash(),
                    &block_2a.mutator_set_accumulator_after().unwrap()
                )
                .await
                .total_confirmed()
                .is_zero());
        }

        #[apply(shared_tokio_runtime)]
        async fn abandoned_utxo_is_unsynced() {
            // 1. create a genesis state for Alice
            // 2. create block_1a where Alice gets a guesser-fee UTXO, set as tip
            // 3. Verify expected balance
            // 4. Verify no abandoned/unsynced MUTXOs
            // 5. create block_1b where Alice doesn't get anything, set as tip
            // 6. Verify presence of abandoned/unsynced MUTXOs.
            let network = Network::Main;
            let mut rng = rand::rng();
            let alice_wallet = WalletEntropy::new_pseudorandom(rng.random());
            let mut alice_global_lock = mock_genesis_global_state(
                0,
                alice_wallet.clone(),
                cli_args::Args::default_with_network(network),
            )
            .await;
            let genesis = Block::genesis(network);
            let guesser_address = alice_wallet.guesser_fee_key().to_address();

            let guesser_fraction = 0.6f64;
            let (block_1a, composer_expected_utxos_1a) =
                make_mock_block_with_puts_and_guesser_preimage_and_guesser_fraction(
                    &genesis,
                    vec![],
                    vec![],
                    None,
                    alice_wallet.nth_generation_spending_key(14),
                    rng.random(),
                    (guesser_fraction, guesser_address.into()),
                    network,
                )
                .await;

            alice_global_lock
                .set_new_self_composed_tip(block_1a.clone(), composer_expected_utxos_1a)
                .await
                .unwrap();
            let wallet_status_1a = alice_global_lock
                .global_state_lock
                .lock_guard()
                .await
                .wallet_state
                .get_wallet_status(
                    block_1a.hash(),
                    &block_1a.mutator_set_accumulator_after().unwrap(),
                )
                .await;
            assert_eq!(
                Block::block_subsidy(1u64.into()),
                wallet_status_1a.total_confirmed(),
            );

            assert!(wallet_status_1a.unsynced.is_empty());

            // Set tip to competing block with no reward for Alice.
            let block_1b = invalid_empty_block(&genesis, network);
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
                .get_wallet_status(
                    block_1b.hash(),
                    &block_1b.mutator_set_accumulator_after().unwrap(),
                )
                .await;
            assert!(wallet_status_1b.total_confirmed().is_zero());
            assert!(!wallet_status_1b.unsynced.is_empty());
        }
    }

    pub(crate) mod scan_mode {
        use std::hint::black_box;

        use proptest::collection;
        use proptest::prelude::any;
        use proptest_arbitrary_interop::arb;

        use super::*;
        use crate::application::config::fee_notification_policy::FeeNotificationPolicy;
        use crate::application::loops::mine_loop::make_coinbase_transaction_stateless;
        use crate::protocol::consensus::block::block_height::BlockHeight;
        use crate::state::wallet::utxo_notification::UtxoNotificationPayload;
        use crate::tests::shared::files::unit_test_data_directory;
        use crate::tests::shared::strategies::txkernel;

        const NUM_FUTURE_KEYS: usize = 20;

        /// Test scan mode.
        ///
        /// In rough terms, this test verifies that importing a wallet followed
        /// by booting the node in scan mode will recover UTXOs sent to it.
        ///
        /// Specifically:
        ///  - Alice is recipient of a transaction in block 1, but the address
        ///    for this transaction uses derivation index 20, which is in the
        ///    future.
        ///  - If Alice does nothing special, she does not catch the UTXO.
        ///  - If Alice activates scan mode with the right parameters, she does
        ///    catch the UTXO.
        ///  - In the last case, her derivation counter and keys are updated accordingly.
        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn test_recovery_on_imported_wallet() {
            let network = Network::Main;
            let alice_secret = WalletEntropy::new_random();
            let data_dir = unit_test_data_directory(network).unwrap();

            // generate events
            let genesis_block = Block::genesis(network);
            let premine_receiver = mock_genesis_global_state(
                0,
                WalletEntropy::devnet_wallet(),
                cli_args::Args::default_with_network(network),
            )
            .await;
            let premine_change_key = premine_receiver
                .lock_guard()
                .await
                .wallet_state
                .nth_spending_key(KeyType::Symmetric, 0);
            let now =
                genesis_block.header().timestamp + Timestamp::months(6) + Timestamp::minutes(5);
            let sender_randomness = rng().random();
            let alice_future_spending_key = alice_secret.nth_generation_spending_key(20);
            let tx_output = TxOutput::onchain_native_currency(
                NativeCurrencyAmount::coins(1),
                sender_randomness,
                alice_future_spending_key.to_address().into(),
                false,
            );
            let config = TxCreationConfig::default()
                .recover_change_off_chain(premine_change_key)
                .with_prover_capability(TxProvingCapability::PrimitiveWitness);
            let consensus_rule_set = ConsensusRuleSet::infer_from(network, BlockHeight::genesis());
            let transaction = premine_receiver
                .api()
                .tx_initiator_internal()
                .create_transaction(
                    vec![tx_output].into(),
                    NativeCurrencyAmount::coins(0),
                    now,
                    config,
                    consensus_rule_set,
                )
                .await
                .unwrap()
                .transaction;
            let block_1 = invalid_block_with_transaction(&genesis_block, transaction.into());

            // some possible CLI configurations:
            // scan mode is inactive
            let cli_default = cli_args::Args::default();
            // scan mode is active but looking in the wrong blocks
            let cli_wrong_range = cli_args::Args {
                scan_blocks: Some(10..=100),
                ..Default::default()
            };
            // scan mode is active but scanning for too few keys
            let cli_too_few_keys = cli_args::Args {
                scan_keys: Some(5),
                ..Default::default()
            };
            // scan mode is active and scanning for the right keys in the right
            // blocks
            let cli_well_configured = cli_args::Args {
                scan_blocks: Some(0..=u64::MAX),
                scan_keys: Some(25),
                ..Default::default()
            };

            for (cli_args, should_catch_utxo) in [
                (cli_default, false),
                (cli_wrong_range, false),
                (cli_too_few_keys, false),
                (cli_well_configured, true),
            ] {
                let mut alice_wallet_state = WalletState::new_from_wallet_entropy(
                    &data_dir,
                    alice_secret.clone(),
                    &cli_args,
                )
                .await;

                let wallet_status_ = alice_wallet_state
                    .get_wallet_status(
                        block_1.hash(),
                        &block_1.mutator_set_accumulator_after().unwrap(),
                    )
                    .await;
                let balance_ = wallet_status_.available_confirmed(now);
                assert_eq!(NativeCurrencyAmount::coins(0), balance_);

                let maintain_mps = true;
                alice_wallet_state
                    .update_wallet_state_with_new_block(
                        &genesis_block.mutator_set_accumulator_after().unwrap(),
                        &block_1,
                        maintain_mps,
                    )
                    .await
                    .unwrap();

                let wallet_status = alice_wallet_state
                    .get_wallet_status(
                        block_1.hash(),
                        &block_1.mutator_set_accumulator_after().unwrap(),
                    )
                    .await;
                let balance = wallet_status.available_confirmed(now);
                if should_catch_utxo {
                    assert_eq!(NativeCurrencyAmount::coins(1), balance);
                    assert_eq!(
                        21,
                        alice_wallet_state.wallet_db.get_generation_key_counter()
                    );
                    assert_eq!(
                        21,
                        alice_wallet_state
                            .get_known_generation_spending_keys()
                            .count()
                    );
                } else {
                    assert_eq!(NativeCurrencyAmount::coins(0), balance);
                    assert_eq!(1, alice_wallet_state.wallet_db.get_generation_key_counter());
                    assert_eq!(
                        1,
                        alice_wallet_state
                            .get_known_generation_spending_keys()
                            .count()
                    );
                }
            }
        }

        #[apply(shared_tokio_runtime)]
        async fn get_future_keys_do_not_modify_counters() {
            let network = Network::Main;
            let mut rng = StdRng::from_rng(&mut rng());
            let wallet_secret = WalletEntropy::new_pseudorandom(rng.random());
            let data_dir = unit_test_data_directory(network).unwrap();
            let wallet_state = WalletState::new_from_wallet_entropy(
                &data_dir,
                wallet_secret,
                &cli_args::Args::default(),
            )
            .await;

            // generate iterators for future keys
            let generation_counter = wallet_state.wallet_db.get_generation_key_counter();
            let symmetric_counter = wallet_state.wallet_db.get_symmetric_key_counter();

            // don't just generate the iterators; run through them also
            let num_future_keys = 100;
            let future_generation_keys = wallet_state
                .get_future_generation_spending_keys(num_future_keys)
                .collect_vec();
            let future_symmetric_keys = wallet_state
                .get_future_symmetric_keys(num_future_keys)
                .collect_vec();

            // verify that the counters haven't changed
            assert_eq!(
                generation_counter,
                wallet_state.wallet_db.get_generation_key_counter(),
            );
            assert_eq!(
                symmetric_counter,
                wallet_state.wallet_db.get_symmetric_key_counter(),
            );

            // make sure passing over the iterators is not being optimized away
            black_box(future_generation_keys);
            black_box(future_symmetric_keys);
        }

        /// Test that the method
        /// [`WalletState::scan_for_utxos_announced_to_future_keys`] behaves as
        /// exepected.
        ///
        /// Specifically:
        ///  - Generate a random transaction kernel.
        ///  - Generate future generation and symmetric keys, with random
        ///    offsets.
        ///  - Generate UTXOs with all necessary supplementary information, one
        ///    for each key.
        ///  - Generate announcements for all UTXOs and put them into the
        ///    transaction kernel.
        ///  - For a subset of UTXOs, put the corresponding addition record into
        ///    the transaction kernel.
        ///  - Scan!
        ///  - Verify that the UTXOs coming back from scanning matches with the
        ///    master list of UTXOs filtered for:
        ///     a) the addition record was selected for placement into the
        ///        kernel;
        ///     b) the relative index is smaller than num_future_keys.
        ///
        #[traced_test]
        #[test_strategy::proptest(async = "tokio")]
        async fn scan_for_utxos_announced_to_future_keys_behaves(
            #[strategy(txkernel::with_lengths(10, 10, 10, false))] kernel: TransactionKernel,
            #[strategy(arb())] wallet_secret: WalletEntropy,
            #[strategy(collection::vec(
                0_usize..100,
                NUM_FUTURE_KEYS,
            ))]
            mut future_generation_relative_indices: Vec<usize>,
            #[strategy(collection::vec(
                0_usize..100,
                NUM_FUTURE_KEYS,
            ))]
            mut future_symmetric_relative_indices: Vec<usize>,
            #[strategy(collection::vec(arb(), 2 * NUM_FUTURE_KEYS))] mut utxo_vec: Vec<Utxo>,
            #[strategy(collection::vec(arb(), 2 * NUM_FUTURE_KEYS))] mut sender_randomness_vec: Vec<
                Digest,
            >,
            #[strategy(collection::vec(any::<bool>(), 2 * NUM_FUTURE_KEYS))] mut select_vec: Vec<
                bool,
            >,
        ) {
            let network = Network::Main;
            let data_dir = unit_test_data_directory(network).unwrap();
            let wallet_state = WalletState::new_from_wallet_entropy(
                &data_dir,
                wallet_secret.clone(),
                &cli_args::Args::default(),
            )
            .await;
            println!("(ignore all log messages above 😆)");

            let generation_counter = wallet_state.wallet_db.get_generation_key_counter();
            let symmetric_counter = wallet_state.wallet_db.get_symmetric_key_counter();

            future_generation_relative_indices.sort();
            let future_generation_keys = future_generation_relative_indices
                .into_iter()
                .map(|relative_index| (relative_index, generation_counter + relative_index as u64))
                .map(|(relative_index, absolute_index)| {
                    (
                        KeyType::Generation,
                        relative_index,
                        absolute_index,
                        SpendingKey::from(
                            wallet_secret.nth_generation_spending_key(absolute_index),
                        ),
                    )
                })
                .collect_vec();
            future_symmetric_relative_indices.sort();
            let future_symmetric_keys = future_symmetric_relative_indices
                .into_iter()
                .map(|relative_index| (relative_index, symmetric_counter + relative_index as u64))
                .map(|(relative_index, absolute_index)| {
                    (
                        KeyType::Symmetric,
                        relative_index,
                        absolute_index,
                        SpendingKey::from(wallet_secret.nth_symmetric_key(absolute_index)),
                    )
                })
                .collect_vec();

            // create master list of UTXOs with context
            struct UtxoContext {
                select: bool,
                key_type: KeyType,
                relative_index: usize,
                absolute_index: u64,
                incoming_utxo: IncomingUtxo,
            }
            let mut announcements = kernel.announcements.clone();
            let mut addition_records = kernel.outputs.clone();
            let mut all_utxos = vec![];
            for (key_type, relative_index, absolute_index, key) in future_generation_keys
                .into_iter()
                .chain(future_symmetric_keys)
            {
                let utxo = utxo_vec.pop().unwrap();
                let sender_randomness = sender_randomness_vec.pop().unwrap();

                let receiver_preimage = key.privacy_preimage();
                let utxo_notification_payload =
                    UtxoNotificationPayload::new(utxo.clone(), sender_randomness);
                let announcement = key
                    .to_address()
                    .generate_announcement(utxo_notification_payload);
                announcements.push(announcement);

                let incoming_utxo = IncomingUtxo {
                    utxo,
                    sender_randomness,
                    receiver_preimage,
                    is_guesser_fee: false,
                };

                let addition_record = incoming_utxo.addition_record();
                let select = select_vec.pop().unwrap();
                if select {
                    addition_records.push(addition_record);
                }

                let utxo_context = UtxoContext {
                    select,
                    key_type,
                    relative_index,
                    absolute_index,
                    incoming_utxo,
                };

                all_utxos.push(utxo_context);
            }

            let new_kernel = TransactionKernelModifier::default()
                .announcements(announcements)
                .outputs(addition_records)
                .modify(kernel);

            // scan
            let caught_utxos = wallet_state
                .scan_for_utxos_announced_to_future_keys(NUM_FUTURE_KEYS, &new_kernel)
                .collect_vec();

            // filter master list according to expectation
            let mut filtered_utxos = vec![];
            for uc in all_utxos {
                if !uc.select {
                    println!("rejecting UTXO because not selected");
                    continue;
                }

                let index_in_range = uc.relative_index < NUM_FUTURE_KEYS;
                if !index_in_range {
                    println!(
                        "rejecting UTXO because index {} >= {}",
                        uc.relative_index, NUM_FUTURE_KEYS
                    );
                    continue;
                }
                let filtered_utxo = (uc.key_type, uc.absolute_index, uc.incoming_utxo);
                filtered_utxos.push(filtered_utxo);
            }

            println!("filtered utxos has {} elements", filtered_utxos.len());

            assert_eq!(filtered_utxos, caught_utxos);
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn scan_mode_recovers_unexpected_offchain_composer_utxos() {
            // Set up Rando with scan mode active
            let network = Network::Main;
            let seed: [u8; 32] = random();
            let cli_args = cli_args::Args {
                fee_notification: FeeNotificationPolicy::OffChain,
                scan_blocks: Some(0..=10),
                compose: true,
                network,
                ..Default::default()
            };
            dbg!(seed);
            let mut rng = StdRng::from_seed(seed);
            let wallet_secret = WalletEntropy::new_pseudorandom(rng.random());
            let mut rando = mock_genesis_global_state(2, wallet_secret.clone(), cli_args).await;

            println!("(ignore all log messages above this line)");

            // Mine block
            // Send composer UTXO notifications off-chain
            let genesis_block = Block::genesis(network);
            let previous_block = genesis_block.clone();
            let now = network.launch_date() + Timestamp::minutes(10);

            let composer_parameters = rando
                .lock_guard()
                .await
                .composer_parameters(BlockHeight::genesis().next());
            let (transaction, _composer_txos) = make_coinbase_transaction_stateless(
                &previous_block,
                composer_parameters.clone(),
                now,
                TritonVmJobQueue::get_instance(),
                rando.cli().proof_job_options_primitive_witness(),
            )
            .await
            .unwrap();

            let new_block = invalid_block_with_transaction(&previous_block, transaction);
            assert!(
                new_block.body().transaction_kernel.announcements.is_empty(),
                "Test assumption: composer reward not announced."
            );
            assert!(
                rando
                    .lock_guard_mut()
                    .await
                    .wallet_state
                    .num_expected_utxos()
                    .await
                    .is_zero(),
                "Test assumption: wallet has no expected UTXOs"
            );

            // Forget about expecting the composer UTXOs

            // Update wallet state with new block (ignoring expected UTXOs)
            // Be saved by scan mode
            let maintain_mps = true;
            rando
                .lock_guard_mut()
                .await
                .wallet_state
                .update_wallet_state_with_new_block(
                    &previous_block.mutator_set_accumulator_after().unwrap(),
                    &new_block,
                    maintain_mps,
                )
                .await
                .unwrap();

            // Lo! composer utxos
            let wallet_status = rando
                .lock_guard()
                .await
                .wallet_state
                .get_wallet_status(
                    new_block.hash(),
                    &new_block.mutator_set_accumulator_after().unwrap(),
                )
                .await;
            println!(
                "wallet status -- # synced unspent: {}",
                wallet_status.synced_unspent.len()
            );
            println!(
                "wallet status -- # synced spent: {}",
                wallet_status.synced_spent.len()
            );
            println!(
                "wallet status -- # unsynced: {}",
                wallet_status.unsynced.len()
            );
            assert_eq!(2, wallet_status.synced_unspent.len());
        }
    }

    pub(crate) mod fee_notifications {

        use super::*;
        use crate::application::config::fee_notification_policy::FeeNotificationPolicy;
        use crate::application::loops::main_loop::proof_upgrader::ProofCollectionToSingleProof;
        use crate::application::loops::main_loop::proof_upgrader::UpdateMutatorSetDataJob;
        use crate::application::loops::main_loop::proof_upgrader::UpgradeJob;
        use crate::application::loops::main_loop::upgrade_incentive::UpgradeIncentive;
        use crate::application::loops::mine_loop::create_block_transaction;
        use crate::application::loops::mine_loop::make_coinbase_transaction_stateless;
        use crate::protocol::consensus::block::block_height::BlockHeight;
        use crate::protocol::consensus::block::block_transaction::BlockTransaction;
        use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
        use crate::MainToPeerTask;
        use crate::PEER_CHANNEL_CAPACITY;

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn wallet_recovers_unexpected_onchain_symmetric_composer_utxos() {
            wallet_recovers_composer_utxos(FeeNotificationPolicy::OnChainSymmetric).await
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn wallet_recovers_unexpected_onchain_generation_composer_utxos() {
            wallet_recovers_composer_utxos(FeeNotificationPolicy::OnChainGeneration).await
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn wallet_recovers_expected_offchain_composer_utxos() {
            wallet_recovers_composer_utxos(FeeNotificationPolicy::OffChain).await
        }

        /// Setup:
        ///  - Rando composes a block, and allocates composer fees to himself
        ///    per the given policy.
        ///  - Rando updates wallet state with the new block, and observes
        ///    composer fee UTXOs.
        async fn wallet_recovers_composer_utxos(
            compose_fee_notification_policy: FeeNotificationPolicy,
        ) {
            // set up Rando
            let network = Network::Main;
            let seed: [u8; 32] = random();
            let cli_args = cli_args::Args {
                fee_notification: compose_fee_notification_policy,
                network,
                ..Default::default()
            };
            dbg!(seed);
            let mut rng = StdRng::from_seed(seed);
            let wallet_secret = WalletEntropy::new_pseudorandom(rng.random());
            let mut global_state_lock =
                mock_genesis_global_state(2, wallet_secret.clone(), cli_args).await;

            println!("(ignore all log messages above this line)");

            // compose block
            let genesis_block = Block::genesis(network);
            let now = network.launch_date() + Timestamp::minutes(10);

            let composer_parameters = global_state_lock
                .lock_guard()
                .await
                .composer_parameters(BlockHeight::genesis().next());
            let (transaction, composer_txos) = make_coinbase_transaction_stateless(
                &genesis_block,
                composer_parameters.clone(),
                now,
                TritonVmJobQueue::get_instance(),
                global_state_lock
                    .cli()
                    .proof_job_options_primitive_witness(),
            )
            .await
            .unwrap();

            let new_block = invalid_block_with_transaction(&genesis_block, transaction);
            let expected_utxos = composer_parameters.extract_expected_utxos(composer_txos);
            global_state_lock
                .lock_guard_mut()
                .await
                .wallet_state
                .add_expected_utxos(expected_utxos.clone())
                .await;

            let num_expected_pub_announcements = match compose_fee_notification_policy {
                FeeNotificationPolicy::OffChain => 0,
                FeeNotificationPolicy::OnChainSymmetric => 2,
                FeeNotificationPolicy::OnChainGeneration => 2,
            };
            assert_eq!(
                num_expected_pub_announcements,
                new_block.body().transaction_kernel.announcements.len()
            );
            let num_expected_expected_utxos = 2 - num_expected_pub_announcements;
            assert_eq!(num_expected_expected_utxos, expected_utxos.len());

            // update wallet state with new block (ignoring expected UTXOs)
            let maintain_mps = true;
            global_state_lock
                .lock_guard_mut()
                .await
                .wallet_state
                .update_wallet_state_with_new_block(
                    &genesis_block.mutator_set_accumulator_after().unwrap(),
                    &new_block,
                    maintain_mps,
                )
                .await
                .unwrap();

            // Lo! composer utxos
            let wallet_status = global_state_lock
                .lock_guard()
                .await
                .wallet_state
                .get_wallet_status(
                    new_block.hash(),
                    &new_block.mutator_set_accumulator_after().unwrap(),
                )
                .await;
            assert_eq!(2, wallet_status.synced_unspent.len());
        }

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn wallet_recovers_expected_offchain_upgrader_fee_utxos() {
            wallet_recovers_upgrader_fee_utxos_given_notification_policy(
                FeeNotificationPolicy::OffChain,
            )
            .await;
        }
        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn wallet_recovers_unexpected_onchain_symmetric_upgrader_fee_utxos() {
            wallet_recovers_upgrader_fee_utxos_given_notification_policy(
                FeeNotificationPolicy::OnChainSymmetric,
            )
            .await;
        }
        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn wallet_recovers_unexpected_onchain_generation_upgrader_fee_utxos() {
            wallet_recovers_upgrader_fee_utxos_given_notification_policy(
                FeeNotificationPolicy::OnChainGeneration,
            )
            .await;
        }

        /// Setup:
        ///  - A new transaction is broadcast. It is synced to genesis block.
        ///  - A new block is mined, ignoring that transaction.
        ///  - Rando upgrades the transaction, and collects a fee through the
        ///    given policy.
        ///  - The upgraded transaction is confirmed in the next block.
        ///  - After updating state with the new block, Rando observes the
        ///    upgrader fee UTXOs.
        ///
        /// Note that the initial transaction is currently a `ProofCollection`
        /// transaction, and is being upgraded twice: once from
        /// `ProofCollection` to `SingleProof`, and once from `SingleProof` to
        /// `SingleProof` but with a new mutator set. Only the first upgrade
        /// generates a fee under the current policy. When this policy changes,
        /// it may suffice to generate a `SingleProof` from the start.
        async fn wallet_recovers_upgrader_fee_utxos_given_notification_policy(
            upgrade_fee_notification_policy: FeeNotificationPolicy,
        ) {
            // derandomize because we will need proofs
            let seed = [
                155, 213, 11, 57, 97, 48, 59, 23, 111, 107, 153, 29, 219, 126, 204, 48, 17, 5, 105,
                31, 185, 57, 156, 90, 7, 121, 39, 201, 232, 33, 159, 189,
            ];
            dbg!(seed);
            let mut rng = StdRng::from_seed(seed);

            // set up premine recipient
            let network = Network::Main;
            let cli_args = cli_args::Args {
                tx_proving_capability: Some(TxProvingCapability::SingleProof),
                network,
                ..Default::default()
            };
            let wallet_secret = WalletEntropy::devnet_wallet();
            let mut alice = mock_genesis_global_state(2, wallet_secret.clone(), cli_args).await;
            let genesis_block = Block::genesis(network);

            println!("(ignore all log messages above this line)");

            // create transaction with fee
            let destination_address =
                GenerationSpendingKey::derive_from_seed(rng.random()).to_address();
            let transferred_amount = NativeCurrencyAmount::coins(2);
            let fee = NativeCurrencyAmount::coins(1);
            let sender_randomness = rng.random();
            let own_medium = UtxoNotificationMedium::OnChain;
            let unowned_medium = UtxoNotificationMedium::OnChain;
            let tx_outputs = vec![TxOutput::auto(
                &alice.lock_guard().await.wallet_state,
                destination_address.into(),
                transferred_amount,
                sender_randomness,
                own_medium,
                unowned_medium,
            )];
            let change_key = alice
                .lock_guard_mut()
                .await
                .wallet_state
                .next_unused_symmetric_key()
                .await;
            let now = network.launch_date() + Timestamp::months(7);
            let dummy_queue = TritonVmJobQueue::get_instance();

            let config = TxCreationConfig::default()
                .recover_change_on_chain(change_key.into())
                .with_prover_capability(TxProvingCapability::ProofCollection);

            let consensus_rule_set = ConsensusRuleSet::infer_from(network, BlockHeight::genesis());
            let proof_collection_transaction = alice
                .api()
                .tx_initiator_internal()
                .create_transaction(tx_outputs.into(), fee, now, config, consensus_rule_set)
                .await
                .unwrap()
                .transaction;
            let old_num_announcements = proof_collection_transaction.kernel.announcements.len();

            // let Rando upgrade that transaction
            // from proof collection to single proof
            let rando_wallet_secret = WalletEntropy::new_pseudorandom(rng.random());
            let rando_cli_args = cli_args::Args {
                fee_notification: upgrade_fee_notification_policy,
                tx_proving_capability: Some(TxProvingCapability::SingleProof),
                network,
                ..Default::default()
            };
            let mut rando =
                mock_genesis_global_state(2, rando_wallet_secret.clone(), rando_cli_args).await;
            let upgrade_incentive = UpgradeIncentive::Gobble(fee);
            let upgrade_job_one =
                UpgradeJob::ProofCollectionToSingleProof(ProofCollectionToSingleProof::new(
                    proof_collection_transaction.kernel.clone(),
                    proof_collection_transaction
                        .proof
                        .clone()
                        .into_proof_collection(),
                    genesis_block.mutator_set_accumulator_after().unwrap(),
                    upgrade_incentive,
                ));
            let (channel_to_nowhere_one, nowhere_one) =
                broadcast::channel::<MainToPeerTask>(PEER_CHANNEL_CAPACITY);
            upgrade_job_one
                .handle_upgrade(dummy_queue.clone(), rando.clone(), channel_to_nowhere_one)
                .await;
            drop(nowhere_one); // drop must occur after message is sent

            // Get the "raised" transaction, which must now be in rando's
            // mempool.
            let single_proof_transaction = rando
                .lock_guard()
                .await
                .mempool
                .get_transactions_for_block_composition(1_000_000_000, None)[0]
                .clone();

            // create block ignoring that transaction. Rando has upgraded tx
            // in mempool, alice does not. Alice composes block.
            let (block_transaction, _composer_utxos) = create_block_transaction(
                &genesis_block,
                alice.clone(),
                now,
                TritonVmProofJobOptions::default(),
            )
            .await
            .unwrap();
            let block_one = Block::compose(
                &genesis_block,
                block_transaction,
                now,
                dummy_queue.clone(),
                TritonVmProofJobOptions::default(),
            )
            .await
            .unwrap();
            alice
                .lock_guard_mut()
                .await
                .set_new_tip(block_one.clone())
                .await
                .unwrap();
            rando
                .lock_guard_mut()
                .await
                .set_new_tip(block_one.clone())
                .await
                .unwrap();

            // upgrade transaction again
            // this time mutator set data
            let genesis_mutator_set = genesis_block.mutator_set_accumulator_after().unwrap();
            let upgrade_job_two = UpgradeJob::UpdateMutatorSetData(UpdateMutatorSetDataJob::new(
                single_proof_transaction.kernel,
                single_proof_transaction.proof.into_single_proof(),
                genesis_mutator_set,
                block_one.mutator_set_update().unwrap(),
                upgrade_incentive,
                consensus_rule_set,
            ));
            let (channel_to_nowhere_two, nowhere_two) =
                broadcast::channel::<MainToPeerTask>(PEER_CHANNEL_CAPACITY);
            upgrade_job_two
                .handle_upgrade(dummy_queue.clone(), rando.clone(), channel_to_nowhere_two)
                .await;
            drop(nowhere_two); // drop must occur after message is sent

            // get upgraded transaction
            let transactions_for_block = rando
                .lock_guard()
                .await
                .mempool
                .get_transactions_for_block_composition(10_000_000, None);
            assert_eq!(1, transactions_for_block.len());
            let upgraded_transaction = transactions_for_block[0].clone();
            let new_num_announcements = upgraded_transaction.kernel.announcements.len();
            if upgrade_fee_notification_policy == FeeNotificationPolicy::OffChain {
                assert_eq!(old_num_announcements, new_num_announcements);
            } else {
                assert_ne!(old_num_announcements, new_num_announcements);
            }

            // merge with some other transaction to set merge bit, Alice gets
            // composer rewards.
            let (some_other_transaction, _) = create_block_transaction(
                &block_one,
                alice,
                block_one.header().timestamp + Timestamp::minutes(10),
                TritonVmProofJobOptions::default(),
            )
            .await
            .unwrap();

            let consensus_rule_set_one =
                ConsensusRuleSet::infer_from(network, block_one.header().height);
            let block_two_transaction = BlockTransaction::merge(
                some_other_transaction.into(),
                upgraded_transaction,
                rng.random(),
                dummy_queue.clone(),
                TritonVmProofJobOptions::default(),
                consensus_rule_set_one,
            )
            .await
            .unwrap();

            // create block with that transaction
            let block_two = Block::compose(
                &block_one,
                block_two_transaction,
                now + Timestamp::minutes(10),
                dummy_queue,
                TritonVmProofJobOptions::default(),
            )
            .await
            .unwrap();

            // update wallet state with that block
            assert!(rando
                .lock_guard()
                .await
                .get_latest_balance_height()
                .await
                .is_none());
            rando
                .lock_guard_mut()
                .await
                .set_new_tip(block_two.clone())
                .await
                .unwrap();

            // Lo! an upgrader utxo
            let wallet_status = rando
                .lock_guard()
                .await
                .wallet_state
                .get_wallet_status(
                    block_two.hash(),
                    &block_two.mutator_set_accumulator_after().unwrap(),
                )
                .await;
            assert_eq!(1, wallet_status.synced_unspent.len());

            let (gobble_utxo, gobble_msmp) = wallet_status.synced_unspent[0].clone();
            assert_eq!(
                fee,
                gobble_utxo.utxo.get_native_currency_amount(),
                "Entire fee must be gobbled."
            );
            assert!(
                !gobble_utxo.utxo.is_timelocked(),
                "Gobbling fees may not be timelocked."
            );
            assert!(
                block_two
                    .mutator_set_accumulator_after()
                    .unwrap()
                    .verify(Tip5::hash(&gobble_utxo.utxo), &gobble_msmp),
                "Wallet's MSMP must be correctly synced"
            );
        }
    }

    mod wallet_db_backup {
        use super::*;
        use crate::tests::shared::files::unit_test_data_directory;

        #[traced_test]
        #[apply(shared_tokio_runtime)]
        async fn backup_wallet_db_and_open() -> Result<()> {
            // basic setup
            let cli = cli_args::Args::default();
            let mut rng = StdRng::from_rng(&mut rng());
            let wallet_entropy = WalletEntropy::new_pseudorandom(rng.random());
            let data_dir = unit_test_data_directory(cli.network).unwrap();
            let configuration = WalletConfiguration::new(&data_dir).absorb_options(&cli);
            let db_dir = configuration.data_directory().wallet_database_dir_path();

            // instantiate WalletState to create a new DB and obtain schema version
            let genesis_block = Block::genesis(configuration.network());
            let schema_version = WalletState::try_new(
                configuration.clone(),
                wallet_entropy.clone(),
                &genesis_block,
            )
            .await?
            .wallet_db
            .schema_version();

            // perform db backup
            let backup_dir = WalletState::backup_database(&configuration, schema_version).await?;

            // verify backup dir exists and is different from source db dir.
            assert!(backup_dir.exists());
            assert_ne!(backup_dir, db_dir);

            // move orig wallet db to wallet-db-tmp. (get it out of the way)
            let db_dir_renamed = configuration
                .data_directory()
                .database_dir_path()
                .join("wallet-db-tmp");
            std::fs::rename(&db_dir, &db_dir_renamed)?;

            // move backup wallet-db to location of original wallet-db so it will be loaded
            std::fs::rename(&backup_dir, &db_dir)?;

            // load backup database into a new WalletState and obtain schema version
            let schema_version_from_backup =
                WalletState::try_new(configuration, wallet_entropy, &genesis_block)
                    .await?
                    .wallet_db
                    .schema_version();

            // verify that schema version from backup DB matches original DB.
            assert_eq!(schema_version, schema_version_from_backup);

            Ok(())
        }
    }
}
