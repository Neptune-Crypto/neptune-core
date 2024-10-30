use std::collections::HashMap;
use std::collections::HashSet;
use std::error::Error;
use std::fmt::Debug;
use std::path::PathBuf;

use anyhow::bail;
use anyhow::Result;
use itertools::Itertools;
use num_traits::CheckedSub;
use num_traits::Zero;
use serde_derive::Deserialize;
use serde_derive::Serialize;
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
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

use super::address::generation_address;
use super::address::symmetric_key;
use super::address::KeyType;
use super::address::SpendingKey;
use super::coin_with_possible_timelock::CoinWithPossibleTimeLock;
use super::expected_utxo::ExpectedUtxo;
use super::expected_utxo::UtxoNotifier;
use super::rusty_wallet_database::RustyWalletDatabase;
use super::unlocked_utxo::UnlockedUtxo;
use super::wallet_status::WalletStatus;
use super::wallet_status::WalletStatusElement;
use super::WalletSecret;
use super::WALLET_INCOMING_SECRETS_FILE_NAME;
use crate::config_models::cli_args::Args;
use crate::config_models::data_directory::DataDirectory;
use crate::database::storage::storage_schema::traits::*;
use crate::database::storage::storage_schema::DbtVec;
use crate::database::storage::storage_vec::traits::*;
use crate::database::storage::storage_vec::Index;
use crate::database::NeptuneLevelDb;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::transaction_output::TxOutputList;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::AnnouncedUtxo;
use crate::models::blockchain::type_scripts::native_currency::NativeCurrency;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::mempool::MempoolEvent;
use crate::models::state::wallet::monitored_utxo::MonitoredUtxo;
use crate::prelude::twenty_first;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
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
    mempool_spent_utxos: HashMap<Digest, Vec<(Utxo, AbsoluteIndexSet, u64)>>,
    mempool_unspent_utxos: HashMap<Digest, Vec<AnnouncedUtxo>>,
}

/// Contains the cryptographic (non-public) data that is needed to recover the mutator set
/// membership proof of a UTXO.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct IncomingUtxoRecoveryData {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
    pub receiver_preimage: Digest,
    pub aocl_index: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct StrongUtxoKey {
    utxo_digest: Digest,
    aocl_index: u64,
}

impl StrongUtxoKey {
    fn new(utxo_digest: Digest, aocl_index: u64) -> Self {
        Self {
            utxo_digest,
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
        // Open file
        #[cfg(test)]
        {
            tokio::fs::create_dir_all(self.wallet_directory_path.clone()).await?;
        }
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

        let mut wallet_state = Self {
            wallet_db: rusty_wallet_database,
            wallet_secret,
            number_of_mps_per_utxo: cli_args.number_of_mps_per_utxo,
            wallet_directory_path: data_dir.wallet_directory_path(),
            mempool_spent_utxos: Default::default(),
            mempool_unspent_utxos: Default::default(),
        };

        // Wallet state has to be initialized with the genesis block, otherwise the outputs
        // from genesis would be unspendable. This should only be done *once* though.
        // This also ensures that any premine outputs are added to the file containing the
        // incoming randomness such that a wallet-DB recovery will include genesis block
        // outputs.
        if sync_label == Digest::default() {
            // Check if we are premine recipients
            let own_spending_key = wallet_state.next_unused_spending_key(KeyType::Generation);
            let own_receiving_address = own_spending_key.to_address();
            for utxo in Block::premine_utxos(cli_args.network) {
                if utxo.lock_script_hash == own_receiving_address.lock_script().hash() {
                    wallet_state
                        .add_expected_utxo(ExpectedUtxo::new(
                            utxo,
                            Block::premine_sender_randomness(cli_args.network),
                            own_spending_key.privacy_preimage(),
                            UtxoNotifier::Premine,
                        ))
                        .await;
                }
            }

            // note: this will write modified state to disk.
            wallet_state
                .update_wallet_state_with_new_block(
                    &MutatorSetAccumulator::default(),
                    &Block::genesis_block(cli_args.network),
                )
                .await
                .expect("Updating wallet state with genesis block must succeed");
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
                    spending_key.privacy_preimage(),
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
                trace!("handling mempool AddTx event.");

                let spent_utxos = self.scan_for_spent_utxos(&tx.kernel).await;

                let announced_utxos = self
                    .scan_for_announced_utxos(&tx.kernel)
                    .chain(self.scan_for_expected_utxos(&tx.kernel).await)
                    .collect_vec();

                let tx_hash = Hash::hash(&tx);
                self.mempool_spent_utxos.insert(tx_hash, spent_utxos);
                self.mempool_unspent_utxos.insert(tx_hash, announced_utxos);
            }
            MempoolEvent::RemoveTx(tx) => {
                trace!("handling mempool RemoveTx event.");
                let tx_hash = Hash::hash(&tx);
                self.mempool_spent_utxos.remove(&tx_hash);
                self.mempool_unspent_utxos.remove(&tx_hash);
            }
            MempoolEvent::UpdateTxMutatorSet(_tx_hash_pre_update, _tx_post_update) => {
                // Utxos are not affected by MutatorSet update, so this is a no-op.
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

    pub async fn confirmed_balance(
        &self,
        tip_digest: Digest,
        timestamp: Timestamp,
    ) -> NeptuneCoins {
        let wallet_status = self.get_wallet_status_from_lock(tip_digest).await;

        wallet_status.synced_unspent_available_amount(timestamp)
    }

    pub async fn unconfirmed_balance(
        &self,
        tip_digest: Digest,
        timestamp: Timestamp,
    ) -> NeptuneCoins {
        self.confirmed_balance(tip_digest, timestamp)
            .await
            .checked_sub(
                &self
                    .mempool_spent_utxos_iter()
                    .map(|u| u.get_native_currency_amount())
                    .sum(),
            )
            .expect("balance must never be negative")
            .safe_add(
                self.mempool_unspent_utxos_iter()
                    .map(|u| u.get_native_currency_amount())
                    .sum(),
            )
            .expect("balance must never overflow")
    }

    // note: does not verify we do not have any dups.
    pub(crate) async fn add_expected_utxo(&mut self, expected_utxo: ExpectedUtxo) {
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

    /// Return a list of UTXOs spent by this wallet in the transaction
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
    ) -> impl Iterator<Item = AnnouncedUtxo> + 'a {
        // scan for announced utxos for every known key of every key type.
        self.get_all_known_spending_keys()
            .into_iter()
            .flat_map(|key| key.scan_for_announced_utxos(tx_kernel).collect_vec())

            // filter for presence in transaction
            //
            // note: this is a nice sanity check, but probably is un-necessary
            //       work that can eventually be removed.
            .filter(|au| match tx_kernel.outputs.contains(&au.addition_record) {
                true => true,
                false => {
                    warn!("Transaction does not contain announced UTXO encrypted to own receiving address. Announced UTXO was: {:#?}", au.utxo);
                    false
                }
            })
    }

    /// Scan the transaction for outputs that match with list of expected
    /// incoming UTXOs, and returns expected UTXOs that are present in the
    /// transaction.
    ///
    /// note: this algorithm is o(n) + o(m) where:
    ///   n = number of ExpectedUtxo in database. (all-time)
    ///   m = number of transaction outputs.
    ///
    /// see https://github.com/Neptune-Crypto/neptune-core/pull/175#issuecomment-2302511025
    ///
    /// Returns an iterator of [AnnouncedUtxo]. (addition record, UTXO, sender randomness, receiver_preimage)
    pub async fn scan_for_expected_utxos<'a>(
        &'a self,
        tx_kernel: &'a TransactionKernel,
    ) -> impl Iterator<Item = AnnouncedUtxo> + 'a {
        let expected_utxos = self.wallet_db.expected_utxos().get_all().await;
        let eu_map: HashMap<_, _> = expected_utxos
            .into_iter()
            .map(|eu| (eu.addition_record, eu))
            .collect();

        tx_kernel
            .outputs
            .iter()
            .filter_map(move |a| eu_map.get(a).map(|eu| eu.into()))
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
            .into_iter()
            .find(|k| k.to_address().lock_script().hash() == utxo.lock_script_hash)
    }

    /// returns all spending keys of all key types with derivation index less than current counter
    pub fn get_all_known_spending_keys(&self) -> Vec<SpendingKey> {
        KeyType::all_types()
            .into_iter()
            .flat_map(|key_type| self.get_known_spending_keys(key_type))
            .collect()
    }

    /// returns all spending keys of `key_type` with derivation index less than current counter
    pub fn get_known_spending_keys(&self, key_type: KeyType) -> Vec<SpendingKey> {
        match key_type {
            KeyType::Generation => self.get_known_generation_spending_keys(),
            KeyType::Symmetric => self.get_known_symmetric_keys(),
        }
    }

    // TODO: These spending keys should probably be derived dynamically from some
    // state in the wallet. And we should allow for other types than just generation
    // addresses.
    //
    // Probably the wallet should keep track of index of latest derived key
    // that has been requested by the user for purpose of receiving
    // funds.  We could also perform a sequential scan at startup (or import)
    // of keys that have received funds, up to some "gap".  In bitcoin/bip32
    // this gap is defined as 20 keys in a row that have never received funds.
    fn get_known_generation_spending_keys(&self) -> Vec<SpendingKey> {
        // for now we always return just the 1st key.
        vec![self.wallet_secret.nth_generation_spending_key(0).into()]
    }

    // TODO: These spending keys should probably be derived dynamically from some
    // state in the wallet. And we should allow for other types than just generation
    // addresses.
    //
    // Probably the wallet should keep track of index of latest derived key
    // that has been requested by the user for purpose of receiving
    // funds.  We could also perform a sequential scan at startup (or import)
    // of keys that have received funds, up to some "gap".  In bitcoin/bip32
    // this gap is defined as 20 keys in a row that have never received funds.
    fn get_known_symmetric_keys(&self) -> Vec<SpendingKey> {
        // for now we always return just the 1st key.
        vec![self.wallet_secret.nth_symmetric_key(0).into()]
    }

    /// Get the next unused spending key of a given type.
    ///
    /// For now, this always returns key at index 0.  In the future it will
    /// return key at present counter (for key_type), and increment the counter.
    ///
    /// Note that incrementing the counter requires &mut self.
    ///
    /// Note that incrementing the counter modifies wallet state.  It is
    /// important to write to disk afterward to avoid possible funds loss.
    pub fn next_unused_spending_key(&mut self, key_type: KeyType) -> SpendingKey {
        match key_type {
            KeyType::Generation => self.next_unused_generation_spending_key().into(),
            KeyType::Symmetric => self.next_unused_symmetric_key().into(),
        }
    }

    /// Get the next unused generation spending key.
    ///
    /// For now, this always returns key at index 0.  In the future it will
    /// return key at present counter, and increment the counter.
    ///
    /// Note that incrementing the counter modifies wallet state.  It is
    /// important to write to disk afterward to avoid possible funds loss.
    fn next_unused_generation_spending_key(&mut self) -> generation_address::GenerationSpendingKey {
        self.wallet_secret.nth_generation_spending_key(0)
    }

    /// Get the next unused symmetric key.
    ///
    /// For now, this always returns key at index 0.  In the future it will
    /// return key at present counter, and increment the counter.
    ///
    /// Note that incrementing the counter modifies wallet state.  It is
    /// important to write to disk afterward to avoid possible funds loss.
    pub fn next_unused_symmetric_key(&mut self) -> symmetric_key::SymmetricKey {
        self.wallet_secret.nth_symmetric_key(0)
    }

    /// Update wallet state with new block. Assume the given block
    /// is valid and that the wallet state is not up to date yet.
    pub async fn update_wallet_state_with_new_block(
        &mut self,
        current_mutator_set_accumulator: &MutatorSetAccumulator,
        new_block: &Block,
    ) -> Result<()> {
        /// Preprocess all own monitored UTXOs prior to processing of the block.
        ///
        /// Returns
        /// - all membership proofs that need to be maintained
        /// - all monitored UTXOs that are double-counted, i.e. the monitored
        ///   UTXOs that were already added through this block. This set will
        ///   be empty unless this block has already been processed.
        async fn preprocess_own_mutxos(
            monitored_utxos: &mut DbtVec<MonitoredUtxo>,
            new_block: &Block,
        ) -> (
            HashMap<StrongUtxoKey, (MsMembershipProof, u64)>,
            HashSet<StrongUtxoKey>,
        ) {
            // Find the membership proofs that were valid at the previous tip. They have
            // to be updated to the mutator set of the new block.
            let mut valid_membership_proofs_and_own_utxo_count: HashMap<
                StrongUtxoKey,
                (MsMembershipProof, u64),
            > = HashMap::default();
            let mut double_counted = HashSet::default();
            let stream = monitored_utxos.stream().await;
            pin_mut!(stream); // needed for iteration

            while let Some((i, monitored_utxo)) = stream.next().await {
                let utxo_digest = Hash::hash(&monitored_utxo.utxo);

                if let Some((confirmation_block, _, _)) = monitored_utxo.confirmed_in_block {
                    if confirmation_block == new_block.hash() {
                        if let Some(msmp) =
                            monitored_utxo.get_membership_proof_for_block(new_block.hash())
                        {
                            let strong_key = StrongUtxoKey::new(utxo_digest, msmp.aocl_leaf_index);
                            double_counted.insert(strong_key);
                        }
                    }
                }

                match monitored_utxo
                    .get_membership_proof_for_block(new_block.kernel.header.prev_block_digest)
                {
                    Some(ms_mp) => {
                        debug!("Found valid mp for UTXO");
                        let replacement_success = valid_membership_proofs_and_own_utxo_count
                            .insert(
                                StrongUtxoKey::new(utxo_digest, ms_mp.aocl_leaf_index),
                                (ms_mp, i),
                            );
                        assert!(
                            replacement_success.is_none(),
                            "Strong key must be unique in wallet DB"
                        );
                    }
                    None => {
                        // Was MUTXO marked as abandoned? Then this is fine. Otherwise, log a warning.
                        // TODO: If MUTXO was spent, maybe we also don't want to maintain it?
                        if monitored_utxo.abandoned_at.is_some() {
                            debug!("Monitored UTXO with digest {utxo_digest} was marked as abandoned. Skipping.");
                        } else {
                            let confirmed_in_block_info = match monitored_utxo.confirmed_in_block {
                                Some(mutxo_received_in_block) => format!(
                                    "UTXO was received at block height {}.",
                                    mutxo_received_in_block.2
                                ),
                                None => String::from("No info about when UTXO was confirmed."),
                            };
                            warn!(
                            "Unable to find valid membership proof for UTXO with digest {utxo_digest}. {confirmed_in_block_info} Current block height is {}", new_block.kernel.header.height
                        );
                        }
                    }
                }
            }

            (valid_membership_proofs_and_own_utxo_count, double_counted)
        }

        let tx_kernel = new_block.kernel.body.transaction_kernel.clone();

        let spent_inputs: Vec<(Utxo, AbsoluteIndexSet, u64)> =
            self.scan_for_spent_utxos(&tx_kernel).await;

        let onchain_received_outputs = self.scan_for_announced_utxos(&tx_kernel);

        let offchain_received_outputs =
            self.scan_for_expected_utxos(&tx_kernel).await.collect_vec();

        let all_received_outputs =
            onchain_received_outputs.chain(offchain_received_outputs.iter().cloned());

        let addition_record_to_utxo_info: HashMap<AdditionRecord, (Utxo, Digest, Digest)> =
            all_received_outputs
                .map(|au| {
                    (
                        au.addition_record,
                        (au.utxo, au.sender_randomness, au.receiver_preimage),
                    )
                })
                .collect();

        debug!(
            "announced outputs received: onchain: {}, offchain: {}, total: {}",
            addition_record_to_utxo_info.len() - offchain_received_outputs.len(),
            offchain_received_outputs.len(),
            addition_record_to_utxo_info.len()
        );

        // Derive the membership proofs for received UTXOs, and in
        // the process update existing membership proofs with
        // updates from this block

        let monitored_utxos = self.wallet_db.monitored_utxos_mut();
        let mut incoming_utxo_recovery_data_list = vec![];

        // return early if there are no monitored utxos and this
        // block does not affect our balance
        if spent_inputs.is_empty()
            && addition_record_to_utxo_info.is_empty()
            && monitored_utxos.is_empty().await
        {
            return Ok(());
        }

        // Get membership proofs that should be maintained, and the set of
        // UTXOs that were already added. The latter is empty if the wallet
        // never processed this block before.
        let (mut valid_membership_proofs_and_own_utxo_count, already_added) =
            preprocess_own_mutxos(monitored_utxos, new_block).await;

        // Loop over all input UTXOs, applying all addition records. In each iteration,
        // a) Update all existing MS membership proofs
        // b) Register incoming transactions and derive their membership proofs
        let mut changed_mps = vec![];
        let mut msa_state: MutatorSetAccumulator = current_mutator_set_accumulator.clone();

        let mut removal_records = tx_kernel.inputs.clone();
        removal_records.reverse();
        let mut removal_records: Vec<&mut RemovalRecord> =
            removal_records.iter_mut().collect::<Vec<_>>();

        for addition_record in new_block.kernel.body.transaction_kernel.outputs.iter() {
            // Don't pull this declaration out of the for-loop since the hash map can grow
            // within this loop.
            let utxo_digests = valid_membership_proofs_and_own_utxo_count
                .keys()
                .map(|key| key.utxo_digest)
                .collect_vec();

            {
                let updated_mp_indices: Result<Vec<usize>, Box<dyn Error>> =
                    MsMembershipProof::batch_update_from_addition(
                        &mut valid_membership_proofs_and_own_utxo_count
                            .values_mut()
                            .map(|(mp, _index)| mp)
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

            // If output UTXO belongs to us, add it to the list of monitored UTXOs and
            // add its membership proof to the list of managed membership proofs.
            if addition_record_to_utxo_info.contains_key(addition_record) {
                let utxo = addition_record_to_utxo_info[addition_record].0.clone();
                let sender_randomness = addition_record_to_utxo_info[addition_record].1;
                let receiver_preimage = addition_record_to_utxo_info[addition_record].2;
                info!(
                    "Received UTXO in block {}, height {}: value = {}",
                    new_block.hash(),
                    new_block.kernel.header.height,
                    utxo.coins
                        .iter()
                        .filter(|coin| coin.type_script_hash == NativeCurrency.hash())
                        .map(|coin| *NeptuneCoins::decode(&coin.state)
                            .expect("Failed to decode coin state as amount"))
                        .sum::<NeptuneCoins>(),
                );
                let utxo_digest = Hash::hash(&utxo);
                let new_own_membership_proof =
                    msa_state.prove(utxo_digest, sender_randomness, receiver_preimage);

                // Add the data required to restore the UTXOs membership proof from public
                // data to the secret's file.
                let utxo_ms_recovery_data = IncomingUtxoRecoveryData {
                    utxo: utxo.clone(),
                    sender_randomness,
                    receiver_preimage,
                    aocl_index: new_own_membership_proof.aocl_leaf_index,
                };
                incoming_utxo_recovery_data_list.push(utxo_ms_recovery_data);

                // Add the new UTXO to the list of monitored UTXOs
                let mut mutxo = MonitoredUtxo::new(utxo, self.number_of_mps_per_utxo);
                mutxo.confirmed_in_block = Some((
                    new_block.hash(),
                    new_block.kernel.header.timestamp,
                    new_block.kernel.header.height,
                ));

                let strong_key =
                    StrongUtxoKey::new(utxo_digest, new_own_membership_proof.aocl_leaf_index);
                if already_added.contains(&strong_key) {
                    debug!("Repeated monitored UTXO. Not adding new entry to monitored UTXOs");
                } else {
                    let mutxos_len = monitored_utxos.len().await;
                    valid_membership_proofs_and_own_utxo_count
                        .insert(strong_key, (new_own_membership_proof, mutxos_len));
                    monitored_utxos.push(mutxo).await;
                }
            }

            // Update mutator set to bring it to the correct state for the next call to batch-update
            msa_state.add(addition_record);
        }

        // sanity check
        {
            let stream = monitored_utxos.stream_values().await;
            pin_mut!(stream); // needed for iteration

            let mutxo_with_valid_mps = stream
                .filter(|mutxo| {
                    futures::future::ready(
                        mutxo.is_synced_to(new_block.kernel.header.prev_block_digest)
                            || mutxo.blockhash_to_membership_proof.is_empty(),
                    )
                })
                .count()
                .await;

            assert_eq!(
                mutxo_with_valid_mps,
                valid_membership_proofs_and_own_utxo_count.len(),
                "Monitored UTXO count must match number of managed membership proofs"
            );
        }

        // apply all removal records
        debug!("Block has {} removal records", removal_records.len());
        debug!(
            "Transaction has {} inputs",
            new_block.kernel.body.transaction_kernel.inputs.len()
        );
        let mut block_tx_input_count: usize = 0;
        while let Some(removal_record) = removal_records.pop() {
            let res = MsMembershipProof::batch_update_from_remove(
                &mut valid_membership_proofs_and_own_utxo_count
                    .values_mut()
                    .map(|(mp, _index)| mp)
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
                        "Discovered own input at input {}, marking UTXO as spent.",
                        block_tx_input_count
                    );

                    let mut spent_mutxo = monitored_utxos.get(*mutxo_list_index).await;
                    spent_mutxo.spent_in_block = Some((
                        new_block.hash(),
                        new_block.kernel.header.timestamp,
                        new_block.kernel.header.height,
                    ));
                    monitored_utxos.set(*mutxo_list_index, spent_mutxo).await;
                }
            }

            msa_state.remove(removal_record);
            block_tx_input_count += 1;
        }

        // Sanity check that `msa_state` agrees with the mutator set from the applied block
        assert_eq!(
            new_block.kernel.body.mutator_set_accumulator.clone().hash(),
            msa_state.hash(),
            "\n\nMutator set in applied block:\n{}\n\nmust agree with that in wallet handler:\n{}\n\n",
            new_block.kernel.body.mutator_set_accumulator.clone().hash(),
            msa_state.hash(),
        );

        changed_mps.sort();
        changed_mps.dedup();
        debug!("Number of mutated membership proofs: {}", changed_mps.len());

        let num_unspent_utxos = {
            let stream = monitored_utxos.stream_values().await;
            pin_mut!(stream); // needed for iteration

            stream
                .filter(|m| futures::future::ready(m.spent_in_block.is_none()))
                .count()
                .await
        };

        debug!("Number of unspent UTXOs: {}", num_unspent_utxos);

        for (&strong_utxo_key, (updated_ms_mp, own_utxo_index)) in
            valid_membership_proofs_and_own_utxo_count.iter()
        {
            let StrongUtxoKey { utxo_digest, .. } = strong_utxo_key;
            let mut monitored_utxo = monitored_utxos.get(*own_utxo_index).await;
            monitored_utxo.add_membership_proof_for_tip(new_block.hash(), updated_ms_mp.to_owned());

            // Sanity check that membership proofs of non-spent transactions are still valid
            assert!(
                monitored_utxo.spent_in_block.is_some()
                    || msa_state.verify(utxo_digest, updated_ms_mp)
            );

            monitored_utxos.set(*own_utxo_index, monitored_utxo).await;

            // TODO: What if a newly added transaction replaces a transaction that was in another fork?
            // How do we ensure that this transaction is not counted twice?
            // One option is to only count UTXOs that are synced as valid.
            // Another option is to attempt to mark those abandoned monitored UTXOs as reorganized.
        }

        // write these to disk.
        for item in incoming_utxo_recovery_data_list.into_iter() {
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
                    .any(|au| au.addition_record == eu.addition_record)
            })
            .map(|(idx, mut eu)| {
                eu.mined_in_block = Some((new_block.hash(), new_block.kernel.header.timestamp));
                (idx as Index, eu)
            });
        self.wallet_db.expected_utxos_mut().set_many(updates).await;

        self.wallet_db.set_sync_label(new_block.hash()).await;
        self.wallet_db.persist().await;

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

    pub async fn get_wallet_status_from_lock(&self, tip_digest: Digest) -> WalletStatus {
        let monitored_utxos = self.wallet_db.monitored_utxos();
        let mut synced_unspent = vec![];
        let mut unsynced_unspent = vec![];
        let mut synced_spent = vec![];
        let mut unsynced_spent = vec![];

        let stream = monitored_utxos.stream().await;
        pin_mut!(stream); // needed for iteration

        while let Some((_i, mutxo)) = stream.next().await {
            // for (_i, mutxo) in monitored_utxos.iter() {
            let utxo = mutxo.utxo.clone();
            let spent = mutxo.spent_in_block.is_some();
            if let Some(mp) = mutxo.get_membership_proof_for_block(tip_digest) {
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
                if spent {
                    unsynced_spent.push(WalletStatusElement::new(any_mp.aocl_leaf_index, utxo));
                } else {
                    unsynced_unspent.push(WalletStatusElement::new(any_mp.aocl_leaf_index, utxo));
                }
            }
        }

        WalletStatus {
            synced_unspent,
            unsynced_unspent,
            synced_spent,
            unsynced_spent,
        }
    }

    /// Allocate sufficient UTXOs to generate a transaction. Requested amount
    /// must include fees that are paid in the transaction.
    pub(crate) async fn allocate_sufficient_input_funds(
        &self,
        total_spend: NeptuneCoins,
        tip_digest: Digest,
        timestamp: Timestamp,
    ) -> Result<Vec<UnlockedUtxo>> {
        // We only attempt to generate a transaction using those UTXOs that have up-to-date
        // membership proofs.
        let wallet_status = self.get_wallet_status_from_lock(tip_digest).await;

        // First check that we have enough. Otherwise return an error.
        if wallet_status.synced_unspent_available_amount(timestamp) < total_spend {
            bail!(
                "Insufficient synced amount to create transaction. Requested: {}, Total synced UTXOs: {}. Total synced amount: {}. Synced unspent available amount: {}. Synced unspent timelocked amount: {}. Total unsynced UTXOs: {}. Unsynced unspent amount: {}. Block is: {}",
                total_spend,
                wallet_status.synced_unspent.len(),
                wallet_status.synced_unspent.iter().map(|(wse, _msmp)| wse.utxo.get_native_currency_amount()).sum::<NeptuneCoins>(),
                wallet_status.synced_unspent_available_amount(timestamp),
                wallet_status.synced_unspent_timelocked_amount(timestamp),
                wallet_status.unsynced_unspent.len(),
                wallet_status.unsynced_unspent_amount(),
                tip_digest);
        }

        let mut input_funds = vec![];
        let mut allocated_amount = NeptuneCoins::zero();
        for (wallet_status_element, membership_proof) in wallet_status.synced_unspent.iter() {
            // Don't attempt to use UTXOs that are still timelocked.
            if !wallet_status_element.utxo.can_spend_at(timestamp) {
                continue;
            }

            // find spending key for this utxo.
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

            // Don't allocate more than needed
            if allocated_amount >= total_spend {
                break;
            }
        }

        Ok(input_funds)
    }

    pub async fn get_all_own_coins_with_possible_timelocks(&self) -> Vec<CoinWithPossibleTimeLock> {
        let monitored_utxos = self.wallet_db.monitored_utxos();
        let mut own_coins = vec![];

        let stream = monitored_utxos.stream_values().await;
        pin_mut!(stream); // needed for iteration

        while let Some(mutxo) = stream.next().await {
            if mutxo.spent_in_block.is_some()
                || mutxo.abandoned_at.is_some()
                || mutxo.get_latest_membership_proof_entry().is_none()
                || mutxo.confirmed_in_block.is_none()
            {
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
    use num_traits::One;
    use rand::thread_rng;
    use rand::Rng;
    use tracing_test::traced_test;

    use super::*;
    use crate::config_models::network::Network;
    use crate::models::state::wallet::expected_utxo::ExpectedUtxo;
    use crate::tests::shared::make_mock_block;
    use crate::tests::shared::mock_genesis_global_state;
    use crate::tests::shared::mock_genesis_wallet_state;

    #[tokio::test]
    #[traced_test]
    async fn does_not_make_tx_with_timelocked_utxos() {
        // Ensure that timelocked UTXOs are not used when selecting input-UTXOs
        // to a transaction.
        // This test is a regression test for issue:
        // <https://github.com/Neptune-Crypto/neptune-core/issues/207>.

        let network = Network::Main;
        let mut alice_global_lock =
            mock_genesis_global_state(network, 0, WalletSecret::devnet_wallet()).await;
        let alice_vm_job_queue = alice_global_lock.vm_job_queue().clone();

        let mut alice = alice_global_lock.global_state_lock.lock_guard_mut().await;
        let launch_timestamp = alice.chain.light_state().header().timestamp;
        let released_timestamp = launch_timestamp + Timestamp::months(12);
        let genesis = alice.chain.light_state();
        let genesis_digest = genesis.hash();
        let alice_ws_genesis = alice
            .wallet_state
            .get_wallet_status_from_lock(genesis_digest)
            .await;

        // First, check that error is returned, when available balance is not
        // there, as it is timelocked.
        let one_coin = NeptuneCoins::new(1);
        assert!(alice_ws_genesis
            .synced_unspent_available_amount(launch_timestamp)
            .is_zero());
        assert!(!alice_ws_genesis
            .synced_unspent_available_amount(released_timestamp)
            .is_zero());
        assert!(
            alice
                .wallet_state
                .allocate_sufficient_input_funds(one_coin, genesis_digest, launch_timestamp)
                .await
                .is_err(),
            "Disallow allocation of timelocked UTXOs"
        );
        assert!(
            alice
                .wallet_state
                .allocate_sufficient_input_funds(one_coin, genesis_digest, released_timestamp)
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
        let alice_address = alice_key.to_address();
        let (block1, cb_utxo, cb_sender_randomness) = make_mock_block(
            genesis,
            Some(block_1_timestamp),
            alice_address,
            Default::default(),
        );
        alice
            .set_new_self_mined_tip(
                block1.clone(),
                ExpectedUtxo::new(
                    cb_utxo,
                    cb_sender_randomness,
                    alice_key.privacy_preimage,
                    UtxoNotifier::OwnMiner,
                ),
                &alice_vm_job_queue,
            )
            .await
            .unwrap();

        let input_utxos = alice
            .wallet_state
            .allocate_sufficient_input_funds(one_coin, block1.hash(), block_1_timestamp)
            .await
            .unwrap();

        assert!(
            input_utxos
                .iter()
                .all(|unlocker| unlocker.utxo.can_spend_at(block_1_timestamp)),
            "All allocated UTXOs must be spendable now"
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn wallet_state_prune_abandoned_mutxos() {
        // Get genesis block. Verify wallet is empty
        // Add two blocks to state containing no UTXOs for own wallet
        // Add a UTXO (e.g. coinbase) in block 3a (height = 3)
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

        let mut rng = thread_rng();
        let network = Network::RegTest;
        let bob_wallet_secret = WalletSecret::new_random();
        let bob_spending_key = bob_wallet_secret.nth_generation_spending_key_for_tests(0);
        let mut bob_global_lock = mock_genesis_global_state(network, 0, bob_wallet_secret).await;
        let bob_vm_job_queue = bob_global_lock.vm_job_queue().clone();
        let mut bob = bob_global_lock.lock_guard_mut().await;
        let genesis_block = Block::genesis_block(network);
        let monitored_utxos_count_init = bob.wallet_state.wallet_db.monitored_utxos().len().await;
        let mut mutator_set_accumulator = genesis_block.kernel.body.mutator_set_accumulator.clone();
        assert!(
            monitored_utxos_count_init.is_zero(),
            "Monitored UTXO list must be empty at init"
        );
        assert!(
            bob.get_latest_balance_height().await.is_none(),
            "Latest balance height must be None at init"
        );

        // Add two blocks with no UTXOs for us
        let alice_address = WalletSecret::new_random()
            .nth_generation_spending_key_for_tests(0)
            .to_address();
        let mut latest_block = genesis_block;
        for _ in 1..=2 {
            let (new_block, _new_block_coinbase_utxo, _new_block_coinbase_sender_randomness) =
                make_mock_block(&latest_block, None, alice_address, rng.gen());
            bob.wallet_state
                .update_wallet_state_with_new_block(&mutator_set_accumulator, &new_block)
                .await
                .unwrap();
            bob.chain
                .archival_state_mut()
                .write_block_as_tip(&new_block)
                .await
                .unwrap();
            bob.chain.light_state_mut().set_block(new_block.clone());

            latest_block = new_block;
            mutator_set_accumulator = latest_block.kernel.body.mutator_set_accumulator.clone();
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
        let own_recipient_address = bob_spending_key.to_address();
        let (block_3a, block_3a_coinbase_utxo, block_3a_coinbase_sender_randomness) =
            make_mock_block(
                &latest_block.clone(),
                None,
                own_recipient_address,
                rng.gen(),
            );
        bob.set_new_self_mined_tip(
            block_3a,
            ExpectedUtxo::new(
                block_3a_coinbase_utxo,
                block_3a_coinbase_sender_randomness,
                bob_spending_key.privacy_preimage,
                UtxoNotifier::OwnMiner,
            ),
            &bob_vm_job_queue,
        )
        .await
        .unwrap();

        assert!(
            bob.wallet_state
                .wallet_db
                .monitored_utxos()
                .len()
                .await
                .is_one(),
            "Monitored UTXO list must have length 1 at block 3a"
        );
        assert!(
            bob.wallet_state
                .wallet_db
                .monitored_utxos()
                .get(0)
                .await
                .abandoned_at
                .is_none(),
            "MUTXO may not be marked as abandoned at block 3a"
        );
        assert_eq!(
            Some(3.into()),
            bob.get_latest_balance_height().await,
            "Latest balance height 3 at block 3a"
        );

        // Fork the blockchain with 3b, with no coinbase for us
        let (block_3b, _block_3b_coinbase_utxo, _block_3b_coinbase_sender_randomness) =
            make_mock_block(&latest_block, None, alice_address, rng.gen());
        bob.set_new_tip(block_3b.clone(), &bob_vm_job_queue)
            .await
            .unwrap();

        assert!(
            bob
                .wallet_state
                .wallet_db
                .monitored_utxos()

                .get(0).await
                .abandoned_at
                .is_none(),
            "MUTXO may not be marked as abandoned at block 3b, as the abandoned chain is not yet old enough and has not been pruned"
        );
        assert!(
            bob.get_latest_balance_height().await.is_none(),
            "Latest balance height must be None at block 3b"
        );
        let prune_count_3b = bob.prune_abandoned_monitored_utxos(10).await.unwrap();
        assert!(prune_count_3b.is_zero());

        // Mine nine blocks on top of 3b, update states
        latest_block = block_3b;
        for _ in 4..=11 {
            let (new_block, _new_block_coinbase_utxo, _new_block_coinbase_sender_randomness) =
                make_mock_block(&latest_block, None, alice_address, rng.gen());
            bob.set_new_tip(new_block.clone(), &bob_vm_job_queue)
                .await
                .unwrap();

            latest_block = new_block;
        }

        let prune_count_11 = bob.prune_abandoned_monitored_utxos(10).await.unwrap();
        assert!(prune_count_11.is_zero());
        assert!(
            bob.wallet_state
                .wallet_db
                .monitored_utxos()
                .get(0)
                .await
                .abandoned_at
                .is_none(),
            "MUTXO must not be abandoned at height 11"
        );
        assert!(
            bob.get_latest_balance_height().await.is_none(),
            "Latest balance height must be None at height 11"
        );

        // Mine *one* more block. Verify that MUTXO is pruned
        let (block_12, _, _) = make_mock_block(&latest_block, None, alice_address, rng.gen());
        bob.set_new_tip(block_12.clone(), &bob_vm_job_queue)
            .await
            .unwrap();

        assert!(
            bob.wallet_state
                .wallet_db
                .monitored_utxos()
                .get(0)
                .await
                .abandoned_at
                .is_none(),
            "MUTXO must *not* be marked as abandoned at height 12, prior to pruning"
        );
        let prune_count_12 = bob.prune_abandoned_monitored_utxos(10).await.unwrap();
        assert!(prune_count_12.is_one());
        assert_eq!(
            (
                block_12.hash(),
                block_12.kernel.header.timestamp,
                12u64.into()
            ),
            bob.wallet_state
                .wallet_db
                .monitored_utxos()
                .get(0)
                .await
                .abandoned_at
                .unwrap(),
            "MUTXO must be marked as abandoned at height 12, after pruning"
        );
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
        let genesis_block = Block::genesis_block(network);

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
                .body()
                .mutator_set_accumulator
                .verify(Hash::hash(&utxo), &ms_membership_proof));
        }
    }

    mod wallet_balance {
        use generation_address::GenerationReceivingAddress;
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        use super::*;
        use crate::job_queue::triton_vm::TritonVmJobQueue;
        use crate::models::blockchain::transaction::transaction_output::UtxoNotificationMedium;
        use crate::models::state::tx_proving_capability::TxProvingCapability;
        use crate::models::state::wallet::address::ReceivingAddress;
        use crate::tests::shared::mine_block_to_wallet_invalid_block_proof;

        /// basic test for confirmed and unconfirmed balance.
        ///
        /// This test:
        ///  1. mines a block to self worth 100
        ///  2. sends 5 to a 3rd party, and 95 change back to self.
        ///  3. verifies that confirmed balance is 100
        ///  4. verifies that unconfirmed balance is 95
        ///  5. empties the mempool (removing our unconfirmed tx)
        ///  6. verifies that unconfirmed balance is 100
        #[traced_test]
        #[tokio::test]
        async fn confirmed_and_unconfirmed_balance() -> Result<()> {
            let network = Network::Main;
            let mut rng = StdRng::seed_from_u64(664505904);
            let mut global_state_lock =
                mock_genesis_global_state(network, 0, WalletSecret::new_pseudorandom(rng.gen()))
                    .await;
            let change_key = global_state_lock
                .lock_guard_mut()
                .await
                .wallet_state
                .next_unused_spending_key(KeyType::Generation);

            let coinbase_amt = NeptuneCoins::new(100);
            let send_amt = NeptuneCoins::new(5);

            let timestamp = Block::genesis_block(network).header().timestamp + Timestamp::hours(1);

            // mine a block to our wallet.  we should have 100 coins after.
            let tip_digest =
                mine_block_to_wallet_invalid_block_proof(&mut global_state_lock, timestamp)
                    .await?
                    .hash();

            let tx = {
                // verify that confirmed and unconfirmed balance are both 100.
                let gs = global_state_lock.lock_guard().await;
                assert_eq!(
                    gs.wallet_state
                        .confirmed_balance(tip_digest, timestamp)
                        .await,
                    coinbase_amt
                );
                assert_eq!(
                    gs.wallet_state
                        .unconfirmed_balance(tip_digest, timestamp)
                        .await,
                    coinbase_amt
                );

                // generate an output that our wallet cannot claim.
                let outputs = vec![(
                    ReceivingAddress::from(GenerationReceivingAddress::derive_from_seed(rng.gen())),
                    send_amt,
                )];

                let tx_outputs = gs.generate_tx_outputs(outputs, UtxoNotificationMedium::OnChain);

                let (tx, _change_output) = gs
                    .create_transaction_with_prover_capability(
                        tx_outputs,
                        change_key,
                        UtxoNotificationMedium::OnChain,
                        NeptuneCoins::zero(),
                        timestamp,
                        TxProvingCapability::SingleProof,
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
                .mempool_insert(tx)
                .await;

            {
                // verify that confirmed balance is still 100
                let gs = global_state_lock.lock_guard().await;
                assert_eq!(
                    gs.wallet_state
                        .confirmed_balance(tip_digest, timestamp)
                        .await,
                    coinbase_amt
                );
                // verify that unconfirmed balance is now 95.
                assert_eq!(
                    gs.wallet_state
                        .unconfirmed_balance(tip_digest, timestamp)
                        .await,
                    coinbase_amt.checked_sub(&send_amt).unwrap()
                );
            }

            // clear the mempool, which drops our unconfirmed tx.
            global_state_lock
                .lock_guard_mut()
                .await
                .mempool_clear()
                .await;

            // verify that wallet's unconfirmed balance is 100 again.
            assert_eq!(
                global_state_lock
                    .lock_guard()
                    .await
                    .wallet_state
                    .unconfirmed_balance(tip_digest, timestamp)
                    .await,
                coinbase_amt
            );

            Ok(())
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

            let mock_utxo =
                Utxo::new_native_currency(LockScript::anyone_can_spend(), NeptuneCoins::new(10));

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
                .scan_for_expected_utxos(&mock_tx_containing_expected_utxo.kernel)
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
                .scan_for_expected_utxos(&tx_without_utxo.kernel)
                .await
                .collect_vec();
            assert!(ret_with_tx_without_utxo.is_empty());
        }

        #[traced_test]
        #[tokio::test]
        async fn prune_stale() {
            let mut wallet =
                mock_genesis_wallet_state(WalletSecret::new_random(), Network::RegTest).await;

            let mock_utxo =
                Utxo::new_native_currency(LockScript::anyone_can_spend(), NeptuneCoins::new(14));

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
                    NeptuneCoins::new(14),
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
}
