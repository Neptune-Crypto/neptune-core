use crate::models::blockchain::type_scripts::native_currency::NativeCurrency;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::consensus::tasm::program::ConsensusProgram;
use crate::prelude::twenty_first;

use crate::database::storage::storage_schema::traits::*;
use crate::database::storage::storage_vec::traits::*;
use crate::database::NeptuneLevelDb;
use anyhow::{bail, Result};
use itertools::Itertools;
use num_traits::Zero;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Debug;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs::OpenOptions;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tracing::{debug, error, info, warn};
use twenty_first::shared_math::bfield_codec::BFieldCodec;
use twenty_first::shared_math::digest::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use twenty_first::util_types::emojihash_trait::Emojihash;

use super::coin_with_possible_timelock::CoinWithPossibleTimeLock;
use super::rusty_wallet_database::RustyWalletDatabase;
use super::utxo_notification_pool::{UtxoNotificationPool, UtxoNotifier};
use super::wallet_status::{WalletStatus, WalletStatusElement};
use super::{WalletSecret, WALLET_INCOMING_SECRETS_FILE_NAME};
use crate::config_models::cli_args::Args;
use crate::config_models::data_directory::DataDirectory;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::transaction::utxo::{LockScript, Utxo};
use crate::models::blockchain::transaction::Transaction;
use crate::models::state::wallet::monitored_utxo::MonitoredUtxo;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::mutator_set_trait::*;
use crate::util_types::mutator_set::removal_record::{AbsoluteIndexSet, RemovalRecord};
use crate::Hash;

pub struct WalletState {
    pub wallet_db: RustyWalletDatabase,
    pub wallet_secret: WalletSecret,
    pub number_of_mps_per_utxo: usize,

    // Any thread may read from expected_utxos, only main thread may write
    pub expected_utxos: UtxoNotificationPool,

    /// Path to directory containing wallet files
    wallet_directory_path: PathBuf,
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
            .field("expected_utxos", &self.expected_utxos)
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
            expected_utxos: UtxoNotificationPool::new(
                cli_args.max_utxo_notification_size,
                cli_args.max_unconfirmed_utxo_notification_count_per_peer,
            ),
            wallet_directory_path: data_dir.wallet_directory_path(),
        };

        // Wallet state has to be initialized with the genesis block, otherwise the outputs
        // from genesis would be unspendable. This should only be done *once* though.
        // This also ensures that any premine outputs are added to the file containing the
        // incoming randomness such that a wallet-DB recovery will include genesis block
        // outputs.
        if sync_label == Digest::default() {
            // Check if we are premine recipients
            let own_spending_key = wallet_state.wallet_secret.nth_generation_spending_key(0);
            let own_receiving_address = own_spending_key.to_address();
            for utxo in Block::premine_utxos() {
                if utxo.lock_script_hash == own_receiving_address.lock_script().hash() {
                    wallet_state
                        .expected_utxos
                        .add_expected_utxo(
                            utxo,
                            Digest::default(),
                            own_spending_key.privacy_preimage,
                            UtxoNotifier::Premine,
                        )
                        .unwrap();
                }
            }

            wallet_state
                .update_wallet_state_with_new_block(
                    &MutatorSetAccumulator::default(),
                    &Block::genesis_block().await,
                )
                .await
                .expect("Updating wallet state with genesis block must succeed");
        }

        wallet_state
    }

    /// Return a list of UTXOs spent by this wallet in the transaction
    async fn scan_for_spent_utxos(
        &self,
        transaction: &Transaction,
    ) -> Vec<(Utxo, AbsoluteIndexSet, u64)> {
        let confirmed_absolute_index_sets = transaction
            .kernel
            .inputs
            .iter()
            .map(|rr| rr.absolute_indices.clone())
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

    /// Scan the given transaction for announced UTXOs as
    /// recognized by owned `SpendingKey`s, and then verify
    /// those announced UTXOs are actually present.
    fn scan_for_announced_utxos(
        &self,
        transaction: &Transaction,
    ) -> Vec<(AdditionRecord, Utxo, Digest, Digest)> {
        // TODO: These spending keys should probably be derived dynamically from some
        // state in the wallet. And we should allow for other types than just generation
        // addresses.
        let spending_keys = [self.wallet_secret.nth_generation_spending_key(0)];

        // get recognized UTXOs
        let recognized_utxos = spending_keys
            .iter()
            .map(|spending_key| spending_key.scan_for_announced_utxos(transaction))
            .collect_vec()
            .concat();

        // filter for presence in transaction
        recognized_utxos
            .into_iter()
            .filter(|(ar, ut, _sr, _rp)| if !transaction.kernel.outputs.contains(ar) {
                warn!("Transaction does not contain announced UTXO encrypted to own receiving address. Announced UTXO was: {ut:#?}");
                false
            } else { true })
            .collect_vec()
    }

    /// Update wallet state with new block. Assume the given block
    /// is valid and that the wallet state is not up to date yet.
    pub async fn update_wallet_state_with_new_block(
        &mut self,
        current_mutator_set_accumulator: &MutatorSetAccumulator,
        new_block: &Block,
    ) -> Result<()> {
        let transaction: Transaction = new_block.kernel.body.transaction.clone();

        let spent_inputs: Vec<(Utxo, AbsoluteIndexSet, u64)> =
            self.scan_for_spent_utxos(&transaction).await;

        // utxo, sender randomness, receiver preimage, addition record
        let mut received_outputs: Vec<(AdditionRecord, Utxo, Digest, Digest)> = vec![];
        received_outputs.append(&mut self.scan_for_announced_utxos(&transaction));
        debug!(
            "received_outputs as announced outputs = {}",
            received_outputs.len()
        );
        let expected_utxos_in_this_block =
            self.expected_utxos.scan_for_expected_utxos(&transaction);
        received_outputs.append(&mut expected_utxos_in_this_block.clone());
        debug!("received total outputs: = {}", received_outputs.len());

        let addition_record_to_utxo_info: HashMap<AdditionRecord, (Utxo, Digest, Digest)> =
            received_outputs
                .into_iter()
                .map(|(ar, utxo, send_rand, rec_premi)| (ar, (utxo, send_rand, rec_premi)))
                .collect();

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

        // Find the membership proofs that were valid at the previous tip. They have
        // to be updated to the mutator set of the new block.
        let mut valid_membership_proofs_and_own_utxo_count: HashMap<
            StrongUtxoKey,
            (MsMembershipProof, u64),
        > = HashMap::default();

        {
            let stream = monitored_utxos.stream().await;
            pin_mut!(stream); // needed for iteration

            while let Some((i, monitored_utxo)) = stream.next().await {
                let utxo_digest = Hash::hash(&monitored_utxo.utxo);

                match monitored_utxo
                    .get_membership_proof_for_block(new_block.kernel.header.prev_block_digest)
                {
                    Some(ms_mp) => {
                        debug!("Found valid mp for UTXO");
                        let replacement_success = valid_membership_proofs_and_own_utxo_count
                            .insert(
                                StrongUtxoKey::new(utxo_digest, ms_mp.auth_path_aocl.leaf_index),
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
        }

        // Loop over all input UTXOs, applying all addition records. In each iteration,
        // a) Update all existing MS membership proofs
        // b) Register incoming transactions and derive their membership proofs
        let mut changed_mps = vec![];
        let mut msa_state: MutatorSetAccumulator = current_mutator_set_accumulator.clone();

        let mut removal_records = transaction.kernel.inputs.clone();
        removal_records.reverse();
        let mut removal_records: Vec<&mut RemovalRecord> =
            removal_records.iter_mut().collect::<Vec<_>>();

        for addition_record in new_block.kernel.body.transaction.kernel.outputs.iter() {
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
                        &msa_state.kernel,
                        addition_record,
                    )
                    .await;
                match updated_mp_indices {
                    Ok(mut indices_of_mutated_mps) => {
                        changed_mps.append(&mut indices_of_mutated_mps)
                    }
                    Err(_) => bail!("Failed to update membership proofs with addition record"),
                };
            }

            // Batch update removal records to keep them valid after next addition
            RemovalRecord::batch_update_from_addition(&mut removal_records, &mut msa_state.kernel)
                .await;

            // If output UTXO belongs to us, add it to the list of monitored UTXOs and
            // add its membership proof to the list of managed membership proofs.
            if addition_record_to_utxo_info.contains_key(addition_record) {
                let utxo = addition_record_to_utxo_info[&addition_record].0.clone();
                let sender_randomness = addition_record_to_utxo_info[&addition_record].1;
                let receiver_preimage = addition_record_to_utxo_info[&addition_record].2;
                info!(
                    "Received UTXO in block {}, height {}: value = {}",
                    new_block.hash().emojihash(),
                    new_block.kernel.header.height,
                    utxo.coins
                        .iter()
                        .filter(|coin| coin.type_script_hash == NativeCurrency.hash())
                        .map(|coin| *NeptuneCoins::decode(&coin.state)
                            .expect("Failed to decode coin state as amount"))
                        .sum::<NeptuneCoins>(),
                );
                let utxo_digest = Hash::hash(&utxo);
                let new_own_membership_proof = msa_state
                    .prove(utxo_digest, sender_randomness, receiver_preimage)
                    .await;

                // Add the data required to restore the UTXOs membership proof from public
                // data to the secret's file.
                let utxo_ms_recovery_data = IncomingUtxoRecoveryData {
                    utxo: utxo.clone(),
                    sender_randomness,
                    receiver_preimage,
                    aocl_index: new_own_membership_proof.auth_path_aocl.leaf_index,
                };
                incoming_utxo_recovery_data_list.push(utxo_ms_recovery_data);

                let mutxos_len = monitored_utxos.len().await;

                valid_membership_proofs_and_own_utxo_count.insert(
                    StrongUtxoKey::new(
                        utxo_digest,
                        new_own_membership_proof.auth_path_aocl.leaf_index,
                    ),
                    (new_own_membership_proof, mutxos_len),
                );

                // Add the new UTXO to the list of monitored UTXOs
                let mut mutxo = MonitoredUtxo::new(utxo, self.number_of_mps_per_utxo);
                mutxo.confirmed_in_block = Some((
                    new_block.hash(),
                    Duration::from_millis(new_block.kernel.header.timestamp.value()),
                    new_block.kernel.header.height,
                ));
                monitored_utxos.push(mutxo).await;
            }

            // Update mutator set to bring it to the correct state for the next call to batch-update
            msa_state.add(addition_record).await;
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
            new_block.kernel.body.transaction.kernel.inputs.len()
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
                        Duration::from_millis(new_block.kernel.header.timestamp.value()),
                        new_block.kernel.header.height,
                    ));
                    monitored_utxos.set(*mutxo_list_index, spent_mutxo).await;
                }
            }

            msa_state.remove(removal_record).await;
            block_tx_input_count += 1;
        }

        // Sanity check that `msa_state` agrees with the mutator set from the applied block
        assert_eq!(
            new_block
                .kernel
                .body
                .mutator_set_accumulator
                .clone()
                .hash()
                .await,
            msa_state.hash().await,
            "Mutator set in wallet-handler must agree with that from applied block"
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
                    || msa_state.verify(utxo_digest, updated_ms_mp).await
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

        self.wallet_db.set_sync_label(new_block.hash()).await;
        self.wallet_db.persist().await;

        // Mark all expected UTXOs that were received in this block as received
        expected_utxos_in_this_block
            .into_iter()
            .for_each(|(addition_rec, _, _, _)| {
                self.expected_utxos
                    .mark_as_received(addition_rec, new_block.hash())
                    .expect("Expected UTXO must be present when marking it as received")
            });

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
                    synced_spent.push(WalletStatusElement::new(mp.auth_path_aocl.leaf_index, utxo));
                } else {
                    synced_unspent.push((
                        WalletStatusElement::new(mp.auth_path_aocl.leaf_index, utxo),
                        mp.clone(),
                    ));
                }
            } else {
                let any_mp = &mutxo.blockhash_to_membership_proof.iter().next().unwrap().1;
                if spent {
                    unsynced_spent.push(WalletStatusElement::new(
                        any_mp.auth_path_aocl.leaf_index,
                        utxo,
                    ));
                } else {
                    unsynced_unspent.push(WalletStatusElement::new(
                        any_mp.auth_path_aocl.leaf_index,
                        utxo,
                    ));
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

    pub async fn allocate_sufficient_input_funds_from_lock(
        &self,
        requested_amount: NeptuneCoins,
        tip_digest: Digest,
        timestamp: u64,
    ) -> Result<Vec<(Utxo, LockScript, MsMembershipProof)>> {
        // TODO: Should return the correct spending keys associated with the UTXOs
        // We only attempt to generate a transaction using those UTXOs that have up-to-date
        // membership proofs.
        let wallet_status = self.get_wallet_status_from_lock(tip_digest).await;

        // First check that we have enough. Otherwise return an error.
        if wallet_status.synced_unspent_available_amount(timestamp) < requested_amount {
            bail!(
                "Insufficient synced amount to create transaction. Requested: {}, Total synced UTXOs: {}. Total synced amount: {}. Synced unspent available amount: {}. Synced unspent timelocked amount: {}. Total unsynced UTXOs: {}. Unsynced unspent amount: {}. Block is: {}",
                requested_amount,
                wallet_status.synced_unspent.len(),
                wallet_status.synced_unspent.iter().map(|(wse, _msmp)| wse.utxo.get_native_currency_amount()).sum::<NeptuneCoins>(),
                wallet_status.synced_unspent_available_amount(timestamp),
                wallet_status.synced_unspent_timelocked_amount(timestamp),
                wallet_status.unsynced_unspent.len(),
                wallet_status.unsynced_unspent_amount(),
                tip_digest.emojihash());
        }

        let mut ret: Vec<(Utxo, LockScript, MsMembershipProof)> = vec![];
        let mut allocated_amount = NeptuneCoins::zero();
        let lock_script = self
            .wallet_secret
            .nth_generation_spending_key(0)
            .to_address()
            .lock_script();
        while allocated_amount < requested_amount {
            let (wallet_status_element, membership_proof) =
                wallet_status.synced_unspent[ret.len()].clone();
            allocated_amount =
                allocated_amount + wallet_status_element.utxo.get_native_currency_amount();
            ret.push((
                wallet_status_element.utxo,
                lock_script.clone(),
                membership_proof,
            ));
        }

        Ok(ret)
    }

    // Allocate sufficient UTXOs to generate a transaction. `amount` must include fees that are
    // paid in the transaction.
    pub async fn allocate_sufficient_input_funds(
        &self,
        requested_amount: NeptuneCoins,
        tip_digest: Digest,
    ) -> Result<Vec<(Utxo, LockScript, MsMembershipProof)>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        self.allocate_sufficient_input_funds_from_lock(requested_amount, tip_digest, now)
            .await
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
    use rand::{thread_rng, Rng};
    use tracing_test::traced_test;

    use crate::{
        config_models::network::Network,
        tests::shared::{get_mock_global_state, get_mock_wallet_state, make_mock_block},
    };

    use super::*;

    #[tokio::test]
    #[traced_test]
    async fn wallet_state_prune_abandoned_mutxos() {
        let mut rng = thread_rng();
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

        let network = Network::Testnet;
        let own_wallet_secret = WalletSecret::new_random();
        let own_spending_key = own_wallet_secret.nth_generation_spending_key(0);
        let own_global_state_lock = get_mock_global_state(network, 0, own_wallet_secret).await;
        let mut own_global_state = own_global_state_lock.lock_guard_mut().await;
        let genesis_block = Block::genesis_block().await;
        let monitored_utxos_count_init = own_global_state
            .wallet_state
            .wallet_db
            .monitored_utxos()
            .len()
            .await;
        let mut mutator_set_accumulator = genesis_block.kernel.body.mutator_set_accumulator.clone();
        assert!(
            monitored_utxos_count_init.is_zero(),
            "Monitored UTXO list must be empty at init"
        );
        assert!(
            own_global_state.get_latest_balance_height().await.is_none(),
            "Latest balance height must be None at init"
        );

        // Add two blocks with no UTXOs for us
        let other_recipient_address = WalletSecret::new_random()
            .nth_generation_spending_key(0)
            .to_address();
        let mut latest_block = genesis_block;
        for _ in 1..=2 {
            let (new_block, _new_block_coinbase_utxo, _new_block_coinbase_sender_randomness) =
                make_mock_block(&latest_block, None, other_recipient_address, rng.gen()).await;
            own_global_state
                .wallet_state
                .update_wallet_state_with_new_block(&mutator_set_accumulator, &new_block)
                .await
                .unwrap();
            own_global_state
                .chain
                .archival_state_mut()
                .write_block(
                    &new_block,
                    Some(latest_block.kernel.header.proof_of_work_family),
                )
                .await
                .unwrap();
            own_global_state
                .chain
                .light_state_mut()
                .set_block(new_block.clone());

            latest_block = new_block;
            mutator_set_accumulator = latest_block.kernel.body.mutator_set_accumulator.clone();
        }
        assert!(
            own_global_state
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .len()
                .await
                .is_zero(),
            "Monitored UTXO list must be empty at height 2"
        );
        assert!(
            own_global_state.get_latest_balance_height().await.is_none(),
            "Latest balance height must be None at height 2"
        );

        // Add block 3a with a coinbase UTXO for us
        let own_recipient_address = own_spending_key.to_address();
        let (block_3a, block_3a_coinbase_utxo, block_3a_coinbase_sender_randomness) =
            make_mock_block(
                &latest_block.clone(),
                None,
                own_recipient_address,
                rng.gen(),
            )
            .await;
        own_global_state
            .wallet_state
            .expected_utxos
            .add_expected_utxo(
                block_3a_coinbase_utxo.clone(),
                block_3a_coinbase_sender_randomness,
                own_spending_key.privacy_preimage,
                UtxoNotifier::OwnMiner,
            )
            .unwrap();
        own_global_state
            .wallet_state
            .update_wallet_state_with_new_block(&mutator_set_accumulator, &block_3a)
            .await
            .unwrap();
        own_global_state
            .chain
            .archival_state_mut()
            .write_block(
                &block_3a,
                Some(latest_block.kernel.header.proof_of_work_family),
            )
            .await
            .unwrap();
        own_global_state
            .chain
            .light_state_mut()
            .set_block(block_3a.clone());

        assert!(
            own_global_state
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .len()
                .await
                .is_one(),
            "Monitored UTXO list must have length 1 at block 3a"
        );
        assert!(
            own_global_state
                .wallet_state
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
            own_global_state.get_latest_balance_height().await,
            "Latest balance height 3 at block 3a"
        );

        // Fork the blockchain with 3b, with no coinbase for us
        let (block_3b, _block_3b_coinbase_utxo, _block_3b_coinbase_sender_randomness) =
            make_mock_block(&latest_block, None, other_recipient_address, rng.gen()).await;
        own_global_state
            .wallet_state
            .update_wallet_state_with_new_block(&mutator_set_accumulator, &block_3b)
            .await
            .unwrap();
        own_global_state
            .chain
            .archival_state_mut()
            .write_block(
                &block_3b,
                Some(latest_block.kernel.header.proof_of_work_family),
            )
            .await
            .unwrap();
        own_global_state
            .chain
            .light_state_mut()
            .set_block(block_3b.clone());

        assert!(
            own_global_state
            .wallet_state
                .wallet_db
                .monitored_utxos()

                .get(0).await
                .abandoned_at
                .is_none(),
            "MUTXO may not be marked as abandoned at block 3b, as the abandoned chain is not yet old enough and has not been pruned"
        );
        assert!(
            own_global_state.get_latest_balance_height().await.is_none(),
            "Latest balance height must be None at block 3b"
        );
        let prune_count_3b = own_global_state
            .prune_abandoned_monitored_utxos(10)
            .await
            .unwrap();
        assert!(prune_count_3b.is_zero());

        // Mine nine blocks on top of 3b, update states
        latest_block = block_3b;
        mutator_set_accumulator = latest_block.kernel.body.mutator_set_accumulator.clone();
        for _ in 4..=11 {
            let (new_block, _new_block_coinbase_utxo, _new_block_coinbase_sender_randomness) =
                make_mock_block(&latest_block, None, other_recipient_address, rng.gen()).await;
            own_global_state
                .wallet_state
                .update_wallet_state_with_new_block(&mutator_set_accumulator, &new_block)
                .await
                .unwrap();
            own_global_state
                .chain
                .archival_state_mut()
                .write_block(
                    &new_block,
                    Some(latest_block.kernel.header.proof_of_work_family),
                )
                .await
                .unwrap();
            own_global_state
                .chain
                .light_state_mut()
                .set_block(new_block.clone());

            latest_block = new_block;
            mutator_set_accumulator = latest_block.kernel.body.mutator_set_accumulator.clone();
        }

        let prune_count_11 = own_global_state
            .prune_abandoned_monitored_utxos(10)
            .await
            .unwrap();
        assert!(prune_count_11.is_zero());
        assert!(
            own_global_state
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .get(0)
                .await
                .abandoned_at
                .is_none(),
            "MUTXO must not be abandoned at height 11"
        );
        assert!(
            own_global_state.get_latest_balance_height().await.is_none(),
            "Latest balance height must be None at height 11"
        );

        // Mine *one* more block. Verify that MUTXO is pruned
        let (block_12, _, _) =
            make_mock_block(&latest_block, None, other_recipient_address, rng.gen()).await;
        own_global_state
            .wallet_state
            .update_wallet_state_with_new_block(&mutator_set_accumulator, &block_12)
            .await
            .unwrap();
        own_global_state
            .chain
            .archival_state_mut()
            .write_block(
                &block_12,
                Some(latest_block.kernel.header.proof_of_work_family),
            )
            .await
            .unwrap();
        own_global_state
            .chain
            .light_state_mut()
            .set_block(block_12.clone());

        assert!(
            own_global_state
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .get(0)
                .await
                .abandoned_at
                .is_none(),
            "MUTXO must *not* be marked as abandoned at height 12, prior to pruning"
        );
        let prune_count_12 = own_global_state
            .prune_abandoned_monitored_utxos(10)
            .await
            .unwrap();
        assert!(prune_count_12.is_one());
        assert_eq!(
            (
                block_12.hash(),
                Duration::from_millis(block_12.kernel.header.timestamp.value()),
                12u64.into()
            ),
            own_global_state
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .get(0)
                .await
                .abandoned_at
                .unwrap(),
            "MUTXO must be marked as abandoned at height 12, after pruning"
        );
        assert!(
            own_global_state.get_latest_balance_height().await.is_none(),
            "Latest balance height must be None at height 12"
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn mock_wallet_state_is_synchronized_to_genesis_block() {
        let network = Network::RegTest;
        let wallet = WalletSecret::devnet_wallet();
        let genesis_block = Block::genesis_block().await;

        let wallet_state = get_mock_wallet_state(wallet, network).await;

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
            assert!(
                genesis_block
                    .body()
                    .mutator_set_accumulator
                    .verify(Hash::hash(&utxo), &ms_membership_proof)
                    .await
            );
        }
    }
}
