use anyhow::{bail, Result};
use itertools::Itertools;
use num_traits::Zero;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Debug;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, LineWriter, Write};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use twenty_first::shared_math::bfield_codec::BFieldCodec;
use twenty_first::shared_math::digest::Digest;
use twenty_first::storage::level_db::DB;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use twenty_first::util_types::emojihash_trait::Emojihash;
use twenty_first::util_types::storage_schema::traits::*;
use twenty_first::util_types::storage_vec::traits::*;

use super::rusty_wallet_database::RustyWalletDatabase;
use super::utxo_notification_pool::{UtxoNotificationPool, UtxoNotifier};
use super::wallet_status::{WalletStatus, WalletStatusElement};
use super::{WalletSecret, WALLET_INCOMING_SECRETS_FILE_NAME};
use crate::config_models::cli_args::Args;
use crate::config_models::data_directory::DataDirectory;
use crate::models::blockchain::block::block_header::BlockHeader;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::transaction::native_coin::NATIVE_COIN_TYPESCRIPT_DIGEST;
use crate::models::blockchain::transaction::utxo::{LockScript, Utxo};
use crate::models::blockchain::transaction::{amount::Amount, Transaction};
use crate::models::state::archival_state::ArchivalState;
use crate::models::state::wallet::monitored_utxo::MonitoredUtxo;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::mutator_set_trait::MutatorSet;
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
    fn store_utxo_ms_recovery_data(
        &self,
        utxo_ms_recovery_data: IncomingUtxoRecoveryData,
    ) -> Result<()> {
        // Open file
        #[cfg(test)]
        {
            std::fs::create_dir_all(self.wallet_directory_path.clone())?;
        }
        let incoming_secrets_file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(self.incoming_secrets_path())?;
        let mut incoming_secrets_file = LineWriter::new(incoming_secrets_file);

        // Create JSON string ending with a newline as this flushes the write
        #[cfg(windows)]
        const LINE_ENDING: &str = "\r\n";
        #[cfg(not(windows))]
        const LINE_ENDING: &str = "\n";

        let mut json_string = serde_json::to_string(&utxo_ms_recovery_data)?;
        json_string.push_str(LINE_ENDING);
        incoming_secrets_file.write_all(json_string.as_bytes())?;

        // Flush just in case, since this is cryptographic data, you can't be too sure
        incoming_secrets_file.flush()?;

        Ok(())
    }

    /// Read recovery-information for mutator set membership proof of a UTXO. Returns all lines in the files,
    /// where each line represents an incoming UTXO.
    pub(crate) fn read_utxo_ms_recovery_data(&self) -> Result<Vec<IncomingUtxoRecoveryData>> {
        let incoming_secrets_file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(self.incoming_secrets_path())?;

        let file_reader = BufReader::new(incoming_secrets_file);
        let mut ret = vec![];
        for line in file_reader.lines() {
            let line = line?;
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

        DataDirectory::create_dir_if_not_exists(&data_dir.wallet_database_dir_path()).unwrap();
        let wallet_db = DB::open(
            &data_dir.wallet_database_dir_path(),
            &crate::database::rusty::create_db_if_missing(),
        );
        let wallet_db = match wallet_db {
            Ok(wdb) => wdb,
            Err(err) => {
                error!("Could not open wallet database: {err:?}");
                panic!();
            }
        };

        let mut rusty_wallet_database = RustyWalletDatabase::connect(wallet_db);
        rusty_wallet_database.restore_or_new();

        let sync_label = rusty_wallet_database.get_sync_label();

        let mut ret = Self {
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
            let own_spending_key = ret.wallet_secret.nth_generation_spending_key(0);
            let own_receiving_address = own_spending_key.to_address();
            for (premine_receiving_address, amount) in Block::premine_distribution() {
                if premine_receiving_address == own_receiving_address {
                    let coins = amount.to_native_coins();
                    let lock_script = own_receiving_address.lock_script();
                    let utxo = Utxo::new(lock_script, coins);

                    ret.expected_utxos
                        .add_expected_utxo(
                            utxo,
                            Digest::default(),
                            own_spending_key.privacy_preimage,
                            UtxoNotifier::Premine,
                        )
                        .unwrap();
                }
            }

            ret.update_wallet_state_with_new_block(&Block::genesis_block())
                .await
                .expect("Updating wallet state with genesis block must succeed");
        }

        ret
    }

    /// Return a list of UTXOs spent by this wallet in the transaction
    fn scan_for_spent_utxos(
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
        for (i, monitored_utxo) in monitored_utxos.iter() {
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

    /// Delete from the database all monitored UTXOs from abandoned chains with a depth deeper than
    /// `block_depth_threshhold`. Use `prune_mutxos_of_unknown_depth = true` to remove MUTXOs from
    /// abandoned chains of unknown depth.
    /// Returns the number of monitored UTXOs removed from the database.
    ///
    /// Locking:
    ///  * acquires `monitored_utxos` lock for write
    pub async fn prune_abandoned_monitored_utxos<'a>(
        &self,
        block_depth_threshhold: usize,
        current_tip: &BlockHeader,
        archival_state: &ArchivalState,
    ) -> Result<usize> {
        const MIN_BLOCK_DEPTH_FOR_MUTXO_PRUNING: usize = 10;
        if block_depth_threshhold < MIN_BLOCK_DEPTH_FOR_MUTXO_PRUNING {
            bail!(
                "
                Cannot prune monitored UTXOs with a depth threshold less than
                {MIN_BLOCK_DEPTH_FOR_MUTXO_PRUNING}. Got threshold {block_depth_threshhold}"
            )
        }

        let current_tip_info: (Digest, Duration, BlockHeight) = (
            Hash::hash(current_tip),
            Duration::from_millis(current_tip.timestamp.value()),
            current_tip.height,
        );

        let mut updates = std::collections::BTreeMap::new();

        // Find monitored_utxo for updating
        for (i, mut mutxo) in self
            .wallet_db
            .monitored_utxos()
            .get_all()
            .into_iter()
            .enumerate()
        {
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
                let depth = current_tip.height - block_height_confirmed + 1;

                let abandoned = depth >= block_depth_threshhold as i128
                    && mutxo.was_abandoned(current_tip, archival_state).await;

                if abandoned {
                    mutxo.abandoned_at = Some(current_tip_info);
                    updates.insert(i as u64, mutxo);
                }
            }
        }

        let removed_count = updates.iter().len();

        // apply updates
        self.wallet_db.monitored_utxos().set_many(updates);

        Ok(removed_count)
    }

    /// Update wallet state with new block. Assumes the given block
    /// is valid and that the wallet state is not up to date yet.
    pub async fn update_wallet_state_with_new_block(&mut self, block: &Block) -> Result<()> {
        let transaction: Transaction = block.body.transaction.clone();

        let spent_inputs: Vec<(Utxo, AbsoluteIndexSet, u64)> =
            self.scan_for_spent_utxos(&transaction);

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

        let monitored_utxos = self.wallet_db.monitored_utxos();

        // return early if there are no monitored utxos and this
        // block does not affect our balance
        if spent_inputs.is_empty()
            && addition_record_to_utxo_info.is_empty()
            && monitored_utxos.is_empty()
        {
            return Ok(());
        }

        // Find the membership proofs that were valid at the previous tip, as these all have
        // to be updated to the mutator set of the new block.
        let mut valid_membership_proofs_and_own_utxo_count: HashMap<
            StrongUtxoKey,
            (MsMembershipProof<Hash>, u64),
        > = HashMap::default();
        for (i, monitored_utxo) in monitored_utxos.iter() {
            let utxo_digest = Hash::hash(&monitored_utxo.utxo);

            match monitored_utxo.get_membership_proof_for_block(block.header.prev_block_digest) {
                Some(ms_mp) => {
                    debug!("Found valid mp for UTXO");
                    let insert_ret = valid_membership_proofs_and_own_utxo_count.insert(
                        StrongUtxoKey::new(utxo_digest, ms_mp.auth_path_aocl.leaf_index),
                        (ms_mp, i),
                    );
                    assert!(
                        insert_ret.is_none(),
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
                        "Unable to find valid membership proof for UTXO with digest {utxo_digest}. {confirmed_in_block_info} Current block height is {}", block.header.height
                    );
                    }
                }
            }
        }

        // Loop over all input UTXOs, applying all addition records. To
        // a) update all existing MS membership proofs
        // b) Register incoming transactions and derive their membership proofs
        let mut changed_mps = vec![];
        let mut msa_state: MutatorSetAccumulator<Hash> =
            block.body.previous_mutator_set_accumulator.to_owned();

        let mut removal_records = transaction.kernel.inputs.clone();
        removal_records.reverse();
        let mut removal_records: Vec<&mut RemovalRecord<Hash>> =
            removal_records.iter_mut().collect::<Vec<_>>();

        for addition_record in block.body.transaction.kernel.outputs.clone().into_iter() {
            // Don't pull this declaration out of the for-loop since the hash map can grow
            // within this loop.
            let utxo_digests = valid_membership_proofs_and_own_utxo_count
                .keys()
                .map(|key| key.utxo_digest)
                .collect_vec();

            {
                let res: Result<Vec<usize>, Box<dyn Error>> =
                    MsMembershipProof::batch_update_from_addition(
                        &mut valid_membership_proofs_and_own_utxo_count
                            .values_mut()
                            .map(|(mp, _index)| mp)
                            .collect_vec(),
                        &utxo_digests,
                        &msa_state.kernel,
                        &addition_record,
                    );
                match res {
                    Ok(mut indices_of_mutated_mps) => {
                        changed_mps.append(&mut indices_of_mutated_mps)
                    }
                    Err(_) => bail!("Failed to update membership proofs with addition record"),
                };
            }

            // Batch update removal records to keep them valid after next addition
            RemovalRecord::batch_update_from_addition(&mut removal_records, &mut msa_state.kernel)
                .expect("MS removal record update from add must succeed in wallet handler");

            // If output UTXO belongs to us, add it to the list of monitored UTXOs and
            // add its membership proof to the list of managed membership proofs.
            if addition_record_to_utxo_info.contains_key(&addition_record) {
                let utxo = addition_record_to_utxo_info[&addition_record].0.clone();
                let sender_randomness = addition_record_to_utxo_info[&addition_record].1;
                let receiver_preimage = addition_record_to_utxo_info[&addition_record].2;
                info!(
                    "Received UTXO in block {}, height {}: value = {}",
                    block.hash.emojihash(),
                    block.header.height,
                    utxo.coins
                        .iter()
                        .filter(|coin| coin.type_script_hash == NATIVE_COIN_TYPESCRIPT_DIGEST)
                        .map(|coin| *Amount::decode(&coin.state)
                            .expect("Failed to decode coin state as amount"))
                        .sum::<Amount>(),
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
                    aocl_index: new_own_membership_proof.auth_path_aocl.leaf_index,
                };
                self.store_utxo_ms_recovery_data(utxo_ms_recovery_data)?;

                valid_membership_proofs_and_own_utxo_count.insert(
                    StrongUtxoKey::new(
                        utxo_digest,
                        new_own_membership_proof.auth_path_aocl.leaf_index,
                    ),
                    (new_own_membership_proof, monitored_utxos.len()),
                );

                // Add the new UTXO to the list of monitored UTXOs
                let mut mutxo = MonitoredUtxo::new(utxo, self.number_of_mps_per_utxo);
                mutxo.confirmed_in_block = Some((
                    block.hash,
                    Duration::from_millis(block.header.timestamp.value()),
                    block.header.height,
                ));
                monitored_utxos.push(mutxo);
            }

            // Update mutator set to bring it to the correct state for the next call to batch-update
            msa_state.add(&addition_record);
        }

        // sanity check
        let mutxo_with_valid_mps = monitored_utxos
            .iter()
            .filter(|(_i, mutxo)| {
                mutxo.is_synced_to(block.header.prev_block_digest)
                    || mutxo.blockhash_to_membership_proof.is_empty()
            })
            .count();
        assert_eq!(
            mutxo_with_valid_mps,
            valid_membership_proofs_and_own_utxo_count.len(),
            "Monitored UTXO count must match number of managed membership proofs"
        );

        // apply all removal records
        debug!("Block has {} removal records", removal_records.len());
        debug!(
            "Transaction has {} inputs",
            block.body.transaction.kernel.inputs.len()
        );
        let mut block_tx_input_count = 0;
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
            RemovalRecord::batch_update_from_remove(&mut removal_records, removal_record)
                .expect("MS removal record update from remove must succeed in wallet handler");

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

                    let mut spent_mutxo = monitored_utxos.get(*mutxo_list_index);
                    spent_mutxo.spent_in_block = Some((
                        block.hash,
                        Duration::from_millis(block.header.timestamp.value()),
                        block.header.height,
                    ));
                    monitored_utxos.set(*mutxo_list_index, spent_mutxo);
                }
            }

            msa_state.remove(removal_record);
            block_tx_input_count += 1;
        }

        // Sanity check that `msa_state` agrees with the mutator set from the applied block
        assert_eq!(
            block.body.next_mutator_set_accumulator.clone().hash(),
            msa_state.hash(),
            "Mutator set in wallet-handler must agree with that from applied block"
        );

        changed_mps.sort();
        changed_mps.dedup();
        debug!("Number of mutated membership proofs: {}", changed_mps.len());

        let num_unspent_utxos = monitored_utxos
            .iter()
            .filter(|(_, m)| m.spent_in_block.is_none())
            .count();

        debug!("Number of unspent UTXOs: {}", num_unspent_utxos);

        for (&strong_utxo_key, (updated_ms_mp, own_utxo_index)) in
            valid_membership_proofs_and_own_utxo_count.iter()
        {
            let StrongUtxoKey { utxo_digest, .. } = strong_utxo_key;
            let mut monitored_utxo = monitored_utxos.get(*own_utxo_index);
            monitored_utxo.add_membership_proof_for_tip(block.hash, updated_ms_mp.to_owned());

            // Sanity check that membership proofs of non-spent transactions are still valid
            assert!(
                monitored_utxo.spent_in_block.is_some()
                    || msa_state.verify(utxo_digest, updated_ms_mp)
            );

            monitored_utxos.set(*own_utxo_index, monitored_utxo);

            // TODO: What if a newly added transaction replaces a transaction that was in another fork?
            // How do we ensure that this transaction is not counted twice?
            // One option is to only count UTXOs that are synced as valid.
            // Another option is to attempt to mark those abandoned monitored UTXOs as reorganized.
        }

        self.wallet_db.set_sync_label(block.hash);
        self.wallet_db.persist();

        // Mark all expected UTXOs that were received in this block as received
        expected_utxos_in_this_block
            .into_iter()
            .for_each(|(addition_rec, _, _, _)| {
                self.expected_utxos
                    .mark_as_received(addition_rec, block.hash)
                    .expect("Expected UTXO must be present when marking it as received")
            });

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
        let synced = monitored_utxos
            .iter()
            .all(|(_, m)| m.get_membership_proof_for_block(tip_hash).is_some());
        synced
    }

    pub fn get_wallet_status_from_lock(&self, tip_digest: Digest) -> WalletStatus {
        let monitored_utxos = self.wallet_db.monitored_utxos();
        let mut synced_unspent = vec![];
        let mut unsynced_unspent = vec![];
        let mut synced_spent = vec![];
        let mut unsynced_spent = vec![];
        for (_i, mutxo) in monitored_utxos.iter() {
            let utxo = mutxo.utxo.clone();
            let spent = mutxo.spent_in_block.is_some();
            if let Some(mp) = mutxo.get_membership_proof_for_block(tip_digest) {
                if spent {
                    synced_spent.push(WalletStatusElement(mp.auth_path_aocl.leaf_index, utxo));
                } else {
                    synced_unspent.push((
                        WalletStatusElement(mp.auth_path_aocl.leaf_index, utxo),
                        mp.clone(),
                    ));
                }
            } else {
                let any_mp = &mutxo.blockhash_to_membership_proof.iter().next().unwrap().1;
                if spent {
                    unsynced_spent
                        .push(WalletStatusElement(any_mp.auth_path_aocl.leaf_index, utxo));
                } else {
                    unsynced_unspent
                        .push(WalletStatusElement(any_mp.auth_path_aocl.leaf_index, utxo));
                }
            }
        }
        WalletStatus {
            synced_unspent_amount: synced_unspent
                .iter()
                .map(|x| x.0 .1.get_native_coin_amount())
                .sum(),
            synced_unspent,
            unsynced_unspent_amount: unsynced_unspent
                .iter()
                .map(|x| x.1.get_native_coin_amount())
                .sum(),
            unsynced_unspent,
            synced_spent_amount: synced_spent
                .iter()
                .map(|x| x.1.get_native_coin_amount())
                .sum(),
            synced_spent,
            unsynced_spent_amount: unsynced_spent
                .iter()
                .map(|x| x.1.get_native_coin_amount())
                .sum(),
            unsynced_spent,
        }
    }

    pub async fn allocate_sufficient_input_funds_from_lock(
        &self,
        requested_amount: Amount,
        tip_digest: Digest,
    ) -> Result<Vec<(Utxo, LockScript, MsMembershipProof<Hash>)>> {
        // TODO: Should return the correct spending keys associated with the UTXOs
        // We only attempt to generate a transaction using those UTXOs that have up-to-date
        // membership proofs.
        let wallet_status = self.get_wallet_status_from_lock(tip_digest);

        // First check that we have enough. Otherwise return an error.
        if wallet_status.synced_unspent_amount < requested_amount {
            // TODO: Change this to `Display` print once available.
            bail!(
                "Insufficient synced amount to create transaction. Requested: {:?}, synced unspent amount: {:?}. Unsynced unspent amount: {:?}. Block is: {}",
                requested_amount,
                wallet_status.synced_unspent_amount, wallet_status.unsynced_unspent_amount,
                tip_digest.emojihash());
        }

        let mut ret: Vec<(Utxo, LockScript, MsMembershipProof<Hash>)> = vec![];
        let mut allocated_amount = Amount::zero();
        let lock_script = self
            .wallet_secret
            .nth_generation_spending_key(0)
            .to_address()
            .lock_script();
        while allocated_amount < requested_amount {
            let (wallet_status_element, membership_proof) =
                wallet_status.synced_unspent[ret.len()].clone();
            allocated_amount = allocated_amount + wallet_status_element.1.get_native_coin_amount();
            ret.push((
                wallet_status_element.1,
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
        requested_amount: Amount,
        tip_digest: Digest,
    ) -> Result<Vec<(Utxo, LockScript, MsMembershipProof<Hash>)>> {
        self.allocate_sufficient_input_funds_from_lock(requested_amount, tip_digest)
            .await
    }
}

#[cfg(test)]
mod tests {
    use num_traits::One;
    use tracing_test::traced_test;

    use crate::{
        config_models::network::Network,
        tests::shared::{get_mock_global_state, make_mock_block},
    };

    use super::*;

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

        let network = Network::Testnet;
        let own_wallet_secret = WalletSecret::new_random();
        let own_spending_key = own_wallet_secret.nth_generation_spending_key(0);
        let own_global_state_lock =
            get_mock_global_state(network, 0, Some(own_wallet_secret)).await;
        let mut own_global_state = own_global_state_lock.lock_guard_mut().await;
        let genesis_block = Block::genesis_block();
        let monitored_utxos_count_init = own_global_state
            .wallet_state
            .wallet_db
            .monitored_utxos()
            .len();
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
                make_mock_block(&latest_block, None, other_recipient_address);
            own_global_state
                .wallet_state
                .update_wallet_state_with_new_block(&new_block)
                .await
                .unwrap();
            own_global_state
                .chain
                .archival_state()
                .write_block(&new_block, Some(latest_block.header.proof_of_work_family))
                .await
                .unwrap();
            own_global_state
                .chain
                .light_state_mut()
                .set_block(new_block.clone());

            latest_block = new_block;
        }
        assert!(
            own_global_state
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .len()
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
            make_mock_block(&latest_block, None, own_recipient_address);
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
            .update_wallet_state_with_new_block(&block_3a)
            .await
            .unwrap();
        own_global_state
            .chain
            .archival_state()
            .write_block(&block_3a, Some(latest_block.header.proof_of_work_family))
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
                .is_one(),
            "Monitored UTXO list must have length 1 at block 3a"
        );
        assert!(
            own_global_state
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .get(0)
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
            make_mock_block(&latest_block, None, other_recipient_address);
        own_global_state
            .wallet_state
            .update_wallet_state_with_new_block(&block_3b)
            .await
            .unwrap();
        own_global_state
            .chain
            .archival_state()
            .write_block(&block_3b, Some(latest_block.header.proof_of_work_family))
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

                .get(0)
                .abandoned_at
                .is_none(),
            "MUTXO may not be marked as abandoned at block 3b, as the abandoned chain is not yet old enough and has not been pruned"
        );
        assert!(
            own_global_state.get_latest_balance_height().await.is_none(),
            "Latest balance height must be None at block 3b"
        );
        let prune_count_3b = own_global_state
            .wallet_state
            .prune_abandoned_monitored_utxos(
                10,
                &block_3b.header,
                own_global_state.chain.archival_state(),
            )
            .await
            .unwrap();
        assert!(prune_count_3b.is_zero());

        // Mine nine blocks on top of 3b, update states
        latest_block = block_3b;
        for _ in 4..=11 {
            let (new_block, _new_block_coinbase_utxo, _new_block_coinbase_sender_randomness) =
                make_mock_block(&latest_block, None, other_recipient_address);
            own_global_state
                .wallet_state
                .update_wallet_state_with_new_block(&new_block)
                .await
                .unwrap();
            own_global_state
                .chain
                .archival_state()
                .write_block(&new_block, Some(latest_block.header.proof_of_work_family))
                .await
                .unwrap();
            own_global_state
                .chain
                .light_state_mut()
                .set_block(new_block.clone());

            latest_block = new_block;
        }

        let prune_count_11 = own_global_state
            .wallet_state
            .prune_abandoned_monitored_utxos(
                10,
                &latest_block.header,
                own_global_state.chain.archival_state(),
            )
            .await
            .unwrap();
        assert!(prune_count_11.is_zero());
        assert!(
            own_global_state
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .get(0)
                .abandoned_at
                .is_none(),
            "MUTXO must not be abandoned at height 11"
        );
        assert!(
            own_global_state.get_latest_balance_height().await.is_none(),
            "Latest balance height must be None at height 11"
        );

        // Mine *one* more block. Verify that MUTXO is pruned
        let (block_12, _, _) = make_mock_block(&latest_block, None, other_recipient_address);
        own_global_state
            .wallet_state
            .update_wallet_state_with_new_block(&block_12)
            .await
            .unwrap();
        own_global_state
            .chain
            .archival_state()
            .write_block(&block_12, Some(latest_block.header.proof_of_work_family))
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
                .abandoned_at
                .is_none(),
            "MUTXO must *not* be marked as abandoned at height 12, prior to pruning"
        );
        let prune_count_12 = own_global_state
            .wallet_state
            .prune_abandoned_monitored_utxos(
                10,
                &block_12.header,
                own_global_state.chain.archival_state(),
            )
            .await
            .unwrap();
        assert!(prune_count_12.is_one());
        assert_eq!(
            (
                block_12.hash,
                Duration::from_millis(block_12.header.timestamp.value()),
                12u64.into()
            ),
            own_global_state
                .wallet_state
                .wallet_db
                .monitored_utxos()
                .get(0)
                .abandoned_at
                .unwrap(),
            "MUTXO must be marked as abandoned at height 12, after pruning"
        );
        assert!(
            own_global_state.get_latest_balance_height().await.is_none(),
            "Latest balance height must be None at height 12"
        );
    }
}
