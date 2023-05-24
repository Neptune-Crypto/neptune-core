use anyhow::{bail, Result};
use itertools::Itertools;
use mutator_set_tf::util_types::mutator_set::addition_record::AdditionRecord;
use mutator_set_tf::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use mutator_set_tf::util_types::mutator_set::mutator_set_trait::MutatorSet;
use mutator_set_tf::util_types::mutator_set::removal_record::{AbsoluteIndexSet, RemovalRecord};
use num_traits::Zero;
use rusty_leveldb::DB;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Debug;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex as TokioMutex;
use tracing::{debug, error, info, warn};
use twenty_first::shared_math::bfield_codec::BFieldCodec;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use twenty_first::util_types::emojihash_trait::Emojihash;
use twenty_first::util_types::storage_schema::StorageWriter;
use twenty_first::util_types::storage_vec::StorageVec;

use mutator_set_tf::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use twenty_first::shared_math::digest::Digest;

use super::rusty_wallet_database::RustyWalletDatabase;
use super::utxo_notification_pool::{UtxoNotificationPool, UtxoNotifier};
use super::wallet_status::{WalletStatus, WalletStatusElement};
use super::WalletSecret;
use crate::config_models::cli_args::Args;
use crate::config_models::data_directory::DataDirectory;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::transaction::amount::Sign;
use crate::models::blockchain::transaction::native_coin::NATIVE_COIN_TYPESCRIPT_DIGEST;
use crate::models::blockchain::transaction::utxo::{LockScript, Utxo};
use crate::models::blockchain::transaction::{amount::Amount, Transaction};
use crate::models::state::wallet::monitored_utxo::MonitoredUtxo;
use crate::Hash;

#[derive(Clone)]
pub struct WalletState {
    pub wallet_db: Arc<TokioMutex<RustyWalletDatabase>>,
    pub wallet_secret: WalletSecret,
    pub number_of_mps_per_utxo: usize,

    // Anyone may read from expected_utxos, only main thread may write
    pub expected_utxos: Arc<std::sync::RwLock<UtxoNotificationPool>>,
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
            .finish()
    }
}

impl WalletState {
    pub async fn new_from_wallet_secret(
        data_dir: Option<&DataDirectory>,
        wallet_secret: WalletSecret,
        cli_args: &Args,
    ) -> Self {
        // Create or connect to wallet block DB
        let wallet_db = match data_dir {
            Some(data_dir) => DB::open(
                data_dir.wallet_database_dir_path(),
                rusty_leveldb::Options::default(),
            ),
            // This case should only be hit when running unit-test
            None => {
                assert!(cfg!(test), "In memory database may only be used for tests");
                DB::open("in-memory DB", rusty_leveldb::in_memory())
            }
        };

        let wallet_db = match wallet_db {
            Ok(wdb) => wdb,
            Err(err) => {
                error!("Could not open wallet database: {err:?}");
                panic!();
            }
        };

        let mut rusty_wallet_database = RustyWalletDatabase::connect(wallet_db);
        rusty_wallet_database.restore_or_new();

        let rusty_wallet_database = Arc::new(TokioMutex::new(rusty_wallet_database));

        let ret = Self {
            wallet_db: rusty_wallet_database.clone(),
            wallet_secret,
            number_of_mps_per_utxo: cli_args.number_of_mps_per_utxo,
            expected_utxos: Arc::new(RwLock::new(UtxoNotificationPool::new(
                cli_args.max_utxo_notification_size,
                cli_args.max_unconfirmed_utxo_notification_count_per_peer,
            ))),
        };

        // Wallet state has to be initialized with the genesis block, otherwise the outputs
        // from genesis would be unspendable. This should only be done *once* though
        {
            let mut wallet_db_lock = rusty_wallet_database.lock().await;
            if wallet_db_lock.get_sync_label() == Digest::default() {
                // Check if we are premine recipients
                let own_spending_key = ret.wallet_secret.nth_generation_spending_key(0);
                let own_receiving_address = own_spending_key.to_address();
                for (premine_receiving_address, amount) in Block::premine_distribution() {
                    if premine_receiving_address == own_receiving_address {
                        let coins = amount.to_native_coins();
                        let lock_script = own_receiving_address.lock_script();
                        let utxo = Utxo::new(lock_script, coins);

                        ret.expected_utxos
                            .write()
                            .unwrap()
                            .add_expected_utxo(
                                utxo,
                                Digest::default(),
                                own_spending_key.privacy_preimage,
                                UtxoNotifier::Premine,
                            )
                            .unwrap();
                    }
                }

                ret.update_wallet_state_with_new_block(
                    &Block::genesis_block(),
                    &mut wallet_db_lock,
                )
                .expect("Updating wallet state with genesis block must succeed");
            }
        }

        ret
    }
}

impl WalletState {
    fn scan_for_spent_utxos(
        &self,
        transaction: &Transaction,
        wallet_db_lock: &mut tokio::sync::MutexGuard<RustyWalletDatabase>,
    ) -> Vec<(Utxo, AbsoluteIndexSet, u64)> {
        let confirmed_absolute_index_sets = transaction
            .kernel
            .inputs
            .iter()
            .map(|rr| rr.absolute_indices.clone())
            .collect_vec();

        let mut spent_own_utxos = vec![];
        for i in 0..wallet_db_lock.monitored_utxos.len() {
            let monitored_utxo = wallet_db_lock.monitored_utxos.get(i);
            let utxo = monitored_utxo.utxo.clone();
            let abs_i = match monitored_utxo.get_latest_membership_proof_entry() {
                Some(msmp) => msmp.1.compute_indices(&Hash::hash(&utxo)),
                None => continue,
            };

            if confirmed_absolute_index_sets.contains(&abs_i) {
                spent_own_utxos.push((utxo, abs_i, i));
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
        let spending_keys = vec![self.wallet_secret.nth_generation_spending_key(0)];

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

    /// Update wallet state with new block. Assumes the given block
    /// is valid and that the wallet state is not up to date yet.
    pub fn update_wallet_state_with_new_block(
        &self,
        block: &Block,
        wallet_db_lock: &mut tokio::sync::MutexGuard<RustyWalletDatabase>,
    ) -> Result<()> {
        let transaction: Transaction = block.body.transaction.clone();

        let spent_inputs: Vec<(Utxo, AbsoluteIndexSet, u64)> =
            self.scan_for_spent_utxos(&transaction, wallet_db_lock);

        // utxo, sender randomness, receiver preimage, addition record
        let mut received_outputs: Vec<(AdditionRecord, Utxo, Digest, Digest)> = vec![];
        received_outputs.append(&mut self.scan_for_announced_utxos(&transaction));
        debug!(
            "received_outputs as announced outputs = {}",
            received_outputs.len()
        );
        let expected_utxos_in_this_block = self
            .expected_utxos
            .read()
            .unwrap()
            .scan_for_expected_utxos(&transaction);
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

        // return early if there are no monitored utxos and this
        // block does not affect our balance
        if spent_inputs.is_empty()
            && addition_record_to_utxo_info.is_empty()
            && wallet_db_lock.monitored_utxos.is_empty()
        {
            return Ok(());
        }

        // Find the membership proofs that were valid at the previous tip, as these all have
        // to be updated to the mutator set of the new block.
        let mut valid_membership_proofs_and_own_utxo_count: HashMap<
            StrongUtxoKey,
            (MsMembershipProof<Hash>, u64),
        > = HashMap::default();
        for i in 0..wallet_db_lock.monitored_utxos.len() {
            let monitored_utxo: MonitoredUtxo = wallet_db_lock.monitored_utxos.get(i);
            let utxo_digest = Hash::hash(&monitored_utxo.utxo);

            match monitored_utxo.get_membership_proof_for_block(&block.header.prev_block_digest) {
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
                None => warn!(
                    "Unable to find valid membership proof for UTXO with digest {utxo_digest}"
                ),
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
                // TODO: Change this logging to use `Display` for `Amount` once functionality is merged from t-f
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
                    msa_state.prove(&utxo_digest, &sender_randomness, &receiver_preimage);

                valid_membership_proofs_and_own_utxo_count.insert(
                    StrongUtxoKey::new(
                        utxo_digest,
                        new_own_membership_proof.auth_path_aocl.leaf_index,
                    ),
                    (
                        new_own_membership_proof,
                        wallet_db_lock.monitored_utxos.len(),
                    ),
                );

                // Add a new UTXO to the list of monitored UTXOs
                let mut mutxo = MonitoredUtxo::new(utxo, self.number_of_mps_per_utxo);
                mutxo.confirmed_in_block = Some((
                    block.hash,
                    Duration::from_millis(block.header.timestamp.value()),
                    block.header.height,
                ));
                wallet_db_lock.monitored_utxos.push(mutxo);
            }

            // Update mutator set to bring it to the correct state for the next call to batch-update
            msa_state.add(&addition_record);
        }

        // sanity checks
        let mut mutxo_with_valid_mps = 0;
        for i in 0..wallet_db_lock.monitored_utxos.len() {
            let mutxo = wallet_db_lock.monitored_utxos.get(i);
            if mutxo.is_synced_to(&block.header.prev_block_digest)
                || mutxo.blockhash_to_membership_proof.is_empty()
            {
                mutxo_with_valid_mps += 1;
            }
        }
        assert_eq!(
            mutxo_with_valid_mps as usize,
            valid_membership_proofs_and_own_utxo_count.len(),
            "Monitored UTXO count must match number of managed membership proofs"
        );

        // apply all removal records
        debug!("Block has {} removal records", removal_records.len());
        debug!(
            "Transaction has {} inputs",
            block.body.transaction.kernel.inputs.len()
        );
        let mut i = 0;
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
            // let input_utxo = block.body.transaction.kernel.inputs[i].utxo;
            // if input_utxo.matches_pubkey(my_pub_key) {
            match spent_inputs
                .iter()
                .find(|(_, abs_i, _mutxo_list_index)| *abs_i == removal_record.absolute_indices)
            {
                None => (),
                Some((_spent_utxo, _abs_i, mutxo_list_index)) => {
                    debug!(
                        "Discovered own input at input {}, marking UTXO as spent.",
                        i
                    );

                    let mut spent_mutxo = wallet_db_lock.monitored_utxos.get(*mutxo_list_index);
                    spent_mutxo.spent_in_block = Some((
                        block.hash,
                        Duration::from_millis(block.header.timestamp.value()),
                        block.header.height,
                    ));
                    wallet_db_lock
                        .monitored_utxos
                        .set(*mutxo_list_index, spent_mutxo);
                }
            }

            msa_state.remove(removal_record);
            i += 1;
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

        let num_monitored_utxos_after_block = wallet_db_lock.monitored_utxos.len();
        let mut num_unspent_utxos = 0;
        for j in 0..num_monitored_utxos_after_block {
            if wallet_db_lock
                .monitored_utxos
                .get(j)
                .spent_in_block
                .is_none()
            {
                num_unspent_utxos += 1;
            }
        }
        debug!("Number of unspent UTXOs: {}", num_unspent_utxos);

        for (
            StrongUtxoKey {
                utxo_digest,
                aocl_index: _,
            },
            (updated_ms_mp, own_utxo_index),
        ) in valid_membership_proofs_and_own_utxo_count.iter()
        {
            let mut monitored_utxo = wallet_db_lock.monitored_utxos.get(*own_utxo_index);
            monitored_utxo.add_membership_proof_for_tip(block.hash, updated_ms_mp.to_owned());

            // Sanity check that membership proofs of non-spent transactions are still valid
            assert!(
                monitored_utxo.spent_in_block.is_some()
                    || msa_state.verify(utxo_digest, updated_ms_mp)
            );

            wallet_db_lock
                .monitored_utxos
                .set(*own_utxo_index, monitored_utxo);

            // TODO: What if a newly added transaction replaces a transaction that was in another fork?
            // How do we ensure that this transaction is not counted twice?
            // One option is to only count UTXOs that are synced as valid.
            // Another option is to attempt to mark those abandoned monitored UTXOs as reorganized.
        }

        wallet_db_lock.set_sync_label(block.hash);
        wallet_db_lock.persist();

        // Mark all expected UTXOs that were received in this block as received
        {
            let mut expected_utxo_writer = self.expected_utxos.write().unwrap();
            expected_utxos_in_this_block
                .into_iter()
                .for_each(|(addition_rec, _, _, _)| {
                    expected_utxo_writer
                        .mark_as_received(addition_rec, block.hash)
                        .expect("Expected UTXO must be present when marking it as received")
                });
        }

        Ok(())
    }

    pub async fn is_synced_to(&self, tip_hash: Digest) -> bool {
        let db_sync_digest = self.wallet_db.lock().await.get_sync_label();
        if db_sync_digest != tip_hash {
            return false;
        }
        let wallet_db_lock = self.wallet_db.lock().await;
        let monitored_utxos = &wallet_db_lock.monitored_utxos;
        for i in 0..monitored_utxos.len() {
            let monitored_utxo = monitored_utxos.get(i);
            let has_current_mp = monitored_utxo
                .get_membership_proof_for_block(&tip_hash)
                .is_some();
            // We assume that the membership proof can only be stored
            // if it is valid for the given block hash, so there is
            // no need to test validity here.
            if !has_current_mp {
                return false;
            }
        }
        true
    }

    pub async fn get_balance(&self) -> Amount {
        debug!("get_balance: Attempting to acquire lock on wallet DB.");

        // Limit scope of wallet DB lock to release it ASAP
        let sum: Amount = {
            // As long as we're only grabbing one lock here, there
            // shouln't be any risk of a deadlock
            let lock = self.wallet_db.lock().await;

            let tick = SystemTime::now();

            let num_monitored_utxos = lock.monitored_utxos.len();
            let mut balance = Amount::zero();
            for i in 0..num_monitored_utxos {
                let monitored_utxo = lock.monitored_utxos.get(i);
                if monitored_utxo.spent_in_block.is_none() {
                    balance = balance + monitored_utxo.utxo.get_native_coin_amount();
                }
            }
            debug!(
                "Computed balance of {} UTXOs in {:?}",
                num_monitored_utxos,
                tick.elapsed(),
            );
            balance
        };

        debug!("get_balance: Released wallet DB lock");
        sum
    }

    pub fn get_wallet_status_from_lock(
        &self,
        lock: &mut tokio::sync::MutexGuard<RustyWalletDatabase>,
        block: &Block,
    ) -> WalletStatus {
        let num_monitored_utxos = lock.monitored_utxos.len();
        let mut synced_unspent = vec![];
        let mut unsynced_unspent = vec![];
        let mut synced_spent = vec![];
        let mut unsynced_spent = vec![];
        for i in 0..num_monitored_utxos {
            let mutxo = lock.monitored_utxos.get(i);
            debug!(
                "mutxo. Synced to: {}",
                mutxo
                    .get_latest_membership_proof_entry()
                    .as_ref()
                    .unwrap()
                    .0
                    .emojihash()
            );
            let utxo = mutxo.utxo.clone();
            let spent = mutxo.spent_in_block.is_some();
            if let Some(mp) = mutxo.get_membership_proof_for_block(&block.hash) {
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

    pub fn allocate_sufficient_input_funds_from_lock(
        &self,
        lock: &mut tokio::sync::MutexGuard<RustyWalletDatabase>,
        requested_amount: Amount,
        block: &Block,
    ) -> Result<Vec<(Utxo, LockScript, MsMembershipProof<Hash>)>> {
        // TODO: Should return the correct spending keys associated with the UTXOs
        // We only attempt to generate a transaction using those UTXOs that have up-to-date
        // membership proofs.
        let wallet_status: WalletStatus = self.get_wallet_status_from_lock(lock, block);

        // First check that we have enough. Otherwise return an error.
        if wallet_status.synced_unspent_amount < requested_amount {
            // TODO: Change this to `Display` print once available.
            bail!(
                "Insufficient synced amount to create transaction. Requested: {:?}, synced unspent amount: {:?}. Unsynced unspent amount: {:?}. Block is: {}",
                requested_amount,
                wallet_status.synced_unspent_amount, wallet_status.unsynced_unspent_amount,
                block.hash.emojihash());
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
        block: &Block,
    ) -> Result<Vec<(Utxo, LockScript, MsMembershipProof<Hash>)>> {
        let mut lock = self.wallet_db.lock().await;
        self.allocate_sufficient_input_funds_from_lock(&mut lock, requested_amount, block)
    }

    pub async fn get_balance_history(&self) -> Vec<(Digest, Duration, Amount, Sign)> {
        let db_lock = self.wallet_db.lock().await;
        let monitored_utxos = db_lock.monitored_utxos.clone();
        let num_monitored_utxos = monitored_utxos.len();
        let mut history = vec![];
        for i in 0..num_monitored_utxos {
            let monitored_utxo: MonitoredUtxo = monitored_utxos.get(i);
            if let Some((confirming_block, confirmation_timestamp, _)) =
                monitored_utxo.confirmed_in_block
            {
                let amount = monitored_utxo.utxo.get_native_coin_amount();
                history.push((
                    confirming_block,
                    confirmation_timestamp,
                    amount,
                    Sign::NonNegative,
                ));
                if let Some((spending_block, spending_timestamp, _block_height)) =
                    monitored_utxo.spent_in_block
                {
                    history.push((spending_block, spending_timestamp, amount, Sign::Negative));
                }
            }
        }
        history
    }
}
