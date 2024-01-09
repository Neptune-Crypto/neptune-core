use anyhow::{bail, Result};
use itertools::Itertools;
use num_traits::{CheckedSub, Zero};
use std::cmp::max;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::shared_math::bfield_codec::BFieldCodec;
use twenty_first::shared_math::digest::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use twenty_first::util_types::emojihash_trait::Emojihash;
use twenty_first::util_types::mmr::mmr_trait::Mmr;
use twenty_first::util_types::storage_schema::StorageWriter;
use twenty_first::util_types::storage_vec::StorageVec;

use self::blockchain_state::BlockchainState;
use self::mempool::Mempool;
use self::networking_state::NetworkingState;
use self::wallet::utxo_notification_pool::UtxoNotifier;
use self::wallet::wallet_state::WalletState;
use self::wallet::wallet_status::WalletStatus;
use super::blockchain::block::block_height::BlockHeight;
use super::blockchain::transaction::transaction_kernel::{
    PubScriptHashAndInput, TransactionKernel,
};
use super::blockchain::transaction::utxo::{LockScript, Utxo};
use super::blockchain::transaction::validity::{TransactionValidityLogic, ValidationLogic};
use super::blockchain::transaction::{
    amount::{Amount, Sign},
    Transaction,
};
use super::blockchain::transaction::{PrimitiveWitness, PubScript, Witness};
use crate::config_models::cli_args;
use crate::models::peer::HandshakeData;
use crate::models::state::wallet::monitored_utxo::MonitoredUtxo;
use crate::time_fn_call_async;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::mutator_set_trait::{commit, MutatorSet};
use crate::util_types::mutator_set::removal_record::RemovalRecord;
use crate::{Hash, VERSION};

pub mod archival_state;
pub mod blockchain_state;
pub mod light_state;
pub mod mempool;
pub mod networking_state;
pub mod shared;
pub mod wallet;

/// `GlobalState` handles all state of a Neptune node that is shared across its threads.
///
/// Some fields are only written to by certain threads.
#[derive(Debug, Clone)]
pub struct GlobalState {
    /// The `WalletState` may be updated by the main thread and the RPC server.
    pub wallet_state: WalletState,

    /// The `BlockchainState` may only be updated by the main thread.
    pub chain: BlockchainState,

    /// The `NetworkingState` may be updated by both the main thread and peer threads.
    pub net: NetworkingState,

    /// The `cli_args::Args` are read-only and accessible by all threads.
    pub cli: cli_args::Args,

    /// The `Mempool` may only be updated by the main thread.
    pub mempool: Mempool,

    // Only the mining thread should write to this, anyone can read.
    pub mining: std::sync::Arc<std::sync::RwLock<bool>>,
}

#[derive(Debug, Clone)]
pub struct UtxoReceiverData {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
    pub receiver_privacy_digest: Digest,
    pub pubscript: PubScript,
    pub pubscript_input: Vec<BFieldElement>,
}

impl GlobalState {
    pub async fn get_wallet_status_for_tip(&self) -> WalletStatus {
        // Grab locks in canonical order, hold over execution of request to wallet
        let mut wallet_db_lock = self.wallet_state.wallet_db.lock().await;
        let tip_digest = self.chain.light_state.latest_block.lock().await.hash;
        self.wallet_state
            .get_wallet_status_from_lock(&mut wallet_db_lock, tip_digest)
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
        let current_tip_digest = self.chain.light_state.get_latest_block().await.hash;
        let monitored_utxos = self
            .wallet_state
            .wallet_db
            .lock()
            .await
            .monitored_utxos
            .clone();

        if monitored_utxos.is_empty() {
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
        let monitored_utxos = monitored_utxos.get_all();
        for mutxo in monitored_utxos.into_iter().rev() {
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
    pub async fn get_balance_history(&self) -> Vec<(Digest, Duration, BlockHeight, Amount, Sign)> {
        let current_tip_digest = self.chain.light_state.get_latest_block().await.hash;

        let db_lock = self.wallet_state.wallet_db.lock().await;
        let monitored_utxos = db_lock.monitored_utxos.clone();
        let mut history = vec![];
        let monitored_utxos = monitored_utxos.get_all();
        for monitored_utxo in monitored_utxos.iter() {
            if monitored_utxo
                .get_membership_proof_for_block(current_tip_digest)
                .is_none()
            {
                continue;
            }

            if let Some((confirming_block, confirmation_timestamp, confirmation_height)) =
                monitored_utxo.confirmed_in_block
            {
                let amount = monitored_utxo.utxo.get_native_coin_amount();
                history.push((
                    confirming_block,
                    confirmation_timestamp,
                    confirmation_height,
                    amount,
                    Sign::NonNegative,
                ));
                if let Some((spending_block, spending_timestamp, spending_height)) =
                    monitored_utxo.spent_in_block
                {
                    history.push((
                        spending_block,
                        spending_timestamp,
                        spending_height,
                        amount,
                        Sign::Negative,
                    ));
                }
            }
        }
        history
    }

    /// Create a transaction that sends coins to the given
    /// `recipient_utxos` from some selection of owned UTXOs.
    /// A change UTXO will be added if needed; the caller
    /// does not need to supply this. The caller must supply
    /// the fee that they are willing to spend to have this
    /// transaction mined.
    ///
    /// Returns the transaction and a vector containing the sender
    /// randomness for each output UTXO.
    pub async fn create_transaction(
        &self,
        receiver_data: Vec<UtxoReceiverData>,
        fee: Amount,
    ) -> Result<Transaction> {
        let mut wallet_db_lock = self.wallet_state.wallet_db.lock().await;

        // Get the block tip as the transaction is made relative to it
        let bc_tip = self.chain.light_state.latest_block.lock().await.to_owned();

        // Get the UTXOs required for this transaction
        let total_spend: Amount = receiver_data
            .iter()
            .map(|x| x.utxo.get_native_coin_amount())
            .sum::<Amount>()
            + fee;

        // todo: accomodate a future change whereby this function also returns the matching spending keys
        let spendable_utxos_and_mps: Vec<(Utxo, LockScript, MsMembershipProof<Hash>)> = self
            .wallet_state
            .allocate_sufficient_input_funds_from_lock(
                &mut wallet_db_lock,
                total_spend,
                bc_tip.hash,
            )?;

        // Create all removal records. These must be relative to the block tip.
        let msa_tip = bc_tip.body.next_mutator_set_accumulator;
        let mut inputs: Vec<RemovalRecord<Hash>> = vec![];
        let mut input_amount: Amount = Amount::zero();
        for (spendable_utxo, _lock_script, mp) in spendable_utxos_and_mps.iter() {
            let removal_record = msa_tip.kernel.drop(Hash::hash(spendable_utxo), mp);
            inputs.push(removal_record);

            input_amount = input_amount + spendable_utxo.get_native_coin_amount();
        }

        let mut transaction_outputs: Vec<AdditionRecord> = vec![];
        let mut output_utxos: Vec<Utxo> = vec![];
        for rd in receiver_data.iter() {
            let addition_record = commit::<Hash>(
                Hash::hash(&rd.utxo),
                rd.sender_randomness,
                rd.receiver_privacy_digest,
            );
            transaction_outputs.push(addition_record);
            output_utxos.push(rd.utxo.to_owned());
        }

        // Send remaining amount back to self
        let change_amount = match input_amount.checked_sub(&total_spend) {
            Some(amt) => amt,
            None => {
                bail!("Cannot create change UTXO with negative amount.");
            }
        };

        // add change UTXO if necessary
        if input_amount > total_spend {
            let own_spending_key_for_change = self
                .wallet_state
                .wallet_secret
                .nth_generation_spending_key(0);
            let own_receiving_address = own_spending_key_for_change.to_address();
            let lock_script = own_receiving_address.lock_script();
            let lock_script_hash = lock_script.hash();
            let change_utxo = Utxo {
                coins: change_amount.to_native_coins(),
                lock_script_hash,
            };
            let receiver_digest = own_receiving_address.privacy_digest;
            let change_sender_randomness = self
                .wallet_state
                .wallet_secret
                .generate_sender_randomness(bc_tip.header.height, receiver_digest);
            let change_addition_record = commit::<Hash>(
                Hash::hash(&change_utxo),
                change_sender_randomness,
                receiver_digest,
            );
            transaction_outputs.push(change_addition_record);
            output_utxos.push(change_utxo.clone());

            // Add change UTXO to pool of expected incoming UTXOs
            let receiver_preimage = own_spending_key_for_change.privacy_preimage;
            let _change_addition_record = self
                .wallet_state
                .expected_utxos
                .write()
                .unwrap()
                .add_expected_utxo(
                    change_utxo,
                    change_sender_randomness,
                    receiver_preimage,
                    UtxoNotifier::Myself,
                )
                .expect("Adding change UTXO to UTXO notification pool must succeed");
        }

        let pubscript_hashes_and_inputs = receiver_data
            .iter()
            .map(|x| PubScriptHashAndInput {
                pubscript_hash: Hash::hash(&x.pubscript),
                pubscript_input: x.pubscript_input.clone(),
            })
            .collect_vec();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        let kernel = TransactionKernel {
            inputs,
            outputs: transaction_outputs,
            pubscript_hashes_and_inputs,
            fee,
            timestamp: BFieldElement::new(timestamp.try_into().unwrap()),
            coinbase: None,
            mutator_set_hash: msa_tip.hash(),
        };

        // TODO: The spending key can be different for each UTXO, and therefore must be supplied by `spendable_utxos_and_mps`.
        let spending_key = self
            .wallet_state
            .wallet_secret
            .nth_generation_spending_key(0);
        let input_utxos = spendable_utxos_and_mps
            .iter()
            .map(|(utxo, _lock_script, _mp)| utxo)
            .cloned()
            .collect_vec();
        let input_lock_scripts = spendable_utxos_and_mps
            .iter()
            .map(|(_utxo, lock_script, _mp)| lock_script.to_owned())
            .collect_vec();
        let input_membership_proofs = spendable_utxos_and_mps
            .iter()
            .map(|(_utxo, _lock_script, mp)| mp)
            .cloned()
            .collect_vec();

        // sanity check: test membership proofs
        for (utxo, membership_proof) in input_utxos.iter().zip(input_membership_proofs.iter()) {
            let item = Hash::hash(utxo);
            assert!(self.chain.light_state.get_latest_block().await.body.next_mutator_set_accumulator.verify(item, membership_proof), "sanity check failed: trying to generate transaction with invalid membership proofs for inputs!");
            debug!(
                "Have valid membership proofs relative to {}",
                self.chain
                    .light_state
                    .get_latest_block()
                    .await
                    .body
                    .next_mutator_set_accumulator
                    .hash()
                    .emojihash()
            );
        }

        let pubscripts = receiver_data
            .iter()
            .map(|rd| rd.pubscript.clone())
            .collect_vec();

        let mutator_set_accumulator = self
            .chain
            .light_state
            .get_latest_block()
            .await
            .body
            .next_mutator_set_accumulator;

        // When reading a digest from secret and standard-in, the digest's
        // zeroth element must be on top of the stack. So the secret-in
        // is here the spending key reversed.
        let mut secret_input = spending_key.unlock_key.encode();
        secret_input.reverse();
        let mut primitive_witness = PrimitiveWitness {
            input_utxos,
            input_lock_scripts,
            lock_script_witnesses: vec![secret_input; spendable_utxos_and_mps.len()],
            input_membership_proofs,
            output_utxos: output_utxos.clone(),
            pubscripts,
            mutator_set_accumulator,
        };

        // Convert the secret-supported claim to a proof, several proofs, or
        // at the very least hide sensitive data.
        let mut transaction_validity_logic =
            TransactionValidityLogic::new_from_witness(&primitive_witness, &kernel);

        if self.cli.privacy {
            transaction_validity_logic
                .prove()
                .expect("Proof generation must work when creating a new transaction");
        } else {
            transaction_validity_logic.lock_scripts_halt.prove().expect(
                "Proof generation must work when unlocking owned UTXOs for a new transaction.",
            );
        }

        // Remove lock script witness from primitive witness to not leak spending keys
        primitive_witness.lock_script_witnesses = vec![];

        Ok(Transaction {
            kernel,
            witness: Witness::ValidityLogic((transaction_validity_logic, primitive_witness)),
        })
    }

    pub async fn get_own_handshakedata(&self) -> HandshakeData {
        let latest_block_header = self.chain.light_state.get_latest_block_header().await;

        HandshakeData {
            tip_header: latest_block_header,
            // TODO: Should be `None` if incoming connections are not accepted
            listen_port: Some(self.cli.peer_port),
            network: self.cli.network,
            instance_id: self.net.instance_id,
            version: VERSION.to_string(),
            // For now, all nodes are archival nodes
            is_archival_node: self.chain.archival_state.is_some(),
        }
    }

    /// In case the wallet database is corrupted or deleted, this method will restore
    /// monitored UTXO data structures from recovery data. This method should only be
    /// called on startup, not while the program is running, since it will only restore
    /// a wallet state, if the monitored UTXOs have been deleted. Not merely if they
    /// are not synced with a valid mutator set membership proof. And this corruption
    /// can only happen if the wallet database is deleted or corrupted.
    pub(crate) async fn restore_monitored_utxos_from_recovery_data(&self) -> Result<()> {
        // Grab locks in canonical order to avoid deadlocks
        let mut wallet_db = self.wallet_state.wallet_db.lock().await;
        let ams_lock = self
            .chain
            .archival_state
            .as_ref()
            .unwrap()
            .archival_mutator_set
            .lock()
            .await;
        let tip = self.chain.light_state.latest_block.lock().await;
        assert_eq!(
            tip.hash,
            ams_lock.get_sync_label(),
            "Archival mutator set must be synced to tip for successful MUTXO recovery"
        );

        // Fetch all incoming UTXOs from recovery data
        let incoming_utxos = self.wallet_state.read_utxo_ms_recovery_data()?;
        let incoming_utxo_count = incoming_utxos.len();
        info!("Checking {} incoming UTXOs", incoming_utxo_count);

        // Loop over all `incoming_utxos` and check if they have a corresponding
        // monitored UTXO in the database. All monitored UTXOs are fetched outside
        // of the loop to avoid DB access/IO inside the loop.
        let mut recovery_data_for_missing_mutxos = vec![];
        let mutxos = wallet_db.monitored_utxos.get_all();
        '_outer: for incoming_utxo in incoming_utxos.into_iter() {
            'inner: for monitored_utxo in mutxos.iter() {
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
        let current_aocl_leaf_count = ams_lock.ams.kernel.aocl.count_leaves();
        let mut restored_mutxos = 0;
        for incoming_utxo in recovery_data_for_missing_mutxos {
            // If the referenced UTXO is in the future from our tip, do not attempt to recover it. Instead: warn the user of this.
            if current_aocl_leaf_count <= incoming_utxo.aocl_index {
                warn!("Cannot restore UTXO with AOCL index {} because it is in the future from our tip. Current AOCL leaf count is {current_aocl_leaf_count}. Maybe this UTXO can be recovered once more blocks are downloaded from peers?", incoming_utxo.aocl_index);
                continue;
            }
            let ms_item = Hash::hash(&incoming_utxo.utxo);
            let restored_msmp_res = ams_lock.ams.restore_membership_proof(
                ms_item,
                incoming_utxo.sender_randomness,
                incoming_utxo.receiver_preimage,
                incoming_utxo.aocl_index,
            );
            let restored_msmp = match restored_msmp_res {
                Ok(msmp) => {
                    // Verify that the restored MSMP is valid
                    if !ams_lock.ams.verify(ms_item, &msmp) {
                        warn!("Restored MSMP is invalid. Skipping restoration of UTXO with AOCL index {}. Maybe this UTXO is on an abandoned chain?", incoming_utxo.aocl_index);
                        continue;
                    }

                    msmp
                }
                Err(err) => bail!("Could not restore MS membership proof. Got: {err}"),
            };

            let mut restored_mutxo =
                MonitoredUtxo::new(incoming_utxo.utxo, self.wallet_state.number_of_mps_per_utxo);
            restored_mutxo.add_membership_proof_for_tip(tip.hash, restored_msmp);

            wallet_db.monitored_utxos.push(restored_mutxo);
            restored_mutxos += 1;
        }

        wallet_db.persist();
        info!("Successfully restored {restored_mutxos} monitored UTXOs to wallet database");

        Ok(())
    }

    pub async fn resync_membership_proofs_from_stored_blocks(
        &self,
        tip_hash: Digest,
    ) -> Result<()> {
        // loop over all monitored utxos
        let monitored_utxos = self
            .wallet_state
            .wallet_db
            .lock()
            .await
            .monitored_utxos
            .clone();
        let num_monitored_utxos = monitored_utxos.len();
        'outer: for i in 0..num_monitored_utxos {
            let mut monitored_utxo = monitored_utxos.get(i).clone();

            // Ignore those MUTXOs that were marked as abandoned
            if monitored_utxo.abandoned_at.is_some() {
                continue;
            }

            // ignore synced ones
            if monitored_utxo.is_synced_to(tip_hash) {
                continue;
            }

            debug!(
                "Resyncing monitored UTXO number {i}, with hash {}",
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
            let (block_hash, mut membership_proof) = monitored_utxo
                .get_latest_membership_proof_entry()
                .expect("Database not in consistent state. Monitored UTXO must have at least one membership proof.");

            // request path-to-tip
            let (backwards, _luca, forwards) = self
                .chain
                .archival_state
                .as_ref()
                .unwrap()
                .find_path(block_hash, tip_hash)
                .await;

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
                    .archival_state
                    .as_ref()
                    .unwrap()
                    .get_block(revert_block_hash)
                    .await?
                    .unwrap();

                debug!("MUTXO confirmed at height {confirming_block_height}, reverting for height {} on abandoned chain", revert_block.header.height);

                // revert removals
                let removal_records = revert_block.body.transaction.kernel.inputs.clone();
                for removal_record in removal_records.iter().rev() {
                    // membership_proof.revert_update_from_removal(&removal);
                    membership_proof
                        .revert_update_from_remove(removal_record)
                        .expect("Could not revert membership proof from removal record.");
                }

                // revert additions
                let previous_mutator_set =
                    revert_block.body.previous_mutator_set_accumulator.clone();
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
                    .archival_state
                    .as_ref()
                    .unwrap()
                    .get_block(apply_block_hash)
                    .await?
                    .unwrap();
                let addition_records = apply_block.body.transaction.kernel.outputs;
                let removal_records = apply_block.body.transaction.kernel.inputs;
                let mut block_msa = apply_block.body.previous_mutator_set_accumulator.clone();

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

                assert_eq!(block_msa, apply_block.body.next_mutator_set_accumulator);
            }

            // store updated membership proof
            monitored_utxo.add_membership_proof_for_tip(tip_hash, membership_proof);
            monitored_utxos.set(i, monitored_utxo);
        }

        // Update sync label and persist
        self.wallet_state
            .wallet_db
            .lock()
            .await
            .set_sync_label(tip_hash);
        self.wallet_state.wallet_db.lock().await.persist();

        Ok(())
    }
}

#[cfg(test)]
mod global_state_tests {
    use crate::{
        config_models::network::Network,
        models::{blockchain::block::Block, state::wallet::utxo_notification_pool::UtxoNotifier},
        tests::shared::{add_block_to_light_state, get_mock_global_state, make_mock_block},
    };
    use num_traits::One;
    use rand::random;
    use tracing_test::traced_test;

    use super::{wallet::WalletSecret, *};

    async fn wallet_state_has_all_valid_mps_for(
        wallet_state: &WalletState,
        tip_block: &Block,
    ) -> bool {
        let wallet_db_lock = wallet_state.wallet_db.lock().await;
        let monitored_utxos = &wallet_db_lock.monitored_utxos;
        for i in 0..monitored_utxos.len() {
            let monitored_utxo = monitored_utxos.get(i);
            let current_mp = monitored_utxo.get_membership_proof_for_block(tip_block.hash);

            match current_mp {
                Some(mp) => {
                    if !tip_block
                        .body
                        .next_mutator_set_accumulator
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
    async fn premine_recipient_can_spend_genesis_block_output() {
        let network = Network::Alpha;
        let other_wallet = WalletSecret::new(wallet::generate_secret_key());
        let global_state = get_mock_global_state(network, 2, None).await;
        let twenty_amount: Amount = 20.into();
        let twenty_coins = twenty_amount.to_native_coins();
        let recipient_address = other_wallet.nth_generation_spending_key(0).to_address();
        let main_lock_script = recipient_address.lock_script();
        let output_utxo = Utxo {
            coins: twenty_coins,
            lock_script_hash: main_lock_script.hash(),
        };
        let sender_randomness = Digest::default();
        let receiver_privacy_digest = recipient_address.privacy_digest;
        let (pubscript, pubscript_input) = recipient_address
            .generate_pubscript_and_input(&output_utxo, sender_randomness)
            .unwrap();
        let receiver_data = vec![UtxoReceiverData {
            utxo: output_utxo.clone(),
            sender_randomness,
            receiver_privacy_digest,
            pubscript,
            pubscript_input,
        }];
        let tx: Transaction = global_state
            .create_transaction(receiver_data, 1.into())
            .await
            .unwrap();

        assert!(tx.is_valid());
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
        let mut other_receiver_data = vec![];
        let mut output_utxos: Vec<Utxo> = vec![];
        for i in 2..5 {
            let amount: Amount = i.into();
            let that_many_coins = amount.to_native_coins();
            let receiving_address = other_wallet.nth_generation_spending_key(0).to_address();
            let lock_script = receiving_address.lock_script();
            let utxo = Utxo {
                coins: that_many_coins,
                lock_script_hash: lock_script.hash(),
            };
            let other_sender_randomness = Digest::default();
            let other_receiver_digest = receiving_address.privacy_digest;
            let (other_pubscript, other_pubscript_input) = receiving_address
                .generate_pubscript_and_input(&utxo, other_sender_randomness)
                .unwrap();
            output_utxos.push(utxo.clone());
            other_receiver_data.push(UtxoReceiverData {
                utxo,
                sender_randomness: other_sender_randomness,
                receiver_privacy_digest: other_receiver_digest,
                pubscript: other_pubscript,
                pubscript_input: other_pubscript_input,
            });
        }

        let new_tx: Transaction = global_state
            .create_transaction(other_receiver_data, 1.into())
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
        let network = Network::Alpha;
        let global_state = get_mock_global_state(network, 2, None).await;
        let other_receiver_address = WalletSecret::new(random())
            .nth_generation_spending_key(0)
            .to_address();
        let genesis_block = Block::genesis_block();
        let (mock_block_1, _, _) = make_mock_block(&genesis_block, None, other_receiver_address);
        crate::tests::shared::add_block_to_archival_state(
            global_state.chain.archival_state.as_ref().unwrap(),
            mock_block_1.clone(),
        )
        .await
        .unwrap();
        add_block_to_light_state(&global_state.chain.light_state, mock_block_1.clone())
            .await
            .unwrap();

        // Delete everything from monitored UTXO (the premined UTXO)
        {
            let wallet_db_lock = global_state.wallet_state.wallet_db.lock().await;
            assert!(
                wallet_db_lock.monitored_utxos.len().is_one(),
                "MUTXO must have genesis element before emptying it"
            );
            wallet_db_lock.monitored_utxos.pop();

            assert!(
                wallet_db_lock.monitored_utxos.is_empty(),
                "MUTXO must be empty after emptying it"
            );
        }

        // Recover the MUTXO from the recovery data, and verify that MUTXOs are restored
        global_state
            .restore_monitored_utxos_from_recovery_data()
            .await
            .unwrap();
        {
            let wallet_db_lock = global_state.wallet_state.wallet_db.lock().await;
            assert!(
                wallet_db_lock.monitored_utxos.len().is_one(),
                "MUTXO must have genesis element after recovering it"
            );

            // Verify that the restored MUTXO has a valid MSMP
            let own_premine_mutxo = wallet_db_lock.monitored_utxos.get(0);
            let ms_item = Hash::hash(&own_premine_mutxo.utxo);
            global_state
                .chain
                .light_state
                .get_latest_block()
                .await
                .body
                .next_mutator_set_accumulator
                .verify(
                    ms_item,
                    &own_premine_mutxo
                        .get_latest_membership_proof_entry()
                        .unwrap()
                        .1,
                );
            assert_eq!(
                mock_block_1.hash,
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
        let network = Network::RegTest;
        let global_state = get_mock_global_state(network, 2, None).await;

        let other_receiver_wallet_secret = WalletSecret::new(random());
        let other_receiver_address = other_receiver_wallet_secret
            .nth_generation_spending_key(0)
            .to_address();

        // 1. Create new block 1 and store it to the DB
        let genesis_block = Block::genesis_block();
        let (mock_block_1a, _, _) = make_mock_block(&genesis_block, None, other_receiver_address);
        {
            let mut block_db_lock = global_state
                .chain
                .archival_state
                .as_ref()
                .unwrap()
                .block_index_db
                .lock()
                .await;
            global_state
                .chain
                .archival_state
                .as_ref()
                .unwrap()
                .write_block(
                    Box::new(mock_block_1a.clone()),
                    &mut block_db_lock,
                    Some(mock_block_1a.header.proof_of_work_family),
                )?;
        }

        // Verify that wallet has a monitored UTXO (from genesis)
        let wallet_status = global_state.get_wallet_status_for_tip().await;
        assert!(!wallet_status.synced_unspent_amount.is_zero());

        // Verify that this is unsynced with mock_block_1a
        assert!(
            global_state
                .wallet_state
                .is_synced_to(genesis_block.hash)
                .await
        );
        assert!(
            !global_state
                .wallet_state
                .is_synced_to(mock_block_1a.hash)
                .await
        );

        // Call resync
        global_state
            .resync_membership_proofs_from_stored_blocks(mock_block_1a.hash)
            .await
            .unwrap();

        // Verify that it is synced
        assert!(
            global_state
                .wallet_state
                .is_synced_to(mock_block_1a.hash)
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
        let network = Network::RegTest;
        let global_state = get_mock_global_state(network, 2, None).await;
        let own_spending_key = global_state
            .wallet_state
            .wallet_secret
            .nth_generation_spending_key(0);
        let own_receiving_address = own_spending_key.to_address();

        // 1. Create new block 1a where we receive a coinbase UTXO, store it
        let genesis_block = global_state
            .chain
            .archival_state
            .as_ref()
            .unwrap()
            .get_latest_block()
            .await;
        let (mock_block_1a, coinbase_utxo, coinbase_output_randomness) =
            make_mock_block(&genesis_block, None, own_receiving_address);
        {
            let mut block_db_lock = global_state
                .chain
                .archival_state
                .as_ref()
                .unwrap()
                .block_index_db
                .lock()
                .await;
            global_state
                .chain
                .archival_state
                .as_ref()
                .unwrap()
                .write_block(
                    Box::new(mock_block_1a.clone()),
                    &mut block_db_lock,
                    Some(mock_block_1a.header.proof_of_work_family),
                )?;
            let mut wallet_db_lock = global_state.wallet_state.wallet_db.lock().await;
            global_state
                .wallet_state
                .expected_utxos
                .write()
                .unwrap()
                .add_expected_utxo(
                    coinbase_utxo,
                    coinbase_output_randomness,
                    own_spending_key.privacy_preimage,
                    UtxoNotifier::OwnMiner,
                )
                .unwrap();
            global_state
                .wallet_state
                .update_wallet_state_with_new_block(&mock_block_1a, &mut wallet_db_lock)
                .unwrap();
        }

        // Verify that wallet has monitored UTXOs, from genesis and from block_1a
        let wallet_status = global_state.wallet_state.get_wallet_status_from_lock(
            &mut global_state.wallet_state.wallet_db.lock().await,
            mock_block_1a.hash,
        );
        assert_eq!(2, wallet_status.synced_unspent.len());

        // Make a new fork from genesis that makes us lose the coinbase UTXO of block 1a
        let other_wallet_secret = WalletSecret::new(random());
        let other_receiving_address = other_wallet_secret
            .nth_generation_spending_key(0)
            .to_address();
        let mut parent_block = genesis_block;
        for _ in 0..5 {
            let (next_block, _, _) = make_mock_block(&parent_block, None, other_receiving_address);
            let mut block_db_lock = global_state
                .chain
                .archival_state
                .as_ref()
                .unwrap()
                .block_index_db
                .lock()
                .await;
            global_state
                .chain
                .archival_state
                .as_ref()
                .unwrap()
                .write_block(
                    Box::new(next_block.clone()),
                    &mut block_db_lock,
                    Some(next_block.header.proof_of_work_family),
                )?;
            let mut wallet_db_lock = global_state.wallet_state.wallet_db.lock().await;
            global_state
                .wallet_state
                .update_wallet_state_with_new_block(&next_block, &mut wallet_db_lock)
                .unwrap();
            parent_block = next_block;
        }

        // Call resync which fails to sync the UTXO that was abandoned when block 1a was abandoned
        global_state
            .resync_membership_proofs_from_stored_blocks(parent_block.hash)
            .await
            .unwrap();

        // Verify that one MUTXO is unsynced, and that 1 (from genesis) is synced
        let wallet_status_after_forking = global_state.wallet_state.get_wallet_status_from_lock(
            &mut global_state.wallet_state.wallet_db.lock().await,
            parent_block.hash,
        );
        assert_eq!(1, wallet_status_after_forking.synced_unspent.len());
        assert_eq!(1, wallet_status_after_forking.unsynced_unspent.len());

        // Verify that the MUTXO from block 1a is considered abandoned, and that the one from
        // genesis block is not.
        let wallet_db_lock = global_state.wallet_state.wallet_db.lock().await;
        let monitored_utxos = &wallet_db_lock.monitored_utxos;
        assert!(
            !monitored_utxos
                .get(0)
                .was_abandoned(
                    &parent_block.header,
                    global_state.chain.archival_state.as_ref().unwrap()
                )
                .await
        );
        assert!(
            monitored_utxos
                .get(1)
                .was_abandoned(
                    &parent_block.header,
                    global_state.chain.archival_state.as_ref().unwrap()
                )
                .await
        );

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn resync_ms_membership_proofs_across_stale_fork() -> Result<()> {
        let network = Network::RegTest;
        let global_state = get_mock_global_state(network, 2, None).await;
        let wallet_secret = global_state.wallet_state.wallet_secret.clone();
        let own_spending_key = wallet_secret.nth_generation_spending_key(0);
        let own_receiving_address = own_spending_key.to_address();
        let other_wallet_secret = WalletSecret::new(random());
        let other_receiving_address = other_wallet_secret
            .nth_generation_spending_key(0)
            .to_address();

        // 1. Create new block 1a where we receive a coinbase UTXO, store it
        let genesis_block = global_state
            .chain
            .archival_state
            .as_ref()
            .unwrap()
            .get_latest_block()
            .await;
        assert!(genesis_block.header.height.is_genesis());
        let (mock_block_1a, coinbase_utxo_1a, cb_utxo_output_randomness_1a) =
            make_mock_block(&genesis_block, None, own_receiving_address);
        {
            let mut block_db_lock = global_state
                .chain
                .archival_state
                .as_ref()
                .unwrap()
                .block_index_db
                .lock()
                .await;
            global_state
                .chain
                .archival_state
                .as_ref()
                .unwrap()
                .write_block(
                    Box::new(mock_block_1a.clone()),
                    &mut block_db_lock,
                    Some(mock_block_1a.header.proof_of_work_family),
                )?;
            global_state
                .wallet_state
                .expected_utxos
                .write()
                .unwrap()
                .add_expected_utxo(
                    coinbase_utxo_1a,
                    cb_utxo_output_randomness_1a,
                    own_spending_key.privacy_preimage,
                    UtxoNotifier::OwnMiner,
                )
                .unwrap();
            let mut wallet_db_lock = global_state.wallet_state.wallet_db.lock().await;
            global_state
                .wallet_state
                .update_wallet_state_with_new_block(&mock_block_1a, &mut wallet_db_lock)
                .unwrap();

            // Verify that UTXO was recorded
            let wallet_status_after_1a = global_state
                .wallet_state
                .get_wallet_status_from_lock(&mut wallet_db_lock, mock_block_1a.hash);
            assert_eq!(2, wallet_status_after_1a.synced_unspent.len());
        }

        // Add 5 blocks on top of 1a
        let mut fork_a_block = mock_block_1a.clone();
        for _ in 0..100 {
            let (next_a_block, _, _) =
                make_mock_block(&fork_a_block, None, other_receiving_address);
            let mut block_db_lock = global_state
                .chain
                .archival_state
                .as_ref()
                .unwrap()
                .block_index_db
                .lock()
                .await;
            global_state
                .chain
                .archival_state
                .as_ref()
                .unwrap()
                .write_block(
                    Box::new(next_a_block.clone()),
                    &mut block_db_lock,
                    Some(next_a_block.header.proof_of_work_family),
                )?;
            let mut wallet_db_lock = global_state.wallet_state.wallet_db.lock().await;
            global_state
                .wallet_state
                .update_wallet_state_with_new_block(&next_a_block, &mut wallet_db_lock)
                .unwrap();
            fork_a_block = next_a_block;
        }

        // Verify that all both MUTXOs have synced MPs
        let wallet_status_on_a_fork = global_state.wallet_state.get_wallet_status_from_lock(
            &mut global_state.wallet_state.wallet_db.lock().await,
            fork_a_block.hash,
        );

        assert_eq!(2, wallet_status_on_a_fork.synced_unspent.len());

        // Fork away from the "a" chain to the "b" chain, with block 1a as LUCA
        let mut fork_b_block = mock_block_1a.clone();
        for _ in 0..100 {
            let (next_b_block, _, _) =
                make_mock_block(&fork_b_block, None, other_receiving_address);
            let mut block_db_lock = global_state
                .chain
                .archival_state
                .as_ref()
                .unwrap()
                .block_index_db
                .lock()
                .await;
            global_state
                .chain
                .archival_state
                .as_ref()
                .unwrap()
                .write_block(
                    Box::new(next_b_block.clone()),
                    &mut block_db_lock,
                    Some(next_b_block.header.proof_of_work_family),
                )?;
            let mut wallet_db_lock = global_state.wallet_state.wallet_db.lock().await;
            global_state
                .wallet_state
                .update_wallet_state_with_new_block(&next_b_block, &mut wallet_db_lock)
                .unwrap();
            fork_b_block = next_b_block;
        }

        // Verify that there are zero MUTXOs with synced MPs
        let wallet_status_on_b_fork_before_resync =
            global_state.wallet_state.get_wallet_status_from_lock(
                &mut global_state.wallet_state.wallet_db.lock().await,
                fork_b_block.hash,
            );
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
            .resync_membership_proofs_from_stored_blocks(fork_b_block.hash)
            .await
            .unwrap();
        let wallet_status_on_b_fork_after_resync =
            global_state.wallet_state.get_wallet_status_from_lock(
                &mut global_state.wallet_state.wallet_db.lock().await,
                fork_b_block.hash,
            );
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
                make_mock_block(&fork_c_block, None, other_receiving_address);
            let mut block_db_lock = global_state
                .chain
                .archival_state
                .as_ref()
                .unwrap()
                .block_index_db
                .lock()
                .await;
            global_state
                .chain
                .archival_state
                .as_ref()
                .unwrap()
                .write_block(
                    Box::new(next_c_block.clone()),
                    &mut block_db_lock,
                    Some(next_c_block.header.proof_of_work_family),
                )?;
            let mut wallet_db_lock = global_state.wallet_state.wallet_db.lock().await;
            global_state
                .wallet_state
                .update_wallet_state_with_new_block(&next_c_block, &mut wallet_db_lock)
                .unwrap();
            fork_c_block = next_c_block;
        }

        // Verify that there are zero MUTXOs with synced MPs
        let wallet_status_on_c_fork_before_resync =
            global_state.wallet_state.get_wallet_status_from_lock(
                &mut global_state.wallet_state.wallet_db.lock().await,
                fork_c_block.hash,
            );
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
            .resync_membership_proofs_from_stored_blocks(fork_c_block.hash)
            .await
            .unwrap();
        let wallet_status_on_c_fork_after_resync =
            global_state.wallet_state.get_wallet_status_from_lock(
                &mut global_state.wallet_state.wallet_db.lock().await,
                fork_c_block.hash,
            );
        assert_eq!(1, wallet_status_on_c_fork_after_resync.synced_unspent.len());
        assert_eq!(
            1,
            wallet_status_on_c_fork_after_resync.unsynced_unspent.len()
        );

        // Also check that UTXO from 1a is considered abandoned
        let wallet_db_lock = global_state.wallet_state.wallet_db.lock().await;
        let monitored_utxos = &wallet_db_lock.monitored_utxos;
        assert!(
            !monitored_utxos
                .get(0)
                .was_abandoned(
                    &fork_c_block.header,
                    global_state.chain.archival_state.as_ref().unwrap()
                )
                .await
        );
        assert!(
            monitored_utxos
                .get(1)
                .was_abandoned(
                    &fork_c_block.header,
                    global_state.chain.archival_state.as_ref().unwrap()
                )
                .await
        );

        Ok(())
    }
}
