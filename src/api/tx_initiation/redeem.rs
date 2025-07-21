//! Provides an easy-to-use API for producing UTXO redemption claims.
//!
//! A UTXO redemption claim is a special transaction satisfying the following
//! constraints:
//!  1. It is backed by a `ProofCollection` only -- no `SingleProof`s.
//!  2. It contains only one or two outputs, the first one without time-lock and
//!     if two the second is time-locked to the earliest release date of all
//!     inputs.
//!  3. The `public_announcements` field contains the plaintext UTXO preimage to
//!     this output along with the [`GenerationReceivingAddress`] that it is
//!     linked to.
//!  4. All spendable inputs are spent. There is no change.
//!  5. All time-locked inputs are spent into the time-locked output.
//!  6. There is no UTXO notification.
//!
//! This API is analogous to [`tx_initiation/send.rs`](super::send).
//!

use std::path::PathBuf;

use itertools::Itertools;
use num_traits::CheckedSub;
use rand::rng;
use rand::Rng;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use thiserror::Error;
use tokio::fs;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

use crate::api::export::ChangePolicy;
use crate::api::export::GlobalStateLock;
use crate::api::export::NativeCurrencyAmount;
use crate::api::export::Network;
use crate::api::export::RedemptionReport;
use crate::api::export::StateLock;
use crate::api::export::Timestamp;
use crate::api::export::Transaction;
use crate::api::export::TransactionDetails;
use crate::api::export::TransactionProofType;
use crate::api::tx_initiation::builder::transaction_builder::TransactionBuilder;
use crate::api::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
use crate::api::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
use crate::api::tx_initiation::builder::tx_input_list_builder::TxInputListBuilder;
use crate::api::tx_initiation::error::CreateTxError;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::transaction::public_announcement::PublicAnnouncement;
use crate::models::blockchain::transaction::utxo::Coin;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::utxo_triple::UtxoTriple;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::models::state::wallet::address::generation_address::GenerationReceivingAddress;
use crate::models::state::wallet::transaction_output::TxOutput;
use crate::triton_vm_job_queue::vm_job_queue;
use crate::util_types::mutator_set::removal_record::AbsoluteIndexSet;
use crate::util_types::mutator_set::removal_record::RemovalRecord;
use crate::util_types::mutator_set::shared::CHUNK_SIZE;
use crate::util_types::mutator_set::shared::WINDOW_SIZE;

/// provides a redeem_utxos() method to produce the UTXO redemption transaction.
#[derive(Debug, Clone)]
pub struct Redeemer {
    global_state_lock: GlobalStateLock,
}

impl From<GlobalStateLock> for Redeemer {
    fn from(global_state_lock: GlobalStateLock) -> Self {
        Self { global_state_lock }
    }
}

#[derive(Debug, Clone, Error)]
pub enum RedeemError {
    #[error("transaction initiation is disabled")]
    TransactionInitiationDisabled,
    #[error("node's proving capability is too weak")]
    ProverCapabilityTooWeak,
    #[error("create transaction error: {0}")]
    CreateTxError(CreateTxError),
}

impl From<CreateTxError> for RedeemError {
    fn from(value: CreateTxError) -> Self {
        Self::CreateTxError(value)
    }
}

impl Redeemer {
    /// Determines whether we can proceed to produce the UTXO redemption claim.
    fn can_proceed(&self) -> Result<(), RedeemError> {
        if self.global_state_lock.cli().no_transaction_initiation {
            tracing::warn!(
                "Cannot produce UTXO redemption claim because `--no-transaction-initiation` flag is set."
            );
            return Err(RedeemError::TransactionInitiationDisabled);
        }

        let capability = self.global_state_lock.cli().proving_capability();
        let proof_type = TransactionProofType::ProofCollection;
        let network = self.global_state_lock.cli().network;
        if !network.use_mock_proof() && !capability.can_prove(proof_type) {
            tracing::warn!(
                "Cannot produce UTXO redemption claim because transaction proving capability is too weak."
            );
            return Err(RedeemError::ProverCapabilityTooWeak);
        }
        Ok(())
    }

    /// Produce a UTXO redemption claim.
    ///
    /// Producing a UTXO redemption claim is an expensive task as it involves
    /// producing many proofs. It is therefore advisable to spawn the task in
    /// the background and return to the user interface server (RPC server) as
    /// quickly as possible and let the task run on its own schedule.
    //
    // This function is a spawn wrapper around [`Self::assemble_data`].
    pub fn start_redeeming_utxos(
        self,
        directory: PathBuf,
        address: Option<GenerationReceivingAddress>,
        timestamp: Timestamp,
    ) -> Result<(), RedeemError> {
        self.can_proceed()?;

        let _handle = tokio::task::spawn(async move {
            self.redeem_utxos(directory, address, timestamp).await;
        });

        Ok(())
    }

    /// Produce a UTXO redemption claim.
    async fn redeem_utxos(
        self,
        directory: PathBuf,
        address: Option<GenerationReceivingAddress>,
        timestamp: Timestamp,
    ) {
        let tx_details = match self.assemble_data(address, timestamp).await {
            Ok(txd) => txd,
            Err(e) => {
                tracing::error!("Could not assemble data for UTXO redemption claim: {}", e);
                return;
            }
        };

        let job_options = self.global_state_lock.cli().as_proof_job_options();

        Self::worker(directory, tx_details, job_options).await;
    }

    async fn assemble_data(
        &self,
        destination_address: Option<GenerationReceivingAddress>,
        timestamp: Timestamp,
    ) -> Result<TransactionDetails, RedeemError> {
        let gsl = &self.global_state_lock;

        tracing::info!("Assembling data for UTXO redemption claim ...");

        // Acquire lock. Write-lock is unnecessary because we do not need to
        // generate new addresses.
        let mut state_lock = StateLock::read_guard(gsl).await;

        // Determine amount. Entire spendable balance.
        let total_amount = state_lock
            .gs()
            .get_wallet_status_for_tip()
            .await
            .synced_unspent_available_amount(timestamp);

        // Select inputs. Wipe them out. All of them.
        let tx_inputs = TxInputListBuilder::new()
            .spendable_inputs(
                state_lock
                    .gs()
                    .wallet_spendable_inputs(timestamp)
                    .await
                    .into_iter()
                    .collect(),
            )
            .policy(crate::api::export::InputSelectionPolicy::ByProvidedOrder)
            .spend_amount(total_amount)
            .build()
            .into_iter()
            .collect_vec();

        // Determine time-locked amount.
        let timelocked_amount = tx_inputs
            .iter()
            .filter(|txinput| txinput.utxo.release_date().is_some())
            .map(|txinput| txinput.utxo.get_native_currency_amount())
            .sum::<NativeCurrencyAmount>();

        // Determine liquid amount: difference between time-locked and total.
        let liquid_amount = total_amount.checked_sub(&timelocked_amount).unwrap();

        // Determine release date: earliest of all time-locks (if any).
        let earliest_release_date = tx_inputs
            .iter()
            .filter_map(|tx_input| tx_input.utxo.release_date())
            .min();

        // Determine recipient address.
        let recipient = destination_address.unwrap_or_else(|| {
            state_lock
                .gs()
                .wallet_state
                .wallet_entropy
                .nth_generation_spending_key(0)
                .to_address()
        });

        // Generate outputs. No notifications.
        let liquid_utxo = Utxo::new(
            recipient.lock_script(),
            vec![Coin::new_native_currency(liquid_amount)],
        );
        let [liquid_sender_randomness, liquid_privacy_digest, timelocked_sender_randomness, timelocked_privacy_digest] = {
            // Keep thread-unsafe RNG inside of a sync scope to avoid async
            // issues.
            let mut rng = rng();
            [
                rng.random::<Digest>(),
                rng.random::<Digest>(),
                rng.random::<Digest>(),
                rng.random::<Digest>(),
            ]
        };
        let liquid_output = TxOutput::no_notification_as_change(
            liquid_utxo,
            liquid_sender_randomness,
            liquid_privacy_digest,
        );
        let mut tx_outputs = vec![liquid_output];
        if let Some(release_date) = earliest_release_date {
            let timelocked_utxo = Utxo::new(
                recipient.lock_script(),
                vec![Coin::new_native_currency(timelocked_amount)],
            )
            .with_time_lock(release_date);
            let timelocked_output = TxOutput::no_notification_as_change(
                timelocked_utxo,
                timelocked_sender_randomness,
                timelocked_privacy_digest,
            );
            tx_outputs.push(timelocked_output);
        }

        // Add plaintext output UTXOs as public announcements.
        let mut public_announcements = vec![];
        for tx_output in &tx_outputs {
            let utxo_triple = UtxoTriple::from(tx_output.clone());
            let public_announcement = PublicAnnouncement {
                message: utxo_triple.encode(),
            };
            public_announcements.push(public_announcement);
        }

        // Add the receiving address as public announcement.
        public_announcements.push(PublicAnnouncement {
            message: recipient.encode(),
        });

        // Generate transaction details. No change, so no risk of changing
        // outputs.
        let transaction_details = TransactionDetailsBuilder::new()
            .inputs(tx_inputs.into())
            .outputs(tx_outputs.into())
            .fee(NativeCurrencyAmount::coins(0))
            .change_policy(ChangePolicy::ExactChange)
            .public_announcements(public_announcements)
            .build(&mut state_lock)
            .await
            .map_err(RedeemError::from)?;

        tracing::info!("Done assembling data for UTXO redemption claim.");

        Ok(transaction_details)
    }

    async fn worker(
        directory: PathBuf,
        tx_details: TransactionDetails,
        mut job_options: TritonVmProofJobOptions,
    ) {
        // Contrary to `TransactionSender::send`, we choose `ProofCollection`
        // here because
        //  a) we are running in a separate task already and therefore can
        //     afford to do expensive proving; and
        //  b) we need a `ProofCollection` (and not a `PrimitiveWitness` or a
        //     `SingleProof`) for the resulting transaction.
        let target_proof_type = TransactionProofType::ProofCollection;
        job_options.job_settings.proof_type = target_proof_type;

        let witness = tx_details.primitive_witness();
        let kernel = witness.kernel.clone();

        // Generate proofs. (ProofCollection only.)
        tracing::info!("Generating proofs ...");
        let proof = match TransactionProofBuilder::new()
            .transaction_details(&tx_details)
            .primitive_witness(witness)
            .job_queue(vm_job_queue())
            .proof_job_options(job_options)
            .build()
            .await
        {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("Could not generate proofs: {e}");
                return;
            }
        };
        tracing::info!("Done generating proofs.");

        // Create transaction.
        let transaction = match TransactionBuilder::new()
            .transaction_kernel(kernel)
            .transaction_proof(proof)
            .build()
        {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("Could not build transaction: {e}");
                return;
            }
        };

        // Store transaction.
        let filename = transaction.kernel.mast_hash().to_hex();
        let suffix = "redeem".to_string();
        let mut path = directory;
        path.push(filename);
        path.set_extension(suffix);
        let mut file = match File::create(path.clone()).await {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(
                    "Could not open or create file `{}` for writing: {e}",
                    path.to_string_lossy()
                );
                return;
            }
        };
        let serialized_transaction = match bincode::serialize(&transaction) {
            Ok(stx) => stx,
            Err(e) => {
                tracing::error!("Could not serialize transaction: {e}");
                return;
            }
        };
        match file.write_all(&serialized_transaction).await {
            Ok(_) => (),
            Err(e) => {
                tracing::error!("Could not write to file: {e}");
            }
        };

        tracing::info!(
            "UTXO redemption claim successfully produced and written to disk at `{}`.",
            path.to_string_lossy()
        );
    }

    /// Validate many UTXO redemption claims. Verify that they are valid
    /// transactions and mutually compatible. Produce a report.
    pub async fn validate_redemption(
        &self,
        directory: PathBuf,
    ) -> Result<RedemptionReport, RedemptionValidationError> {
        // read claims from disk
        let redemption_claims = Self::load_redemption_claims_from_directory(directory).await?;

        // validate claims individually
        let mut invalid_claims = vec![];
        let network = Network::Main;
        for (file_path, transaction) in &redemption_claims {
            if !transaction.is_valid(network).await {
                invalid_claims.push((file_path, transaction));
            }
        }
        if !invalid_claims.is_empty() {
            let file_names_of_invalid_claims = invalid_claims
                .into_iter()
                .map(|(file_path, _tx)| file_path)
                .cloned()
                .collect_vec();
            return Err(RedemptionValidationError::InvalidClaims(
                file_names_of_invalid_claims,
            ));
        }

        // validate synchronization to current mutator set hash
        let mut mutator_set_accumulator = self
            .global_state_lock
            .lock_guard()
            .await
            .chain
            .light_state()
            .mutator_set_accumulator_after()
            .map_err(|_e| RedemptionValidationError::InvalidChainState)?;
        let mutator_set_hash = mutator_set_accumulator.hash();
        let mut unsynced_claims = vec![];
        for (file_path, transaction) in &redemption_claims {
            if transaction.kernel.mutator_set_hash != mutator_set_hash {
                unsynced_claims.push((file_path, transaction));
            }
        }
        if !unsynced_claims.is_empty() {
            let file_names_of_unsynced_claims = unsynced_claims
                .into_iter()
                .map(|(file_path, _tx)| file_path)
                .cloned()
                .collect_vec();
            return Err(RedemptionValidationError::UnsyncedClaims(
                file_names_of_unsynced_claims,
            ));
        }

        // validate earliest possible AOCL leaf indices
        let absolute_index_set_to_earliest_possible_aocl_leaf_index =
            |absolute_index_set: AbsoluteIndexSet| {
                let max_absolute_index = absolute_index_set.to_array().into_iter().max().unwrap();
                let window_start = max_absolute_index.next_multiple_of(u128::from(CHUNK_SIZE))
                    - u128::from(WINDOW_SIZE);
                u64::try_from(window_start / u128::from(CHUNK_SIZE))
                    .expect("mutator set arithmetic guarantees that AOCL indices are valid u64s")
            };
        let num_utxos_in_premine = Block::premine_utxos(network).len();
        let mut all_removal_records = redemption_claims
            .iter()
            .flat_map(|(_fp, tx)| tx.kernel.inputs.clone())
            .collect_vec();
        for removal_record in &all_removal_records {
            let earliest_possible_aocl_leaf_index =
                absolute_index_set_to_earliest_possible_aocl_leaf_index(
                    removal_record.absolute_indices,
                );
            if earliest_possible_aocl_leaf_index < u64::try_from(num_utxos_in_premine).unwrap() {
                return Err(RedemptionValidationError::PotentialPremineClaim(
                    earliest_possible_aocl_leaf_index,
                ));
            }
        }

        // validate mutual compatibility with mutator set
        while let Some(removal_record) = all_removal_records.pop() {
            if !mutator_set_accumulator.can_remove(&removal_record) {
                return Err(RedemptionValidationError::MutuallyIncompatibleClaims);
            }
            RemovalRecord::batch_update_from_remove(
                &mut all_removal_records.iter_mut().collect_vec(),
                &removal_record,
            );
            mutator_set_accumulator.remove(&removal_record);
        }

        // parse claims; validate public announcements; produce report
        let mut report = RedemptionReport::new();
        for (file_path, transaction) in redemption_claims {
            let mut utxo_triples = vec![];
            let mut destination = None;
            for (j, public_announcement) in
                transaction.kernel.public_announcements.iter().enumerate()
            {
                let address_parse_result =
                    GenerationReceivingAddress::decode(&public_announcement.message);
                let utxo_parse_result = UtxoTriple::decode(&public_announcement.message);

                if address_parse_result.is_err() && utxo_parse_result.is_err() {
                    return Err(RedemptionValidationError::UnparsablePublicAnnouncement(
                        file_path, j,
                    ));
                }

                if let Ok(utxo_triple) = utxo_parse_result {
                    if !transaction
                        .kernel
                        .outputs
                        .contains(&utxo_triple.addition_record())
                    {
                        return Err(RedemptionValidationError::UtxoNotOutput(file_path, j));
                    }
                    utxo_triples.push(*utxo_triple);
                }

                if let Ok(address) = address_parse_result {
                    destination = Some(*address);
                }
            }

            let Some(destination) = destination else {
                return Err(RedemptionValidationError::MissingDestinationAddress);
            };

            for utxo_triple in utxo_triples {
                report.add_row(
                    utxo_triple.utxo().get_native_currency_amount(),
                    utxo_triple.utxo().release_date(),
                    destination,
                );
            }
        }

        Ok(report)
    }

    async fn load_redemption_claims_from_directory(
        dir: PathBuf,
    ) -> Result<Vec<(PathBuf, Transaction)>, RedemptionValidationError> {
        let mut transactions = Vec::new();
        let mut rd = fs::read_dir(&dir)
            .await
            .map_err(RedemptionValidationError::ReadDir)?;
        while let Some(entry) = rd
            .next_entry()
            .await
            .map_err(RedemptionValidationError::ReadDir)?
        {
            let file_path = entry.path();
            // skip directories
            let metadata = fs::metadata(&file_path)
                .await
                .map_err(|e| RedemptionValidationError::FileRead(file_path.clone(), e))?;
            if !metadata.is_file() {
                continue;
            }

            let bytes = fs::read(&file_path)
                .await
                .map_err(|e| RedemptionValidationError::FileRead(file_path.clone(), e))?;

            let transaction = bincode::deserialize::<Transaction>(&bytes)
                .map_err(|e| RedemptionValidationError::Deserialize(file_path.clone(), e))?;

            transactions.push((file_path, transaction));
        }
        Ok(transactions)
    }
}

#[derive(Debug, Error)]
pub enum RedemptionValidationError {
    #[error("error reading directory: {0}")]
    ReadDir(#[from] std::io::Error),
    #[error("error reading file '{0}': {1}")]
    FileRead(PathBuf, #[source] std::io::Error),
    #[error("failed to deserialize file `{0}`: {1}")]
    Deserialize(PathBuf, #[source] Box<bincode::ErrorKind>),
    #[error("chain state is invalid: could not produce mutator set accumulator after")]
    InvalidChainState,
    #[error("invalid claims:\n{0:#?}")]
    InvalidClaims(Vec<PathBuf>),
    #[error("unsynced claims:\n{0:#?}")]
    UnsyncedClaims(Vec<PathBuf>),
    #[error("one or more claims are mutually incompatible")]
    MutuallyIncompatibleClaims,
    #[error("potential premine claim: lower bound on AOCL leaf index is {0} < num premine UTXOs")]
    PotentialPremineClaim(u64),
    #[error("public announcement {1} of {0} cannot be parsed as UTXO or address")]
    UnparsablePublicAnnouncement(PathBuf, usize),
    #[error("parsed UTXO of public announcement {1} of {0} is not present in transaction outputs")]
    UtxoNotOutput(PathBuf, usize),
    #[error("destination address is missing")]
    MissingDestinationAddress,
}
