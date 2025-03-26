//! a builder for [Transaction] and [TxCreationArtifacts].
//!
//! It is expected that usually callers will prefer to build
//! [TxCreationArtifacts] as it can be used as input for the
//! record_and_broadcast() API.
//!
//! Here is a typical Transaction initiation sequence using
//! the builder API.
//!
//! ```rust
//! fn send_transaction(gsl: GlobalStateLock, recipient: ReceivingAddress, amount: NativeCurrencyAmount, change_policy: ChangePolicy) -> anyhow::Result<()> {
//!
//!    // acquire lock.  write-lock is only needed if we must generate a
//!    // new change receiving address.  However, that is also the most common
//!    // scenario.
//!    let mut state_lock = match change_policy {
//!        ChangePolicy::RecoverToNextUnusedKey { .. } => StateLock::read_guard(&gsl).await,
//!        _ => StateLock::WriteGuard(&mut gsl).await,
//!    };
//!
//!    // select inputs
//!    let tx_inputs = TxInputListBuilder::new()
//!        .spendable_inputs(
//!                state_lock
//!                .gs()
//!                .wallet_spendable_inputs(timestamp)
//!                .await
//!                .into_iter()
//!                .collect(),
//!        )
//!        .policy(InputSelectionPolicy::Random)
//!        .spend_amount(tx_outputs.total_native_coins() + fee)
//!        .build();
//!
//!    // generate outputs
//!    let tx_outputs = TxOutputListBuilder::new()
//!        .output_format(output_format);
//!        .build(&state_lock).await
//!
//!    // generate tx details
//!    let tx_details = TransactionDetailsBuilder::new()
//!        .inputs(tx_inputs.into_iter().into())
//!        .outputs(tx_outputs)
//!        .fee(fee)
//!        .change_policy(change_policy)
//!        .build(&mut state_lock)
//!        .await?;
//!    drop(state_lock);  // release lock asap.
//!
//!    let tx_details_rc = Arc::new(tx_details);
//!
//!    // generate proof
//!    let proof = TransactionProofBuilder::new()
//!        .transaction_details(tx_details_rc.clone())
//!        .job_queue(vm_job_queue())
//!        .tx_proving_capability(gsl.cli().prover_capability())
//!        .build()
//!        .await?;
//!
//!    // assemble transaction
//!    let tx_creation_artifacts = TransactionBuilder::new()
//!        .transaction_details(tx_details_rc.clone())
//!        .transaction_proof(proof)
//!        .build_tx_artifacts(state_lock.gs().cli().network)?;
//!
//!    gsl.tx_initiator().record_and_broadcast_transaction(&tx_creation_artifacts)?;
//! }
//! ```
//!
//! note: the above example fn is very similar to the implementation of [TransactionSender::send()].

use std::sync::Arc;

use crate::config_models::network::Network;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::Transaction;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::state::transaction_details::TransactionDetails;
use crate::tx_initiation::error::CreateTxError;
use crate::tx_initiation::export::TxCreationArtifacts;

#[derive(Debug, Default)]
pub struct TransactionBuilder {
    transaction_details: Option<Arc<TransactionDetails>>,
    transaction_proof: Option<TransactionProof>,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn transaction_details(mut self, transaction_details: Arc<TransactionDetails>) -> Self {
        self.transaction_details = Some(transaction_details);
        self
    }

    pub fn transaction_proof(mut self, transaction_proof: TransactionProof) -> Self {
        self.transaction_proof = Some(transaction_proof);
        self
    }

    pub fn build(self) -> Result<Transaction, CreateTxError> {
        let (Some(tx_details), Some(proof)) = (self.transaction_details, self.transaction_proof)
        else {
            return Err(CreateTxError::MissingRequirement);
        };

        let witness = PrimitiveWitness::from_transaction_details(&tx_details);

        Ok(Transaction {
            kernel: witness.kernel,
            proof,
        })
    }

    /// note: the builder does not validate the resulting artifacts.
    /// caller can do so with TxCreationArtifacts::verify()
    pub fn build_tx_artifacts(
        self,
        network: Network,
    ) -> Result<TxCreationArtifacts, CreateTxError> {
        let (Some(details), Some(proof)) = (self.transaction_details, self.transaction_proof)
        else {
            return Err(CreateTxError::MissingRequirement);
        };

        let witness = PrimitiveWitness::from_transaction_details(&details);

        let transaction = Transaction {
            kernel: witness.kernel,
            proof,
        };

        Ok(TxCreationArtifacts {
            network,
            transaction: Arc::new(transaction),
            details,
        })
    }
}
