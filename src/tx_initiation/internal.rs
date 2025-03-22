use std::sync::Arc;

use crate::models::blockchain::transaction::Transaction;
use crate::models::state::transaction_details::TransactionDetails;
use crate::models::state::tx_creation_config::TxCreationConfig;
use crate::tx_initiation::builder::transaction_builder::TransactionBuilder;
use crate::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;

/// note: this is a internal internal (private) API.
///
/// note: this is now just a wrapper around TransactionProofBuilder and
/// TransactionBuilder
pub(crate) async fn create_raw_transaction(
    tx_details_arc: Arc<TransactionDetails>,
    config: TxCreationConfig,
) -> anyhow::Result<Transaction> {
    let proof = TransactionProofBuilder::new()
        .transaction_details(tx_details_arc.clone())
        .job_queue(config.job_queue())
        .proof_job_options(config.proof_job_options())
        .tx_proving_capability(config.prover_capability())
        .build()
        .await?;

    Ok(TransactionBuilder::new()
        .transaction_details(tx_details_arc)
        .transaction_proof(proof)
        .build()?)
}
