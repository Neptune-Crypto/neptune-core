use std::sync::Arc;

use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::Transaction;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::state::transaction_details::TransactionDetails;
use crate::tx_initiation::error::CreateTxError;

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

        let kernel = PrimitiveWitness::from_transaction_details(&tx_details).kernel;

        Ok(Transaction { kernel, proof })
    }
}
