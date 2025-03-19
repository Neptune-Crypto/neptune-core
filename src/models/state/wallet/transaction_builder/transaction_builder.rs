use std::sync::Arc;

use crate::models::state::PrimitiveWitness;
use crate::models::state::Transaction;
use crate::models::state::TransactionDetails;
use crate::models::state::TransactionProof;

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

    pub fn build(self) -> anyhow::Result<Transaction> {
        let (Some(tx_details), Some(proof)) = (self.transaction_details, self.transaction_proof)
        else {
            anyhow::bail!("cannot build: missing component(s)");
        };

        let kernel = PrimitiveWitness::from_transaction_details(&tx_details).kernel;

        Ok(Transaction { kernel, proof })
    }
}
