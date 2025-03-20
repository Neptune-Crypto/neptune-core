use std::sync::Arc;

use crate::job_queue::triton_vm::TritonVmJobQueue;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::validity::proof_collection::ProofCollection;
use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::models::state::transaction_details::TransactionDetails;
use crate::models::state::tx_proving_capability::TxProvingCapability;

#[derive(Debug, Default)]
pub struct TransactionProofBuilder {
    transaction_details: Option<Arc<TransactionDetails>>,
    job_queue: Option<Arc<TritonVmJobQueue>>,
    proof_job_options: TritonVmProofJobOptions,
    tx_proving_capability: TxProvingCapability,
    proof_type: Option<TxProvingCapability>,
}

impl TransactionProofBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn transaction_details(mut self, transaction_details: Arc<TransactionDetails>) -> Self {
        self.transaction_details = Some(transaction_details);
        self
    }

    pub fn job_queue(mut self, job_queue: Arc<TritonVmJobQueue>) -> Self {
        self.job_queue = Some(job_queue);
        self
    }

    pub fn proof_job_options(mut self, proof_job_options: TritonVmProofJobOptions) -> Self {
        self.proof_job_options = proof_job_options;
        self
    }

    pub fn proof_type(mut self, proof_type: TxProvingCapability) -> Self {
        self.proof_type = Some(proof_type);
        self
    }

    pub fn tx_proving_capability(mut self, tx_proving_capability: TxProvingCapability) -> Self {
        self.tx_proving_capability = tx_proving_capability;
        self
    }

    // fn build(self) -> Result<TransactionProof, TransactionProofBuildError> {
    pub async fn build(self) -> anyhow::Result<TransactionProof> {
        let (Some(tx_details), Some(job_queue)) = (self.transaction_details, self.job_queue) else {
            anyhow::bail!("cannot build: missing component(s)");
        };

        let TransactionProofBuilder {
            proof_job_options,
            proof_type,
            tx_proving_capability,
            ..
        } = self;

        // if proof_type is not provided, then we default to the max we are
        // capable of.
        let proof_type = proof_type.unwrap_or(tx_proving_capability);

        if !tx_proving_capability.can_prove(proof_type) {
            anyhow::bail!("cannot build: insufficient proving capability");
        }

        let primitive_witness = PrimitiveWitness::from_transaction_details(&tx_details);

        let transaction_proof = match proof_type {
            TxProvingCapability::PrimitiveWitness => TransactionProof::Witness(primitive_witness),
            TxProvingCapability::LockScript => todo!(),
            TxProvingCapability::ProofCollection => TransactionProof::ProofCollection(
                ProofCollection::produce(&primitive_witness, job_queue, proof_job_options).await?,
            ),
            TxProvingCapability::SingleProof => TransactionProof::SingleProof(
                SingleProof::produce(&primitive_witness, job_queue, proof_job_options).await?,
            ),
        };

        Ok(transaction_proof)
    }
}
