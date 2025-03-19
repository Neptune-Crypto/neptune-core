use std::sync::Arc;

use crate::job_queue::triton_vm::TritonVmJobQueue;
use crate::models::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::models::state::PrimitiveWitness;
use crate::models::state::ProofCollection;
use crate::models::state::SingleProof;
use crate::models::state::TransactionDetails;
use crate::models::state::TransactionProof;
use crate::models::state::TxProvingCapability;

#[derive(Debug, Default)]
pub struct TransactionProofBuilder {
    transaction_details: Option<Arc<TransactionDetails>>,
    job_queue: Option<Arc<TritonVmJobQueue>>,
    proof_job_options: TritonVmProofJobOptions,
    tx_proving_capability: TxProvingCapability,
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
            tx_proving_capability,
            ..
        } = self;

        let primitive_witness = PrimitiveWitness::from_transaction_details(&tx_details);

        let transaction_proof = match tx_proving_capability {
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
