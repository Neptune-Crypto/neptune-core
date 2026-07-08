use neptune_consensus::transaction::transaction_kernel::TransactionKernel;
use neptune_consensus::transaction::validity::neptune_proof::NeptuneProof;

use crate::primitive_witness_update::PrimitiveWitnessUpdate;
use crate::transaction_kernel_id::TransactionKernelId;
use crate::transaction_kernel_id::Txid;

/// A task defined by the mempool for updating mutator-set related data for a
/// transaction such that it is valid under a new block.
///
/// Unlike the main loop's `proof_upgrader::UpgradeJob`, this does
/// not contain the mutator-set related data to actually perform the update.
/// That data must be fetched by the caller prior to performing the update.
#[derive(Debug, Clone)]
pub enum MempoolUpdateJob {
    /// The mempool transaction was primitive-witness backed
    PrimitiveWitness(PrimitiveWitnessUpdate),

    /// The transaction was proof-collection backed
    ProofCollection(PrimitiveWitnessUpdate),

    /// The transaction was single-proof backed
    SingleProof {
        old_kernel: TransactionKernel,
        old_single_proof: NeptuneProof,
    },
}

impl MempoolUpdateJob {
    pub fn txid(&self) -> TransactionKernelId {
        match self {
            MempoolUpdateJob::PrimitiveWitness(primitive_witness_update) => {
                primitive_witness_update.old_primitive_witness.kernel.txid()
            }
            MempoolUpdateJob::ProofCollection(primitive_witness_update) => {
                primitive_witness_update.old_primitive_witness.kernel.txid()
            }
            MempoolUpdateJob::SingleProof { old_kernel, .. } => old_kernel.txid(),
        }
    }
}
