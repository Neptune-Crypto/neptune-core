use crate::api::export::NeptuneProof;
use crate::api::export::TransactionKernelId;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::state::mempool::primitive_witness_update::PrimitiveWitnessUpdate;

/// A task defined by the mempool for updating mutator-set related data for a
/// transaction such that it is valid under a new block.
///
/// Unlike
/// [`crate::application::loops::main_loop::proof_upgrader::UpgradeJob`] does
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
    pub(crate) fn txid(&self) -> TransactionKernelId {
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
