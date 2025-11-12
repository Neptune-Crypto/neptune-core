use std::ops::Deref;
use std::sync::Arc;

use crate::api::export::Transaction;
use crate::api::export::TransactionProof;
use crate::application::triton_vm_job_queue::TritonVmJobQueue;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::validity::tasm::single_proof::merge_branch::MergeWitness;
use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;

/// Newtype for [`TransactionKernel`] where removal records are packed. For use
/// in the context of [`BlockTransaction`]s. See [`BlockTransaction`] for more
/// documentation. The difference between regular [`Transaction`]s and
/// [`BlockTransaction`]s is contained in the kernel, which is why
/// [`BlockTransaction`] has a custom kernel type but not a custom proof type.
#[derive(Debug, Clone)]
pub(crate) struct BlockTransactionKernel(TransactionKernel);

impl Deref for BlockTransactionKernel {
    type Target = TransactionKernel;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<BlockTransactionKernel> for TransactionKernel {
    fn from(value: BlockTransactionKernel) -> Self {
        value.0
    }
}

impl TryFrom<TransactionKernel> for BlockTransactionKernel {
    type Error = ();

    fn try_from(value: TransactionKernel) -> Result<Self, Self::Error> {
        match value.merge_bit {
            true => Ok(Self(value)),
            false => Err(()),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum BlockOrRegularTransactionKernel {
    Block(BlockTransactionKernel),
    Regular(TransactionKernel),
}

impl From<BlockOrRegularTransactionKernel> for TransactionKernel {
    fn from(value: BlockOrRegularTransactionKernel) -> Self {
        match value {
            BlockOrRegularTransactionKernel::Block(block_transaction_kernel) => {
                block_transaction_kernel.0
            }
            BlockOrRegularTransactionKernel::Regular(transaction_kernel) => transaction_kernel,
        }
    }
}

/// Essentially a newtype for [`Transaction`], specifically for use in the
/// context of *the* transaction in a given block. Contains packed removal
/// records.
///
/// The point about packing is that it does not change type: this operation maps
/// a `Vec<RemovalRecord>` to a `Vec<RemovalRecord>` purely by removing
/// redundant information that can later be added back cheaply.
#[derive(Debug, Clone)]
pub(crate) struct BlockTransaction {
    pub(crate) kernel: BlockTransactionKernel,
    pub(crate) proof: TransactionProof,
}

impl TryFrom<Transaction> for BlockTransaction {
    type Error = ();

    fn try_from(value: Transaction) -> Result<Self, Self::Error> {
        Ok(Self {
            kernel: value.kernel.try_into()?,
            proof: value.proof,
        })
    }
}

impl From<BlockTransaction> for Transaction {
    fn from(value: BlockTransaction) -> Self {
        Self {
            kernel: value.kernel.0,
            proof: value.proof,
        }
    }
}

/// A transaction, but when it is undefined or unknown whether it is a
/// regular [`Transaction`] or a [`BlockTransaction`].
#[derive(Debug, Clone)]
pub(crate) enum BlockOrRegularTransaction {
    Block(BlockTransaction),
    Regular(Transaction),
}

impl BlockOrRegularTransaction {
    pub(crate) fn kernel(&self) -> BlockOrRegularTransactionKernel {
        match self {
            BlockOrRegularTransaction::Block(block_transaction) => {
                BlockOrRegularTransactionKernel::Block(block_transaction.kernel.clone())
            }
            BlockOrRegularTransaction::Regular(transaction) => {
                BlockOrRegularTransactionKernel::Regular(transaction.kernel.clone())
            }
        }
    }

    pub(crate) fn proof(&self) -> TransactionProof {
        match self {
            BlockOrRegularTransaction::Block(block_transaction) => block_transaction.proof.clone(),
            BlockOrRegularTransaction::Regular(transaction) => transaction.proof.clone(),
        }
    }
}

impl From<Transaction> for BlockOrRegularTransaction {
    fn from(value: Transaction) -> Self {
        BlockOrRegularTransaction::Regular(value)
    }
}

impl From<BlockTransaction> for BlockOrRegularTransaction {
    fn from(value: BlockTransaction) -> Self {
        BlockOrRegularTransaction::Block(value)
    }
}

impl TryFrom<BlockOrRegularTransaction> for BlockTransaction {
    type Error = ();

    fn try_from(value: BlockOrRegularTransaction) -> Result<Self, Self::Error> {
        match value {
            BlockOrRegularTransaction::Block(block_transaction) => Ok(block_transaction),
            BlockOrRegularTransaction::Regular(_) => Err(()),
        }
    }
}

impl From<BlockOrRegularTransaction> for Transaction {
    fn from(value: BlockOrRegularTransaction) -> Self {
        match value {
            BlockOrRegularTransaction::Block(block_transaction) => Self {
                kernel: block_transaction.kernel.into(),
                proof: block_transaction.proof,
            },
            BlockOrRegularTransaction::Regular(transaction) => transaction,
        }
    }
}

impl BlockTransaction {
    /// Merge a [`BlockTransaction`] or a regular [`Transaction`] with a
    /// regular [`Transaction`], resulting in a [`BlockTransaction`].
    ///
    /// See also: [`Transaction::merge_with`], which should be used if
    ///  - a) the arguments are two regular [`Transaction`]s; and
    ///  - b) the result must be a regular [`Transaction`] as well.
    pub(crate) async fn merge(
        coinbase: BlockOrRegularTransaction,
        other: Transaction,
        shuffle_seed: [u8; 32],
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
        #[expect(unused_variables, reason = "anticipate future fork")]
        consensus_rule_set: ConsensusRuleSet,
    ) -> anyhow::Result<BlockTransaction> {
        let merge_witness = MergeWitness::for_composition(coinbase, other, shuffle_seed);
        let tx = MergeWitness::merge(merge_witness, triton_vm_job_queue, proof_job_options).await?;

        Ok(tx.try_into().expect("Must have merge bit set"))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::util_types::mutator_set::removal_record::removal_record_list::RemovalRecordList;

    impl BlockTransaction {
        /// Upgrade a regular [`Transaction`] into a [`BlockTransaction`] by
        /// setting the merge bit and packing the removal records. If a proof is
        /// supplied, it will (probably) become invalid. Use only in tests where
        /// the proof does not matter.
        pub(crate) fn upgrade(tx: Transaction) -> Self {
            let packed = RemovalRecordList::pack(tx.kernel.inputs.clone());
            let kernel = TransactionKernelModifier::default()
                .merge_bit(true)
                .inputs(packed)
                .modify(tx.kernel);
            let transaction = Transaction {
                kernel,
                proof: tx.proof,
            };
            Self::try_from(transaction).expect("just set merge bit")
        }

        /// Produce an invalid [`BlockTransaction`] from a transaction kernel.
        /// Is guaranteed to have an invalid transaction proof. Use only in
        /// tests.
        pub(crate) fn from_tx_kernel(kernel: TransactionKernel) -> Self {
            let packed = RemovalRecordList::pack(kernel.inputs.clone());
            let kernel = TransactionKernelModifier::default()
                .merge_bit(true)
                .inputs(packed)
                .modify(kernel);
            let transaction = Transaction {
                kernel,
                proof: TransactionProof::invalid(),
            };
            Self::try_from(transaction).expect("just set merge bit")
        }
    }
}
