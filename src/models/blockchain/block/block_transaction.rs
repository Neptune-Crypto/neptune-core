use std::ops::Deref;

use crate::api::export::Transaction;
use crate::api::export::TransactionProof;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;

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

#[cfg(test)]
pub(crate) mod tests {
    use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelModifier;

    use super::*;

    impl BlockTransaction {
        /// Upgrade a regular [`Transaction`] into a [`BlockTransaction`] by
        /// setting the merge bit. If a proof is supplied, it may become
        /// invalid. Use only in tests where the proof does not matter.
        pub(crate) fn upgrade(tx: Transaction) -> Self {
            let kernel = TransactionKernelModifier::default()
                .merge_bit(true)
                .modify(tx.kernel);
            let transaction = Transaction {
                kernel,
                proof: tx.proof,
            };
            Self::try_from(transaction).expect("just set merge bit")
        }
    }
}
