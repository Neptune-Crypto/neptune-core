use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;

use anyhow::ensure;
use neptune_mutator_set::removal_record::removal_record_list::RemovalRecordList;
use neptune_mutator_set::removal_record::RemovalRecord;

use crate::consensus_rule_set::ConsensusRuleSet;
use crate::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::proof_abstractions::triton_vm_job_queue::TritonVmJobQueue;
use crate::transaction::transaction_kernel::TransactionKernel;
use crate::transaction::transaction_proof::TransactionProof;
use crate::transaction::validity::tasm::single_proof::merge_branch::bound_time_diff::BoundTimeDiff;
use crate::transaction::validity::tasm::single_proof::merge_branch::MergeWitness;
use crate::transaction::Transaction;

/// Newtype for [`TransactionKernel`] where removal records are packed. For use
/// in the context of [`BlockTransaction`]s. See [`BlockTransaction`] for more
/// documentation. The difference between regular [`Transaction`]s and
/// [`BlockTransaction`]s is contained in the kernel, which is why
/// [`BlockTransaction`] has a custom kernel type but not a custom proof type.
#[derive(Debug, Clone)]
pub struct BlockTransactionKernel(TransactionKernel);

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
pub enum BlockOrRegularTransactionKernel {
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

impl Deref for BlockOrRegularTransactionKernel {
    type Target = TransactionKernel;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Block(kernel) => kernel,
            Self::Regular(kernel) => kernel,
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
pub struct BlockTransaction {
    pub(crate) kernel: BlockTransactionKernel,
    pub(crate) proof: TransactionProof,

    /// The transaction kernel's inputs, packed. With packed chunks. Retains the
    /// chunk witness data in case the block rules strip this data from the
    /// block.
    pub(crate) inputs_with_chunk_data: Vec<RemovalRecord>,
}

impl TryFrom<Transaction> for BlockTransaction {
    type Error = ();

    /// Assumes the kernel's inputs carry their chunk data.
    fn try_from(value: Transaction) -> Result<Self, Self::Error> {
        Ok(Self {
            inputs_with_chunk_data: value.kernel.inputs.clone(),
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
pub enum BlockOrRegularTransaction {
    Block(BlockTransaction),
    Regular(Transaction),
}

impl BlockOrRegularTransaction {
    pub fn kernel(&self) -> BlockOrRegularTransactionKernel {
        match self {
            BlockOrRegularTransaction::Block(block_transaction) => {
                BlockOrRegularTransactionKernel::Block(block_transaction.kernel.clone())
            }
            BlockOrRegularTransaction::Regular(transaction) => {
                BlockOrRegularTransactionKernel::Regular(transaction.kernel.clone())
            }
        }
    }

    pub fn proof(&self) -> TransactionProof {
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
    /// Construct a [`BlockTransaction`] from its kernel and proof. Assumes the
    /// kernel's inputs contain chunk data.
    pub fn new(kernel: BlockTransactionKernel, proof: TransactionProof) -> Self {
        Self {
            inputs_with_chunk_data: kernel.inputs.clone(),
            kernel,
            proof,
        }
    }

    /// The transaction kernel of this block transaction.
    pub fn kernel(&self) -> &TransactionKernel {
        &self.kernel
    }

    /// The proof of this block transaction.
    pub fn proof(&self) -> &TransactionProof {
        &self.proof
    }

    /// The kernel's inputs, packed, with their chunk data, even where the
    /// kernel does not contain it.
    pub fn inputs_with_chunk_data(&self) -> &[RemovalRecord] {
        &self.inputs_with_chunk_data
    }

    /// Merge a [`BlockTransaction`] or a regular [`Transaction`] with a
    /// regular [`Transaction`], resulting in a [`BlockTransaction`].
    ///
    /// See also: [`Transaction::merge_with`], which should be used if
    ///  - a) the arguments are two regular [`Transaction`]s; and
    ///  - b) the result must be a regular [`Transaction`] as well.
    pub async fn merge(
        coinbase: BlockOrRegularTransaction,
        other: Transaction,
        shuffle_seed: [u8; 32],
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
        consensus_rule_set: ConsensusRuleSet,
    ) -> anyhow::Result<BlockTransaction> {
        Self::merge_into(
            coinbase,
            other,
            shuffle_seed,
            true,
            triton_vm_job_queue,
            proof_job_options,
            consensus_rule_set,
        )
        .await
    }

    /// Merge a regular [`Transaction`] into a [`BlockTransaction`], keeping
    /// the block transaction's inputs first and the other's after them, so
    /// that an SWBF update tree over the block transaction's inputs extends
    /// by the other's. Outputs and announcements are shuffled as in
    /// [`Self::merge`].
    pub async fn merge_appending(
        block_transaction: BlockTransaction,
        other: Transaction,
        shuffle_seed: [u8; 32],
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
        consensus_rule_set: ConsensusRuleSet,
    ) -> anyhow::Result<BlockTransaction> {
        Self::merge_into(
            block_transaction.into(),
            other,
            shuffle_seed,
            false,
            triton_vm_job_queue,
            proof_job_options,
            consensus_rule_set,
        )
        .await
    }

    /// Merge two transactions.
    ///
    /// The coinbase input is either only the coinbase, or a transaction merged
    /// with the coinbase transaction.
    ///
    /// The returned block transaction will contain the chunk witness data even
    /// if that is removed from the block's transaction kernel.
    async fn merge_into(
        coinbase: BlockOrRegularTransaction,
        other: Transaction,
        shuffle_seed: [u8; 32],
        shuffle_inputs: bool,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
        consensus_rule_set: ConsensusRuleSet,
    ) -> anyhow::Result<BlockTransaction> {
        let cb_ts = coinbase.kernel().timestamp;
        let other_ts = other.kernel.timestamp;
        let diff = std::cmp::max(cb_ts, other_ts) - std::cmp::min(cb_ts, other_ts);
        ensure!(
            diff <= BoundTimeDiff::MAX_TIMESTAMP_DIFF,
            "Time difference may not be too big when merging with coinbase transactions"
        );
        let allow_big_chunks = consensus_rule_set.allow_big_chunks();
        let left_inputs = match &coinbase {
            BlockOrRegularTransaction::Block(block_transaction) => RemovalRecordList::try_unpack(
                block_transaction.inputs_with_chunk_data.clone(),
                allow_big_chunks,
            )?,
            BlockOrRegularTransaction::Regular(transaction) => transaction.kernel.inputs.clone(),
        };

        // Store chunk data if removed from the block's tx kernel.
        let mut inputs_by_index_set = left_inputs
            .into_iter()
            .chain(other.kernel.inputs.clone())
            .map(|input| (input.absolute_indices, input))
            .collect::<HashMap<_, _>>();

        let merge_witness = if shuffle_inputs {
            MergeWitness::for_composition(coinbase, other, shuffle_seed, consensus_rule_set)
        } else {
            MergeWitness::for_composition_appending(
                coinbase,
                other,
                shuffle_seed,
                consensus_rule_set,
            )
        };
        let tx = MergeWitness::merge(
            merge_witness,
            consensus_rule_set,
            triton_vm_job_queue,
            proof_job_options,
        )
        .await?;

        // Same order as the kernel's inputs, which may lack the chunk data.
        let inputs_with_chunk_data =
            RemovalRecordList::try_unpack(tx.kernel.inputs.clone(), allow_big_chunks)?
                .iter()
                .map(|input| inputs_by_index_set.remove(&input.absolute_indices))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| {
                    anyhow::anyhow!("merged inputs must come from the merged transactions")
                })?;
        let inputs_with_chunk_data =
            RemovalRecordList::pack(inputs_with_chunk_data, allow_big_chunks);

        Ok(Self {
            inputs_with_chunk_data,
            ..tx.try_into().expect("Must have merge bit set")
        })
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl BlockTransaction {
    /// Upgrade a regular [`Transaction`] into a [`BlockTransaction`] by
    /// setting the merge bit and packing the removal records. If a proof is
    /// supplied, it will (probably) become invalid. Use only in tests where
    /// the proof does not matter.
    pub fn upgrade(tx: Transaction) -> Self {
        use neptune_mutator_set::removal_record::removal_record_list::RemovalRecordList;

        use crate::transaction::transaction_kernel::TransactionKernelModifier;

        let packed = RemovalRecordList::pack(tx.kernel.inputs.clone(), true);
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
    pub fn from_tx_kernel(kernel: TransactionKernel) -> Self {
        use neptune_mutator_set::removal_record::removal_record_list::RemovalRecordList;

        use crate::transaction::transaction_kernel::TransactionKernelModifier;

        let packed = RemovalRecordList::pack(kernel.inputs.clone(), true);
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use itertools::Itertools;
    use neptune_primitives::network::Network;
    use neptune_primitives::timestamp::Timestamp;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;
    use crate::proof_abstractions::test_runtime::tokio_runtime;
    use crate::transaction::primitive_witness::PrimitiveWitness;
    use crate::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::transaction::validity::neptune_proof::Proof;

    fn mock_transaction(witness: &PrimitiveWitness, timestamp: Timestamp) -> Transaction {
        Transaction {
            kernel: TransactionKernelModifier::default()
                .timestamp(timestamp)
                .modify(witness.kernel.clone()),
            proof: TransactionProof::SingleProof(Proof::valid_mock()),
        }
    }

    #[proptest(cases = 5)]
    fn zeta_merges_keep_the_chunk_data_the_kernel_strips(
        #[strategy(PrimitiveWitness::arbitrary_tuple_with_matching_mutator_sets_and_given_coinbase(
            [(2, 1, 0), (2, 1, 0), (2, 1, 0)],
            None,
        ))]
        witnesses: [PrimitiveWitness; 3],
        #[strategy(arb())] shuffle_seeds: [[u8; 32]; 2],
    ) {
        let consensus_rule_set = ConsensusRuleSet::HardforkZeta;
        let allow_big_chunks = consensus_rule_set.allow_big_chunks();
        let options = TritonVmProofJobOptions::default_with_network(Network::RegTest);
        let timestamp = witnesses[0].kernel.timestamp;
        let [left, middle, right] = witnesses
            .each_ref()
            .map(|witness| mock_transaction(witness, timestamp));
        let all_inputs = [&left, &middle, &right]
            .into_iter()
            .flat_map(|tx| tx.kernel.inputs.clone())
            .collect_vec();

        let rt = tokio_runtime();
        let fresh = rt
            .block_on(BlockTransaction::merge(
                left.into(),
                middle,
                shuffle_seeds[0],
                TritonVmJobQueue::get_instance(),
                options.clone(),
                consensus_rule_set,
            ))
            .unwrap();
        let appended = rt
            .block_on(BlockTransaction::merge_appending(
                fresh.clone(),
                right,
                shuffle_seeds[1],
                TritonVmJobQueue::get_instance(),
                options,
                consensus_rule_set,
            ))
            .unwrap();

        for block_transaction in [fresh, appended] {
            let kernel_inputs = RemovalRecordList::try_unpack(
                block_transaction.kernel.inputs.clone(),
                allow_big_chunks,
            )
            .unwrap();
            prop_assert!(kernel_inputs
                .iter()
                .all(|input| input.target_chunks.is_empty()));

            let with_chunk_data = RemovalRecordList::try_unpack(
                block_transaction.inputs_with_chunk_data.clone(),
                allow_big_chunks,
            )
            .unwrap();
            prop_assert_eq!(
                kernel_inputs
                    .iter()
                    .map(|input| input.absolute_indices)
                    .collect_vec(),
                with_chunk_data
                    .iter()
                    .map(|input| input.absolute_indices)
                    .collect_vec()
            );
            prop_assert!(with_chunk_data
                .iter()
                .all(|input| all_inputs.contains(input)));
            prop_assert!(with_chunk_data
                .iter()
                .any(|input| !input.target_chunks.is_empty()));
        }
    }
}
