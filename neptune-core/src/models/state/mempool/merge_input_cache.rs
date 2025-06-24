use crate::models::state::NeptuneProof;
use crate::models::state::TransactionKernel;
use crate::models::state::UpgradePriority;
use bytesize::ByteSize;
use get_size2::GetSize;
use std::collections::HashSet;
use std::collections::VecDeque;

/// A transaction that was input to a merge of two transactions. In other words:
/// either a or b in the operation merge(a, b) -> c, where a, b, and c are all
/// transcations.
#[derive(Debug, Clone, GetSize)]
pub(super) struct MergeInputCacheElement {
    tx_kernel: TransactionKernel,
    single_proof: NeptuneProof,
    upgrade_priority: UpgradePriority,
}

/// The mempools cache of transactions that conflict with transactions in the
/// mempool but might still be mined in the future in case the merged
/// transaction that kicked out the elements contained herein is not mined.
///
/// Imagine two transactions a and b in the mempool. Someone merges the two
/// transactions a and b into a new transaction c. This new c transaction
/// conflicts with both a and b because they have overlapping inputs. So not all
/// transactions a, b, and c are simulataneously mineable. Because of this
/// conflict, the insertion of c into the mempool removes transaction a and b.
/// But if a new block is mined containing transaction a, then transaction b
/// can still be mined (after an update). So without this cache, transaction b
/// has now dissapeared from the mempool. The solution is to keep a and b
/// around until one of their inputs are mined since they might both be mined
/// later in case the winning composer ignored the c transaction.
#[derive(Debug, GetSize)]
pub(super) struct MergeInputCache {
    elements: VecDeque<MergeInputCacheElement>,
    max_total_size: ByteSize,
}

impl MergeInputCache {
    pub(super) fn new(max_total_size: ByteSize) -> Self {
        Self {
            elements: Default::default(),
            max_total_size,
        }
    }

    fn clear(&mut self) {
        self.elements.clear();
    }

    pub(super) fn len(&self) -> usize {
        self.elements.len()
    }

    pub(super) fn insert(
        &mut self,
        tx_kernel: TransactionKernel,
        single_proof: NeptuneProof,
        upgrade_priority: UpgradePriority,
    ) {
        while self.elements.len() >= self.max_len {
            self.elements.pop_front();
        }

        self.elements.push_back(MergeInputCacheElement {
            tx_kernel,
            single_proof,
            upgrade_priority,
        });
    }

    /// Update the merge cache with a new block. Returns the transactions that
    /// can now go back into the mempool but does not filter for internal
    /// conflicts. So returned elements may be mutually incompatible but are
    /// guaranteed to be individually compatible with the new block. Clears the
    /// cache.
    pub(super) fn update_with_block(
        &mut self,
        block_bf_set_union: HashSet<u128>,
    ) -> Vec<MergeInputCacheElement> {
        let mut ret = vec![];
        while let Some(elem) = self.elements.pop_front() {
            let transaction_index_sets: HashSet<_> = elem
                .tx_kernel
                .inputs
                .iter()
                .map(|rr| rr.absolute_indices.to_array())
                .collect();
            let still_mineable = transaction_index_sets.iter().all(|index_set| {
                index_set
                    .iter()
                    .any(|index| !block_bf_set_union.contains(index))
            });
            if still_mineable {
                ret.push(elem);
            }
        }

        ret
    }
}
