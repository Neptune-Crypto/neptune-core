use crate::models::state::NeptuneProof;
use crate::models::state::TransactionKernel;
use crate::models::state::UpgradePriority;
use get_size2::GetSize;
use std::collections::HashSet;
use std::collections::VecDeque;

/// A transaction that was input to a merge of two transactions. In other words:
/// either a or b in the operation merge(a, b) -> c, where a, b, and c are all
/// transcations.
#[derive(Debug, Clone, GetSize)]
pub(super) struct MergeInputCacheElement {
    pub(super) tx_kernel: TransactionKernel,
    pub(super) single_proof: NeptuneProof,
    pub(super) upgrade_priority: UpgradePriority,
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
/// around until one of their inputs are mined since both a and b might both be
/// mined in case the winning composer ignored the c transaction, or the c
/// transaction came in too late.
#[derive(Debug, GetSize, Default)]
#[cfg_attr(test, derive(Clone))] // *never* use Clone outside of tests
pub(super) struct MergeInputCache {
    elements: VecDeque<MergeInputCacheElement>,
}

impl MergeInputCache {
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.elements.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    pub(super) fn pop_front(&mut self) -> Option<MergeInputCacheElement> {
        self.elements.pop_front()
    }

    pub(super) fn insert(
        &mut self,
        tx_kernel: TransactionKernel,
        single_proof: NeptuneProof,
        upgrade_priority: UpgradePriority,
    ) {
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
        block_bf_set_union: &HashSet<u128>,
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
