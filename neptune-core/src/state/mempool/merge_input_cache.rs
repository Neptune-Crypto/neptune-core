use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;

use get_size2::GetSize;

use crate::api::export::TransactionKernelId;
use crate::state::NeptuneProof;
use crate::state::TransactionKernel;
use crate::state::UpgradePriority;

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
// *never* use Clone outside of tests as only one instance of the mempool cache
// should ever be needed by the aplication. Also: This cache can have a size in
// the gigabytes so any application logic cloning it would have terrible
// performance.
#[cfg_attr(test, derive(Clone))]
pub(super) struct MergeInputCache {
    tx_dictionary: HashMap<TransactionKernelId, MergeInputCacheElement>,

    insertion_order: VecDeque<TransactionKernelId>,
}

impl MergeInputCache {
    pub(super) fn contains(&self, txid: &TransactionKernelId) -> bool {
        self.tx_dictionary.contains_key(txid)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.tx_dictionary.is_empty()
    }

    pub(super) fn clear(&mut self) {
        self.tx_dictionary.clear();
        self.insertion_order.clear();
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.tx_dictionary.len()
    }

    pub(super) fn pop_oldest(&mut self) -> Option<MergeInputCacheElement> {
        let oldest = self.insertion_order.pop_front();
        oldest.map(|txid| {
            self.tx_dictionary
                .remove(&txid)
                .expect("fields must be in sync")
        })
    }

    pub(super) fn insert(
        &mut self,
        tx_kernel: TransactionKernel,
        single_proof: NeptuneProof,
        upgrade_priority: UpgradePriority,
    ) {
        let txid = tx_kernel.txid();
        let cache_element = MergeInputCacheElement {
            tx_kernel,
            single_proof,
            upgrade_priority,
        };
        let existing = self.tx_dictionary.insert(txid, cache_element);

        if existing.is_none() {
            self.insertion_order.push_back(txid);
        }
        assert_eq!(
            self.tx_dictionary.len(),
            self.insertion_order.len(),
            "fields must agree on lengths"
        );
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
        while let Some(txid) = self.insertion_order.pop_front() {
            let elem = self
                .tx_dictionary
                .remove(&txid)
                .expect("Reported element must exist");
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
