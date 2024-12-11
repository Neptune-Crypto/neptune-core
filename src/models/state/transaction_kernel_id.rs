use std::fmt::Display;

use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::Digest;
use tasm_lib::triton_vm::prelude::Tip5;

use tasm_lib::twenty_first::prelude::CpuParallel;
use tasm_lib::twenty_first::prelude::MerkleTreeMaker;

use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;

/// A unique identifier of a transaction whose value is unaffected by a
/// transaction update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, GetSize, Hash, Serialize, Deserialize)]
pub struct TransactionKernelId(Digest);

impl Display for TransactionKernelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.to_hex())
    }
}

impl TransactionKernel {
    // Return a digest that is unchanged by transaction updates.
    ///
    /// Return a digest that only commits to those fields of the
    /// [TransactionKernel] that are *unchanged* by a transaction update, where
    /// a transaction update makes a transaction valid relative to a new state
    /// of the mutator set. A transaction update refers to the returned
    /// transaction from [new_with_updated_mutator_set_records].
    ///
    ///
    /// [new_with_updated_mutator_set_records]: super::Transaction
    pub(crate) fn txid(&self) -> TransactionKernelId {
        // Since the `Update` program allows permutation of inputs, we must sort
        // the digests of the absolute indices to arrive at a digest that is
        // unchanged by an update.
        let mut index_set_hash = self
            .inputs
            .iter()
            .map(|x| Tip5::hash(&x.absolute_indices))
            .collect_vec();
        index_set_hash.sort_unstable();
        let index_set_hash = index_set_hash
            .into_iter()
            .flat_map(|x| x.values().to_vec())
            .collect_vec();
        let index_set_hash = Tip5::hash_varlen(&index_set_hash);

        // The `Update` consensus program does not permit permutation of outputs
        // so we don't have to sort here.
        let output_hash = self
            .outputs
            .iter()
            .flat_map(|x| x.canonical_commitment.values().to_vec())
            .collect_vec();
        let output_hash = Tip5::hash_varlen(&output_hash);

        // No permutation of public announcements allowed
        let public_announcements_hash = self
            .public_announcements
            .iter()
            .flat_map(|x| Tip5::hash_varlen(&x.message).values().to_vec())
            .collect_vec();
        let public_announcements_hash = Tip5::hash_varlen(&public_announcements_hash);

        let fee_hash = Tip5::hash(&self.fee);

        let coinbase_hash = Tip5::hash(&self.coinbase);

        // Build a Merkle tree from all five digests, and treat the root as the
        // digest
        let mut digests = vec![
            index_set_hash,
            output_hash,
            public_announcements_hash,
            fee_hash,
            coinbase_hash,
        ];

        // pad until length is a power of two
        while digests.len() & (digests.len() - 1) != 0 {
            digests.push(Digest::default());
        }

        let as_digest = CpuParallel::from_digests(&digests).unwrap().root();

        TransactionKernelId(as_digest)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
    use crate::models::blockchain::transaction::Transaction;

    #[test]
    fn txid_value_is_constant_under_transaction_update() {
        // Verify that the function `txid` returns the same digest before and
        // after a transaction has been updated wrt. a new block.
        let mut test_runner = TestRunner::deterministic();

        let [to_be_updated, mined] =
            PrimitiveWitness::arbitrary_tuple_with_matching_mutator_sets([(4, 4, 4), (3, 3, 3)])
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
        let tx_id_original = to_be_updated.kernel.txid();

        let additions = mined.kernel.outputs.clone();
        let removals = mined.kernel.inputs.clone();
        let updated =
            Transaction::new_with_primitive_witness_ms_data(to_be_updated, additions, removals);

        assert_eq!(tx_id_original, updated.kernel.txid());
    }
}
