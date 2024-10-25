use get_size::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::twenty_first::prelude::Mmr;

use crate::models::blockchain::block::block_body::BlockBody;
use crate::models::blockchain::block::mutator_set_update::MutatorSetUpdate;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::transaction::Transaction;

/// Wraps all information necessary to produce a block.
///
/// Represents the first stage in the block production pipeline, which looks
/// like this:
///
/// ```notest
/// predecessor : Block --------.
///                             |-- new --> BlockPrimitiveWitness
/// transaction : Transaction --'                               |
///                                                             |
///                                                             |---> BlockBody --.
///                                                             |                 |
/// TransactionIsValid : BlockConsensusProgram <-- conversion --+-> }             |
///  |               ? : BlockConsensusProgram <-- conversion --+-> } Appendix ---|
///  | ......        ? : BlockConsensusProgram <-- conversion --'-> }             |
/// prove                                                                         |
///  | prove                                                                      |
///  |  | prove                                                                   |
///  |  |  |       ...           ...                  ...                         |  
///  v  v  v                                                                      |
/// SoftClaimsWitness --------------- produce ----------------------> BlockProof -|
///                                                                               |
///                                                 Block <---------- mining -----'
/// ```
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub(crate) struct BlockPrimitiveWitness {
    pub(crate) predecessor_block: Block,
    pub(crate) transaction: Transaction,
    maybe_body: Option<BlockBody>,
}

impl BlockPrimitiveWitness {
    pub(crate) fn body(&mut self) -> BlockBody {
        if let Some(body) = &self.maybe_body {
            return body.to_owned();
        }

        let predecessor_body = self.predecessor_block.body();

        let mut mutator_set = predecessor_body.mutator_set_accumulator.clone();
        let mutator_set_update = MutatorSetUpdate::new(
            self.transaction.kernel.inputs.clone(),
            self.transaction.kernel.outputs.clone(),
        );
        mutator_set_update.apply_to_accumulator(&mut mutator_set).unwrap_or_else(|e| {panic!("attempting to produce a block body from a transaction whose mutator set update is incompatible: {e:?}");});

        let lock_free_mmr = predecessor_body.lock_free_mmr_accumulator.clone();

        let mut block_mmr = predecessor_body.block_mmr_accumulator.clone();
        block_mmr.append(self.predecessor_block.hash());

        let body = BlockBody::new(
            self.transaction.kernel.clone(),
            mutator_set,
            lock_free_mmr,
            block_mmr,
        );
        self.maybe_body = Some(body.clone());
        body
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::sync::OnceLock;

    use proptest::prelude::BoxedStrategy;
    use proptest::strategy::Strategy;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;

    use crate::models::blockchain::block::block_appendix::BlockAppendix;
    use crate::models::blockchain::block::block_body::BlockBody;
    use crate::models::blockchain::block::block_header::BlockHeader;
    use crate::models::blockchain::block::block_kernel::BlockKernel;
    use crate::models::blockchain::block::Block;
    use crate::models::blockchain::block::BlockProof;
    use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
    use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
    use crate::models::blockchain::transaction::Transaction;
    use crate::models::blockchain::transaction::TransactionProof;
    use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

    use super::BlockPrimitiveWitness;

    fn arbitrary_block_transaction_with_mutator_set(
        num_inputs: usize,
        num_outputs: usize,
        num_announcements: usize,
    ) -> BoxedStrategy<(Transaction, MutatorSetAccumulator)> {
        (
            PrimitiveWitness::arbitrary_pair_with_inputs_and_coinbase_respectively(
                num_inputs,
                num_outputs,
                num_announcements,
            ),
            arb::<[u8; 32]>(),
        )
            .prop_map(|((primwit_inputs, primwit_coinbase), shuffle_seed)| {
                let mutator_set_accumulator = primwit_inputs.mutator_set_accumulator.clone();
                let single_proof_inputs = SingleProof::produce(&primwit_inputs);
                let tx_inputs = Transaction {
                    kernel: primwit_inputs.kernel,
                    proof: TransactionProof::SingleProof(single_proof_inputs),
                };
                let single_proof_coinbase = SingleProof::produce(&primwit_coinbase);
                let tx_coinbase = Transaction {
                    kernel: primwit_coinbase.kernel,
                    proof: TransactionProof::SingleProof(single_proof_coinbase),
                };

                (
                    tx_inputs.merge_with(tx_coinbase, shuffle_seed),
                    mutator_set_accumulator,
                )
            })
            .boxed()
    }

    pub(crate) fn deterministic_block_primitive_witness() -> BlockPrimitiveWitness {
        let mut test_runner = TestRunner::deterministic();

        BlockPrimitiveWitness::arbitrary()
            .new_tree(&mut test_runner)
            .unwrap()
            .current()
    }

    impl BlockPrimitiveWitness {
        pub(crate) fn new(predecessor_block: Block, transaction: Transaction) -> Self {
            Self {
                predecessor_block,
                transaction,
                maybe_body: None,
            }
        }

        pub(crate) fn arbitrary() -> BoxedStrategy<BlockPrimitiveWitness> {
            let parent_header = arb::<BlockHeader>();
            let parent_appendix = arb::<BlockAppendix>();
            let block_transaction_with_mutator_set =
                arbitrary_block_transaction_with_mutator_set(2, 2, 2);
            (
                parent_header,
                parent_appendix,
                block_transaction_with_mutator_set,
            )
                .prop_flat_map(
                    move |(header, appendix, (block_tx, mutator_set_accumulator))| {
                        BlockBody::arbitrary_with_mutator_set_accumulator(mutator_set_accumulator)
                            .prop_map(move |body| {
                                let parent_kernel = BlockKernel {
                                    header: header.clone(),
                                    body,
                                    appendix: appendix.clone(),
                                };
                                let parent = Block {
                                    kernel: parent_kernel,
                                    proof: BlockProof::Invalid,
                                    digest: OnceLock::new(),
                                };

                                BlockPrimitiveWitness::new(parent, block_tx.clone())
                            })
                    },
                )
                .boxed()
        }
    }
}
