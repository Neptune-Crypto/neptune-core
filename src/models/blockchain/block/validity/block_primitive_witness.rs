use std::sync::OnceLock;

use tasm_lib::twenty_first::prelude::Mmr;

use crate::models::blockchain::block::block_body::BlockBody;
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
///                                                             |---> BlockBody ----}-.
///                                                             |                     |
/// TransactionIsValid : BlockConsensusProgram <-- conversion --+-> }                 |
///  |               ? : BlockConsensusProgram <-- conversion --+-> } Appendix -----}-|
///  | ......        ? : BlockConsensusProgram <-- conversion --'-> }                 |
/// prove                                                                             |
///  | prove                                                                          |
///  |  | prove                                                                       |
///  |  |  |                                                                          |-> Block
///  v  v  v                                                                          |
/// AppendixWitness ---------------  produce  ----------------------> BlockProof ---}-|
///                                                                               |   |
///                                                                   mining -----'   |
///                                                                      |            |
///                                                                      v            |
///                                                                   Header -------}-'
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BlockPrimitiveWitness {
    pub(crate) predecessor_block: Block,
    pub(crate) transaction: Transaction,
    maybe_body: OnceLock<BlockBody>,
}

impl BlockPrimitiveWitness {
    pub(crate) fn new(predecessor_block: Block, transaction: Transaction) -> Self {
        Self {
            predecessor_block,
            transaction,
            maybe_body: OnceLock::new(),
        }
    }

    pub(crate) fn body(&self) -> &BlockBody {
        self.maybe_body.get_or_init(||{

            let predecessor_body = self.predecessor_block.body();

            assert_eq!(
                predecessor_body.mutator_set_accumulator.hash(),
                self.transaction.kernel.mutator_set_hash,
                "Mutator sets must agree in transaction and predecessor block."
            );


            // All but two of the addition records stem from the transaction's
            // outputs. The two remaining are the guesser-rewards from the
            // previous block.
            let mut mutator_set = predecessor_body.mutator_set_accumulator.clone();
            let mutator_set_update = Block::ms_update_from_predecessor_and_new_tx_kernel(&self.predecessor_block, &self.transaction.kernel);

            mutator_set_update.apply_to_accumulator(&mut mutator_set).unwrap_or_else(|e| {
                panic!("attempting to produce a block body from a transaction whose mutator set update is incompatible: {e:?}");
            });

            let lock_free_mmr = predecessor_body.lock_free_mmr_accumulator.clone();

            let mut block_mmr = predecessor_body.block_mmr_accumulator.clone();
            block_mmr.append(self.predecessor_block.hash());

            BlockBody::new(
                self.transaction.kernel.clone(),
                mutator_set,
                lock_free_mmr,
                block_mmr,
            )
        })
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::sync::OnceLock;

    use proptest::prelude::BoxedStrategy;
    use proptest::strategy::Strategy;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;

    use super::BlockPrimitiveWitness;
    use crate::job_queue::triton_vm::TritonVmJobPriority;
    use crate::job_queue::triton_vm::TritonVmJobQueue;
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
                let rt = tokio::runtime::Runtime::new().unwrap();
                let _guard = rt.enter();

                let single_proof_inputs = rt
                    .block_on(SingleProof::produce(
                        &primwit_inputs,
                        &TritonVmJobQueue::dummy(),
                        TritonVmJobPriority::default().into(),
                    ))
                    .unwrap();

                let tx_inputs = Transaction {
                    kernel: primwit_inputs.kernel,
                    proof: TransactionProof::SingleProof(single_proof_inputs),
                };
                let single_proof_coinbase = rt
                    .block_on(SingleProof::produce(
                        &primwit_coinbase,
                        &TritonVmJobQueue::dummy(),
                        TritonVmJobPriority::default().into(),
                    ))
                    .unwrap();
                let tx_coinbase = Transaction {
                    kernel: primwit_coinbase.kernel,
                    proof: TransactionProof::SingleProof(single_proof_coinbase),
                };

                (
                    rt.block_on(tx_inputs.merge_with(
                        tx_coinbase,
                        shuffle_seed,
                        &TritonVmJobQueue::dummy(),
                        TritonVmJobPriority::default().into(),
                    ))
                    .unwrap(),
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
