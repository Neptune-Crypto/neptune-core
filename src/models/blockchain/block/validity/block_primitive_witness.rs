use std::sync::OnceLock;

use tasm_lib::twenty_first::prelude::Mmr;
use tasm_lib::Digest;

use crate::models::blockchain::block::block_body::BlockBody;
use crate::models::blockchain::block::block_header::BlockHeader;
use crate::models::blockchain::block::mutator_set_update::MutatorSetUpdate;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::transaction::Transaction;
use crate::models::proof_abstractions::timestamp::Timestamp;

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
///        SingleProof : BlockConsensusProgram <-- conversion --+-> }                 |
///         |        ? : BlockConsensusProgram <-- conversion --+-> } Appendix -----}-|
///         | ...... ? : BlockConsensusProgram <-- conversion --'-> }                 |
///        prove                                                                      |
///         | prove                                                                   |
///         |  | prove                                                                |
///         |  |  |                                                                   |-> Block
///         v  v  v                                                                   |
/// AppendixWitness ---------------  produce  ----------------------> BlockProof ---}-|
///                                                                               |   |
///                                                                   mining -----'   |
///                                                                      |            |
///                                                                      v            |
///                                                                   Header -------}-'
/// ```
// note: I removed unused PartialEq, Eq derive.   If we ever need one
// PartialEq should be derived manually to ignore maybe_body.
#[derive(Clone, Debug)]
pub(crate) struct BlockPrimitiveWitness {
    predecessor_block: Block,
    transaction: Transaction,

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

    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    pub(crate) fn header(
        &self,
        timestamp: Timestamp,
        nonce: Digest,
        target_block_interval: Option<Timestamp>,
    ) -> BlockHeader {
        let parent_header = self.predecessor_block.header();
        let parent_digest = self.predecessor_block.hash();
        Block::template_header(
            parent_header,
            parent_digest,
            timestamp,
            nonce,
            target_block_interval,
        )
    }

    #[cfg(test)]
    pub(crate) fn predecessor_block(&self) -> &Block {
        &self.predecessor_block
    }

    pub(crate) fn body(&self) -> &BlockBody {
        self.maybe_body.get_or_init(|| {
            let predecessor_msa_digest = self.predecessor_block
            .mutator_set_accumulator_after()
            .hash();
            let tx_msa_digest = self.transaction.kernel.mutator_set_hash;
            assert_eq!(
                predecessor_msa_digest,
                tx_msa_digest,
                "Mutator set of transaction must agree with mutator set after previous block.\
                \nPredecessor block had {predecessor_msa_digest};\ntransaction had {tx_msa_digest}\n\n"
            );

            let mut mutator_set = self.predecessor_block.mutator_set_accumulator_after();
            let mutator_set_update = MutatorSetUpdate::new(
                self.transaction.kernel.inputs.clone(),
                self.transaction.kernel.outputs.clone(),
            );

            // Due to tests, we don't verify that the removal records can be applied. That is
            // the caller's responsibility to ensure by e.g. calling block.is_valid() after
            // constructing a block.
            mutator_set_update.apply_to_accumulator_unsafe(&mut mutator_set);

            let predecessor_body = self.predecessor_block.body();
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

    use itertools::izip;
    use itertools::Itertools;
    use num_traits::CheckedSub;
    use proptest::collection::vec;
    use proptest::prelude::Arbitrary;
    use proptest::prelude::BoxedStrategy;
    use proptest::strategy::Strategy;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::triton_vm::prelude::Tip5;
    use tasm_lib::twenty_first::prelude::AlgebraicHasher;
    use tasm_lib::Digest;

    use super::BlockPrimitiveWitness;
    use crate::job_queue::triton_vm::TritonVmJobPriority;
    use crate::job_queue::triton_vm::TritonVmJobQueue;
    use crate::models::blockchain::block::block_appendix::BlockAppendix;
    use crate::models::blockchain::block::block_body::BlockBody;
    use crate::models::blockchain::block::block_header::BlockHeader;
    use crate::models::blockchain::block::block_kernel::BlockKernel;
    use crate::models::blockchain::block::Block;
    use crate::models::blockchain::block::BlockProof;
    use crate::models::blockchain::block::TARGET_BLOCK_INTERVAL;
    use crate::models::blockchain::transaction::lock_script::LockScript;
    use crate::models::blockchain::transaction::lock_script::LockScriptAndWitness;
    use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
    use crate::models::blockchain::transaction::utxo::Utxo;
    use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
    use crate::models::blockchain::transaction::Transaction;
    use crate::models::blockchain::transaction::TransactionProof;
    use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
    use crate::models::proof_abstractions::timestamp::Timestamp;
    use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
    use crate::util_types::mutator_set::msa_and_records::MsaAndRecords;
    use crate::util_types::mutator_set::removal_record::RemovalRecord;

    fn arbitrary_block_transaction_from_msa_and_records(
        num_outputs: usize,
        num_announcements: usize,
        msa_and_records: MsaAndRecords,
        input_utxos: Vec<Utxo>,
        lock_scripts_and_witnesses: Vec<LockScriptAndWitness>,
        coinbase_amount: NeptuneCoins,
        timestamp: Timestamp,
    ) -> BoxedStrategy<Transaction> {
        (
            PrimitiveWitness::arbitrary_pair_with_inputs_and_coinbase_respectively_from_msa_and_records(
                num_outputs,
                num_announcements,
                msa_and_records,
                input_utxos,
                lock_scripts_and_witnesses,
                coinbase_amount,
                timestamp
            ),
            arb::<[u8; 32]>(),
        )
            .prop_map(move |((primwit_inputs, primwit_coinbase), shuffle_seed)| {
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

                rt.block_on(tx_inputs.merge_with(
                    tx_coinbase,
                    shuffle_seed,
                    &TritonVmJobQueue::dummy(),
                    TritonVmJobPriority::default().into(),
                ))
                .unwrap()
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
            const NUM_INPUTS: usize = 2;
            (
                NeptuneCoins::arbitrary_non_negative(),
                vec(0f64..1f64, NUM_INPUTS - 1),
                vec(arb::<Digest>(), NUM_INPUTS),
                vec(arb::<Digest>(), NUM_INPUTS),
                vec(arb::<Digest>(), NUM_INPUTS),
                0..u64::MAX,
            )
                .prop_flat_map(
                    |(
                        total_input,
                        input_distribution,
                        hash_lock_keys,
                        sender_randomnesses,
                        receiver_preimages,
                        aocl_size,
                    )| {
                        let mut input_amounts = input_distribution
                            .into_iter()
                            .map(|fraction| total_input.lossy_f64_fraction_mul(fraction).unwrap())
                            .collect_vec();
                        input_amounts.push(
                            total_input
                                .checked_sub(&input_amounts.iter().cloned().sum::<NeptuneCoins>())
                                .unwrap(),
                        );
                        let lock_scripts_and_witnesses = hash_lock_keys
                            .iter()
                            .copied()
                            .map(LockScriptAndWitness::hash_lock)
                            .collect_vec();
                        let lock_script_hashes = lock_scripts_and_witnesses
                            .iter()
                            .map(|lsaw| LockScript::from(lsaw).hash())
                            .collect_vec();
                        let input_utxos = input_amounts
                            .into_iter()
                            .zip(lock_script_hashes)
                            .map(|(amount, hash)| (hash, amount.to_native_coins()).into())
                            .collect_vec();
                        let own_items = input_utxos.iter().map(Tip5::hash).collect_vec();
                        let removables = izip!(
                            own_items.iter().copied(),
                            sender_randomnesses.iter().copied(),
                            receiver_preimages.iter().copied()
                        )
                        .collect_vec();
                        MsaAndRecords::arbitrary_with((removables.clone(), aocl_size))
                            .prop_flat_map(move |msa_and_records| {
                                let removal_records = msa_and_records.removal_records;
                                let membership_proofs = msa_and_records.membership_proofs;
                                let intermediate_mutator_set_accumulator =
                                    msa_and_records.mutator_set_accumulator;

                                let input_utxos = input_utxos.clone();
                                let own_items = own_items.clone();
                                let lock_scripts_and_witnesses = lock_scripts_and_witnesses.clone();

                                let parent_header = arb::<BlockHeader>();
                                let parent_appendix = arb::<BlockAppendix>();
                                let parent_body = BlockBody::arbitrary_with_mutator_set_accumulator(
                                    intermediate_mutator_set_accumulator.clone(),
                                );
                                (parent_header, parent_body, parent_appendix).prop_flat_map(
                                    move |(header, body, appendix)| {
                                        let parent_kernel = BlockKernel {
                                            header: header.clone(),
                                            body: body.clone(),
                                            appendix: appendix.clone(),
                                        };
                                        let predecessor_block = Block {
                                            kernel: parent_kernel,
                                            proof: BlockProof::Invalid,
                                            digest: OnceLock::new(),
                                        };

                                        let coinbase_amount = Block::block_subsidy(
                                            predecessor_block.header().height.next(),
                                        );
                                        let timestamp = predecessor_block.header().timestamp
                                            + TARGET_BLOCK_INTERVAL;

                                        let miner_fee_records =
                                            predecessor_block.guesser_fee_addition_records();

                                        let mut mutator_set_accumulator_after_block =
                                            intermediate_mutator_set_accumulator.clone();
                                        let mut membership_proofs = membership_proofs.clone();
                                        let mut removal_records = removal_records.clone();

                                        for addition_record in &miner_fee_records {
                                            MsMembershipProof::batch_update_from_addition(
                                                &mut membership_proofs.iter_mut().collect_vec(),
                                                &own_items.clone(),
                                                &mutator_set_accumulator_after_block,
                                                addition_record,
                                            )
                                            .expect("update from addition should always work");
                                            RemovalRecord::batch_update_from_addition(
                                                &mut removal_records.iter_mut().collect_vec(),
                                                &mutator_set_accumulator_after_block,
                                            );
                                            mutator_set_accumulator_after_block
                                                .add(addition_record);
                                        }

                                        let msa_and_records_after_block = MsaAndRecords {
                                            mutator_set_accumulator:
                                                mutator_set_accumulator_after_block,
                                            removal_records,
                                            membership_proofs,
                                        };
                                        arbitrary_block_transaction_from_msa_and_records(
                                            2,
                                            2,
                                            msa_and_records_after_block,
                                            input_utxos.clone(),
                                            lock_scripts_and_witnesses.clone(),
                                            coinbase_amount,
                                            timestamp,
                                        )
                                        .prop_map(
                                            move |block_tx| {
                                                BlockPrimitiveWitness::new(
                                                    predecessor_block.clone(),
                                                    block_tx.clone(),
                                                )
                                            },
                                        )
                                    },
                                )
                            })
                    },
                )
                .boxed()
        }
    }
}
