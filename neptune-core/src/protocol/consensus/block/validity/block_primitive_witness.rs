use std::sync::OnceLock;

use tasm_lib::twenty_first::prelude::Mmr;

use crate::api::export::Network;
use crate::protocol::consensus::block::block_body::BlockBody;
use crate::protocol::consensus::block::block_header::BlockHeader;
use crate::protocol::consensus::block::block_transaction::BlockTransaction;
use crate::protocol::consensus::block::mutator_set_update::MutatorSetUpdate;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::util_types::mutator_set::removal_record::removal_record_list::RemovalRecordList;

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
/// BlockProofWitness -------------  produce  ----------------------> BlockProof ---}-|
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
    pub(super) predecessor_block: Block,

    transaction: BlockTransaction,

    maybe_body: OnceLock<BlockBody>,

    pub(super) network: Network,
}

impl BlockPrimitiveWitness {
    pub(crate) fn new(
        predecessor_block: Block,
        transaction: BlockTransaction,
        network: Network,
    ) -> Self {
        Self {
            predecessor_block,
            transaction,
            maybe_body: OnceLock::new(),
            network,
        }
    }

    pub fn transaction(&self) -> &BlockTransaction {
        &self.transaction
    }

    pub(crate) fn header(
        &self,
        timestamp: Timestamp,
        target_block_interval: Timestamp,
    ) -> BlockHeader {
        let parent_header = self.predecessor_block.header();
        let parent_digest = self.predecessor_block.hash();
        BlockHeader::template_header(
            parent_header,
            parent_digest,
            timestamp,
            target_block_interval,
        )
    }

    /// Builds the block body from its witness.
    ///
    /// # Panics
    ///
    ///  - If predecessor has negative transaction fee.
    pub(crate) fn body(&self) -> &BlockBody {
        self.maybe_body.get_or_init(|| {
            let predecessor_msa = self
                .predecessor_block
                .mutator_set_accumulator_after()
                .expect("Predecessor must have mutator set after");
            let predecessor_msa_digest = predecessor_msa
                .hash();
            let transaction_kernel = TransactionKernel::from(self.transaction.kernel.clone());
            let tx_msa_digest = transaction_kernel.mutator_set_hash;
            assert_eq!(
                predecessor_msa_digest,
                tx_msa_digest,
                "Mutator set of transaction must agree with mutator set after previous block.\
                \nPredecessor block had {predecessor_msa_digest};\ntransaction had {tx_msa_digest}\n\n"
            );

            let inputs = RemovalRecordList::try_unpack(transaction_kernel.inputs.clone()).expect("Inputs must be packed in block transaction");

            let mutator_set_update = MutatorSetUpdate::new(inputs, self.transaction.kernel.outputs.clone());

            // Due to tests, we don't verify that the removal records can be
            // applied. That is the caller's responsibility to ensure by e.g.
            // checking block validity after constructing a block.
            let mut mutator_set = predecessor_msa;
            mutator_set_update.apply_to_accumulator_unsafe(&mut mutator_set);

            let predecessor_body = self.predecessor_block.body();
            let lock_free_mmr = predecessor_body.lock_free_mmr_accumulator.clone();
            let mut block_mmr = predecessor_body.block_mmr_accumulator.clone();
            block_mmr.append(self.predecessor_block.hash());

            BlockBody::new(
                transaction_kernel.to_owned(),
                mutator_set,
                lock_free_mmr,
                block_mmr,
            )
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
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
    use tasm_lib::prelude::Digest;
    use tasm_lib::triton_vm::prelude::BFieldElement;
    use tasm_lib::triton_vm::prelude::Tip5;
    use tasm_lib::twenty_first::bfe;

    use super::BlockPrimitiveWitness;
    use crate::api::export::BlockHeight;
    use crate::api::export::Network;
    use crate::application::triton_vm_job_queue::TritonVmJobPriority;
    use crate::application::triton_vm_job_queue::TritonVmJobQueue;
    use crate::protocol::consensus::block::block_appendix::BlockAppendix;
    use crate::protocol::consensus::block::block_body::BlockBody;
    use crate::protocol::consensus::block::block_header::BlockHeader;
    use crate::protocol::consensus::block::block_kernel::BlockKernel;
    use crate::protocol::consensus::block::block_transaction::BlockTransaction;
    use crate::protocol::consensus::block::difficulty_control::Difficulty;
    use crate::protocol::consensus::block::Block;
    use crate::protocol::consensus::block::BlockProof;
    use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
    use crate::protocol::consensus::transaction::lock_script::LockScriptAndWitness;
    use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
    use crate::protocol::consensus::transaction::utxo::Utxo;
    use crate::protocol::consensus::transaction::validity::single_proof::produce_single_proof;
    use crate::protocol::consensus::transaction::Transaction;
    use crate::protocol::consensus::transaction::TransactionProof;
    use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
    use crate::protocol::proof_abstractions::timestamp::Timestamp;
    use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
    use crate::util_types::mutator_set::msa_and_records::MsaAndRecords;
    use crate::util_types::mutator_set::removal_record::RemovalRecord;

    /// Returns transactions without packed inputs
    #[cfg_attr(test, expect(clippy::too_many_arguments))]
    fn arbitrary_block_transaction_from_msa_and_records(
        num_outputs: usize,
        num_announcements: usize,
        msa_and_records: MsaAndRecords,
        input_utxos: Vec<Utxo>,
        lock_scripts_and_witnesses: Vec<LockScriptAndWitness>,
        coinbase_amount: NativeCurrencyAmount,
        timestamp: Timestamp,
        block_height: BlockHeight,
    ) -> BoxedStrategy<BlockTransaction> {
        let network = Network::Main; // explicit assumption
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);
        (
            PrimitiveWitness::arbitrary_pair_with_coinbase_and_inputs_respectively_from_msa_and_records(
                num_outputs,
                num_announcements,
                msa_and_records,
                input_utxos,
                lock_scripts_and_witnesses,
                coinbase_amount,
                timestamp,
            ),
            arb::<[u8; 32]>(),
        )
            .prop_map(move |((primwit_coinbase, primwit_inputs), shuffle_seed)| {
                let rt = crate::tests::tokio_runtime();
                let _guard = rt.enter();

                let proof_job_options = TritonVmProofJobOptions::from(TritonVmJobPriority::default());

                let single_proof_coinbase = rt
                    .block_on(produce_single_proof(
                        &primwit_coinbase,
                        TritonVmJobQueue::get_instance(),
                        proof_job_options.clone(),
                        consensus_rule_set,
                    ))
                    .unwrap();

                let tx_coinbase = Transaction {
                    kernel: primwit_coinbase.kernel,
                    proof: TransactionProof::SingleProof(single_proof_coinbase),
                };
                let single_proof_inputs = rt
                    .block_on(produce_single_proof(
                        &primwit_inputs,
                        TritonVmJobQueue::get_instance(),
                        proof_job_options.clone(),
                        consensus_rule_set
                    ))
                    .unwrap();
                let tx_inputs = Transaction {
                    kernel: primwit_inputs.kernel,
                    proof: TransactionProof::SingleProof(single_proof_inputs),
                };

                rt.block_on(BlockTransaction::merge(
                    tx_coinbase.into(),
                    tx_inputs,
                    shuffle_seed,
                    TritonVmJobQueue::get_instance(),
                    proof_job_options.clone(),
                    consensus_rule_set,
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
        pub(crate) fn predecessor_block(&self) -> &Block {
            &self.predecessor_block
        }

        pub(crate) fn arbitrary() -> BoxedStrategy<BlockPrimitiveWitness> {
            (1..BFieldElement::MAX)
                .prop_flat_map(|block_height_as_u64| {
                    let block_height = BlockHeight::new(bfe!(block_height_as_u64));
                    Self::arbitrary_with_block_height(block_height)
                })
                .boxed()
        }

        pub(crate) fn deterministic_with_block_height(block_height: BlockHeight) -> Self {
            let mut test_runner = TestRunner::deterministic();

            Self::arbitrary_with_block_height(block_height)
                .new_tree(&mut test_runner)
                .unwrap()
                .current()
        }

        pub(crate) fn deterministic_with_block_height_and_difficulty(
            block_height: BlockHeight,
            difficulty: Difficulty,
        ) -> Self {
            let mut test_runner = TestRunner::deterministic();

            Self::arbitrary_with_height_and_difficulty(block_height, difficulty)
                .new_tree(&mut test_runner)
                .unwrap()
                .current()
        }

        pub(crate) fn arbitrary_with_height_and_difficulty(
            block_height: BlockHeight,
            difficulty: Difficulty,
        ) -> BoxedStrategy<BlockPrimitiveWitness> {
            const NUM_INPUTS: usize = 2;
            let network = Network::Main;

            (
                NativeCurrencyAmount::arbitrary_non_negative(),
                vec(0f64..1f64, NUM_INPUTS - 1),
                vec(arb::<Digest>(), NUM_INPUTS),
                vec(arb::<Digest>(), NUM_INPUTS),
                vec(arb::<Digest>(), NUM_INPUTS),
                0..u64::MAX / 2,
            )
                .prop_flat_map(
                    move |(
                        total_input,
                        input_distribution,
                        hash_lock_keys,
                        sender_randomnesses,
                        receiver_preimages,
                        aocl_size,
                    )| {
                        let mut input_amounts = input_distribution
                            .into_iter()
                            .map(|fraction| total_input.lossy_f64_fraction_mul(fraction))
                            .collect_vec();
                        input_amounts.push(
                            total_input
                                .checked_sub(
                                    &input_amounts.iter().copied().sum::<NativeCurrencyAmount>(),
                                )
                                .unwrap(),
                        );
                        let lock_scripts_and_witnesses = hash_lock_keys
                            .iter()
                            .copied()
                            .map(LockScriptAndWitness::standard_hash_lock_from_preimage)
                            .collect_vec();
                        let input_utxos = input_amounts
                            .into_iter()
                            .zip(lock_scripts_and_witnesses.iter())
                            .map(|(amount, ls_and_w)| {
                                Utxo::new(ls_and_w.program.hash(), amount.to_native_coins())
                            })
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
                                let unpacked_removal_records =
                                    msa_and_records.unpacked_removal_records();
                                let membership_proofs = msa_and_records.membership_proofs;
                                let intermediate_mutator_set_accumulator =
                                    msa_and_records.mutator_set_accumulator;

                                let input_utxos = input_utxos.clone();
                                let own_items = own_items.clone();
                                let lock_scripts_and_witnesses = lock_scripts_and_witnesses.clone();

                                let parent_height = block_height.previous().unwrap();
                                let parent_header =
                                    BlockHeader::arbitrary_with_height_and_difficulty(
                                        parent_height,
                                        difficulty,
                                    );
                                let parent_appendix = arb::<BlockAppendix>();
                                let parent_body = BlockBody::arbitrary_with_mutator_set_accumulator(
                                    intermediate_mutator_set_accumulator.clone(),
                                );
                                (parent_header, parent_body, parent_appendix).prop_flat_map(
                                    move |(header, body, appendix)| {
                                        let parent_kernel = BlockKernel {
                                            header,
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
                                            + network.target_block_interval();

                                        let miner_fee_records = predecessor_block
                                            .guesser_fee_addition_records()
                                            .unwrap();

                                        let mut mutator_set_accumulator_after_block =
                                            intermediate_mutator_set_accumulator.clone();
                                        let mut membership_proofs = membership_proofs.clone();
                                        let mut unpacked_removal_records =
                                            unpacked_removal_records.clone();

                                        for addition_record in &miner_fee_records {
                                            MsMembershipProof::batch_update_from_addition(
                                                &mut membership_proofs.iter_mut().collect_vec(),
                                                &own_items.clone(),
                                                &mutator_set_accumulator_after_block,
                                                addition_record,
                                            )
                                            .expect("update from addition should always work");
                                            RemovalRecord::batch_update_from_addition(
                                                &mut unpacked_removal_records
                                                    .iter_mut()
                                                    .collect_vec(),
                                                &mutator_set_accumulator_after_block,
                                            );
                                            mutator_set_accumulator_after_block
                                                .add(addition_record);
                                        }

                                        let msa_and_records_after_block = MsaAndRecords::new(
                                            mutator_set_accumulator_after_block,
                                            unpacked_removal_records,
                                            membership_proofs,
                                        );
                                        arbitrary_block_transaction_from_msa_and_records(
                                            2,
                                            2,
                                            msa_and_records_after_block,
                                            input_utxos.clone(),
                                            lock_scripts_and_witnesses.clone(),
                                            coinbase_amount,
                                            timestamp,
                                            block_height,
                                        )
                                        .prop_map(
                                            move |block_tx| {
                                                BlockPrimitiveWitness::new(
                                                    predecessor_block.clone(),
                                                    block_tx.clone(),
                                                    network,
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

        pub(crate) fn arbitrary_with_block_height(
            block_height: BlockHeight,
        ) -> BoxedStrategy<BlockPrimitiveWitness> {
            let difficulty = arb::<Difficulty>();
            difficulty
                .prop_flat_map(move |difficulty| {
                    Self::arbitrary_with_height_and_difficulty(block_height, difficulty)
                })
                .boxed()
        }
    }
}
