use std::sync::OnceLock;

use neptune_mutator_set::removal_record::removal_record_list::RemovalRecordList;
use neptune_primitives::network::Network;
use neptune_primitives::timestamp::Timestamp;
use num_traits::CheckedSub;
use tasm_lib::twenty_first::prelude::Mmr;

use crate::block::block_body::BlockBody;
use crate::block::block_body::NUM_GUESSER_FEE_OUTPUTS;
use crate::block::block_header::BlockHeader;
use crate::block::block_transaction::BlockTransaction;
use crate::block::mutator_set_update::MutatorSetUpdate;
use crate::block::pow::LustrationStatus;
use crate::block::Block;
use crate::consensus_rule_set::ConsensusRuleSet;
use crate::consensus_rule_set::LustrationRule;
use crate::transaction::transaction_kernel::TransactionKernel;

/// Wraps all information necessary to produce a block.
///
/// Represents the first stage in the block production pipeline, which looks
/// like this:
///
/// ```notest
/// predecessor : Block --------.
///                             |-- new --> BlockPrimitiveWitness
/// transaction : Transaction --'                      |
///                                                    |
///                                                    |---> BlockBody --.------}--.
///                                                    |                 |         |
///        SingleProof : BlockProgram <-- conversion --+-> }             |         |
///         |        ? : BlockProgram <-- conversion --+-> } Appendix ---+------}--|
///         | ...... ? : BlockProgram <-- conversion --'-> }             |         |
///        prove                                                         |         |
///         | prove                                                      |         |
///         |  | prove                                                   |         |
///         |  |  |                                                      |          > Block
///         v  v  v                                                      |         |
/// BlockProofWitness ---------  produce  -----> BlockProof -------------+------}--|
///                                                                      |         |
///                                                                   mining       |
///                                                                      |         |
///                                                                      v         |
///                                                               Blockheader --}--'
/// ```
#[derive(Clone, Debug)]
pub struct BlockPrimitiveWitness {
    pub(super) predecessor_block: Block,

    transaction: BlockTransaction,

    maybe_body: OnceLock<BlockBody>,

    pub(super) network: Network,
}

impl BlockPrimitiveWitness {
    pub fn new(predecessor_block: Block, transaction: BlockTransaction, network: Network) -> Self {
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

    /// Return the index of the last AOCL element in this block, including
    /// guesser reward UTXOs.
    fn max_aocl_leaf_index(&self) -> u64 {
        let num_own_outputs =
            self.transaction.kernel.outputs.len() as u64 + NUM_GUESSER_FEE_OUTPUTS;
        self.predecessor_block.body().max_aocl_leaf_index() + num_own_outputs
    }

    pub fn header(&self, timestamp: Timestamp, target_block_interval: Timestamp) -> BlockHeader {
        let parent_header = self.predecessor_block.header();
        let parent_digest = self.predecessor_block.hash();
        let mut header = BlockHeader::template_header(
            parent_header,
            parent_digest,
            timestamp,
            target_block_interval,
            self.network,
        );

        let consensus_rule_set = ConsensusRuleSet::infer_from(self.network, header.height);

        let max_aocl_leaf_index = self.max_aocl_leaf_index();
        match ConsensusRuleSet::lustration_rule(self.network, header.height, max_aocl_leaf_index) {
            Some(LustrationRule::Initial(lustration_status)) => {
                header.pow.set_lustration_status(lustration_status)
            }
            Some(LustrationRule::Updated { .. }) => {
                let parent_lustration_status = parent_header.pow.lustration_status().expect("Parent lustration status must be parseable when lustration status must be updated");
                let parent_aocl_threshold = parent_lustration_status.max_lustrating_aocl_leaf_index;
                let lustrated_in_this_block = self
                    .transaction
                    .kernel
                    .verified_lustration_amount(
                        parent_aocl_threshold,
                        consensus_rule_set.fix_lustration_double_counting(),
                    )
                    .expect("Transaction used for block proposal must lustrate correctly");
                let new_counter = parent_lustration_status.counter.checked_sub(&lustrated_in_this_block).expect("Transaction used for block proposal may not generate a negative lustration counter");
                let new_lustration_status = LustrationStatus {
                    counter: new_counter,
                    max_lustrating_aocl_leaf_index: parent_aocl_threshold,
                };
                header.pow.set_lustration_status(new_lustration_status)
            }
            None => (),
        };

        header
    }

    /// Builds the block body from its witness.
    ///
    /// # Panics
    ///
    ///  - If predecessor has negative transaction fee.
    pub fn body(&self) -> &BlockBody {
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

#[cfg(any(test, feature = "test-helpers"))]
mod test_support {
    use itertools::izip;
    use itertools::Itertools;
    use neptune_mutator_set::ms_membership_proof::MsMembershipProof;
    use neptune_mutator_set::msa_and_records::MsaAndRecords;
    use neptune_mutator_set::removal_record::RemovalRecord;
    use neptune_primitives::block_height::BlockHeight;
    use neptune_primitives::difficulty_control::Difficulty;
    use proptest::collection::vec;
    use proptest::prelude::Arbitrary;
    use proptest::prelude::BoxedStrategy;
    use proptest::strategy::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::prelude::Digest;
    use tasm_lib::triton_vm::prelude::BFieldElement;
    use tasm_lib::triton_vm::prelude::Tip5;
    use tasm_lib::twenty_first::bfe;

    use super::*;
    use crate::block::block_appendix::BlockAppendix;
    use crate::block::block_kernel::BlockKernel;
    use crate::block::BlockProof;
    use crate::proof_abstractions::tasm::program::TritonVmProofJobOptions;
    use crate::proof_abstractions::triton_vm_job_queue::TritonVmJobQueue;
    use crate::transaction::lock_script::LockScriptAndWitness;
    use crate::transaction::primitive_witness::PrimitiveWitness;
    use crate::transaction::utxo::Utxo;
    use crate::transaction::validity::single_proof::produce_single_proof;
    use crate::transaction::Transaction;
    use crate::transaction::TransactionProof;
    use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

    impl BlockPrimitiveWitness {
        pub fn predecessor_block(&self) -> &Block {
            &self.predecessor_block
        }

        pub fn arbitrary(network: Network) -> BoxedStrategy<BlockPrimitiveWitness> {
            (1..BFieldElement::MAX)
                .prop_flat_map(move |block_height_as_u64| {
                    let block_height = BlockHeight::new(bfe!(block_height_as_u64));
                    Self::arbitrary_with_block_height(block_height, network)
                })
                .boxed()
        }

        pub fn deterministic_with_block_height(
            block_height: BlockHeight,
            network: Network,
        ) -> Self {
            let mut test_runner = TestRunner::deterministic();

            Self::arbitrary_with_block_height(block_height, network)
                .new_tree(&mut test_runner)
                .unwrap()
                .current()
        }

        pub fn deterministic_with_block_height_and_difficulty(
            block_height: BlockHeight,
            difficulty: Difficulty,
            network: Network,
        ) -> Self {
            let mut test_runner = TestRunner::deterministic();

            Self::arbitrary_with_height_and_difficulty(block_height, difficulty, network)
                .new_tree(&mut test_runner)
                .unwrap()
                .current()
        }

        pub fn arbitrary_with_height_and_difficulty(
            block_height: BlockHeight,
            difficulty: Difficulty,
            network: Network,
        ) -> BoxedStrategy<BlockPrimitiveWitness> {
            const NUM_INPUTS: usize = 2;

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
                                            network,
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

        pub fn arbitrary_with_block_height(
            block_height: BlockHeight,
            network: Network,
        ) -> BoxedStrategy<BlockPrimitiveWitness> {
            let difficulty = arb::<Difficulty>();
            difficulty
                .prop_flat_map(move |difficulty| {
                    Self::arbitrary_with_height_and_difficulty(block_height, difficulty, network)
                })
                .boxed()
        }
    }

    /// Returns transactions without packed inputs
    #[expect(clippy::too_many_arguments)]
    fn arbitrary_block_transaction_from_msa_and_records(
        num_outputs: usize,
        num_announcements: usize,
        msa_and_records: MsaAndRecords,
        input_utxos: Vec<Utxo>,
        lock_scripts_and_witnesses: Vec<LockScriptAndWitness>,
        coinbase_amount: NativeCurrencyAmount,
        timestamp: Timestamp,
        block_height: BlockHeight,
        network: Network,
    ) -> BoxedStrategy<BlockTransaction> {
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
            let rt = crate::proof_abstractions::test_runtime::tokio_runtime();
            let _guard = rt.enter();

            let proof_job_options = TritonVmProofJobOptions::default_with_network(network);

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
                    consensus_rule_set,
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
}

#[cfg(any(test, feature = "test-helpers"))]
pub fn deterministic_block_primitive_witness(network: Network) -> BlockPrimitiveWitness {
    use proptest::strategy::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    let mut test_runner = TestRunner::deterministic();

    BlockPrimitiveWitness::arbitrary(network)
        .new_tree(&mut test_runner)
        .unwrap()
        .current()
}
