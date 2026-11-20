//! The cost of the `KnowsBlockExtraData` program as a function of the parent
//! block's number of inputs, against an archival mutator set.
//!
//! Prints a table; run with `cargo bench --bench knows_block_extra_data`.

use itertools::Itertools;
use neptune_archival_mutator_set::test_shared::populated_rusty_mutator_set;
use neptune_consensus::block::block_appendix::BlockAppendix;
use neptune_consensus::block::validity::knows_block_extra_data::sampled_inputs;
use neptune_consensus::block::validity::knows_block_extra_data::KnowsBlockExtraData;
use neptune_consensus::block::validity::knows_block_extra_data::KnowsBlockExtraDataWitness;
use neptune_consensus::block::Block;
use neptune_consensus::consensus_rule_set::ConsensusRuleSet;
use neptune_consensus::proof_abstractions::SecretWitness;
use neptune_consensus::transaction::transaction_kernel::TransactionKernelModifier;
use neptune_mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
use neptune_mutator_set::removal_record::removal_record_list::RemovalRecordList;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_primitives::block_height::BlockHeight;
use neptune_primitives::network::Network;
use tasm_lib::prelude::Digest;
use tasm_lib::snippet_bencher::BenchmarkResult;
use tasm_lib::triton_vm::prelude::*;

/// Items in the mutator set; every second one is spent.
const LOG2_NUM_ADDITIONS: u32 = 22;
const NUM_PARENT_INPUTS: &[usize] = &[100, 1000, 5000, 16_384];

fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (rms, unspent) = rt.block_on(populated_rusty_mutator_set(1 << LOG2_NUM_ADDITIONS, 2, 0));
    let ams = rms.ams();
    let mutator_set = rt.block_on(ams.accumulator());
    println!(
        "AOCL 2^{LOG2_NUM_ADDITIONS}, inactive SWBF {} chunks",
        rt.block_on(ams.swbf_inactive.num_leafs())
    );
    println!(
        "parent inputs | chunks | clock cycles | hash rows | u32 rows | op stack rows | ram rows | padded height"
    );

    let activation_height = BlockHeight::from(5u64);
    for &num_parent_inputs in NUM_PARENT_INPUTS {
        let step = unspent.len() / num_parent_inputs;
        let index_sets = unspent
            .iter()
            .step_by(step)
            .take(num_parent_inputs)
            .copied()
            .collect_vec();
        let stripped = index_sets
            .iter()
            .map(|&absolute_indices| RemovalRecord {
                absolute_indices,
                target_chunks: ChunkDictionary::empty(),
            })
            .collect_vec();

        let mut prev_block = Block::genesis(Network::Main);
        let kernel = TransactionKernelModifier::default()
            .inputs(RemovalRecordList::pack(stripped.clone(), true))
            .mutator_set_hash(mutator_set.hash())
            .modify(prev_block.body().transaction_kernel.clone());
        prev_block.set_transaction_kernel(kernel);
        prev_block.kernel_mut().header.height = activation_height;
        prev_block.kernel_mut().header.prev_block_digest = Digest::default();
        let claim = KnowsBlockExtraData::claim(
            Digest::default(),
            activation_height,
            ConsensusRuleSet::HardforkZeta,
        );
        prev_block.set_appendix(BlockAppendix::new(vec![claim]));

        // Only the sampled inputs need their chunk data.
        let mut full_inputs = stripped;
        for position in sampled_inputs(prev_block.hash(), num_parent_inputs) {
            full_inputs[position].target_chunks =
                rt.block_on(ams.chunk_dictionary(full_inputs[position].absolute_indices));
        }

        let witness = KnowsBlockExtraDataWitness::new(
            &prev_block,
            &mutator_set,
            &full_inputs,
            activation_height,
        );
        let (aet, _) = VM::trace_execution(
            witness.program(),
            witness.standard_input(),
            witness.nondeterminism(),
        )
        .unwrap();
        let rows = BenchmarkResult::new(&aet);
        println!(
            "{num_parent_inputs:>13} | {:>6} | {:>12} | {:>9} | {:>8} | {:>13} | {:>8} | 2^{}",
            witness.num_chunks(),
            rows.clock_cycle_count,
            rows.hash_table_height,
            rows.u32_table_height,
            rows.op_stack_table_height,
            rows.ram_table_height,
            aet.padded_height().ilog2()
        );
    }
}
