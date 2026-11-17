//! The cost of reading a block's extra data from the archival mutator set,
//! which happens while a new tip is applied, compared with the cost of
//! applying the block's removals to the archival mutator set.

use divan::Bencher;
use itertools::Itertools;
use neptune_archival_mutator_set::rusty_archival_mutator_set::RustyArchivalMutatorSet;
use neptune_archival_mutator_set::test_shared::populated_rusty_mutator_set;
use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use neptune_mutator_set::removal_record::removal_record_list::RemovalRecordList;
use neptune_mutator_set::removal_record::RemovalRecord;

fn main() {
    divan::main();
}

/// Items in the mutator set before the block.
const NUM_ADDITIONS: u64 = 1 << 16;

/// Every this many items are spent before the block.
const REMOVAL_STRIDE: u64 = 3;

const NUM_INPUTS: &[usize] = &[10, 100, 1000];

/// A populated mutator set and the index sets of a block's inputs, spread
/// over all unspent items.
fn setup(
    rt: &tokio::runtime::Runtime,
    num_inputs: usize,
) -> (RustyArchivalMutatorSet, Vec<AbsoluteIndexSet>) {
    let (rms, unspent) = rt.block_on(populated_rusty_mutator_set(
        NUM_ADDITIONS,
        REMOVAL_STRIDE,
        0,
    ));
    let step = unspent.len() / num_inputs;
    let inputs = unspent
        .into_iter()
        .step_by(step)
        .take(num_inputs)
        .collect_vec();

    (rms, inputs)
}

/// One chunk dictionary per input, deduplicated afterwards.
#[divan::bench(args = NUM_INPUTS, sample_count = 10)]
fn naive(bencher: Bencher, num_inputs: usize) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (rms, inputs) = setup(&rt, num_inputs);
    let ams = rms.ams();

    bencher.bench_local(|| {
        rt.block_on(async {
            let mut removal_records = vec![];
            for &absolute_indices in &inputs {
                removal_records.push(RemovalRecord {
                    absolute_indices,
                    target_chunks: ams.chunk_dictionary(absolute_indices).await,
                });
            }
            let num_leafs_swbfi = ams.swbf_inactive.num_leafs().await;
            RemovalRecordList::deconstruct(removal_records, num_leafs_swbfi, true)
        })
    });
}

/// Each chunk and node read once, nothing hashed.
#[divan::bench(args = NUM_INPUTS, sample_count = 10)]
fn deduplicated(bencher: Bencher, num_inputs: usize) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (rms, inputs) = setup(&rt, num_inputs);
    let ams = rms.ams();

    bencher.bench_local(|| {
        rt.block_on(async {
            let (authentication_structures, chunks) = ams.chunk_witness_data(&inputs).await;
            let chunks = chunks.iter().map(|chunk| chunk.pack(true)).collect_vec();
            (authentication_structures, chunks)
        })
    });
}

/// Reference: applying the inputs' removals to the archival mutator set, and
/// reverting them so that every sample starts from the same state.
#[divan::bench(args = NUM_INPUTS, sample_count = 10)]
fn batch_remove_and_revert(bencher: Bencher, num_inputs: usize) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (mut rms, inputs) = setup(&rt, num_inputs);

    bencher.bench_local(|| {
        rt.block_on(async {
            let ams = rms.ams_mut();
            ams.batch_remove(&inputs).await.unwrap();
            ams.revert_batch_remove(&inputs).await;
        })
    });
}
