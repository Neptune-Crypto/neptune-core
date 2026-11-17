//! Database-backed test-support constructors for the archival mutator set.
//!
//! These were split out of `neptune_mutator_set::test_shared` together with the
//! archival types they depend on. The accumulator-only helpers still live in
//! [`neptune_mutator_set::test_shared`].

use neptune_database::storage::storage_vec::traits::*;
use neptune_database::NeptuneLevelDb;
use neptune_mutator_set::commit;
use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use neptune_mutator_set::removal_record::chunk::Chunk;
use neptune_mutator_set::shared::CHUNK_SIZE;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::twenty_first::tip5::digest::Digest;

use crate::archival_mutator_set::ArchivalMutatorSet;
use crate::rusty_archival_mutator_set::RustyArchivalMutatorSet;

pub async fn get_all_indices_with_duplicates<
    MmrStorage: StorageVec<Digest> + Send + Sync,
    ChunkStorage: StorageVec<Chunk> + Send + Sync,
>(
    archival_mutator_set: &mut ArchivalMutatorSet<MmrStorage, ChunkStorage>,
) -> Vec<u128> {
    let mut ret: Vec<u128> = vec![];

    for index in &archival_mutator_set.swbf_active.sbf {
        ret.push(u128::from(*index));
    }

    let chunk_count = archival_mutator_set.chunks.len().await;
    for chunk_index in 0..chunk_count {
        let chunk = archival_mutator_set.chunks.get(chunk_index).await;
        for index in &chunk.relative_indices {
            ret.push(u128::from(*index) + u128::from(CHUNK_SIZE) * u128::from(chunk_index));
        }
    }

    ret
}

/// A mutator set with `num_additions` items added, deterministically
/// derived from `seed`, and every `removal_stride`-th of them removed. Returns
/// the absolute index sets of the items not removed, in order of addition.
pub async fn populated_rusty_mutator_set(
    num_additions: u64,
    removal_stride: u64,
    seed: u64,
) -> (RustyArchivalMutatorSet, Vec<AbsoluteIndexSet>) {
    let mut rms = empty_rusty_mutator_set().await;
    let digest = |i: u64, k: u64| {
        Tip5::hash_varlen(&[
            BFieldElement::new(seed),
            BFieldElement::new(i),
            BFieldElement::new(k),
        ])
    };

    let mut removed = vec![];
    let mut kept = vec![];
    for i in 0..num_additions {
        let (item, sender_randomness, receiver_preimage) =
            (digest(i, 0), digest(i, 1), digest(i, 2));
        rms.ams_mut()
            .add(&commit(item, sender_randomness, receiver_preimage.hash()))
            .await;
        let index_set = AbsoluteIndexSet::compute(item, sender_randomness, receiver_preimage, i);
        if i % removal_stride == 0 {
            removed.push(index_set);
        } else {
            kept.push(index_set);
        }
    }
    rms.ams_mut()
        .batch_remove(&removed)
        .await
        .expect("distinct items are no double spends");

    (rms, kept)
}

pub async fn empty_rusty_mutator_set() -> RustyArchivalMutatorSet {
    let db = NeptuneLevelDb::open_new_test_database(true, None, None, None)
        .await
        .unwrap();
    let rusty_mutator_set: RustyArchivalMutatorSet = RustyArchivalMutatorSet::connect(db).await;
    rusty_mutator_set
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use macro_rules_attr::apply;
    use neptune_mutator_set::test_shared::insert_mock_item;
    use neptune_mutator_set::test_shared::mock_item_and_randomnesses;

    use super::*;
    use crate::test_utils::shared_tokio_runtime;

    #[apply(shared_tokio_runtime)]
    async fn can_call() {
        let mut rms = empty_rusty_mutator_set().await;
        let ams = rms.ams_mut();
        let _ = get_all_indices_with_duplicates(ams).await;
        let _ = mock_item_and_randomnesses();
        let _ = insert_mock_item(&mut ams.accumulator().await);
    }
}
