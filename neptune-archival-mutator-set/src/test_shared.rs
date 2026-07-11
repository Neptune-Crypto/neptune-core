//! Database-backed test-support constructors for the archival mutator set.
//!
//! These were split out of `neptune_mutator_set::test_shared` together with the
//! archival types they depend on. The accumulator-only helpers still live in
//! [`neptune_mutator_set::test_shared`].

use neptune_database::storage::storage_vec::traits::*;
use neptune_database::NeptuneLevelDb;
use neptune_mutator_set::removal_record::chunk::Chunk;
use neptune_mutator_set::shared::CHUNK_SIZE;
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
