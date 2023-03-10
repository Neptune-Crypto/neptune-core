use std::{cell::RefCell, rc::Rc};

use rusty_leveldb::{WriteBatch, DB};
use twenty_first::{
    shared_math::tip5::Digest,
    util_types::{algebraic_hasher::AlgebraicHasher, storage_vec::RustyLevelDbVec},
};

use super::{active_window::ActiveWindow, archival_mutator_set::ArchivalMutatorSet, chunk::Chunk};

pub const AOCL_KEY: u8 = 0u8;
pub const SWBFI_KEY: u8 = 1u8;
pub const CHUNK_KEY: u8 = 2u8;
pub const ACTIVE_WINDOW_KEY: u8 = 3u8;
pub const SYNC_KEY: u8 = 4u8;

pub type RustyLevelDbArchivalMutatorSet<H> =
    ArchivalMutatorSet<H, RustyLevelDbVec<Digest>, RustyLevelDbVec<Chunk>>;

impl<H: AlgebraicHasher> RustyLevelDbArchivalMutatorSet<H> {
    /// Restore from database or create new. Return the Archival
    /// Mutator Set and the sync label.
    pub fn restore(db: Rc<RefCell<DB>>) -> (Self, Digest) {
        let aw_bytes = db.borrow_mut().get(&[ACTIVE_WINDOW_KEY]);
        let aw = match aw_bytes {
            Some(bytes) => bincode::deserialize(&bytes).unwrap(),
            None => ActiveWindow::default(),
        };

        let aocl_storage = RustyLevelDbVec::new(db.clone(), AOCL_KEY, "aocl");
        let swbfi_storage = RustyLevelDbVec::new(db.clone(), SWBFI_KEY, "swbfi");
        let chunk_storage = RustyLevelDbVec::new(db.clone(), CHUNK_KEY, "chunks");

        let sync_label = match db.borrow_mut().get(&[SYNC_KEY]) {
            Some(bytes) => bincode::deserialize(&bytes).unwrap(),
            None => Digest::default(),
        };

        (
            Self::new_or_restore(aocl_storage, swbfi_storage, chunk_storage, aw),
            sync_label,
        )
    }

    /// Persist to disk with label.
    pub fn persist(&mut self, write_batch: &mut WriteBatch, sync_label: Digest) {
        self.kernel.aocl.persist(write_batch);
        self.kernel.swbf_inactive.persist(write_batch);
        self.chunks.pull_queue(write_batch);
        // self.kernel.swbf_active.sbf.pull_queue(write_batch);

        write_batch.put(
            &[ACTIVE_WINDOW_KEY],
            &bincode::serialize(&self.kernel.swbf_active).unwrap(),
        );

        write_batch.put(&[SYNC_KEY], &bincode::serialize(&sync_label).unwrap());
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use rand::{random, thread_rng, RngCore};
    use twenty_first::shared_math::tip5::Tip5;

    use crate::{
        test_shared::mutator_set::{empty_rustyleveldb_ams, make_item_and_randomness},
        util_types::mutator_set::{
            ms_membership_proof::MsMembershipProof, mutator_set_trait::MutatorSet,
            shared::BATCH_SIZE,
        },
    };

    use super::*;

    #[test]
    fn persist_test() {
        type H = Tip5;

        let num_additions = 150 + 2 * BATCH_SIZE as usize;
        let num_removals = 50usize;
        let mut rng = thread_rng();

        let (mut archival_mutator_set, db) = empty_rustyleveldb_ams();

        let mut items = vec![];
        let mut mps = vec![];

        for _ in 0..num_additions {
            let (item, randomness) = make_item_and_randomness();
            let mut addition_record = archival_mutator_set.commit(&item, &randomness);
            let mp = archival_mutator_set.prove(&item, &randomness, true);

            MsMembershipProof::batch_update_from_addition(
                &mut mps.iter_mut().collect_vec(),
                &items,
                &mut archival_mutator_set.kernel,
                &addition_record,
            )
            .expect("Cannot batch update from addition");

            mps.push(mp);
            items.push(item);
            archival_mutator_set.add(&mut addition_record);
        }

        // Verify membership
        for (mp, item) in mps.iter().zip(items.iter()) {
            assert!(archival_mutator_set.verify(item, mp));
        }

        // Remove items
        let mut removed_items = vec![];
        let mut removed_mps = vec![];
        for _ in 0..num_removals {
            let index = rng.next_u64() as usize % items.len();
            let item = items[index];
            let membership_proof = mps[index].clone();
            let removal_record = archival_mutator_set.drop(&item, &membership_proof);
            MsMembershipProof::batch_update_from_remove(
                &mut mps.iter_mut().collect_vec(),
                &removal_record,
            )
            .expect("Could not batch update membership proofs from remove");

            archival_mutator_set.remove(&removal_record);

            removed_items.push(items.remove(index));
            removed_mps.push(mps.remove(index));
        }

        // let mut removal_record_indices0 = removal_record0.absolute_indices.to_vec();
        // let mut set_indices_in_archival_ms =
        //     get_all_indices_with_duplicates(&mut archival_mutator_set);
        // removal_record_indices0.sort_unstable();
        // set_indices_in_archival_ms.sort_unstable();

        // assert_eq!(removal_record_indices0, set_indices_in_archival_ms, "Set indices in MS must match removal record indices when Bloom filter was empty prior to removal.");

        // Let's store the active window back to the database and create
        // a new archival object from the databases it contains and then check
        // that this archival MS contains the same values
        let sync_label: Digest = random();
        let mut write_batch = WriteBatch::new();
        archival_mutator_set.persist(&mut write_batch, sync_label);
        db.borrow_mut().write(write_batch, true).unwrap();

        let active_window_before = archival_mutator_set.kernel.swbf_active.clone();

        drop(archival_mutator_set);

        let (mut new_archival_mutator_set, retrieved_sync_label) =
            RustyLevelDbArchivalMutatorSet::<H>::restore(db);

        // Verify memberships
        for (index, (mp, item)) in mps.iter().zip(items.iter()).enumerate() {
            assert!(
                new_archival_mutator_set.verify(item, mp),
                "membership proof {index} does not verify"
            );
        }

        // Verify non-membership
        for (mp, item) in removed_mps.iter().zip(removed_items.iter()) {
            assert!(!new_archival_mutator_set.verify(item, mp));
        }

        assert_eq!(sync_label, retrieved_sync_label);

        let active_window_after = new_archival_mutator_set.kernel.swbf_active.clone();

        assert_eq!(active_window_before, active_window_after);
    }
}
