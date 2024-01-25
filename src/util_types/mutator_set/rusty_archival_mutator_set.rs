use crate::prelude::twenty_first;

use twenty_first::storage::level_db::DB;
use twenty_first::storage::storage_schema::{traits::*, DbtSingleton, DbtVec, SimpleRustyStorage};
use twenty_first::{
    shared_math::{bfield_codec::BFieldCodec, tip5::Digest},
    util_types::{algebraic_hasher::AlgebraicHasher, mmr::archival_mmr::ArchivalMmr},
};

use super::{
    active_window::ActiveWindow, archival_mutator_set::ArchivalMutatorSet, chunk::Chunk,
    mutator_set_kernel::MutatorSetKernel,
};

type AmsMmrStorage = DbtVec<Digest>;
type AmsChunkStorage = DbtVec<Chunk>;
pub struct RustyArchivalMutatorSet<H>
where
    H: AlgebraicHasher + BFieldCodec,
{
    ams: ArchivalMutatorSet<H, AmsMmrStorage, AmsChunkStorage>,
    storage: SimpleRustyStorage,
    active_window_storage: DbtSingleton<Vec<u32>>,
    sync_label: DbtSingleton<Digest>,
}

impl<H: AlgebraicHasher + BFieldCodec> RustyArchivalMutatorSet<H> {
    pub fn connect(db: DB) -> Self {
        let mut storage = SimpleRustyStorage::new_with_callback(
            db,
            "RustyArchivalMutatorSet-Schema",
            crate::LOG_LOCK_EVENT_CB,
        );

        let aocl = storage.schema.new_vec::<Digest>("aocl");
        let swbfi = storage.schema.new_vec::<Digest>("swbfi");
        let chunks = storage.schema.new_vec::<Chunk>("chunks");
        let active_window = storage.schema.new_singleton::<Vec<u32>>("active_window");
        let sync_label = storage.schema.new_singleton::<Digest>("sync_label");
        storage.restore_or_new();

        let kernel = MutatorSetKernel::<H, ArchivalMmr<H, AmsMmrStorage>> {
            aocl: ArchivalMmr::<H, AmsMmrStorage>::new(aocl),
            swbf_inactive: ArchivalMmr::<H, AmsMmrStorage>::new(swbfi),
            swbf_active: ActiveWindow::<H>::new(),
        };

        let ams = ArchivalMutatorSet::<H, AmsMmrStorage, AmsChunkStorage> { chunks, kernel };

        Self {
            ams,
            storage,
            sync_label,
            active_window_storage: active_window,
        }
    }

    #[inline]
    pub fn ams(&self) -> &ArchivalMutatorSet<H, AmsMmrStorage, AmsChunkStorage> {
        &self.ams
    }

    #[inline]
    pub fn ams_mut(&mut self) -> &mut ArchivalMutatorSet<H, AmsMmrStorage, AmsChunkStorage> {
        &mut self.ams
    }

    #[inline]
    pub fn get_sync_label(&self) -> Digest {
        self.sync_label.get()
    }

    #[inline]
    pub fn set_sync_label(&mut self, sync_label: Digest) {
        self.sync_label.set(sync_label);
    }
}

impl<H: AlgebraicHasher + BFieldCodec> StorageWriter for RustyArchivalMutatorSet<H> {
    fn persist(&mut self) {
        self.active_window_storage
            .set(self.ams().kernel.swbf_active.sbf.clone());

        self.storage.persist();
    }

    fn restore_or_new(&mut self) {
        self.storage.restore_or_new();

        // The field `digests` of ArchivalMMR should always have at
        // least one element (a dummy digest), owing to 1-indexation.
        self.ams_mut().kernel.aocl.fix_dummy();
        self.ams_mut().kernel.swbf_inactive.fix_dummy();

        // populate active window
        self.ams_mut().kernel.swbf_active.sbf = self.active_window_storage.get();
    }
}

#[cfg(test)]
mod tests {
    use crate::util_types::mutator_set::mutator_set_trait::{commit, MutatorSet};
    use itertools::Itertools;
    use rand::{random, thread_rng, RngCore};
    use twenty_first::shared_math::tip5::Tip5;

    use crate::util_types::mutator_set::{
        ms_membership_proof::MsMembershipProof, shared::BATCH_SIZE,
    };
    use crate::util_types::test_shared::mutator_set::*;
    use twenty_first::util_types::mmr::mmr_trait::Mmr;

    use super::*;

    #[tokio::test]
    async fn persist_test() {
        type H = Tip5;

        let num_additions = 150 + 2 * BATCH_SIZE as usize;
        let num_removals = 50usize;
        let mut rng = thread_rng();

        let db = DB::open_new_test_database(false, None, None, None).unwrap();
        let db_path = db.path().clone();
        let mut rusty_mutator_set: RustyArchivalMutatorSet<H> =
            RustyArchivalMutatorSet::connect(db);
        println!("Connected to database");
        rusty_mutator_set.restore_or_new();
        println!("Restored or new odne.");

        let mut items = vec![];
        let mut mps = vec![];

        println!(
            "before additions mutator set contains {} elements",
            rusty_mutator_set.ams().kernel.aocl.count_leaves()
        );

        for _ in 0..num_additions {
            let (item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();
            let addition_record =
                commit::<H>(item, sender_randomness, receiver_preimage.hash::<H>());
            let mp =
                rusty_mutator_set
                    .ams()
                    .kernel
                    .prove(item, sender_randomness, receiver_preimage);

            MsMembershipProof::batch_update_from_addition(
                &mut mps.iter_mut().collect_vec(),
                &items,
                &rusty_mutator_set.ams().kernel,
                &addition_record,
            )
            .expect("Cannot batch update from addition");

            mps.push(mp);
            items.push(item);
            rusty_mutator_set.ams_mut().add(&addition_record);
        }

        println!(
            "after additions mutator set contains {} elements",
            rusty_mutator_set.ams().kernel.aocl.count_leaves()
        );

        // Verify membership
        for (mp, &item) in mps.iter().zip(items.iter()) {
            assert!(rusty_mutator_set.ams().verify(item, mp));
        }

        // Remove items
        let mut removed_items = vec![];
        let mut removed_mps = vec![];
        for _ in 0..num_removals {
            let index = rng.next_u64() as usize % items.len();
            let item = items[index];
            let membership_proof = mps[index].clone();
            let removal_record = rusty_mutator_set
                .ams_mut()
                .kernel
                .drop(item, &membership_proof);
            MsMembershipProof::batch_update_from_remove(
                &mut mps.iter_mut().collect_vec(),
                &removal_record,
            )
            .expect("Could not batch update membership proofs from remove");

            rusty_mutator_set.ams_mut().remove(&removal_record);

            removed_items.push(items.remove(index));
            removed_mps.push(mps.remove(index));
        }

        // Let's store the active window back to the database and create
        // a new archival object from the databases it contains and then check
        // that this archival MS contains the same values
        let sync_label: Digest = random();
        rusty_mutator_set.set_sync_label(sync_label);

        println!(
            "at persistence mutator set aocl contains {} elements",
            rusty_mutator_set.ams().kernel.aocl.count_leaves()
        );

        // persist and drop
        rusty_mutator_set.persist();

        let active_window_before = rusty_mutator_set.ams().kernel.swbf_active.clone();

        drop(rusty_mutator_set); // Drop DB

        // new database
        let new_db = DB::open_test_database(&db_path, true, None, None, None)
            .expect("should open existing database");
        let mut new_rusty_mutator_set: RustyArchivalMutatorSet<H> =
            RustyArchivalMutatorSet::connect(new_db);
        new_rusty_mutator_set.restore_or_new();

        // Verify memberships
        println!(
            "restored mutator set contains {} elements",
            new_rusty_mutator_set.ams().kernel.aocl.count_leaves()
        );
        for (index, (mp, &item)) in mps.iter().zip(items.iter()).enumerate() {
            assert!(
                new_rusty_mutator_set.ams().verify(item, mp),
                "membership proof {index} does not verify"
            );
        }

        // Verify non-membership
        for (index, (mp, &item)) in removed_mps.iter().zip(removed_items.iter()).enumerate() {
            assert!(
                !new_rusty_mutator_set.ams().verify(item, mp),
                "membership proof of non-member {index} still valid"
            );
        }

        let retrieved_sync_label = new_rusty_mutator_set.get_sync_label();
        assert_eq!(sync_label, retrieved_sync_label);

        let active_window_after = new_rusty_mutator_set.ams().kernel.swbf_active.clone();

        assert_eq!(active_window_before, active_window_after);
    }
}
