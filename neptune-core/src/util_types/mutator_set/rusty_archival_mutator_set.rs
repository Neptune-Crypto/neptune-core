use tasm_lib::twenty_first::tip5::digest::Digest;

use super::active_window::ActiveWindow;
use super::archival_mutator_set::ArchivalMutatorSet;
use super::removal_record::chunk::Chunk;
use crate::application::database::storage::storage_schema::traits::*;
use crate::application::database::storage::storage_schema::DbtSingleton;
use crate::application::database::storage::storage_schema::DbtVec;
use crate::application::database::storage::storage_schema::RustyKey;
use crate::application::database::storage::storage_schema::RustyValue;
use crate::application::database::storage::storage_schema::SimpleRustyStorage;
use crate::application::database::NeptuneLevelDb;
use crate::util_types::archival_mmr::ArchivalMmr;

type AmsMmrStorage = DbtVec<Digest>;
type AmsChunkStorage = DbtVec<Chunk>;

#[derive(Debug)]
pub struct RustyArchivalMutatorSet {
    ams: ArchivalMutatorSet<AmsMmrStorage, AmsChunkStorage>,
    storage: SimpleRustyStorage,
    active_window_storage: DbtSingleton<Vec<u32>>,
    sync_label: DbtSingleton<Digest>,
}

impl RustyArchivalMutatorSet {
    pub async fn connect(db: NeptuneLevelDb<RustyKey, RustyValue>) -> Self {
        let mut storage = SimpleRustyStorage::new_with_callback(
            db,
            "RustyArchivalMutatorSet-Schema",
            crate::LOG_TOKIO_LOCK_EVENT_CB,
        );

        let aocl = storage.schema.new_vec::<Digest>("aocl").await;
        let swbfi = storage.schema.new_vec::<Digest>("swbfi").await;
        let chunks = storage.schema.new_vec::<Chunk>("chunks").await;
        let active_window = storage
            .schema
            .new_singleton::<Vec<u32>>("active_window")
            .await;
        let sync_label = storage.schema.new_singleton::<Digest>("sync_label").await;

        let ams = ArchivalMutatorSet::<AmsMmrStorage, AmsChunkStorage> {
            chunks,
            aocl: ArchivalMmr::<AmsMmrStorage>::new(aocl).await,
            swbf_inactive: ArchivalMmr::<AmsMmrStorage>::new(swbfi).await,
            swbf_active: ActiveWindow::new(),
        };

        Self {
            ams,
            storage,
            sync_label,
            active_window_storage: active_window,
        }
    }

    #[inline]
    pub fn ams(&self) -> &ArchivalMutatorSet<AmsMmrStorage, AmsChunkStorage> {
        &self.ams
    }

    #[inline]
    pub fn ams_mut(&mut self) -> &mut ArchivalMutatorSet<AmsMmrStorage, AmsChunkStorage> {
        &mut self.ams
    }

    #[inline]
    pub fn get_sync_label(&self) -> Digest {
        self.sync_label.get()
    }

    #[inline]
    pub async fn set_sync_label(&mut self, sync_label: Digest) {
        self.sync_label.set(sync_label).await;
    }

    pub async fn restore_or_new(&mut self) {
        // The field `digests` of ArchivalMMR should always have at
        // least one element (a dummy digest), owing to 1-indexation.
        self.ams_mut().aocl.fix_dummy_async().await;
        self.ams_mut().swbf_inactive.fix_dummy_async().await;

        // populate active window
        self.ams_mut().swbf_active.sbf = self.active_window_storage.get();
    }
}

impl StorageWriter for RustyArchivalMutatorSet {
    async fn persist(&mut self) {
        self.active_window_storage
            .set(self.ams().swbf_active.sbf.clone())
            .await;

        self.storage.persist().await;
    }

    async fn drop_unpersisted(&mut self) {
        self.ams_mut().swbf_active.sbf = self.active_window_storage.get();
        self.storage.drop_unpersisted().await;
        self.ams_mut().aocl.delete_cache().await;
        self.ams_mut().swbf_inactive.delete_cache().await;
        self.ams_mut().chunks.delete_cache().await;
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use itertools::Itertools;
    use macro_rules_attr::apply;
    use rand::random;
    use rand::RngCore;

    use super::*;
    use crate::tests::shared_tokio_runtime;
    use crate::util_types::mutator_set::commit;
    use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
    use crate::util_types::mutator_set::shared::BATCH_SIZE;
    use crate::util_types::test_shared::mutator_set::*;

    #[apply(shared_tokio_runtime)]
    async fn persist_test() {
        let num_additions = 150 + 2 * BATCH_SIZE as usize;
        let num_removals = 50usize;
        let mut rng = rand::rng();

        let db = NeptuneLevelDb::open_new_test_database(false, None, None, None)
            .await
            .unwrap();
        let db_path = db.path().clone();
        let mut rusty_mutator_set: RustyArchivalMutatorSet =
            RustyArchivalMutatorSet::connect(db).await;
        println!("Connected to database");
        rusty_mutator_set.restore_or_new().await;
        println!("Restored or new done.");

        let mut items = vec![];
        let mut mps = vec![];

        println!(
            "before additions mutator set contains {} elements",
            rusty_mutator_set.ams().aocl.num_leafs().await
        );

        for _ in 0..num_additions {
            let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
            let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
            let mp = rusty_mutator_set
                .ams()
                .prove(item, sender_randomness, receiver_preimage)
                .await;

            MsMembershipProof::batch_update_from_addition(
                &mut mps.iter_mut().collect_vec(),
                &items,
                &rusty_mutator_set.ams().accumulator().await,
                &addition_record,
            )
            .expect("Cannot batch update from addition");

            mps.push(mp);
            items.push(item);
            rusty_mutator_set.ams_mut().add(&addition_record).await;
        }

        println!(
            "after additions mutator set contains {} elements",
            rusty_mutator_set.ams().aocl.num_leafs().await
        );

        // Verify membership
        for (mp, &item) in mps.iter().zip(items.iter()) {
            assert!(rusty_mutator_set.ams().verify(item, mp).await);
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
                .drop(item, &membership_proof)
                .await;
            MsMembershipProof::batch_update_from_remove(
                &mut mps.iter_mut().collect_vec(),
                &removal_record,
            )
            .expect("Could not batch update membership proofs from remove");

            rusty_mutator_set.ams_mut().remove(&removal_record).await;

            removed_items.push(items.remove(index));
            removed_mps.push(mps.remove(index));
        }

        // Let's store the active window back to the database and create
        // a new archival object from the databases it contains and then check
        // that this archival MS contains the same values
        let sync_label: Digest = random();
        rusty_mutator_set.set_sync_label(sync_label).await;

        println!(
            "at persistence mutator set aocl contains {} elements",
            rusty_mutator_set.ams().aocl.num_leafs().await
        );

        // persist and drop
        rusty_mutator_set.persist().await;

        let active_window_before = rusty_mutator_set.ams().swbf_active.clone();

        drop(rusty_mutator_set); // Drop DB

        // new database
        let new_db = NeptuneLevelDb::open_test_database(&db_path, true, None, None, None)
            .await
            .expect("should open existing database");
        let mut new_rusty_mutator_set: RustyArchivalMutatorSet =
            RustyArchivalMutatorSet::connect(new_db).await;
        new_rusty_mutator_set.restore_or_new().await;

        // Verify memberships
        println!(
            "restored mutator set contains {} elements",
            new_rusty_mutator_set.ams().aocl.num_leafs().await
        );
        for (index, (mp, &item)) in mps.iter().zip(items.iter()).enumerate() {
            assert!(
                new_rusty_mutator_set.ams().verify(item, mp).await,
                "membership proof {index} does not verify"
            );
        }

        // Verify non-membership
        for (index, (mp, &item)) in removed_mps.iter().zip(removed_items.iter()).enumerate() {
            assert!(
                !new_rusty_mutator_set.ams().verify(item, mp).await,
                "membership proof of non-member {index} still valid",
            );
        }

        let retrieved_sync_label = new_rusty_mutator_set.get_sync_label();
        assert_eq!(sync_label, retrieved_sync_label);

        let active_window_after = new_rusty_mutator_set.ams().swbf_active.clone();

        assert_eq!(active_window_before, active_window_after);
    }
}
