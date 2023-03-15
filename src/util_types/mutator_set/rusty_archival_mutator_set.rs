use std::{cell::RefCell, sync::Arc};

use itertools::Itertools;
use rusty_leveldb::{WriteBatch, DB};
use twenty_first::{
    shared_math::{b_field_element::BFieldElement, tip5::Digest},
    util_types::{
        algebraic_hasher::AlgebraicHasher,
        mmr::{archival_mmr::ArchivalMmr, mmr_trait::Mmr},
        storage_schema::{
            DbtSchema, DbtSingleton, DbtVec, RustyKey, StorageReader, StorageSingleton,
            StorageWriter, WriteOperation,
        },
    },
};

use super::{
    active_window::ActiveWindow, archival_mutator_set::ArchivalMutatorSet, chunk::Chunk,
    mutator_set_kernel::MutatorSetKernel,
};

pub const AOCL_KEY: u8 = 0u8;
pub const SWBFI_KEY: u8 = 1u8;
pub const CHUNK_KEY: u8 = 2u8;
pub const ACTIVE_WINDOW_KEY: u8 = 3u8;
pub const SYNC_KEY: u8 = 4u8;

struct RamsReader {
    db: Arc<RefCell<DB>>,
}

impl StorageReader<RustyKey, RustyMSValue> for RamsReader {
    fn get(&mut self, key: RustyKey) -> Option<RustyMSValue> {
        self.db.as_ref().borrow_mut().get(&key.0).map(RustyMSValue)
    }
}

#[derive(Debug)]
pub struct RustyMSValue(Vec<u8>);

impl From<RustyMSValue> for u64 {
    fn from(value: RustyMSValue) -> Self {
        u64::from_be_bytes(value.0.try_into().unwrap())
    }
}
impl From<u64> for RustyMSValue {
    fn from(value: u64) -> Self {
        RustyMSValue(value.to_be_bytes().to_vec())
    }
}
impl From<RustyMSValue> for Digest {
    fn from(value: RustyMSValue) -> Self {
        Digest::new(
            value
                .0
                .chunks(8)
                .map(|ch| {
                    u64::from_be_bytes(ch.try_into().expect("Cannot cast RustyMSValue into Digest"))
                })
                .map(BFieldElement::new)
                .collect::<Vec<_>>()
                .try_into().expect("Can cast RustyMSValue into BFieldElements but number does not match that of Digest."),
        )
    }
}
impl From<Digest> for RustyMSValue {
    fn from(value: Digest) -> Self {
        RustyMSValue(
            value
                .values()
                .map(|b| b.value())
                .map(u64::to_be_bytes)
                .concat(),
        )
    }
}
impl From<RustyMSValue> for Chunk {
    fn from(value: RustyMSValue) -> Self {
        Chunk {
            relative_indices: value
                .0
                .chunks(4)
                .map(|ch| {
                    u32::from_be_bytes(
                        ch.try_into()
                            .expect("Could not convert RustyMSValue into Chunk"),
                    )
                })
                .collect::<Vec<_>>(),
        }
    }
}
impl From<Chunk> for RustyMSValue {
    fn from(value: Chunk) -> Self {
        RustyMSValue(
            value
                .relative_indices
                .iter()
                .map(|i| i.to_be_bytes())
                .collect::<Vec<_>>()
                .concat(),
        )
    }
}
impl From<RustyMSValue> for Vec<u32> {
    fn from(value: RustyMSValue) -> Self {
        value
            .0
            .chunks(4)
            .map(|ch| {
                u32::from_be_bytes(
                    ch.try_into()
                        .expect("Cannot unpack RustyMSValue as Vec<u32>s"),
                )
            })
            .collect_vec()
    }
}
impl From<Vec<u32>> for RustyMSValue {
    fn from(value: Vec<u32>) -> Self {
        RustyMSValue(
            value
                .iter()
                .map(|&i| i.to_be_bytes())
                .collect_vec()
                .concat(),
        )
    }
}

type AmsMmrStorage = Arc<RefCell<DbtVec<RustyKey, RustyMSValue, u64, Digest>>>;
type AmsChunkStorage = Arc<RefCell<DbtVec<RustyKey, RustyMSValue, u64, Chunk>>>;
pub struct RustyArchivalMutatorSet<H>
where
    H: AlgebraicHasher,
{
    pub ams: ArchivalMutatorSet<H, AmsMmrStorage, AmsChunkStorage>,
    schema: DbtSchema<RustyKey, RustyMSValue, RamsReader>,
    db: Arc<RefCell<DB>>,
    active_window_storage: Arc<RefCell<DbtSingleton<RustyKey, RustyMSValue, Vec<u32>>>>,
    sync_label: Arc<RefCell<DbtSingleton<RustyKey, RustyMSValue, Digest>>>,
}

impl<H: AlgebraicHasher> RustyArchivalMutatorSet<H> {
    pub fn connect(db: DB) -> RustyArchivalMutatorSet<H> {
        let db_pointer = Arc::new(RefCell::new(db));
        let reader = RamsReader {
            db: db_pointer.clone(),
        };
        let reader_pointer = Arc::new(RefCell::new(reader));
        let mut schema = DbtSchema::<RustyKey, RustyMSValue, RamsReader> {
            tables: vec![],
            reader: reader_pointer,
        };
        let aocl_storage = schema.new_vec::<u64, Digest>("aocl");
        let swbf_inactive_storage = schema.new_vec::<u64, Digest>("swbfi");
        let chunks = schema.new_vec::<u64, Chunk>("chunks");
        let active_window_storage =
            schema.new_singleton::<Vec<u32>>(RustyKey("active_window".into()));
        let sync_label = schema.new_singleton::<Digest>(RustyKey("sync_label".into()));
        let active_window = ActiveWindow::<H>::new();
        let kernel = MutatorSetKernel::<H, ArchivalMmr<H, AmsMmrStorage>> {
            aocl: ArchivalMmr::<H, AmsMmrStorage>::new(aocl_storage),
            swbf_inactive: ArchivalMmr::<H, AmsMmrStorage>::new(swbf_inactive_storage),
            swbf_active: active_window,
        };
        let ams = ArchivalMutatorSet::<H, AmsMmrStorage, AmsChunkStorage> { chunks, kernel };
        Self {
            ams,
            schema,
            db: db_pointer,
            active_window_storage,
            sync_label,
        }
    }

    pub fn get_sync_label(&self) -> Digest {
        self.sync_label.get()
    }

    pub fn set_sync_label(&mut self, sync_label: Digest) {
        self.sync_label.set(sync_label);
    }
}

impl<H: AlgebraicHasher> StorageWriter<RustyKey, RustyMSValue> for RustyArchivalMutatorSet<H> {
    fn persist(&mut self) {
        let mut write_batch = WriteBatch::new();

        self.active_window_storage
            .set(self.ams.kernel.swbf_active.sbf.clone());

        for table in &self.schema.tables {
            let operations = table.as_ref().borrow_mut().pull_queue();
            for op in operations {
                match op {
                    WriteOperation::Write(key, value) => write_batch.put(&key.0, &value.0),
                    WriteOperation::Delete(key) => write_batch.delete(&key.0),
                }
            }
        }

        self.db
            .as_ref()
            .borrow_mut()
            .write(write_batch, true)
            .expect("Could not persist to database.");
    }

    fn restore_or_new(&mut self) {
        for table in &self.schema.tables {
            table.as_ref().borrow_mut().restore_or_new();
        }

        // The field `digests` of ArchivalMMR should always have at
        // least one element (a dummy digest), owing to 1-indexation.
        self.ams.kernel.aocl.fix_dummy();
        self.ams.kernel.swbf_inactive.fix_dummy();
        println!(
            "Number of leafs in aocl at restoration: {}",
            self.ams.kernel.aocl.count_leaves(),
        );

        // populate active window
        self.ams.kernel.swbf_active.sbf = self.active_window_storage.get();
    }
}

#[cfg(test)]
mod tests {
    use crate::util_types::mutator_set::mutator_set_trait::MutatorSet;
    use itertools::Itertools;
    use rand::{random, thread_rng, RngCore};
    use twenty_first::shared_math::tip5::Tip5;

    use crate::{
        test_shared::mutator_set::make_item_and_randomness,
        util_types::mutator_set::{ms_membership_proof::MsMembershipProof, shared::BATCH_SIZE},
    };
    use twenty_first::util_types::mmr::mmr_trait::Mmr;

    use super::*;

    #[test]
    fn persist_test() {
        type H = Tip5;

        let num_additions = 150 + 2 * BATCH_SIZE as usize;
        let num_removals = 50usize;
        let mut rng = thread_rng();

        // let (mut archival_mutator_set, db) = empty_rustyleveldb_ams();
        let options = rusty_leveldb::in_memory();
        let db = DB::open("test-database", options.clone()).expect("Could not open database.");
        let mut rusty_mutator_set: RustyArchivalMutatorSet<H> =
            RustyArchivalMutatorSet::connect(db);
        println!("Connected to database");
        rusty_mutator_set.restore_or_new();
        println!("Restored or new odne.");

        let mut items = vec![];
        let mut mps = vec![];

        println!(
            "before additions mutator set contains {} elements",
            rusty_mutator_set.ams.kernel.aocl.count_leaves()
        );

        for _ in 0..num_additions {
            let (item, randomness) = make_item_and_randomness();
            let mut addition_record = rusty_mutator_set.ams.kernel.commit(&item, &randomness);
            let mp = rusty_mutator_set.ams.kernel.prove(&item, &randomness, true);

            MsMembershipProof::batch_update_from_addition(
                &mut mps.iter_mut().collect_vec(),
                &items,
                &mut rusty_mutator_set.ams.kernel,
                &addition_record,
            )
            .expect("Cannot batch update from addition");

            mps.push(mp);
            items.push(item);
            rusty_mutator_set.ams.add(&mut addition_record);
        }

        println!(
            "after additions mutator set contains {} elements",
            rusty_mutator_set.ams.kernel.aocl.count_leaves()
        );

        // Verify membership
        for (mp, item) in mps.iter().zip(items.iter()) {
            assert!(rusty_mutator_set.ams.verify(item, mp));
        }

        // Remove items
        let mut removed_items = vec![];
        let mut removed_mps = vec![];
        for _ in 0..num_removals {
            let index = rng.next_u64() as usize % items.len();
            let item = items[index];
            let membership_proof = mps[index].clone();
            let removal_record = rusty_mutator_set.ams.kernel.drop(&item, &membership_proof);
            MsMembershipProof::batch_update_from_remove(
                &mut mps.iter_mut().collect_vec(),
                &removal_record,
            )
            .expect("Could not batch update membership proofs from remove");

            rusty_mutator_set.ams.remove(&removal_record);

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
            rusty_mutator_set.ams.kernel.aocl.count_leaves()
        );

        // persist and drop
        rusty_mutator_set.persist();

        let active_window_before = rusty_mutator_set.ams.kernel.swbf_active.clone();

        rusty_mutator_set
            .db
            .as_ref()
            .borrow_mut()
            .close()
            .expect("Could not close database.");

        // new database
        let new_db = DB::open("test-database", options).expect("Could not open database.");
        let mut new_rusty_mutator_set: RustyArchivalMutatorSet<H> =
            RustyArchivalMutatorSet::connect(new_db);
        new_rusty_mutator_set.restore_or_new();

        // Verify memberships
        println!(
            "restored mutator set contains {} elements",
            new_rusty_mutator_set.ams.kernel.aocl.count_leaves()
        );
        for (index, (mp, item)) in mps.iter().zip(items.iter()).enumerate() {
            assert!(
                new_rusty_mutator_set.ams.verify(item, mp),
                "membership proof {index} does not verify"
            );
        }

        // Verify non-membership
        for (index, (mp, item)) in removed_mps.iter().zip(removed_items.iter()).enumerate() {
            assert!(
                !new_rusty_mutator_set.ams.verify(item, mp),
                "membership proof of non-member {index} still valid"
            );
        }

        let retrieved_sync_label = new_rusty_mutator_set.get_sync_label();
        assert_eq!(sync_label, retrieved_sync_label);

        let active_window_after = new_rusty_mutator_set.ams.kernel.swbf_active.clone();

        assert_eq!(active_window_before, active_window_after);
    }
}
