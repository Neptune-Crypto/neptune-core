use std::io;
use std::io::BufRead;
use std::io::Write;

use neptune_archival_mmr::ArchivalMmr;
use neptune_database::storage::storage_schema::traits::*;
use neptune_database::storage::storage_schema::DbtSingleton;
use neptune_database::storage::storage_schema::DbtVec;
use neptune_database::storage::storage_schema::RustyKey;
use neptune_database::storage::storage_schema::RustyValue;
use neptune_database::storage::storage_schema::SimpleRustyStorage;
use neptune_database::storage::storage_vec::traits::*;
use neptune_database::NeptuneLevelDb;
use neptune_mutator_set::active_window::ActiveWindow;
use neptune_mutator_set::removal_record::chunk::Chunk;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::tip5::digest::Digest;
use tasm_lib::twenty_first::util_types::mmr::shared_advanced::right_lineage_length_and_own_height;

use crate::archival_mutator_set::ArchivalMutatorSet;

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
        let mut storage = SimpleRustyStorage::new(db);

        // Don't change this order, since it's stored on disk, and used to
        // share the archival mutator set.
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

    /// A handle to the database, for streaming the set out and for
    /// replacing it.
    pub fn db(&self) -> NeptuneLevelDb<RustyKey, RustyValue> {
        self.storage.db().clone()
    }

    // The tables as numbered in `connect`, in the order they are made.
    const AOCL_TABLE: u8 = 0;
    const CHUNKS_TABLE: u8 = 2;
    const WINDOW_TABLE: u8 = 3;
    const SYNC_LABEL_TABLE: u8 = 4;

    // The tags of the items in a stream of the set.
    const AOCL_LEAF: u8 = 0;
    const CHUNK: u8 = 1;
    const WINDOW: u8 = 2;
    const SYNC_LABEL: u8 = 3;

    /// Num of elements read into a set between each persist.
    const NUM_ELEMENTS_PER_PERSIST: usize = 4096;

    /// Write what the set is made of to `writer`, in one pass over the
    /// stored pairs: the AOCL leafs, the chunks, the active window and the
    /// sync label, each as one tag byte followed by its stored encoding.
    /// The internal nodes of both MMRs are left out. Blocks.
    pub fn write_leafs(
        db: &NeptuneLevelDb<RustyKey, RustyValue>,
        writer: &mut impl Write,
    ) -> io::Result<u64> {
        let mut written = 0;
        for (key, value) in db.iter_u8() {
            // Both are stored as bincode of a byte vector: an 8-byte length,
            // then the bytes. A vector element's key is its table followed
            // by its index; a singleton's key is its table alone.
            let key = &key[8..];
            let element = &value[8..];
            let tag = match (key.first(), key.len()) {
                (Some(&Self::AOCL_TABLE), 9) => {
                    let node_index = u64::from_be_bytes(key[1..].try_into().unwrap());
                    let is_leaf =
                        node_index > 0 && right_lineage_length_and_own_height(node_index).1 == 0;
                    if !is_leaf {
                        continue;
                    }
                    Self::AOCL_LEAF
                }
                (Some(&Self::CHUNKS_TABLE), 9) => Self::CHUNK,
                (Some(&Self::WINDOW_TABLE), 1) => Self::WINDOW,
                (Some(&Self::SYNC_LABEL_TABLE), 1) => Self::SYNC_LABEL,
                _ => continue,
            };
            writer.write_all(&[tag])?;
            writer.write_all(element)?;
            written += 1 + element.len() as u64;
        }
        Ok(written)
    }

    /// Build an archival mutator set from the output of [`Self::write_leafs`],
    /// stopping as soon as it holds more AOCL leafs or chunks than allowed.
    ///
    /// Own archival mutator set must be empty when this is done.
    pub async fn read_leafs(
        &mut self,
        reader: &mut impl BufRead,
        max_aocl_leafs: u64,
        max_chunks: u64,
    ) -> io::Result<()> {
        let mut since_persist = 0;
        let mut aocl_leafs = 0;
        let mut chunks = 0;
        let mut tag = [0u8];
        loop {
            match reader.read_exact(&mut tag) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(error) => return Err(error),
            }
            match tag[0] {
                Self::AOCL_LEAF => {
                    aocl_leafs += 1;
                    if aocl_leafs > max_aocl_leafs {
                        return Err(io::Error::other("more AOCL leafs than allowed"));
                    }
                    let leaf = bincode::deserialize_from(&mut *reader).map_err(io::Error::other)?;
                    self.ams_mut().aocl.append(leaf).await;
                }
                Self::CHUNK => {
                    chunks += 1;
                    if chunks > max_chunks {
                        return Err(io::Error::other("more chunks than allowed"));
                    }
                    let chunk: Chunk =
                        bincode::deserialize_from(&mut *reader).map_err(io::Error::other)?;
                    self.ams_mut()
                        .swbf_inactive
                        .append(Tip5::hash(&chunk))
                        .await;
                    self.ams_mut().chunks.push(chunk).await;
                }
                Self::WINDOW => {
                    self.ams_mut().swbf_active.sbf =
                        bincode::deserialize_from(&mut *reader).map_err(io::Error::other)?;
                }
                Self::SYNC_LABEL => {
                    let label =
                        bincode::deserialize_from(&mut *reader).map_err(io::Error::other)?;
                    self.set_sync_label(label).await;
                }
                other => {
                    return Err(io::Error::other(format!(
                        "unknown tag {other} in mutator set stream"
                    )));
                }
            }
            since_persist += 1;
            if since_persist == Self::NUM_ELEMENTS_PER_PERSIST {
                self.persist().await;
                since_persist = 0;
            }
        }
        self.persist().await;
        Ok(())
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
    use neptune_mutator_set::commit;
    use neptune_mutator_set::ms_membership_proof::MsMembershipProof;
    use neptune_mutator_set::shared::BATCH_SIZE;
    use neptune_mutator_set::test_shared::*;
    use rand::random;
    use rand::Rng;

    use super::*;
    use crate::test_utils::shared_tokio_runtime;

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

            rusty_mutator_set
                .ams_mut()
                .remove(removal_record.absolute_indices)
                .await
                .unwrap();

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

    #[apply(shared_tokio_runtime)]
    async fn a_streamed_set_is_rebuilt_and_tampering_shows_in_the_hash() {
        use crate::test_shared::empty_rusty_mutator_set;

        // Enough additions to slide the window, so that chunks exist, and
        // removals in both the active and the inactive filter.
        let num_additions = 4 * BATCH_SIZE as usize + 3;
        let mut rms = empty_rusty_mutator_set().await;
        let mut membership_proofs: Vec<MsMembershipProof> = vec![];
        let mut items: Vec<Digest> = vec![];
        for _ in 0..num_additions {
            let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
            let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
            let membership_proof = rms
                .ams()
                .prove(item, sender_randomness, receiver_preimage)
                .await;
            MsMembershipProof::batch_update_from_addition(
                &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                &items,
                &rms.ams().accumulator().await,
                &addition_record,
            )
            .unwrap();
            rms.ams_mut().add(&addition_record).await;
            membership_proofs.push(membership_proof);
            items.push(item);
        }
        for (membership_proof, &item) in membership_proofs.iter().zip_eq(&items).step_by(3) {
            let removal_record = rms.ams().drop(item, membership_proof).await;
            rms.ams_mut()
                .remove(removal_record.absolute_indices)
                .await
                .unwrap();
        }
        rms.set_sync_label(random()).await;
        rms.persist().await;
        let expected = rms.ams().accumulator().await;

        let mut stream = Vec::new();
        RustyArchivalMutatorSet::write_leafs(&rms.db(), &mut stream).unwrap();
        let num_chunks = rms.ams().chunks.len().await;
        let mut copy = empty_rusty_mutator_set().await;
        copy.restore_or_new().await;
        copy.read_leafs(
            &mut std::io::Cursor::new(&stream),
            num_additions as u64,
            num_chunks,
        )
        .await
        .unwrap();
        assert_eq!(expected.hash(), copy.ams().accumulator().await.hash());
        assert_eq!(rms.get_sync_label(), copy.get_sync_label());
        assert_eq!(num_chunks, copy.ams().chunks.len().await);

        // One leaf or chunk more than allowed stops the read.
        for (max_leafs, max_chunks) in [
            (num_additions as u64 - 1, num_chunks),
            (num_additions as u64, num_chunks - 1),
        ] {
            let mut bounded = empty_rusty_mutator_set().await;
            bounded.restore_or_new().await;
            assert!(bounded
                .read_leafs(&mut std::io::Cursor::new(&stream), max_leafs, max_chunks)
                .await
                .is_err());
        }

        // One bit flipped in the first leaf changes the hash.
        let first_leaf = bincode::serialize(&rms.ams().aocl.get_leaf_async(0).await).unwrap();
        let at = stream
            .windows(first_leaf.len())
            .position(|window| window == first_leaf)
            .unwrap();
        stream[at] ^= 1;
        let mut tampered = empty_rusty_mutator_set().await;
        tampered.restore_or_new().await;
        tampered
            .read_leafs(
                &mut std::io::Cursor::new(&stream),
                num_additions as u64,
                num_chunks,
            )
            .await
            .unwrap();
        assert_ne!(expected.hash(), tampered.ams().accumulator().await.hash());
    }
}
