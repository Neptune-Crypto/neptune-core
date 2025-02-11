use std::collections::HashMap;

#[cfg(test)]
use arbitrary::Arbitrary;
use get_size2::GetSize;
use itertools::Itertools;
use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::TasmObject;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::LeafMutation;
use twenty_first::math::bfield_codec::BFieldCodec;
use twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use twenty_first::util_types::mmr::mmr_trait::Mmr;

use super::active_window::ActiveWindow;
use super::addition_record::AdditionRecord;
use super::chunk::Chunk;
use super::chunk_dictionary::ChunkDictionary;
use super::get_swbf_indices;
use super::ms_membership_proof::MsMembershipProof;
use super::removal_record::AbsoluteIndexSet;
use super::removal_record::RemovalRecord;
use super::shared::BATCH_SIZE;
use super::shared::CHUNK_SIZE;
use super::shared::WINDOW_SIZE;
use crate::models::blockchain::shared::Hash;
use crate::prelude::twenty_first;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, GetSize, BFieldCodec, TasmObject)]
#[cfg_attr(test, derive(Arbitrary))]
pub struct MutatorSetAccumulator {
    pub aocl: MmrAccumulator,
    pub swbf_inactive: MmrAccumulator,
    pub swbf_active: ActiveWindow,
}

impl Default for MutatorSetAccumulator {
    fn default() -> Self {
        Self {
            aocl: MmrAccumulator::new_from_leafs(vec![]),
            swbf_inactive: MmrAccumulator::new_from_leafs(vec![]),
            swbf_active: Default::default(),
        }
    }
}

impl MutatorSetAccumulator {
    pub fn new(
        aocl: &[Digest],
        aocl_leaf_count: u64,
        swbf_inactive: &[Digest],
        swbf_active: &ActiveWindow,
    ) -> Self {
        let swbf_inactive_leaf_count = aocl_leaf_count / (BATCH_SIZE as u64);
        Self {
            aocl: MmrAccumulator::init(aocl.to_vec(), aocl_leaf_count),
            swbf_inactive: MmrAccumulator::init(swbf_inactive.to_vec(), swbf_inactive_leaf_count),
            swbf_active: swbf_active.clone(),
        }
    }

    /// Helper function. Like `add` but also returns the chunk that
    /// was added to the inactive SWBF if the window slid (and None
    /// otherwise) since this is needed by the archival version of
    /// the mutator set.
    pub fn add_helper(&mut self, addition_record: &AdditionRecord) -> Option<(u64, Chunk)> {
        // Notice that `add` cannot return a membership proof since `add` cannot know the
        // randomness that was used to create the commitment. This randomness can only be know
        // by the sender and/or receiver of the UTXO. And `add` must be run by all nodes keeping
        // track of the mutator set.

        // add to list
        let item_index = self.aocl.num_leafs();
        self.aocl
            .append(addition_record.canonical_commitment.to_owned()); // ignore auth path

        if !Self::window_slides(item_index) {
            return None;
        }

        // if window slides, update filter
        // First update the inactive part of the SWBF, the SWBF MMR
        let new_chunk: Chunk = self.swbf_active.slid_chunk();
        let chunk_digest: Digest = Hash::hash(&new_chunk);
        let new_chunk_index = self.swbf_inactive.num_leafs();
        self.swbf_inactive.append(chunk_digest); // ignore auth path

        // Then move window to the right, equivalent to moving values
        // inside window to the left.
        self.swbf_active.slide_window();

        // Return the chunk that was added to the inactive part of the SWBF.
        // This chunk is needed by the Archival mutator set. The Regular
        // mutator set can ignore it.
        Some((new_chunk_index, new_chunk))
    }

    /// Return the batch index for the latest addition to the mutator set
    pub fn get_batch_index(&self) -> u64 {
        match self.aocl.num_leafs() {
            0 => 0,
            n => (n - 1) / BATCH_SIZE as u64,
        }
    }

    /// Return the lowest and the highest chunk index that are represented in
    /// the active window, inclusive.
    /// The returned limits are inclusive, i.e. they point to the chunk with
    /// the lowest chunk index and the chunk with the highest chunk index that
    /// are still contained in the active window.
    pub fn active_window_chunk_interval(&self) -> (u64, u64) {
        let batch_index = self.get_batch_index();
        (batch_index, batch_index + (WINDOW_SIZE / CHUNK_SIZE) as u64)
    }

    /// Remove a record and return the chunks that have been updated in this process,
    /// after applying the update. Does not mutate the removal record.
    pub fn remove_helper(&mut self, removal_record: &RemovalRecord) -> HashMap<u64, Chunk> {
        let batch_index = self.get_batch_index();
        let active_window_start = batch_index as u128 * CHUNK_SIZE as u128;

        // insert all indices
        let mut new_target_chunks: ChunkDictionary = removal_record.target_chunks.clone();
        let chunkindices_to_indices_dict: HashMap<u64, Vec<u128>> =
            removal_record.get_chunkidx_to_indices_dict();

        for (chunk_index, indices) in chunkindices_to_indices_dict {
            if chunk_index >= batch_index {
                // index is in the active part, so insert it in the active part of the Bloom filter
                for index in indices {
                    let relative_index = (index - active_window_start) as u32;
                    self.swbf_active.insert(relative_index);
                }

                continue;
            }

            // If chunk index is not in the active part, insert the index into the relevant chunk
            let new_target_chunks_clone = new_target_chunks.clone();
            let relevant_chunk = new_target_chunks
                .get_mut(&chunk_index)
                .unwrap_or_else(|| {
                    panic!(
                        "Can't get chunk index {chunk_index} from removal record dictionary! dictionary: {:?}\nAOCL size: {}\nbatch index: {}\nRemoval record: {:?}",
                        new_target_chunks_clone,
                        self.aocl.num_leafs(),
                        batch_index,
                        removal_record
                    )
                });
            for index in indices {
                let relative_index = (index % CHUNK_SIZE as u128) as u32;
                relevant_chunk.1.insert(relative_index);
            }
        }

        // update mmr
        // to do this, we need to keep track of all membership proofs
        // If we want to update the membership proof with this removal, we
        // could use the below function.
        let mutation_data = new_target_chunks.chunk_indices_and_membership_proofs_and_leafs();
        self.swbf_inactive.batch_mutate_leaf_and_update_mps(
            &mut [],
            &[],
            mutation_data
                .iter()
                .map(|(i, p, l)| LeafMutation::new(*i, *l, p.clone()))
                .collect_vec(),
        );

        new_target_chunks
            .into_iter()
            .map(|(chunk_index, (_mp, chunk))| (chunk_index, chunk))
            .collect()
    }

    /// Check if a removal record can be applied to a mutator set. Returns false if either
    /// the MMR membership proofs are unsynced, or if all its indices are already set.
    pub fn can_remove(&self, removal_record: &RemovalRecord) -> bool {
        let mut have_absent_index = false;
        if !removal_record.validate(self) {
            return false;
        }

        for inserted_index in removal_record.absolute_indices.to_vec().into_iter() {
            // determine if inserted index lives in active window
            let active_window_start =
                (self.aocl.num_leafs() / BATCH_SIZE as u64) as u128 * CHUNK_SIZE as u128;
            if inserted_index < active_window_start {
                let inserted_index_chunkidx = (inserted_index / CHUNK_SIZE as u128) as u64;
                if let Some((_mmr_mp, chunk)) =
                    removal_record.target_chunks.get(&inserted_index_chunkidx)
                {
                    let relative_index = (inserted_index % CHUNK_SIZE as u128) as u32;
                    if !chunk.contains(relative_index) {
                        have_absent_index = true;
                        break;
                    }
                }
            } else {
                let relative_index = (inserted_index - active_window_start) as u32;
                if !self.swbf_active.contains(relative_index) {
                    have_absent_index = true;
                    break;
                }
            }
        }

        have_absent_index
    }
}

impl MutatorSetAccumulator {
    /// Generates a membership proof that will the valid when the item
    /// is added to the mutator set.
    pub fn prove(
        &self,
        item: Digest,
        sender_randomness: Digest,
        receiver_preimage: Digest,
    ) -> MsMembershipProof {
        // compute commitment
        let item_commitment = Hash::hash_pair(item, sender_randomness);

        // simulate adding to commitment list
        let aocl_leaf_index = self.aocl.num_leafs();
        let auth_path_aocl = self.aocl.to_accumulator().append(item_commitment);
        let target_chunks: ChunkDictionary = ChunkDictionary::default();

        // return membership proof
        MsMembershipProof {
            sender_randomness: sender_randomness.to_owned(),
            receiver_preimage: receiver_preimage.to_owned(),
            auth_path_aocl,
            target_chunks,
            aocl_leaf_index,
        }
    }

    pub fn verify(&self, item: Digest, membership_proof: &MsMembershipProof) -> bool {
        // If data index does not exist in AOCL, return false
        // This also ensures that no "future" indices will be
        // returned from `get_indices`, so we don't have to check for
        // future indices in a separate check.
        let aocl_leaf_count = self.aocl.num_leafs();
        if aocl_leaf_count <= membership_proof.aocl_leaf_index {
            return false;
        }

        // verify that a commitment to the item lives in the aocl mmr
        let leaf = Hash::hash_pair(
            Hash::hash_pair(item, membership_proof.sender_randomness),
            Hash::hash_pair(
                membership_proof.receiver_preimage,
                Digest::new([BFieldElement::zero(); Digest::LEN]),
            ),
        );
        let is_aocl_member = membership_proof.auth_path_aocl.verify(
            membership_proof.aocl_leaf_index,
            leaf,
            &self.aocl.peaks(),
            aocl_leaf_count,
        );
        if !is_aocl_member {
            return false;
        }

        // verify that some indices are not present in the swbf
        let mut has_absent_index = false;
        let mut entries_in_dictionary = true;
        let mut all_auth_paths_are_valid = true;

        // prepare parameters of inactive part
        let current_batch_index: u64 = self.get_batch_index();
        let window_start = current_batch_index as u128 * CHUNK_SIZE as u128;

        // Get all Bloom filter indices
        let all_indices = AbsoluteIndexSet::new(&get_swbf_indices(
            item,
            membership_proof.sender_randomness,
            membership_proof.receiver_preimage,
            membership_proof.aocl_leaf_index,
        ));

        let Ok((indices_in_inactive_swbf, indices_in_active_swbf)) =
            all_indices.split_by_activity(self)
        else {
            return false;
        };

        for (chunk_index, indices) in indices_in_inactive_swbf {
            if !membership_proof.target_chunks.contains_key(&chunk_index) {
                entries_in_dictionary = false;
                break;
            }

            let (swbf_inactive_mp, swbf_inactive_chunk): &(MmrMembershipProof, Chunk) =
                membership_proof.target_chunks.get(&chunk_index).unwrap();
            let valid_auth_path = swbf_inactive_mp.verify(
                chunk_index,
                Hash::hash(swbf_inactive_chunk),
                &self.swbf_inactive.peaks(),
                self.swbf_inactive.num_leafs(),
            );

            all_auth_paths_are_valid = all_auth_paths_are_valid && valid_auth_path;

            'inner_inactive: for index in indices {
                let index_within_chunk = index % CHUNK_SIZE as u128;
                if !swbf_inactive_chunk.contains(index_within_chunk as u32) {
                    has_absent_index = true;
                    break 'inner_inactive;
                }
            }
        }

        for index in indices_in_active_swbf {
            let relative_index = index - window_start;
            if !self.swbf_active.contains(relative_index as u32) {
                has_absent_index = true;
                break;
            }
        }

        // return verdict
        is_aocl_member && entries_in_dictionary && all_auth_paths_are_valid && has_absent_index
    }

    /// Generates a removal record with which to update the set commitment.
    pub fn drop(&self, item: Digest, membership_proof: &MsMembershipProof) -> RemovalRecord {
        let indices: AbsoluteIndexSet = AbsoluteIndexSet::new(&get_swbf_indices(
            item,
            membership_proof.sender_randomness,
            membership_proof.receiver_preimage,
            membership_proof.aocl_leaf_index,
        ));

        RemovalRecord {
            absolute_indices: indices,
            target_chunks: membership_proof.target_chunks.clone(),
        }
    }

    pub fn add(&mut self, addition_record: &AdditionRecord) {
        self.add_helper(addition_record);
    }

    /// Remove an item given its removal record. It is the caller's
    /// responsibility to ensure that the removal record can be applied, for
    /// instance by using [`can_remove`](Self::can_remove).
    pub fn remove(&mut self, removal_record: &RemovalRecord) {
        self.remove_helper(removal_record);
    }

    pub fn hash(&self) -> Digest {
        let aocl_mmr_bagged = self.aocl.bag_peaks();
        let inactive_swbf_bagged = self.swbf_inactive.bag_peaks();
        let active_swbf_bagged = Hash::hash(&self.swbf_active);
        let default = Digest::default();

        Hash::hash_pair(
            Hash::hash_pair(aocl_mmr_bagged, inactive_swbf_bagged),
            Hash::hash_pair(active_swbf_bagged, default),
        )
    }

    /// Apply a bunch of removal records. Return a hashmap of
    /// { chunk index => updated_chunk }.
    pub fn batch_remove(
        &mut self,
        mut removal_records: Vec<RemovalRecord>,
        preserved_membership_proofs: &mut [&mut MsMembershipProof],
    ) -> HashMap<u64, Chunk> {
        {
            let batch_index = self.get_batch_index();
            let active_window_start = batch_index as u128 * CHUNK_SIZE as u128;

            // Collect all indices that that are set by the removal records
            let all_removal_records_indices: Vec<u128> = removal_records
                .iter()
                .map(|x| x.absolute_indices.to_vec())
                .concat();

            // Loop over all indices from removal records in order to create a mapping
            // {chunk index => chunk mutation } where "chunk mutation" has the type of
            // `Chunk` but only represents the values which are set by the removal records
            // being handled.
            let mut chunkidx_to_chunk_difference_dict: HashMap<u64, Chunk> = HashMap::new();
            all_removal_records_indices.iter().for_each(|index| {
                if *index >= active_window_start {
                    let relative_index = (index - active_window_start) as u32;
                    self.swbf_active.insert(relative_index);
                } else {
                    chunkidx_to_chunk_difference_dict
                        .entry((index / CHUNK_SIZE as u128) as u64)
                        .or_insert_with(Chunk::empty_chunk)
                        .insert((*index % CHUNK_SIZE as u128) as u32);
                }
            });

            // Collect all affected chunks as they look before these removal records are applied
            // These chunks are part of the removal records, so we fetch them there.
            let mut mutation_data_preimage: HashMap<u64, (&mut Chunk, MmrMembershipProof)> =
                HashMap::new();
            for removal_record in removal_records.iter_mut() {
                for (chunk_index, (mmr_mp, chunk)) in removal_record.target_chunks.iter_mut() {
                    let chunk_hash = Hash::hash(chunk);
                    let prev_val =
                        mutation_data_preimage.insert(*chunk_index, (chunk, mmr_mp.to_owned()));

                    // Sanity check that all removal records agree on both chunks and MMR membership
                    // proofs.
                    if let Some((chnk, mm)) = prev_val {
                        assert!(mm == *mmr_mp && chunk_hash == Hash::hash(chnk))
                    }
                }
            }

            // Apply the removal records: the new chunk is obtained by adding the chunk difference
            for (chunk_index, (chunk, _)) in mutation_data_preimage.iter_mut() {
                **chunk = chunk
                    .clone()
                    .combine(chunkidx_to_chunk_difference_dict[chunk_index].clone())
                    .clone();
            }

            // Set the chunk values in the membership proofs that we want to preserve to the
            // newly calculated chunk values.
            // This is done by looping over all membership proofs and checking if they contain
            // any of the chunks that are affected by the removal records.
            for mp in preserved_membership_proofs.iter_mut() {
                for (chunk_index, (_, chunk)) in mp.target_chunks.iter_mut() {
                    if mutation_data_preimage.contains_key(chunk_index) {
                        mutation_data_preimage[chunk_index].0.clone_into(chunk);
                    }
                }
            }

            // Calculate the digests of the affected leafs in the inactive part of the sliding-window
            // Bloom filter such that we can apply a batch-update operation to the MMR through which
            // this part of the Bloom filter is represented.
            let swbf_inactive_mutation_data = mutation_data_preimage
                .into_iter()
                .map(|(k, v)| (k, Hash::hash(v.0), v.1))
                .collect_vec();

            // Create a vector of pointers to the MMR-membership part of the mutator set membership
            // proofs that we want to preserve. This is used as input to a batch-call to the
            // underlying MMR.
            let preseved_mmr_leaf_indices = preserved_membership_proofs
                .iter()
                .flat_map(|msmp| msmp.target_chunks.iter().map(|(i, _)| *i).collect_vec())
                .collect_vec();
            let mut preseved_mmr_membership_proofs: Vec<&mut MmrMembershipProof> =
                preserved_membership_proofs
                    .iter_mut()
                    .flat_map(|x| {
                        x.target_chunks
                            .iter_mut()
                            .map(|y| &mut y.1 .0)
                            .collect::<Vec<_>>()
                    })
                    .collect();

            // Apply the batch-update to the inactive part of the sliding window Bloom filter.
            // This updates both the inactive part of the SWBF and the MMR membership proofs
            self.swbf_inactive.batch_mutate_leaf_and_update_mps(
                &mut preseved_mmr_membership_proofs,
                &preseved_mmr_leaf_indices,
                swbf_inactive_mutation_data
                    .iter()
                    .map(|(i, l, p)| LeafMutation::new(*i, *l, p.clone()))
                    .collect_vec(),
            );

            chunkidx_to_chunk_difference_dict
        }
    }

    /// Determine if the window slides before absorbing an item,
    /// given the index of the to-be-added item.
    pub fn window_slides(added_index: u64) -> bool {
        added_index != 0 && added_index % BATCH_SIZE as u64 == 0

        // example cases:
        //  - index == 0 we don't care about
        //  - index == 1 does not generate a slide
        //  - index == n * BATCH_SIZE generates a slide for any n
    }

    pub fn window_slides_back(removed_index: u64) -> bool {
        Self::window_slides(removed_index)
    }
}

#[cfg(test)]
mod ms_accumulator_tests {
    use itertools::izip;
    use itertools::Itertools;
    use proptest::prop_assert_eq;
    use rand::Rng;
    use test_strategy::proptest;

    use super::*;
    use crate::util_types::mutator_set::commit;
    use crate::util_types::mutator_set::shared::BATCH_SIZE;
    use crate::util_types::mutator_set::shared::CHUNK_SIZE;
    use crate::util_types::mutator_set::shared::NUM_TRIALS;
    use crate::util_types::mutator_set::shared::WINDOW_SIZE;
    use crate::util_types::test_shared::mutator_set::*;

    #[test]
    fn active_window_chunk_interval_unit_test() {
        let mut accumulator: MutatorSetAccumulator = MutatorSetAccumulator::default();
        let (start_empty, end_empty) = accumulator.active_window_chunk_interval();
        assert_eq!(0, start_empty);
        assert_eq!((WINDOW_SIZE / CHUNK_SIZE) as u64, end_empty);

        // Insert batch-size items and verify that a new batch interval is reported
        for _ in 0..BATCH_SIZE + 1 {
            let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
            let addition_record = commit(item, sender_randomness, receiver_preimage.hash());

            let (start, end) = accumulator.active_window_chunk_interval();
            assert_eq!(0, start);
            assert_eq!((WINDOW_SIZE / CHUNK_SIZE) as u64, end);
            accumulator.add(&addition_record);
        }

        let (start_final, end_final) = accumulator.active_window_chunk_interval();
        assert_eq!(1, start_final);
        assert_eq!((WINDOW_SIZE / CHUNK_SIZE) as u64 + 1, end_final);
    }

    #[proptest(cases = 10)]
    fn batch_index_and_active_window_chunk_interval_agree(
        #[strategy(1u64..10u64 * BATCH_SIZE as u64)] num_insertions: u64,
    ) {
        let mut accumulator: MutatorSetAccumulator = MutatorSetAccumulator::default();
        for _ in 0..num_insertions {
            let (start, end) = accumulator.active_window_chunk_interval();
            let batch_interval = accumulator.get_batch_index();
            prop_assert_eq!(batch_interval, start);
            prop_assert_eq!(batch_interval + (WINDOW_SIZE / CHUNK_SIZE) as u64, end);

            let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
            let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
            accumulator.add(&addition_record);
        }
    }

    #[tokio::test]
    async fn mutator_set_batch_remove_accumulator_test() {
        // Test the batch-remove function for mutator set accumulator
        let mut accumulator: MutatorSetAccumulator = MutatorSetAccumulator::default();
        let mut membership_proofs: Vec<MsMembershipProof> = vec![];
        let mut items: Vec<Digest> = vec![];

        // Add N elements to the MS
        let num_additions = 44;
        for _ in 0..num_additions {
            let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();

            let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
            let membership_proof = accumulator.prove(item, sender_randomness, receiver_preimage);

            MsMembershipProof::batch_update_from_addition(
                &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                &items,
                &accumulator,
                &addition_record,
            )
            .expect("MS membership update must work");

            accumulator.add(&addition_record);

            membership_proofs.push(membership_proof);
            items.push(item);
        }

        // Now build removal records for about half of the elements
        let mut rng = rand::rng();
        let mut skipped_removes: Vec<bool> = vec![];
        let mut removal_records: Vec<RemovalRecord> = vec![];
        for (mp, &item) in membership_proofs.iter().zip_eq(items.iter()) {
            let skipped = rng.random_range(0.0..1.0) < 0.5;
            skipped_removes.push(skipped);
            if !skipped {
                removal_records.push(accumulator.drop(item, mp));
            }
        }

        for (mp, &item) in membership_proofs.iter().zip_eq(items.iter()) {
            assert!(accumulator.verify(item, mp));
        }

        // Remove the entries with batch_remove
        accumulator.batch_remove(
            removal_records,
            &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
        );

        // Verify that the expected membership proofs fail/pass
        for (mp, &item, skipped) in izip!(
            membership_proofs.iter(),
            items.iter(),
            skipped_removes.into_iter()
        ) {
            // If this removal record was not applied, then the membership proof must verify
            assert_eq!(skipped, accumulator.verify(item, mp));
        }
    }

    #[tokio::test]
    async fn mutator_set_accumulator_pbt() {
        // This tests verifies that items can be added and removed from the mutator set
        // without assuming anything about the order of the adding and removal. It also
        // verifies that the membership proofs handled through an mutator set accumulator
        // are the same as those that are produced from an archival mutator set.

        // This function mixes both archival and accumulator testing.
        // It *may* be considered bad style to do it this way, but there is a
        // lot of code duplication that is avoided by doing that.

        let mut accumulator: MutatorSetAccumulator = MutatorSetAccumulator::default();
        let mut rms_after = empty_rusty_mutator_set().await;
        let archival_after_remove = rms_after.ams_mut();
        let mut rms_before = empty_rusty_mutator_set().await;
        let archival_before_remove = rms_before.ams_mut();
        let number_of_interactions = 100;
        let mut rng = rand::rng();

        // The outer loop runs two times:
        // 1. insert `number_of_interactions / 2` items, then randomly insert and remove `number_of_interactions / 2` times
        // 2. Randomly insert and remove `number_of_interactions` times
        // This should test both inserting/removing in an empty MS and in a non-empty MS
        for start_fill in [false, true] {
            let mut membership_proofs_batch: Vec<MsMembershipProof> = vec![];
            let mut membership_proofs_sequential: Vec<MsMembershipProof> = vec![];
            let mut items: Vec<Digest> = vec![];
            let mut rands: Vec<(Digest, Digest)> = vec![];
            let mut last_ms_commitment: Option<Digest> = None;
            for i in 0..number_of_interactions {
                // Verify that commitment to both the accumulator and archival data structure agree
                let new_commitment = accumulator.hash();
                assert_eq!(
                    new_commitment,
                    archival_after_remove.hash().await,
                    "Commitment to archival/accumulator MS must agree"
                );
                match last_ms_commitment {
                    None => (),
                    Some(commitment) => assert_ne!(
                        commitment, new_commitment,
                        "MS commitment must change upon insertion/deletion"
                    ),
                };
                last_ms_commitment = Some(new_commitment);

                if rng.random_range(0u8..2) == 0 || start_fill && i < number_of_interactions / 2 {
                    // Add a new item to the mutator set and update all membership proofs
                    let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();

                    let addition_record: AdditionRecord =
                        commit(item, sender_randomness, receiver_preimage.hash());
                    let membership_proof_acc =
                        accumulator.prove(item, sender_randomness, receiver_preimage);

                    // Update all membership proofs
                    // Uppdate membership proofs in batch
                    let previous_mps = membership_proofs_batch.clone();
                    let indices_of_updated_mps = MsMembershipProof::batch_update_from_addition(
                        &mut membership_proofs_batch.iter_mut().collect::<Vec<_>>(),
                        &items,
                        &accumulator,
                        &addition_record,
                    )
                    .expect("Batch mutation must return OK");

                    // Update membership proofs sequentially
                    for (mp, &own_item) in membership_proofs_sequential.iter_mut().zip(items.iter())
                    {
                        let update_res_seq =
                            mp.update_from_addition(own_item, &accumulator, &addition_record);
                        assert!(update_res_seq.is_ok());
                    }

                    accumulator.add(&addition_record);
                    archival_after_remove.add(&addition_record).await;
                    archival_before_remove.add(&addition_record).await;

                    println!("{}: Inserted", i);
                    for j in 0..items.len() {
                        if indices_of_updated_mps.contains(&j) {
                            assert_ne!(
                                previous_mps[j], membership_proofs_batch[j],
                                "membership proof marked as updated but still identical"
                            );
                            assert!(
                                !accumulator.verify(items[j], &previous_mps[j]),
                                "Verify must fail for old proof, j = {}. AOCL data index was: {}.\n\nOld mp:\n {:?}.\n\nNew mp is\n {:?}",
                                j,
                                previous_mps[j].aocl_leaf_index,
                                previous_mps[j],
                                membership_proofs_batch[j]
                            );
                        } else {
                            assert_eq!(
                                previous_mps[j], membership_proofs_batch[j],
                                "membership proof underwent update but not marked as such"
                            );
                            assert!(
                                accumulator.verify(items[j], &previous_mps[j]),
                                "Verify must succeed for old proof, j = {}. AOCL data index was: {}.\n\nOld mp:\n {:?}.\n\nNew mp is\n {:?}",
                                j,
                                previous_mps[j].aocl_leaf_index,
                                previous_mps[j],
                                membership_proofs_batch[j]
                            );
                        }
                    }

                    membership_proofs_batch.push(membership_proof_acc.clone());
                    membership_proofs_sequential.push(membership_proof_acc);
                    items.push(item);
                    rands.push((sender_randomness, receiver_preimage));
                } else {
                    // Remove an item from the mutator set and update all membership proofs
                    if membership_proofs_batch.is_empty() {
                        // Set `last_ms_commitment` to None since it will otherwise be the
                        // same as in last iteration of this inner loop, and that will fail
                        // a test condition.
                        last_ms_commitment = None;
                        continue;
                    }

                    let item_index = rng.random_range(0..membership_proofs_batch.len());
                    let removal_item = items.remove(item_index);
                    let removal_mp = membership_proofs_batch.remove(item_index);
                    let _removal_mp_seq = membership_proofs_sequential.remove(item_index);
                    let _removal_rand = rands.remove(item_index);

                    // generate removal record
                    let removal_record: RemovalRecord = accumulator.drop(removal_item, &removal_mp);
                    assert!(removal_record.validate(&accumulator));

                    // update membership proofs
                    // Uppdate membership proofs in batch
                    let original_membership_proofs_batch = membership_proofs_batch.clone();
                    let batch_update_ret = MsMembershipProof::batch_update_from_remove(
                        &mut membership_proofs_batch.iter_mut().collect::<Vec<_>>(),
                        &removal_record,
                    );
                    assert!(batch_update_ret.is_ok());

                    // Update membership proofs sequentially
                    let original_membership_proofs_sequential =
                        membership_proofs_sequential.clone();
                    let mut update_by_remove_return_values: Vec<bool> = vec![];
                    for mp in membership_proofs_sequential.iter_mut() {
                        let update_res_seq = mp.update_from_remove(&removal_record);
                        update_by_remove_return_values.push(update_res_seq);
                    }

                    // remove item from set
                    assert!(accumulator.verify(removal_item, &removal_mp));
                    let removal_record_copy = removal_record.clone();
                    accumulator.remove(&removal_record);
                    archival_after_remove.remove(&removal_record).await;

                    // Verify that removal record's indices are all set
                    for removed_index in removal_record.absolute_indices.to_vec() {
                        assert!(
                            archival_after_remove
                                .bloom_filter_contains(removed_index)
                                .await
                        );
                    }

                    archival_before_remove.remove(&removal_record_copy).await;
                    assert!(!accumulator.verify(removal_item, &removal_mp));

                    // Verify that the sequential `update_from_remove` return value is correct
                    // The return value from `update_from_remove` shows if the membership proof
                    // was updated or not.
                    for (j, updated, original_mp, &item) in izip!(
                        0..,
                        update_by_remove_return_values,
                        original_membership_proofs_sequential.iter(),
                        items.iter()
                    ) {
                        if updated {
                            assert!(
                                !accumulator.verify(item, original_mp),
                                "j = {}, \n\nOriginal mp:\n{:#?}\n\nNew mp:\n{:#?}",
                                j,
                                original_mp,
                                membership_proofs_sequential[j]
                            );
                        } else {
                            assert!(
                                accumulator.verify(item, original_mp),
                                "j = {}, \n\nOriginal mp:\n{:#?}\n\nNew mp:\n{:#?}",
                                j,
                                original_mp,
                                membership_proofs_sequential[j]
                            );
                        }
                    }

                    // Verify that `batch_update_from_remove` return value is correct
                    // The return value indicates which membership proofs
                    let updated_indices: Vec<usize> = batch_update_ret.unwrap();
                    for (j, (original_mp, &item)) in original_membership_proofs_batch
                        .iter()
                        .zip(items.iter())
                        .enumerate()
                    {
                        let item_was_updated = updated_indices.contains(&j);
                        let item_verifies = accumulator.verify(item, original_mp);
                        let item_verifies_iff_not_updated = item_verifies != item_was_updated;
                        assert!(item_verifies_iff_not_updated);
                    }

                    println!("{}: Removed", i);
                }

                // Verify that all membership proofs are valid after these additions and removals
                // Also verify that batch-update and sequential update of membership proofs agree.
                for (mp_batch, mp_seq, &item, &(sender_randomness, receiver_preimage)) in izip!(
                    membership_proofs_batch.iter(),
                    membership_proofs_sequential.iter(),
                    items.iter(),
                    rands.iter()
                ) {
                    assert!(accumulator.verify(item, mp_batch));

                    // Verify that the membership proof can be restored from an archival instance
                    let arch_mp = archival_after_remove
                        .restore_membership_proof(
                            item,
                            sender_randomness,
                            receiver_preimage,
                            mp_batch.aocl_leaf_index,
                        )
                        .await
                        .unwrap();
                    assert_eq!(arch_mp, mp_batch.to_owned());

                    // Verify that sequential and batch update produces the same membership proofs
                    assert_eq!(mp_batch, mp_seq);
                }
            }
        }
    }

    #[test]
    fn test_mutator_set_accumulator_decode() {
        for _ in 0..100 {
            let msa = random_mutator_set_accumulator();
            let encoded = msa.encode();
            let decoded: MutatorSetAccumulator = *MutatorSetAccumulator::decode(&encoded).unwrap();
            assert_eq!(msa, decoded);
        }
    }

    #[ignore]
    #[test]
    fn profile() {
        // populate a mutator set with items according to some target profile,
        // and then print the size of the mutator set accumulator, in bytes
        let mut rng = rand::rng();
        println!(
            "profiling Mutator Set (w, b, s, k) = ({}, {}, {}, {}) ...",
            WINDOW_SIZE, BATCH_SIZE, CHUNK_SIZE, NUM_TRIALS
        );
        let mut msa = MutatorSetAccumulator::default();
        let mut items_and_membership_proofs: Vec<(Digest, MsMembershipProof)> = vec![];
        let target_set_size = 100;
        let num_iterations = 10000;

        for i in 0..num_iterations {
            if i % 100 == 0 {
                println!("{}/{}", i, num_iterations);
            }
            let operation = if items_and_membership_proofs.len()
                > (1.25 * target_set_size as f64) as usize
            {
                rng.random_range(0..10) >= 3
            } else if items_and_membership_proofs.len() < (0.8 * target_set_size as f64) as usize {
                rng.random_range(0..10) < 3
            } else {
                rng.random_range(0..10) < 5
            };
            if operation && !items_and_membership_proofs.is_empty() {
                // removal
                let index = rng.random_range(0..items_and_membership_proofs.len());
                let (item, membership_proof) = items_and_membership_proofs.swap_remove(index);
                let removal_record = msa.drop(item, &membership_proof);
                for (_it, mp) in items_and_membership_proofs.iter_mut() {
                    mp.update_from_remove(&removal_record);
                }
                msa.remove(&removal_record);
            } else {
                // addition
                let item = rng.random::<Digest>();
                let sender_randomness = rng.random::<Digest>();
                let receiver_preimage = rng.random::<Digest>();
                let addition_record = commit(item, sender_randomness, receiver_preimage);
                for (it, mp) in items_and_membership_proofs.iter_mut() {
                    mp.update_from_addition(*it, &msa, &addition_record)
                        .unwrap();
                }
                let membership_proof = msa.prove(item, sender_randomness, receiver_preimage);
                msa.add(&addition_record);
                items_and_membership_proofs.push((item, membership_proof));
            }
        }

        println!("{} operations resulted in a set containin {} elements; mutator set accumulator size: {} bytes", num_iterations, items_and_membership_proofs.len(), msa.get_size());
    }
}
