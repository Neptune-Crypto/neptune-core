use std::collections::HashMap;

use get_size2::GetSize;
use itertools::Itertools;
use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::TasmObject;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::LeafMutation;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;

use super::active_window::ActiveWindow;
use super::addition_record::AdditionRecord;
use super::ms_membership_proof::MsMembershipProof;
use super::removal_record::absolute_index_set::AbsoluteIndexSet;
use super::removal_record::chunk::Chunk;
use super::removal_record::chunk_dictionary::ChunkDictionary;
use super::removal_record::RemovalRecord;
use super::shared::BATCH_SIZE;
use super::shared::CHUNK_SIZE;
use super::shared::WINDOW_SIZE;
use crate::util_types::mutator_set::aocl_to_swbfi_leaf_counts;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, GetSize, BFieldCodec, TasmObject)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(arbitrary::Arbitrary))]
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
        let swbf_inactive_leaf_count = aocl_to_swbfi_leaf_counts(aocl_leaf_count);
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
        let chunk_digest: Digest = Tip5::hash(&new_chunk);
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
        aocl_to_swbfi_leaf_counts(self.aocl.num_leafs())
    }

    /// Return the lowest and the highest chunk index that are represented in
    /// the active window, inclusive.
    /// The returned limits are inclusive, i.e. they point to the chunk with
    /// the lowest chunk index and the chunk with the highest chunk index that
    /// are still contained in the active window.
    pub fn active_window_chunk_interval(&self) -> (u64, u64) {
        let batch_index = self.get_batch_index();
        (
            batch_index,
            batch_index + u64::from(WINDOW_SIZE / CHUNK_SIZE),
        )
    }

    /// Remove a record and return the chunks that have been updated in this
    /// process, after applying the update. Does not mutate the removal record.
    ///
    /// It's the callers responsibility to call `can_remove` before invocing
    /// this function, as the chunks are read from the removal records, that
    /// must thus be valid and synced to the current state of the mutator set.
    /// Otherwise, the mutator set will end up in an invalid state.
    pub fn remove_helper(&mut self, removal_record: &RemovalRecord) -> HashMap<u64, Chunk> {
        let batch_index = self.get_batch_index();
        let active_window_start = u128::from(batch_index) * u128::from(CHUNK_SIZE);

        // insert all indices
        let mut new_target_chunks: ChunkDictionary = removal_record.target_chunks.clone();
        let chunkindices_to_indices_dict: HashMap<u64, Vec<u128>> =
            removal_record.get_chunkidx_to_indices_dict();

        for (chunk_index, absolute_indices) in chunkindices_to_indices_dict {
            if chunk_index >= batch_index {
                // index is in the active part, so insert it in the active part of the Bloom filter
                for index in absolute_indices {
                    let relative_index = u32::try_from(index - active_window_start)
                        .expect("Relative index for active window must be valid u32");
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
            for index in absolute_indices {
                let relative_index = (index % u128::from(CHUNK_SIZE)) as u32;
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

    /// Check if a removal record can be applied to a mutator set. Returns false
    /// if either the MMR membership proofs are unsynced, or if all its indices
    /// are already set, or if the chunk dictionary is missing entries.
    pub fn can_remove(&self, removal_record: &RemovalRecord) -> bool {
        let mut have_absent_index = false;

        // Validate verifies that the all required chunk/MMR membership proof
        // pairs are present, and that all MMR membership proofs are valid
        // against the mutator set accumulator.
        if !removal_record.validate(self) {
            return false;
        }

        let swbfi_num_leafs = self.get_batch_index();
        let active_window_start = u128::from(swbfi_num_leafs) * u128::from(CHUNK_SIZE);
        for inserted_index in removal_record.absolute_indices.to_vec() {
            // determine if inserted index lives in active window
            if inserted_index < active_window_start {
                let inserted_index_chunkidx = (inserted_index / u128::from(CHUNK_SIZE)) as u64;
                let (_mmr_mp, chunk) = removal_record
                    .target_chunks
                    .get(&inserted_index_chunkidx)
                    .expect("Presence of required MMR MPs should have already been established.");
                let relative_index = (inserted_index % u128::from(CHUNK_SIZE)) as u32;
                if !chunk.contains(relative_index) {
                    have_absent_index = true;
                    break;
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
        let item_commitment = Tip5::hash_pair(item, sender_randomness);

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
        let leaf = Tip5::hash_pair(
            Tip5::hash_pair(item, membership_proof.sender_randomness),
            Tip5::hash_pair(
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
        let window_start = u128::from(current_batch_index) * u128::from(CHUNK_SIZE);

        // Get all Bloom filter indices
        let all_indices = AbsoluteIndexSet::compute(
            item,
            membership_proof.sender_randomness,
            membership_proof.receiver_preimage,
            membership_proof.aocl_leaf_index,
        );

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
                Tip5::hash(swbf_inactive_chunk),
                &self.swbf_inactive.peaks(),
                self.swbf_inactive.num_leafs(),
            );

            all_auth_paths_are_valid = all_auth_paths_are_valid && valid_auth_path;

            'inner_inactive: for index in indices {
                let index_within_chunk = index % u128::from(CHUNK_SIZE);
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
        let indices: AbsoluteIndexSet = AbsoluteIndexSet::compute(
            item,
            membership_proof.sender_randomness,
            membership_proof.receiver_preimage,
            membership_proof.aocl_leaf_index,
        );

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
        let active_swbf_bagged = Tip5::hash(&self.swbf_active);
        let default = Digest::default();

        Tip5::hash_pair(
            Tip5::hash_pair(aocl_mmr_bagged, inactive_swbf_bagged),
            Tip5::hash_pair(active_swbf_bagged, default),
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
            let active_window_start = u128::from(batch_index) * u128::from(CHUNK_SIZE);

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
            for index in all_removal_records_indices {
                if index >= active_window_start {
                    let relative_index = (index - active_window_start) as u32;
                    self.swbf_active.insert(relative_index);
                } else {
                    chunkidx_to_chunk_difference_dict
                        .entry((index / u128::from(CHUNK_SIZE)) as u64)
                        .or_insert_with(Chunk::empty_chunk)
                        .insert((index % u128::from(CHUNK_SIZE)) as u32);
                }
            }

            // Collect all affected chunks as they look before these removal records are applied
            // These chunks are part of the removal records, so we fetch them there.
            let mut mutation_data_preimage: HashMap<u64, (&mut Chunk, MmrMembershipProof)> =
                HashMap::new();
            for removal_record in &mut removal_records {
                for (chunk_index, (mmr_mp, chunk)) in removal_record.target_chunks.iter_mut() {
                    let chunk_hash = Tip5::hash(chunk);
                    let prev_val =
                        mutation_data_preimage.insert(*chunk_index, (chunk, mmr_mp.to_owned()));

                    // Sanity check that all removal records agree on both chunks and MMR membership
                    // proofs.
                    if let Some((chnk, mm)) = prev_val {
                        assert!(mm == *mmr_mp && chunk_hash == Tip5::hash(chnk))
                    }
                }
            }

            // Apply the removal records: the new chunk is obtained by adding the chunk difference
            for (chunk_index, (chunk, _)) in &mut mutation_data_preimage {
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
                .map(|(k, v)| (k, Tip5::hash(v.0), v.1))
                .collect_vec();

            // Create a vector of pointers to the MMR-membership part of the mutator set membership
            // proofs that we want to preserve. This is used as input to a batch-call to the
            // underlying MMR.
            let preserved_mmr_leaf_indices = preserved_membership_proofs
                .iter()
                .flat_map(|msmp| msmp.target_chunks.iter().map(|(i, _)| *i).collect_vec())
                .collect_vec();
            let mut preserved_mmr_membership_proofs: Vec<&mut MmrMembershipProof> =
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
                &mut preserved_mmr_membership_proofs,
                &preserved_mmr_leaf_indices,
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
        added_index != 0 && added_index.is_multiple_of(u64::from(BATCH_SIZE))

        // example cases:
        //  - index == 0 we don't care about
        //  - index == 1 does not generate a slide
        //  - index == n * BATCH_SIZE generates a slide for any n
    }

    pub fn window_slides_back(removed_index: u64) -> bool {
        Self::window_slides(removed_index)
    }
}

#[cfg(any(test, feature = "arbitrary-impls"))]
impl MutatorSetAccumulator {
    /// Return true if the mutator set is internally consistent, e.g. has the
    /// right number of elements in the Bloom filter MMR given the number of
    /// leafs in the AOCL.
    pub(crate) fn is_consistent(&self) -> bool {
        let expected_num_leafs_bfmmr = aocl_to_swbfi_leaf_counts(self.aocl.num_leafs());
        let correct_bfmmr_num_leafs = expected_num_leafs_bfmmr == self.swbf_inactive.num_leafs();

        // These unwraps can't fail as that would require some pretty long
        // numbers, even on a 16 bit architecture.
        let consistent_aocl =
            usize::try_from(self.aocl.num_leafs().count_ones()).unwrap() == self.aocl.peaks().len();
        let consistent_swbf = usize::try_from(self.swbf_inactive.num_leafs().count_ones()).unwrap()
            == self.swbf_inactive.peaks().len();

        correct_bfmmr_num_leafs && consistent_aocl && consistent_swbf
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use itertools::izip;
    use itertools::Itertools;
    use macro_rules_attr::apply;
    use proptest::prelude::*;
    use proptest::prop_assert_eq;
    use rand::Rng;
    use test_strategy::proptest;

    use super::*;
    use crate::tests::shared_tokio_runtime;
    use crate::util_types::mutator_set::commit;
    use crate::util_types::mutator_set::shared::BATCH_SIZE;
    use crate::util_types::mutator_set::shared::CHUNK_SIZE;
    use crate::util_types::mutator_set::shared::NUM_TRIALS;
    use crate::util_types::mutator_set::shared::WINDOW_SIZE;
    use crate::util_types::test_shared::mutator_set::*;

    mod can_remove {
        use proptest::arbitrary::Arbitrary;
        use proptest::collection::vec;
        use proptest::test_runner::TestRunner;
        use proptest_arbitrary_interop::arb;
        use rand::rng;

        use super::*;
        use crate::protocol::consensus::block::mutator_set_update::MutatorSetUpdate;
        use crate::util_types::mutator_set::msa_and_records::MsaAndRecords;

        #[proptest]
        fn missing_chunk_dictionary_entry_small(
            #[strategy((1u64)..=(u64::from(u8::MAX)))] _num_leafs_aocl: u64,
            #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), 1usize))]
            _removables: Vec<(Digest, Digest, Digest)>,
            #[strategy(MsaAndRecords::arbitrary_with((#_removables, #_num_leafs_aocl)))]
            msa_and_records: MsaAndRecords,
        ) {
            let mut removal_record = msa_and_records.unpacked_removal_records()[0].clone();

            // Only test removal records with non-empty chunk dictionaries
            prop_assume!(!removal_record.target_chunks.dictionary.is_empty());

            assert!(msa_and_records
                .mutator_set_accumulator
                .can_remove(&removal_record));

            // Remove one element from the chunk dictionary and confirm failure.
            removal_record.target_chunks.dictionary.pop();

            assert!(!msa_and_records
                .mutator_set_accumulator
                .can_remove(&removal_record));
        }

        #[proptest]
        fn missing_chunk_dictionary_entry(
            #[strategy(0usize..30)] _num_removals: usize,
            #[strategy((#_num_removals as u64)..=(u64::from(u8::MAX)))] _num_leafs_aocl: u64,
            #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_removals))]
            _removables: Vec<(Digest, Digest, Digest)>,
            #[strategy(MsaAndRecords::arbitrary_with((#_removables, #_num_leafs_aocl)))]
            msa_and_records: MsaAndRecords,
        ) {
            let removal_records = msa_and_records.unpacked_removal_records();
            for rr in &removal_records {
                assert!(msa_and_records.mutator_set_accumulator.can_remove(rr));
            }

            // Remove one element from the chunk dictionary and confirm failure.
            for rr in removal_records {
                for i in 0..rr.target_chunks.dictionary.len() {
                    let mut bad = rr.clone();
                    bad.target_chunks.dictionary.remove(i);
                    assert!(!msa_and_records.mutator_set_accumulator.can_remove(&bad));
                }
            }
        }

        #[test]
        fn can_remove_false_when_already_removed_small_aocl() {
            // Verify that `can_remove` always returns false when the item has
            // already been removed. Do this for AOCL leaf count from 1 to ..
            let mut test_runner = TestRunner::deterministic();

            let mut rng = rng();
            for num_leafs in 1..=(3 * BATCH_SIZE as usize) {
                let msa_and_records = MsaAndRecords::arbitrary_with((
                    vec![(rng.random(), rng.random(), Digest::default()); num_leafs],
                    num_leafs as u64,
                ))
                .new_tree(&mut test_runner)
                .unwrap()
                .current();

                let removal_records = msa_and_records.unpacked_removal_records();
                for rr in &removal_records {
                    assert!(msa_and_records.mutator_set_accumulator.can_remove(rr));
                }

                for rr in removal_records {
                    let mut mutated_msa = msa_and_records.mutator_set_accumulator.clone();
                    mutated_msa.remove(&rr);
                    assert!(
                        !mutated_msa.can_remove(&rr),
                        "Can remove must return false after RR has been applied"
                    );
                }
            }
        }

        #[proptest]
        fn can_remove_agrees_with_update_result(
            #[strategy(0usize..30)] _num_removals: usize,
            #[strategy((#_num_removals as u64)..=(u64::from(u8::MAX)))] _num_leafs_aocl: u64,
            #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_removals))]
            _removables: Vec<(Digest, Digest, Digest)>,
            #[strategy(MsaAndRecords::arbitrary_with((#_removables, #_num_leafs_aocl)))]
            msa_and_records: MsaAndRecords,
        ) {
            let removal_records = msa_and_records.unpacked_removal_records();
            for rr in &removal_records {
                assert!(msa_and_records.mutator_set_accumulator.can_remove(rr));
            }

            let original_msa = msa_and_records.mutator_set_accumulator;
            for rr in removal_records {
                let mut mutated_msa = original_msa.clone();
                let as_msu = MutatorSetUpdate::new(vec![rr.clone()], vec![]);
                assert!(as_msu.apply_to_accumulator(&mut mutated_msa).is_ok());
                assert!(
                    !mutated_msa.can_remove(&rr),
                    "Can remove must return false after RR has been applied"
                );
            }
        }
    }

    #[test]
    fn active_window_chunk_interval_unit_test() {
        let mut accumulator: MutatorSetAccumulator = MutatorSetAccumulator::default();
        let (start_empty, end_empty) = accumulator.active_window_chunk_interval();
        assert_eq!(0, start_empty);
        assert_eq!(u64::from(WINDOW_SIZE / CHUNK_SIZE), end_empty);

        // Insert batch-size items and verify that a new batch interval is reported
        for _ in 0..BATCH_SIZE + 1 {
            let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
            let addition_record = commit(item, sender_randomness, receiver_preimage.hash());

            let (start, end) = accumulator.active_window_chunk_interval();
            assert_eq!(0, start);
            assert_eq!(u64::from(WINDOW_SIZE / CHUNK_SIZE), end);
            accumulator.add(&addition_record);
        }

        let (start_final, end_final) = accumulator.active_window_chunk_interval();
        assert_eq!(1, start_final);
        assert_eq!(u64::from(WINDOW_SIZE / CHUNK_SIZE) + 1, end_final);
    }

    #[proptest(cases = 10)]
    fn batch_index_and_active_window_chunk_interval_agree(
        #[strategy(1u64..10u64 * u64::from(BATCH_SIZE))] num_insertions: u64,
    ) {
        let mut accumulator: MutatorSetAccumulator = MutatorSetAccumulator::default();
        for _ in 0..num_insertions {
            let (start, end) = accumulator.active_window_chunk_interval();
            let batch_interval = accumulator.get_batch_index();
            prop_assert_eq!(batch_interval, start);
            prop_assert_eq!(batch_interval + u64::from(WINDOW_SIZE / CHUNK_SIZE), end);

            let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
            let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
            accumulator.add(&addition_record);
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn mutator_set_batch_remove_accumulator_test() {
        // Test the batch-remove function for mutator set accumulator
        let mut accumulator: MutatorSetAccumulator = MutatorSetAccumulator::default();
        let mut membership_proofs: Vec<MsMembershipProof> = vec![];
        let mut items: Vec<Digest> = vec![];

        // Add N elements to the MS
        let num_additions = 400;
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
        let mut accumulator_batch_remove = accumulator.clone();
        let updated_chunks = accumulator_batch_remove.batch_remove(
            removal_records.clone(),
            &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
        );

        // Verify return value from batch-removal method: updated chunks must
        // agree with chunks in membership proofs. If all membership proofs are
        // valid, then this check verifies that the returned chunks are correct.
        for (chk_idx, chunk) in &updated_chunks {
            for msmp in &membership_proofs {
                for (chidx, (_, chnk)) in &msmp.target_chunks.dictionary {
                    if *chidx == *chk_idx {
                        assert_eq!(chunk, chnk);
                    }
                }
            }
        }

        // Remove the entries one-by-one
        let mut accumulator_individual_remove = accumulator;
        while let Some(rr) = removal_records.pop() {
            RemovalRecord::batch_update_from_remove(
                &mut removal_records.iter_mut().collect_vec(),
                &rr,
            );

            accumulator_individual_remove.remove(&rr);
        }

        assert_eq!(
            accumulator_individual_remove, accumulator_batch_remove,
            "Mutator sets must agree regardless of removal method"
        );

        // Verify that the expected membership proofs fail/pass
        for (mp, &item, skipped) in izip!(
            membership_proofs.iter(),
            items.iter(),
            skipped_removes.into_iter()
        ) {
            // If this removal record was not applied, then the membership proof must verify
            assert_eq!(skipped, accumulator_individual_remove.verify(item, mp));
        }
    }

    #[apply(shared_tokio_runtime)]
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
                    for mp in &mut membership_proofs_sequential {
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

                    // Verify that the membership proof can be restored from an archival instance,
                    // both without and with privacy.
                    let arch_mp = archival_after_remove
                        .restore_membership_proof(
                            item,
                            sender_randomness,
                            receiver_preimage,
                            mp_batch.aocl_leaf_index,
                        )
                        .await
                        .unwrap();
                    let arch_mp_alt = archival_after_remove
                        .restore_membership_proof_privacy_preserving(arch_mp.compute_indices(item))
                        .await
                        .unwrap()
                        .extract_ms_membership_proof(
                            mp_batch.aocl_leaf_index,
                            sender_randomness,
                            receiver_preimage,
                        )
                        .unwrap();
                    assert_eq!(arch_mp, arch_mp_alt);
                    assert_eq!(arch_mp, mp_batch.to_owned());

                    // Verify that sequential and batch update produces the same membership proofs
                    assert_eq!(mp_batch, mp_seq);
                }
            }
        }
    }

    proptest::proptest! {
        #![proptest_config(ProptestConfig {
            cases: 100, .. ProptestConfig::default()
          })]
        #[test]
        fn test_mutator_set_accumulator_decode(
            msa in proptest_arbitrary_interop::arb::<MutatorSetAccumulator>()
        ) {
            let encoded = msa.encode();
            let decoded: MutatorSetAccumulator = *MutatorSetAccumulator::decode(&encoded).unwrap();
            prop_assert_eq!(msa, decoded);
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
                > (1.25 * f64::from(target_set_size)) as usize
            {
                rng.random_range(0..10) >= 3
            } else if items_and_membership_proofs.len()
                < (0.8 * f64::from(target_set_size)) as usize
            {
                rng.random_range(0..10) < 3
            } else {
                rng.random_range(0..10) < 5
            };
            if operation && !items_and_membership_proofs.is_empty() {
                // removal
                let index = rng.random_range(0..items_and_membership_proofs.len());
                let (item, membership_proof) = items_and_membership_proofs.swap_remove(index);
                let removal_record = msa.drop(item, &membership_proof);
                for (_it, mp) in &mut items_and_membership_proofs {
                    mp.update_from_remove(&removal_record);
                }
                msa.remove(&removal_record);
            } else {
                // addition
                let item = rng.random::<Digest>();
                let sender_randomness = rng.random::<Digest>();
                let receiver_preimage = rng.random::<Digest>();
                let addition_record = commit(item, sender_randomness, receiver_preimage);
                for (it, mp) in &mut items_and_membership_proofs {
                    mp.update_from_addition(*it, &msa, &addition_record)
                        .unwrap();
                }
                let membership_proof = msa.prove(item, sender_randomness, receiver_preimage);
                msa.add(&addition_record);
                items_and_membership_proofs.push((item, membership_proof));
            }
        }

        println!("{} operations resulted in a set containing {} elements; mutator set accumulator size: {} bytes", num_iterations, items_and_membership_proofs.len(), msa.get_size());
    }
}
