pub(crate) mod absolute_index_set;
pub(crate) mod chunk;
pub(crate) mod chunk_dictionary;
pub(crate) mod removal_record_list;

use std::collections::HashMap;
use std::collections::HashSet;
use std::ops::IndexMut;

use absolute_index_set::AbsoluteIndexSet;
#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Result;
// #[cfg(any(test, feature = "arbitrary-impls"))]
use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde_derive::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::twenty_first::util_types::mmr;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::LeafMutation;
use twenty_first::math::bfield_codec::BFieldCodec;
use twenty_first::util_types::mmr::mmr_trait::Mmr;

use super::mutator_set_accumulator::MutatorSetAccumulator;
use super::removal_record::chunk_dictionary::ChunkDictionary;
use super::shared::get_batch_mutation_argument_for_removal_record;
use super::shared::indices_to_hash_map;
use super::shared::BATCH_SIZE;
use super::shared::CHUNK_SIZE;
use super::MutatorSetError;
use crate::prelude::twenty_first;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, GetSize, BFieldCodec, TasmObject)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(Arbitrary))]
pub struct RemovalRecord {
    pub absolute_indices: AbsoluteIndexSet,
    pub target_chunks: ChunkDictionary,
}

impl RemovalRecord {
    /// Update a batch of removal records that are synced to a given mutator set, in anticipation
    /// of one addition to that mutator set. (The addition record
    /// does not matter; all necessary information is in the mutator set.)
    pub fn batch_update_from_addition(
        removal_records: &mut [&mut Self],
        mutator_set: &MutatorSetAccumulator,
    ) {
        let new_item_index = mutator_set.aocl.num_leafs();

        // if window does not slide, do nothing
        if !MutatorSetAccumulator::window_slides(new_item_index) {
            return;
        }

        // window does slide
        let new_chunk = mutator_set.swbf_active.slid_chunk();
        let new_chunk_digest: Digest = Tip5::hash(&new_chunk);

        let next_batch_index = new_item_index / u64::from(BATCH_SIZE);
        let current_batch_index = next_batch_index - 1;
        assert_eq!(
            current_batch_index,
            mutator_set.swbf_inactive.num_leafs(),
            "Number of SWBF MMR leafs must match current batch index"
        );

        // Insert the new chunk digest into the accumulator-version of the
        // SWBF MMR to get its authentication path. It's important to convert the MMR
        // to an MMR Accumulator here, since we don't want to drag around or clone
        // a whole archival MMR for this operation, as the archival MMR can be in the
        // size of gigabytes, whereas the MMR accumulator should be in the size of
        // kilobytes.
        let mut mmra: MmrAccumulator = mutator_set.swbf_inactive.to_accumulator();
        let new_swbf_auth_path: mmr::mmr_membership_proof::MmrMembershipProof =
            mmra.append(new_chunk_digest);

        // Collect all indices for all removal records that are being updated
        let mut chunk_index_to_rr_index: HashMap<u64, Vec<usize>> = HashMap::new();
        removal_records.iter().enumerate().for_each(|(i, rr)| {
            let indices = &rr.absolute_indices;
            let chunks_set: HashSet<u64> = indices
                .to_array()
                .iter()
                .map(|x| (x / u128::from(CHUNK_SIZE)) as u64)
                .collect();

            for chnkidx in chunks_set {
                chunk_index_to_rr_index.entry(chnkidx).or_default().push(i);
            }
        });

        // Find the removal records that need a new dictionary entry for the chunk
        // that's being added to the inactive part by this addition.
        let batch_index = new_item_index / u64::from(BATCH_SIZE);
        let old_window_start_batch_index = batch_index - 1;

        let rrs_for_new_chunk_dictionary_entry: Vec<usize> =
            match chunk_index_to_rr_index.get(&old_window_start_batch_index) {
                Some(vals) => vals.clone(),
                None => vec![],
            };

        // Find the removal records that have dictionary entry MMR membership proofs
        // that need to be updated because of the window sliding.
        let mut rrs_for_batch_append: HashSet<usize> = HashSet::new();
        for (chunk_index, mp_indices) in chunk_index_to_rr_index {
            if chunk_index < old_window_start_batch_index {
                for mp_index in mp_indices {
                    rrs_for_batch_append.insert(mp_index);
                }
            }
        }

        // Perform the updates

        // First insert the new entry into the chunk dictionary for the removal
        // record that need it.
        for i in &rrs_for_new_chunk_dictionary_entry {
            removal_records.index_mut(*i).target_chunks.insert(
                old_window_start_batch_index,
                (new_swbf_auth_path.clone(), new_chunk.clone()),
            );
        }

        // Collect those MMR membership proofs for chunks whose authentication
        // path might need to be updated due to the insertion of a new leaf in the
        // SWBF MMR.
        // This is a bit ugly and a bit slower than it could be. To prevent this
        // for-loop, you probably could collect the `Vec<&mut mp>` in the code above,
        // instead of just collecting the indices into the removal record vector.
        // It is, however, quite acceptable that many of the MMR membership proofs are
        // repeated since the MMR `batch_update_from_append` handles this optimally.
        // So relegating that bookkeeping to this function instead would not be more
        // efficient.
        let mut mmr_membership_proofs_for_append: Vec<
            &mut mmr::mmr_membership_proof::MmrMembershipProof,
        > = vec![];
        let mut leaf_indices = vec![];
        for (i, rr) in removal_records.iter_mut().enumerate() {
            if rrs_for_batch_append.contains(&i) {
                for (chunk_index, (mmr_mp, _chnk)) in rr.target_chunks.iter_mut() {
                    if *chunk_index != old_window_start_batch_index {
                        mmr_membership_proofs_for_append.push(mmr_mp);
                        leaf_indices.push(*chunk_index);
                    }
                }
            }
        }

        // Perform the update of all the MMR membership proofs contained in the removal records
        mmr::mmr_membership_proof::MmrMembershipProof::batch_update_from_append(
            &mut mmr_membership_proofs_for_append,
            &leaf_indices,
            mutator_set.swbf_inactive.num_leafs(),
            new_chunk_digest,
            &mutator_set.swbf_inactive.peaks(),
        );
    }

    pub fn batch_update_from_remove(
        removal_records: &mut [&mut Self],
        applied_removal_record: &RemovalRecord,
    ) {
        // Set all chunk values to the new values and calculate the mutation argument
        // for the batch updating of the MMR membership proofs.
        let mut chunk_dictionaries: Vec<&mut ChunkDictionary> = removal_records
            .iter_mut()
            .map(|mp| &mut mp.target_chunks)
            .collect();
        let (_mutated_chunks_by_rr_indices, mutation_argument) =
            get_batch_mutation_argument_for_removal_record(
                applied_removal_record,
                &mut chunk_dictionaries,
            );

        // Collect all the MMR membership proofs from the chunk dictionaries.
        let mut own_mmr_mps: Vec<&mut mmr::mmr_membership_proof::MmrMembershipProof> = vec![];
        let mut leaf_indices = vec![];
        for chunk_dict in &mut chunk_dictionaries {
            for (chunk_index, (mp, _)) in chunk_dict.iter_mut() {
                own_mmr_mps.push(mp);
                leaf_indices.push(*chunk_index);
            }
        }

        // Perform the batch mutation of the MMR membership proofs
        mmr::mmr_membership_proof::MmrMembershipProof::batch_update_from_batch_leaf_mutation(
            &mut own_mmr_mps,
            &leaf_indices,
            mutation_argument
                .iter()
                .map(|(i, p, l)| LeafMutation::new(*i, *l, p.clone()))
                .collect_vec(),
        );
    }

    fn has_required_authenticated_chunks(
        &self,
        mutator_set_accumulator: &MutatorSetAccumulator,
    ) -> bool {
        let Ok((inactive, _)) = self
            .absolute_indices
            .split_by_activity(mutator_set_accumulator)
        else {
            return false;
        };

        let required_chunk_indices: HashSet<u64> = inactive.into_keys().collect();
        let proven_chunk_indices: HashSet<u64> =
            self.target_chunks.all_chunk_indices().into_iter().collect();
        required_chunk_indices == proven_chunk_indices
    }

    /// Validates that a removal record is synchronized against the inactive
    /// part of the SWBF, and that all required chunk/MMR membership proofs are
    /// present.
    pub fn validate(&self, mutator_set: &MutatorSetAccumulator) -> bool {
        self.validate_inner(mutator_set).is_ok()
    }

    /// Same as [`Self::validate`] but with informative error code.
    pub(crate) fn validate_inner(
        &self,
        mutator_set: &MutatorSetAccumulator,
    ) -> Result<(), RemovalRecordValidityError> {
        if !self.has_required_authenticated_chunks(mutator_set) {
            return Err(RemovalRecordValidityError::AbsentAuthenticatedChunk);
        }

        let swbfi_peaks = mutator_set.swbf_inactive.peaks();
        let swbfi_leaf_count = mutator_set.swbf_inactive.num_leafs();
        let maybe_invalid_chunk =
            self.target_chunks
                .iter()
                .find(|(chunk_index, (mmr_proof, chunk))| {
                    let leaf_digest = Tip5::hash(chunk);
                    !mmr_proof.verify(*chunk_index, leaf_digest, &swbfi_peaks, swbfi_leaf_count)
                });
        if let Some((chunk_index, _)) = maybe_invalid_chunk {
            return Err(RemovalRecordValidityError::InvalidSwbfiMmrMp {
                chunk_index: *chunk_index,
            });
        }

        Ok(())
    }

    /// Returns a hashmap from chunk index to chunk.
    pub fn get_chunkidx_to_indices_dict(&self) -> HashMap<u64, Vec<u128>> {
        indices_to_hash_map(&self.absolute_indices.to_array())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemovalRecordValidityError {
    AbsentAuthenticatedChunk,
    InvalidSwbfiMmrMp { chunk_index: u64 },
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use itertools::Itertools;
    use proptest::prelude::*;
    use proptest_arbitrary_interop::arb;
    use rand::prelude::IndexedRandom;
    use rand::Rng;
    use tasm_lib::prelude::Tip5;
    use tasm_lib::triton_vm::prelude::BFieldCodec;

    use super::*;
    use crate::util_types::mutator_set::addition_record::AdditionRecord;
    use crate::util_types::mutator_set::commit;
    use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
    use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
    use crate::util_types::mutator_set::removal_record::removal_record_list::RemovalRecordList;
    use crate::util_types::mutator_set::shared::CHUNK_SIZE;
    use crate::util_types::mutator_set::shared::NUM_TRIALS;
    use crate::util_types::test_shared::mutator_set::*;

    #[test]
    fn increment_bloom_filter_index_behaves_as_expected() {
        let (_item, _mp, removal_record) = mock_item_mp_rr_for_init_msa();
        let original_index_set = removal_record.absolute_indices;
        for i in 0..NUM_TRIALS as usize {
            let mut mutated_index_set = original_index_set;
            mutated_index_set.increment_bloom_filter_index(i);

            assert_ne!(original_index_set, mutated_index_set);

            mutated_index_set.decrement_bloom_filter_index(i);
            assert_eq!(original_index_set, mutated_index_set);
        }
    }

    #[test]
    fn get_size_test() {
        let (_item, _mp, removal_record) = mock_item_mp_rr_for_init_msa();

        let serialization_result = bincode::serialize(&removal_record).unwrap();
        let reported_size = removal_record.get_size();

        // Assert that length of serialization result have same
        // order of magnitude as reported size result.
        assert!(serialization_result.len() * 2 > reported_size);
        assert!(reported_size * 2 > serialization_result.len());
    }

    #[test]
    fn split_by_activity_one_element_test() {
        let mut accumulator: MutatorSetAccumulator = MutatorSetAccumulator::default();
        let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
        let mp: MsMembershipProof = accumulator.prove(item, sender_randomness, receiver_preimage);
        accumulator.add(&mp.addition_record(item));
        let removal_record: RemovalRecord = accumulator.drop(item, &mp);
        let (inactive, active) = removal_record
            .absolute_indices
            .split_by_activity(&accumulator)
            .unwrap();

        assert!(
            inactive.is_empty(),
            "Indices in inactive part of Bloom filter must be
            empty set when window hasn't slid yet"
        );
        assert_eq!(
            NUM_TRIALS as usize,
            active.len(),
            "All indices must be located in the active window when window hasn't slid"
        );
    }

    #[test]
    fn verify_that_removal_records_and_mp_indices_agree() {
        let (item, mp, removal_record) = mock_item_mp_rr_for_init_msa();

        let mut mp_indices = mp.compute_indices(item).to_array();
        mp_indices.sort_unstable();
        let mut removal_rec_indices = removal_record.absolute_indices.to_array();
        removal_rec_indices.sort_unstable();

        assert_eq!(
            mp_indices, removal_rec_indices,
            "Removal record indices must agree with membership proof indices."
        );
    }

    #[test]
    fn hash_test() {
        let (_item, _mp, removal_record) = mock_item_mp_rr_for_init_msa();

        let mut removal_record_alt: RemovalRecord = removal_record.clone();
        assert_eq!(
            Tip5::hash(&removal_record),
            Tip5::hash(&removal_record_alt),
            "Same removal record must hash to same value"
        );

        // Verify that changing the absolute indices, changes the hash value
        removal_record_alt
            .absolute_indices
            .increment_bloom_filter_index(NUM_TRIALS as usize / 4);
        assert_ne!(
            Tip5::hash(&removal_record),
            Tip5::hash(&removal_record_alt),
            "Changing an index must produce a new hash"
        );
    }

    #[test]
    fn get_chunkidx_to_indices_test() {
        let (item, mp, removal_record) = mock_item_mp_rr_for_init_msa();

        let chunks2indices = removal_record.get_chunkidx_to_indices_dict();

        // Verify that indices from membership proof and remove records agree
        let mut rr_indices: Vec<u128> = chunks2indices.clone().into_values().concat();
        rr_indices.sort_unstable();
        let mut mp_indices = mp.compute_indices(item).to_array();
        mp_indices.sort_unstable();
        assert_eq!(mp_indices.to_vec(), rr_indices);
        assert_eq!(NUM_TRIALS as usize, rr_indices.len());

        // Verify that the hash map has put the indices into the correct buckets
        for (key, values) in chunks2indices {
            for value in values {
                assert!(
                    (value - u128::from(key) * u128::from(CHUNK_SIZE)) < u128::from(CHUNK_SIZE)
                );
            }
        }
    }

    #[test]
    fn removal_record_serialization_test() {
        // TODO: You could argue that this test doesn't belong here, as it tests the behavior of
        // an imported library. I included it here, though, because the setup seems a bit clumsy
        // to me so far.

        let (_item, _mp, removal_record) = mock_item_mp_rr_for_init_msa();

        let json: String = serde_json::to_string(&removal_record).unwrap();
        let s_back = serde_json::from_str::<RemovalRecord>(&json).unwrap();
        assert_eq!(s_back.absolute_indices, removal_record.absolute_indices);
        assert_eq!(s_back.target_chunks, removal_record.target_chunks);
    }

    #[test]
    fn simple_remove_test() {
        // Verify that a single element can be added to and removed from the mutator set
        let mut accumulator: MutatorSetAccumulator = MutatorSetAccumulator::default();
        let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
        let addition_record: AdditionRecord =
            commit(item, sender_randomness, receiver_preimage.hash());
        let mp = accumulator.prove(item, sender_randomness, receiver_preimage);

        assert!(
            !accumulator.verify(item, &mp),
            "Item must fail to verify before it is added"
        );
        accumulator.add(&addition_record);
        let rr = accumulator.drop(item, &mp);
        assert!(
            accumulator.verify(item, &mp),
            "Item must succeed in verification after it is added"
        );
        accumulator.remove(&rr);
        assert!(
            !accumulator.verify(item, &mp),
            "Item must fail to verify after it is removed"
        );
    }

    #[test]
    fn validate_on_out_of_bounds_index() {
        let mut accumulator: MutatorSetAccumulator = MutatorSetAccumulator::default();
        let (min_index_in_active_window, max_index_in_active_window) =
            accumulator.active_window_chunk_interval();
        let num_chunks_in_active_window = max_index_in_active_window - min_index_in_active_window;

        let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
        let addition_record: AdditionRecord =
            commit(item, sender_randomness, receiver_preimage.hash());

        let mp = accumulator.prove(item, sender_randomness, receiver_preimage);
        accumulator.add(&addition_record);
        let mut rr_for_aocl0 = accumulator.drop(item, &mp);

        // Add so many items, that the current active window is completely
        // replaced by the inactive part of the sliding-window Bloom filter.
        // That way, the removal record is guaranteed to be invalid against
        // the empty mutator set.
        for _ in 0..u64::from(BATCH_SIZE) * num_chunks_in_active_window + 1 {
            RemovalRecord::batch_update_from_addition(&mut [&mut rr_for_aocl0], &accumulator);
            accumulator.add(&addition_record);
        }

        assert!(rr_for_aocl0.validate(&accumulator));
        assert!(!rr_for_aocl0.validate(&MutatorSetAccumulator::default()));
    }

    /// non-deterministic; a correction was shelved at <https://github.com/Neptune-Crypto/neptune-core/pull/554>
    #[test_strategy::proptest(cases = 10)]
    fn removal_record_missing_chunk_element_is_invalid_pbt(
        #[strategy(1u64..20*u64::from(BATCH_SIZE))] initial_additions: u64,
        #[strategy(0u64..(#initial_additions as u64))] index_to_drop: u64,
    ) {
        // Construct a valid removal record, verify that it is considered
        // valid, then remove one element from its chunk dictionary and verify
        // that it is now considered invalid.
        let mut accumulator: MutatorSetAccumulator = MutatorSetAccumulator::default();
        let mut mps = vec![];
        let mut items = vec![];
        for j in 0..initial_additions {
            let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
            let addition_record: AdditionRecord =
                commit(item, sender_randomness, receiver_preimage.hash());
            let mp = accumulator.prove(item, sender_randomness, receiver_preimage);
            MsMembershipProof::batch_update_from_addition(
                &mut mps.iter_mut().collect_vec(),
                &items,
                &accumulator,
                &addition_record,
            )
            .unwrap();
            accumulator.add(&addition_record);

            if j == index_to_drop {
                mps.push(mp.clone());
                items.push(item);
            }
        }

        let msmp = mps[0].clone();
        let item = items[0];

        let mut rr = accumulator.drop(item, &msmp);
        assert!(rr.validate(&accumulator));

        // If the removal record has no indices in the inactive part of the
        // Bloom filter, then continue to next test case.
        let (inactive, _) = rr.absolute_indices.split_by_activity(&accumulator).unwrap();
        if inactive.is_empty() {
            return Ok(());
        }

        let to_remove = **inactive
            .keys()
            .collect_vec()
            .choose(&mut rand::rng())
            .unwrap();
        rr.target_chunks.remove(&to_remove);
        assert!(!rr.validate(&accumulator));
    }

    #[test]
    fn batch_update_from_addition_pbt() {
        // Verify that a single element can be added to and removed from the mutator set

        let test_iterations = 10;
        for _ in 0..test_iterations {
            let mut accumulator: MutatorSetAccumulator = MutatorSetAccumulator::default();
            let mut removal_records: Vec<(usize, RemovalRecord)> = vec![];
            let mut items = vec![];
            let mut mps = vec![];
            for i in 0..2 * BATCH_SIZE + 4 {
                let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();

                let addition_record: AdditionRecord =
                    commit(item, sender_randomness, receiver_preimage.hash());
                let mp = accumulator.prove(item, sender_randomness, receiver_preimage);

                // Update all removal records from addition, then add the element
                RemovalRecord::batch_update_from_addition(
                    &mut removal_records
                        .iter_mut()
                        .map(|x| &mut x.1)
                        .collect::<Vec<_>>(),
                    &accumulator,
                );
                let update_res_mp = MsMembershipProof::batch_update_from_addition(
                    &mut mps.iter_mut().collect::<Vec<_>>(),
                    &items,
                    &accumulator,
                    &addition_record,
                );
                assert!(
                    update_res_mp.is_ok(),
                    "batch update must return OK, i = {}",
                    i
                );
                accumulator.add(&addition_record);
                mps.push(mp.clone());
                items.push(item);

                for removal_record in removal_records.iter().map(|x| &x.1) {
                    assert!(
                        removal_record.validate(&accumulator),
                        "removal records must validate, i = {}",
                        i
                    );
                    assert!(
                        accumulator.can_remove(removal_record),
                        "removal records must return true on `can_remove`, i = {}",
                        i
                    );
                }

                let rr = accumulator.drop(item, &mp);
                removal_records.push((i as usize, rr));
            }

            // pick a random removal record from the list of all removal records and check that it still
            // works.
            //
            // Note that in order to use more than one of the removal records at this points would require
            // updating the remaining removal records from removal, and that's not what we want to test in
            // this function, so we only test one of the removal records here.
            let (chosen_index, random_removal_record) =
                removal_records.choose(&mut rand::rng()).unwrap();
            assert!(accumulator.verify(items[*chosen_index], &mps[*chosen_index]));
            assert!(
                accumulator.can_remove(random_removal_record),
                "removal records must return true on `can_remove`",
            );
            assert!(
                random_removal_record.validate(&accumulator),
                "removal record must have valid MMR MPs"
            );
            accumulator.remove(random_removal_record);
            assert!(!accumulator.verify(items[*chosen_index], &mps[*chosen_index]));

            assert!(
                !accumulator.can_remove(random_removal_record),
                "removal records must return false on `can_remove` after removal",
            );
        }
    }

    #[test]
    fn batch_update_from_addition_and_remove_pbt() {
        // Verify that a single element can be added to and removed from the mutator set

        let mut accumulator: MutatorSetAccumulator = MutatorSetAccumulator::default();

        let mut removal_records: Vec<(usize, RemovalRecord)> = vec![];
        let mut items = vec![];
        let mut mps = vec![];
        for i in 0..16 * BATCH_SIZE + 4 {
            let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();

            let addition_record: AdditionRecord =
                commit(item, sender_randomness, receiver_preimage.hash());
            let mp = accumulator.prove(item, sender_randomness, receiver_preimage);

            // Update all removal records and membership proofs from addition,
            // then add the element.
            RemovalRecord::batch_update_from_addition(
                &mut removal_records
                    .iter_mut()
                    .map(|x| &mut x.1)
                    .collect::<Vec<_>>(),
                &accumulator,
            );
            let update_res_mp = MsMembershipProof::batch_update_from_addition(
                &mut mps.iter_mut().collect::<Vec<_>>(),
                &items,
                &accumulator,
                &addition_record,
            );
            assert!(
                update_res_mp.is_ok(),
                "batch update must return OK, i = {}",
                i
            );
            accumulator.add(&addition_record);
            mps.push(mp.clone());
            items.push(item);

            for removal_record in removal_records.iter().map(|x| &x.1) {
                assert!(
                    removal_record.validate(&accumulator),
                    "removal records must validate, i = {}",
                    i
                );
                assert!(
                    accumulator.can_remove(removal_record),
                    "removal records must return true on `can_remove`, i = {}",
                    i
                );
            }
            let just_removal_records = removal_records
                .iter()
                .map(|(_, rr)| rr.clone())
                .collect_vec();
            assert_eq!(
                just_removal_records.clone(),
                RemovalRecordList::try_unpack(RemovalRecordList::pack(
                    just_removal_records.clone(),
                ),)
                .unwrap_or_else(|err| panic!(
                    "i: {i};\n\n just_removal_records: {just_removal_records:#?}\n. Error:\n{err}"
                )),
                "i: {i};\n\n just_removal_records: {just_removal_records:#?}\n"
            );

            let rr = accumulator.drop(item, &mp);

            removal_records.push((i as usize, rr));
        }

        // Now apply all removal records one at a time and batch update the
        // remaining removal records to keep them valid.
        for i in 0..16 * BATCH_SIZE + 4 {
            let remove_idx = rand::rng().random_range(0..removal_records.len());
            let random_removal_record = removal_records.remove(remove_idx).1;
            RemovalRecord::batch_update_from_remove(
                &mut removal_records
                    .iter_mut()
                    .map(|x| &mut x.1)
                    .collect::<Vec<_>>(),
                &random_removal_record,
            );

            assert!(accumulator.can_remove(&random_removal_record));
            accumulator.remove(&random_removal_record);
            assert!(!accumulator.can_remove(&random_removal_record));

            for removal_record in removal_records.iter().map(|x| &x.1) {
                assert!(
                    removal_record.validate(&accumulator),
                    "removal records must validate, i = {}",
                    i
                );
                assert!(accumulator.can_remove(removal_record));
            }

            let just_removal_records = removal_records
                .iter()
                .map(|(_, rr)| rr.clone())
                .collect_vec();
            assert_eq!(
                just_removal_records.clone(),
                RemovalRecordList::try_unpack(RemovalRecordList::pack(just_removal_records),)
                    .unwrap()
            );
        }
    }

    proptest::proptest! {
        #[test]
        fn test_index_set_serialization(
            original_indexset in crate::tests::shared::strategies::absindset()
        ) {
            let serialized_indexset = serde_json::to_string(&original_indexset).unwrap();
            let reconstructed_indexset: AbsoluteIndexSet =
                serde_json::from_str(&serialized_indexset).unwrap();

            assert_eq!(original_indexset, reconstructed_indexset);
        }
    }

    proptest::proptest! {
        #![proptest_config(ProptestConfig {
            cases: 10, .. ProptestConfig::default()
          })]
        #[test]
        fn test_removal_record_decode(removal_record in arb::<RemovalRecord>()) {
                let encoded = &removal_record.encode();
                let decoded = *RemovalRecord::decode(encoded).unwrap();
                assert_eq!(removal_record, decoded);
        }

        #[test]
        fn test_removal_record_vec_decode(removal_records in proptest::collection::vec(arb::<RemovalRecord>(), 0..10)) {
                let encoded = removal_records.encode();
                let decoded = *Vec::<RemovalRecord>::decode(&encoded).unwrap();
                assert_eq!(removal_records, decoded);
        }
    }

    proptest::proptest! {
        #![proptest_config(ProptestConfig {
            cases: 100, .. ProptestConfig::default()
          })]
        #[test]
        fn test_absindexset_record_decode(removal_record in arb::<RemovalRecord>()) {
                let encoded_absindexset = removal_record.absolute_indices.encode();
                let decoded_absindexset = *AbsoluteIndexSet::decode(&encoded_absindexset).unwrap();
                assert_eq!(
                    removal_record.absolute_indices,
                    decoded_absindexset
                );
        }
    }
}
