use std::collections::HashMap;
use std::collections::HashSet;
use std::marker::PhantomData;
use std::ops::IndexMut;

use arbitrary::Arbitrary;
use get_size2::GetSize;
use itertools::Itertools;
use serde::de::SeqAccess;
use serde::de::Visitor;
use serde::ser::SerializeTuple;
use serde::Deserialize;
use serde_derive::Serialize;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::LeafMutation;
use twenty_first::math::bfield_codec::BFieldCodec;
use twenty_first::math::tip5::Digest;
use twenty_first::util_types::mmr;
use twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use twenty_first::util_types::mmr::mmr_trait::Mmr;

use super::chunk_dictionary::ChunkDictionary;
use super::mutator_set_accumulator::MutatorSetAccumulator;
use super::shared::get_batch_mutation_argument_for_removal_record;
use super::shared::indices_to_hash_map;
use super::shared::BATCH_SIZE;
use super::shared::CHUNK_SIZE;
use super::shared::NUM_TRIALS;
use super::MutatorSetError;
use crate::models::blockchain::shared::Hash;
use crate::prelude::twenty_first;

#[derive(Debug, Clone, Copy, PartialEq, Eq, BFieldCodec, TasmObject, Arbitrary)]
pub struct AbsoluteIndexSet([u128; NUM_TRIALS as usize]);

impl GetSize for AbsoluteIndexSet {
    fn get_stack_size() -> usize {
        std::mem::size_of::<Self>()
    }

    fn get_heap_size(&self) -> usize {
        self.0.get_heap_size()
    }

    fn get_size(&self) -> usize {
        Self::get_stack_size() + GetSize::get_heap_size(self)
    }
}

impl AbsoluteIndexSet {
    pub fn new(indices: &[u128; NUM_TRIALS as usize]) -> Self {
        Self(*indices)
    }

    pub fn sort_unstable(&mut self) {
        self.0.sort_unstable();
    }

    pub fn to_vec(&self) -> Vec<u128> {
        self.0.to_vec()
    }

    pub fn to_array(&self) -> [u128; NUM_TRIALS as usize] {
        self.0
    }

    pub fn to_array_mut(&mut self) -> &mut [u128; NUM_TRIALS as usize] {
        &mut self.0
    }

    /// Split the [`AbsoluteIndexSet`] into two parts, one for chunks in the
    /// inactive part of the Bloom filter and another one for chunks in the
    /// active part of the Bloom filter.
    ///
    /// Returns an error if a removal index is a future value, i.e. one that's
    /// not yet covered by the active window.
    #[allow(clippy::type_complexity)]
    pub fn split_by_activity(
        &self,
        mutator_set: &MutatorSetAccumulator,
    ) -> Result<(HashMap<u64, Vec<u128>>, Vec<u128>), MutatorSetError> {
        let (aw_chunk_index_min, aw_chunk_index_max) = mutator_set.active_window_chunk_interval();
        let (inactive, active): (HashMap<_, _>, HashMap<_, _>) = indices_to_hash_map(&self.0)
            .into_iter()
            .partition(|&(chunk_index, _)| chunk_index < aw_chunk_index_min);

        if let Some(chunk_index) = active.keys().find(|&&k| k > aw_chunk_index_max) {
            return Err(MutatorSetError::AbsoluteRemovalIndexIsFutureIndex {
                current_max_chunk_index: aw_chunk_index_max,
                saw_chunk_index: *chunk_index,
            });
        }

        let active = active.into_values().flatten().collect_vec();

        Ok((inactive, active))
    }
}

impl serde::Serialize for AbsoluteIndexSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_tuple(NUM_TRIALS as usize)?;
        for b in self.0 {
            seq.serialize_element(&b)?;
        }
        seq.end()
    }
}

/// ArrayVisitor
/// Used for deserializing large arrays, with size known at compile time.
/// Credit: MikailBag https://github.com/serde-rs/serde/issues/1937
struct ArrayVisitor<T, const N: usize>(PhantomData<T>);

impl<'de, T, const N: usize> Visitor<'de> for ArrayVisitor<T, N>
where
    T: Deserialize<'de>,
{
    type Value = [T; N];

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str(&format!("an array of length {}", N))
    }

    #[inline]
    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        // can be optimized using MaybeUninit
        let mut data = Vec::with_capacity(N);
        for _ in 0..N {
            match (seq.next_element())? {
                Some(val) => data.push(val),
                None => return Err(serde::de::Error::invalid_length(N, &self)),
            }
        }
        match data.try_into() {
            Ok(arr) => Ok(arr),
            Err(_) => unreachable!(),
        }
    }
}

impl<'de> Deserialize<'de> for AbsoluteIndexSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(AbsoluteIndexSet::new(&deserializer.deserialize_tuple(
            NUM_TRIALS as usize,
            ArrayVisitor::<u128, { NUM_TRIALS as usize }>(PhantomData),
        )?))
    }
}

#[derive(
    Clone, Debug, Deserialize, Serialize, PartialEq, Eq, GetSize, BFieldCodec, TasmObject, Arbitrary,
)]
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
        let new_chunk_digest: Digest = Hash::hash(&new_chunk);

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
                .map(|x| (x / CHUNK_SIZE as u128) as u64)
                .collect();

            chunks_set
                .iter()
                .for_each(|chnkidx| chunk_index_to_rr_index.entry(*chnkidx).or_default().push(i));
        });

        // Find the removal records that need a new dictionary entry for the chunk
        // that's being added to the inactive part by this addition.
        let batch_index = new_item_index / BATCH_SIZE as u64;
        let old_window_start_batch_index = batch_index - 1;

        let rrs_for_new_chunk_dictionary_entry: Vec<usize> =
            match chunk_index_to_rr_index.get(&old_window_start_batch_index) {
                Some(vals) => vals.clone(),
                None => vec![],
            };

        // Find the removal records that have dictionary entry MMR membership proofs
        // that need to be updated because of the window sliding.
        let mut rrs_for_batch_append: HashSet<usize> = HashSet::new();
        for (chunk_index, mp_indices) in chunk_index_to_rr_index.into_iter() {
            if chunk_index < old_window_start_batch_index {
                for mp_index in mp_indices {
                    rrs_for_batch_append.insert(mp_index);
                }
            }
        }

        // Perform the updates

        // First insert the new entry into the chunk dictionary for the removal
        // record that need it.
        for i in rrs_for_new_chunk_dictionary_entry.iter() {
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
        for chunk_dict in chunk_dictionaries.iter_mut() {
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

    /// Validates that a removal record is synchronized against the inactive part of the SWBF
    pub fn validate(&self, mutator_set: &MutatorSetAccumulator) -> bool {
        if !self.has_required_authenticated_chunks(mutator_set) {
            return false;
        }

        let swbfi_peaks = mutator_set.swbf_inactive.peaks();
        let swbfi_leaf_count = mutator_set.swbf_inactive.num_leafs();
        self.target_chunks.all(|(chunk_index, (mmr_proof, chunk))| {
            let leaf_digest = Hash::hash(chunk);
            mmr_proof.verify(*chunk_index, leaf_digest, &swbfi_peaks, swbfi_leaf_count)
        })
    }

    /// Returns a hashmap from chunk index to chunk.
    pub fn get_chunkidx_to_indices_dict(&self) -> HashMap<u64, Vec<u128>> {
        indices_to_hash_map(&self.absolute_indices.to_array())
    }
}

#[cfg(test)]
mod removal_record_tests {
    use itertools::Itertools;
    use rand::seq::SliceRandom;
    use rand::thread_rng;
    use rand::Rng;
    use rand::RngCore;
    use test_strategy::proptest;

    use super::*;
    use crate::util_types::mutator_set::addition_record::AdditionRecord;
    use crate::util_types::mutator_set::commit;
    use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
    use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
    use crate::util_types::mutator_set::shared::CHUNK_SIZE;
    use crate::util_types::mutator_set::shared::NUM_TRIALS;
    use crate::util_types::test_shared::mutator_set::*;

    impl AbsoluteIndexSet {
        /// Test-function used for negative tests of removal records
        pub(crate) fn increment_bloom_filter_index(&mut self, index: usize) {
            self.0[index] = self.0[index].wrapping_add(1);
        }

        /// Test-function used for negative tests of removal records
        pub(crate) fn decrement_bloom_filter_index(&mut self, index: usize) {
            self.0[index] = self.0[index].wrapping_sub(1);
        }
    }

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

        let mut mp_indices = mp.compute_indices(item).0;
        mp_indices.sort_unstable();
        let mut removal_rec_indices = removal_record.absolute_indices.0;
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
            Hash::hash(&removal_record),
            Hash::hash(&removal_record_alt),
            "Same removal record must hash to same value"
        );

        // Verify that changing the absolute indices, changes the hash value
        removal_record_alt.absolute_indices.to_array_mut()[NUM_TRIALS as usize / 4] += 1;
        assert_ne!(
            Hash::hash(&removal_record),
            Hash::hash(&removal_record_alt),
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
        let mut mp_indices = mp.compute_indices(item).0;
        mp_indices.sort_unstable();
        assert_eq!(mp_indices.to_vec(), rr_indices);
        assert_eq!(NUM_TRIALS as usize, rr_indices.len());

        // Verify that the hash map has put the indices into the correct buckets
        for (key, values) in chunks2indices {
            for value in values {
                assert!((value - key as u128 * CHUNK_SIZE as u128) < CHUNK_SIZE as u128);
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
        for _ in 0..(BATCH_SIZE as u64) * num_chunks_in_active_window + 1 {
            RemovalRecord::batch_update_from_addition(&mut [&mut rr_for_aocl0], &accumulator);
            accumulator.add(&addition_record);
        }

        assert!(rr_for_aocl0.validate(&accumulator));
        assert!(!rr_for_aocl0.validate(&MutatorSetAccumulator::default()));
    }

    #[proptest(cases = 10)]
    fn removal_record_missing_chunk_element_is_invalid_pbt(
        #[strategy(1u64..20*BATCH_SIZE as u64)] initial_additions: u64,
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
            .choose(&mut thread_rng())
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
                removal_records.choose(&mut rand::thread_rng()).unwrap();
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
        for i in 0..12 * BATCH_SIZE + 4 {
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

            let rr = accumulator.drop(item, &mp);

            removal_records.push((i as usize, rr));
        }

        // Now apply all removal records one at a time and batch update the remaining removal records
        for i in 0..12 * BATCH_SIZE + 4 {
            let remove_idx = rand::thread_rng().gen_range(0..removal_records.len());
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
        }
    }

    #[test]
    fn test_index_set_serialization() {
        let mut rng = thread_rng();
        let original_indexset = AbsoluteIndexSet::new(
            &(0..NUM_TRIALS)
                .map(|_| ((rng.next_u64() as u128) << 64) | (rng.next_u64() as u128))
                .collect_vec()
                .try_into()
                .unwrap(),
        );
        let serialized_indexset = serde_json::to_string(&original_indexset).unwrap();
        let reconstructed_indexset: AbsoluteIndexSet =
            serde_json::from_str(&serialized_indexset).unwrap();

        assert_eq!(original_indexset, reconstructed_indexset);
    }

    #[test]
    fn test_removal_record_decode() {
        for _ in 0..10 {
            let removal_record = random_removal_record();
            let encoded = removal_record.encode();
            let decoded = *RemovalRecord::decode(&encoded).unwrap();
            assert_eq!(removal_record, decoded);
        }
    }

    #[test]
    fn test_removal_record_vec_decode() {
        let mut rng = thread_rng();
        for _ in 0..10 {
            let length = rng.gen_range(0..10);
            let removal_records = vec![random_removal_record(); length];
            let encoded = removal_records.encode();
            let decoded = *Vec::<RemovalRecord>::decode(&encoded).unwrap();
            assert_eq!(removal_records, decoded);
        }
    }

    #[test]
    fn test_absindexset_record_decode() {
        for _ in 0..100 {
            let removal_record = random_removal_record();
            let encoded_absindexset = removal_record.absolute_indices.encode();
            let decoded_absindexset = *AbsoluteIndexSet::decode(&encoded_absindexset).unwrap();
            assert_eq!(removal_record.absolute_indices, decoded_absindexset);
        }
    }
}
