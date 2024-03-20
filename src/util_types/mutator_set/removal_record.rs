use crate::models::blockchain::shared::Hash;
use crate::prelude::twenty_first;

use arbitrary::Arbitrary;
use get_size::GetSize;
use itertools::Itertools;
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::Deserialize;
use serde_derive::Serialize;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::ops::IndexMut;
use tasm_lib::structure::tasm_object::TasmObject;
use twenty_first::shared_math::bfield_codec::BFieldCodec;
use twenty_first::shared_math::tip5::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

use super::chunk_dictionary::{pseudorandom_chunk_dictionary, ChunkDictionary};
use super::mutator_set_kernel::MutatorSetKernel;
use super::shared::{
    get_batch_mutation_argument_for_removal_record, indices_to_hash_map, BATCH_SIZE, CHUNK_SIZE,
    NUM_TRIALS,
};
use twenty_first::util_types::mmr;

use crate::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
use crate::util_types::mmr::traits::*;
use crate::util_types::mmr::MmrAccumulator;

#[derive(Debug, Clone, PartialEq, Eq, BFieldCodec, Arbitrary)]
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
    /// Update a batch of removal records that are synced to a given mutator set, given
    /// that that mutator set will be updated with an addition. (The addition record
    /// does not matter; all necessary information is in the mutator set.)
    pub async fn batch_update_from_addition<MMR: Mmr<Hash>>(
        removal_records: &mut [&mut Self],
        mutator_set: &mut MutatorSetKernel<MMR>,
    ) {
        let new_item_index = mutator_set.aocl.count_leaves().await;

        // if window does not slide, do nothing
        if !MutatorSetKernel::<MMR>::window_slides(new_item_index) {
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
        let mut mmra: MmrAccumulator<Hash> = mutator_set.swbf_inactive.to_accumulator().await;
        let new_swbf_auth_path: MmrMembershipProof<Hash> = mmra.append(new_chunk_digest).await;

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
            removal_records
                .index_mut(*i)
                .target_chunks
                .dictionary
                .insert(
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
            &mut mmr::mmr_membership_proof::MmrMembershipProof<Hash>,
        > = vec![];
        for (i, rr) in removal_records.iter_mut().enumerate() {
            if rrs_for_batch_append.contains(&i) {
                for (_, (mmr_mp, _chnk)) in rr.target_chunks.dictionary.iter_mut() {
                    mmr_membership_proofs_for_append.push(mmr_mp);
                }
            }
        }

        // Perform the update of all the MMR membership proofs contained in the removal records
        MmrMembershipProof::<Hash>::batch_update_from_append(
            &mut mmr_membership_proofs_for_append,
            mutator_set.swbf_inactive.count_leaves().await,
            new_chunk_digest,
            &mutator_set.swbf_inactive.get_peaks().await,
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
        let mut own_mmr_mps: Vec<&mut MmrMembershipProof<Hash>> = vec![];
        for chunk_dict in chunk_dictionaries.iter_mut() {
            for (_, (mp, _)) in chunk_dict.dictionary.iter_mut() {
                own_mmr_mps.push(mp);
            }
        }

        // Perform the batch mutation of the MMR membership proofs
        MmrMembershipProof::batch_update_from_batch_leaf_mutation(
            &mut own_mmr_mps,
            mutation_argument,
        );
    }

    /// Validates that a removal record is synchronized against the inactive part of the SWBF
    pub async fn validate<M>(&self, mutator_set: &MutatorSetKernel<M>) -> bool
    where
        M: Mmr<Hash>,
    {
        let peaks = mutator_set.swbf_inactive.get_peaks().await;
        let leaf_count = mutator_set.swbf_inactive.count_leaves().await;

        self.target_chunks
            .dictionary
            .iter()
            .all(|(_i, (proof, chunk))| {
                let leaf_digest = Hash::hash(chunk);
                let (verified, _final_state) = proof.verify(&peaks, leaf_digest, leaf_count);
                verified
            })
    }

    /// Returns a hashmap from chunk index to chunk.
    pub fn get_chunkidx_to_indices_dict(&self) -> HashMap<u64, Vec<u128>> {
        indices_to_hash_map(&self.absolute_indices.to_array())
    }
}

/// Generate a pseudorandom removal record from the given seed, for testing purposes.
pub fn pseudorandom_removal_record(seed: [u8; 32]) -> RemovalRecord {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let absolute_indices = AbsoluteIndexSet::new(
        &(0..NUM_TRIALS as usize)
            .map(|_| ((rng.next_u64() as u128) << 64) ^ rng.next_u64() as u128)
            .collect_vec()
            .try_into()
            .unwrap(),
    );
    let target_chunks = pseudorandom_chunk_dictionary(rng.gen::<[u8; 32]>());

    RemovalRecord {
        absolute_indices,
        target_chunks,
    }
}

#[cfg(test)]
mod removal_record_tests {
    use itertools::Itertools;
    use rand::seq::SliceRandom;
    use rand::{thread_rng, Rng, RngCore};

    use crate::util_types::mutator_set::addition_record::AdditionRecord;
    use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
    use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
    use crate::util_types::mutator_set::mutator_set_trait::*;
    use crate::util_types::mutator_set::shared::{CHUNK_SIZE, NUM_TRIALS};
    use crate::util_types::test_shared::mutator_set::*;

    use super::*;

    async fn get_item_mp_and_removal_record() -> (Digest, MsMembershipProof, RemovalRecord) {
        let mut accumulator: MutatorSetAccumulator = MutatorSetAccumulator::default();
        let (item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();
        let mp: MsMembershipProof = accumulator
            .prove(item, sender_randomness, receiver_preimage)
            .await;
        let removal_record: RemovalRecord = accumulator.drop(item, &mp);
        (item, mp, removal_record)
    }

    #[tokio::test]
    async fn get_size_test() {
        let (_item, _mp, removal_record) = get_item_mp_and_removal_record().await;

        let serialization_result = bincode::serialize(&removal_record).unwrap();
        let reported_size = removal_record.get_size();

        // Assert that length of serialization result have same
        // order of magnitude as reported size result.
        assert!(serialization_result.len() * 2 > reported_size);
        assert!(reported_size * 2 > serialization_result.len());
    }

    #[tokio::test]
    async fn verify_that_removal_records_and_mp_indices_agree() {
        let (item, mp, removal_record) = get_item_mp_and_removal_record().await;

        let mut mp_indices = mp.compute_indices(item).0;
        mp_indices.sort_unstable();
        let mut removal_rec_indices = removal_record.absolute_indices.0;
        removal_rec_indices.sort_unstable();

        assert_eq!(
            mp_indices, removal_rec_indices,
            "Removal record indices must agree with membership proof indices."
        );
    }

    #[tokio::test]
    async fn hash_test() {
        let (_item, _mp, removal_record) = get_item_mp_and_removal_record().await;

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

    #[tokio::test]
    async fn get_chunkidx_to_indices_test() {
        let (item, mp, removal_record) = get_item_mp_and_removal_record().await;

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

    #[tokio::test]
    async fn removal_record_serialization_test() {
        // TODO: You could argue that this test doesn't belong here, as it tests the behavior of
        // an imported library. I included it here, though, because the setup seems a bit clumsy
        // to me so far.

        let (_item, _mp, removal_record) = get_item_mp_and_removal_record().await;

        let json: String = serde_json::to_string(&removal_record).unwrap();
        let s_back = serde_json::from_str::<RemovalRecord>(&json).unwrap();
        assert_eq!(s_back.absolute_indices, removal_record.absolute_indices);
        assert_eq!(s_back.target_chunks, removal_record.target_chunks);
    }

    #[tokio::test]
    async fn simple_remove_test() {
        // Verify that a single element can be added to and removed from the mutator set
        let mut accumulator: MutatorSetAccumulator = MutatorSetAccumulator::default();
        let (item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();
        let addition_record: AdditionRecord =
            commit(item, sender_randomness, receiver_preimage.hash::<Hash>());
        let mp = accumulator
            .prove(item, sender_randomness, receiver_preimage)
            .await;

        assert!(
            !accumulator.verify(item, &mp).await,
            "Item must fail to verify before it is added"
        );
        accumulator.add(&addition_record).await;
        let rr = accumulator.drop(item, &mp);
        assert!(
            accumulator.verify(item, &mp).await,
            "Item must succeed in verification after it is added"
        );
        accumulator.remove(&rr).await;
        assert!(
            !accumulator.verify(item, &mp).await,
            "Item must fail to verify after it is removed"
        );
    }

    #[tokio::test]
    async fn batch_update_from_addition_pbt() {
        // Verify that a single element can be added to and removed from the mutator set

        let test_iterations = 10;
        for _ in 0..test_iterations {
            let mut accumulator: MutatorSetAccumulator = MutatorSetAccumulator::default();
            let mut removal_records: Vec<(usize, RemovalRecord)> = vec![];
            let mut items = vec![];
            let mut mps = vec![];
            for i in 0..2 * BATCH_SIZE + 4 {
                let (item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();

                let addition_record: AdditionRecord =
                    commit(item, sender_randomness, receiver_preimage.hash::<Hash>());
                let mp = accumulator
                    .prove(item, sender_randomness, receiver_preimage)
                    .await;

                // Update all removal records from addition, then add the element
                RemovalRecord::batch_update_from_addition(
                    &mut removal_records
                        .iter_mut()
                        .map(|x| &mut x.1)
                        .collect::<Vec<_>>(),
                    &mut accumulator.kernel,
                )
                .await;
                let update_res_mp = MsMembershipProof::batch_update_from_addition(
                    &mut mps.iter_mut().collect::<Vec<_>>(),
                    &items,
                    &accumulator.kernel,
                    &addition_record,
                )
                .await;
                assert!(
                    update_res_mp.is_ok(),
                    "batch update must return OK, i = {}",
                    i
                );
                accumulator.add(&addition_record).await;
                mps.push(mp.clone());
                items.push(item);

                for removal_record in removal_records.iter().map(|x| &x.1) {
                    assert!(
                        removal_record.validate(&accumulator.kernel).await,
                        "removal records must validate, i = {}",
                        i
                    );
                    assert!(
                        accumulator.kernel.can_remove(removal_record).await,
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
            assert!(
                accumulator
                    .verify(items[*chosen_index], &mps[*chosen_index])
                    .await
            );
            assert!(
                accumulator.kernel.can_remove(random_removal_record).await,
                "removal records must return true on `can_remove`",
            );
            assert!(
                random_removal_record.validate(&accumulator.kernel).await,
                "removal record must have valid MMR MPs"
            );
            accumulator.remove(random_removal_record).await;
            assert!(
                !accumulator
                    .verify(items[*chosen_index], &mps[*chosen_index])
                    .await
            );

            assert!(
                !accumulator.kernel.can_remove(random_removal_record).await,
                "removal records must return false on `can_remove` after removal",
            );
        }
    }

    #[tokio::test]
    async fn batch_update_from_addition_and_remove_pbt() {
        // Verify that a single element can be added to and removed from the mutator set

        let mut accumulator: MutatorSetAccumulator = MutatorSetAccumulator::default();

        let mut removal_records: Vec<(usize, RemovalRecord)> = vec![];
        let mut original_first_removal_record = None;
        let mut items = vec![];
        let mut mps = vec![];
        for i in 0..12 * BATCH_SIZE + 4 {
            let (item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();

            let addition_record: AdditionRecord =
                commit(item, sender_randomness, receiver_preimage.hash::<Hash>());
            let mp = accumulator
                .prove(item, sender_randomness, receiver_preimage)
                .await;

            // Update all removal records from addition, then add the element
            RemovalRecord::batch_update_from_addition(
                &mut removal_records
                    .iter_mut()
                    .map(|x| &mut x.1)
                    .collect::<Vec<_>>(),
                &mut accumulator.kernel,
            )
            .await;
            let update_res_mp = MsMembershipProof::batch_update_from_addition(
                &mut mps.iter_mut().collect::<Vec<_>>(),
                &items,
                &accumulator.kernel,
                &addition_record,
            )
            .await;
            assert!(
                update_res_mp.is_ok(),
                "batch update must return OK, i = {}",
                i
            );
            accumulator.add(&addition_record).await;
            mps.push(mp.clone());
            items.push(item);

            for removal_record in removal_records.iter().map(|x| &x.1) {
                assert!(
                    removal_record.validate(&accumulator.kernel).await,
                    "removal records must validate, i = {}",
                    i
                );
                assert!(
                    accumulator.kernel.can_remove(removal_record).await,
                    "removal records must return true on `can_remove`, i = {}",
                    i
                );
            }

            let rr = accumulator.drop(item, &mp);
            if original_first_removal_record.is_none() {
                original_first_removal_record = Some(rr.clone());
            };

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

            accumulator.remove(&random_removal_record).await;

            for removal_record in removal_records.iter().map(|x| &x.1) {
                assert!(
                    removal_record.validate(&accumulator.kernel).await,
                    "removal records must validate, i = {}",
                    i
                );
                assert!(accumulator.kernel.can_remove(removal_record).await);
            }
        }

        // Verify that the original removal record is no longer valid since its
        // MMR MPs are deprecated
        assert!(
            original_first_removal_record
                .as_ref()
                .unwrap()
                .validate(&accumulator.kernel)
                .await
        );
        assert!(
            !accumulator
                .kernel
                .can_remove(&original_first_removal_record.unwrap())
                .await
        );
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
