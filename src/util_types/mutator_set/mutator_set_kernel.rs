use crate::prelude::twenty_first;

use get_size::GetSize;
use itertools::Itertools;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::{error::Error, fmt};
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::shared_math::bfield_codec::BFieldCodec;
use twenty_first::shared_math::tip5::{Digest, DIGEST_LENGTH};
use twenty_first::util_types::algebraic_hasher::{AlgebraicHasher, SpongeHasher};
use twenty_first::util_types::mmr;
use twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
use twenty_first::util_types::mmr::mmr_trait::Mmr;

use super::active_window::ActiveWindow;
use super::addition_record::AdditionRecord;
use super::chunk::Chunk;
use super::chunk_dictionary::ChunkDictionary;
use super::ms_membership_proof::MsMembershipProof;
use super::removal_record::AbsoluteIndexSet;
use super::removal_record::RemovalRecord;
use super::shared::{indices_to_hash_map, BATCH_SIZE, CHUNK_SIZE, NUM_TRIALS, WINDOW_SIZE};

impl Error for MutatorSetKernelError {}

impl fmt::Display for MutatorSetKernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum MutatorSetKernelError {
    RequestedAoclAuthPathOutOfBounds((u64, u64)),
    RequestedSwbfAuthPathOutOfBounds((u64, u64)),
    MutatorSetIsEmpty,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, GetSize)]
pub struct MutatorSetKernel<H: AlgebraicHasher + BFieldCodec, MMR: Mmr<H>> {
    pub aocl: MMR,
    pub swbf_inactive: MMR,
    pub swbf_active: ActiveWindow<H>,
}

// FIXME: Apply over-sampling to circumvent risk of duplicates.
pub fn get_swbf_indices<H: AlgebraicHasher>(
    item: Digest,
    sender_randomness: Digest,
    receiver_preimage: Digest,
    aocl_leaf_index: u64,
) -> [u128; NUM_TRIALS as usize] {
    let batch_index: u128 = aocl_leaf_index as u128 / BATCH_SIZE as u128;
    let batch_offset: u128 = batch_index * CHUNK_SIZE as u128;
    let leaf_index_bfes = aocl_leaf_index.encode();
    let input = [
        item.encode(),
        sender_randomness.encode(),
        receiver_preimage.encode(),
        leaf_index_bfes,
        // Pad according to spec
        vec![
            BFieldElement::one(),
            BFieldElement::zero(),
            BFieldElement::zero(),
        ],
    ]
    .concat();
    assert_eq!(
        input.len() % DIGEST_LENGTH,
        0,
        "Input to sponge must be a multiple digest length"
    );

    let mut sponge = <H as SpongeHasher>::init();
    H::absorb_repeatedly(&mut sponge, input.iter());
    H::sample_indices(&mut sponge, WINDOW_SIZE, NUM_TRIALS as usize)
        .into_iter()
        .map(|sample_index| sample_index as u128 + batch_offset)
        .collect_vec()
        .try_into()
        .unwrap()
}

impl<H: AlgebraicHasher + BFieldCodec, M: Mmr<H>> MutatorSetKernel<H, M> {
    /// Generates a removal record with which to update the set commitment.
    pub fn drop(&self, item: Digest, membership_proof: &MsMembershipProof<H>) -> RemovalRecord<H> {
        let indices: AbsoluteIndexSet = AbsoluteIndexSet::new(&get_swbf_indices::<H>(
            item,
            membership_proof.sender_randomness,
            membership_proof.receiver_preimage,
            membership_proof.auth_path_aocl.leaf_index,
        ));

        RemovalRecord {
            absolute_indices: indices,
            target_chunks: membership_proof.target_chunks.clone(),
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

    /// Return the batch index for the latest addition to the mutator set
    pub fn get_batch_index(&self) -> u64 {
        match self.aocl.count_leaves() {
            0 => 0,
            n => (n - 1) / BATCH_SIZE as u64,
        }
    }

    /// Helper function. Like `add` but also returns the chunk that
    /// was added to the inactive SWBF if the window slid (and None
    /// otherwise) since this is needed by the archival version of
    /// the mutator set.
    pub fn add_helper(&mut self, addition_record: &AdditionRecord) -> Option<(u64, Chunk)> {
        // Notice that `add` cannot return a membership proof since `add` cannot know the
        // randomness that was used to create the commitment. This randomness can only be know
        // by the sender and/or receiver of the UTXO. And `add` must be run be all nodes keeping
        // track of the mutator set.

        // add to list
        let item_index = self.aocl.count_leaves();
        self.aocl
            .append(addition_record.canonical_commitment.to_owned()); // ignore auth path

        if !Self::window_slides(item_index) {
            return None;
        }

        // if window slides, update filter
        // First update the inactive part of the SWBF, the SWBF MMR
        let chunk: Chunk = self.swbf_active.slid_chunk();
        let chunk_digest: Digest = H::hash(&chunk);
        self.swbf_inactive.append(chunk_digest); // ignore auth path

        // Then move window to the right, equivalent to moving values
        // inside window to the left.
        self.swbf_active.slide_window();

        let chunk_index_for_inserted_chunk = self.swbf_inactive.count_leaves() - 1;

        // Return the chunk that was added to the inactive part of the SWBF.
        // This chunk is needed by the Archival mutator set. The Regular
        // mutator set can ignore it.
        Some((chunk_index_for_inserted_chunk, chunk))
    }

    /// Remove a record and return the chunks that have been updated in this process,
    /// after applying the update. Does not mutate the removal record.
    pub fn remove_helper(&mut self, removal_record: &RemovalRecord<H>) -> HashMap<u64, Chunk> {
        let batch_index = self.get_batch_index();
        let active_window_start = batch_index as u128 * CHUNK_SIZE as u128;

        // insert all indices
        let mut new_target_chunks: ChunkDictionary<H> = removal_record.target_chunks.clone();
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
            let relevant_chunk = new_target_chunks.dictionary.get_mut(&chunk_index).unwrap();
            for index in indices {
                let relative_index = (index % CHUNK_SIZE as u128) as u32;
                relevant_chunk.1.insert(relative_index);
            }
        }

        // update mmr
        // to do this, we need to keep track of all membership proofs
        let all_mmr_membership_proofs = new_target_chunks
            .dictionary
            .values()
            .map(|(p, _c)| p.to_owned());
        let all_leafs = new_target_chunks
            .dictionary
            .values()
            .map(|(_p, chunk)| H::hash(chunk));
        let mutation_data: Vec<(MmrMembershipProof<H>, Digest)> =
            all_mmr_membership_proofs.zip(all_leafs).collect();

        // If we want to update the membership proof with this removal, we
        // could use the below function.
        self.swbf_inactive
            .batch_mutate_leaf_and_update_mps(&mut [], mutation_data);

        new_target_chunks
            .dictionary
            .into_iter()
            .map(|(chunk_index, (_mp, chunk))| (chunk_index, chunk))
            .collect()
    }

    /// Generates a membership proof that will the valid when the item
    /// is added to the mutator set.
    pub fn prove(
        &self,
        item: Digest,
        sender_randomness: Digest,
        receiver_preimage: Digest,
    ) -> MsMembershipProof<H> {
        // compute commitment
        let item_commitment = H::hash_pair(item, sender_randomness);

        // simulate adding to commitment list
        let auth_path_aocl = self.aocl.to_accumulator().append(item_commitment);
        let target_chunks: ChunkDictionary<H> = ChunkDictionary::default();

        // return membership proof
        MsMembershipProof {
            sender_randomness: sender_randomness.to_owned(),
            receiver_preimage: receiver_preimage.to_owned(),
            auth_path_aocl,
            target_chunks,
        }
    }

    pub fn verify(&self, item: Digest, membership_proof: &MsMembershipProof<H>) -> bool {
        // If data index does not exist in AOCL, return false
        // This also ensures that no "future" indices will be
        // returned from `get_indices`, so we don't have to check for
        // future indices in a separate check.
        if self.aocl.count_leaves() <= membership_proof.auth_path_aocl.leaf_index {
            return false;
        }

        // verify that a commitment to the item lives in the aocl mmr
        let leaf = H::hash_pair(
            H::hash_pair(item, membership_proof.sender_randomness),
            H::hash_pair(
                membership_proof.receiver_preimage,
                Digest::new([BFieldElement::zero(); DIGEST_LENGTH]),
            ),
        );
        let (is_aocl_member, _) = membership_proof.auth_path_aocl.verify(
            &self.aocl.get_peaks(),
            leaf,
            self.aocl.count_leaves(),
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

        // Get all bloom filter indices
        let all_indices = AbsoluteIndexSet::new(&get_swbf_indices::<H>(
            item,
            membership_proof.sender_randomness,
            membership_proof.receiver_preimage,
            membership_proof.auth_path_aocl.leaf_index,
        ));

        let chunkidx_to_indices_dict = indices_to_hash_map(&all_indices.to_array());
        'outer: for (chunk_index, indices) in chunkidx_to_indices_dict.into_iter() {
            if chunk_index < current_batch_index {
                // verify mmr auth path
                if !membership_proof
                    .target_chunks
                    .dictionary
                    .contains_key(&chunk_index)
                {
                    entries_in_dictionary = false;
                    break 'outer;
                }

                let mp_and_chunk: &(mmr::mmr_membership_proof::MmrMembershipProof<H>, Chunk) =
                    membership_proof
                        .target_chunks
                        .dictionary
                        .get(&chunk_index)
                        .unwrap();
                let (valid_auth_path, _) = mp_and_chunk.0.verify(
                    &self.swbf_inactive.get_peaks(),
                    H::hash(&mp_and_chunk.1),
                    self.swbf_inactive.count_leaves(),
                );

                all_auth_paths_are_valid = all_auth_paths_are_valid && valid_auth_path;

                'inner_inactive: for index in indices {
                    let index_within_chunk = index % CHUNK_SIZE as u128;
                    if !mp_and_chunk.1.contains(index_within_chunk as u32) {
                        has_absent_index = true;
                        break 'inner_inactive;
                    }
                }
            } else {
                // indices are in active window
                'inner_active: for index in indices {
                    let relative_index = index - window_start;
                    if !self.swbf_active.contains(relative_index as u32) {
                        has_absent_index = true;
                        break 'inner_active;
                    }
                }
            }
        }

        // return verdict
        is_aocl_member && entries_in_dictionary && all_auth_paths_are_valid && has_absent_index
    }

    /// Apply a bunch of removal records. Return a hashmap of
    /// { chunk index => updated_chunk }.
    pub fn batch_remove(
        &mut self,
        mut removal_records: Vec<RemovalRecord<H>>,
        preserved_membership_proofs: &mut [&mut MsMembershipProof<H>],
    ) -> HashMap<u64, Chunk> {
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
        let mut mutation_data_preimage: HashMap<u64, (&mut Chunk, MmrMembershipProof<H>)> =
            HashMap::new();
        for removal_record in removal_records.iter_mut() {
            for (chunk_index, (mmr_mp, chunk)) in removal_record.target_chunks.dictionary.iter_mut()
            {
                let chunk_hash = H::hash(chunk);
                let prev_val =
                    mutation_data_preimage.insert(*chunk_index, (chunk, mmr_mp.to_owned()));

                // Sanity check that all removal records agree on both chunks and MMR membership
                // proofs.
                if let Some((chnk, mm)) = prev_val {
                    assert!(mm == *mmr_mp && chunk_hash == H::hash(chnk))
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
            for (chunk_index, (_, chunk)) in mp.target_chunks.dictionary.iter_mut() {
                if mutation_data_preimage.contains_key(chunk_index) {
                    *chunk = mutation_data_preimage[chunk_index].0.to_owned();
                }
            }
        }

        // Calculate the digests of the affected leafs in the inactive part of the sliding-window
        // Bloom filter such that we can apply a batch-update operation to the MMR through which
        // this part of the Bloom filter is represented.
        let swbf_inactive_mutation_data: Vec<(MmrMembershipProof<H>, Digest)> =
            mutation_data_preimage
                .into_values()
                .map(|x| (x.1, H::hash(x.0)))
                .collect();

        // Create a vector of pointers to the MMR-membership part of the mutator set membership
        // proofs that we want to preserve. This is used as input to a batch-call to the
        // underlying MMR.
        let mut preseved_mmr_membership_proofs: Vec<&mut MmrMembershipProof<H>> =
            preserved_membership_proofs
                .iter_mut()
                .flat_map(|x| {
                    x.target_chunks
                        .dictionary
                        .iter_mut()
                        .map(|y| &mut y.1 .0)
                        .collect::<Vec<_>>()
                })
                .collect();

        // Apply the batch-update to the inactive part of the sliding window Bloom filter.
        // This updates both the inactive part of the SWBF and the MMR membership proofs
        self.swbf_inactive.batch_mutate_leaf_and_update_mps(
            &mut preseved_mmr_membership_proofs,
            swbf_inactive_mutation_data,
        );

        chunkidx_to_chunk_difference_dict
    }

    /// Check if a removal record can be applied to a mutator set. Returns false if either
    /// the MMR membership proofs are unsynced, or if all its indices are already set.
    pub fn can_remove(&self, removal_record: &RemovalRecord<H>) -> bool {
        let mut have_absent_index = false;
        if !removal_record.validate(self) {
            return false;
        }

        for inserted_index in removal_record.absolute_indices.to_vec().into_iter() {
            // determine if inserted index lives in active window
            let active_window_start =
                (self.aocl.count_leaves() / BATCH_SIZE as u64) as u128 * CHUNK_SIZE as u128;
            if inserted_index < active_window_start {
                let inserted_index_chunkidx = (inserted_index / CHUNK_SIZE as u128) as u64;
                if let Some((_mmr_mp, chunk)) = removal_record
                    .target_chunks
                    .dictionary
                    .get(&inserted_index_chunkidx)
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

impl<H: AlgebraicHasher + BFieldCodec, MMR: Mmr<H> + BFieldCodec> BFieldCodec
    for MutatorSetKernel<H, MMR>
{
    type Error = anyhow::Error;
    fn decode(sequence: &[BFieldElement]) -> anyhow::Result<Box<Self>> {
        let mut index = 0;
        let aocl_len: usize = match sequence.first() {
            Some(aocl_len) => aocl_len.value().try_into()?,
            None => anyhow::bail!("Invalid sequence length for decoding MutatorSetKernel."),
        };
        index += 1;
        let aocl = match MMR::decode(&sequence[index..(index + aocl_len)]) {
            Ok(decoded) => *decoded,
            Err(err) => anyhow::bail!("Failed to decode AOCL-MMR. Error was: {err}"),
        };
        index += aocl_len;

        let swbf_inactive_len: usize = match sequence.get(index) {
            Some(swbf_inactive_len) => swbf_inactive_len.value().try_into()?,
            None => anyhow::bail!("Invalid sequence length for decoding MutatorSetKernel."),
        };
        index += 1;
        let swbf_inactive = match MMR::decode(&sequence[index..(index + swbf_inactive_len)]) {
            Ok(decoded) => *decoded,
            Err(err) => anyhow::bail!("Failed to decode SWBF-MMR. Error was: {err}"),
        };
        index += swbf_inactive_len;

        let swbf_active_len: usize = match sequence.get(index) {
            Some(swbf_active_len) => swbf_active_len.value().try_into()?,
            None => anyhow::bail!("Invalid sequence length for decoding MutatorSetKernel."),
        };
        index += 1;
        let swbf_active = *ActiveWindow::decode(&sequence[index..(index + swbf_active_len)])?;
        index += swbf_active_len;

        if sequence.len() != index {
            anyhow::bail!("Invalid sequence length for decoding MutatorSetKernel.");
        }

        Ok(Box::new(Self {
            aocl,
            swbf_inactive,
            swbf_active,
        }))
    }

    fn encode(&self) -> Vec<BFieldElement> {
        let aocl_encoded = self.aocl.encode();
        let aocl_len = BFieldElement::new(aocl_encoded.len() as u64);

        let swbf_inactive_encoded = self.swbf_inactive.encode();
        let swbf_inactive_len = BFieldElement::new(swbf_inactive_encoded.len() as u64);

        let swbf_active_encoded = self.swbf_active.encode();
        let swbf_active_len = BFieldElement::new(swbf_active_encoded.len() as u64);
        [
            vec![aocl_len],
            aocl_encoded,
            vec![swbf_inactive_len],
            swbf_inactive_encoded,
            vec![swbf_active_len],
            swbf_active_encoded,
        ]
        .concat()
    }

    fn static_length() -> Option<usize> {
        None
    }
}

#[cfg(test)]
mod accumulation_scheme_tests {
    use rand::prelude::*;
    use rand::Rng;

    use twenty_first::shared_math::tip5::Tip5;
    use twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

    use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
    use crate::util_types::mutator_set::mutator_set_trait::commit;
    use crate::util_types::mutator_set::mutator_set_trait::MutatorSet;
    use crate::util_types::test_shared::mutator_set::*;

    use super::*;

    #[test]
    fn get_batch_index_test() {
        // Verify that the method to get batch index returns sane results
        type H = Tip5;
        let mut mutator_set = MutatorSetAccumulator::<H>::default();
        assert_eq!(
            0,
            mutator_set.kernel.get_batch_index(),
            "Batch index for empty MS must be zero"
        );

        for i in 0..BATCH_SIZE {
            let (item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();
            let addition_record =
                commit::<H>(item, sender_randomness, receiver_preimage.hash::<H>());
            mutator_set.add(&addition_record);
            assert_eq!(
                0,
                mutator_set.kernel.get_batch_index(),
                "Batch index must be 0 after adding {} elements",
                i
            );
        }

        let (item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();
        let addition_record = commit::<H>(item, sender_randomness, receiver_preimage.hash::<H>());
        mutator_set.add(&addition_record);
        assert_eq!(
            1,
            mutator_set.kernel.get_batch_index(),
            "Batch index must be one after adding BATCH_SIZE+1 elements"
        );
    }

    #[test]
    fn mutator_set_hash_test() {
        type H = Tip5;

        let empty_set = MutatorSetAccumulator::<H>::default();
        let empty_hash = empty_set.hash();

        // Add one element to append-only commitment list
        let mut set_with_aocl_append = MutatorSetAccumulator::<H>::default();

        let (item0, _sender_randomness, _receiver_preimage) = make_item_and_randomnesses();

        set_with_aocl_append.kernel.aocl.append(item0);
        let hash_of_aocl_append = set_with_aocl_append.hash();

        assert_ne!(
            empty_hash, hash_of_aocl_append,
            "Appending to AOCL must change MutatorSet commitment"
        );

        // Manipulate inactive SWBF
        let mut set_with_swbf_inactive_append = MutatorSetAccumulator::<H>::default();
        set_with_swbf_inactive_append
            .kernel
            .swbf_inactive
            .append(item0);
        let hash_of_one_in_inactive = set_with_swbf_inactive_append.hash();
        assert_ne!(
            empty_hash, hash_of_one_in_inactive,
            "Changing inactive must change MS hash"
        );
        assert_ne!(
            hash_of_aocl_append, hash_of_one_in_inactive,
            "One in AOCL and one in inactive must hash to different digests"
        );

        // Manipulate active window
        let mut active_window_changed = empty_set;
        active_window_changed.kernel.swbf_active.insert(42);
        assert_ne!(
            empty_hash,
            active_window_changed.hash(),
            "Changing active window must change commitment"
        );

        // Sanity check bc reasons
        active_window_changed.kernel.swbf_active.remove(42);
        assert_eq!(
            empty_hash,
            active_window_changed.hash(),
            "Commitment to empty MS must be consistent"
        );
    }

    #[test]
    fn ms_get_indices_test() {
        // Test that `get_indices` behaves as expected, i.e.
        // that it always returns something of length `NUM_TRIALS`, and that the
        // returned values are in the expected range.
        type H = Tip5;

        let (item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();
        let ret: [u128; NUM_TRIALS as usize] =
            get_swbf_indices::<H>(item, sender_randomness, receiver_preimage, 0);
        assert_eq!(NUM_TRIALS as usize, ret.len());
        assert!(ret.iter().all(|&x| x < WINDOW_SIZE as u128));
    }

    #[test]
    fn ms_get_indices_test_big() {
        // Test that `get_indices` behaves as expected. I.e. that it returns indices in the correct range,
        // and always returns something of length `NUM_TRIALS`.
        type H = Tip5;
        for _ in 0..1000 {
            let (item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();
            let ret: [u128; NUM_TRIALS as usize] =
                get_swbf_indices::<H>(item, sender_randomness, receiver_preimage, 0);
            assert_eq!(NUM_TRIALS as usize, ret.len());
            assert!(ret.iter().all(|&x| x < WINDOW_SIZE as u128));
        }

        for _ in 0..1000 {
            let (item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();
            let ret: [u128; NUM_TRIALS as usize] = get_swbf_indices::<H>(
                item,
                sender_randomness,
                receiver_preimage,
                (17 * BATCH_SIZE) as u64,
            );
            assert_eq!(NUM_TRIALS as usize, ret.len());
            assert!(ret
                .iter()
                .all(|&x| (x as u32) < WINDOW_SIZE + 17 * CHUNK_SIZE
                    && (x as u32) >= 17 * CHUNK_SIZE));
        }
    }

    #[test]
    fn init_test() {
        type H = Tip5;

        let accumulator = MutatorSetAccumulator::<H>::default();
        let mut rms = empty_rusty_mutator_set::<H>();
        let archival = rms.ams_mut();

        // Verify that function to get batch index does not overflow for the empty MS
        assert_eq!(
            0,
            accumulator.kernel.get_batch_index(),
            "Batch index must be zero for empty MS accumulator"
        );
        assert_eq!(
            0,
            archival.kernel.get_batch_index(),
            "Batch index must be zero for empty archival MS"
        );
    }

    #[test]
    fn verify_future_indices_test() {
        // Ensure that `verify` does not crash when given a membership proof
        // that represents a future addition to the AOCL.
        type H = Tip5;
        let mut mutator_set = MutatorSetAccumulator::<H>::default().kernel;
        let empty_mutator_set = MutatorSetAccumulator::<H>::default().kernel;

        for _ in 0..2 * BATCH_SIZE + 2 {
            let (item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();

            let addition_record: AdditionRecord =
                commit::<H>(item, sender_randomness, receiver_preimage.hash::<H>());
            let membership_proof: MsMembershipProof<H> =
                mutator_set.prove(item, sender_randomness, receiver_preimage);
            mutator_set.add_helper(&addition_record);
            assert!(mutator_set.verify(item, &membership_proof));

            // Verify that a future membership proof returns false and does not crash
            assert!(!empty_mutator_set.verify(item, &membership_proof));
        }
    }

    #[test]
    fn test_membership_proof_update_from_add() {
        type H = Tip5;

        let mut mutator_set = MutatorSetAccumulator::<H>::default();
        let (own_item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();

        let addition_record =
            commit::<H>(own_item, sender_randomness, receiver_preimage.hash::<H>());
        let mut membership_proof =
            mutator_set.prove(own_item, sender_randomness, receiver_preimage);
        mutator_set.kernel.add_helper(&addition_record);

        // Update membership proof with add operation. Verify that it has changed, and that it now fails to verify.
        let (new_item, new_sender_randomness, new_receiver_preimage) = make_item_and_randomnesses();
        let new_addition_record = commit::<H>(
            new_item,
            new_sender_randomness,
            new_receiver_preimage.hash::<H>(),
        );
        let original_membership_proof = membership_proof.clone();
        let changed_mp = match membership_proof.update_from_addition(
            own_item,
            &mutator_set,
            &new_addition_record,
        ) {
            Ok(changed) => changed,
            Err(err) => panic!("{}", err),
        };
        assert!(
            changed_mp,
            "Update must indicate that membership proof has changed"
        );
        assert_ne!(
            original_membership_proof.auth_path_aocl,
            membership_proof.auth_path_aocl
        );
        assert!(
            mutator_set.verify(own_item, &original_membership_proof),
            "Original membership proof must verify prior to addition"
        );
        assert!(
            !mutator_set.verify(own_item, &membership_proof),
            "New membership proof must fail to verify prior to addition"
        );

        // Insert the new element into the mutator set, then verify that the membership proof works and
        // that the original membership proof is invalid.
        mutator_set.kernel.add_helper(&new_addition_record);
        assert!(
            !mutator_set.verify(own_item, &original_membership_proof),
            "Original membership proof must fail to verify after addition"
        );
        assert!(
            mutator_set.verify(own_item, &membership_proof),
            "New membership proof must verify after addition"
        );
    }

    #[test]
    fn membership_proof_updating_from_add_pbt() {
        type H = Tip5;
        let mut rng = thread_rng();

        let mut mutator_set = MutatorSetAccumulator::<H>::default();

        let num_additions = rng.gen_range(0..=100i32);
        println!(
            "running multiple additions test for {} additions",
            num_additions
        );

        let mut membership_proofs_and_items: Vec<(MsMembershipProof<H>, Digest)> = vec![];
        for i in 0..num_additions {
            println!("loop iteration {}", i);

            let (item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();

            let addition_record =
                commit::<H>(item, sender_randomness, receiver_preimage.hash::<H>());
            let membership_proof = mutator_set.prove(item, sender_randomness, receiver_preimage);

            // Update all membership proofs
            for (mp, itm) in membership_proofs_and_items.iter_mut() {
                let original_mp = mp.clone();
                let changed_res = mp.update_from_addition(*itm, &mutator_set, &addition_record);
                assert!(changed_res.is_ok());

                // verify that the boolean returned value from the updater method is set correctly
                assert_eq!(changed_res.unwrap(), original_mp != *mp);
            }

            // Add the element
            assert!(!mutator_set.verify(item, &membership_proof));
            mutator_set.kernel.add_helper(&addition_record);
            assert!(mutator_set.verify(item, &membership_proof));
            membership_proofs_and_items.push((membership_proof, item));

            // Verify that all membership proofs work
            assert!(membership_proofs_and_items
                .clone()
                .into_iter()
                .all(|(mp, itm)| mutator_set.verify(itm, &mp)));
        }
    }

    #[test]
    fn test_add_and_prove() {
        type H = Tip5;

        let mut mutator_set = MutatorSetAccumulator::<H>::default();
        let (item0, sender_randomness0, receiver_preimage0) = make_item_and_randomnesses();

        let addition_record =
            commit::<H>(item0, sender_randomness0, receiver_preimage0.hash::<H>());
        let membership_proof = mutator_set.prove(item0, sender_randomness0, receiver_preimage0);

        assert!(!mutator_set.verify(item0, &membership_proof));

        mutator_set.kernel.add_helper(&addition_record);

        assert!(mutator_set.verify(item0, &membership_proof));

        // Insert a new item and verify that this still works
        let (item1, sender_randomness1, receiver_preimage1) = make_item_and_randomnesses();
        let new_ar = commit::<H>(item1, sender_randomness1, receiver_preimage1.hash::<H>());
        let new_mp = mutator_set.prove(item1, sender_randomness1, receiver_preimage1);
        assert!(!mutator_set.verify(item1, &new_mp));

        mutator_set.kernel.add_helper(&new_ar);
        assert!(mutator_set.verify(item1, &new_mp));

        // Insert ~2*BATCH_SIZE  more elements and
        // verify that it works throughout. The reason we insert this many
        // is that we want to make sure that the window slides into a new
        // position.
        for _ in 0..2 * BATCH_SIZE + 4 {
            let (item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();
            let other_ar = commit::<H>(item, sender_randomness, receiver_preimage.hash::<H>());
            let other_mp = mutator_set.prove(item, sender_randomness, receiver_preimage);
            assert!(!mutator_set.verify(item, &other_mp));

            mutator_set.kernel.add_helper(&other_ar);
            assert!(mutator_set.verify(item, &other_mp));
        }
    }

    #[test]
    fn batch_update_from_addition_and_removal_test() {
        type H = Tip5;
        let mut mutator_set = MutatorSetAccumulator::<H>::default();

        // It's important to test number of additions around the shifting of the window,
        // i.e. around batch size.
        let num_additions_list = vec![
            1,
            2,
            BATCH_SIZE - 1,
            BATCH_SIZE,
            BATCH_SIZE + 1,
            6 * BATCH_SIZE - 1,
            6 * BATCH_SIZE,
            6 * BATCH_SIZE + 1,
        ];

        let mut membership_proofs: Vec<MsMembershipProof<H>> = vec![];
        let mut items = vec![];

        for num_additions in num_additions_list {
            for _ in 0..num_additions {
                let (new_item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();

                let addition_record =
                    commit::<H>(new_item, sender_randomness, receiver_preimage.hash::<H>());
                let membership_proof =
                    mutator_set.prove(new_item, sender_randomness, receiver_preimage);

                // Update *all* membership proofs with newly added item
                let batch_update_res = MsMembershipProof::<H>::batch_update_from_addition(
                    &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                    &items,
                    &mutator_set.kernel,
                    &addition_record,
                );
                assert!(batch_update_res.is_ok());

                mutator_set.kernel.add_helper(&addition_record);
                assert!(mutator_set.verify(new_item, &membership_proof));

                for (mp, &item) in membership_proofs.iter().zip(items.iter()) {
                    assert!(mutator_set.verify(item, mp));
                }

                membership_proofs.push(membership_proof);
                items.push(new_item);
            }

            // Remove items from MS, and verify correct updating of membership proofs
            for _ in 0..num_additions {
                let item = items.pop().unwrap();
                let mp = membership_proofs.pop().unwrap();
                assert!(mutator_set.verify(item, &mp));

                // generate removal record
                let removal_record: RemovalRecord<H> = mutator_set.drop(item, &mp);
                assert!(removal_record.validate(&mutator_set.kernel));
                assert!(mutator_set.kernel.can_remove(&removal_record));

                // update membership proofs
                let res = MsMembershipProof::batch_update_from_remove(
                    &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                    &removal_record,
                );
                assert!(res.is_ok());

                // remove item from set
                mutator_set.kernel.remove_helper(&removal_record);
                assert!(!mutator_set.verify(item, &mp));

                for (&itm, membp) in items.iter().zip(membership_proofs.iter()) {
                    assert!(mutator_set.verify(itm, membp));
                }
            }
        }
    }

    #[test]
    fn test_multiple_adds() {
        type H = Tip5;

        let mut mutator_set = MutatorSetAccumulator::<H>::default();

        let num_additions = 65;

        let mut items_and_membership_proofs: Vec<(Digest, MsMembershipProof<H>)> = vec![];

        for _ in 0..num_additions {
            let (new_item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();

            let addition_record =
                commit::<H>(new_item, sender_randomness, receiver_preimage.hash::<H>());
            let membership_proof =
                mutator_set.prove(new_item, sender_randomness, receiver_preimage);

            // Update *all* membership proofs with newly added item
            for (updatee_item, mp) in items_and_membership_proofs.iter_mut() {
                let original_mp = mp.clone();
                assert!(mutator_set.verify(*updatee_item, mp));
                let changed_res =
                    mp.update_from_addition(*updatee_item, &mutator_set, &addition_record);
                assert!(changed_res.is_ok());

                // verify that the boolean returned value from the updater method is set correctly
                assert_eq!(changed_res.unwrap(), original_mp != *mp);
            }

            mutator_set.kernel.add_helper(&addition_record);
            assert!(mutator_set.verify(new_item, &membership_proof));

            (0..items_and_membership_proofs.len()).for_each(|j| {
                let (old_item, mp) = &items_and_membership_proofs[j];
                assert!(mutator_set.verify(*old_item, mp))
            });

            items_and_membership_proofs.push((new_item, membership_proof));
        }

        // Verify all membership proofs
        (0..items_and_membership_proofs.len()).for_each(|k| {
            assert!(mutator_set.verify(
                items_and_membership_proofs[k].0,
                &items_and_membership_proofs[k].1,
            ));
        });

        // Remove items from MS, and verify correct updating of membership proof
        (0..num_additions).for_each(|i| {
            (i..items_and_membership_proofs.len()).for_each(|k| {
                assert!(mutator_set.verify(
                    items_and_membership_proofs[k].0,
                    &items_and_membership_proofs[k].1,
                ));
            });
            let (item, mp) = items_and_membership_proofs[i].clone();

            assert!(mutator_set.verify(item, &mp));

            // generate removal record
            let removal_record: RemovalRecord<H> = mutator_set.drop(item, &mp);
            assert!(removal_record.validate(&mutator_set.kernel));
            assert!(mutator_set.kernel.can_remove(&removal_record));
            (i..items_and_membership_proofs.len()).for_each(|k| {
                assert!(mutator_set.verify(
                    items_and_membership_proofs[k].0,
                    &items_and_membership_proofs[k].1,
                ));
            });

            // update membership proofs
            ((i + 1)..num_additions).for_each(|j| {
                assert!(mutator_set.verify(
                    items_and_membership_proofs[j].0,
                    &items_and_membership_proofs[j].1
                ));
                let update_res = items_and_membership_proofs[j]
                    .1
                    .update_from_remove(&removal_record.clone());
                assert!(update_res.is_ok());
            });

            // remove item from set
            mutator_set.kernel.remove_helper(&removal_record);
            assert!(!mutator_set.verify(item, &mp));

            ((i + 1)..items_and_membership_proofs.len()).for_each(|k| {
                assert!(mutator_set.verify(
                    items_and_membership_proofs[k].0,
                    &items_and_membership_proofs[k].1,
                ));
            });
        });
    }

    #[test]
    fn ms_serialization_test() {
        // This test verifies that the mutator set structure can be serialized and deserialized.
        // When Rust spawns threads (as it does when it runs tests, and in the Neptune Core client),
        // the new threads only get 2MB stack memory initially. This can result in stack overflows
        // in the runtime. This test is to verify that that does not happen.
        // Cf. https://stackoverflow.com/questions/72618777/how-to-deserialize-a-nested-big-array
        // and https://stackoverflow.com/questions/72621410/how-do-i-use-serde-stacker-in-my-deserialize-implementation
        type H = Tip5;
        type Mmr = MmrAccumulator<H>;
        type Ms = MutatorSetKernel<H, Mmr>;
        let mut mutator_set: Ms = MutatorSetAccumulator::<H>::default().kernel;

        let json_empty = serde_json::to_string(&mutator_set).unwrap();
        println!("json = \n{}", json_empty);
        let s_back = serde_json::from_str::<Ms>(&json_empty).unwrap();
        assert!(s_back.aocl.is_empty());
        assert!(s_back.swbf_inactive.is_empty());
        assert!(s_back.swbf_active.sbf.is_empty());

        // Add an item, verify correct serialization
        let (mp, item) = insert_mock_item(&mut mutator_set);
        let json_one_add = serde_json::to_string(&mutator_set).unwrap();
        println!("json_one_add = \n{}", json_one_add);
        let s_back_one_add = serde_json::from_str::<Ms>(&json_one_add).unwrap();
        assert_eq!(1, s_back_one_add.aocl.count_leaves());
        assert!(s_back_one_add.swbf_inactive.is_empty());
        assert!(s_back_one_add.swbf_active.sbf.is_empty());
        assert!(s_back_one_add.verify(item, &mp));

        // Remove an item, verify correct serialization
        remove_mock_item(&mut mutator_set, item, &mp);
        let json_one_add_one_remove = serde_json::to_string(&mutator_set).unwrap();
        println!("json_one_add = \n{}", json_one_add_one_remove);
        let s_back_one_add_one_remove =
            serde_json::from_str::<Ms>(&json_one_add_one_remove).unwrap();
        assert_eq!(
            1,
            s_back_one_add_one_remove.aocl.count_leaves(),
            "AOCL must still have exactly one leaf"
        );
        assert!(
            s_back_one_add_one_remove.swbf_inactive.is_empty(),
            "Window should not have moved"
        );
        assert!(
            !s_back_one_add_one_remove.swbf_active.sbf.is_empty(),
            "Some of the indices in the active window must now be set"
        );
        assert!(
            !s_back_one_add_one_remove.verify(item, &mp),
            "Membership proof must fail after removal"
        );
    }
}
