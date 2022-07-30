use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    ops::IndexMut,
};

use crate::util_types::mutator_set::{
    chunk::Chunk, set_commitment::get_swbf_indices, shared::BATCH_SIZE,
};
use twenty_first::{
    shared_math::b_field_element::BFieldElement,
    util_types::{
        mmr::{self, mmr_accumulator::MmrAccumulator, mmr_trait::Mmr},
        simple_hasher::{self, ToDigest},
    },
};

use super::{
    addition_record::AdditionRecord,
    chunk_dictionary::ChunkDictionary,
    removal_record::RemovalRecord,
    set_commitment::SetCommitment,
    shared::{CHUNK_SIZE, NUM_TRIALS},
    transfer_ms_membership_proof::TransferMsMembershipProof,
};

impl Error for MembershipProofError {}

impl fmt::Display for MembershipProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum MembershipProofError {
    AlreadyExistingChunk(u128),
    MissingChunkOnUpdateFromAdd(u128),
    MissingChunkOnUpdateFromRemove(u128),
}

// This struct should not be serializable, as it, due to the `cached_bits` field
// should not be shared between peers.
#[derive(Debug, Clone)]
pub struct MsMembershipProof<H: simple_hasher::Hasher> {
    pub randomness: H::Digest,
    pub auth_path_aocl: mmr::mmr_membership_proof::MmrMembershipProof<H>,
    pub target_chunks: ChunkDictionary<H>,

    // Cached bits are optional to store, but will prevent a lot of hashing in
    // later bookkeeping, such as updating the membership proof.
    // Warning: These bits should not be trusted and should only be calculated
    // locally. If they are trusted the soundness of the mutator set is compromised.
    pub cached_bits: Option<[u128; NUM_TRIALS]>,
}

/// Convert a transfer version of the membership proof to one for internal use.
/// The important thing here is that `cached_bits` is not shared between peers.
impl<H: simple_hasher::Hasher> From<TransferMsMembershipProof<H>> for MsMembershipProof<H> {
    fn from(transfer: TransferMsMembershipProof<H>) -> Self {
        Self {
            randomness: transfer.randomness,
            auth_path_aocl: transfer.auth_path_aocl,
            target_chunks: transfer.target_chunks,
            cached_bits: None,
        }
    }
}

// This conversion is kept here to avoid circular dependencies -- not sure if we have
// to avoid that, though.
impl<H: simple_hasher::Hasher> From<MsMembershipProof<H>> for TransferMsMembershipProof<H> {
    fn from(mp: MsMembershipProof<H>) -> Self {
        Self {
            randomness: mp.randomness,
            auth_path_aocl: mp.auth_path_aocl,
            target_chunks: mp.target_chunks,
        }
    }
}

impl<H: simple_hasher::Hasher> PartialEq for MsMembershipProof<H> {
    // Equality for a membership proof does not look at cached bits, as they are just cached data
    // Whether they are set or not, does not change the membership proof.
    fn eq(&self, other: &Self) -> bool {
        self.randomness == other.randomness
            && self.auth_path_aocl == other.auth_path_aocl
            && self.target_chunks == other.target_chunks
    }
}

impl<H> MsMembershipProof<H>
where
    u128: ToDigest<<H as simple_hasher::Hasher>::Digest>,
    Vec<BFieldElement>: ToDigest<<H as simple_hasher::Hasher>::Digest>,
    H: simple_hasher::Hasher,
{
    /// Get an argument to the MMR `batch_update_from_batch_leaf_mutation`,
    /// and mutate the chunk dictionary chunk values.
    /// This function is factored out because it is shared by `update_from_remove`
    /// and `batch_update_from_remove`.
    #[allow(clippy::type_complexity)]
    fn get_batch_mutation_argument_for_removal_record(
        removal_record: &RemovalRecord<H>,
        chunk_dictionaries: &mut [&mut ChunkDictionary<H>],
    ) -> (
        HashSet<usize>,
        Vec<(mmr::mmr_membership_proof::MmrMembershipProof<H>, H::Digest)>,
    ) {
        let hasher = H::new();
        let mut mutation_argument_hash_map: HashMap<
            u128,
            (mmr::mmr_membership_proof::MmrMembershipProof<H>, H::Digest),
        > = HashMap::new();
        let rem_record_chunk_idx_to_bit_indices: HashMap<u128, Vec<u128>> =
            removal_record.get_chunk_index_to_bit_indices();

        let mut mutated_chunks_by_input_indices: HashSet<usize> = HashSet::new();
        for (chunk_index, bit_indices) in rem_record_chunk_idx_to_bit_indices.iter() {
            for (i, chunk_dictionary) in chunk_dictionaries.iter_mut().enumerate() {
                match chunk_dictionary.dictionary.get_mut(chunk_index) {
                    // Leaf exists in own membership proof
                    Some((mp, chnk)) => {
                        for bit_index in bit_indices.iter() {
                            let index = (bit_index % CHUNK_SIZE as u128) as usize;
                            if !chnk.get_bit(index) {
                                mutated_chunks_by_input_indices.insert(i);
                            }
                            chnk.set_bit(index);
                        }

                        // If this leaf/membership proof pair has not already been collected,
                        // then store it as a mutation argument. This assumes that all membership
                        // proofs in all chunk dictionaries are valid.
                        if !mutation_argument_hash_map.contains_key(chunk_index) {
                            mutation_argument_hash_map
                                .insert(*chunk_index, (mp.to_owned(), chnk.hash::<H>(&hasher)));
                        }
                    }

                    // Leaf does not exists in own membership proof, so we get it from the removal record
                    None => {
                        match removal_record.target_chunks.dictionary.get(chunk_index) {
                            None => {
                                // This should mean that bit index is in the active part of the
                                // SWBF. But we have no way of checking that AFAIK. So we just continue.
                                continue;
                            }
                            Some((mp, chnk)) => {
                                let mut target_chunk = chnk.to_owned();
                                for bit_index in bit_indices.iter() {
                                    target_chunk.set_bit((bit_index % CHUNK_SIZE as u128) as usize);
                                }

                                if !mutation_argument_hash_map.contains_key(chunk_index) {
                                    mutation_argument_hash_map.insert(
                                        *chunk_index,
                                        (mp.to_owned(), target_chunk.hash::<H>(&hasher)),
                                    );
                                }
                            }
                        };
                    }
                };
            }
        }

        (
            mutated_chunks_by_input_indices,
            mutation_argument_hash_map.into_values().collect(),
        )
    }

    /// Helper function to cache the bits so they don't have to be recalculated multiple times
    pub fn cache_indices(&mut self, item: &H::Digest) {
        let hasher = H::new();
        let bits = get_swbf_indices(
            &hasher,
            item,
            &self.randomness,
            self.auth_path_aocl.data_index,
        );

        self.cached_bits = Some(bits);
    }

    pub fn batch_update_from_addition<MMR: Mmr<H>>(
        membership_proofs: &mut [&mut Self],
        own_items: &[H::Digest],
        mutator_set: &mut SetCommitment<H, MMR>,
        addition_record: &AdditionRecord<H>,
    ) -> Result<Vec<usize>, Box<dyn Error>> {
        assert!(
            membership_proofs
                .iter()
                .all(|mp| mp.auth_path_aocl.data_index < mutator_set.aocl.count_leaves()),
            "No AOCL data index can point outside of provided mutator set"
        );
        assert_eq!(
            membership_proofs.len(),
            own_items.len(),
            "Function must be called with same number of membership proofs and items"
        );

        let new_item_index = mutator_set.aocl.count_leaves();

        // Update AOCL MMR membership proofs
        let indices_for_updated_mps =
            mmr::mmr_membership_proof::MmrMembershipProof::batch_update_from_append(
                &mut membership_proofs
                    .iter_mut()
                    .map(|x| &mut x.auth_path_aocl)
                    .collect::<Vec<_>>(),
                new_item_index,
                &addition_record.commitment,
                &mutator_set.aocl.get_peaks(),
            );

        // if window does not slide, we are done
        if !SetCommitment::<H, MMR>::window_slides(new_item_index) {
            return Ok(indices_for_updated_mps);
        }

        // window does slide
        let batch_index = new_item_index / BATCH_SIZE as u128;
        let old_window_start_batch_index = batch_index - 1;
        let new_chunk = Chunk {
            bits: mutator_set.swbf_active.get_sliding_chunk_bits(),
        };
        let hasher = H::new();
        let new_chunk_digest: H::Digest = new_chunk.hash::<H>(&hasher);

        // Insert the new chunk digest into the accumulator-version of the
        // SWBF MMR to get its authentication path. It's important to convert the MMR
        // to an MMR Accumulator here, since we don't want to drag around or clone
        // a whole archival MMR for this operation, as the archival MMR can be in the
        // size of gigabytes, whereas the MMR accumulator should be in the size of
        // kilobytes.
        let mut mmra: MmrAccumulator<H> = mutator_set.swbf_inactive.to_accumulator();
        let new_swbf_auth_path: mmr::mmr_membership_proof::MmrMembershipProof<H> =
            mmra.append(new_chunk_digest.clone());

        // Collect all bit indices for all membership proofs that are being updated
        // Notice that this is a *very* expensive operation if the bit indices are
        // not already known. I.e., the `None` case below is very expensive.
        let mut chunk_index_to_mp_index: HashMap<u128, Vec<usize>> = HashMap::new();
        membership_proofs
            .iter()
            .zip(own_items.iter())
            .enumerate()
            .for_each(|(i, (mp, item))| {
                let bits = match mp.cached_bits {
                    Some(bs) => bs,
                    None => get_swbf_indices(
                        &hasher,
                        item,
                        &mp.randomness,
                        mp.auth_path_aocl.data_index,
                    ),
                };
                let chunks_set: HashSet<u128> =
                    bits.iter().map(|x| x / CHUNK_SIZE as u128).collect();
                chunks_set.iter().for_each(|chnkidx| {
                    chunk_index_to_mp_index
                        .entry(*chnkidx)
                        .or_insert_with(Vec::new)
                        .push(i)
                });
            });

        // Find the membership proofs that need a new dictionary entry for the chunk that's being
        // added to the inactive part by this addition.
        let mps_for_new_chunk_dictionary_entry: Vec<usize> =
            match chunk_index_to_mp_index.get(&old_window_start_batch_index) {
                Some(vals) => vals.clone(),
                None => vec![],
            };

        // Find the membership proofs that have dictionary entry MMR membership proofs that need
        // to be updated because of the window sliding. We just
        let mut mps_for_batch_append: HashSet<usize> = HashSet::new();
        for (chunk_index, mp_indices) in chunk_index_to_mp_index.into_iter() {
            if chunk_index < old_window_start_batch_index {
                for mp_index in mp_indices {
                    mps_for_batch_append.insert(mp_index);
                }
            }
        }

        // Perform the updates

        // First insert the new entry into the chunk dictionary for the membership
        // proofs that need it.
        for i in mps_for_new_chunk_dictionary_entry.clone() {
            membership_proofs
                .index_mut(i)
                .target_chunks
                .dictionary
                .insert(
                    old_window_start_batch_index,
                    (new_swbf_auth_path.clone(), new_chunk),
                );
        }

        // Collect those MMR membership proofs for chunks whose authentication
        // path might need to be updated due to the insertion of a new leaf in the
        // SWBF MMR.
        // This is a bit ugly and a bit slower than it could be. To prevent this
        // for-loop, you probably could collect the `Vec<&mut mp>` in the code above,
        // instead of just collecting the indices into the membership proof vector.
        // It is, however, quite acceptable that many of the MMR membership proofs are
        // repeated since the MMR `batch_update_from_append` handles this optimally.
        // So relegating that bookkeeping to this function instead would not be more
        // efficient.
        let mut mmr_membership_proofs_for_append: Vec<
            &mut mmr::mmr_membership_proof::MmrMembershipProof<H>,
        > = vec![];

        // The `mmr_membership_proof_index_to_membership_proof_index` variable is to remember
        // which parts of the MMR membership proofs that map to MS membership proofs. This is
        // required to return the indices of the MS membership proofs that have been updated
        // by this function call.
        let mut mmr_membership_proof_index_to_membership_proof_index: Vec<usize> = vec![];
        for (i, mp) in membership_proofs.iter_mut().enumerate() {
            if mps_for_batch_append.contains(&i) {
                for (_, (mmr_mp, _chnk)) in mp.target_chunks.dictionary.iter_mut() {
                    mmr_membership_proofs_for_append.push(mmr_mp);
                    mmr_membership_proof_index_to_membership_proof_index.push(i);
                }
            }
        }

        let indices_for_mutated_values =
            mmr::mmr_membership_proof::MmrMembershipProof::<H>::batch_update_from_append(
                &mut mmr_membership_proofs_for_append,
                mutator_set.swbf_inactive.count_leaves(),
                &new_chunk_digest,
                &mutator_set.swbf_inactive.get_peaks(),
            );
        let mut swbf_mutated_indices: Vec<usize> = vec![];
        for j in indices_for_mutated_values {
            swbf_mutated_indices.push(mmr_membership_proof_index_to_membership_proof_index[j]);
        }

        // Gather the indices the are returned. These indices indicate which membership
        // proofs that have been mutated.
        let mut all_mutated_mp_indices: Vec<usize> = vec![
            swbf_mutated_indices,
            indices_for_updated_mps,
            mps_for_new_chunk_dictionary_entry,
        ]
        .concat();
        all_mutated_mp_indices.sort_unstable();
        all_mutated_mp_indices.dedup();

        Ok(all_mutated_mp_indices)
    }

    /**
     * update_from_addition
     * Updates a membership proof in anticipation of an addition to the set.
     */
    pub fn update_from_addition<MMR: Mmr<H>>(
        &mut self,
        own_item: &H::Digest,
        mutator_set: &mut SetCommitment<H, MMR>,
        addition_record: &AdditionRecord<H>,
    ) -> Result<bool, Box<dyn Error>> {
        assert!(self.auth_path_aocl.data_index < mutator_set.aocl.count_leaves());
        let new_item_index = mutator_set.aocl.count_leaves();
        let batch_index = new_item_index / BATCH_SIZE as u128;

        // Update AOCL MMR membership proof
        let aocl_mp_updated = self.auth_path_aocl.update_from_append(
            mutator_set.aocl.count_leaves(),
            &addition_record.commitment,
            &mutator_set.aocl.get_peaks(),
        );

        // if window does not slide, we are done
        if !SetCommitment::<H, MMR>::window_slides(new_item_index) {
            return Ok(aocl_mp_updated);
        }

        // window does slide
        let old_window_start_batch_index = batch_index - 1;
        let new_window_start_batch_index = batch_index;
        let new_chunk = Chunk {
            bits: mutator_set.swbf_active.get_sliding_chunk_bits(),
        };

        let hasher = H::new();
        let new_chunk_digest: H::Digest = new_chunk.hash::<H>(&hasher);

        // Get bit indices from either the cached bits, or by recalculating them. Notice
        // that the latter is an expensive operation.
        let all_bit_indices = match self.cached_bits {
            Some(bits) => bits,
            None => get_swbf_indices(
                &hasher,
                own_item,
                &self.randomness,
                self.auth_path_aocl.data_index,
            ),
        };
        let chunk_indices_set: HashSet<u128> = all_bit_indices
            .into_iter()
            .map(|bi| bi / CHUNK_SIZE as u128)
            .collect::<HashSet<u128>>();

        // Get an accumulator-version of the MMR and insert the new SWBF leaf to get its
        // authentication path.
        // It's important to convert the MMR
        // to an MMR Accumulator here, since we don't want to drag around or clone
        // a whole archival MMR for this operation, as the archival MMR can be in the
        // size of gigabytes, whereas the MMR accumulator should be in the size of
        // kilobytes.
        let mut mmra: MmrAccumulator<H> = mutator_set.swbf_inactive.to_accumulator();
        let new_auth_path: mmr::mmr_membership_proof::MmrMembershipProof<H> =
            mmra.append(new_chunk_digest.clone());

        let mut swbf_chunk_dictionary_updated = false;
        'outer: for chunk_index in chunk_indices_set.into_iter() {
            // Update for bit values that are in the inactive part of the SWBF.
            // Here the MMR membership proofs of the chunks must be updated.
            if chunk_index < old_window_start_batch_index {
                let mp = match self.target_chunks.dictionary.get_mut(&chunk_index) {
                    // If this record is not found, the MembershipProof is in a broken
                    // state.
                    None => {
                        return Err(Box::new(MembershipProofError::MissingChunkOnUpdateFromAdd(
                            chunk_index,
                        )))
                    }
                    Some((m, _chnk)) => m,
                };
                let swbf_chunk_dict_updated_local: bool = mp.update_from_append(
                    mutator_set.swbf_inactive.count_leaves(),
                    &new_chunk_digest,
                    &mutator_set.swbf_inactive.get_peaks(),
                );
                swbf_chunk_dictionary_updated =
                    swbf_chunk_dictionary_updated || swbf_chunk_dict_updated_local;

                continue 'outer;
            }

            // if bit is in the part that is becoming inactive, add a dictionary entry
            if old_window_start_batch_index <= chunk_index
                && chunk_index < new_window_start_batch_index
            {
                if self.target_chunks.dictionary.contains_key(&chunk_index) {
                    return Err(Box::new(MembershipProofError::AlreadyExistingChunk(
                        chunk_index,
                    )));
                }

                // add dictionary entry
                self.target_chunks
                    .dictionary
                    .insert(chunk_index, (new_auth_path.clone(), new_chunk));
                swbf_chunk_dictionary_updated = true;

                continue 'outer;
            }

            // If `chunk_index` refers to bits that are still in the active window, do nothing.
        }

        Ok(swbf_chunk_dictionary_updated || aocl_mp_updated)
    }

    /// Update multiple membership proofs from one remove operation. Returns the indices of the membership proofs
    /// that have been mutated.
    pub fn batch_update_from_remove(
        membership_proofs: &mut [&mut Self],
        removal_record: &RemovalRecord<H>,
    ) -> Result<Vec<usize>, Box<dyn Error>> {
        // Set all chunk values to the new values and calculate the mutation argument
        // for the batch updating of the MMR membership proofs.
        let mut chunk_dictionaries: Vec<&mut ChunkDictionary<H>> = membership_proofs
            .iter_mut()
            .map(|mp| &mut mp.target_chunks)
            .collect();
        let (mutated_chunks_by_mp_indices, mutation_argument) =
            Self::get_batch_mutation_argument_for_removal_record(
                removal_record,
                &mut chunk_dictionaries,
            );

        // Collect all the MMR membership proofs from the chunk dictionaries.
        // Also keep track of which MS membership proof they came from, so the
        // function can report back which MS membership proofs that have been
        // mutated
        let mut own_mmr_mps: Vec<&mut mmr::mmr_membership_proof::MmrMembershipProof<H>> = vec![];
        let mut mmr_mp_index_to_input_index: Vec<usize> = vec![];
        for (i, chunk_dict) in chunk_dictionaries.iter_mut().enumerate() {
            for (_, (mp, _)) in chunk_dict.dictionary.iter_mut() {
                own_mmr_mps.push(mp);
                mmr_mp_index_to_input_index.push(i);
            }
        }

        // Perform the batch mutation of the MMR membership proofs
        let mutated_mmr_mps =
            mmr::mmr_membership_proof::MmrMembershipProof::batch_update_from_batch_leaf_mutation(
                &mut own_mmr_mps,
                mutation_argument,
            );

        // Keep track of which MS membership proofs that were mutated
        let mut ret: Vec<usize> = mutated_chunks_by_mp_indices.into_iter().collect();
        for index in mutated_mmr_mps {
            ret.push(mmr_mp_index_to_input_index[index]);
        }
        ret.sort_unstable();
        ret.dedup();

        Ok(ret)
    }

    pub fn update_from_remove(
        &mut self,
        removal_record: &RemovalRecord<H>,
    ) -> Result<bool, Box<dyn Error>> {
        // Set all chunk values to the new values and calculate the mutation argument
        // for the batch updating of the MMR membership proofs.
        let mut chunk_dictionaries = vec![&mut self.target_chunks];
        let (mutated_chunk_dictionary_index, mutation_argument) =
            Self::get_batch_mutation_argument_for_removal_record(
                removal_record,
                &mut chunk_dictionaries,
            );

        // update membership proofs
        // Note that *all* membership proofs must be updated. It's not sufficient to update
        // those whose leaf has changed, since an authentication path changes if *any* leaf
        // in the same Merkle tree (under the same MMR peak) changes.
        // It would be sufficient to only update the membership proofs that live in the Merkle
        // trees that have been updated, but it probably will not give a measureable speedup
        // since this change would not reduce the amount of hashing needed
        let mut chunk_mmr_mps: Vec<&mut mmr::mmr_membership_proof::MmrMembershipProof<H>> = self
            .target_chunks
            .dictionary
            .iter_mut()
            .map(|(_, (mmr_mp, _))| mmr_mp)
            .collect();

        let mutated_mmr_mp_indices: Vec<usize> =
            mmr::mmr_membership_proof::MmrMembershipProof::batch_update_from_batch_leaf_mutation(
                &mut chunk_mmr_mps,
                mutation_argument,
            );

        Ok(!mutated_mmr_mp_indices.is_empty() || !mutated_chunk_dictionary_index.is_empty())
    }
}

#[cfg(test)]
mod ms_proof_tests {

    use crate::util_types::mutator_set::{
        mutator_set_accumulator::MutatorSetAccumulator, shared::BITS_PER_U32,
    };
    use rand::thread_rng;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};
    use twenty_first::util_types::{
        blake3_wrapper::{self, Blake3Hash},
        mmr,
        simple_hasher::Hasher,
    };

    use super::*;

    #[test]
    fn mp_cache_bits_test() {
        type H = blake3::Hasher;
        type Digest = blake3_wrapper::Blake3Hash;
        let hasher = H::new();
        let mut prng = thread_rng();
        let mut accumulator: MutatorSetAccumulator<H> = MutatorSetAccumulator::default();
        let item = hasher.hash::<Digest>(&(prng.next_u64() as u128).into());
        let randomness = hasher.hash::<Digest>(&(prng.next_u64() as u128).into());
        let mut mp = accumulator.prove(&item, &randomness, false);

        // Verify that bits are not cached, then cache them with the helper function
        assert!(mp.cached_bits.is_none());
        mp.cache_indices(&item);
        assert!(mp.cached_bits.is_some());

        // Verify that cached bits are the same as those generated from a new membership proof
        // made with the `cache_bits` argument set to true.
        let mp_generated_with_cached_bits = accumulator.prove(&item, &randomness, true);
        assert_eq!(mp_generated_with_cached_bits.cached_bits, mp.cached_bits);
    }

    #[test]
    fn mp_equality_test() {
        type Hasher = blake3::Hasher;
        type Digest = Blake3Hash;
        let hasher: Hasher = blake3::Hasher::new();
        let mut rng = ChaCha20Rng::from_seed(
            vec![vec![0, 1, 4, 33], vec![0; 28]]
                .concat()
                .try_into()
                .unwrap(),
        );
        let randomness = hasher.hash(
            &(0..3)
                .map(|_| BFieldElement::new(rng.next_u64()))
                .collect::<Vec<_>>(),
        );
        let other_randomness = hasher.hash(
            &(0..3)
                .map(|_| BFieldElement::new(rng.next_u64()))
                .collect::<Vec<_>>(),
        );
        let mp_with_cached_bits = MsMembershipProof::<Hasher> {
            randomness: randomness,
            auth_path_aocl: mmr::mmr_membership_proof::MmrMembershipProof::<Hasher> {
                data_index: 0,
                authentication_path: vec![],
            },
            target_chunks: ChunkDictionary::default(),
            cached_bits: Some([1u128; NUM_TRIALS]),
        };
        let mp_without_cached_bits = MsMembershipProof::<Hasher> {
            randomness: randomness,
            auth_path_aocl: mmr::mmr_membership_proof::MmrMembershipProof::<Hasher> {
                data_index: 0,
                authentication_path: vec![],
            },
            target_chunks: ChunkDictionary::default(),
            cached_bits: None,
        };
        let mp_with_different_data_index = MsMembershipProof::<Hasher> {
            randomness: randomness,
            auth_path_aocl: mmr::mmr_membership_proof::MmrMembershipProof::<Hasher> {
                data_index: 100073,
                authentication_path: vec![],
            },
            target_chunks: ChunkDictionary::default(),
            cached_bits: None,
        };
        let mp_with_different_randomness = MsMembershipProof::<Hasher> {
            randomness: other_randomness,
            auth_path_aocl: mmr::mmr_membership_proof::MmrMembershipProof::<Hasher> {
                data_index: 0,
                authentication_path: vec![],
            },
            target_chunks: ChunkDictionary::default(),
            cached_bits: None,
        };

        // Verify that the caching of bits does not change the equality value of a membership proof
        assert_eq!(mp_with_cached_bits, mp_without_cached_bits);

        // Verify that a different data index (a different auth path) is a different MP
        assert_ne!(mp_with_different_data_index, mp_with_cached_bits);

        // Verify that different randomness is a different MP
        assert_ne!(mp_with_different_randomness, mp_with_cached_bits);

        // Test that a different chunk dictionary results in a different MP
        // For this test to be performed, we first need an MMR membership proof and a chunk.

        // Construct an MMR with 7 leafs
        let mmr_digests: Vec<Digest> = (10u128..17).map(|i| i.into()).collect::<Vec<_>>();
        let mut mmra: MmrAccumulator<Hasher> = MmrAccumulator::new(mmr_digests);

        // Get an MMR membership proof by adding the 8th leaf
        let zero_chunk = Chunk {
            bits: [0u32; CHUNK_SIZE / BITS_PER_U32],
        };
        let mmr_mp = mmra.append(zero_chunk.hash(&hasher));

        // Verify that the MMR membership proof has the expected length of 3 (sanity check)
        assert_eq!(3, mmr_mp.authentication_path.len());

        // Create a new mutator set membership proof with a non-empty chunk dictionary
        // and verify that it is considered a different membership proof
        let mut mp_mutated: MsMembershipProof<Hasher> = mp_with_cached_bits.clone();
        mp_mutated
            .target_chunks
            .dictionary
            .insert(0, (mmr_mp, zero_chunk));
        assert_ne!(mp_mutated, mp_with_cached_bits);
        assert_ne!(mp_mutated, mp_without_cached_bits);
    }
}
