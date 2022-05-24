use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    ops::IndexMut,
};

use itertools::Itertools;

use crate::{
    shared_math::b_field_element::BFieldElement,
    util_types::{
        mmr::{self, mmr_accumulator::MmrAccumulator, mmr_trait::Mmr},
        mutator_set::{chunk::Chunk, set_commitment::BATCH_SIZE},
        simple_hasher::{self, ToDigest},
    },
};

use super::{
    addition_record::AdditionRecord,
    chunk_dictionary::ChunkDictionary,
    removal_record::RemovalRecord,
    set_commitment::{SetCommitment, CHUNK_SIZE, NUM_TRIALS},
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

#[derive(Debug, Clone)]
pub struct MembershipProof<H: simple_hasher::Hasher> {
    pub randomness: H::Digest,
    pub auth_path_aocl: mmr::membership_proof::MembershipProof<H>,
    pub target_chunks: ChunkDictionary<H>,

    // Cached bits are optional to store, but will prevent a lot of hashing in
    // later bookkeeping, such as updating the membership proof.
    pub cached_bits: Option<[u128; NUM_TRIALS]>,
}

impl<H: simple_hasher::Hasher> PartialEq for MembershipProof<H> {
    fn eq(&self, other: &Self) -> bool {
        self.randomness == other.randomness
            && self.auth_path_aocl == other.auth_path_aocl
            && self.target_chunks == other.target_chunks
    }
}

impl<H> MembershipProof<H>
where
    u128: ToDigest<<H as simple_hasher::Hasher>::Digest>,
    Vec<BFieldElement>: ToDigest<<H as simple_hasher::Hasher>::Digest>,
    H: simple_hasher::Hasher,
{
    /// Get an argument to the MMR `batch_update_from_batch_leaf_mutation`,
    /// and mutate the chunk dictionary chunk values.
    /// This function is factored out because it is shared by `update_from_remove`
    /// and `batch_update_from_remove`.
    fn get_batch_mutation_argument_for_removal_record(
        removal_record: &RemovalRecord<H>,
        chunk_dictionaries: &mut [&mut ChunkDictionary<H>],
    ) -> Vec<(mmr::membership_proof::MembershipProof<H>, H::Digest)> {
        let hasher = H::new();
        let mut mutation_argument_hash_map: HashMap<
            u128,
            (mmr::membership_proof::MembershipProof<H>, H::Digest),
        > = HashMap::new();
        // let mut mutation_argument: Vec<(mmr::membership_proof::MembershipProof<H>, H::Digest)> =
        //     vec![];
        let mut rem_record_chunk_idx_to_bit_indices: HashMap<u128, Vec<u128>> = HashMap::new();
        removal_record
            .bit_indices
            .iter()
            .map(|bi| (bi / CHUNK_SIZE as u128, bi))
            .for_each(|(k, v)| {
                rem_record_chunk_idx_to_bit_indices
                    .entry(k)
                    .or_insert_with(Vec::new)
                    .push(*v);
            });

        for (chunk_index, bit_indices) in rem_record_chunk_idx_to_bit_indices.iter() {
            for chunk_dictionary in chunk_dictionaries.iter_mut() {
                match chunk_dictionary.dictionary.get_mut(chunk_index) {
                    // Leaf exists in own membership proof
                    Some((mp, chnk)) => {
                        for bit_index in bit_indices.iter() {
                            chnk.bits[(bit_index % CHUNK_SIZE as u128) as usize] = true;
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
                                    target_chunk.bits[(bit_index % CHUNK_SIZE as u128) as usize] =
                                        true;
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

        mutation_argument_hash_map.into_values().collect()
    }

    pub fn batch_update_from_addition<MMR: Mmr<H>>(
        membership_proofs: &mut [&mut Self],
        own_items: &[H::Digest],
        mutator_set: &SetCommitment<H, MMR>,
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
            mmr::membership_proof::MembershipProof::batch_update_from_append(
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
            bits: mutator_set.swbf_active[0..CHUNK_SIZE].try_into().unwrap(),
        };
        let new_chunk_digest: H::Digest = new_chunk.hash::<H>(&mutator_set.hasher);

        // Insert the new chunk digest into the accumulator-version of the
        // SWBF MMR to get its authentication path. It's important to convert the MMR
        // to an MMR Accumulator here, since we don't want to drag around or clone
        // a whole archival MMR for this operation, as the archival MMR can be in the
        // size of gigabytes, whereas the MMR accumulator should be in the size of
        // kilobytes.
        let mut mmra: MmrAccumulator<H> = mutator_set.swbf_inactive.to_accumulator();
        let new_swbf_auth_path: mmr::membership_proof::MembershipProof<H> =
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
                    None => {
                        mutator_set.get_indices(item, &mp.randomness, mp.auth_path_aocl.data_index)
                    }
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
        for i in mps_for_new_chunk_dictionary_entry {
            membership_proofs
                .index_mut(i)
                .target_chunks
                .dictionary
                .insert(
                    old_window_start_batch_index,
                    (new_swbf_auth_path.clone(), new_chunk),
                );
        }

        // This is a bit ugly and a bit slower than it could be. To prevent this
        // for-loop, you probably could collect the `Vec<&mut mp>` in the code above,
        // instead of just collecting the indices into the membership proof vector.
        // It is, however, quite acceptable that many of the MMR membership proofs are
        // repeated since the MMR `batch_update_from_append` handles this optimally.
        // So relegating that bookkeeping to this function instead would not be more
        // efficient.
        let mut mmr_membership_proofs_for_append: Vec<
            &mut mmr::membership_proof::MembershipProof<H>,
        > = vec![];
        for (i, mp) in membership_proofs.iter_mut().enumerate() {
            if mps_for_batch_append.contains(&i) {
                for (_, (mmr_mp, _chnk)) in mp.target_chunks.dictionary.iter_mut() {
                    mmr_membership_proofs_for_append.push(mmr_mp);
                }
            }
        }

        let indices_for_mutated_values =
            mmr::membership_proof::MembershipProof::<H>::batch_update_from_append(
                &mut mmr_membership_proofs_for_append,
                mutator_set.swbf_inactive.count_leaves(),
                &new_chunk_digest,
                &mutator_set.swbf_inactive.get_peaks(),
            );

        // Gather the indices the are returned. These indices indicate which membership
        // proofs that have been mutated.
        let mut all_mutated_mp_indices: Vec<usize> =
            vec![indices_for_mutated_values, indices_for_updated_mps].concat();
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
        mutator_set: &SetCommitment<H, MMR>,
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
            bits: mutator_set.swbf_active[0..CHUNK_SIZE].try_into().unwrap(),
        };

        let new_chunk_digest: H::Digest = new_chunk.hash::<H>(&mutator_set.hasher);

        // Get bit indices from either the cached bits, or by recalculating them. Notice
        // that the latter is an expensive operation.
        let all_bit_indices = match self.cached_bits {
            Some(bits) => bits,
            None => {
                mutator_set.get_indices(own_item, &self.randomness, self.auth_path_aocl.data_index)
            }
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
        let new_auth_path: mmr::membership_proof::MembershipProof<H> =
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

    pub fn batch_update_from_remove(
        membership_proofs: &mut [&mut Self],
        removal_record: &RemovalRecord<H>,
    ) -> Result<(), Box<dyn Error>> {
        // TODO: Fix the return type to return indices of membership proofs that have
        // been mutated.
        // Set all chunk values to the new values and calculate the mutation argument
        // for the batch updating of the MMR membership proofs.
        let mut chunk_dictionaries: Vec<&mut ChunkDictionary<H>> = membership_proofs
            .iter_mut()
            .map(|mp| &mut mp.target_chunks)
            .collect();
        let mutation_argument = Self::get_batch_mutation_argument_for_removal_record(
            removal_record,
            &mut chunk_dictionaries,
        );

        let mut own_mmr_membership_proofs: Vec<&mut mmr::membership_proof::MembershipProof<H>> =
            membership_proofs
                .iter_mut()
                .map(|mp| {
                    mp.target_chunks
                        .dictionary
                        .iter_mut()
                        .map(|entry| &mut entry.1 .0)
                        .collect::<Vec<_>>()
                })
                .concat();

        mmr::membership_proof::MembershipProof::batch_update_from_batch_leaf_mutation(
            &mut own_mmr_membership_proofs,
            mutation_argument,
        );

        Ok(())
    }

    pub fn update_from_remove(
        &mut self,
        removal_record: &RemovalRecord<H>,
    ) -> Result<(), Box<dyn Error>> {
        // TODO: Make this function return boolean indicating if it was changed or not

        // Set all chunk values to the new values and calculate the mutation argument
        // for the batch updating of the MMR membership proofs.
        let mut chunk_dictionaries = vec![&mut self.target_chunks];
        let mutation_argument = Self::get_batch_mutation_argument_for_removal_record(
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
        let mut own_membership_proofs_copy: Vec<mmr::membership_proof::MembershipProof<H>> = self
            .target_chunks
            .dictionary
            .iter()
            .map(|(_, (p, _))| p.clone())
            .collect();

        // TODO: Remove the copying of the objects here
        mmr::membership_proof::MembershipProof::batch_update_from_batch_leaf_mutation(
            &mut own_membership_proofs_copy.iter_mut().collect::<Vec<_>>(),
            mutation_argument,
        );

        // Copy back all updated membership proofs
        for mp in own_membership_proofs_copy {
            let mut target = self
                .target_chunks
                .dictionary
                .get_mut(&mp.data_index)
                .unwrap();
            target.0 = mp;
        }

        Ok(())
    }
}
