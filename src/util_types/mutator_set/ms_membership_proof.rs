use crate::models::blockchain::shared::Hash;
use crate::prelude::twenty_first;

use crate::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
use arbitrary::Arbitrary;
use get_size::GetSize;
use itertools::Itertools;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::marker::PhantomData;
use std::ops::IndexMut;
use tasm_lib::structure::tasm_object::TasmObject;
use twenty_first::shared_math::bfield_codec::BFieldCodec;
use twenty_first::shared_math::other::log_2_floor;
use twenty_first::shared_math::tip5::Digest;

use crate::util_types::mmr::traits::*;
use crate::util_types::mmr::MmrAccumulator;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

use super::addition_record::AdditionRecord;
use super::chunk_dictionary::{pseudorandom_chunk_dictionary, ChunkDictionary};
use super::mutator_set_accumulator::MutatorSetAccumulator;
use super::mutator_set_kernel::{get_swbf_indices, MutatorSetKernel};
use super::removal_record::AbsoluteIndexSet;
use super::removal_record::RemovalRecord;
use super::shared::{
    get_batch_mutation_argument_for_removal_record,
    prepare_authenticated_batch_modification_for_removal_record_reversion, BATCH_SIZE, CHUNK_SIZE,
};
impl Error for MembershipProofError {}

impl fmt::Display for MembershipProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum MembershipProofError {
    AlreadyExistingChunk(u64),
    MissingChunkOnUpdateFromAdd(u64),
}

// In order to store this structure in the database, it needs to be serializable.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, GetSize, BFieldCodec, TasmObject, Arbitrary,
)]
pub struct MsMembershipProof {
    pub sender_randomness: Digest,
    pub receiver_preimage: Digest,
    pub auth_path_aocl: MmrMembershipProof<Hash>,
    pub target_chunks: ChunkDictionary,
}

impl MsMembershipProof {
    /// Compute the indices that will be added to the SWBF if this item is removed.
    pub fn compute_indices(&self, item: Digest) -> AbsoluteIndexSet {
        AbsoluteIndexSet::new(&get_swbf_indices(
            item,
            self.sender_randomness,
            self.receiver_preimage,
            self.auth_path_aocl.leaf_index,
        ))
    }

    /// Update a list of membership proofs in anticipation of an addition. If successful,
    /// return (wrapped in an Ok) a vector of all indices of updated membership proofs.
    pub async fn batch_update_from_addition<MMR: Mmr<Hash>>(
        membership_proofs: &mut [&mut Self],
        own_items: &[Digest],
        mutator_set: &MutatorSetKernel<MMR>,
        addition_record: &AdditionRecord,
    ) -> Result<Vec<usize>, Box<dyn Error>> {
        let count_leaves = mutator_set.aocl.count_leaves().await;
        assert!(
            membership_proofs
                .iter()
                .all(|mp| mp.auth_path_aocl.leaf_index < count_leaves),
            "No AOCL data index can point outside of provided mutator set. aocl leaf count: {}; mp leaf indices: {}",
            count_leaves,
            membership_proofs.iter().map(|x| x.auth_path_aocl.leaf_index.to_string()).join(",")
        );
        assert_eq!(
            membership_proofs.len(),
            own_items.len(),
            "Function must be called with same number of membership proofs and items. Got {} items and {} membership proofs", own_items.len(), membership_proofs.len()
        );

        let new_item_index = mutator_set.aocl.count_leaves().await;

        // Update AOCL MMR membership proofs
        let indices_for_updated_mps = MmrMembershipProof::batch_update_from_append(
            &mut membership_proofs
                .iter_mut()
                .map(|x| &mut x.auth_path_aocl)
                .collect::<Vec<_>>(),
            new_item_index,
            addition_record.canonical_commitment,
            &mutator_set.aocl.get_peaks().await,
        );

        // if window does not slide, we are done
        if !MutatorSetKernel::<MMR>::window_slides(new_item_index) {
            return Ok(indices_for_updated_mps);
        }

        // window does slide
        let batch_index = new_item_index / BATCH_SIZE as u64;
        let old_window_start_batch_index = batch_index - 1;
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

        // Collect all indices for all membership proofs that are being updated
        // Notice that this is a *very* expensive operation if the indices are
        // not already known. I.e., the `None` case below is very expensive.
        let mut chunk_index_to_mp_index: HashMap<u64, Vec<usize>> = HashMap::new();
        membership_proofs
            .iter()
            .zip(own_items.iter())
            .enumerate()
            .for_each(|(i, (mp, &item))| {
                let indices = AbsoluteIndexSet::new(&get_swbf_indices(
                    item,
                    mp.sender_randomness,
                    mp.receiver_preimage,
                    mp.auth_path_aocl.leaf_index,
                ));
                let chunks_set: HashSet<u64> = indices
                    .to_array()
                    .iter()
                    .map(|x| (x / CHUNK_SIZE as u128) as u64)
                    .collect();
                chunks_set.iter().for_each(|chnkidx| {
                    chunk_index_to_mp_index.entry(*chnkidx).or_default().push(i)
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
        for i in mps_for_new_chunk_dictionary_entry.iter() {
            membership_proofs
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
        // instead of just collecting the indices into the membership proof vector.
        // It is, however, quite acceptable that many of the MMR membership proofs are
        // repeated since the MMR `batch_update_from_append` handles this optimally.
        // So relegating that bookkeeping to this function instead would not be more
        // efficient.
        let mut mmr_membership_proofs_for_append: Vec<&mut MmrMembershipProof<Hash>> = vec![];

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

        let indices_for_mutated_values = MmrMembershipProof::<Hash>::batch_update_from_append(
            &mut mmr_membership_proofs_for_append,
            mutator_set.swbf_inactive.count_leaves().await,
            new_chunk_digest,
            &mutator_set.swbf_inactive.get_peaks().await,
        );
        let mut swbf_mutated_indices: Vec<usize> = vec![];
        for j in indices_for_mutated_values {
            swbf_mutated_indices.push(mmr_membership_proof_index_to_membership_proof_index[j]);
        }

        // Gather the indices the are returned. These indices indicate which membership
        // proofs that have been mutated.
        let mut all_mutated_mp_indices: Vec<usize> = [
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
    pub async fn update_from_addition(
        &mut self,
        own_item: Digest,
        mutator_set: &MutatorSetAccumulator,
        addition_record: &AdditionRecord,
    ) -> Result<bool, Box<dyn Error>> {
        assert!(self.auth_path_aocl.leaf_index < mutator_set.kernel.aocl.count_leaves().await);
        let new_item_index = mutator_set.kernel.aocl.count_leaves().await;

        // Update AOCL MMR membership proof
        let aocl_mp_updated = self.auth_path_aocl.update_from_append(
            mutator_set.kernel.aocl.count_leaves().await,
            addition_record.canonical_commitment,
            &mutator_set.kernel.aocl.get_peaks().await,
        );

        // if window does not slide, we are done
        if !MutatorSetKernel::<MmrAccumulator<Hash>>::window_slides(new_item_index) {
            return Ok(aocl_mp_updated);
        }

        // window does slide
        let new_chunk = mutator_set.kernel.swbf_active.slid_chunk();
        let new_chunk_digest: Digest = Hash::hash(&new_chunk);

        // Get indices by recalculating them. (We do not cache indices any more.)
        let all_indices = get_swbf_indices(
            own_item,
            self.sender_randomness,
            self.receiver_preimage,
            self.auth_path_aocl.leaf_index,
        );
        let chunk_indices_set: HashSet<u64> = all_indices
            .into_iter()
            .map(|bi| (bi / CHUNK_SIZE as u128) as u64)
            .collect::<HashSet<u64>>();

        // Get an accumulator-version of the MMR and insert the new SWBF leaf to get its
        // authentication path.
        // It's important to convert the MMR
        // to an MMR Accumulator here, since we don't want to drag around or clone
        // a whole archival MMR for this operation, as the archival MMR can be in the
        // size of gigabytes, whereas the MMR accumulator should be in the size of
        // kilobytes.
        let mut mmra: MmrAccumulator<Hash> =
            mutator_set.kernel.swbf_inactive.to_accumulator().await;
        let new_auth_path: MmrMembershipProof<Hash> = mmra.append(new_chunk_digest).await;

        let mut swbf_chunk_dictionary_updated = false;
        let batch_index = new_item_index / BATCH_SIZE as u64;
        let old_window_start_batch_index = batch_index - 1;
        let new_window_start_batch_index = batch_index;
        'outer: for chunk_index in chunk_indices_set.into_iter() {
            // Update for indices that are in the inactive part of the SWBF.
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
                    mutator_set.kernel.swbf_inactive.count_leaves().await,
                    new_chunk_digest,
                    &mutator_set.kernel.swbf_inactive.get_peaks().await,
                );
                swbf_chunk_dictionary_updated =
                    swbf_chunk_dictionary_updated || swbf_chunk_dict_updated_local;

                continue 'outer;
            }

            // if index is in the part that is becoming inactive, add a dictionary entry
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
                    .insert(chunk_index, (new_auth_path.clone(), new_chunk.clone()));
                swbf_chunk_dictionary_updated = true;

                continue 'outer;
            }

            // If `chunk_index` refers to indices that are still in the active window, do nothing.
        }

        Ok(swbf_chunk_dictionary_updated || aocl_mp_updated)
    }

    /// Resets a membership proof to its state prior to updating it
    /// with one or many addition records, given only
    /// the state of the mutator set kernel prior to adding them.
    pub async fn revert_update_from_batch_addition(
        &mut self,
        previous_mutator_set: &MutatorSetAccumulator,
    ) {
        // calculate AOCL MMR MP length
        let previous_leaf_count = previous_mutator_set.kernel.aocl.count_leaves().await;
        assert!(
            previous_leaf_count > self.auth_path_aocl.leaf_index,
            "Cannot revert a membership proof for an item to back its state before the item was added to the mutator set."
        );
        let aocl_discrepancies = self.auth_path_aocl.leaf_index ^ previous_leaf_count;
        let aocl_mt_height = log_2_floor(aocl_discrepancies as u128);

        // trim to length
        while self.auth_path_aocl.authentication_path.len() > aocl_mt_height as usize {
            self.auth_path_aocl.authentication_path.pop();
        }

        // remove chunks from unslid windows
        let swbfi_leaf_count = previous_mutator_set
            .kernel
            .swbf_inactive
            .count_leaves()
            .await;
        self.target_chunks
            .dictionary
            .retain(|k, _v| *k < swbfi_leaf_count);

        // iterate over all retained chunk authentication paths
        for (k, (mp, _chnk)) in self.target_chunks.dictionary.iter_mut() {
            // calculate length
            let chunk_discrepancies = swbfi_leaf_count ^ k;
            let chunk_mt_height = log_2_floor(chunk_discrepancies as u128);

            // trim to length
            while mp.authentication_path.len() > chunk_mt_height as usize {
                mp.authentication_path.pop();
            }
        }
    }

    /// Update multiple membership proofs from one remove operation. Returns the indices of the membership proofs
    /// that have been mutated.
    pub fn batch_update_from_remove(
        membership_proofs: &mut [&mut Self],
        removal_record: &RemovalRecord,
    ) -> Result<Vec<usize>, Box<dyn Error>> {
        // Set all chunk values to the new values and calculate the mutation argument
        // for the batch updating of the MMR membership proofs.
        let mut chunk_dictionaries: Vec<&mut ChunkDictionary> = membership_proofs
            .iter_mut()
            .map(|mp| &mut mp.target_chunks)
            .collect();
        let (mutated_chunks_by_mp_indices, mutation_argument) =
            get_batch_mutation_argument_for_removal_record(removal_record, &mut chunk_dictionaries);

        // Collect all the MMR membership proofs from the chunk dictionaries.
        // Also keep track of which MS membership proof they came from, so the
        // function can report back which MS membership proofs that have been
        // mutated.
        // The chunk values contained in the MS membership proof's chunk dictionary has already
        // been updated by the `get_batch_mutation_argument_for_removal_record` function.
        let mut own_mmr_mps: Vec<&mut MmrMembershipProof<Hash>> = vec![];
        let mut mmr_mp_index_to_input_index: Vec<usize> = vec![];
        for (i, chunk_dict) in chunk_dictionaries.iter_mut().enumerate() {
            for (_, (mp, _)) in chunk_dict.dictionary.iter_mut() {
                own_mmr_mps.push(mp);
                mmr_mp_index_to_input_index.push(i);
            }
        }

        // Perform the batch mutation of the MMR membership proofs
        let mutated_mmr_mps = MmrMembershipProof::batch_update_from_batch_leaf_mutation(
            &mut own_mmr_mps,
            mutation_argument,
        );

        // Keep track of which MS membership proofs that were mutated. This is all those membership
        // proofs which have a mutated chunk
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
        removal_record: &RemovalRecord,
    ) -> Result<bool, Box<dyn Error>> {
        // Removing items does not slide the active window. We only
        // need to take into account new indices in the sparse Bloom
        // filter, and only in the inactive part. Specifically: we
        // need to update the chunks and their membership proofs.

        // Set all chunk values to the new values and calculate the mutation argument
        // for the batch updating of the MMR membership proofs.
        let mut chunk_dictionaries = vec![&mut self.target_chunks];
        let (mutated_chunk_dictionary_index, mutation_argument) =
            get_batch_mutation_argument_for_removal_record(removal_record, &mut chunk_dictionaries);

        // update membership proofs
        // Note that *all* membership proofs must be updated. It's not sufficient to update
        // those whose leaf has changed, since an authentication path changes if *any* leaf
        // in the same Merkle tree (under the same MMR peak) changes.
        // It would be sufficient to only update the membership proofs that live in the Merkle
        // trees that have been updated, but it probably will not give a measureable speedup
        // since this change would not reduce the amount of hashing needed
        let mut chunk_mmr_mps: Vec<&mut MmrMembershipProof<Hash>> = self
            .target_chunks
            .dictionary
            .iter_mut()
            .map(|(_, (mmr_mp, _))| mmr_mp)
            .collect();

        let mutated_mmr_mp_indices: Vec<usize> =
            MmrMembershipProof::batch_update_from_batch_leaf_mutation(
                &mut chunk_mmr_mps,
                mutation_argument,
            );

        Ok(!mutated_mmr_mp_indices.is_empty() || !mutated_chunk_dictionary_index.is_empty())
    }

    /// Resets a membership proof to its state prior to updating it
    /// with a removal record.
    pub fn revert_update_from_remove(
        &mut self,
        removal_record: &RemovalRecord,
    ) -> Result<bool, Box<dyn Error>> {
        // The logic here is essentially the same as in
        // `update_from_remove` but with the new and old chunks
        // swapped.

        // Set all chunk values to the old values and prepare
        // for batch updating of the MMR membership proofs.
        let mut chunk_dictionaries = vec![&mut self.target_chunks];
        let (mutated_chunk_dictionary_index, batch_membership) =
            prepare_authenticated_batch_modification_for_removal_record_reversion(
                removal_record,
                &mut chunk_dictionaries,
            );

        // update MMR membership proofs
        // Note that *all* MMR membership proofs must be updated. It's not sufficient to update
        // those whose leaf has changed, since an authentication path changes if *any* leaf
        // in the same Merkle tree (under the same MMR peak) changes.
        let mut chunk_mmr_mps: Vec<&mut MmrMembershipProof<Hash>> = self
            .target_chunks
            .dictionary
            .iter_mut()
            .map(|(_, (mmr_mp, _))| mmr_mp)
            .collect();

        let mutated_mmr_mp_indices: Vec<usize> =
            MmrMembershipProof::batch_update_from_batch_leaf_mutation(
                &mut chunk_mmr_mps,
                batch_membership,
            );

        Ok(!mutated_mmr_mp_indices.is_empty() || !mutated_chunk_dictionary_index.is_empty())
    }
}

/// Generate a pseudorandom mutator set membership proof from the given seed, for testing
/// purposes.
pub fn pseudorandom_mutator_set_membership_proof(seed: [u8; 32]) -> MsMembershipProof {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let sender_randomness: Digest = rng.gen();
    let receiver_preimage: Digest = rng.gen();
    let auth_path_aocl: MmrMembershipProof<Hash> = pseudorandom_mmr_membership_proof(rng.gen());
    let target_chunks: ChunkDictionary = pseudorandom_chunk_dictionary(rng.gen());
    MsMembershipProof {
        sender_randomness,
        receiver_preimage,
        auth_path_aocl,
        target_chunks,
    }
}

/// Generate a pseudorandom Merkle mountain range membership proof from the given seed,
/// for testing purposes.
pub fn pseudorandom_mmr_membership_proof<H: AlgebraicHasher>(
    seed: [u8; 32],
) -> MmrMembershipProof<H> {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let leaf_index: u64 = rng.gen();
    let authentication_path: Vec<Digest> =
        (0..rng.gen_range(0..15)).map(|_| rng.gen()).collect_vec();
    MmrMembershipProof {
        leaf_index,
        authentication_path,
        _hasher: PhantomData,
    }
}

#[cfg(test)]
mod ms_proof_tests {

    use crate::util_types::mutator_set::chunk::Chunk;
    use crate::util_types::mutator_set::mutator_set_trait::*;
    use crate::util_types::test_shared::mutator_set::{
        empty_rusty_mutator_set, make_item_and_randomnesses, random_mutator_set_membership_proof,
    };

    use super::*;
    use crate::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
    use itertools::{Either, Itertools};
    use rand::rngs::StdRng;
    use rand::{random, thread_rng, Rng, RngCore, SeedableRng};
    use twenty_first::shared_math::other::random_elements;

    #[tokio::test]
    async fn mp_equality_test() {
        let mut rng = thread_rng();

        let (_item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();

        let base_mp = MsMembershipProof {
            sender_randomness,
            receiver_preimage,
            auth_path_aocl: MmrMembershipProof::<Hash>::new(0, vec![]),
            target_chunks: ChunkDictionary::default(),
        };

        let mp_with_different_leaf_index = MsMembershipProof {
            sender_randomness,
            receiver_preimage,
            auth_path_aocl: MmrMembershipProof::<Hash>::new(100073, vec![]),
            target_chunks: ChunkDictionary::default(),
        };

        let mp_with_different_sender_randomness = MsMembershipProof {
            sender_randomness: rng.gen(),
            receiver_preimage,
            auth_path_aocl: MmrMembershipProof::<Hash>::new(0, vec![]),
            target_chunks: ChunkDictionary::default(),
        };

        let mp_with_different_receiver_preimage = MsMembershipProof {
            receiver_preimage: rng.gen(),
            sender_randomness,
            auth_path_aocl: MmrMembershipProof::<Hash>::new(0, vec![]),
            target_chunks: ChunkDictionary::default(),
        };

        // Verify that a different data index (a different auth path) is a different MP
        assert_ne!(mp_with_different_leaf_index, base_mp);

        // Verify that different sender randomness is a different MP
        assert_ne!(mp_with_different_sender_randomness, base_mp);

        // Verify that different receiver preimage is a different MP
        assert_ne!(mp_with_different_receiver_preimage, base_mp);

        // Test that a different chunk dictionary results in a different MP
        // For this test to be performed, we first need an MMR membership proof and a chunk.

        // Construct an MMR with 7 leafs
        let mmr_digests = random_elements::<Digest>(7);
        let mut mmra: MmrAccumulator<Hash> = MmrAccumulator::new(mmr_digests).await;

        // Get an MMR membership proof by adding the 8th leaf
        let zero_chunk = Chunk::empty_chunk();
        let mmr_mp = mmra.append(Hash::hash(&zero_chunk)).await;

        // Verify that the MMR membership proof has the expected length of 3 (sanity check)
        assert_eq!(3, mmr_mp.authentication_path.len());

        // Create a new mutator set membership proof with a non-empty chunk dictionary
        // and verify that it is considered a different membership proof
        let mut mp_mutated: MsMembershipProof = base_mp.clone();
        mp_mutated
            .target_chunks
            .dictionary
            .insert(0, (mmr_mp, zero_chunk));
        assert_ne!(mp_mutated, base_mp);
    }

    #[tokio::test]
    async fn serialization_test() {
        // This test belongs here since the serialization for `Option<[T; $len]>` is implemented
        // in this code base as a macro. So this is basically a test of that macro.
        let accumulator: MutatorSetAccumulator = MutatorSetAccumulator::default();
        for _ in 0..10 {
            let (item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();

            let mp = accumulator
                .kernel
                .prove(item, sender_randomness, receiver_preimage)
                .await;

            let json: String = serde_json::to_string(&mp).unwrap();
            let mp_again = serde_json::from_str::<MsMembershipProof>(&json).unwrap();

            assert_eq!(mp_again.target_chunks, mp.target_chunks);
            assert_eq!(mp_again, mp);
        }
    }

    #[tokio::test]
    async fn revert_update_from_remove_test() {
        let n = 100;
        let mut rng = thread_rng();

        let own_index = rng.next_u32() as usize % n;
        let mut own_membership_proof = None;
        let mut own_item = None;

        // set up mutator set
        let mut rms = empty_rusty_mutator_set().await;
        let archival_mutator_set = rms.ams_mut();
        let mut membership_proofs: Vec<(Digest, MsMembershipProof)> = vec![];

        // add items
        for i in 0..n {
            let item: Digest = random();
            let sender_randomness: Digest = random();
            let receiver_preimage: Digest = random();
            let addition_record = commit(item, sender_randomness, receiver_preimage.hash::<Hash>());

            for (oi, mp) in membership_proofs.iter_mut() {
                mp.update_from_addition(
                    *oi,
                    &archival_mutator_set.accumulator().await,
                    &addition_record,
                )
                .await
                .expect("Could not update membership proof from addition.");
            }

            let membership_proof = archival_mutator_set
                .prove(item, sender_randomness, receiver_preimage)
                .await;
            if i == own_index {
                own_membership_proof = Some(membership_proof);
                own_item = Some(item);
            } else {
                membership_proofs.push((item, membership_proof));
                if i > own_index {
                    own_membership_proof
                        .as_mut()
                        .unwrap()
                        .update_from_addition(
                            own_item.unwrap(),
                            &archival_mutator_set.accumulator().await,
                            &addition_record,
                        )
                        .await
                        .expect("Could not update membership proof from addition record.");
                }
            }

            archival_mutator_set.add(&addition_record).await;
        }

        // assert that own mp is valid
        assert!(
            archival_mutator_set
                .verify(own_item.unwrap(), own_membership_proof.as_ref().unwrap())
                .await
        );

        // Assert that all other mps are valid
        for (itm, mp) in membership_proofs.iter() {
            assert!(archival_mutator_set.verify(*itm, mp).await);
        }

        // generate some removal records
        let mut removal_records = vec![];
        for (item, membership_proof) in membership_proofs.into_iter() {
            if rng.next_u32() % 2 == 1 {
                let removal_record = archival_mutator_set.drop(item, &membership_proof);
                removal_records.push(removal_record);
            }
        }
        let cutoff_point = 1 + (rng.next_u32() as usize % (removal_records.len() - 1));
        let mut membership_proof_snapshot = None;

        // apply removal records
        for i in 0..removal_records.len() {
            let (immutable_records, mutable_records) = removal_records.split_at_mut(i + 1);
            let applied_removal_record = immutable_records.last().unwrap();

            RemovalRecord::batch_update_from_remove(
                &mut mutable_records.iter_mut().collect::<Vec<_>>(),
                applied_removal_record,
            );

            own_membership_proof
                .as_mut()
                .unwrap()
                .update_from_remove(applied_removal_record)
                .expect("Could not update membership proof from removal record");

            archival_mutator_set.remove(applied_removal_record).await;

            if i + 1 == cutoff_point {
                membership_proof_snapshot = Some(own_membership_proof.as_ref().unwrap().clone());
            }
        }

        // assert valid
        assert!(
            archival_mutator_set
                .verify(own_item.unwrap(), own_membership_proof.as_ref().unwrap())
                .await
        );

        // revert some removal records
        let mut reversions = removal_records[cutoff_point..].to_vec();
        reversions.reverse();
        for revert_removal_record in reversions.iter() {
            own_membership_proof
                .as_mut()
                .unwrap()
                .revert_update_from_remove(revert_removal_record)
                .expect("Could not revert update from removal record.");

            archival_mutator_set
                .revert_remove(revert_removal_record)
                .await;

            // keep other removal records up-to-date?
            // - nah, we don't need them for anything anymore
        }

        // assert valid
        assert!(
            archival_mutator_set
                .verify(own_item.unwrap(), own_membership_proof.as_ref().unwrap())
                .await
        );

        // assert same as snapshot before application-and-reversion
        assert_eq!(
            own_membership_proof.unwrap(),
            membership_proof_snapshot.unwrap()
        );
    }

    #[tokio::test]
    async fn revert_update_single_remove_test() {
        let mut rms = empty_rusty_mutator_set().await;
        let ams = rms.ams_mut();
        let mut mps = vec![];
        let mut items = vec![];
        let mut addition_records = vec![];
        let ms_size = 30;
        for _ in 0..ms_size {
            let item: Digest = random();
            let sender_randomness: Digest = random();
            let receiver_preimage: Digest = random();
            let addition_record = commit(item, sender_randomness, receiver_preimage.hash::<Hash>());
            MsMembershipProof::batch_update_from_addition(
                &mut mps.iter_mut().collect_vec(),
                &items,
                &ams.accumulator().await.kernel,
                &addition_record,
            )
            .await
            .unwrap();
            mps.push(ams.prove(item, sender_randomness, receiver_preimage).await);
            items.push(item);
            ams.add(&addition_record).await;
            addition_records.push(addition_record);
        }

        // Verify that all MPs are valid
        for i in 0..ms_size {
            assert!(ams.verify(items[i], &mps[i]).await);
        }

        // Remove all `ms_size` elements from the MS
        let mut removal_records = vec![];
        for i in 0..ms_size {
            let removal_record = ams.drop(items[i], &mps[i]);
            ams.remove(&removal_record).await;
            MsMembershipProof::batch_update_from_remove(
                &mut mps.iter_mut().collect_vec(),
                &removal_record,
            )
            .unwrap();
            removal_records.push(removal_record);

            // Verify that the rest of the MPs are still valid
            for j in 0..ms_size {
                if j > i {
                    assert!(ams.verify(items[j], &mps[j]).await);
                } else {
                    assert!(!ams.verify(items[j], &mps[j]).await);
                }
            }
        }

        // Verify that all MPs are invalid since their items were removed
        for i in 0..ms_size {
            assert!(!ams.verify(items[i], &mps[i]).await);
        }

        // Revert all removals in opposite order and verify that the MPs become valid again
        for i in (0..ms_size).rev() {
            ams.revert_remove(&removal_records[i]).await;
            for mp in mps.iter_mut().take(ms_size) {
                mp.revert_update_from_remove(&removal_records[i]).unwrap();
            }
            for j in 0..ms_size {
                if j < i {
                    assert!(!ams.verify(items[j], &mps[j]).await);
                } else {
                    assert!(ams.verify(items[j], &mps[j]).await);
                }
            }
        }

        // Verify all MPs after reverting all removals
        for i in 0..ms_size {
            ams.verify(items[i], &mps[i]).await;
        }
    }

    #[tokio::test]
    async fn revert_update_single_addition_test() {
        for j in 2..30 {
            let mut rms = empty_rusty_mutator_set().await;
            let ams = rms.ams_mut();

            // Add `j` items to MSA
            let mut mps = vec![];
            let mut items = vec![];
            let mut addition_records = vec![];
            for _ in 0..j {
                let item: Digest = random();
                let sender_randomness: Digest = random();
                let receiver_preimage: Digest = random();
                let addition_record =
                    commit(item, sender_randomness, receiver_preimage.hash::<Hash>());
                MsMembershipProof::batch_update_from_addition(
                    &mut mps.iter_mut().collect_vec(),
                    &items,
                    &ams.accumulator().await.kernel,
                    &addition_record,
                )
                .await
                .unwrap();
                mps.push(ams.prove(item, sender_randomness, receiver_preimage).await);
                items.push(item);
                ams.add(&addition_record).await;
                addition_records.push(addition_record);
            }

            // Revert all adds but the first one, and keep the 1st MP updated
            for i in (1..j).rev() {
                ams.revert_add(&addition_records[i]).await;
                mps[0]
                    .revert_update_from_batch_addition(&ams.accumulator().await)
                    .await;
                assert!(
                    ams.verify(items[0], &mps[0]).await,
                    "MP should be valid after reversion"
                );
                if i != 1 {
                    // We also check the 2nd MP for good measure, as long as its item is still in the MS
                    mps[1]
                        .revert_update_from_batch_addition(&ams.accumulator().await)
                        .await;
                    assert!(
                        ams.verify(items[1], &mps[1]).await,
                        "MP should be valid after reversion"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn revert_update_from_addition_batches_test() {
        let mut msa: MutatorSetAccumulator = MutatorSetAccumulator::new();

        let mut rng = thread_rng();
        for _ in 0..10 {
            let init_size = rng.gen_range(0..200);
            let first_batch_size = rng.gen_range(0..200);
            let last_batch_size = rng.gen_range(0..200);

            // Add `init_size` items to MSA
            for _ in 0..init_size {
                let item: Digest = random();
                let sender_randomness: Digest = random();
                let receiver_preimage: Digest = random();
                let addition_record =
                    commit(item, sender_randomness, receiver_preimage.hash::<Hash>());
                msa.add(&addition_record).await;
            }

            // Add own item with associated membership proof that we want to keep updated
            let own_item: Digest = random();
            let own_sender_randomness: Digest = random();
            let own_receiver_preimage: Digest = random();
            let own_addition_record = commit(
                own_item,
                own_sender_randomness,
                own_receiver_preimage.hash::<Hash>(),
            );
            let mut own_mp = msa
                .prove(own_item, own_sender_randomness, own_receiver_preimage)
                .await;
            msa.add(&own_addition_record).await;
            let msa_after_own_add = msa.clone();

            // Apply 1st batch of additions
            for _ in 0..first_batch_size {
                let item: Digest = random();
                let sender_randomness: Digest = random();
                let receiver_preimage: Digest = random();
                let addition_record =
                    commit(item, sender_randomness, receiver_preimage.hash::<Hash>());
                own_mp
                    .update_from_addition(own_item, &msa, &addition_record)
                    .await
                    .unwrap();
                msa.add(&addition_record).await;
                assert!(
                    msa.verify(own_item, &own_mp).await,
                    "Own mp must be valid after update"
                );
            }

            let msa_after_first_batch = msa.clone();

            // Apply 2nd batch of additions
            for _ in 0..last_batch_size {
                let item: Digest = random();
                let sender_randomness: Digest = random();
                let receiver_preimage: Digest = random();
                let addition_record =
                    commit(item, sender_randomness, receiver_preimage.hash::<Hash>());
                own_mp
                    .update_from_addition(own_item, &msa, &addition_record)
                    .await
                    .unwrap();
                msa.add(&addition_record).await;
                assert!(
                    msa.verify(own_item, &own_mp).await,
                    "Own mp must be valid after update"
                );
            }

            // revert last batch
            own_mp
                .revert_update_from_batch_addition(&msa_after_first_batch)
                .await;
            assert!(msa_after_first_batch.verify(own_item, &own_mp).await);

            // revert first batch
            own_mp
                .revert_update_from_batch_addition(&msa_after_own_add)
                .await;
            assert!(msa_after_own_add.verify(own_item, &own_mp).await);
        }
    }

    #[tokio::test]
    async fn revert_update_from_addition_test() {
        let mut rng = thread_rng();
        let n = rng.next_u32() as usize % 100 + 1;
        // let n = 55;

        let own_index = rng.next_u32() as usize % n;
        // let own_index = 8;
        let mut own_membership_proof = None;
        let mut own_item = None;

        // set up mutator set
        let mut rms = empty_rusty_mutator_set().await;
        let archival_mutator_set = rms.ams_mut();

        // add items
        let mut addition_records = vec![];
        for i in 0..n {
            let item: Digest = random();
            let sender_randomness: Digest = random();
            let receiver_preimage: Digest = random();
            let addition_record = commit(item, sender_randomness, receiver_preimage.hash::<Hash>());
            addition_records.push(addition_record);

            let membership_proof = archival_mutator_set
                .prove(item, sender_randomness, receiver_preimage)
                .await;
            match i.cmp(&own_index) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => {
                    own_membership_proof = Some(membership_proof);
                    own_item = Some(item);
                }
                std::cmp::Ordering::Greater => {
                    assert!(
                        archival_mutator_set
                            .verify(own_item.unwrap(), own_membership_proof.as_ref().unwrap())
                            .await
                    );
                    assert!(
                        archival_mutator_set
                            .accumulator()
                            .await
                            .verify(own_item.unwrap(), own_membership_proof.as_ref().unwrap())
                            .await
                    );
                    own_membership_proof
                        .as_mut()
                        .unwrap()
                        .update_from_addition(
                            own_item.unwrap(),
                            &archival_mutator_set.accumulator().await,
                            &addition_record,
                        )
                        .await
                        .expect("Could not update membership proof from addition record.");
                }
            }

            let mutator_set_before = archival_mutator_set.accumulator().await;
            archival_mutator_set.add(&addition_record).await;

            if i > own_index {
                let own_item = own_item.as_ref().unwrap().to_owned();
                assert!(
                    archival_mutator_set
                        .kernel
                        .verify(own_item, own_membership_proof.as_ref().unwrap(),)
                        .await
                );

                let mut memproof = own_membership_proof.as_ref().unwrap().clone();

                assert!(
                    archival_mutator_set
                        .kernel
                        .verify(own_item, &memproof,)
                        .await
                );

                memproof
                    .revert_update_from_batch_addition(&mutator_set_before)
                    .await;

                assert!(mutator_set_before.verify(own_item, &memproof).await);
                // assert!(previous_mutator_set.set_commitment.verify(own_item, self));
            }
        }

        // revert additions
        let (_petrified, revertible) = addition_records.split_at(own_index + 1);
        for addition_record in revertible.iter().rev() {
            archival_mutator_set.revert_add(addition_record).await;
            own_membership_proof
                .as_mut()
                .unwrap()
                .revert_update_from_batch_addition(&archival_mutator_set.accumulator().await)
                .await;

            assert!(
                archival_mutator_set
                    .verify(own_item.unwrap(), own_membership_proof.as_ref().unwrap())
                    .await
            );
        }
    }

    #[tokio::test]
    async fn revert_updates_mixed_test() {
        let mut rng_seeder = thread_rng();
        // let seed_integer = rng.next_u32();
        let error_tuple: (usize, u32) = (
            10 + rng_seeder.next_u32() as usize % 100,
            rng_seeder.next_u32(),
        );
        let n = error_tuple.0;
        let seed_integer = error_tuple.1;
        let margin = n / 5;
        println!("*********************** seed: {seed_integer} ***********************");
        let seed = seed_integer.to_be_bytes();
        let mut seed_as_bytes = [0u8; 32];
        for i in 0..32 {
            seed_as_bytes[i] = seed[i % 4];
        }

        let mut rng = StdRng::from_seed(seed_as_bytes);

        let mut rms = empty_rusty_mutator_set().await;
        let archival_mutator_set = rms.ams_mut();

        let own_index = rng.next_u32() as usize % 10;
        let mut own_item = Digest::default();
        let mut track_index = 0;

        let mut rates = HashMap::<String, f64>::new();
        rates.insert("additions".to_owned(), 0.7);
        rates.insert("removals".to_owned(), 0.95);

        let mut tracked_items_and_membership_proofs: Vec<(Digest, MsMembershipProof)> = vec![];
        let mut removed_items_and_membership_proofs: Vec<(Digest, MsMembershipProof, usize)> =
            vec![];
        let mut records: Vec<Either<AdditionRecord, RemovalRecord>> = vec![];

        for i in 0..2000 {
            let sample: f64 = rng.gen();

            // addition
            if sample <= rates["additions"] || i == own_index {
                println!(
                    "{i}. (set size {}) addition",
                    tracked_items_and_membership_proofs.len()
                );

                // generate item and randomness
                let item: Digest = rng.gen();
                let sender_randomness: Digest = rng.gen();
                let receiver_preimage: Digest = rng.gen();

                // generate addition record
                let addition_record =
                    commit(item, sender_randomness, receiver_preimage.hash::<Hash>());

                // record membership proof
                let membership_proof = archival_mutator_set
                    .prove(item, sender_randomness, receiver_preimage)
                    .await;

                // update existing membership proof
                for (it, mp) in tracked_items_and_membership_proofs.iter_mut() {
                    mp.update_from_addition(
                        *it,
                        &archival_mutator_set.accumulator().await,
                        &addition_record,
                    )
                    .await
                    .expect("Could not update membership proof from addition.");
                }

                // apply record
                archival_mutator_set.add(&addition_record).await;

                // record record
                records.push(Either::Left(addition_record));

                // if own record, set iamp index and own item
                if i == own_index {
                    track_index = tracked_items_and_membership_proofs.len();
                    own_item = item;
                    println!("own item index: {track_index}");
                }

                // record item, membership proof pair
                tracked_items_and_membership_proofs.push((item, membership_proof));

                // if too many items are in the mutator set, revise rates
                if tracked_items_and_membership_proofs.len() > n + margin && i > n {
                    *rates.get_mut("additions").unwrap() = 0.3;
                    *rates.get_mut("removals").unwrap() = 0.8;
                }
            }
            // removal
            else if sample > rates["additions"]
                && sample <= rates["removals"]
                && tracked_items_and_membership_proofs.len() > 1
            {
                println!(
                    "{i}. (set size {}) removal",
                    tracked_items_and_membership_proofs.len()
                );

                // sample index of item and membership proof to remove,
                // but not the index of the own item
                let mut index = track_index;
                while index == track_index {
                    index = rng.next_u32() as usize % tracked_items_and_membership_proofs.len()
                }

                // remove the indicated item and membership proof from the track list
                let (item, membership_proof) = tracked_items_and_membership_proofs.remove(index);
                if track_index > index {
                    track_index -= 1;
                }

                // generate a removal record
                let removal_record = archival_mutator_set.drop(item, &membership_proof);

                // update the other membership proofs with the removal record
                for (_, mp) in tracked_items_and_membership_proofs.iter_mut() {
                    mp.update_from_remove(&removal_record)
                        .expect("Could not update from remove.");
                }

                // don't lose track of the removed item
                assert!(
                    archival_mutator_set.verify(item, &membership_proof).await,
                    "track index: {track_index}\nitem index: {index}",
                );
                removed_items_and_membership_proofs.push((item, membership_proof.clone(), index));

                // remove the item from the mutator set
                archival_mutator_set.remove(&removal_record).await;

                // record record
                records.push(Either::Right(removal_record));

                // if there are too few items in the mutator set, revise rates
                if tracked_items_and_membership_proofs.len() < n - margin && i > n {
                    *rates.get_mut("additions").unwrap() = 0.5;
                    *rates.get_mut("removals").unwrap() = 0.8;
                }
            }
            // reversion
            else if tracked_items_and_membership_proofs.len() > 1 {
                // sample reversion depth
                let max_reversions = tracked_items_and_membership_proofs.len() - track_index;
                if max_reversions > 0 {
                    let num_reversions = rng.next_u32() as usize % max_reversions;
                    if num_reversions > 0 {
                        let set_size_was = tracked_items_and_membership_proofs.len();

                        // test if all records to be reverted are additions
                        let mut all_reversions_are_additions = true;
                        for j in 0..num_reversions {
                            if !matches!(records[records.len() - 1 - j], Either::Left(_)) {
                                all_reversions_are_additions = false;
                            }
                        }

                        // if they are, revert via batch
                        if all_reversions_are_additions && num_reversions > 1 {
                            println!(
                                "{i}. (set size {}) reversion [{}]",
                                tracked_items_and_membership_proofs.len(),
                                vec!["a"; num_reversions].join("")
                            );
                            for _ in 0..num_reversions {
                                if let Some(Either::Left(addition_record)) = records.pop() {
                                    archival_mutator_set.revert_add(&addition_record).await;
                                }
                                tracked_items_and_membership_proofs.pop();
                            }
                            for (_, mp) in tracked_items_and_membership_proofs.iter_mut() {
                                mp.revert_update_from_batch_addition(
                                    &archival_mutator_set.accumulator().await,
                                )
                                .await;
                            }
                        }
                        // otherwise, revert individually
                        else {
                            let mut records_abbreviation = "".to_string();
                            for _ in 0..num_reversions {
                                if let Some(record) = records.pop() {
                                    match record {
                                        Either::Left(addition_record) => {
                                            records_abbreviation =
                                                format!("{records_abbreviation}a");

                                            // revert update to mutator set
                                            archival_mutator_set.revert_add(&addition_record).await;
                                            tracked_items_and_membership_proofs.pop();
                                            for (_, mp) in
                                                tracked_items_and_membership_proofs.iter_mut()
                                            {
                                                mp.revert_update_from_batch_addition(
                                                    &archival_mutator_set.accumulator().await,
                                                )
                                                .await;
                                            }
                                        }
                                        Either::Right(removal_record) => {
                                            let mut _report_index = 0;

                                            // start reverting removal record
                                            records_abbreviation =
                                                format!("{records_abbreviation}r");

                                            // revert update to mutator set
                                            archival_mutator_set
                                                .revert_remove(&removal_record)
                                                .await;

                                            // assert valid proofs
                                            for (_, mp) in
                                                tracked_items_and_membership_proofs.iter_mut()
                                            {
                                                mp.revert_update_from_remove(&removal_record)
                                                    .expect("Could not revert remove.");
                                            }

                                            match removed_items_and_membership_proofs.pop() {
                                                Some((item, membership_proof, index)) => {
                                                    assert!(
                                                        archival_mutator_set
                                                            .verify(item, &membership_proof)
                                                            .await
                                                    );
                                                    tracked_items_and_membership_proofs
                                                        .insert(index, (item, membership_proof));
                                                    _report_index = index;
                                                    if index <= track_index {
                                                        track_index += 1;
                                                    }
                                                }
                                                None => {
                                                    panic!("No entries in removed_items_and_membership_proofs to pop!");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            println!(
                                "{i}. (set size {}) reversion ({})",
                                set_size_was, records_abbreviation
                            );
                        }
                    }
                }
            }

            if i > own_index {
                assert_eq!(own_item, tracked_items_and_membership_proofs[track_index].0);
                assert!(
                    archival_mutator_set
                        .verify(
                            own_item,
                            &tracked_items_and_membership_proofs[track_index].1
                        )
                        .await,
                    "seed: {seed_integer} / n: {n}",
                );
            }
        }
    }

    #[test]
    fn test_decode_mutator_set_membership_proof() {
        for _ in 0..100 {
            let msmp = random_mutator_set_membership_proof();
            let encoded = msmp.encode();
            let decoded: MsMembershipProof = *MsMembershipProof::decode(&encoded).unwrap();
            assert_eq!(msmp, decoded);
        }
    }
}
