use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
};

use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

use crate::{
    shared_math::b_field_element::BFieldElement,
    util_types::{
        mmr::{self, mmr_accumulator::MmrAccumulator, mmr_trait::Mmr},
        simple_hasher::{self, ToDigest},
    },
};

pub const WINDOW_SIZE: usize = 30000;
pub const CHUNK_SIZE: usize = 1500;
pub const BATCH_SIZE: usize = 10;
pub const NUM_TRIALS: usize = 5; // TODO: Change to 160 in production

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Chunk {
    bits: [bool; CHUNK_SIZE],
}

impl Chunk {
    const BIT_CAPACITY_PER_BFIELD_ELEMENT: usize = 63;

    #[inline]
    const fn get_hashpreimage_length() -> usize {
        CHUNK_SIZE / Self::BIT_CAPACITY_PER_BFIELD_ELEMENT
            + if CHUNK_SIZE % Self::BIT_CAPACITY_PER_BFIELD_ELEMENT == 0 {
                0
            } else {
                1
            }
    }

    #[inline]
    fn hash_preimage(&self) -> Vec<BFieldElement> {
        let num_iterations = CHUNK_SIZE / Self::BIT_CAPACITY_PER_BFIELD_ELEMENT;
        let mut ret: Vec<BFieldElement> = Vec::with_capacity(Self::get_hashpreimage_length());
        let mut acc: u64;
        for i in 0..num_iterations {
            acc = 0;
            for j in 0..Self::BIT_CAPACITY_PER_BFIELD_ELEMENT {
                acc += if self.bits[i * Self::BIT_CAPACITY_PER_BFIELD_ELEMENT + j] {
                    1 << j
                } else {
                    0
                };
            }
            ret.push(BFieldElement::new(acc));
        }
        if CHUNK_SIZE % Self::BIT_CAPACITY_PER_BFIELD_ELEMENT != 0 {
            acc = 0;
            for j in 0..CHUNK_SIZE % Self::BIT_CAPACITY_PER_BFIELD_ELEMENT {
                acc += if self.bits[num_iterations * Self::BIT_CAPACITY_PER_BFIELD_ELEMENT + j] {
                    1 << j
                } else {
                    0
                };
            }
            ret.push(BFieldElement::new(acc));
        }

        ret
    }

    pub fn hash<H: simple_hasher::Hasher>(&self, hasher: &H) -> H::Digest
    where
        Vec<BFieldElement>: ToDigest<H::Digest>,
    {
        let preimage = self.hash_preimage();

        hasher.hash(&preimage.to_digest())
    }
}

#[derive(Clone, Debug)]
pub struct ChunkDictionary<H: simple_hasher::Hasher> {
    // {chunk index => (membership proof for the whole chunk to which bit belongs, chunk value)}
    dictionary: HashMap<u128, (mmr::membership_proof::MembershipProof<H>, Chunk)>,
}

impl<H: simple_hasher::Hasher> PartialEq for ChunkDictionary<H> {
    fn eq(&self, other: &Self) -> bool {
        self.dictionary == other.dictionary
    }
}

impl<H: simple_hasher::Hasher> ChunkDictionary<H> {
    fn default() -> ChunkDictionary<H> {
        Self {
            dictionary: HashMap::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AdditionRecord<H: simple_hasher::Hasher> {
    commitment: H::Digest,
    aocl_snapshot: MmrAccumulator<H>,
}

impl<H: simple_hasher::Hasher> AdditionRecord<H>
where
    u128: ToDigest<<H as simple_hasher::Hasher>::Digest>,
{
    pub fn has_matching_aocl(&self, aocl_accumulator: &MmrAccumulator<H>) -> bool {
        self.aocl_snapshot.count_leaves() == aocl_accumulator.count_leaves()
            && self.aocl_snapshot.get_peaks() == aocl_accumulator.get_peaks()
    }
}

#[derive(Clone, Debug)]
pub struct RemovalRecord<H: simple_hasher::Hasher> {
    bit_indices: Vec<u128>,
    target_chunks: ChunkDictionary<H>,
}

#[derive(Clone, Debug)]
pub struct SetCommitment<H: simple_hasher::Hasher> {
    aocl: MmrAccumulator<H>,
    swbf_inactive: MmrAccumulator<H>,
    swbf_active: [bool; WINDOW_SIZE],
    hasher: H,
}

impl<H: simple_hasher::Hasher> RemovalRecord<H>
where
    u128: ToDigest<<H as simple_hasher::Hasher>::Digest>,
    Vec<BFieldElement>: ToDigest<<H as simple_hasher::Hasher>::Digest>,
{
    pub fn validate(&self, mutator_set: &SetCommitment<H>) -> bool {
        let peaks = mutator_set.swbf_inactive.get_peaks();
        self.target_chunks.dictionary.iter().all(|(_i, (p, c))| {
            p.verify(
                &peaks,
                &c.hash::<H>(&mutator_set.hasher),
                mutator_set.swbf_inactive.count_leaves(),
            )
            .0
        })
    }
}

impl<H: simple_hasher::Hasher> SetCommitment<H>
where
    u128: ToDigest<<H as simple_hasher::Hasher>::Digest>,
    Vec<BFieldElement>: ToDigest<<H as simple_hasher::Hasher>::Digest>,
{
    pub fn default() -> Self {
        Self {
            aocl: MmrAccumulator::new(vec![]),
            swbf_inactive: MmrAccumulator::new(vec![]),
            swbf_active: [false; WINDOW_SIZE as usize],
            hasher: H::new(),
        }
    }

    /// Generates an addition record from an item and explicit random-
    /// ness. The addition record is itself a commitment to the item,
    /// but tailored to adding the item to the mutator set in its
    /// current state.
    pub fn commit(&self, item: &H::Digest, randomness: &H::Digest) -> AdditionRecord<H> {
        let canonical_commitment = self.hasher.hash_pair(item, randomness);

        AdditionRecord {
            commitment: canonical_commitment,
            aocl_snapshot: self.aocl.clone(),
        }
    }

    /// Helper function. Computes the bloom filter bit indices of the
    /// item, randomness, index triple.
    pub fn get_indices(&self, item: &H::Digest, randomness: &H::Digest, index: u128) -> Vec<u128> {
        let batch_index = index / BATCH_SIZE as u128;
        let timestamp: H::Digest = (index as u128).to_digest();
        let mut rhs = self.hasher.hash_pair(&timestamp, randomness);
        rhs = self.hasher.hash_pair(item, &rhs);
        let mut indices: Vec<u128> = Vec::with_capacity(NUM_TRIALS);

        // Collect all indices in parallel, using counter-mode
        (0..NUM_TRIALS)
            .into_par_iter()
            .map(|i| {
                let counter: H::Digest = (i as u128).to_digest();
                let pseudorandomness = self.hasher.hash_pair(&counter, &rhs);
                self.hasher
                    .sample_index_not_power_of_two(&pseudorandomness, WINDOW_SIZE)
                    as u128
                    + batch_index * CHUNK_SIZE as u128
            })
            .collect_into_vec(&mut indices);

        indices
    }

    /**
     * drop
     * Generates a removal record with which to update the set commitment.
     */
    pub fn drop(
        &self,
        item: &H::Digest,
        membership_proof: &MembershipProof<H>,
    ) -> RemovalRecord<H> {
        let bit_indices = self.get_indices(
            item,
            &membership_proof.randomness,
            membership_proof.auth_path_aocl.data_index,
        );

        RemovalRecord {
            bit_indices,
            target_chunks: membership_proof.target_chunks.clone(),
        }
    }

    /**
     * window_slides
     * Determine if the window slides before absorbing an item,
     * given the index of the to-be-added item.
     */
    pub fn window_slides(index: u128) -> bool {
        index != 0 && index % BATCH_SIZE as u128 == 0

        // example cases:
        //  - index == 0 we don't care about
        //  - index == 1 does not generate a slide
        //  - index == n * BATCH_SIZE generates a slide for any n
    }

    ///   add
    ///   Updates the set-commitment with an addition record. The new
    ///   commitment represents the set $S union {c}$ ,
    ///   where S is the set represented by the old
    ///   commitment and c is the commitment to the new item AKA the
    ///   *addition record*.
    pub fn add(&mut self, addition_record: &AdditionRecord<H>) {
        // Notice that `add` cannot return a membership proof since `add` cannot know the
        // randomness that was used to create the commitment. This randomness can only be know
        // by the sender and/or receiver of the UTXO. And `add` must be run be all nodes keeping
        // track of the mutator set.
        // verify aocl snapshot
        if !addition_record.has_matching_aocl(&self.aocl) {
            panic!("Addition record has aocl snapshot that does not match with the AOCL it is being added to.")
        }

        // add to list
        let item_index = self.aocl.count_leaves();
        self.aocl.append(addition_record.commitment.to_owned()); // ignore auth path

        // if window slides, update filter
        if Self::window_slides(item_index) {
            // First update the inactive part of the SWBF, the SWBF MMR
            let chunk: Chunk = Chunk {
                bits: self.swbf_active[..CHUNK_SIZE].try_into().unwrap(),
            };
            let chunk_digest: H::Digest = chunk.hash::<H>(&self.hasher);
            self.swbf_inactive.append(chunk_digest); // ignore auth path

            // Then move window to the right, equivalent to moving values
            // inside window to the left.
            for i in CHUNK_SIZE..WINDOW_SIZE {
                self.swbf_active[i - CHUNK_SIZE] = self.swbf_active[i];
            }

            for i in (WINDOW_SIZE - CHUNK_SIZE)..WINDOW_SIZE {
                self.swbf_active[i] = false;
            }
        }
    }

    /// remove
    /// Updates the mutator set so as to remove the item determined by
    /// its removal record.
    // TODO: Do we also want the provided removal record to be updated?
    pub fn remove(&mut self, removal_record: &RemovalRecord<H>) {
        let batch_index = self.aocl.count_leaves() / BATCH_SIZE as u128;
        let window_start = batch_index * CHUNK_SIZE as u128;

        // set all bits
        let mut new_target_chunks = removal_record.target_chunks.clone();
        for bit_index in removal_record.bit_indices.iter() {
            // if bit is in active part
            if *bit_index >= window_start {
                let relative_index = bit_index - window_start;
                self.swbf_active[relative_index as usize] = true;
                continue;
            }

            // bit is not in active part, so set bits in relevant chunk
            let mut relevant_chunk = new_target_chunks
                .dictionary
                .get_mut(&(bit_index / CHUNK_SIZE as u128))
                .unwrap();
            relevant_chunk.1.bits[(bit_index % CHUNK_SIZE as u128) as usize] = true;
        }

        // update mmr
        // to do this, we need to keep track of all membership proofs
        let mut all_membership_proofs: Vec<_> = new_target_chunks
            .dictionary
            .values()
            .map(|(p, _c)| p.to_owned())
            .collect();
        let mut all_leafs: Vec<_> = new_target_chunks
            .dictionary
            .values()
            .map(|(_p, c)| c.hash::<H>(&self.hasher))
            .collect();

        // TODO: With an MMR function that can batch-mutate leafs, this loop should be avoidable.
        for _ in 0..all_membership_proofs.len() {
            let local_membership_proof = all_membership_proofs.pop().unwrap();
            let local_leaf = all_leafs.pop().unwrap();

            self.swbf_inactive
                .mutate_leaf(&local_membership_proof, &local_leaf);
            mmr::membership_proof::MembershipProof::batch_update_from_leaf_mutation(
                &mut all_membership_proofs,
                &local_membership_proof,
                &local_leaf,
            );
        }
    }

    /**
     * prove
     * Generates a membership proof that will the valid when the item
     * is added to the mutator set.
     */
    pub fn prove(&self, item: &H::Digest, randomness: &H::Digest) -> MembershipProof<H> {
        // compute commitment
        let item_commitment = self.hasher.hash_pair(item, randomness);

        // simulate adding to commitment list
        let auth_path_aocl = self.aocl.clone().append(item_commitment);
        let target_chunks: ChunkDictionary<H> = ChunkDictionary::default();

        // return membership proof
        MembershipProof {
            randomness: randomness.to_owned(),
            auth_path_aocl,
            target_chunks,
        }
    }

    pub fn verify(&self, item: &H::Digest, membership_proof: &MembershipProof<H>) -> bool {
        // If data index does not exist in AOCL, return false
        // This also ensures that no "future" bit indices will be
        // returned from `get_indices`, so we don't have to check for
        // future indices in a separate check.
        if self.aocl.count_leaves() <= membership_proof.auth_path_aocl.data_index {
            return false;
        }

        // verify that a commitment to the item lives in the aocl mmr
        let leaf = self.hasher.hash_pair(item, &membership_proof.randomness);
        let (is_aocl_member, _) = membership_proof.auth_path_aocl.verify(
            &self.aocl.get_peaks(),
            &leaf,
            self.aocl.count_leaves(),
        );
        if !is_aocl_member {
            return false;
        }

        // verify that some indicated bits in the swbf are unset
        let mut has_unset_bits = false;
        let mut entries_in_dictionary = true;
        let mut all_auth_paths_are_valid = true;

        // prepare parameters of inactive part
        let current_batch_index: u128 = (self.aocl.count_leaves() - 1) / BATCH_SIZE as u128;
        let window_start = current_batch_index * CHUNK_SIZE as u128;
        let all_bit_indices = self.get_indices(
            item,
            &membership_proof.randomness,
            membership_proof.auth_path_aocl.data_index,
        );
        let mut chunk_index_to_bit_indices: HashMap<u128, Vec<u128>> = HashMap::new();
        all_bit_indices
            .iter()
            .map(|bi| (bi / CHUNK_SIZE as u128, bi))
            .for_each(|(k, v)| {
                chunk_index_to_bit_indices
                    .entry(k)
                    .or_insert_with(Vec::new)
                    .push(*v);
            });

        'outer: for (chunk_index, bit_indices) in chunk_index_to_bit_indices.into_iter() {
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

                let mp_and_chunk: &(mmr::membership_proof::MembershipProof<H>, Chunk) =
                    membership_proof
                        .target_chunks
                        .dictionary
                        .get(&chunk_index)
                        .unwrap();
                let (valid_auth_path, _) = mp_and_chunk.0.verify(
                    &self.swbf_inactive.get_peaks(),
                    &mp_and_chunk.1.hash::<H>(&self.hasher),
                    self.swbf_inactive.count_leaves(),
                );

                all_auth_paths_are_valid = all_auth_paths_are_valid && valid_auth_path;

                'inner_inactive: for bit_index in bit_indices {
                    let index_within_chunk = bit_index % CHUNK_SIZE as u128;
                    if !mp_and_chunk.1.bits[index_within_chunk as usize] {
                        has_unset_bits = true;
                        break 'inner_inactive;
                    }
                }
            } else {
                // bits are in active window
                'inner_active: for bit_index in bit_indices {
                    let relative_index = bit_index - window_start;
                    if !self.swbf_active[relative_index as usize] {
                        has_unset_bits = true;
                        break 'inner_active;
                    }
                }
            }
        }

        // return verdict
        is_aocl_member && entries_in_dictionary && all_auth_paths_are_valid && has_unset_bits
    }
}

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
    randomness: H::Digest,
    auth_path_aocl: mmr::membership_proof::MembershipProof<H>,
    target_chunks: ChunkDictionary<H>,
}

impl<H: simple_hasher::Hasher> PartialEq for MembershipProof<H> {
    fn eq(&self, other: &Self) -> bool {
        self.randomness == other.randomness
            && self.auth_path_aocl == other.auth_path_aocl
            && self.target_chunks == other.target_chunks
    }
}

impl<H: simple_hasher::Hasher> MembershipProof<H>
where
    u128: ToDigest<<H as simple_hasher::Hasher>::Digest>,
    Vec<BFieldElement>: ToDigest<<H as simple_hasher::Hasher>::Digest>,
{
    /**
     * update_from_addition
     * Updates a membership proof in anticipation of an addition to the set.
     */
    pub fn update_from_addition(
        &mut self,
        own_item: &H::Digest,
        mutator_set: &SetCommitment<H>,
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
        if !SetCommitment::<H>::window_slides(new_item_index) {
            return Ok(aocl_mp_updated);
        }

        // window does slide
        let old_window_start_batch_index = batch_index - 1;
        let new_window_start_batch_index = batch_index;
        let new_chunk = Chunk {
            bits: mutator_set.swbf_active[0..CHUNK_SIZE].try_into().unwrap(),
        };

        let new_chunk_digest: H::Digest = new_chunk.hash::<H>(&mutator_set.hasher);
        let all_bit_indices =
            mutator_set.get_indices(own_item, &self.randomness, self.auth_path_aocl.data_index);
        let chunk_indices_set: HashSet<u128> = all_bit_indices
            .into_iter()
            .map(|bi| bi / CHUNK_SIZE as u128)
            .collect::<HashSet<u128>>();

        let mut mmra_copy = mutator_set.swbf_inactive.clone();
        let new_auth_path: mmr::membership_proof::MembershipProof<H> =
            mmra_copy.append(new_chunk_digest.clone());

        let mut swbf_chunk_dictionary_updated = false;
        'outer: for chunk_index in chunk_indices_set.into_iter() {
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

    pub fn update_from_remove(
        &mut self,
        removal_record: &RemovalRecord<H>,
    ) -> Result<(), Box<dyn Error>> {
        // TODO: Make this function return boolean indicating if it was changed or not

        let hasher = H::new();
        let mut mutation_argument: Vec<(mmr::membership_proof::MembershipProof<H>, H::Digest)> =
            vec![];
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
            match self.target_chunks.dictionary.get_mut(chunk_index) {
                // Leaf exists in own membership proof
                Some((mp, chnk)) => {
                    for bit_index in bit_indices.iter() {
                        chnk.bits[(bit_index % CHUNK_SIZE as u128) as usize] = true;
                    }

                    mutation_argument.push((mp.to_owned(), chnk.hash::<H>(&hasher)));
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
                                target_chunk.bits[(bit_index % CHUNK_SIZE as u128) as usize] = true;
                            }

                            mutation_argument
                                .push((mp.to_owned(), target_chunk.hash::<H>(&hasher)));
                        }
                    };
                }
            };
        }

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

        mmr::membership_proof::MembershipProof::batch_update_from_batch_leaf_mutation(
            &mut own_membership_proofs_copy,
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

#[cfg(test)]
mod chunk_tests {
    use crate::shared_math::traits::IdentityValues;

    use super::*;

    #[test]
    fn chunk_hashpreimage_test() {
        let zero_chunk = Chunk {
            bits: [false; CHUNK_SIZE],
        };
        let zero_chunk_hash_preimage = zero_chunk.hash_preimage();
        assert_eq!(
            Chunk::get_hashpreimage_length(),
            zero_chunk_hash_preimage.len()
        );
        for elem in zero_chunk_hash_preimage {
            assert!(elem.is_zero());
        }

        let mut one_one = Chunk {
            bits: [false; CHUNK_SIZE],
        };
        one_one.bits[63] = true;
        let one_one_preimage = one_one.hash_preimage();
        assert_eq!(Chunk::get_hashpreimage_length(), one_one_preimage.len());
        assert!(one_one_preimage[0].is_zero());
        assert!(one_one_preimage[1].is_one());
        for i in 2..Chunk::get_hashpreimage_length() {
            assert!(one_one_preimage[i].is_zero());
        }

        let mut two_ones = Chunk {
            bits: [false; CHUNK_SIZE],
        };
        two_ones.bits[63] = true;
        two_ones.bits[64] = true;
        let two_ones_preimage = two_ones.hash_preimage();
        assert!(two_ones_preimage[0].is_zero());
        assert_eq!(3, two_ones_preimage[1].value());
        for i in 2..Chunk::get_hashpreimage_length() {
            assert!(two_ones_preimage[i].is_zero());
        }
    }
}

#[cfg(test)]
mod accumulation_scheme_tests {
    use crate::{
        shared_math::{
            rescue_prime_xlix::{
                neptune_params, RescuePrimeXlix, RP_DEFAULT_OUTPUT_SIZE, RP_DEFAULT_WIDTH,
            },
            traits::GetRandomElements,
        },
        util_types::{
            blake3_wrapper,
            simple_hasher::{Hasher, RescuePrimeProduction},
        },
    };
    use rand::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};

    use super::*;

    #[test]
    fn init_test() {
        SetCommitment::<RescuePrimeProduction>::default();
    }

    #[test]
    fn verify_future_bits_test() {
        // Ensure that `verify` does not crash when given a membership proof
        // that represents a future addition to the AOCL.
        let mut mutator_set = SetCommitment::<RescuePrimeXlix<RP_DEFAULT_WIDTH>>::default();
        let empty_mutator_set = SetCommitment::<RescuePrimeXlix<RP_DEFAULT_WIDTH>>::default();
        let hasher: RescuePrimeXlix<RP_DEFAULT_WIDTH> = neptune_params();
        let mut prng = thread_rng();
        for _ in 0..2 * BATCH_SIZE + 2 {
            let item: Vec<BFieldElement> = hasher.hash(
                &BFieldElement::random_elements(3, &mut prng),
                RP_DEFAULT_OUTPUT_SIZE,
            );
            let randomness: Vec<BFieldElement> = hasher.hash(
                &BFieldElement::random_elements(3, &mut prng),
                RP_DEFAULT_OUTPUT_SIZE,
            );

            let addition_record: AdditionRecord<RescuePrimeXlix<RP_DEFAULT_WIDTH>> =
                mutator_set.commit(&item, &randomness);
            let membership_proof: MembershipProof<RescuePrimeXlix<RP_DEFAULT_WIDTH>> =
                mutator_set.prove(&item, &randomness);
            mutator_set.add(&addition_record);
            assert!(mutator_set.verify(&item, &membership_proof));

            // Verify that a future membership proof returns false and does not crash
            assert!(!empty_mutator_set.verify(&item, &membership_proof));
        }
    }

    #[test]
    fn test_membership_proof_update_from_add() {
        let mut mutator_set = SetCommitment::<RescuePrimeXlix<RP_DEFAULT_WIDTH>>::default();
        let hasher: RescuePrimeXlix<RP_DEFAULT_WIDTH> = neptune_params();
        let own_item: Vec<BFieldElement> =
            hasher.hash(&vec![BFieldElement::new(1215)], RP_DEFAULT_OUTPUT_SIZE);
        let randomness: Vec<BFieldElement> =
            hasher.hash(&vec![BFieldElement::new(1776)], RP_DEFAULT_OUTPUT_SIZE);

        let addition_record: AdditionRecord<RescuePrimeXlix<RP_DEFAULT_WIDTH>> =
            mutator_set.commit(&own_item, &randomness);
        let mut membership_proof: MembershipProof<RescuePrimeXlix<RP_DEFAULT_WIDTH>> =
            mutator_set.prove(&own_item, &randomness);
        mutator_set.add(&addition_record);

        // Update membership proof with add operation. Verify that it has changed, and that it now fails to verify.
        let new_item: Vec<BFieldElement> =
            hasher.hash(&vec![BFieldElement::new(1648)], RP_DEFAULT_OUTPUT_SIZE);
        let new_randomness: Vec<BFieldElement> =
            hasher.hash(&vec![BFieldElement::new(1807)], RP_DEFAULT_OUTPUT_SIZE);
        let new_addition_record: AdditionRecord<RescuePrimeXlix<RP_DEFAULT_WIDTH>> =
            mutator_set.commit(&new_item, &new_randomness);
        let original_membership_proof: MembershipProof<RescuePrimeXlix<RP_DEFAULT_WIDTH>> =
            membership_proof.clone();
        let changed_mp = match membership_proof.update_from_addition(
            &own_item,
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
            mutator_set.verify(&own_item, &original_membership_proof),
            "Original membership proof must verify prior to addition"
        );
        assert!(
            !mutator_set.verify(&own_item, &membership_proof),
            "New membership proof must fail to verify prior to addition"
        );

        // Insert the new element into the mutator set, then verify that the membership proof works and
        // that the original membership proof is invalid.
        mutator_set.add(&new_addition_record);
        assert!(
            !mutator_set.verify(&own_item, &original_membership_proof),
            "Original membership proof must fail to verify after addition"
        );
        assert!(
            mutator_set.verify(&own_item, &membership_proof),
            "New membership proof must verify after addition"
        );
    }

    #[test]
    fn membership_proof_updating_from_add_pbt() {
        type Hasher = blake3::Hasher;
        let mut rng = ChaCha20Rng::from_seed(
            vec![vec![0, 1, 4, 33], vec![0; 28]]
                .concat()
                .try_into()
                .unwrap(),
        );

        let mut mutator_set = SetCommitment::<Hasher>::default();
        let hasher: Hasher = blake3::Hasher::new();

        let num_additions = rng.gen_range(0..=100i32);
        println!(
            "running multiple additions test for {} additions",
            num_additions
        );

        let mut membership_proofs_and_items: Vec<(
            MembershipProof<Hasher>,
            blake3_wrapper::Blake3Hash,
        )> = vec![];
        for i in 0..num_additions {
            println!("loop iteration {}", i);
            let item: blake3_wrapper::Blake3Hash = hasher.hash(
                &(0..3)
                    .map(|_| BFieldElement::new(rng.next_u64()))
                    .collect::<Vec<_>>(),
            );
            let randomness = hasher.hash(
                &(0..3)
                    .map(|_| BFieldElement::new(rng.next_u64()))
                    .collect::<Vec<_>>(),
            );

            let addition_record = mutator_set.commit(&item, &randomness);
            let membership_proof = mutator_set.prove(&item, &randomness);

            // Update all membership proofs
            for (mp, item) in membership_proofs_and_items.iter_mut() {
                let original_mp = mp.clone();
                let changed_res = mp.update_from_addition(item, &mutator_set, &addition_record);
                assert!(changed_res.is_ok());

                // verify that the boolean returned value from the updater method is set correctly
                assert_eq!(changed_res.unwrap(), original_mp != *mp);
            }

            // Add the element
            assert!(!mutator_set.verify(&item, &membership_proof));
            mutator_set.add(&addition_record);
            assert!(mutator_set.verify(&item, &membership_proof));
            membership_proofs_and_items.push((membership_proof, item));

            // Verify that all membership proofs work
            assert!(membership_proofs_and_items
                .clone()
                .into_iter()
                .all(|(mp, item)| mutator_set.verify(&item.into(), &mp)));
        }
    }

    #[test]
    fn test_add_and_prove() {
        let mut mutator_set = SetCommitment::<RescuePrimeXlix<RP_DEFAULT_WIDTH>>::default();
        let hasher: RescuePrimeXlix<RP_DEFAULT_WIDTH> = neptune_params();
        let item0: Vec<BFieldElement> =
            hasher.hash(&vec![BFieldElement::new(1215)], RP_DEFAULT_OUTPUT_SIZE);
        let randomness0: Vec<BFieldElement> =
            hasher.hash(&vec![BFieldElement::new(1776)], RP_DEFAULT_OUTPUT_SIZE);

        let addition_record = mutator_set.commit(&item0, &randomness0);
        let membership_proof = mutator_set.prove(&item0, &randomness0);

        assert!(!mutator_set.verify(&item0, &membership_proof));

        mutator_set.add(&addition_record);

        assert!(mutator_set.verify(&item0, &membership_proof));

        // Insert a new item and verify that this still works
        let item1: Vec<BFieldElement> =
            hasher.hash(&vec![BFieldElement::new(1846)], RP_DEFAULT_OUTPUT_SIZE);
        let randomness1: Vec<BFieldElement> =
            hasher.hash(&vec![BFieldElement::new(2009)], RP_DEFAULT_OUTPUT_SIZE);
        let addition_record = mutator_set.commit(&item1, &randomness1);
        let membership_proof = mutator_set.prove(&item1, &randomness1);
        assert!(!mutator_set.verify(&item1, &membership_proof));
        mutator_set.add(&addition_record);
        assert!(mutator_set.verify(&item1, &membership_proof));

        // Insert ~2*BATCH_SIZE  more elements and
        // verify that it works throughout. The reason we insert this many
        // is that we want to make sure that the window slides into a new
        // position.
        let mut prng = thread_rng();
        for _ in 0..2 * BATCH_SIZE + 4 {
            let item: Vec<BFieldElement> = hasher.hash(
                &BFieldElement::random_elements(2, &mut prng),
                RP_DEFAULT_OUTPUT_SIZE,
            );
            let randomness: Vec<BFieldElement> = hasher.hash(
                &BFieldElement::random_elements(2, &mut prng),
                RP_DEFAULT_OUTPUT_SIZE,
            );
            let addition_record = mutator_set.commit(&item, &randomness);
            let membership_proof = mutator_set.prove(&item, &randomness);
            assert!(!mutator_set.verify(&item, &membership_proof));
            mutator_set.add(&addition_record);
            assert!(mutator_set.verify(&item, &membership_proof));
        }
    }

    #[test]
    fn test_multiple_adds() {
        // set up rng
        let mut rng = ChaCha20Rng::from_seed(
            vec![vec![0, 1, 4, 33], vec![0; 28]]
                .concat()
                .try_into()
                .unwrap(),
        );

        type Hasher = blake3::Hasher;
        type Digest = blake3_wrapper::Blake3Hash;
        let hasher = Hasher::new();
        let mut mutator_set = SetCommitment::<Hasher>::default();

        let num_additions = 65;

        let mut items_and_membership_proofs: Vec<(Digest, MembershipProof<Hasher>)> = vec![];

        for _ in 0..num_additions {
            let new_item = hasher.hash(
                &(0..3)
                    .map(|_| BFieldElement::new(rng.next_u64()))
                    .collect::<Vec<_>>(),
            );
            let randomness = hasher.hash(
                &(0..3)
                    .map(|_| BFieldElement::new(rng.next_u64()))
                    .collect::<Vec<_>>(),
            );

            let addition_record = mutator_set.commit(&new_item, &randomness);
            let membership_proof = mutator_set.prove(&new_item, &randomness);

            // Update *all* membership proofs with newly added item
            for (updatee_item, mp) in items_and_membership_proofs.iter_mut() {
                let original_mp = mp.clone();
                assert!(mutator_set.verify(updatee_item, mp));
                let changed_res =
                    mp.update_from_addition(&updatee_item, &mutator_set, &addition_record);
                assert!(changed_res.is_ok());

                // verify that the boolean returned value from the updater method is set correctly
                assert_eq!(changed_res.unwrap(), original_mp != *mp);
            }

            mutator_set.add(&addition_record);
            assert!(mutator_set.verify(&new_item, &membership_proof));

            for j in 0..items_and_membership_proofs.len() {
                let (old_item, mp) = &items_and_membership_proofs[j];
                assert!(mutator_set.verify(&old_item, &mp))
            }

            items_and_membership_proofs.push((new_item, membership_proof));
        }

        // Verify all membership proofs
        for k in 0..items_and_membership_proofs.len() {
            assert!(mutator_set.verify(
                &items_and_membership_proofs[k].0,
                &items_and_membership_proofs[k].1,
            ));
        }

        // Remove items from MS, and verify correct updating of membership proof
        for i in 0..num_additions {
            for k in i..items_and_membership_proofs.len() {
                assert!(mutator_set.verify(
                    &items_and_membership_proofs[k].0,
                    &items_and_membership_proofs[k].1,
                ));
            }
            let (item, mp) = items_and_membership_proofs[i].clone();

            assert!(mutator_set.verify(&item, &mp));

            // generate removal record
            let mut removal_record: RemovalRecord<Hasher> = mutator_set.drop(&item.into(), &mp);
            assert!(removal_record.validate(&mutator_set));
            for k in i..items_and_membership_proofs.len() {
                assert!(mutator_set.verify(
                    &items_and_membership_proofs[k].0,
                    &items_and_membership_proofs[k].1,
                ));
            }

            // update membership proofs
            for j in (i + 1)..num_additions {
                assert!(mutator_set.verify(
                    &items_and_membership_proofs[j].0,
                    &items_and_membership_proofs[j].1
                ));
                assert!(removal_record.validate(&mutator_set));
                let update_res = items_and_membership_proofs[j]
                    .1
                    .update_from_remove(&removal_record.clone());
                assert!(update_res.is_ok());
                assert!(removal_record.validate(&mutator_set));
            }

            // remove item from set
            mutator_set.remove(&mut removal_record);
            assert!(!mutator_set.verify(&item.into(), &mp));

            for k in (i + 1)..items_and_membership_proofs.len() {
                assert!(mutator_set.verify(
                    &items_and_membership_proofs[k].0,
                    &items_and_membership_proofs[k].1,
                ));
            }
        }
    }
}
