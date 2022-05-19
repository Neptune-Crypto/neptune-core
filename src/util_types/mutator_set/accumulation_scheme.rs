use std::collections::{HashMap, HashSet};

use itertools::Itertools;

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
    pub fn hash<H: simple_hasher::Hasher>(&self) -> H::Digest
    where
        Vec<BFieldElement>: ToDigest<H::Digest>,
    {
        let num_iterations = CHUNK_SIZE / 63;
        let mut ret: Vec<BFieldElement> = vec![];
        let mut acc: u64;
        for i in 0..num_iterations {
            acc = 0;
            for j in 0..63 {
                acc += if self.bits[i * 63 + j] { 1 << j } else { 0 };
            }
            ret.push(BFieldElement::new(acc));
        }
        if CHUNK_SIZE % 63 != 0 {
            acc = 0;
            for j in 0..CHUNK_SIZE % 63 {
                acc += if self.bits[num_iterations * 63 + j] {
                    1 << j
                } else {
                    0
                };
            }
            ret.push(BFieldElement::new(acc));
        }

        let hasher = H::new();
        hasher.hash(&ret.to_digest())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ChunkDictionary<H: simple_hasher::Hasher> {
    // {chunk index => (membership proof for the whole chunk to which bit belongs, chunk value)}
    dictionary: HashMap<u128, (mmr::membership_proof::MembershipProof<H>, Chunk)>,
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
}

impl<H: simple_hasher::Hasher> RemovalRecord<H>
where
    u128: ToDigest<<H as simple_hasher::Hasher>::Digest>,
    Vec<BFieldElement>: ToDigest<<H as simple_hasher::Hasher>::Digest>,
{
    pub fn validate(&self, mutator_set: &SetCommitment<H>) -> bool {
        self.target_chunks.dictionary.iter().all(|(i, (p, c))| {
            p.verify(
                &mutator_set.swbf_inactive.get_peaks(),
                &c.hash::<H>(),
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
        }
    }

    /// Generates an addition record from an item and explicit random-
    /// ness. The addition record is itself a commitment to the item,
    /// but tailored to adding the item to the mutator set in its
    /// current state.
    pub fn commit(&self, item: &H::Digest, randomness: &H::Digest) -> AdditionRecord<H> {
        let hasher = H::new();
        let canonical_commitment = hasher.hash_pair(item, randomness);

        AdditionRecord {
            commitment: canonical_commitment,
            aocl_snapshot: self.aocl.clone(),
        }
    }

    /// Helper function. Computes the bloom filter bit indices of the
    /// item, randomness, index triple.
    pub fn get_indices(item: &H::Digest, randomness: &H::Digest, index: u128) -> Vec<u128> {
        let hasher = H::new();
        let batch_index = index / BATCH_SIZE as u128;
        let timestamp: H::Digest = (index as u128).to_digest();
        let mut rhs = hasher.hash_pair(&timestamp, randomness);
        rhs = hasher.hash_pair(item, &rhs);
        let mut indices: Vec<u128> = vec![];
        for i in 0..NUM_TRIALS {
            let counter: H::Digest = (i as u128).to_digest();
            let pseudorandomness = hasher.hash_pair(&counter, &rhs);
            let bit_index = hasher.sample_index_not_power_of_two(&pseudorandomness, WINDOW_SIZE)
                as u128
                + batch_index * CHUNK_SIZE as u128;
            indices.push(bit_index);
        }

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
        let bit_indices = Self::get_indices(
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
        // verify aocl snapshot
        if !addition_record.has_matching_aocl(&self.aocl) {
            panic!("Addition record has aocl snapshot that does not match with the AOCL it is being added to.")
        }

        // add to list
        let item_index = self.aocl.count_leaves();
        self.aocl.append(addition_record.commitment.to_owned()); // ignore auth path

        // if window slides, update filter
        if Self::window_slides(item_index) {
            let chunk: Chunk = Chunk {
                bits: self.swbf_active[..CHUNK_SIZE].try_into().unwrap(),
            };

            // Move window to the right, equivalent to moving values inside window
            // to the left.
            for i in CHUNK_SIZE..WINDOW_SIZE {
                self.swbf_active[i - CHUNK_SIZE] = self.swbf_active[i];
            }

            for i in (WINDOW_SIZE - CHUNK_SIZE)..WINDOW_SIZE {
                self.swbf_active[i] = false;
            }

            let chunk_digest: H::Digest = chunk.hash::<H>();
            self.swbf_inactive.append(chunk_digest); // ignore auth path
        }
    }

    /// remove
    /// Updates the mutator set so as to remove the item determined by
    /// its removal record, which is updated also
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
        let all_leafs: Vec<_> = new_target_chunks
            .dictionary
            .values()
            .map(|(_p, c)| c.hash::<H>())
            .collect();
        for i in 0..all_membership_proofs.len() {
            let local_membership_proof = all_membership_proofs[i].clone();
            let local_leaf = all_leafs[i].clone();

            self.swbf_inactive
                .mutate_leaf(&local_membership_proof, &local_leaf);
            mmr::membership_proof::MembershipProof::batch_update_from_leaf_mutation(
                &mut all_membership_proofs,
                &local_membership_proof,
                &local_leaf,
            );
            assert!(
                local_membership_proof
                    .verify(
                        &self.swbf_inactive.get_peaks(),
                        &local_leaf,
                        self.swbf_inactive.count_leaves(),
                    )
                    .0
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
        let hasher = H::new();
        let item_commitment = hasher.hash_pair(item, randomness);

        // simulate adding to commitment list
        let new_item_index = self.aocl.count_leaves();
        let aocl_auth_path = self.aocl.clone().append(item_commitment);

        // get indices of bits to be set when item is removed
        let bit_indices = Self::get_indices(item, randomness, new_item_index);

        let mut target_chunks: ChunkDictionary<H> = ChunkDictionary::default();
        // if window slides, filter will be updated
        if Self::window_slides(new_item_index) {
            let chunk: Chunk = Chunk {
                bits: self.swbf_active[..CHUNK_SIZE].try_into().unwrap(),
            };
            let chunk_digest = chunk.hash::<H>();
            let new_chunk_path = self.swbf_inactive.clone().append(chunk_digest);

            // prepare swbf MMR authentication paths
            for bit_index in bit_indices {
                // compute the index of the boundary between inactive and active parts
                let window_start: u128 = //.
                    (new_item_index / BATCH_SIZE as u128) // which batch
                     * CHUNK_SIZE as u128; // # bits per bach

                // if index lies in inactive part of filter, add an mmr auth path
                if bit_index < window_start {
                    target_chunks.dictionary.insert(
                        bit_index / CHUNK_SIZE as u128,
                        (new_chunk_path.clone(), chunk),
                    );
                }
            }
        }

        // return membership proof
        MembershipProof {
            randomness: randomness.to_owned(),
            auth_path_aocl: aocl_auth_path,
            target_chunks,
        }
    }

    pub fn verify(&self, item: &H::Digest, membership_proof: &MembershipProof<H>) -> bool {
        // If data index does not exist in AOCL, return false
        if self.aocl.count_leaves() <= membership_proof.auth_path_aocl.data_index {
            return false;
        }

        // verify that a commitment to the item lives in the aocl mmr
        let hasher = H::new();
        let leaf = hasher.hash_pair(item, &membership_proof.randomness);
        let (is_aocl_member, _) = membership_proof.auth_path_aocl.verify(
            &self.aocl.get_peaks(),
            &leaf,
            self.aocl.count_leaves(),
        );

        // verify that some indicated bits in the swbf are unset
        let mut has_unset_bits = false;
        let mut entries_in_dictionary = true;
        let mut all_auth_paths_are_valid = true;
        let mut no_future_bits = true;
        let item_index = membership_proof.auth_path_aocl.data_index;

        // prepare parameters of inactive part
        let current_batch_index: u128 = (self.aocl.count_leaves() - 1) / BATCH_SIZE as u128;
        let window_start = current_batch_index * CHUNK_SIZE as u128;
        let window_stop = window_start + WINDOW_SIZE as u128;
        let bit_indices = Self::get_indices(item, &membership_proof.randomness, item_index);

        // get indices of bits to be set when item is removed
        for bit_index in bit_indices {
            // if bit index is left of the window
            if bit_index < window_start {
                // verify mmr auth path
                if !membership_proof
                    .target_chunks
                    .dictionary
                    .contains_key(&(bit_index / CHUNK_SIZE as u128))
                {
                    entries_in_dictionary = false;
                    continue;
                }

                let (mp, chunk): (mmr::membership_proof::MembershipProof<H>, Chunk) =
                    membership_proof.target_chunks.dictionary[&(bit_index / CHUNK_SIZE as u128)]
                        .clone();
                let (valid_auth_path, _) = mp.verify(
                    &self.swbf_inactive.get_peaks(),
                    &chunk.hash::<H>(),
                    self.swbf_inactive.count_leaves(),
                );

                all_auth_paths_are_valid = all_auth_paths_are_valid && valid_auth_path;

                // verify that bit is possibly unset
                let index_within_chunk = bit_index % CHUNK_SIZE as u128;
                if !chunk.bits[index_within_chunk as usize] {
                    has_unset_bits = true;
                }
                continue;
            }

            // Check whether bitindex is a future index, or in the active window
            if bit_index >= window_stop {
                no_future_bits = false;
            } else {
                let relative_index = bit_index - window_start;
                if !self.swbf_active[relative_index as usize] {
                    has_unset_bits = true;
                }
            }
        }

        // return verdict
        is_aocl_member
            && entries_in_dictionary
            && all_auth_paths_are_valid
            && no_future_bits
            && has_unset_bits
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MembershipProof<H: simple_hasher::Hasher> {
    randomness: H::Digest,
    auth_path_aocl: mmr::membership_proof::MembershipProof<H>,
    target_chunks: ChunkDictionary<H>,
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
    ) {
        assert!(self.auth_path_aocl.data_index < mutator_set.aocl.count_leaves());
        let new_item_index = mutator_set.aocl.count_leaves();
        let batch_index = new_item_index / BATCH_SIZE as u128;

        // Update AOCL MMR membership proof
        self.auth_path_aocl.update_from_append(
            mutator_set.aocl.count_leaves(),
            &addition_record.commitment,
            &mutator_set.aocl.get_peaks(),
        );

        // if window does not slide, we are done
        if !SetCommitment::<H>::window_slides(new_item_index) {
            return;
        }

        // window does slide
        assert!(SetCommitment::<H>::window_slides(new_item_index));
        let old_window_start = (batch_index - 1) * CHUNK_SIZE as u128;
        let new_window_start = batch_index * CHUNK_SIZE as u128;
        let bit_indices = SetCommitment::<H>::get_indices(
            own_item,
            &self.randomness,
            self.auth_path_aocl.data_index,
        );
        let new_chunk = Chunk {
            bits: mutator_set.swbf_active[0..CHUNK_SIZE].try_into().unwrap(),
        };
        let new_chunk_digest: H::Digest = new_chunk.hash::<H>();
        let mut mmra_copy = mutator_set.swbf_inactive.clone();
        let new_auth_path: mmr::membership_proof::MembershipProof<H> =
            mmra_copy.append(new_chunk_digest.clone());

        for bit_index in bit_indices {
            // if bit index is in dictionary, update auth path
            if bit_index < old_window_start {
                let chunk_index = bit_index / CHUNK_SIZE as u128;
                let mp = match self.target_chunks.dictionary.get_mut(&chunk_index) {
                    None => continue,
                    Some((m, _chnk)) => m,
                };
                mp.update_from_append(
                    mutator_set.swbf_inactive.count_leaves(),
                    &new_chunk_digest,
                    &mutator_set.swbf_inactive.get_peaks(),
                );
            }

            // if bit is in the part that is becoming inactive, add a dictionary entry
            if old_window_start <= bit_index && bit_index < new_window_start {
                // generate dictionary entry
                let chunk_index = bit_index / CHUNK_SIZE as u128;

                // assert that dictionary entry does not exist already
                // because if it does then there's nothing left to do
                if self.target_chunks.dictionary.contains_key(&chunk_index) {
                    continue;
                }

                let mut batch_indices_in_dictionary = self.target_chunks.dictionary.keys();
                assert!(
                    !batch_indices_in_dictionary.contains(&(bit_index / CHUNK_SIZE as u128)),
                    "Unexpected duplicate bit index found in target chunks dictionary: {}",
                    bit_index
                );

                // add dictionary entry
                self.target_chunks
                    .dictionary
                    .insert(chunk_index, (new_auth_path.clone(), new_chunk));
            }

            // if bit is still in active window, do nothing
        }

        // TODO: Consider if we want a return value indicating if membership proof has changed
    }

    pub fn update_from_remove(&mut self, removal_record: &RemovalRecord<H>) {
        // set bits in own chunks
        // for all chunks in the chunk dictionary
        let mut self_updated_chunk_indices: HashSet<u128> = HashSet::new();
        for (own_chunk_index, (_, own_chunk)) in self.target_chunks.dictionary.iter_mut() {
            // for all bit indices in removal record
            for bit_index in removal_record.bit_indices.iter() {
                // if chunk indices match, set bit
                if bit_index / CHUNK_SIZE as u128 == *own_chunk_index {
                    own_chunk.bits[(bit_index % CHUNK_SIZE as u128) as usize] = true;
                    self_updated_chunk_indices.insert(*own_chunk_index);
                }
            }
        }

        // update membership proofs
        let mut own_membership_proofs_copy: Vec<mmr::membership_proof::MembershipProof<H>> = self
            .target_chunks
            .dictionary
            .iter()
            .map(|(_, (p, _))| p.clone())
            .collect();
        let mut modified_leaf_proofs = own_membership_proofs_copy.clone();
        let mut modified_leafs: Vec<_> = self
            .target_chunks
            .dictionary
            .iter()
            .map(|(_, (_, c))| c.hash::<H>())
            .collect();

        // Find path update data that is not contained in the membership proof
        // but only in the removal record
        for bit_index in removal_record.bit_indices.iter() {
            if !self_updated_chunk_indices.contains(&(bit_index / CHUNK_SIZE as u128))
                && removal_record
                    .target_chunks
                    .dictionary
                    .iter()
                    .find(|(i, _)| **i == bit_index / CHUNK_SIZE as u128)
                    .is_some()
            {
                // Algorithms are like sausages. It is best not to see them being made.
                println!("target found for bit_index = {} !!", bit_index);
                let mut target_leaf = removal_record
                    .target_chunks
                    .dictionary
                    .iter()
                    .find(|(i, _)| **i == bit_index / CHUNK_SIZE as u128)
                    .unwrap()
                    .1
                     .1
                    .clone();
                let target_chunk_index = *removal_record
                    .target_chunks
                    .dictionary
                    .iter()
                    .find(|(i, _)| **i == bit_index / CHUNK_SIZE as u128)
                    .unwrap()
                    .0;
                for bit_index in removal_record
                    .bit_indices
                    .iter()
                    .filter(|i| target_chunk_index == *i / CHUNK_SIZE as u128)
                {
                    target_leaf.bits[*bit_index as usize % CHUNK_SIZE] = true;
                }
                let target_ap = removal_record
                    .target_chunks
                    .dictionary
                    .iter()
                    .find(|(i, _)| **i == bit_index / CHUNK_SIZE as u128)
                    .unwrap()
                    .1
                     .0
                    .clone();
                modified_leaf_proofs.push(target_ap);
                modified_leafs.push(target_leaf.hash::<H>());

                self_updated_chunk_indices.insert(bit_index / CHUNK_SIZE as u128);
            }
        }

        mmr::membership_proof::MembershipProof::batch_update_from_batch_leaf_mutation(
            &mut own_membership_proofs_copy,
            &modified_leaf_proofs,
            &modified_leafs,
        );
        for i in 0..own_membership_proofs_copy.len() {
            let mp = own_membership_proofs_copy[i].clone();
            let mut target = self
                .target_chunks
                .dictionary
                .get_mut(&mp.data_index)
                .unwrap();
            target.0 = mp;
        }

        // bits in the active part of the filter
        // will be set when change is applied to mutator set
        // no need to anticipate here
    }
}

#[cfg(test)]
mod accumulation_scheme_tests {
    use crate::{
        shared_math::rescue_prime_xlix::{
            neptune_params, RescuePrimeXlix, RP_DEFAULT_OUTPUT_SIZE, RP_DEFAULT_WIDTH,
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
        membership_proof.update_from_addition(&own_item, &mutator_set, &new_addition_record);
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
            for mp in membership_proofs_and_items.iter_mut() {
                mp.0.update_from_addition(&mp.1.into(), &mutator_set, &addition_record);
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
    fn test_add() {
        let mut mutator_set = SetCommitment::<RescuePrimeXlix<RP_DEFAULT_WIDTH>>::default();
        let hasher: RescuePrimeXlix<RP_DEFAULT_WIDTH> = neptune_params();
        let item: Vec<BFieldElement> =
            hasher.hash(&vec![BFieldElement::new(1215)], RP_DEFAULT_OUTPUT_SIZE);
        let randomness: Vec<BFieldElement> =
            hasher.hash(&vec![BFieldElement::new(1776)], RP_DEFAULT_OUTPUT_SIZE);

        let addition_record = mutator_set.commit(&item, &randomness);
        let membership_proof = mutator_set.prove(&item, &randomness);

        assert!(false == mutator_set.verify(&item, &membership_proof));

        mutator_set.add(&addition_record);

        assert!(true == mutator_set.verify(&item, &membership_proof));
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
        for i in 0..num_additions {
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
            let mut j = 0;
            for (updatee_item, mp) in items_and_membership_proofs.iter_mut() {
                assert!(mutator_set.verify(updatee_item, mp));
                mp.update_from_addition(&updatee_item, &mutator_set, &addition_record);
                j += 1;
            }

            mutator_set.add(&addition_record);
            assert!(mutator_set.verify(&new_item, &membership_proof));

            for j in 0..items_and_membership_proofs.len() {
                let (old_item, mp) = &items_and_membership_proofs[j];
                assert!(mutator_set.verify(&old_item, &mp))
            }

            items_and_membership_proofs.push((new_item, membership_proof));
        }

        for k in 0..items_and_membership_proofs.len() {
            assert!(mutator_set.verify(
                &items_and_membership_proofs[k].0,
                &items_and_membership_proofs[k].1,
            ));
        }

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
                items_and_membership_proofs[j]
                    .1
                    .update_from_remove(&removal_record.clone());
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
