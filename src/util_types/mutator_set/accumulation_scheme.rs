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
pub const NUM_TRIALS: usize = 2; //TODO: Change to 160 in production;

pub struct SetCommitment<H: simple_hasher::Hasher> {
    aocl: MmrAccumulator<H>,
    swbf_inactive: MmrAccumulator<H>,
    swbf_active: [bool; WINDOW_SIZE],
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Chunk {
    bits: [bool; CHUNK_SIZE],
}

impl Chunk {
    pub fn hash<H: simple_hasher::Hasher<Digest = Vec<BFieldElement>>>(
        &self,
    ) -> Vec<BFieldElement> {
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
        hasher.hash(&ret)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ChunkDictionary<H: simple_hasher::Hasher> {
    // (bloom filter bit index, membership proof for the whole chunk to which bit belongs, chunk value)
    dictionary: Vec<(u128, mmr::membership_proof::MembershipProof<H>, Chunk)>,
}

impl<H: simple_hasher::Hasher> ChunkDictionary<H> {
    fn default() -> ChunkDictionary<H> {
        Self { dictionary: vec![] }
    }
}

pub struct AdditionRecord<H: simple_hasher::Hasher<Digest = Vec<BFieldElement>>> {
    commitment: H::Digest,
    aocl_snapshot: MmrAccumulator<H>,
}

impl<H: simple_hasher::Hasher<Digest = Vec<BFieldElement>>> AdditionRecord<H> {
    pub fn has_matching_aocl(&self, aocl_accumulator: &MmrAccumulator<H>) -> bool {
        self.aocl_snapshot.count_leaves() == aocl_accumulator.count_leaves()
            && self.aocl_snapshot.get_peaks() == aocl_accumulator.get_peaks()
    }
}

impl<H: simple_hasher::Hasher<Digest = Vec<BFieldElement>>> SetCommitment<H>
where
    u128: ToDigest<<H as simple_hasher::Hasher>::Digest>,
{
    pub fn default() -> Self {
        Self {
            aocl: MmrAccumulator::new(vec![]),
            swbf_inactive: MmrAccumulator::new(vec![]),
            swbf_active: [false; WINDOW_SIZE as usize],
        }
    }

    /**
     * commit
     * Generates an addition record from an item and explicit random-
     * ness. The addition record is itself a commitment to the item,
     * but tailored to adding the item to the mutator set in its
     * current state.
     */
    pub fn commit(&self, item: &H::Digest, randomness: &H::Digest) -> AdditionRecord<H> {
        let hasher = H::new();
        let canonical_commitment = hasher.hash_pair(item, randomness);

        AdditionRecord {
            commitment: canonical_commitment,
            aocl_snapshot: self.aocl.clone(),
        }
    }

    /**
     * add
     * Updates the set-commitment with an addition record. The new
     * commitment represents the set
     *          S union {c} ,
     * where S is the set represented by the old
     * commitment and c is the commitment to the new item AKA the
     * *addition record*.
     */
    pub fn add(&mut self, addition_record: &AdditionRecord<H>) {
        // verify aocl snapshot
        if !addition_record.has_matching_aocl(&self.aocl) {
            panic!("Addition record has aocl snapshot that does not match with the AOCL it is being added to.")
        }

        // add to list
        let item_index = self.aocl.count_leaves();
        self.aocl.append(addition_record.commitment.to_owned()); // ignore auth path

        // if window slides, update filter
        if item_index % BATCH_SIZE as u128 == 0 {
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

            let chunk_digest = chunk.hash::<H>();
            self.swbf_inactive.append(chunk_digest); // ignore auth path
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
        let item_index = self.aocl.count_leaves();
        let batch_index = item_index / BATCH_SIZE as u128;
        let aocl_auth_path = self.aocl.clone().append(item_commitment);

        let mut target_chunks: ChunkDictionary<H> = ChunkDictionary::default();
        // if window slides, filter will be updated
        if (1 + item_index) % BATCH_SIZE as u128 == 0 {
            let chunk: Chunk = Chunk {
                bits: self.swbf_active[..CHUNK_SIZE].try_into().unwrap(),
            };
            let chunk_digest = chunk.hash::<H>();
            let new_chunk_path = self.swbf_inactive.clone().append(chunk_digest);

            // prepare swbf MMR authentication paths
            let timestamp: Vec<BFieldElement> = (item_index as u128).to_digest();
            let rhs = hasher.hash_pair(&timestamp, randomness);
            for i in 0..NUM_TRIALS {
                let counter: Vec<BFieldElement> = (i as u128).to_digest();
                let pseudorandomness = hasher.hash_pair(&counter, &rhs);
                let bit_index = hasher.sample_index_not_power_of_two(&pseudorandomness, WINDOW_SIZE)
                    as u128
                    + batch_index * CHUNK_SIZE as u128;

                // compute the index of the boundary between inactive and active parts
                let window_start: u128 = //.
                    ((1 + item_index) / BATCH_SIZE as u128) // which batch
                     * CHUNK_SIZE as u128; // # bits per bach

                // if index lies in inactive part of filter, add an mmr auth path
                if bit_index < window_start {
                    target_chunks
                        .dictionary
                        .push((bit_index, new_chunk_path.clone(), chunk));
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
        // if 0 elements were added, no proof can be valid
        if self.aocl.count_leaves() == 0 {
            return false;
        }

        println!("---");

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
        let timestamp: Vec<BFieldElement> = (item_index).to_digest();
        let item_batch_index = item_index / BATCH_SIZE as u128;
        let rhs = hasher.hash_pair(&timestamp, &membership_proof.randomness);
        for i in 0..NUM_TRIALS {
            // get index
            let counter: Vec<BFieldElement> = (i as u128).to_digest();
            let pseudorandomness = hasher.hash_pair(&counter, &rhs);

            let bit_index = hasher.sample_index_not_power_of_two(&pseudorandomness, WINDOW_SIZE)
                as u128
                + item_batch_index * CHUNK_SIZE as u128;

            // locate the bit index relative to the current window
            let current_batch_index: u128 = (self.aocl.count_leaves() - 1) / BATCH_SIZE as u128;
            let window_start = current_batch_index * CHUNK_SIZE as u128;
            let window_stop = window_start + WINDOW_SIZE as u128;
            let relative_index = bit_index - window_start;
            // if bit index is left of the window
            if bit_index < window_start {
                // verify mmr auth path
                let matching_entries: Vec<&(
                    u128,
                    mmr::membership_proof::MembershipProof<H>,
                    Chunk,
                )> = membership_proof
                    .target_chunks
                    .dictionary
                    .iter()
                    .filter(|ch| ch.0 == bit_index)
                    .collect();
                if matching_entries.len() != 1 {
                    entries_in_dictionary = false;
                    continue;
                }
                let (valid_auth_path, _) = matching_entries[0].1.verify(
                    &self.swbf_inactive.get_peaks(),
                    &matching_entries[0].2.hash::<H>(),
                    self.swbf_inactive.count_leaves(),
                );
                all_auth_paths_are_valid = all_auth_paths_are_valid && valid_auth_path;

                // verify that bit is possibly unset
                if !matching_entries[0].2.bits[relative_index as usize] {
                    has_unset_bits = true;
                }
            } else if bit_index >= window_stop {
                no_future_bits = false;
            }
            // if bit is in the active part of the filter
            else if !self.swbf_active[relative_index as usize] {
                has_unset_bits = true;
            }
        }

        println!("is_aocl_member: {}", is_aocl_member);
        println!("entries_in_dictionary: {}", entries_in_dictionary);
        println!("all_auth_paths_are_valid: {}", all_auth_paths_are_valid);
        println!("no_future_bits: {}", no_future_bits);
        println!("has_unset_bits: {}", has_unset_bits);

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

impl<H: simple_hasher::Hasher<Digest = Vec<BFieldElement>>> MembershipProof<H>
where
    u128: ToDigest<<H as simple_hasher::Hasher>::Digest>,
{
    /**
     * update_from_addition
     * Updates a membership proof in anticipation of an addition to the set.
     */
    pub fn update_from_addition(
        &mut self,
        mutator_set: &SetCommitment<H>,
        addition_record: &AdditionRecord<H>,
    ) {
        // Update AOCL MMR membership proof
        self.auth_path_aocl.update_from_append(
            mutator_set.aocl.count_leaves(),
            &addition_record.commitment,
            &mutator_set.aocl.get_peaks(),
        );

        // Update chunks dictionary if window slides
        // Check that window slides
        if (mutator_set.aocl.count_leaves() + 1) % BATCH_SIZE as u128 != 0 {
            return;
        }

        // Window slides
        let batch_index = mutator_set.aocl.count_leaves() / BATCH_SIZE as u128;
        let old_window_start = batch_index * CHUNK_SIZE as u128;
        let new_window_start = (batch_index + 1) * CHUNK_SIZE as u128;
        let hasher = H::new();
        let timestamp: Vec<BFieldElement> = (self.auth_path_aocl.data_index).to_digest();
        let rhs = hasher.hash_pair(&timestamp, &self.randomness);
        for i in 0..NUM_TRIALS {
            // get index
            let counter: Vec<BFieldElement> = (i as u128).to_digest();
            let pseudorandomness = hasher.hash_pair(&counter, &rhs);

            let bit_index = hasher.sample_index_not_power_of_two(&pseudorandomness, WINDOW_SIZE)
                as u128
                + self.auth_path_aocl.data_index * CHUNK_SIZE as u128;

            let chunk = Chunk {
                bits: mutator_set.swbf_active[0..CHUNK_SIZE].try_into().unwrap(),
            };

            // if bit index is in dictionary, update auth path
            if bit_index < old_window_start {
                self.target_chunks
                    .dictionary
                    .iter_mut()
                    .for_each(|(i, ap, _c)| {
                        // TODO: This if condition will only be true for *one* i, so we can probably
                        // find a way to short-circuit this iterator, or change the datatype of ChunkDictionary
                        // to a hash map
                        if *i == bit_index {
                            ap.update_from_append(
                                batch_index,
                                &chunk.hash::<H>(),
                                &mutator_set.swbf_inactive.get_peaks(),
                            );
                        }
                    });
                continue;
            }

            // if bit is in the part that is becoming inactive, add a dictionary entry
            if old_window_start < bit_index && bit_index <= new_window_start {
                let auth_path = mutator_set.swbf_inactive.clone().append(chunk.hash::<H>());
                self.target_chunks
                    .dictionary
                    .push((bit_index, auth_path, chunk));
                continue;
            }

            // if bit is still in active window, do nothing
        }

        // TODO: Consider if we want a return value indicating if membership proof has changed
    }
}

#[cfg(test)]
mod accumulation_scheme_tests {

    use crate::{
        shared_math::rescue_prime_xlix::{
            neptune_params, RescuePrimeXlix, RP_DEFAULT_OUTPUT_SIZE, RP_DEFAULT_WIDTH,
        },
        util_types::simple_hasher::RescuePrimeProduction,
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
        let item: Vec<BFieldElement> =
            hasher.hash(&vec![BFieldElement::new(1215)], RP_DEFAULT_OUTPUT_SIZE);
        let randomness: Vec<BFieldElement> =
            hasher.hash(&vec![BFieldElement::new(1776)], RP_DEFAULT_OUTPUT_SIZE);

        let addition_record: AdditionRecord<RescuePrimeXlix<RP_DEFAULT_WIDTH>> =
            mutator_set.commit(&item, &randomness);
        let mut membership_proof: MembershipProof<RescuePrimeXlix<RP_DEFAULT_WIDTH>> =
            mutator_set.prove(&item, &randomness);
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
        membership_proof.update_from_addition(&mutator_set, &new_addition_record);
        assert_ne!(
            original_membership_proof.auth_path_aocl,
            membership_proof.auth_path_aocl
        );
        assert!(
            mutator_set.verify(&item, &original_membership_proof),
            "Original membership proof must verify prior to addition"
        );
        assert!(
            !mutator_set.verify(&item, &membership_proof),
            "New membership proof must fail to verify prior to addition"
        );

        // Insert the new element into the mutator set, then verify that the membership proof works and
        // that the original membership proof is invalid.
        mutator_set.add(&new_addition_record);
        assert!(
            !mutator_set.verify(&item, &original_membership_proof),
            "Original membership proof must fail to verify after addition"
        );
        assert!(
            mutator_set.verify(&item, &membership_proof),
            "New membership proof must verify after addition"
        );
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

        let mut mutator_set = SetCommitment::<RescuePrimeXlix<RP_DEFAULT_WIDTH>>::default();
        let hasher: RescuePrimeXlix<RP_DEFAULT_WIDTH> = neptune_params();

        let num_additions = rng.gen_range(0..=1000);
        println!(
            "running multiple additions test for {} additions",
            num_additions
        );

        for i in 0..num_additions {
            println!("loop iteration {}", i);
            let item: Vec<BFieldElement> = hasher.hash(
                &(0..3)
                    .map(|_| BFieldElement::new(rng.next_u64()))
                    .collect::<Vec<_>>(),
                RP_DEFAULT_OUTPUT_SIZE,
            );
            let randomness: Vec<BFieldElement> = hasher.hash(
                &(0..3)
                    .map(|_| BFieldElement::new(rng.next_u64()))
                    .collect::<Vec<_>>(),
                RP_DEFAULT_OUTPUT_SIZE,
            );

            let addition_record = mutator_set.commit(&item, &randomness);
            let membership_proof = mutator_set.prove(&item, &randomness);

            assert!(!mutator_set.verify(&item, &membership_proof));

            mutator_set.add(&addition_record);

            assert!(mutator_set.verify(&item, &membership_proof));
        }
    }
}
