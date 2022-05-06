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
pub const NUM_TRIALS: usize = 160;

pub struct SetCommitment<H: simple_hasher::Hasher> {
    aocl: MmrAccumulator<H>,
    swbf_inactive: MmrAccumulator<H>,
    swbf_active: [bool; WINDOW_SIZE],
}

#[derive(Clone, Copy, Debug)]
pub struct Chunk {
    bits: [bool; CHUNK_SIZE],
}

impl ToDigest<Vec<BFieldElement>> for Chunk {
    fn to_digest(&self) -> Vec<BFieldElement> {
        let num_iterations = (CHUNK_SIZE / 63);
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
        }

        ret
    }
}

impl Chunk {
    pub fn hash(&self) -> Vec<BFieldElement> {
        self.to_digest()
    }
}

#[derive(Clone, Debug)]
pub struct ChunkDictionary<H: simple_hasher::Hasher> {
    dictionary: Vec<(u128, mmr::membership_proof::MembershipProof<H>, Chunk)>,
}

impl<H: simple_hasher::Hasher> ChunkDictionary<H> {
    fn default() -> ChunkDictionary<H> {
        Self { dictionary: vec![] }
    }
}

pub struct MembershipProof<H: simple_hasher::Hasher> {
    randomness: H::Digest,
    auth_path_aocl: mmr::membership_proof::MembershipProof<H>,
    target_chunks: ChunkDictionary<H>,
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
    pub fn commit(self: &Self, item: &H::Digest, randomness: &H::Digest) -> AdditionRecord<H> {
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
            // self.swbf_active =
            //     // self.swbf_active[CHUNK_SIZE..WINDOW_SIZE].concatenate([false; CHUNK_SIZE as usize]);
            //     self.swbf_active[]
            let chunk_digest = chunk.hash();
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
        let item_commitment = hasher.hash_pair(&item, &randomness);

        // simulate adding to commitment list
        let item_index = self.aocl.count_leaves();
        let batch_index = item_index / BATCH_SIZE as u128;
        let aocl_auth_path = self.aocl.clone().append(item_commitment);

        let mut target_chunks: ChunkDictionary<H> = ChunkDictionary::default();
        // if window slides, filter will be updated
        if item_index % BATCH_SIZE as u128 == 0 {
            let chunk: Chunk = Chunk {
                bits: self.swbf_active[..CHUNK_SIZE].try_into().unwrap(),
            };
            let chunk_digest = chunk.hash();
            let new_chunk_path = self.swbf_inactive.clone().append(chunk_digest);

            // prepare swbf MMR authentication paths
            let timestamp: Vec<BFieldElement> = (item_index as u128).to_digest();
            let rhs = hasher.hash_pair(&timestamp, &randomness);
            for i in 0..NUM_TRIALS {
                let counter: Vec<BFieldElement> = (i as u128).to_digest();
                let pseudorandomness = hasher.hash_pair(&counter, &rhs);
                let index = hasher.sample_index_not_power_of_two(&pseudorandomness, WINDOW_SIZE)
                    as u128
                    + batch_index * CHUNK_SIZE as u128;

                // if index lies in inactive part of filter, add an mmr auth path
                if index < (1 + item_index) / BATCH_SIZE as u128 * CHUNK_SIZE as u128 {
                    target_chunks
                        .dictionary
                        .push((index, new_chunk_path.clone(), chunk));
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
        // verify that a commitment to the item lives in the aocl mmr
        let hasher = H::new();
        let leaf = hasher.hash_pair(&item, &membership_proof.randomness);
        let (is_aocl_member, _) = membership_proof.auth_path_aocl.verify(
            &self.aocl.get_peaks(),
            &leaf,
            self.aocl.count_leaves(),
        );

        // verify that some indicated bits in the swbf are unset
        let mut has_unset_bits = false;
        let mut entries_in_dictionary = true;
        let mut all_auth_paths_are_valid = true;
        let item_index = membership_proof.auth_path_aocl.data_index;
        let timestamp: Vec<BFieldElement> = (item_index).to_digest();
        let batch_index = item_index / BATCH_SIZE as u128;
        let rhs = hasher.hash_pair(&timestamp, &membership_proof.randomness);
        for i in 0..NUM_TRIALS {
            // get index
            let counter: Vec<BFieldElement> = (i as u128).to_digest();
            let pseudorandomness = hasher.hash_pair(&counter, &rhs);

            let index = hasher.sample_index_not_power_of_two(&pseudorandomness, WINDOW_SIZE)
                as u128
                + batch_index * CHUNK_SIZE as u128;

            // if index is in the inactive part of the filter,
            if index < (1 + self.aocl.count_leaves()) / BATCH_SIZE as u128 * CHUNK_SIZE as u128 {
                // verify mmr auth path
                let matching_entries: Vec<&(
                    u128,
                    mmr::membership_proof::MembershipProof<H>,
                    Chunk,
                )> = membership_proof
                    .target_chunks
                    .dictionary
                    .iter()
                    .filter(|ch| ch.0 == index)
                    .collect();
                if matching_entries.len() != 1 {
                    entries_in_dictionary = false;
                    continue;
                }
                let (valid_auth_path, unnecessary_peak) = matching_entries[0].1.verify(
                    &self.swbf_inactive.get_peaks(),
                    &matching_entries[0].2.hash(),
                    self.swbf_inactive.count_leaves(),
                );
                all_auth_paths_are_valid = all_auth_paths_are_valid && valid_auth_path;

                // verify that bit is possibly unset
                let relative_index = index - matching_entries[0].1.data_index * CHUNK_SIZE as u128;
                if matching_entries[0].2.bits[relative_index as usize] == false {
                    has_unset_bits = true;
                }
            }
            // if bit is in the active part of the filter
            else {
                let relative_index = index
                    - (1 + self.aocl.count_leaves()) / BATCH_SIZE as u128 * CHUNK_SIZE as u128;
                if self.swbf_active[relative_index as usize] == false {
                    has_unset_bits = true;
                }
            }
        }

        // return verdict
        is_aocl_member && entries_in_dictionary && all_auth_paths_are_valid && has_unset_bits
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

    use super::*;

    #[test]
    fn init_test() {
        SetCommitment::<RescuePrimeProduction>::default();
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
}
