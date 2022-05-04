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

pub struct Chunk {
    bits: [bool; CHUNK_SIZE],
}

impl ToDigest<Vec<BFieldElement>> for Chunk {
    fn to_digest(&self) -> Vec<BFieldElement> {
        let num_iterations = (CHUNK_SIZE / 63) + if CHUNK_SIZE % 63 == 0 { 0 } else { 1 };
        let mut ret: Vec<BFieldElement> = vec![];
        let mut acc: u64;
        for i in 0..num_iterations {
            acc = 0;
            for j in 0..63 {
                acc += if self.bits[i * 63 + j] { 1 << j } else { 0 };
            }
            ret.push(BFieldElement::new(acc));
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
    dictionary: Vec<(u128, mmr::membership_proof::MembershipProof<H>)>,
}

impl<H: simple_hasher::Hasher> ChunkDictionary<H> {
    fn default() -> ChunkDictionary<H> {
        Self { dictionary: vec![] }
    }
}

pub struct MembershipProof<H: simple_hasher::Hasher> {
    index: u128,
    randomness: H::Digest,
    auth_path_aocl: mmr::membership_proof::MembershipProof<H>,
    target_chunks: ChunkDictionary<H>,
}

pub struct AdditionRecord<H: simple_hasher::Hasher<Digest = Vec<BFieldElement>>> {
    commitment: H::Digest,
    index: u128,
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
     * add
     * Updates the set-commitment. The new commitment represents the
     * set
     *          S union {c} ,
     * where S is the set represented by the old
     * commitment and c is the commitment to the new item AKA the
     * *addition record*.
     */
    pub fn add(&mut self, addition_record: AdditionRecord<H>) {
        // verify aocl snapshot
        if !addition_record.has_matching_aocl(&self.aocl) {
            panic!("Addition record has aocl snapshot that does not match with the AOCL it is being added to.")
        }

        // add to list
        let item_index = self.aocl.count_leaves();
        self.aocl.append(addition_record.commitment); // ignore auth path

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

    pub fn prove(&self, item: H::Digest, randomness: H::Digest) -> MembershipProof<H> {
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
                let index = hasher.sample_index(&pseudorandomness, WINDOW_SIZE) as u128
                    + batch_index * CHUNK_SIZE as u128;

                if index < (1 + item_index) / BATCH_SIZE as u128 * CHUNK_SIZE as u128 {
                    target_chunks
                        .dictionary
                        .push((index, new_chunk_path.clone()));
                }
            }
        }

        // return membership proof
        MembershipProof {
            randomness,
            auth_path_aocl: aocl_auth_path,
            target_chunks,
            index: item_index,
        }
    }
}

#[cfg(test)]
mod accumulation_scheme_tests {
    use crate::util_types::simple_hasher::RescuePrimeProduction;

    use super::*;

    #[test]
    fn init_test() {
        SetCommitment::<RescuePrimeProduction>::default();
    }
}
