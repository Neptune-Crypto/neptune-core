use crate::util_types::{
    mmr::{self, mmr_accumulator::MmrAccumulator, mmr_trait::Mmr},
    simple_hasher::{self, ToDigest},
};

pub const WINDOW_SIZE: usize = 3200;
pub const CHUNK_SIZE: usize = 160;
pub const BATCH_SIZE: usize = 20;
pub const NUM_TRIALS: usize = 160;

pub struct Commitment<H: simple_hasher::Hasher> {
    aocl: MmrAccumulator<H>,
    swbf: MmrAccumulator<H>,
    window: [bool; WINDOW_SIZE],
}

pub struct Chunk<Digest> {
    bits: [bool; CHUNK_SIZE],
    PhantomData: Digest,
}

impl<Digest: ToDigest<Digest>> Chunk<Digest> {
    pub fn hash(&self) -> Digest {
        self.to_digest()
    }
}

pub struct ChunkDictionary<H: simple_hasher::Hasher> {
    dictionary: Vec<(u128, mmr::membership_proof::MembershipProof<H>)>,
}

pub struct MembershipProof<H: simple_hasher::Hasher> {
    index: u128,
    randomness: [u8; 20],
    auth_path_aocl: mmr::membership_proof::MembershipProof<H>,
    target_chunks: ChunkDictionary<H>,
}

pub struct AdditionRecord<H: simple_hasher::Hasher> {
    commitment: H::Digest,
    index: u128,
    aocl_snapshot: MmrAccumulator<H>,
}

impl<H: simple_hasher::Hasher> Commitment<H>
where
    u128: ToDigest<<H as simple_hasher::Hasher>::Digest>,
{
    pub fn default() -> Self {
        Self {
            aocl: MmrAccumulator::new(vec![]),
            swbf: MmrAccumulator::new(vec![]),
            window: [false; WINDOW_SIZE as usize],
        }
    }

    /**
     * add
     * Updates the set-commitment. The new commitment represents the
     * set S union {c}, where S is the set represented by the old
     * commitment and c is the commitment to the new item.
     */
    pub fn add(&mut self, item_commitment: H::Digest) -> AdditionRecord<H> {
        // add to list
        let item_index = self.aocl.count_leaves();
        let aocl_snapshot = self.aocl.clone();
        self.aocl.append(item_commitment); // ignore auth path

        // if window slides, update filter
        if item_index % BATCH_SIZE as u128 == 0 {
            let chunk: Chunk<H> = self.window[..CHUNK_SIZE];
            self.window =
                self.window[CHUNK_SIZE..WINDOW_SIZE].concatenate([false; CHUNK_SIZE as usize]);
            let chunk_digest = chunk.hash();
            self.swbf.append(chunk_digest); // ignore auth path
        }

        // return addition record
        AdditionRecord {
            commitment: item_commitment,
            index: item_index,
            aocl_snapshot: aocl_snapshot,
        }
    }

    pub fn prove(&self, item: H::Digest, randomness: H::Digest) -> MembershipProof<H> {
        // compute commitment
        let hasher = H::new();
        let item_commitment = hasher.hash_pair(&item, &randomness);

        // simulate to commitment list
        let item_index = self.aocl.count_leaves();
        let batch_index = item_index / BATCH_SIZE;
        let aocl_auth_path = self.aocl.clone().append(item_commitment);

        // if window slides, filter will be updated
        if item_index % BATCH_SIZE as u128 == 0 {
            let chunk: Chunk<H> = self.window[..CHUNK_SIZE];
            self.window =
                self.window[CHUNK_SIZE..WINDOW_SIZE].concatenate([false; CHUNK_SIZE as usize]);
            let chunk_digest = chunk.hash();
            let new_chunk_path = self.swbf.clone().append(chunk_digest);

            // prepare filter MMR authentication paths
            let timestamp = H::into(item_index);
            let rhs = hasher.hash_pair(timestamp, &randomness);
            let mut target_chunks = ChunkDictionary::default();
            for i in 0..NUM_TRIALS {
                let mut counter = H::into(i);
                let mut pseudorandomness = hasher.hash_pair(counter, &rhs);
                let mut index =
                    hasher.sample_index(&pseudorandomness, WINDOW_SIZE) + batch_index * CHUNK_SIZE;

                if index < (1 + item_index) / BATCH_SIZE * CHUNK_SIZE {
                    target_chunks
                        .chunk_dictionary
                        .append((index, new_chunk_path));
                }
            }

            // return membership proof
            MembershipProof {
                randomness,
                auth_path_aocl: aocl_auth_path,
                target_chunks,
                index: item_index,
            }
            // MembershipProof {
            //     index: item_index,
            //     randomness: randomness,
            //     auth_path_aocl: aocl_auth_path,
            //     target_chunks: target_chunks,
            // }
        }
    }
}

#[cfg(test)]
mod accumulation_scheme_tests {
    use crate::util_types::simple_hasher::RescuePrimeProduction;

    use super::*;

    #[test]
    fn init_test() {
        Commitment::<RescuePrimeProduction>::default();
        Commitment::<blake3::Hasher>::default();
    }
}
