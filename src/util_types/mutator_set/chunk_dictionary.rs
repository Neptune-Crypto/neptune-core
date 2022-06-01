use std::collections::HashMap;

use super::chunk::Chunk;
use crate::util_types::{mmr, simple_hasher};

#[derive(Clone, Debug)]
pub struct ChunkDictionary<H: simple_hasher::Hasher> {
    // {chunk index => (membership proof for the whole chunk to which bit belongs, chunk value)}
    pub dictionary: HashMap<u128, (mmr::mmr_membership_proof::MmrMembershipProof<H>, Chunk)>,
}

impl<H: simple_hasher::Hasher> PartialEq for ChunkDictionary<H> {
    fn eq(&self, other: &Self) -> bool {
        self.dictionary == other.dictionary
    }
}

impl<H: simple_hasher::Hasher> ChunkDictionary<H> {
    pub fn default() -> ChunkDictionary<H> {
        Self {
            dictionary: HashMap::new(),
        }
    }
}
