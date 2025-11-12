use std::slice::Iter;
use std::slice::IterMut;
use std::vec::IntoIter;

#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::TasmObject;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
use triton_vm::prelude::Digest;

use super::chunk::Chunk;
use crate::prelude::triton_vm;

type AuthenticatedChunk = (MmrMembershipProof, Chunk);
type ChunkIndex = u64;

#[derive(
    Clone, Debug, Serialize, Deserialize, GetSize, PartialEq, Eq, Default, BFieldCodec, TasmObject,
)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(Arbitrary))]
pub struct ChunkDictionary {
    /// {chunk index => (MMR membership proof for the whole chunk to which index belongs, chunk value)}
    /// This list is always sorted. It has max. NUM_TRIALS=45 elements, so we
    /// don't care about the cost of reallocation when `insert`ing or
    /// `remove`ing.
    pub(crate) dictionary: Vec<(u64, (MmrMembershipProof, Chunk))>,
}

impl ChunkDictionary {
    pub fn empty() -> Self {
        Self {
            dictionary: Vec::new(),
        }
    }

    pub fn new(mut dictionary: Vec<(ChunkIndex, AuthenticatedChunk)>) -> Self {
        dictionary.sort_by_key(|(k, _v)| *k);
        Self { dictionary }
    }

    pub fn indices_and_leafs(&self) -> Vec<(ChunkIndex, Digest)> {
        self.dictionary
            .iter()
            .map(|(k, (_mp, ch))| (*k, Tip5::hash(ch)))
            .collect_vec()
    }

    pub fn indices_and_chunks(&self) -> Vec<(ChunkIndex, Chunk)> {
        self.dictionary
            .iter()
            .map(|(k, (_mp, ch))| (*k, ch.clone()))
            .collect_vec()
    }

    pub fn chunk_indices_and_membership_proofs_and_leafs(
        &self,
    ) -> Vec<(u64, MmrMembershipProof, Digest)> {
        self.dictionary
            .iter()
            .map(|(k, (mp, ch))| (*k, mp.clone(), Tip5::hash(ch)))
            .collect_vec()
    }

    pub fn chunk_indices_and_membership_proofs_and_leafs_iter_mut(
        &mut self,
    ) -> std::slice::IterMut<'_, (u64, (MmrMembershipProof, Chunk))> {
        self.dictionary.iter_mut()
    }

    pub fn authentication_paths(&self) -> Vec<MmrMembershipProof> {
        self.dictionary
            .iter()
            .map(|(_, (mp, _))| mp.to_owned())
            .collect()
    }

    pub fn all_chunk_indices(&self) -> Vec<ChunkIndex> {
        self.dictionary.iter().map(|(ci, _)| *ci).collect_vec()
    }

    pub fn contains_key(&self, key: &ChunkIndex) -> bool {
        self.dictionary
            .iter()
            .any(|(chunk_index, _)| *chunk_index == *key)
    }

    pub fn get(&self, key: &ChunkIndex) -> Option<&AuthenticatedChunk> {
        self.dictionary
            .iter()
            .find(|(chunk_index, _)| *chunk_index == *key)
            .map(|(_, value)| value)
    }

    pub fn all<F: FnMut(&(ChunkIndex, AuthenticatedChunk)) -> bool>(&self, f: F) -> bool {
        self.dictionary.iter().all(f)
    }

    pub fn is_empty(&self) -> bool {
        self.dictionary.is_empty()
    }

    pub fn iter(&self) -> Iter<'_, (ChunkIndex, AuthenticatedChunk)> {
        self.dictionary.iter()
    }

    pub fn len(&self) -> usize {
        self.dictionary.len()
    }

    pub fn iter_mut(&mut self) -> IterMut<'_, (ChunkIndex, AuthenticatedChunk)> {
        self.dictionary.iter_mut()
    }

    pub fn insert(
        &mut self,
        index: ChunkIndex,
        value: AuthenticatedChunk,
    ) -> Option<AuthenticatedChunk> {
        if let Some((_found_chunk_index, found_authenticated_chunk)) =
            self.dictionary.iter_mut().find(|(k, _v)| *k == index)
        {
            let old_chunk = found_authenticated_chunk.clone();
            *found_authenticated_chunk = value;
            Some(old_chunk)
        } else {
            let insertion_index = self.dictionary.iter().filter(|(k, _v)| *k < index).count();
            self.dictionary.insert(insertion_index, (index, value));
            None
        }
    }

    pub fn get_mut(&mut self, index: &ChunkIndex) -> Option<&mut AuthenticatedChunk> {
        self.dictionary
            .iter_mut()
            .find(|(k, _v)| *k == *index)
            .map(|(_k, v)| v)
    }

    pub fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&(ChunkIndex, AuthenticatedChunk)) -> bool,
    {
        self.dictionary.retain(f)
    }

    pub fn remove(&mut self, index: &ChunkIndex) -> Option<AuthenticatedChunk> {
        let maybe_position = self
            .dictionary
            .iter()
            .enumerate()
            .find(|(_i, (k, _v))| *k == *index)
            .map(|(i, _)| i);
        if let Some(definite_position) = maybe_position {
            let (_chunk_index, authenticated_chunk) = self.dictionary.remove(definite_position);
            Some(authenticated_chunk)
        } else {
            None
        }
    }
}

impl IntoIterator for ChunkDictionary {
    type Item = (ChunkIndex, AuthenticatedChunk);

    type IntoIter = IntoIter<(ChunkIndex, AuthenticatedChunk)>;

    fn into_iter(self) -> Self::IntoIter {
        self.dictionary.into_iter()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod tests {
    use macro_rules_attr::apply;
    use tasm_lib::twenty_first::math::other::random_elements;

    use super::*;
    use crate::tests::shared_tokio_runtime;
    use crate::util_types::archival_mmr::tests::mock;
    use crate::util_types::mutator_set::shared::CHUNK_SIZE;

    #[apply(shared_tokio_runtime)]
    async fn hash_test() {
        let chunkdict0 = ChunkDictionary::default();
        let chunkdict00 = ChunkDictionary::default();
        assert_eq!(Tip5::hash(&chunkdict0), Tip5::hash(&chunkdict00));

        // Insert elements
        let num_leaves = 3;
        let leaf_hashes: Vec<Digest> = random_elements(num_leaves);
        let archival_mmr = mock::get_ammr_from_digests(leaf_hashes).await;

        let key1: u64 = 898989;
        let mp1: MmrMembershipProof = archival_mmr.prove_membership_async(1).await;
        let chunk1: Chunk = {
            Chunk {
                relative_indices: (0..CHUNK_SIZE).collect(),
            }
        };
        let value1 = (mp1, chunk1);
        let chunkdict1 = ChunkDictionary::new(vec![(key1, value1.clone())]);

        // Insert two more element and verify that the hash is deterministic which implies that the
        // elements in the preimage are sorted deterministically.
        let key2: u64 = 8989;
        let mp2: MmrMembershipProof = archival_mmr.prove_membership_async(2).await;
        let mut chunk2 = Chunk::empty_chunk();
        chunk2.insert(CHUNK_SIZE / 2 + 1);
        let value2 = (mp2, chunk2);
        let chunkdict2 = ChunkDictionary::new(vec![(key1, value1.clone()), (key2, value2.clone())]);

        let key3: u64 = 89;
        let chunkdict3 = ChunkDictionary::new(vec![
            (key1, value1.clone()),
            (key2, value2.clone()),
            (key3, value2.clone()),
        ]);

        assert_ne!(Tip5::hash(&chunkdict0), Tip5::hash(&chunkdict1));
        assert_ne!(Tip5::hash(&chunkdict0), Tip5::hash(&chunkdict2));
        assert_ne!(Tip5::hash(&chunkdict0), Tip5::hash(&chunkdict3));
        assert_ne!(Tip5::hash(&chunkdict1), Tip5::hash(&chunkdict2));
        assert_ne!(Tip5::hash(&chunkdict1), Tip5::hash(&chunkdict3));
        assert_ne!(Tip5::hash(&chunkdict2), Tip5::hash(&chunkdict3));

        // Construct similar data structure to `two_elements` but insert key/value pairs in opposite order
        let chunkdict3_alt = ChunkDictionary::new(vec![
            (key3, value2.clone()),
            (key1, value1.clone()),
            (key2, value2.clone()),
        ]);

        // Verify that keys are sorted deterministically when hashing chunk dictionary.
        // This test fails if the hash method does not sort the keys
        assert_eq!(Tip5::hash(&chunkdict3), Tip5::hash(&chunkdict3_alt));

        // Negative: Construct data structure where the keys and values are switched
        let chunkdict3_switched =
            ChunkDictionary::new(vec![(key1, value2.clone()), (key2, value1), (key3, value2)]);

        assert_ne!(Tip5::hash(&chunkdict3), Tip5::hash(&chunkdict3_switched));
    }

    #[apply(shared_tokio_runtime)]
    async fn serialization_test() {
        // TODO: You could argue that this test doesn't belong here, as it tests the behavior of
        // an imported library. I included it here, though, because the setup seems a bit clumsy
        // to me so far.
        let s_empty: ChunkDictionary = ChunkDictionary::empty();
        let json = serde_json::to_string(&s_empty).unwrap();
        println!("json = {}", json);
        let s_back = serde_json::from_str::<ChunkDictionary>(&json).unwrap();
        assert!(s_back.is_empty());

        // Build a non-empty chunk dict and verify that it still works
        let key: u64 = 898989;
        let leaf_hashes: Vec<Digest> = random_elements(3);
        let archival_mmr = mock::get_ammr_from_digests(leaf_hashes).await;
        let mp: MmrMembershipProof = archival_mmr.prove_membership_async(1).await;
        let chunk = Chunk {
            relative_indices: (0..CHUNK_SIZE).collect(),
        };

        let s_non_empty = ChunkDictionary::new(vec![(key, (mp.clone(), chunk.clone()))]);
        let json_non_empty = serde_json::to_string(&s_non_empty).unwrap();
        println!("json_non_empty = {}", json_non_empty);
        let s_back_non_empty = serde_json::from_str::<ChunkDictionary>(&json_non_empty).unwrap();
        assert!(!s_back_non_empty.is_empty());
        assert!(s_back_non_empty.contains_key(&key));
        assert_eq!((mp, chunk), s_back_non_empty.get(&key).unwrap().clone());
    }

    #[test_strategy::proptest]
    fn test_chunk_dictionary_decode(
        #[strategy(proptest_arbitrary_interop::arb::<ChunkDictionary>())]
        chunk_dictionary: ChunkDictionary,
    ) {
        let encoded = chunk_dictionary.encode();
        let decoded = *ChunkDictionary::decode(&encoded).unwrap();

        assert_eq!(chunk_dictionary, decoded);
    }
}
