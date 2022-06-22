use serde::{Deserialize, Serialize};
use twenty_first::util_types::{
    merkle_tree::MerkleTree,
    mutator_set::{addition_record::AdditionRecord, removal_record::RemovalRecord},
    simple_hasher::Hasher,
};

use super::{
    digest::{Digest, Hashable},
    shared::Hash,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MutatorSetUpdate {
    pub removals: Vec<RemovalRecord<Hash>>,
    pub additions: Vec<AdditionRecord<Hash>>,
}

impl Hashable for MutatorSetUpdate {
    fn hash(&self) -> Digest {
        let addition_digests: Vec<_> = self.additions.iter().map(|a| a.hash()).collect();
        let removal_digests: Vec<_> = self.removals.iter().map(|a| a.hash()).collect();
        let additions_root =
            MerkleTree::<Hash>::root_from_arbitrary_number_of_digests(&addition_digests);
        let removals_root =
            MerkleTree::<Hash>::root_from_arbitrary_number_of_digests(&removal_digests);
        let hasher = Hash::new();

        Digest::new(
            hasher
                .hash_pair(&additions_root, &removals_root)
                .try_into()
                .unwrap(),
        )
    }
}

impl MutatorSetUpdate {
    pub fn new(removals: Vec<RemovalRecord<Hash>>, additions: Vec<AdditionRecord<Hash>>) -> Self {
        Self {
            additions,
            removals,
        }
    }
}
