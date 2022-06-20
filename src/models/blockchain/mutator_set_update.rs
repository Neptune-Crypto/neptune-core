use serde::{Deserialize, Serialize};
use twenty_first::{
    shared_math::b_field_element::BFieldElement,
    util_types::{
        merkle_tree::MerkleTree,
        mutator_set::{addition_record::AdditionRecord, removal_record::RemovalRecord},
        simple_hasher::Hasher,
    },
};

use super::{digest::RESCUE_PRIME_OUTPUT_SIZE_IN_BFES, shared::Hash};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MutatorSetUpdate {
    pub removals: Vec<RemovalRecord<Hash>>,
    pub additions: Vec<AdditionRecord<Hash>>,
}

impl MutatorSetUpdate {
    pub fn new(removals: Vec<RemovalRecord<Hash>>, additions: Vec<AdditionRecord<Hash>>) -> Self {
        Self {
            additions,
            removals,
        }
    }

    pub fn hash(&self) -> [BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES] {
        let addition_digests: Vec<_> = self.additions.iter().map(|a| a.hash()).collect();
        let removal_digests: Vec<_> = self.removals.iter().map(|a| a.hash()).collect();
        let additions_root =
            MerkleTree::<Hash>::root_from_arbitrary_number_of_digests(&addition_digests);
        let removals_root =
            MerkleTree::<Hash>::root_from_arbitrary_number_of_digests(&removal_digests);
        let hasher = Hash::new();

        hasher
            .hash_pair(&additions_root, &removals_root)
            .try_into()
            .unwrap()
    }
}
