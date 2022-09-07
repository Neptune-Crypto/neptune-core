use anyhow::{bail, Result};
use mutator_set_tf::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use mutator_set_tf::util_types::mutator_set::mutator_set_trait::MutatorSet;
use mutator_set_tf::util_types::mutator_set::{
    addition_record::AdditionRecord, removal_record::RemovalRecord,
};
use serde::{Deserialize, Serialize};
use twenty_first::util_types::{merkle_tree::MerkleTree, simple_hasher::Hasher};

use crate::models::blockchain::digest::{Digest, Hashable};
use crate::models::blockchain::shared::Hash;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MutatorSetUpdate {
    // The ordering of the removal/addition records must match that of
    // the block.
    pub removals: Vec<RemovalRecord<Hash>>,
    pub additions: Vec<AdditionRecord<Hash>>,
}

impl Hashable for MutatorSetUpdate {
    fn hash(&self) -> Digest {
        let additions = self.additions.to_owned();
        let addition_digests: Vec<_> = additions.into_iter().map(|a| a.hash()).collect();
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
    pub fn default() -> Self {
        MutatorSetUpdate {
            removals: vec![],
            additions: vec![],
        }
    }

    pub fn new(removals: Vec<RemovalRecord<Hash>>, additions: Vec<AdditionRecord<Hash>>) -> Self {
        Self {
            additions,
            removals,
        }
    }

    /// Apply a mutator set update to a mutator set accumulator. Changes the input mutator set
    /// accumulator according to the provided additions and removals.
    pub fn apply(&self, ms_accumulator: &mut MutatorSetAccumulator<Hash>) -> Result<()> {
        let mut addition_records: Vec<AdditionRecord<Hash>> = self.additions.clone();
        let mut removal_records = self.removals.clone();
        let mut removal_records: Vec<&mut RemovalRecord<Hash>> =
            removal_records.iter_mut().collect::<Vec<_>>();
        while let Some(mut addition_record) = addition_records.pop() {
            let update_res =
                RemovalRecord::batch_update_from_addition(&mut removal_records, ms_accumulator);

            if update_res.is_err() {
                bail!("Failed to update removal records with addition record");
            }

            ms_accumulator.add(&mut addition_record);
        }

        while let Some(removal_record) = removal_records.pop() {
            let update_res =
                RemovalRecord::batch_update_from_remove(&mut removal_records, removal_record);

            if update_res.is_err() {
                bail!("Failed to update removal records with addition record");
            }

            ms_accumulator.remove(removal_record);
        }

        Ok(())
    }
}
