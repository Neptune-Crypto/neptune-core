use serde::{Deserialize, Serialize};
use twenty_first::util_types::mutator_set::{
    addition_record::AdditionRecord, removal_record::RemovalRecord,
};

use super::shared::Hash;

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

    // TODO: Replace this with a Merkle root implementation that can handle a
}
