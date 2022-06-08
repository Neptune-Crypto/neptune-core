use serde::{Deserialize, Serialize};
use twenty_first::util_types::mutator_set::{
    addition_record::AdditionRecord, removal_record::RemovalRecord,
};

use super::shared::Hash;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MutatorSetUpdate {
    removals: Vec<RemovalRecord<Hash>>,
    additions: Vec<AdditionRecord<Hash>>,
}
