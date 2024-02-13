use anyhow::Result;

use serde::{Deserialize, Serialize};

use crate::util_types::mutator_set::{
    addition_record::AdditionRecord, mutator_set_accumulator::MutatorSetAccumulator,
    mutator_set_trait::MutatorSet, removal_record::RemovalRecord,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MutatorSetUpdate {
    // The ordering of the removal/addition records must match that of
    // the block.
    pub removals: Vec<RemovalRecord>,
    pub additions: Vec<AdditionRecord>,
}

impl MutatorSetUpdate {
    pub fn new(removals: Vec<RemovalRecord>, additions: Vec<AdditionRecord>) -> Self {
        Self {
            additions,
            removals,
        }
    }

    /// Apply a mutator set update to a mutator set accumulator. Changes the input mutator set
    /// accumulator according to the provided additions and removals.
    pub fn apply(&self, ms_accumulator: &mut MutatorSetAccumulator) -> Result<()> {
        let mut addition_records: Vec<AdditionRecord> = self.additions.clone();
        addition_records.reverse();
        let mut removal_records = self.removals.clone();
        removal_records.reverse();
        let mut removal_records: Vec<&mut RemovalRecord> =
            removal_records.iter_mut().collect::<Vec<_>>();
        while let Some(addition_record) = addition_records.pop() {
            RemovalRecord::batch_update_from_addition(
                &mut removal_records,
                &mut ms_accumulator.kernel,
            );

            ms_accumulator.add(&addition_record);
        }

        while let Some(removal_record) = removal_records.pop() {
            RemovalRecord::batch_update_from_remove(&mut removal_records, removal_record);

            ms_accumulator.remove(removal_record);
        }

        Ok(())
    }
}
