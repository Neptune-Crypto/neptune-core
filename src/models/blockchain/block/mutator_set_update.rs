use anyhow::Result;

use serde::{Deserialize, Serialize};

use crate::util_types::mutator_set::{
    addition_record::AdditionRecord, mutator_set_accumulator::MutatorSetAccumulator,
    mutator_set_trait::*, removal_record::RemovalRecord,
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

    /// Apply a mutator-set-update to a mutator-set-accumulator. Changes the mutator
    /// set accumulator according to the provided addition and removal records.
    pub async fn apply_to_accumulator(
        &self,
        ms_accumulator: &mut MutatorSetAccumulator,
    ) -> Result<()> {
        self.apply_to_accumulator_and_records(ms_accumulator, &mut [])
            .await
    }

    /// Apply a mutator-set-update to a mutator-set-accumulator and a bunch of
    /// removal records. Changes the mutator set accumulator according to the
    /// to-be-applied addition and removal records. This method assumes that the
    /// removal records in the update are distinct from the ones that are to be
    /// updated.
    pub async fn apply_to_accumulator_and_records(
        &self,
        ms_accumulator: &mut MutatorSetAccumulator,
        removal_records: &mut [&mut RemovalRecord],
    ) -> Result<()> {
        let mut cloned_removals = self.removals.clone();
        let mut applied_removal_records = cloned_removals.iter_mut().rev().collect::<Vec<_>>();
        for addition_record in self.additions.iter() {
            RemovalRecord::batch_update_from_addition(
                &mut applied_removal_records,
                &mut ms_accumulator.kernel,
            )
            .await;

            RemovalRecord::batch_update_from_addition(removal_records, &mut ms_accumulator.kernel)
                .await;

            ms_accumulator.add(addition_record).await;
        }

        while let Some(applied_removal_record) = applied_removal_records.pop() {
            RemovalRecord::batch_update_from_remove(
                &mut applied_removal_records,
                applied_removal_record,
            );

            RemovalRecord::batch_update_from_remove(removal_records, applied_removal_record);

            ms_accumulator.remove(applied_removal_record).await;
        }

        Ok(())
    }
}
