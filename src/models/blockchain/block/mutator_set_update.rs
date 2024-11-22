use anyhow::bail;
use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;

use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::removal_record::RemovalRecord;

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

    /// Like `apply_to_accumulator` but does not verify that the removal records
    /// could be removed. In other words: This does not check if double spend is
    /// happening.
    pub(crate) fn apply_to_accumulator_unsafe(&self, ms_accumulator: &mut MutatorSetAccumulator) {
        let _valid_removal_records =
            self.apply_to_accumulator_and_records_inner(ms_accumulator, &mut []);
    }

    /// Apply a mutator-set-update to a mutator-set-accumulator.
    ///
    /// Changes the mutator
    /// set accumulator according to the provided addition and removal records.
    ///
    /// # Return Value
    ///
    /// Returns an error if some removal record could not be removed.
    pub fn apply_to_accumulator(&self, ms_accumulator: &mut MutatorSetAccumulator) -> Result<()> {
        let valid_removal_records =
            self.apply_to_accumulator_and_records_inner(ms_accumulator, &mut []);
        if valid_removal_records {
            Ok(())
        } else {
            bail!("Cannot remove item from mutator set.");
        }
    }

    /// Apply a mutator-set-update to a mutator-set-accumulator and a bunch of
    /// removal records.
    ///
    /// Changes the mutator set accumulator according to the
    /// to-be-applied addition and removal records. This method assumes that the
    /// removal records in the update are distinct from the ones that are to be
    /// updated.
    ///
    /// # Return Value
    ///
    /// Returns an error if some removal record could not be removed. This
    /// return value **must** be verified to be OK. If it is not, then the
    /// mutator set will be in an invalid state.
    pub fn apply_to_accumulator_and_records(
        &self,
        ms_accumulator: &mut MutatorSetAccumulator,
        removal_records: &mut [&mut RemovalRecord],
    ) -> Result<()> {
        let valid_removal_records =
            self.apply_to_accumulator_and_records_inner(ms_accumulator, removal_records);
        if valid_removal_records {
            Ok(())
        } else {
            bail!("Cannot remove item from mutator set.");
        }
    }

    /// Apply a mutator set update to a mutator set accumulator. Modifies the
    /// mutator set according to the content of the mutator set update and
    /// returns a boolean indicating if all removal records were valid.
    ///
    /// If this boolean is false, then at least one removal record was invalid
    /// which could for example mean a double-spend, or an invalid MMR
    /// membership proof into the sliding-window Bloom filter.
    ///
    /// This function should *not* be made public, as the caller should always
    /// explicitly decide if they want the safe or unsafe version which checks
    /// the returned boolean.
    fn apply_to_accumulator_and_records_inner(
        &self,
        ms_accumulator: &mut MutatorSetAccumulator,
        removal_records: &mut [&mut RemovalRecord],
    ) -> bool {
        let mut cloned_removals = self.removals.clone();
        let mut applied_removal_records = cloned_removals.iter_mut().rev().collect::<Vec<_>>();
        for addition_record in self.additions.iter() {
            RemovalRecord::batch_update_from_addition(&mut applied_removal_records, ms_accumulator);

            RemovalRecord::batch_update_from_addition(removal_records, ms_accumulator);

            ms_accumulator.add(addition_record);
        }

        let mut removal_records_are_valid = true;
        while let Some(applied_removal_record) = applied_removal_records.pop() {
            RemovalRecord::batch_update_from_remove(
                &mut applied_removal_records,
                applied_removal_record,
            );

            RemovalRecord::batch_update_from_remove(removal_records, applied_removal_record);

            if !ms_accumulator.can_remove(applied_removal_record) {
                removal_records_are_valid = false;
            }
            ms_accumulator.remove(applied_removal_record);
        }

        removal_records_are_valid
    }
}

#[cfg(test)]
mod tests {
    use num_traits::Zero;

    use super::*;

    impl MutatorSetUpdate {
        /// Return the number of removal records
        pub(crate) fn num_removals(&self) -> usize {
            self.removals.len()
        }

        /// Return the number of removal records
        pub(crate) fn num_additions(&self) -> usize {
            self.additions.len()
        }

        pub(crate) fn is_empty(&self) -> bool {
            self.num_removals().is_zero() && self.num_additions().is_zero()
        }
    }
}
