use anyhow::Result;
use neptune_mutator_set::addition_record::AdditionRecord;
use neptune_mutator_set::authenticated_item::AuthenticatedItem;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_mutator_set::removal_record::RemovalRecord;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MutatorSetUpdate {
    // The ordering of the removal/addition records must match that of
    // the block.
    /// The unpacked removal records
    pub removals: Vec<RemovalRecord>,

    /// Addition records
    pub additions: Vec<AdditionRecord>,
}

impl MutatorSetUpdate {
    /// Construct a new [`MutatorSetUpdate`] from the given [`RemovalRecord`]s
    /// and [`AdditionRecord`]s.
    ///
    /// Takes *unpacked* [`RemovalRecord`]s.
    pub fn new(removals: Vec<RemovalRecord>, additions: Vec<AdditionRecord>) -> Self {
        Self {
            additions,
            removals,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.removals.is_empty() && self.additions.is_empty()
    }

    /// Compose a chain of mutator-set updates into a single update.
    ///
    /// Mutator-set updates compose like arrows between mutator-set states:
    /// given `A -> B` and `B -> C`, this returns `A -> C`. Concatenating the
    /// addition and removal records is only a part of that. Each removal
    /// record carries MMR-authentication paths and chunks derived against the
    /// state it was made for, and an arrow out of `A` is only well-formed once
    /// those are re-derived against `A`. To that end, the removal records
    /// collected from later updates are reverted over each earlier update, one
    /// update at a time, until they reach `A`.
    ///
    /// `chain` is ordered from the most recent update going backwards, e.g.
    /// from a chain tip towards older blocks. Each element holds the mutator
    /// set accumulator that an update applies to, along with the update
    /// itself. The records in the returned update are ordered forwards, ready
    /// for sequential application to `A`.
    pub fn compose(chain: &[(MutatorSetAccumulator, MutatorSetUpdate)]) -> MutatorSetUpdate {
        // All removal records collected so far, valid at the state that the
        // most recently processed update applies to, in forward application
        // order.
        let mut composed_removals: Vec<RemovalRecord> = vec![];
        let mut addition_batches_reversed: Vec<&Vec<AdditionRecord>> = vec![];

        for (predecessor_msa, update) in chain {
            if !composed_removals.is_empty() {
                // Reverting the collected records over this update requires
                // the update's own removal records synced to the update's
                // resulting state, as sources of authentication data. Replay
                // the additions on the predecessor accumulator, then bring
                // the records through the application of all the update's
                // removals — including themselves — in one combined pass.
                let mut replay_msa = predecessor_msa.clone();
                let mut applied_removals = update.removals.clone();
                for addition_record in &update.additions {
                    RemovalRecord::batch_update_from_addition(
                        &mut applied_removals.iter_mut().collect::<Vec<_>>(),
                        &replay_msa,
                    );
                    replay_msa.add(addition_record);
                }
                let pre_removal_forms = applied_removals.clone();
                RemovalRecord::batch_update_from_removals(
                    &mut applied_removals.iter_mut().collect::<Vec<_>>(),
                    &pre_removal_forms,
                );

                // Walk the collected records back to the state that this
                // update applies to: undo all the removals in one pass, then
                // the additions.
                RemovalRecord::batch_revert_update_from_removals(
                    &mut composed_removals.iter_mut().collect::<Vec<_>>(),
                    &applied_removals,
                );
                RemovalRecord::batch_revert_update_from_addition(
                    &mut composed_removals.iter_mut().collect::<Vec<_>>(),
                    predecessor_msa.swbf_inactive.num_leafs(),
                );
            }

            // This update's own removal records, as stored, are already valid
            // at the state that the update applies to. They apply before
            // everything collected so far.
            composed_removals.splice(0..0, update.removals.iter().cloned());
            addition_batches_reversed.push(&update.additions);
        }

        let composed_additions = addition_batches_reversed
            .into_iter()
            .rev()
            .flatten()
            .copied()
            .collect();
        MutatorSetUpdate::new(composed_removals, composed_additions)
    }

    /// Like `apply_to_accumulator` but does not verify that the removal records
    /// could be removed. In other words: This does not check if double spend is
    /// happening.
    pub(crate) fn apply_to_accumulator_unsafe(&self, ms_accumulator: &mut MutatorSetAccumulator) {
        let _valid_removal_records =
            self.apply_to_accumulator_and_records_inner(ms_accumulator, &mut [], &mut []);
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
            self.apply_to_accumulator_and_records_inner(ms_accumulator, &mut [], &mut []);
        if valid_removal_records {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Cannot remove item from mutator set."))
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
        authenticated_items: &mut [&mut AuthenticatedItem],
    ) -> Result<()> {
        let valid_removal_records = self.apply_to_accumulator_and_records_inner(
            ms_accumulator,
            removal_records,
            authenticated_items,
        );
        if valid_removal_records {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Cannot remove item from mutator set."))
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
    ///
    /// Removal records may not be packed.
    fn apply_to_accumulator_and_records_inner(
        &self,
        ms_accumulator: &mut MutatorSetAccumulator,
        removal_records: &mut [&mut RemovalRecord],
        authenticated_items: &mut [&mut AuthenticatedItem],
    ) -> bool {
        let mut cloned_removals = self.removals.clone();
        {
            let mut own_removal_records = cloned_removals.iter_mut().collect::<Vec<_>>();
            for addition_record in &self.additions {
                RemovalRecord::batch_update_from_addition(&mut own_removal_records, ms_accumulator);

                RemovalRecord::batch_update_from_addition(removal_records, ms_accumulator);

                AuthenticatedItem::batch_update_from_addition(
                    authenticated_items,
                    ms_accumulator,
                    *addition_record,
                );

                ms_accumulator.add(addition_record);
            }
        }

        let removal_records_are_valid = ms_accumulator.can_remove_all(&cloned_removals);

        // Apply all removal records in one batch. The batch application
        // produces the same accumulator, removal records and authenticated
        // items as applying the records one at a time: the Bloom filter
        // insertions commute.
        RemovalRecord::batch_update_from_removals(removal_records, &cloned_removals);
        let mut preserved_membership_proofs = authenticated_items
            .iter_mut()
            .map(|authenticated_item| &mut authenticated_item.ms_membership_proof)
            .collect::<Vec<_>>();
        ms_accumulator.batch_remove(cloned_removals, &mut preserved_membership_proofs);

        removal_records_are_valid
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use neptune_mutator_set::msa_and_records::MsaAndRecords;
    use proptest::collection::vec;
    use proptest::prelude::TestCaseError;
    use proptest::prop_assert;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::prelude::Digest;
    use test_strategy::proptest;

    use super::MutatorSetUpdate;

    fn prop(msa_and_records: MsaAndRecords) -> std::result::Result<(), TestCaseError> {
        let removal_records = msa_and_records.unpacked_removal_records();
        for rr in &removal_records {
            prop_assert!(msa_and_records.mutator_set_accumulator.can_remove(rr));
        }

        let original_msa = msa_and_records.mutator_set_accumulator;
        for rr in removal_records {
            let mut mutated_msa = original_msa.clone();
            let as_msu = MutatorSetUpdate::new(vec![rr.clone()], vec![]);
            prop_assert!(as_msu.apply_to_accumulator(&mut mutated_msa).is_ok());
            prop_assert!(
                !mutated_msa.can_remove(&rr),
                "Can remove must return false after RR has been applied"
            );
        }

        Ok(())
    }

    #[proptest]
    fn can_remove_agrees_with_update_result_u8(
        #[strategy(0usize..40)] _num_removals: usize,
        #[strategy((#_num_removals as u64)..=(u64::from(u8::MAX)))] _num_leafs_aocl: u64,
        #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_removals))]
        _removables: Vec<(Digest, Digest, Digest)>,
        #[strategy(MsaAndRecords::arbitrary_with((#_removables, #_num_leafs_aocl)))]
        msa_and_records: MsaAndRecords,
    ) {
        prop_assert!(prop(msa_and_records).is_ok())
    }

    #[proptest(cases = 10)]
    fn can_remove_agrees_with_update_result_u16(
        #[strategy(0usize..40)] _num_removals: usize,
        #[strategy((#_num_removals as u64)..=(u64::from(u16::MAX)))] _num_leafs_aocl: u64,
        #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_removals))]
        _removables: Vec<(Digest, Digest, Digest)>,
        #[strategy(MsaAndRecords::arbitrary_with((#_removables, #_num_leafs_aocl)))]
        msa_and_records: MsaAndRecords,
    ) {
        prop_assert!(prop(msa_and_records).is_ok())
    }

    mod batch_apply {
        use itertools::Itertools;
        use neptune_mutator_set::authenticated_item::AuthenticatedItem;
        use neptune_mutator_set::commit;
        use neptune_mutator_set::msa_and_records::MsaAndRecords;
        use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
        use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
        use neptune_mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
        use neptune_mutator_set::removal_record::RemovalRecord;
        use neptune_mutator_set::shared::NUM_TRIALS;
        use proptest::collection::vec;
        use proptest::prelude::TestCaseError;
        use proptest::prop_assert;
        use proptest::prop_assert_eq;
        use proptest_arbitrary_interop::arb;
        use tasm_lib::prelude::Digest;
        use test_strategy::proptest;

        use super::MutatorSetUpdate;

        /// The sequential implementation that
        /// `apply_to_accumulator_and_records_inner` used before batch
        /// application, kept as a reference for differential testing.
        ///
        /// Practially like the production code but without using the fastest
        /// possible batch method for removal record maintanence. Weaker than
        /// the production code since the `can_remove` check is applied in-order
        /// here, and in an order-independent way in the production code. This
        /// weakness can, in the consensus path, only be hit with negligible
        /// (read: ~2^(-160)) probability. So switching to the batching-version
        /// in the production code is technically a softfork, just one that can
        /// only be hit with negligible probability.
        fn sequential_apply_reference(
            update: &MutatorSetUpdate,
            ms_accumulator: &mut MutatorSetAccumulator,
            removal_records: &mut [&mut RemovalRecord],
            authenticated_items: &mut [&mut AuthenticatedItem],
        ) -> bool {
            let mut cloned_removals = update.removals.clone();
            let mut remaining_removal_records =
                cloned_removals.iter_mut().rev().collect::<Vec<_>>();
            for addition_record in &update.additions {
                RemovalRecord::batch_update_from_addition(
                    &mut remaining_removal_records,
                    ms_accumulator,
                );
                RemovalRecord::batch_update_from_addition(removal_records, ms_accumulator);
                AuthenticatedItem::batch_update_from_addition(
                    authenticated_items,
                    ms_accumulator,
                    *addition_record,
                );
                ms_accumulator.add(addition_record);
            }

            let mut removal_records_are_valid = true;
            while let Some(applied_removal_record) = remaining_removal_records.pop() {
                RemovalRecord::batch_update_from_remove(
                    &mut remaining_removal_records,
                    applied_removal_record,
                );
                RemovalRecord::batch_update_from_remove(removal_records, applied_removal_record);
                AuthenticatedItem::batch_update_from_remove(
                    authenticated_items,
                    applied_removal_record,
                );
                if !ms_accumulator.can_remove(applied_removal_record) {
                    removal_records_are_valid = false;
                }
                ms_accumulator.remove(applied_removal_record);
            }

            removal_records_are_valid
        }

        fn batch_and_sequential_apply_agree(
            msa_and_records: MsaAndRecords,
            removables: Vec<(Digest, Digest, Digest)>,
            num_removals: usize,
            addition_preimages: Vec<(Digest, Digest, Digest)>,
        ) -> std::result::Result<(), TestCaseError> {
            let all_records = msa_and_records.unpacked_removal_records();
            let all_mps = &msa_and_records.membership_proofs;
            let msa = &msa_and_records.mutator_set_accumulator;

            let additions = addition_preimages
                .iter()
                .map(|(item, sender_randomness, receiver_preimage)| {
                    commit(*item, *sender_randomness, receiver_preimage.hash())
                })
                .collect_vec();
            let update = MutatorSetUpdate::new(all_records[..num_removals].to_vec(), additions);

            // The records and authenticated items to be maintained through
            // the application.
            let preserved_records = all_records[num_removals..].to_vec();
            let preserved_items = removables[num_removals..]
                .iter()
                .zip(&all_mps[num_removals..])
                .map(|((item, _, _), ms_membership_proof)| AuthenticatedItem {
                    item: *item,
                    ms_membership_proof: ms_membership_proof.clone(),
                })
                .collect_vec();

            let mut msa_batch = msa.clone();
            let mut records_batch = preserved_records.clone();
            let mut items_batch = preserved_items.clone();
            let batch_result = update.apply_to_accumulator_and_records(
                &mut msa_batch,
                &mut records_batch.iter_mut().collect_vec(),
                &mut items_batch.iter_mut().collect_vec(),
            );

            let mut msa_sequential = msa.clone();
            let mut records_sequential = preserved_records.clone();
            let mut items_sequential = preserved_items.clone();
            let sequential_is_valid = sequential_apply_reference(
                &update,
                &mut msa_sequential,
                &mut records_sequential.iter_mut().collect_vec(),
                &mut items_sequential.iter_mut().collect_vec(),
            );

            prop_assert!(batch_result.is_ok());
            prop_assert!(sequential_is_valid);
            prop_assert_eq!(msa_sequential, msa_batch);
            prop_assert_eq!(records_sequential, records_batch);
            for (sequential, batch) in items_sequential.iter().zip(&items_batch) {
                prop_assert_eq!(sequential.item, batch.item);
                prop_assert_eq!(&sequential.ms_membership_proof, &batch.ms_membership_proof);
            }

            Ok(())
        }

        #[proptest(cases = 12)]
        fn batch_apply_agrees_with_sequential_apply_u8(
            #[strategy(1usize..10)] num_removals: usize,
            #[strategy(1usize..6)] _num_preserved: usize,
            #[strategy((((#num_removals + #_num_preserved) as u64))..=(u64::from(u8::MAX)))]
            _num_leafs_aocl: u64,
            #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #num_removals + #_num_preserved))]
            removables: Vec<(Digest, Digest, Digest)>,
            #[strategy(MsaAndRecords::arbitrary_with((#removables, #_num_leafs_aocl)))]
            msa_and_records: MsaAndRecords,
            #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), 0usize..8))]
            addition_preimages: Vec<(Digest, Digest, Digest)>,
        ) {
            prop_assert!(batch_and_sequential_apply_agree(
                msa_and_records,
                removables,
                num_removals,
                addition_preimages
            )
            .is_ok())
        }

        #[proptest(cases = 6)]
        fn batch_apply_agrees_with_sequential_apply_u16(
            #[strategy(1usize..10)] num_removals: usize,
            #[strategy(1usize..6)] _num_preserved: usize,
            #[strategy((((#num_removals + #_num_preserved) as u64))..=(u64::from(u16::MAX)))]
            _num_leafs_aocl: u64,
            #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #num_removals + #_num_preserved))]
            removables: Vec<(Digest, Digest, Digest)>,
            #[strategy(MsaAndRecords::arbitrary_with((#removables, #_num_leafs_aocl)))]
            msa_and_records: MsaAndRecords,
            #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), 0usize..8))]
            addition_preimages: Vec<(Digest, Digest, Digest)>,
        ) {
            prop_assert!(batch_and_sequential_apply_agree(
                msa_and_records,
                removables,
                num_removals,
                addition_preimages
            )
            .is_ok())
        }

        #[proptest(cases = 3)]
        fn batch_apply_agrees_with_sequential_apply_u32(
            #[strategy(1usize..10)] num_removals: usize,
            #[strategy(1usize..6)] _num_preserved: usize,
            #[strategy((((#num_removals + #_num_preserved) as u64))..=(u64::from(u32::MAX)))]
            _num_leafs_aocl: u64,
            #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #num_removals + #_num_preserved))]
            removables: Vec<(Digest, Digest, Digest)>,
            #[strategy(MsaAndRecords::arbitrary_with((#removables, #_num_leafs_aocl)))]
            msa_and_records: MsaAndRecords,
            #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), 0usize..8))]
            addition_preimages: Vec<(Digest, Digest, Digest)>,
        ) {
            prop_assert!(batch_and_sequential_apply_agree(
                msa_and_records,
                removables,
                num_removals,
                addition_preimages
            )
            .is_ok())
        }

        #[proptest(cases = 3)]
        fn batch_apply_agrees_with_sequential_apply_u63(
            #[strategy(1usize..10)] num_removals: usize,
            #[strategy(1usize..6)] _num_preserved: usize,
            #[strategy((((#num_removals + #_num_preserved) as u64))..=(u64::MAX / 2))]
            _num_leafs_aocl: u64,
            #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #num_removals + #_num_preserved))]
            removables: Vec<(Digest, Digest, Digest)>,
            #[strategy(MsaAndRecords::arbitrary_with((#removables, #_num_leafs_aocl)))]
            msa_and_records: MsaAndRecords,
            #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), 0usize..8))]
            addition_preimages: Vec<(Digest, Digest, Digest)>,
        ) {
            prop_assert!(batch_and_sequential_apply_agree(
                msa_and_records,
                removables,
                num_removals,
                addition_preimages
            )
            .is_ok())
        }

        #[proptest(cases = 10)]
        fn duplicated_removal_record_invalidates_update(
            #[strategy(1u64..=(u64::from(u8::MAX)))] _num_leafs_aocl: u64,
            #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), 1))]
            _removables: Vec<(Digest, Digest, Digest)>,
            #[strategy(MsaAndRecords::arbitrary_with((#_removables, #_num_leafs_aocl)))]
            msa_and_records: MsaAndRecords,
        ) {
            let removal_record = msa_and_records.unpacked_removal_records()[0].clone();
            let update =
                MutatorSetUpdate::new(vec![removal_record.clone(), removal_record], vec![]);

            let mut msa_batch = msa_and_records.mutator_set_accumulator.clone();
            prop_assert!(update.apply_to_accumulator(&mut msa_batch).is_err());

            let mut msa_sequential = msa_and_records.mutator_set_accumulator.clone();
            let sequential_is_valid =
                sequential_apply_reference(&update, &mut msa_sequential, &mut [], &mut []);
            prop_assert!(!sequential_is_valid);

            prop_assert_eq!(msa_sequential, msa_batch);
        }

        /// The batch check is stricter than sequential application in one
        /// corner: a removal record whose indices are covered by the Bloom
        /// filter and the *other* records of the update combined, without
        /// being covered by the Bloom filter and earlier records alone.
        /// passes sequentially but fails the batch check. For honestly
        /// generated removal records this corner has negligible probability.
        #[test]
        fn batch_check_rejects_fully_covered_record_where_sequential_accepts() {
            // All indices lie in the initial active window, so removal
            // records with empty chunk dictionaries are valid.
            fn removal_record(indices: [u128; NUM_TRIALS as usize]) -> RemovalRecord {
                RemovalRecord {
                    absolute_indices: AbsoluteIndexSet::new(indices),
                    target_chunks: ChunkDictionary::default(),
                }
            }

            // The pre-state has indices 0..45 set.
            let pre_set = core::array::from_fn(|i| i as u128);
            let mut msa = MutatorSetAccumulator::default();
            MutatorSetUpdate::new(vec![removal_record(pre_set)], vec![])
                .apply_to_accumulator(&mut msa)
                .unwrap();

            // The first record's indices are covered by the pre-state
            // (0..20) and the second record (100..125) combined; the second
            // record has twenty uncovered indices (200..220).
            let first = core::array::from_fn(|i| {
                if i < 20 {
                    i as u128
                } else {
                    100 + (i as u128 - 20)
                }
            });
            let second = core::array::from_fn(|i| {
                if i < 25 {
                    100 + i as u128
                } else {
                    200 + (i as u128 - 25)
                }
            });
            let update =
                MutatorSetUpdate::new(vec![removal_record(first), removal_record(second)], vec![]);

            let mut msa_sequential = msa.clone();
            let sequential_is_valid =
                sequential_apply_reference(&update, &mut msa_sequential, &mut [], &mut []);
            assert!(sequential_is_valid);

            let mut msa_batch = msa.clone();
            assert!(update.apply_to_accumulator(&mut msa_batch).is_err());

            assert_eq!(msa_sequential, msa_batch);
        }
    }

    mod compose {
        use itertools::Itertools;
        use neptune_mutator_set::addition_record::AdditionRecord;
        use neptune_mutator_set::authenticated_item::AuthenticatedItem;
        use neptune_mutator_set::commit;
        use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
        use neptune_mutator_set::removal_record::RemovalRecord;
        use neptune_mutator_set::shared::BATCH_SIZE;
        use neptune_mutator_set::test_shared::mock_item_and_randomnesses;
        use rand::Rng;

        use super::MutatorSetUpdate;

        #[test]
        fn compose_three_updates_into_one() {
            // Construct three valid updates, and compose them into one. Verify the
            // correctness of the composed update.
            let mut accumulator = MutatorSetAccumulator::default();

            let (initial_ars, (items, (srs, rps))): (Vec<_>, (Vec<_>, (Vec<_>, Vec<_>))) = (0..100)
                .map(|_| {
                    let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
                    (
                        commit(item, sender_randomness, receiver_preimage.hash()),
                        (item, (sender_randomness, receiver_preimage)),
                    )
                })
                .collect_vec()
                .into_iter()
                .unzip();

            // List of consistent pairs of (mutator set acc, update) where the
            // update's removal records are valid under the mutator set acc.
            let mut states = vec![(
                accumulator.clone(),
                MutatorSetUpdate::new(vec![], initial_ars.clone()),
            )];

            let mut auth_items = vec![];
            for j in 0..100 {
                AuthenticatedItem::batch_update_from_addition(
                    &mut auth_items.iter_mut().collect_vec(),
                    &accumulator,
                    initial_ars[j],
                );
                auth_items.push(AuthenticatedItem {
                    item: items[j],
                    ms_membership_proof: accumulator.prove(items[j], srs[j], rps[j]),
                });
                accumulator.add(&initial_ars[j]);
            }

            // Construct and apply the next two consistent updates
            for j in 0..=1 {
                // Construct all addition records/removal records before applying
                // anything, as all cryptographic data must only be valid against
                // the snapshotted accumulator.
                let mut addition_records = vec![];
                for _ in 0..100 {
                    let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
                    let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
                    addition_records.push(addition_record);
                }

                let rrs = auth_items
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| i % 3 == j)
                    .map(|(_, auth_item)| {
                        accumulator.drop(auth_item.item, &auth_item.ms_membership_proof)
                    })
                    .collect_vec();

                let update = MutatorSetUpdate::new(rrs, addition_records);
                states.push((accumulator.clone(), update.clone()));

                update
                    .apply_to_accumulator_and_records(
                        &mut accumulator,
                        &mut [],
                        &mut auth_items.iter_mut().collect_vec(),
                    )
                    .unwrap();
            }

            states.reverse();

            let composed = MutatorSetUpdate::compose(&states);

            let mut rebuilt_from_composition = MutatorSetAccumulator::default();
            composed
                .apply_to_accumulator(&mut rebuilt_from_composition)
                .unwrap();

            assert_eq!(accumulator, rebuilt_from_composition)
        }

        #[test]
        fn compose_block_mutations_equals_sequential_application() {
            let mut rng = rand::rng();
            let mut accumulator = MutatorSetAccumulator::default();

            // A pool of live removal records, kept synced to the accumulator, for
            // the updates to draw their removals from. `pool_tags` records, per
            // pool entry, whether the removed item predates the chain of updates.
            let mut pool: Vec<RemovalRecord> = vec![];
            let mut pool_tags: Vec<bool> = vec![];
            let add_item = |accumulator: &mut MutatorSetAccumulator,
                            pool: &mut Vec<RemovalRecord>|
             -> AdditionRecord {
                let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
                let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
                let mp = accumulator.prove(item, sender_randomness, receiver_preimage);
                RemovalRecord::batch_update_from_addition(
                    &mut pool.iter_mut().collect::<Vec<_>>(),
                    accumulator,
                );
                accumulator.add(&addition_record);
                pool.push(accumulator.drop(item, &mp));
                addition_record
            };

            // Seed the accumulator so the first update has something to remove.
            for _ in 0..(2 * BATCH_SIZE) {
                add_item(&mut accumulator, &mut pool);
            }
            pool_tags.extend(std::iter::repeat_n(true, pool.len()));

            // Build a chain of updates, each with additions and removals, applied
            // to the accumulator as it goes.
            let old_msa = accumulator.clone();
            let num_updates = 6;
            let mut chain = vec![];
            let mut chain_tags = vec![];
            for _ in 0..num_updates {
                let predecessor_msa = accumulator.clone();

                // Draw this update's removals from the pool. Their pre-update
                // form goes into the chain; the working copies follow the
                // update's application.
                let mut working_removals = vec![];
                let mut update_tags = vec![];
                for _ in 0..2 {
                    let draw = rng.random_range(0..pool.len());
                    working_removals.push(pool.remove(draw));
                    update_tags.push(pool_tags.remove(draw));
                }
                let stored_removals = working_removals.clone();

                // Create and apply the additions one at a time, keeping the pool
                // and the pending removals in sync.
                let mut additions = vec![];
                for _ in 0..4 {
                    let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
                    let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
                    let mp = accumulator.prove(item, sender_randomness, receiver_preimage);
                    RemovalRecord::batch_update_from_addition(
                        &mut pool
                            .iter_mut()
                            .chain(working_removals.iter_mut())
                            .collect::<Vec<_>>(),
                        &accumulator,
                    );
                    accumulator.add(&addition_record);
                    pool.push(accumulator.drop(item, &mp));
                    pool_tags.push(false);
                    additions.push(addition_record);
                }

                // Apply the removals, keeping the pool in sync.
                MutatorSetUpdate::new(working_removals, vec![])
                    .apply_to_accumulator_and_records(
                        &mut accumulator,
                        &mut pool.iter_mut().collect::<Vec<_>>(),
                        &mut [],
                    )
                    .unwrap();

                chain.push((
                    predecessor_msa,
                    MutatorSetUpdate::new(stored_removals, additions),
                ));
                chain_tags.push(update_tags);
            }
            let tip_hash = accumulator.hash();

            // Compose the chain, most recent update first.
            chain.reverse();
            chain_tags.reverse();
            let composed = MutatorSetUpdate::compose(&chain);

            // Composed removal records for items that predate the chain must be
            // valid at the old state. Records for items added within the chain
            // itself cannot be: those become valid only as the replay of the
            // additions progresses, which the application below checks.
            let composed_tags = chain_tags.iter().rev().flatten().collect::<Vec<_>>();
            assert_eq!(composed_tags.len(), composed.removals.len());
            for (born_before_chain, removal_record) in composed_tags.iter().zip(&composed.removals)
            {
                if **born_before_chain {
                    assert!(removal_record.validate(&old_msa));
                    assert!(old_msa.can_remove(removal_record));
                }
            }
            let mut replay_msa = old_msa;
            composed.apply_to_accumulator(&mut replay_msa).unwrap();
            assert_eq!(tip_hash, replay_msa.hash());
        }
    }
}
