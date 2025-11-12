use std::error::Error;
use std::fmt;

use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;

use self::addition_record::AdditionRecord;
use crate::util_types::mutator_set::shared::BATCH_SIZE;

pub mod active_window;
pub mod addition_record;
pub mod archival_mutator_set;
pub mod authenticated_item;
pub mod mmra_and_membership_proofs;
pub mod ms_membership_proof;
#[cfg(any(test, feature = "arbitrary-impls"))]
pub mod msa_and_records;
pub mod mutator_set_accumulator;
pub mod removal_record;
pub mod root_and_paths;
pub mod rusty_archival_mutator_set;
pub mod shared;

impl Error for MutatorSetError {}

impl fmt::Display for MutatorSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MutatorSetError {
    RequestedAoclAuthPathOutOfBounds((u64, u64)),
    RequestedSwbfAuthPathOutOfBounds((u64, u64)),
    MutatorSetIsEmpty,
    AbsoluteRemovalIndexIsFutureIndex {
        current_max_chunk_index: u64,
        saw_chunk_index: u64,
    },
    AbsoluteIndexExceedsTheoreticalBound,
    RequestedAoclAuthPathNotContainedInResponse {
        request_aocl_leaf_index: u64,
    },
}

/// Generates an addition record from an item and explicit random-
/// ness. The addition record is itself a commitment to the item.
pub fn commit(item: Digest, sender_randomness: Digest, receiver_digest: Digest) -> AdditionRecord {
    let canonical_commitment =
        Tip5::hash_pair(Tip5::hash_pair(item, sender_randomness), receiver_digest);

    AdditionRecord::new(canonical_commitment)
}

/// Converts a number of leafs in the AOCL into a number of leafs in the
/// SWBF-MMR.
///
/// Common pitfall. The difference by one reflects the timing mismatch: the
/// window slides immediately prior to adding the first element of the new
/// batch, *not* after adding the last element of a batch. The subtraction must
/// be saturating because the empty mutator set is the exception to this rule:
/// no window slides occur when the first element is added to the first batch.
///
/// |             # leafs AOCL              | # leafs SWBFI |
/// |:-------------------------------------:|:-------------:|
/// |                                     0 |             0 |
/// |                        BATCH_SIZE - 1 |             0 |
/// |                            BATCH_SIZE |             0 |
/// |                        BATCH_SIZE + 1 |             1 |
/// |                        k * BATCH_SIZE |         k - 1 |
/// | k * BATCH_SIZE + {1, ..., BATCH_SIZE} |             k |
///
pub fn aocl_to_swbfi_leaf_counts(aocl_leaf_count: u64) -> u64 {
    aocl_leaf_count.saturating_sub(1) / u64::from(BATCH_SIZE)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use macro_rules_attr::apply;
    use rand::Rng;
    use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;
    use tests::ms_membership_proof::MsMembershipProof;
    use tests::removal_record::RemovalRecord;

    use super::*;
    use crate::tests::shared_tokio_runtime;
    use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
    use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
    use crate::util_types::mutator_set::shared::BATCH_SIZE;
    use crate::util_types::mutator_set::shared::CHUNK_SIZE;
    use crate::util_types::mutator_set::shared::WINDOW_SIZE;
    use crate::util_types::test_shared::mutator_set::*;

    #[test]
    fn get_batch_index_test() {
        // Verify that the method to get batch index returns sane results

        let mut mutator_set = MutatorSetAccumulator::default();
        assert_eq!(
            0,
            mutator_set.get_batch_index(),
            "Batch index for empty MS must be zero"
        );

        for i in 0..BATCH_SIZE {
            let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
            let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
            mutator_set.add(&addition_record);
            assert_eq!(
                0,
                mutator_set.get_batch_index(),
                "Batch index must be 0 after adding {} elements",
                i
            );
        }

        let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
        let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
        mutator_set.add(&addition_record);
        assert_eq!(
            1,
            mutator_set.get_batch_index(),
            "Batch index must be one after adding BATCH_SIZE+1 elements"
        );
    }

    #[apply(shared_tokio_runtime)]
    async fn mutator_set_hash_test() {
        let empty_set = MutatorSetAccumulator::default();
        let empty_hash = empty_set.hash();

        // Add one element to append-only commitment list
        let mut set_with_aocl_append = MutatorSetAccumulator::default();

        let (item0, _sender_randomness, _receiver_preimage) = mock_item_and_randomnesses();

        set_with_aocl_append.aocl.append(item0);
        let hash_of_aocl_append = set_with_aocl_append.hash();

        assert_ne!(
            empty_hash, hash_of_aocl_append,
            "Appending to AOCL must change MutatorSet commitment"
        );

        // Manipulate inactive SWBF
        let mut set_with_swbf_inactive_append = MutatorSetAccumulator::default();
        set_with_swbf_inactive_append.swbf_inactive.append(item0);
        let hash_of_one_in_inactive = set_with_swbf_inactive_append.hash();
        assert_ne!(
            empty_hash, hash_of_one_in_inactive,
            "Changing inactive must change MS hash"
        );
        assert_ne!(
            hash_of_aocl_append, hash_of_one_in_inactive,
            "One in AOCL and one in inactive must hash to different digests"
        );

        // Manipulate active window
        let mut active_window_changed = empty_set;
        active_window_changed.swbf_active.insert(42);
        assert_ne!(
            empty_hash,
            active_window_changed.hash(),
            "Changing active window must change commitment"
        );

        // Sanity check bc reasons
        active_window_changed.swbf_active.remove(42);
        assert_eq!(
            empty_hash,
            active_window_changed.hash(),
            "Commitment to empty MS must be consistent"
        );
    }

    #[test]
    fn ms_get_indices_test() {
        let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
        let ret = AbsoluteIndexSet::compute(item, sender_randomness, receiver_preimage, 0);
        assert!(ret.to_array().iter().all(|&x| x < u128::from(WINDOW_SIZE)));
    }

    #[test]
    fn ms_get_indices_test_big() {
        // Test that `get_indices` behaves as expected. I.e. that it returns indices in the correct range,
        // and always returns something of length `NUM_TRIALS`.
        let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
        let ret = AbsoluteIndexSet::compute(
            item,
            sender_randomness,
            receiver_preimage,
            u64::from(17 * BATCH_SIZE),
        );
        assert!(ret
            .to_array()
            .iter()
            .all(|&x| (x as u32) < WINDOW_SIZE + 17 * CHUNK_SIZE && (x as u32) >= 17 * CHUNK_SIZE));
    }

    #[apply(shared_tokio_runtime)]
    async fn init_test() {
        let accumulator = MutatorSetAccumulator::default();
        let mut rms = empty_rusty_mutator_set().await;
        let archival = rms.ams_mut();

        // Verify that function to get batch index does not overflow for the empty MS
        assert_eq!(
            0,
            accumulator.get_batch_index(),
            "Batch index must be zero for empty MS accumulator"
        );
        assert_eq!(
            0,
            archival.get_batch_index_async().await,
            "Batch index must be zero for empty archival MS"
        );
    }

    #[test]
    fn verify_future_indices_test() {
        // Ensure that `verify` does not crash when given a membership proof
        // that represents a future addition to the AOCL.

        let mut mutator_set = MutatorSetAccumulator::default();
        let empty_mutator_set = MutatorSetAccumulator::default();

        for _ in 0..2 * BATCH_SIZE + 2 {
            let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();

            let addition_record: AdditionRecord =
                commit(item, sender_randomness, receiver_preimage.hash());
            let membership_proof: MsMembershipProof =
                mutator_set.prove(item, sender_randomness, receiver_preimage);
            mutator_set.add_helper(&addition_record);
            assert!(mutator_set.verify(item, &membership_proof));

            // Verify that a future membership proof returns false and does not crash
            assert!(!empty_mutator_set.verify(item, &membership_proof));
        }
    }

    #[test]
    fn test_membership_proof_update_from_add() {
        let mut mutator_set = MutatorSetAccumulator::default();
        let (own_item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();

        let addition_record = commit(own_item, sender_randomness, receiver_preimage.hash());
        let mut membership_proof =
            mutator_set.prove(own_item, sender_randomness, receiver_preimage);
        mutator_set.add_helper(&addition_record);

        // Update membership proof with add operation. Verify that it has changed, and that it now fails to verify.
        let (new_item, new_sender_randomness, new_receiver_preimage) = mock_item_and_randomnesses();
        let new_addition_record = commit(
            new_item,
            new_sender_randomness,
            new_receiver_preimage.hash(),
        );
        let original_membership_proof = membership_proof.clone();
        let changed_mp = match membership_proof.update_from_addition(
            own_item,
            &mutator_set,
            &new_addition_record,
        ) {
            Ok(changed) => changed,
            Err(err) => panic!("{}", err),
        };
        assert!(
            changed_mp,
            "Update must indicate that membership proof has changed"
        );
        assert_ne!(
            original_membership_proof.auth_path_aocl,
            membership_proof.auth_path_aocl
        );
        assert!(
            mutator_set.verify(own_item, &original_membership_proof),
            "Original membership proof must verify prior to addition"
        );
        assert!(
            !mutator_set.verify(own_item, &membership_proof),
            "New membership proof must fail to verify prior to addition"
        );

        // Insert the new element into the mutator set, then verify that the membership proof works and
        // that the original membership proof is invalid.
        mutator_set.add_helper(&new_addition_record);
        assert!(
            !mutator_set.verify(own_item, &original_membership_proof),
            "Original membership proof must fail to verify after addition"
        );
        assert!(
            mutator_set.verify(own_item, &membership_proof),
            "New membership proof must verify after addition"
        );
    }

    #[test]
    fn membership_proof_updating_from_add_pbt() {
        let mut rng = rand::rng();

        let mut mutator_set = MutatorSetAccumulator::default();

        let num_additions = rng.random_range(0..=100i32);
        println!(
            "running multiple additions test for {} additions",
            num_additions
        );

        let mut membership_proofs_and_items: Vec<(MsMembershipProof, Digest)> = vec![];
        for i in 0..num_additions {
            println!("loop iteration {}", i);

            let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();

            let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
            let membership_proof = mutator_set.prove(item, sender_randomness, receiver_preimage);

            // Update all membership proofs
            for (mp, itm) in &mut membership_proofs_and_items {
                let original_mp = mp.clone();
                let changed_res = mp.update_from_addition(*itm, &mutator_set, &addition_record);
                assert!(changed_res.is_ok());

                // verify that the boolean returned value from the updater method is set correctly
                assert_eq!(changed_res.unwrap(), original_mp != *mp);
            }

            // Add the element
            assert!(!mutator_set.verify(item, &membership_proof));
            mutator_set.add_helper(&addition_record);
            assert!(mutator_set.verify(item, &membership_proof));
            membership_proofs_and_items.push((membership_proof, item));

            // Verify that all membership proofs work
            assert!(membership_proofs_and_items
                .clone()
                .into_iter()
                .all(|(mp, itm)| mutator_set.verify(itm, &mp)));
        }
    }

    #[test]
    fn test_add_and_prove() {
        let mut mutator_set = MutatorSetAccumulator::default();
        let (item0, sender_randomness0, receiver_preimage0) = mock_item_and_randomnesses();

        let addition_record = commit(item0, sender_randomness0, receiver_preimage0.hash());
        let membership_proof = mutator_set.prove(item0, sender_randomness0, receiver_preimage0);

        assert!(!mutator_set.verify(item0, &membership_proof));

        mutator_set.add_helper(&addition_record);

        assert!(mutator_set.verify(item0, &membership_proof));

        // Insert a new item and verify that this still works
        let (item1, sender_randomness1, receiver_preimage1) = mock_item_and_randomnesses();
        let new_ar = commit(item1, sender_randomness1, receiver_preimage1.hash());
        let new_mp = mutator_set.prove(item1, sender_randomness1, receiver_preimage1);
        assert!(!mutator_set.verify(item1, &new_mp));

        mutator_set.add_helper(&new_ar);
        assert!(mutator_set.verify(item1, &new_mp));

        // Insert ~2*BATCH_SIZE  more elements and
        // verify that it works throughout. The reason we insert this many
        // is that we want to make sure that the window slides into a new
        // position.
        for _ in 0..2 * BATCH_SIZE + 4 {
            let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
            let other_ar = commit(item, sender_randomness, receiver_preimage.hash());
            let other_mp = mutator_set.prove(item, sender_randomness, receiver_preimage);
            assert!(!mutator_set.verify(item, &other_mp));

            mutator_set.add_helper(&other_ar);
            assert!(mutator_set.verify(item, &other_mp));
        }
    }

    #[test]
    fn batch_update_from_addition_and_removal_test() {
        let mut mutator_set = MutatorSetAccumulator::default();

        // It's important to test number of additions around the shifting of the window,
        // i.e. around batch size.
        let num_additions_list = vec![
            1,
            2,
            BATCH_SIZE - 1,
            BATCH_SIZE,
            BATCH_SIZE + 1,
            6 * BATCH_SIZE - 1,
            6 * BATCH_SIZE,
            6 * BATCH_SIZE + 1,
        ];

        let mut membership_proofs: Vec<MsMembershipProof> = vec![];
        let mut items = vec![];

        for num_additions in num_additions_list {
            for _ in 0..num_additions {
                let (new_item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();

                let addition_record = commit(new_item, sender_randomness, receiver_preimage.hash());
                let membership_proof =
                    mutator_set.prove(new_item, sender_randomness, receiver_preimage);

                // Update *all* membership proofs with newly added item
                let batch_update_res = MsMembershipProof::batch_update_from_addition(
                    &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                    &items,
                    &mutator_set,
                    &addition_record,
                );
                assert!(batch_update_res.is_ok());

                mutator_set.add_helper(&addition_record);
                assert!(mutator_set.verify(new_item, &membership_proof));

                for (mp, &item) in membership_proofs.iter().zip(items.iter()) {
                    assert!(mutator_set.verify(item, mp));
                }

                membership_proofs.push(membership_proof);
                items.push(new_item);
            }

            // Remove items from MS, and verify correct updating of membership proofs
            for _ in 0..num_additions {
                let item = items.pop().unwrap();
                let mp = membership_proofs.pop().unwrap();
                assert!(mutator_set.verify(item, &mp));

                // generate removal record
                let removal_record: RemovalRecord = mutator_set.drop(item, &mp);
                assert!(removal_record.validate(&mutator_set));
                assert!(mutator_set.can_remove(&removal_record));

                // update membership proofs
                let res = MsMembershipProof::batch_update_from_remove(
                    &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                    &removal_record,
                );
                assert!(res.is_ok());

                // remove item from set
                mutator_set.remove_helper(&removal_record);
                assert!(!mutator_set.verify(item, &mp));

                for (&itm, membp) in items.iter().zip(membership_proofs.iter()) {
                    assert!(mutator_set.verify(itm, membp));
                }
            }
        }
    }

    #[test]
    fn test_multiple_adds() {
        let mut mutator_set = MutatorSetAccumulator::default();

        let num_additions = 65;

        let mut items_and_membership_proofs: Vec<(Digest, MsMembershipProof)> = vec![];

        for _ in 0..num_additions {
            let (new_item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();

            let addition_record = commit(new_item, sender_randomness, receiver_preimage.hash());
            let membership_proof =
                mutator_set.prove(new_item, sender_randomness, receiver_preimage);

            // Update *all* membership proofs with newly added item
            for (updatee_item, mp) in &mut items_and_membership_proofs {
                let original_mp = mp.clone();
                assert!(mutator_set.verify(*updatee_item, mp));
                let changed_res =
                    mp.update_from_addition(*updatee_item, &mutator_set, &addition_record);
                assert!(changed_res.is_ok());

                // verify that the boolean returned value from the updater method is set correctly
                assert_eq!(changed_res.unwrap(), original_mp != *mp);
            }

            mutator_set.add_helper(&addition_record);
            assert!(mutator_set.verify(new_item, &membership_proof));

            (0..items_and_membership_proofs.len()).for_each(|j| {
                let (old_item, mp) = &items_and_membership_proofs[j];
                assert!(mutator_set.verify(*old_item, mp))
            });

            items_and_membership_proofs.push((new_item, membership_proof));
        }

        // Verify all membership proofs
        (0..items_and_membership_proofs.len()).for_each(|k| {
            assert!(mutator_set.verify(
                items_and_membership_proofs[k].0,
                &items_and_membership_proofs[k].1,
            ));
        });

        // Remove items from MS, and verify correct updating of membership proof
        (0..num_additions).for_each(|i| {
            (i..items_and_membership_proofs.len()).for_each(|k| {
                assert!(mutator_set.verify(
                    items_and_membership_proofs[k].0,
                    &items_and_membership_proofs[k].1,
                ));
            });
            let (item, mp) = items_and_membership_proofs[i].clone();

            assert!(mutator_set.verify(item, &mp));

            // generate removal record
            let removal_record: RemovalRecord = mutator_set.drop(item, &mp);
            assert!(removal_record.validate(&mutator_set));
            assert!(mutator_set.can_remove(&removal_record));
            (i..items_and_membership_proofs.len()).for_each(|k| {
                assert!(mutator_set.verify(
                    items_and_membership_proofs[k].0,
                    &items_and_membership_proofs[k].1,
                ));
            });

            // update membership proofs
            ((i + 1)..num_additions).for_each(|j| {
                assert!(mutator_set.verify(
                    items_and_membership_proofs[j].0,
                    &items_and_membership_proofs[j].1
                ));
                items_and_membership_proofs[j]
                    .1
                    .update_from_remove(&removal_record.clone());
            });

            // remove item from set
            mutator_set.remove_helper(&removal_record);
            assert!(!mutator_set.verify(item, &mp));

            ((i + 1)..items_and_membership_proofs.len()).for_each(|k| {
                assert!(mutator_set.verify(
                    items_and_membership_proofs[k].0,
                    &items_and_membership_proofs[k].1,
                ));
            });
        });
    }

    #[test]
    fn ms_serialization_test() {
        // This test verifies that the mutator set structure can be serialized and deserialized.
        // When Rust spawns threads (as it does when it runs tests, and in the Neptune Core client),
        // the new threads only get 2MB stack memory initially. This can result in stack overflows
        // in the runtime. This test is to verify that that does not happen.
        // Cf. https://stackoverflow.com/questions/72618777/how-to-deserialize-a-nested-big-array
        // and https://stackoverflow.com/questions/72621410/how-do-i-use-serde-stacker-in-my-deserialize-implementation
        let mut mutator_set = MutatorSetAccumulator::default();

        let json_empty = serde_json::to_string(&mutator_set).unwrap();
        println!("json = \n{}", json_empty);
        let s_back = serde_json::from_str::<MutatorSetAccumulator>(&json_empty).unwrap();
        assert!(s_back.aocl.is_empty());
        assert!(s_back.swbf_inactive.is_empty());
        assert!(s_back.swbf_active.sbf.is_empty());

        // Add an item, verify correct serialization
        let (mp, item) = insert_mock_item(&mut mutator_set);
        let json_one_add = serde_json::to_string(&mutator_set).unwrap();
        println!("json_one_add = \n{}", json_one_add);
        let s_back_one_add = serde_json::from_str::<MutatorSetAccumulator>(&json_one_add).unwrap();
        assert_eq!(1, s_back_one_add.aocl.num_leafs());
        assert!(s_back_one_add.swbf_inactive.is_empty());
        assert!(s_back_one_add.swbf_active.sbf.is_empty());
        assert!(s_back_one_add.verify(item, &mp));

        // Remove an item, verify correct serialization
        remove_mock_item(&mut mutator_set, item, &mp);
        let json_one_add_one_remove = serde_json::to_string(&mutator_set).unwrap();
        println!("json_one_add = \n{}", json_one_add_one_remove);
        let s_back_one_add_one_remove =
            serde_json::from_str::<MutatorSetAccumulator>(&json_one_add_one_remove).unwrap();
        assert_eq!(
            1,
            s_back_one_add_one_remove.aocl.num_leafs(),
            "AOCL must still have exactly one leaf"
        );
        assert!(
            s_back_one_add_one_remove.swbf_inactive.is_empty(),
            "Window should not have moved"
        );
        assert!(
            !s_back_one_add_one_remove.swbf_active.sbf.is_empty(),
            "Some of the indices in the active window must now be set"
        );
        assert!(
            !s_back_one_add_one_remove.verify(item, &mp),
            "Membership proof must fail after removal"
        );
    }
}
