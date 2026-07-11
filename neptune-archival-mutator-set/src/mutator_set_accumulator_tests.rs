//! Tests relocated from `neptune_mutator_set::{lib, mutator_set_accumulator}`.
//!
//! These verify that the in-memory `MutatorSetAccumulator` agrees with a
//! database-backed archival mutator set, so they must live in the crate that
//! can depend on both.

use itertools::izip;
use macro_rules_attr::apply;
use neptune_mutator_set::addition_record::AdditionRecord;
use neptune_mutator_set::commit;
use neptune_mutator_set::ms_membership_proof::MsMembershipProof;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_mutator_set::test_shared::mock_item_and_randomnesses;
use rand::Rng;
use tasm_lib::twenty_first::tip5::digest::Digest;

use crate::test_shared::empty_rusty_mutator_set;
use crate::test_utils::shared_tokio_runtime;

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

#[apply(shared_tokio_runtime)]
async fn mutator_set_accumulator_pbt() {
    // This tests verifies that items can be added and removed from the mutator set
    // without assuming anything about the order of the adding and removal. It also
    // verifies that the membership proofs handled through an mutator set accumulator
    // are the same as those that are produced from an archival mutator set.

    // This function mixes both archival and accumulator testing.
    // It *may* be considered bad style to do it this way, but there is a
    // lot of code duplication that is avoided by doing that.

    let mut accumulator: MutatorSetAccumulator = MutatorSetAccumulator::default();
    let mut rms_after = empty_rusty_mutator_set().await;
    let archival_after_remove = rms_after.ams_mut();
    let mut rms_before = empty_rusty_mutator_set().await;
    let archival_before_remove = rms_before.ams_mut();
    let number_of_interactions = 100;
    let mut rng = rand::rng();

    // The outer loop runs two times:
    // 1. insert `number_of_interactions / 2` items, then randomly insert and remove `number_of_interactions / 2` times
    // 2. Randomly insert and remove `number_of_interactions` times
    // This should test both inserting/removing in an empty MS and in a non-empty MS
    for start_fill in [false, true] {
        let mut membership_proofs_batch: Vec<MsMembershipProof> = vec![];
        let mut membership_proofs_sequential: Vec<MsMembershipProof> = vec![];
        let mut items: Vec<Digest> = vec![];
        let mut rands: Vec<(Digest, Digest)> = vec![];
        let mut last_ms_commitment: Option<Digest> = None;
        for i in 0..number_of_interactions {
            // Verify that commitment to both the accumulator and archival data structure agree
            let new_commitment = accumulator.hash();
            assert_eq!(
                new_commitment,
                archival_after_remove.hash().await,
                "Commitment to archival/accumulator MS must agree"
            );
            match last_ms_commitment {
                None => (),
                Some(commitment) => assert_ne!(
                    commitment, new_commitment,
                    "MS commitment must change upon insertion/deletion"
                ),
            };
            last_ms_commitment = Some(new_commitment);

            if rng.random_range(0u8..2) == 0 || start_fill && i < number_of_interactions / 2 {
                // Add a new item to the mutator set and update all membership proofs
                let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();

                let addition_record: AdditionRecord =
                    commit(item, sender_randomness, receiver_preimage.hash());
                let membership_proof_acc =
                    accumulator.prove(item, sender_randomness, receiver_preimage);

                // Update all membership proofs
                // Uppdate membership proofs in batch
                let previous_mps = membership_proofs_batch.clone();
                let indices_of_updated_mps = MsMembershipProof::batch_update_from_addition(
                    &mut membership_proofs_batch.iter_mut().collect::<Vec<_>>(),
                    &items,
                    &accumulator,
                    &addition_record,
                )
                .expect("Batch mutation must return OK");

                // Update membership proofs sequentially
                for (mp, &own_item) in membership_proofs_sequential.iter_mut().zip(items.iter()) {
                    let update_res_seq =
                        mp.update_from_addition(own_item, &accumulator, &addition_record);
                    assert!(update_res_seq.is_ok());
                }

                accumulator.add(&addition_record);
                archival_after_remove.add(&addition_record).await;
                archival_before_remove.add(&addition_record).await;

                println!("{}: Inserted", i);
                for j in 0..items.len() {
                    if indices_of_updated_mps.contains(&j) {
                        assert_ne!(
                            previous_mps[j], membership_proofs_batch[j],
                            "membership proof marked as updated but still identical"
                        );
                        assert!(
                            !accumulator.verify(items[j], &previous_mps[j]),
                            "Verify must fail for old proof, j = {}. AOCL data index was: {}.\n\nOld mp:\n {:?}.\n\nNew mp is\n {:?}",
                            j,
                            previous_mps[j].aocl_leaf_index,
                            previous_mps[j],
                            membership_proofs_batch[j]
                        );
                    } else {
                        assert_eq!(
                            previous_mps[j], membership_proofs_batch[j],
                            "membership proof underwent update but not marked as such"
                        );
                        assert!(
                            accumulator.verify(items[j], &previous_mps[j]),
                            "Verify must succeed for old proof, j = {}. AOCL data index was: {}.\n\nOld mp:\n {:?}.\n\nNew mp is\n {:?}",
                            j,
                            previous_mps[j].aocl_leaf_index,
                            previous_mps[j],
                            membership_proofs_batch[j]
                        );
                    }
                }

                membership_proofs_batch.push(membership_proof_acc.clone());
                membership_proofs_sequential.push(membership_proof_acc);
                items.push(item);
                rands.push((sender_randomness, receiver_preimage));
            } else {
                // Remove an item from the mutator set and update all membership proofs
                if membership_proofs_batch.is_empty() {
                    // Set `last_ms_commitment` to None since it will otherwise be the
                    // same as in last iteration of this inner loop, and that will fail
                    // a test condition.
                    last_ms_commitment = None;
                    continue;
                }

                let item_index = rng.random_range(0..membership_proofs_batch.len());
                let removal_item = items.remove(item_index);
                let removal_mp = membership_proofs_batch.remove(item_index);
                let _removal_mp_seq = membership_proofs_sequential.remove(item_index);
                let _removal_rand = rands.remove(item_index);

                // generate removal record
                let removal_record: RemovalRecord = accumulator.drop(removal_item, &removal_mp);
                assert!(removal_record.validate(&accumulator));

                // update membership proofs
                // Uppdate membership proofs in batch
                let original_membership_proofs_batch = membership_proofs_batch.clone();
                let batch_update_ret = MsMembershipProof::batch_update_from_remove(
                    &mut membership_proofs_batch.iter_mut().collect::<Vec<_>>(),
                    &removal_record,
                );
                assert!(batch_update_ret.is_ok());

                // Update membership proofs sequentially
                let original_membership_proofs_sequential = membership_proofs_sequential.clone();
                let mut update_by_remove_return_values: Vec<bool> = vec![];
                for mp in &mut membership_proofs_sequential {
                    let update_res_seq = mp.update_from_remove(&removal_record);
                    update_by_remove_return_values.push(update_res_seq);
                }

                // remove item from set
                assert!(accumulator.verify(removal_item, &removal_mp));
                let removal_record_copy = removal_record.clone();
                accumulator.remove(&removal_record);
                archival_after_remove.remove(&removal_record).await;

                // Verify that removal record's indices are all set
                for removed_index in removal_record.absolute_indices.to_vec() {
                    assert!(
                        archival_after_remove
                            .bloom_filter_contains(removed_index)
                            .await
                    );
                }

                archival_before_remove.remove(&removal_record_copy).await;
                assert!(!accumulator.verify(removal_item, &removal_mp));

                // Verify that the sequential `update_from_remove` return value is correct
                // The return value from `update_from_remove` shows if the membership proof
                // was updated or not.
                for (j, updated, original_mp, &item) in izip!(
                    0..,
                    update_by_remove_return_values,
                    original_membership_proofs_sequential.iter(),
                    items.iter()
                ) {
                    if updated {
                        assert!(
                            !accumulator.verify(item, original_mp),
                            "j = {}, \n\nOriginal mp:\n{:#?}\n\nNew mp:\n{:#?}",
                            j,
                            original_mp,
                            membership_proofs_sequential[j]
                        );
                    } else {
                        assert!(
                            accumulator.verify(item, original_mp),
                            "j = {}, \n\nOriginal mp:\n{:#?}\n\nNew mp:\n{:#?}",
                            j,
                            original_mp,
                            membership_proofs_sequential[j]
                        );
                    }
                }

                // Verify that `batch_update_from_remove` return value is correct
                // The return value indicates which membership proofs
                let updated_indices: Vec<usize> = batch_update_ret.unwrap();
                for (j, (original_mp, &item)) in original_membership_proofs_batch
                    .iter()
                    .zip(items.iter())
                    .enumerate()
                {
                    let item_was_updated = updated_indices.contains(&j);
                    let item_verifies = accumulator.verify(item, original_mp);
                    let item_verifies_iff_not_updated = item_verifies != item_was_updated;
                    assert!(item_verifies_iff_not_updated);
                }

                println!("{}: Removed", i);
            }

            // Verify that all membership proofs are valid after these additions and removals
            // Also verify that batch-update and sequential update of membership proofs agree.
            for (mp_batch, mp_seq, &item, &(sender_randomness, receiver_preimage)) in izip!(
                membership_proofs_batch.iter(),
                membership_proofs_sequential.iter(),
                items.iter(),
                rands.iter()
            ) {
                assert!(accumulator.verify(item, mp_batch));

                // Verify that the membership proof can be restored from an archival instance,
                // both without and with privacy.
                let arch_mp = archival_after_remove
                    .restore_membership_proof(
                        item,
                        sender_randomness,
                        receiver_preimage,
                        mp_batch.aocl_leaf_index,
                    )
                    .await
                    .unwrap();
                let arch_mp_alt = archival_after_remove
                    .restore_membership_proof_privacy_preserving(arch_mp.compute_indices(item))
                    .await
                    .unwrap()
                    .extract_ms_membership_proof(
                        mp_batch.aocl_leaf_index,
                        sender_randomness,
                        receiver_preimage,
                    )
                    .unwrap();
                assert_eq!(arch_mp, arch_mp_alt);
                assert_eq!(arch_mp, mp_batch.to_owned());

                // Verify that sequential and batch update produces the same membership proofs
                assert_eq!(mp_batch, mp_seq);
            }
        }
    }
}
