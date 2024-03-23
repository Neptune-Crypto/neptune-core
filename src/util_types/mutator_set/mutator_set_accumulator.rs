use crate::models::blockchain::shared::Hash;
use crate::prelude::twenty_first;

use crate::util_types::mmr::traits::*;
use crate::util_types::mmr::MmrAccumulator;
use get_size::GetSize;
use serde::{Deserialize, Serialize};
use twenty_first::shared_math::bfield_codec::BFieldCodec;
use twenty_first::shared_math::tip5::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

use super::{
    active_window::ActiveWindow, addition_record::AdditionRecord,
    ms_membership_proof::MsMembershipProof, mutator_set_kernel::MutatorSetKernel,
    mutator_set_trait::*, removal_record::RemovalRecord,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, GetSize, BFieldCodec)]
pub struct MutatorSetAccumulator {
    pub kernel: MutatorSetKernel<MmrAccumulator<Hash>>,
}

impl MutatorSetAccumulator {
    pub fn new() -> Self {
        let set_commitment = MutatorSetKernel::<MmrAccumulator<Hash>> {
            aocl: MmrAccumulator::default(),
            swbf_inactive: MmrAccumulator::default(),
            swbf_active: ActiveWindow::new(),
        };

        Self {
            kernel: set_commitment,
        }
    }
}

impl Default for MutatorSetAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl MutatorSetAsync for MutatorSetAccumulator {
    async fn prove(
        &mut self,
        item: Digest,
        sender_randomness: Digest,
        receiver_preimage: Digest,
    ) -> MsMembershipProof {
        self.kernel
            .prove(item, sender_randomness, receiver_preimage)
            .await
    }

    async fn verify(&self, item: Digest, membership_proof: &MsMembershipProof) -> bool {
        self.kernel.verify(item, membership_proof).await
    }

    fn drop(&self, item: Digest, membership_proof: &MsMembershipProof) -> RemovalRecord {
        self.kernel.drop(item, membership_proof)
    }

    async fn add(&mut self, addition_record: &AdditionRecord) {
        self.kernel.add_helper(addition_record).await;
    }

    async fn remove(&mut self, removal_record: &RemovalRecord) {
        self.kernel.remove_helper(removal_record).await;
    }

    async fn hash(&self) -> Digest {
        let aocl_mmr_bagged = self.kernel.aocl.bag_peaks().await;
        let inactive_swbf_bagged = self.kernel.swbf_inactive.bag_peaks().await;
        let active_swbf_bagged = Hash::hash(&self.kernel.swbf_active);
        let default = Digest::default();

        Hash::hash_pair(
            Hash::hash_pair(aocl_mmr_bagged, inactive_swbf_bagged),
            Hash::hash_pair(active_swbf_bagged, default),
        )
    }

    async fn batch_remove(
        &mut self,
        removal_records: Vec<RemovalRecord>,
        preserved_membership_proofs: &mut [&mut MsMembershipProof],
    ) {
        self.kernel
            .batch_remove(removal_records, preserved_membership_proofs)
            .await;
    }
}

#[cfg(test)]
mod ms_accumulator_tests {
    use crate::util_types::{
        mutator_set::shared::{BATCH_SIZE, CHUNK_SIZE, NUM_TRIALS, WINDOW_SIZE},
        test_shared::mutator_set::*,
    };
    use itertools::{izip, Itertools};
    use rand::{thread_rng, Rng};

    use crate::util_types::mutator_set::mutator_set_trait::*;

    use super::*;

    #[tokio::test]
    async fn mutator_set_batch_remove_accumulator_test() {
        // Test the batch-remove function for mutator set accumulator
        let mut accumulator: MutatorSetAccumulator = MutatorSetAccumulator::default();
        let mut membership_proofs: Vec<MsMembershipProof> = vec![];
        let mut items: Vec<Digest> = vec![];

        // Add N elements to the MS
        let num_additions = 44;
        for _ in 0..num_additions {
            let (item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();

            let addition_record = commit(item, sender_randomness, receiver_preimage.hash::<Hash>());
            let membership_proof = accumulator
                .prove(item, sender_randomness, receiver_preimage)
                .await;

            MsMembershipProof::batch_update_from_addition(
                &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                &items,
                &accumulator.kernel,
                &addition_record,
            )
            .await
            .expect("MS membership update must work");

            accumulator.add(&addition_record).await;

            membership_proofs.push(membership_proof);
            items.push(item);
        }

        // Now build removal records for about half of the elements
        let mut rng = rand::thread_rng();
        let mut skipped_removes: Vec<bool> = vec![];
        let mut removal_records: Vec<RemovalRecord> = vec![];
        for (mp, &item) in membership_proofs.iter().zip_eq(items.iter()) {
            let skipped = rng.gen_range(0.0..1.0) < 0.5;
            skipped_removes.push(skipped);
            if !skipped {
                removal_records.push(accumulator.drop(item, mp));
            }
        }

        for (mp, &item) in membership_proofs.iter().zip_eq(items.iter()) {
            assert!(accumulator.verify(item, mp).await);
        }

        // Remove the entries with batch_remove
        accumulator
            .batch_remove(
                removal_records,
                &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
            )
            .await;

        // Verify that the expected membership proofs fail/pass
        for (mp, &item, skipped) in izip!(
            membership_proofs.iter(),
            items.iter(),
            skipped_removes.into_iter()
        ) {
            // If this removal record was not applied, then the membership proof must verify
            assert_eq!(skipped, accumulator.verify(item, mp).await);
        }
    }

    #[tokio::test]
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
        let mut rng = rand::thread_rng();

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
                let new_commitment = accumulator.hash().await;
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

                if rng.gen_range(0u8..2) == 0 || start_fill && i < number_of_interactions / 2 {
                    // Add a new item to the mutator set and update all membership proofs
                    let (item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();

                    let addition_record: AdditionRecord =
                        commit(item, sender_randomness, receiver_preimage.hash::<Hash>());
                    let membership_proof_acc = accumulator
                        .prove(item, sender_randomness, receiver_preimage)
                        .await;

                    // Update all membership proofs
                    // Uppdate membership proofs in batch
                    let previous_mps = membership_proofs_batch.clone();
                    let update_result = MsMembershipProof::batch_update_from_addition(
                        &mut membership_proofs_batch.iter_mut().collect::<Vec<_>>(),
                        &items,
                        &accumulator.kernel,
                        &addition_record,
                    )
                    .await;
                    assert!(update_result.is_ok(), "Batch mutation must return OK");

                    // Update membership proofs sequentially
                    for (mp, &own_item) in membership_proofs_sequential.iter_mut().zip(items.iter())
                    {
                        let update_res_seq = mp
                            .update_from_addition(own_item, &accumulator, &addition_record)
                            .await;
                        assert!(update_res_seq.is_ok());
                    }

                    accumulator.add(&addition_record).await;
                    archival_after_remove.add(&addition_record).await;
                    archival_before_remove.add(&addition_record).await;

                    let updated_mp_indices = update_result.unwrap();
                    println!("{}: Inserted", i);
                    for j in 0..items.len() {
                        if updated_mp_indices.contains(&j) {
                            assert!(
                                !accumulator.verify(items[j], &previous_mps[j]).await,
                                "Verify must fail for old proof, j = {}. AOCL data index was: {}.\n\nOld mp:\n {:?}.\n\nNew mp is\n {:?}",
                                j,
                                previous_mps[j].auth_path_aocl.leaf_index,
                                previous_mps[j],
                                membership_proofs_batch[j]
                            );
                        } else {
                            assert!(
                                accumulator.verify(items[j], &previous_mps[j]).await,
                                "Verify must succeed for old proof, j = {}. AOCL data index was: {}.\n\nOld mp:\n {:?}.\n\nNew mp is\n {:?}",
                                j,
                                previous_mps[j].auth_path_aocl.leaf_index,
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

                    let item_index = rng.gen_range(0..membership_proofs_batch.len());
                    let removal_item = items.remove(item_index);
                    let removal_mp = membership_proofs_batch.remove(item_index);
                    let _removal_mp_seq = membership_proofs_sequential.remove(item_index);
                    let _removal_rand = rands.remove(item_index);

                    // generate removal record
                    let removal_record: RemovalRecord = accumulator.drop(removal_item, &removal_mp);
                    assert!(removal_record.validate(&accumulator.kernel).await);

                    // update membership proofs
                    // Uppdate membership proofs in batch
                    let original_membership_proofs_batch = membership_proofs_batch.clone();
                    let batch_update_ret = MsMembershipProof::batch_update_from_remove(
                        &mut membership_proofs_batch.iter_mut().collect::<Vec<_>>(),
                        &removal_record,
                    );
                    assert!(batch_update_ret.is_ok());

                    // Update membership proofs sequentially
                    let original_membership_proofs_sequential =
                        membership_proofs_sequential.clone();
                    let mut update_by_remove_return_values: Vec<bool> = vec![];
                    for mp in membership_proofs_sequential.iter_mut() {
                        let update_res_seq = mp.update_from_remove(&removal_record);
                        assert!(update_res_seq.is_ok());
                        update_by_remove_return_values.push(update_res_seq.unwrap());
                    }

                    // remove item from set
                    assert!(accumulator.verify(removal_item, &removal_mp).await);
                    let removal_record_copy = removal_record.clone();
                    accumulator.remove(&removal_record).await;
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
                    assert!(!accumulator.verify(removal_item, &removal_mp).await);

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
                                !accumulator.verify(item, original_mp).await,
                                "j = {}, \n\nOriginal mp:\n{:#?}\n\nNew mp:\n{:#?}",
                                j,
                                original_mp,
                                membership_proofs_sequential[j]
                            );
                        } else {
                            assert!(
                                accumulator.verify(item, original_mp).await,
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
                        let item_verifies = accumulator.verify(item, original_mp).await;
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
                    assert!(accumulator.verify(item, mp_batch).await);

                    // Verify that the membership proof can be restored from an archival instance
                    let arch_mp = archival_after_remove
                        .restore_membership_proof(
                            item,
                            sender_randomness,
                            receiver_preimage,
                            mp_batch.auth_path_aocl.leaf_index,
                        )
                        .await
                        .unwrap();
                    assert_eq!(arch_mp, mp_batch.to_owned());

                    // Verify that sequential and batch update produces the same membership proofs
                    assert_eq!(mp_batch, mp_seq);
                }
            }
        }
    }

    #[test]
    fn test_mutator_set_accumulator_decode() {
        for _ in 0..100 {
            let msa = random_mutator_set_accumulator();
            let encoded = msa.encode();
            let decoded: MutatorSetAccumulator = *MutatorSetAccumulator::decode(&encoded).unwrap();
            assert_eq!(msa, decoded);
        }
    }

    #[ignore]
    #[tokio::test]
    async fn profile() {
        // populate a mutator set with items according to some target profile,
        // and then print the size of the mutator set accumulator, in bytes
        let mut rng = thread_rng();
        println!(
            "profiling Mutator Set (w, b, s, k) = ({}, {}, {}, {}) ...",
            WINDOW_SIZE, BATCH_SIZE, CHUNK_SIZE, NUM_TRIALS
        );
        let mut msa = MutatorSetAccumulator::new();
        let mut items_and_membership_proofs: Vec<(Digest, MsMembershipProof)> = vec![];
        let target_set_size = 100;
        let num_iterations = 10000;

        for i in 0..num_iterations {
            if i % 100 == 0 {
                println!("{}/{}", i, num_iterations);
            }
            let operation = if items_and_membership_proofs.len()
                > (1.25 * target_set_size as f64) as usize
            {
                rng.gen_range(0..10) >= 3
            } else if items_and_membership_proofs.len() < (0.8 * target_set_size as f64) as usize {
                rng.gen_range(0..10) < 3
            } else {
                rng.gen_range(0..10) < 5
            };
            if operation && !items_and_membership_proofs.is_empty() {
                // removal
                let index = rng.gen_range(0..items_and_membership_proofs.len());
                let (item, membership_proof) = items_and_membership_proofs.swap_remove(index);
                let removal_record = msa.drop(item, &membership_proof);
                for (_it, mp) in items_and_membership_proofs.iter_mut() {
                    mp.update_from_remove(&removal_record).unwrap();
                }
                msa.remove(&removal_record).await;
            } else {
                // addition
                let item = rng.gen::<Digest>();
                let sender_randomness = rng.gen::<Digest>();
                let receiver_preimage = rng.gen::<Digest>();
                let addition_record = commit(item, sender_randomness, receiver_preimage);
                for (it, mp) in items_and_membership_proofs.iter_mut() {
                    mp.update_from_addition(*it, &msa, &addition_record)
                        .await
                        .unwrap();
                }
                let membership_proof = msa.prove(item, sender_randomness, receiver_preimage).await;
                msa.add(&addition_record).await;
                items_and_membership_proofs.push((item, membership_proof));
            }
        }

        println!("{} operations resulted in a set containin {} elements; mutator set accumulator size: {} bytes", num_iterations, items_and_membership_proofs.len(), msa.get_size());
    }
}
