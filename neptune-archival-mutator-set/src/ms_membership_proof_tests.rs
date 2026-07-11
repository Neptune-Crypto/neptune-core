//! Tests relocated from `neptune_mutator_set::ms_membership_proof`.
//!
//! These exercise `MsMembershipProof` update/revert logic driven by a
//! database-backed archival mutator set, so they must live in the crate that
//! can depend on both the accumulator and the archival mutator set.

use std::collections::HashMap;

use itertools::Either;
use itertools::Itertools;
use macro_rules_attr::apply;
use neptune_mutator_set::addition_record::AdditionRecord;
use neptune_mutator_set::commit;
use neptune_mutator_set::ms_membership_proof::MsMembershipProof;
use neptune_mutator_set::removal_record::RemovalRecord;
use proptest::collection;
use proptest::prelude::any;
use proptest_arbitrary_interop::arb;
use rand::random;
use rand::rngs::StdRng;
use rand::Rng;
use rand::RngCore;
use rand::SeedableRng;
use tasm_lib::twenty_first::tip5::digest::Digest;

use crate::test_shared::empty_rusty_mutator_set;
use crate::test_utils::shared_tokio_runtime;

const N: usize = 100;

#[test_strategy::proptest(async = "tokio")]
async fn revert_update_from_remove_test(
    #[strategy(0..N)] own_index: usize,
    #[strategy(collection::vec(arb::<Digest>(), N))] mut item_vec: Vec<Digest>,
    #[strategy(collection::vec(arb::<Digest>(), N))] mut sender_randomness_vec: Vec<Digest>,
    #[strategy(collection::vec(arb::<Digest>(), N))] mut receiver_preimage_vec: Vec<Digest>,
    #[strategy(collection::vec(any::<bool>(), N))] mut condition: Vec<bool>,
    #[any] cutoff_rand: usize,
) {
    let mut own_membership_proof = None;
    let mut own_item = None;

    // set up mutator set
    let mut rms = empty_rusty_mutator_set().await;
    let archival_mutator_set = rms.ams_mut();
    let mut membership_proofs: Vec<(Digest, MsMembershipProof)> = vec![];

    // add items
    for i in 0..N {
        let item: Digest = item_vec.pop().unwrap();
        let sender_randomness: Digest = sender_randomness_vec.pop().unwrap();
        let receiver_preimage: Digest = receiver_preimage_vec.pop().unwrap();
        let addition_record = commit(item, sender_randomness, receiver_preimage.hash());

        for (oi, mp) in &mut membership_proofs {
            mp.update_from_addition(
                *oi,
                &archival_mutator_set.accumulator().await,
                &addition_record,
            )
            .expect("Could not update membership proof from addition.");
        }

        let membership_proof = archival_mutator_set
            .prove(item, sender_randomness, receiver_preimage)
            .await;
        if i == own_index {
            own_membership_proof = Some(membership_proof);
            own_item = Some(item);
        } else {
            membership_proofs.push((item, membership_proof));
            if i > own_index {
                own_membership_proof
                    .as_mut()
                    .unwrap()
                    .update_from_addition(
                        own_item.unwrap(),
                        &archival_mutator_set.accumulator().await,
                        &addition_record,
                    )
                    .expect("Could not update membership proof from addition record.");
            }
        }

        archival_mutator_set.add(&addition_record).await;
    }

    // assert that own mp is valid
    assert!(
        archival_mutator_set
            .verify(own_item.unwrap(), own_membership_proof.as_ref().unwrap())
            .await
    );

    // Assert that all other mps are valid
    for (itm, mp) in &membership_proofs {
        assert!(archival_mutator_set.verify(*itm, mp).await);
    }

    // generate some removal records
    let mut removal_records = vec![];
    for (item, membership_proof) in membership_proofs {
        if condition.pop().unwrap() {
            let removal_record = archival_mutator_set.drop(item, &membership_proof).await;
            removal_records.push(removal_record);
        }
    }
    let cutoff_point = 1 + (cutoff_rand % (removal_records.len() - 1));
    let mut membership_proof_snapshot = None;

    // apply removal records
    for i in 0..removal_records.len() {
        let (immutable_records, mutable_records) = removal_records.split_at_mut(i + 1);
        let applied_removal_record = immutable_records.last().unwrap();

        RemovalRecord::batch_update_from_remove(
            &mut mutable_records.iter_mut().collect::<Vec<_>>(),
            applied_removal_record,
        );

        own_membership_proof
            .as_mut()
            .unwrap()
            .update_from_remove(applied_removal_record);

        archival_mutator_set.remove(applied_removal_record).await;

        if i + 1 == cutoff_point {
            membership_proof_snapshot = Some(own_membership_proof.as_ref().unwrap().clone());
        }
    }

    // assert valid
    assert!(
        archival_mutator_set
            .verify(own_item.unwrap(), own_membership_proof.as_ref().unwrap())
            .await
    );

    // revert some removal records
    let mut reversions = removal_records[cutoff_point..].to_vec();
    reversions.reverse();
    for revert_removal_record in &reversions {
        own_membership_proof
            .as_mut()
            .unwrap()
            .revert_update_from_remove(revert_removal_record);

        archival_mutator_set
            .revert_remove(revert_removal_record)
            .await;

        // keep other removal records up-to-date?
        // - nah, we don't need them for anything anymore
    }

    // assert valid
    assert!(
        archival_mutator_set
            .verify(own_item.unwrap(), own_membership_proof.as_ref().unwrap())
            .await
    );

    // assert same as snapshot before application-and-reversion
    assert_eq!(
        own_membership_proof.unwrap(),
        membership_proof_snapshot.unwrap()
    );
}

#[apply(shared_tokio_runtime)]
async fn revert_update_single_remove_test() {
    let mut rms = empty_rusty_mutator_set().await;
    let ams = rms.ams_mut();
    let mut mps = vec![];
    let mut items = vec![];
    let mut addition_records = vec![];
    let ms_size = 30;
    for _ in 0..ms_size {
        let item: Digest = random();
        let sender_randomness: Digest = random();
        let receiver_preimage: Digest = random();
        let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
        MsMembershipProof::batch_update_from_addition(
            &mut mps.iter_mut().collect_vec(),
            &items,
            &ams.accumulator().await,
            &addition_record,
        )
        .unwrap();
        mps.push(ams.prove(item, sender_randomness, receiver_preimage).await);
        items.push(item);
        ams.add(&addition_record).await;
        addition_records.push(addition_record);
    }

    // Verify that all MPs are valid
    for i in 0..ms_size {
        assert!(ams.verify(items[i], &mps[i]).await);
    }

    // Remove all `ms_size` elements from the MS
    let mut removal_records = vec![];
    for i in 0..ms_size {
        let removal_record = ams.drop(items[i], &mps[i]).await;
        ams.remove(&removal_record).await;
        MsMembershipProof::batch_update_from_remove(
            &mut mps.iter_mut().collect_vec(),
            &removal_record,
        )
        .unwrap();
        removal_records.push(removal_record);

        // Verify that the rest of the MPs are still valid
        for j in 0..ms_size {
            if j > i {
                assert!(ams.verify(items[j], &mps[j]).await);
            } else {
                assert!(!ams.verify(items[j], &mps[j]).await);
            }
        }
    }

    // Verify that all MPs are invalid since their items were removed
    for i in 0..ms_size {
        assert!(!ams.verify(items[i], &mps[i]).await);
    }

    // Revert all removals in opposite order and verify that the MPs become valid again
    for i in (0..ms_size).rev() {
        ams.revert_remove(&removal_records[i]).await;
        for mp in mps.iter_mut().take(ms_size) {
            mp.revert_update_from_remove(&removal_records[i]);
        }
        for j in 0..ms_size {
            if j < i {
                assert!(!ams.verify(items[j], &mps[j]).await);
            } else {
                assert!(ams.verify(items[j], &mps[j]).await);
            }
        }
    }

    // Verify all MPs after reverting all removals
    for i in 0..ms_size {
        ams.verify(items[i], &mps[i]).await;
    }
}

#[apply(shared_tokio_runtime)]
async fn revert_update_single_addition_test() {
    for j in 2..30 {
        let mut rms = empty_rusty_mutator_set().await;
        let ams = rms.ams_mut();

        // Add `j` items to MSA
        let mut mps = vec![];
        let mut items = vec![];
        let mut addition_records = vec![];
        for _ in 0..j {
            let item: Digest = random();
            let sender_randomness: Digest = random();
            let receiver_preimage: Digest = random();
            let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
            MsMembershipProof::batch_update_from_addition(
                &mut mps.iter_mut().collect_vec(),
                &items,
                &ams.accumulator().await,
                &addition_record,
            )
            .unwrap();
            mps.push(ams.prove(item, sender_randomness, receiver_preimage).await);
            items.push(item);
            ams.add(&addition_record).await;
            addition_records.push(addition_record);
        }

        // Revert all adds but the first one, and keep the 1st MP updated
        for i in (1..j).rev() {
            ams.revert_add(&addition_records[i]).await;
            mps[0].revert_update_from_batch_addition(&ams.accumulator().await);
            assert!(
                ams.verify(items[0], &mps[0]).await,
                "MP should be valid after reversion"
            );
            if i != 1 {
                // We also check the 2nd MP for good measure, as long as its item is still in the MS
                mps[1].revert_update_from_batch_addition(&ams.accumulator().await);
                assert!(
                    ams.verify(items[1], &mps[1]).await,
                    "MP should be valid after reversion"
                );
            }
        }
    }
}

#[apply(shared_tokio_runtime)]
async fn revert_update_from_addition_test() {
    let mut rng = rand::rng();
    let n = rng.next_u32() as usize % 100 + 1;
    // let n = 55;

    let own_index = rng.next_u32() as usize % n;
    // let own_index = 8;
    let mut own_membership_proof = None;
    let mut own_item = None;

    // set up mutator set
    let mut rms = empty_rusty_mutator_set().await;
    let archival_mutator_set = rms.ams_mut();

    // add items
    let mut addition_records = vec![];
    for i in 0..n {
        let item: Digest = random();
        let sender_randomness: Digest = random();
        let receiver_preimage: Digest = random();
        let addition_record = commit(item, sender_randomness, receiver_preimage.hash());
        addition_records.push(addition_record);

        let membership_proof = archival_mutator_set
            .prove(item, sender_randomness, receiver_preimage)
            .await;
        match i.cmp(&own_index) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => {
                own_membership_proof = Some(membership_proof);
                own_item = Some(item);
            }
            std::cmp::Ordering::Greater => {
                assert!(
                    archival_mutator_set
                        .verify(own_item.unwrap(), own_membership_proof.as_ref().unwrap())
                        .await
                );
                assert!(archival_mutator_set
                    .accumulator()
                    .await
                    .verify(own_item.unwrap(), own_membership_proof.as_ref().unwrap()));
                own_membership_proof
                    .as_mut()
                    .unwrap()
                    .update_from_addition(
                        own_item.unwrap(),
                        &archival_mutator_set.accumulator().await,
                        &addition_record,
                    )
                    .expect("Could not update membership proof from addition record.");
            }
        }

        let mutator_set_before = archival_mutator_set.accumulator().await;
        archival_mutator_set.add(&addition_record).await;

        if i > own_index {
            let own_item = own_item.as_ref().unwrap().to_owned();
            assert!(
                archival_mutator_set
                    .verify(own_item, own_membership_proof.as_ref().unwrap(),)
                    .await
            );

            let mut memproof = own_membership_proof.as_ref().unwrap().clone();

            assert!(archival_mutator_set.verify(own_item, &memproof,).await);

            memproof.revert_update_from_batch_addition(&mutator_set_before);

            assert!(mutator_set_before.verify(own_item, &memproof));
            // assert!(previous_mutator_set.set_commitment.verify(own_item, self));
        }
    }

    // revert additions
    let (_petrified, revertible) = addition_records.split_at(own_index + 1);
    for addition_record in revertible.iter().rev() {
        archival_mutator_set.revert_add(addition_record).await;
        own_membership_proof
            .as_mut()
            .unwrap()
            .revert_update_from_batch_addition(&archival_mutator_set.accumulator().await);

        assert!(
            archival_mutator_set
                .verify(own_item.unwrap(), own_membership_proof.as_ref().unwrap())
                .await
        );
    }
}

#[apply(shared_tokio_runtime)]
async fn revert_updates_mixed_test() {
    let mut rng_seeder = rand::rng();
    let error_tuple: (usize, u32) = (
        10 + rng_seeder.next_u32() as usize % 100,
        rng_seeder.next_u32(),
    );
    let n = error_tuple.0;
    let seed_integer = error_tuple.1;
    let margin = n / 5;
    println!("*********************** seed: {seed_integer} ***********************");
    let seed = seed_integer.to_be_bytes();
    let mut seed_as_bytes = [0u8; 32];
    for i in 0..32 {
        seed_as_bytes[i] = seed[i % 4];
    }

    let mut rng = StdRng::from_seed(seed_as_bytes);

    let mut rms = empty_rusty_mutator_set().await;
    let archival_mutator_set = rms.ams_mut();

    let own_index = rng.next_u32() as usize % 10;
    let mut own_item = Digest::default();
    let mut track_index = 0;

    let mut rates = HashMap::<String, f64>::new();
    rates.insert("additions".to_owned(), 0.7);
    rates.insert("removals".to_owned(), 0.95);

    let mut tracked_items_and_membership_proofs: Vec<(Digest, MsMembershipProof)> = vec![];
    let mut removed_items_and_membership_proofs: Vec<(Digest, MsMembershipProof, usize)> = vec![];
    let mut records: Vec<Either<AdditionRecord, RemovalRecord>> = vec![];

    for i in 0..2000 {
        let sample: f64 = rng.random();

        // addition
        if sample <= rates["additions"] || i == own_index {
            println!(
                "{i}. (set size {}) addition",
                tracked_items_and_membership_proofs.len()
            );

            // generate item and randomness
            let item: Digest = rng.random();
            let sender_randomness: Digest = rng.random();
            let receiver_preimage: Digest = rng.random();

            // generate addition record
            let addition_record = commit(item, sender_randomness, receiver_preimage.hash());

            // record membership proof
            let membership_proof = archival_mutator_set
                .prove(item, sender_randomness, receiver_preimage)
                .await;

            // update existing membership proof
            for (it, mp) in &mut tracked_items_and_membership_proofs {
                mp.update_from_addition(
                    *it,
                    &archival_mutator_set.accumulator().await,
                    &addition_record,
                )
                .expect("Could not update membership proof from addition.");
            }

            // apply record
            archival_mutator_set.add(&addition_record).await;

            // record record
            records.push(Either::Left(addition_record));

            // if own record, set iamp index and own item
            if i == own_index {
                track_index = tracked_items_and_membership_proofs.len();
                own_item = item;
                println!("own item index: {track_index}");
            }

            // record item, membership proof pair
            tracked_items_and_membership_proofs.push((item, membership_proof));

            // if too many items are in the mutator set, revise rates
            if tracked_items_and_membership_proofs.len() > n + margin && i > n {
                *rates.get_mut("additions").unwrap() = 0.3;
                *rates.get_mut("removals").unwrap() = 0.8;
            }
        }
        // removal
        else if sample > rates["additions"]
            && sample <= rates["removals"]
            && tracked_items_and_membership_proofs.len() > 1
        {
            println!(
                "{i}. (set size {}) removal",
                tracked_items_and_membership_proofs.len()
            );

            // sample index of item and membership proof to remove,
            // but not the index of the own item
            let mut index = track_index;
            while index == track_index {
                index = rng.next_u32() as usize % tracked_items_and_membership_proofs.len()
            }

            // remove the indicated item and membership proof from the track list
            let (item, membership_proof) = tracked_items_and_membership_proofs.remove(index);
            if track_index > index {
                track_index -= 1;
            }

            // generate a removal record
            let removal_record = archival_mutator_set.drop(item, &membership_proof).await;

            // update the other membership proofs with the removal record
            for (_, mp) in &mut tracked_items_and_membership_proofs {
                mp.update_from_remove(&removal_record);
            }

            // don't lose track of the removed item
            assert!(
                archival_mutator_set.verify(item, &membership_proof).await,
                "track index: {track_index}\nitem index: {index}",
            );
            removed_items_and_membership_proofs.push((item, membership_proof.clone(), index));

            // remove the item from the mutator set
            archival_mutator_set.remove(&removal_record).await;

            // record record
            records.push(Either::Right(removal_record));

            // if there are too few items in the mutator set, revise rates
            if tracked_items_and_membership_proofs.len() < n - margin && i > n {
                *rates.get_mut("additions").unwrap() = 0.5;
                *rates.get_mut("removals").unwrap() = 0.8;
            }
        }
        // reversion
        else if tracked_items_and_membership_proofs.len() > 1 {
            // sample reversion depth
            let max_reversions = tracked_items_and_membership_proofs.len() - track_index;
            if max_reversions > 0 {
                let num_reversions = rng.next_u32() as usize % max_reversions;
                if num_reversions > 0 {
                    let set_size_was = tracked_items_and_membership_proofs.len();

                    // test if all records to be reverted are additions
                    let mut all_reversions_are_additions = true;
                    for j in 0..num_reversions {
                        if !matches!(records[records.len() - 1 - j], Either::Left(_)) {
                            all_reversions_are_additions = false;
                        }
                    }

                    // if they are, revert via batch
                    if all_reversions_are_additions && num_reversions > 1 {
                        println!(
                            "{i}. (set size {}) reversion [{}]",
                            tracked_items_and_membership_proofs.len(),
                            vec!["a"; num_reversions].join("")
                        );
                        for _ in 0..num_reversions {
                            if let Some(Either::Left(addition_record)) = records.pop() {
                                archival_mutator_set.revert_add(&addition_record).await;
                            }
                            tracked_items_and_membership_proofs.pop();
                        }
                        for (_, mp) in &mut tracked_items_and_membership_proofs {
                            mp.revert_update_from_batch_addition(
                                &archival_mutator_set.accumulator().await,
                            );
                        }
                    }
                    // otherwise, revert individually
                    else {
                        let mut records_abbreviation = "".to_string();
                        for _ in 0..num_reversions {
                            if let Some(record) = records.pop() {
                                match record {
                                    Either::Left(addition_record) => {
                                        records_abbreviation = format!("{records_abbreviation}a");

                                        // revert update to mutator set
                                        archival_mutator_set.revert_add(&addition_record).await;
                                        tracked_items_and_membership_proofs.pop();
                                        for (_, mp) in &mut tracked_items_and_membership_proofs {
                                            mp.revert_update_from_batch_addition(
                                                &archival_mutator_set.accumulator().await,
                                            );
                                        }
                                    }
                                    Either::Right(removal_record) => {
                                        let mut _report_index = 0;

                                        // start reverting removal record
                                        records_abbreviation = format!("{records_abbreviation}r");

                                        // revert update to mutator set
                                        archival_mutator_set.revert_remove(&removal_record).await;

                                        // assert valid proofs
                                        for (_, mp) in &mut tracked_items_and_membership_proofs {
                                            mp.revert_update_from_remove(&removal_record);
                                        }

                                        match removed_items_and_membership_proofs.pop() {
                                            Some((item, membership_proof, index)) => {
                                                assert!(
                                                    archival_mutator_set
                                                        .verify(item, &membership_proof)
                                                        .await
                                                );
                                                tracked_items_and_membership_proofs
                                                    .insert(index, (item, membership_proof));
                                                _report_index = index;
                                                if index <= track_index {
                                                    track_index += 1;
                                                }
                                            }
                                            None => {
                                                panic!("No entries in removed_items_and_membership_proofs to pop!");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        println!(
                            "{i}. (set size {}) reversion ({})",
                            set_size_was, records_abbreviation
                        );
                    }
                }
            }
        }

        if i > own_index {
            assert_eq!(own_item, tracked_items_and_membership_proofs[track_index].0);
            assert!(
                archival_mutator_set
                    .verify(
                        own_item,
                        &tracked_items_and_membership_proofs[track_index].1
                    )
                    .await,
                "seed: {seed_integer} / n: {n}",
            );
        }
    }
}
