use crate::{
    shared_math::b_field_element::BFieldElement,
    util_types::{
        mmr::mmr_accumulator::MmrAccumulator,
        simple_hasher::{Hasher, ToDigest},
    },
};

use super::{
    addition_record::AdditionRecord, membership_proof::MembershipProof,
    mutator_set_trait::MutatorSet, removal_record::RemovalRecord, set_commitment::SetCommitment,
};

pub type MutatorSetAccumulator<H> = SetCommitment<H, MmrAccumulator<H>>;

impl<H: Hasher> MutatorSet<H> for MutatorSetAccumulator<H>
where
    u128: ToDigest<<H as Hasher>::Digest>,
    Vec<BFieldElement>: ToDigest<<H as Hasher>::Digest>,
    H: Hasher,
{
    fn default() -> Self {
        SetCommitment::default()
    }

    fn prove(
        &self,
        item: &H::Digest,
        randomness: &H::Digest,
        store_bits: bool,
    ) -> MembershipProof<H> {
        self.prove(item, randomness, store_bits)
    }

    fn verify(&self, item: &H::Digest, membership_proof: &MembershipProof<H>) -> bool {
        self.verify(item, membership_proof)
    }

    fn commit(&self, item: &H::Digest, randomness: &H::Digest) -> AdditionRecord<H> {
        self.commit(item, randomness)
    }

    fn drop(&self, item: &H::Digest, membership_proof: &MembershipProof<H>) -> RemovalRecord<H> {
        self.drop(item, membership_proof)
    }

    fn add(&mut self, addition_record: &AdditionRecord<H>) {
        self.add_helper(addition_record);
    }

    fn remove(&mut self, removal_record: &RemovalRecord<H>) {
        self.remove_helper(removal_record);
    }
}

#[cfg(test)]
mod accumulation_scheme_tests {
    use crate::util_types::{
        blake3_wrapper, mutator_set::archival_mutator_set::ArchivalMutatorSet,
        simple_hasher::Hasher,
    };
    use rand::prelude::*;
    use rand_core::RngCore;

    use super::*;

    #[test]
    fn mutator_set_accumulator_pbt() {
        // This tests verifies that items can be added and removed from the mutator set
        // without assuming anything about the order of the adding and removal. It also
        // verifies that the membership proofs handled through an mutator set accumulator
        // are the same as those that are produced from an archival mutator set.

        // This function mixes both archival and accumulator testing.
        // It *may* be considered bad style to do it this way, but there is a
        // lot of code duplication that is avoided by doing that.
        type Hasher = blake3::Hasher;
        type Digest = blake3_wrapper::Blake3Hash;
        let hasher = Hasher::new();
        let mut accumulator: MutatorSetAccumulator<Hasher> = MutatorSetAccumulator::default();
        let mut archival: ArchivalMutatorSet<Hasher> = ArchivalMutatorSet::default();
        let number_of_interactions = 50;
        let mut prng = thread_rng();

        // The outer loop runs two times:
        // 1. insert `number_of_interactions / 2` items, then randomly insert and remove `number_of_interactions / 2` times
        // 2. Randomly insert and remove `number_of_interactions` times
        for start_fill in [true, false] {
            let mut membership_proofs_batch: Vec<MembershipProof<Hasher>> = vec![];
            let mut membership_proofs_sequential: Vec<MembershipProof<Hasher>> = vec![];
            let mut items: Vec<Digest> = vec![];
            let mut rands: Vec<Digest> = vec![];
            for i in 0..number_of_interactions {
                if prng.gen_range(0u8..2) == 0 || start_fill && i < number_of_interactions / 2 {
                    // Add a new item to the mutator set and update all membership proofs
                    let item = hasher.hash::<Digest>(&(prng.next_u64() as u128).into());
                    let randomness = hasher.hash::<Digest>(&(prng.next_u64() as u128).into());
                    let addition_record: AdditionRecord<Hasher> =
                        accumulator.commit(&item, &randomness);
                    let membership_proof_acc = accumulator.prove(&item, &randomness, true);

                    // Update all membership proofs
                    // Uppdate membership proofs in batch
                    let previous_mps = membership_proofs_batch.clone();
                    let update_result = MembershipProof::batch_update_from_addition(
                        &mut membership_proofs_batch.iter_mut().collect::<Vec<_>>(),
                        &items,
                        &accumulator,
                        &addition_record,
                    );
                    assert!(update_result.is_ok(), "Batch mutation must return OK");

                    // Update membership proofs sequentially
                    for (mp, own_item) in membership_proofs_sequential.iter_mut().zip(items.iter())
                    {
                        let update_res_seq =
                            mp.update_from_addition(own_item, &accumulator, &addition_record);
                        assert!(update_res_seq.is_ok());
                    }

                    accumulator.add(&addition_record);
                    archival.add(&addition_record);

                    let updated_mp_indices = update_result.unwrap();
                    println!("{}: Inserted", i);
                    for j in 0..items.len() {
                        if updated_mp_indices.contains(&j) {
                            assert!(
                                !accumulator.verify(&items[j], &previous_mps[j]),
                                "Verify must fail for old proof, j = {}. AOCL data index was: {}.\n\nOld mp:\n {:?}.\n\nNew mp is\n {:?}",
                                j,
                                previous_mps[j].auth_path_aocl.data_index,
                                previous_mps[j],
                                membership_proofs_batch[j]
                            );
                        } else {
                            assert!(
                                accumulator.verify(&items[j], &previous_mps[j]),
                                "Verify must succeed for old proof, j = {}. AOCL data index was: {}.\n\nOld mp:\n {:?}.\n\nNew mp is\n {:?}",
                                j,
                                previous_mps[j].auth_path_aocl.data_index,
                                previous_mps[j],
                                membership_proofs_batch[j]
                            );
                        }
                    }

                    membership_proofs_batch.push(membership_proof_acc.clone());
                    membership_proofs_sequential.push(membership_proof_acc);
                    items.push(item);
                    rands.push(randomness);
                } else {
                    // Remove an item from the mutator set and update all membership proofs
                    if membership_proofs_batch.is_empty() {
                        continue;
                    }

                    let item_index = prng.gen_range(0..membership_proofs_batch.len());
                    let removal_item = items.remove(item_index);
                    let removal_mp = membership_proofs_batch.remove(item_index);
                    let _removal_mp_seq = membership_proofs_sequential.remove(item_index);
                    let _removal_rand = rands.remove(item_index);

                    // generate removal record
                    let mut removal_record: RemovalRecord<Hasher> =
                        accumulator.drop(&removal_item.into(), &removal_mp);
                    assert!(removal_record.validate(&accumulator));

                    // update membership proofs
                    // Uppdate membership proofs in batch
                    let res = MembershipProof::batch_update_from_remove(
                        &mut membership_proofs_batch.iter_mut().collect::<Vec<_>>(),
                        &removal_record,
                    );
                    assert!(res.is_ok());

                    // Update membership proofs sequentially
                    for mp in membership_proofs_sequential.iter_mut() {
                        let update_res_seq = mp.update_from_remove(&removal_record);
                        assert!(update_res_seq.is_ok());
                    }

                    // remove item from set
                    assert!(accumulator.verify(&removal_item.into(), &removal_mp));
                    accumulator.remove(&mut removal_record);
                    archival.remove(&mut removal_record);
                    assert!(!accumulator.verify(&removal_item.into(), &removal_mp));

                    println!("{}: Removed", i);
                }

                // Verify that all membership proofs are valid after these additions and removals
                // Also verify that batch-update and sequential update of membership proofs agree.
                for (((mp_batch, mp_seq), item), rand) in membership_proofs_batch
                    .iter()
                    .zip(membership_proofs_sequential.iter())
                    .zip(items.iter())
                    .zip(rands.iter())
                {
                    assert!(accumulator.verify(item, mp_batch));

                    // Verify that the membership proof can be restored from an archival instance
                    let arch_mp = archival
                        .restore_membership_proof(item, rand, mp_batch.auth_path_aocl.data_index)
                        .unwrap();
                    assert_eq!(arch_mp, *mp_batch);

                    // Also verify that cached bits are set for both proofs and that they agree
                    assert!(arch_mp.cached_bits.is_some());
                    assert_eq!(arch_mp.cached_bits, mp_batch.cached_bits);

                    // Verify that sequential and batch update produces the same membership proofs
                    assert_eq!(mp_batch, mp_seq);
                }
            }
        }
    }
}
