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
    use crate::util_types::{blake3_wrapper, simple_hasher::Hasher};
    use rand::prelude::*;
    use rand_core::RngCore;

    use super::*;

    #[test]
    fn mutator_set_accumulator_pbt() {
        type Hasher = blake3::Hasher;
        type Digest = blake3_wrapper::Blake3Hash;
        let hasher = Hasher::new();
        let mut ms: MutatorSetAccumulator<Hasher> = MutatorSetAccumulator::default();
        let number_of_interactions = 50;
        let mut prng = thread_rng();

        let mut membership_proofs: Vec<MembershipProof<Hasher>> = vec![];
        let mut items: Vec<Digest> = vec![];

        // The outer loop runs two times:
        // 1. insert `number_of_interactions / 2` items, then randomly insert and remove `number_of_interactions / 2` times
        // 2. Randomly insert and remove `number_of_interactions` times
        for start_fill in [true, false] {
            for i in 0..number_of_interactions {
                if prng.gen_range(0u8..2) == 0 || start_fill && i < number_of_interactions / 2 {
                    // Add a new item to the mutator set and update all membership proofs
                    let item = hasher.hash::<Digest>(&(prng.next_u64() as u128).into());
                    let randomness = hasher.hash::<Digest>(&(prng.next_u64() as u128).into());
                    let addition_record: AdditionRecord<Hasher> = ms.commit(&item, &randomness);
                    let membership_proof = ms.prove(&item, &randomness, true);
                    let update_result = MembershipProof::batch_update_from_addition(
                        &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                        &items,
                        &ms,
                        &addition_record,
                    );
                    assert!(update_result.is_ok(), "Batch mutation must return OK");
                    ms.add(&addition_record);

                    membership_proofs.push(membership_proof);
                    items.push(item);

                    // Update all membership proofs
                    println!("{}: Inserted", i);
                } else {
                    // Remove an item from the mutator set and update all membership proofs
                    if membership_proofs.is_empty() {
                        continue;
                    }

                    let item_index = prng.gen_range(0..membership_proofs.len());
                    let removal_item = items.remove(item_index);
                    let removal_mp = membership_proofs.remove(item_index);

                    // generate removal record
                    let mut removal_record: RemovalRecord<Hasher> =
                        ms.drop(&removal_item.into(), &removal_mp);
                    assert!(removal_record.validate(&ms));

                    // update membership proofs
                    let res = MembershipProof::batch_update_from_remove(
                        &mut membership_proofs.iter_mut().collect::<Vec<_>>(),
                        &removal_record,
                    );
                    assert!(res.is_ok());

                    // remove item from set
                    assert!(ms.verify(&removal_item.into(), &removal_mp));
                    ms.remove(&mut removal_record);
                    assert!(!ms.verify(&removal_item.into(), &removal_mp));

                    println!("{}: Removed", i);
                }

                // Verify that all membership proofs are valid after these additions and removals
                // TODO: This for-loop is pretty slow. Can we make a batch verifier for MS membership proofs?
                for (_, (mp, item)) in membership_proofs.iter().zip(items.iter()).enumerate() {
                    assert!(ms.verify(&item, &mp));
                }
            }
        }
    }
}
