use rand::{thread_rng, RngCore};

use crate::{
    shared_math::b_field_element::BFieldElement,
    util_types::{
        mmr::mmr_trait::Mmr,
        mutator_set::{
            ms_membership_proof::MsMembershipProof, removal_record::RemovalRecord,
            set_commitment::SetCommitment,
        },
        simple_hasher::{self, ToDigest},
    },
};

pub fn insert_item<H: simple_hasher::Hasher, M: Mmr<H>>(
    mutator_set: &mut SetCommitment<H, M>,
) -> (MsMembershipProof<H>, H::Digest)
where
    u128: ToDigest<H::Digest>,
    Vec<BFieldElement>: ToDigest<<H as simple_hasher::Hasher>::Digest>,
{
    let mut prng = thread_rng();
    let hasher = H::new();
    let new_item = hasher.hash(
        &(0..3)
            .map(|_| BFieldElement::new(prng.next_u64()))
            .collect::<Vec<_>>(),
    );
    let randomness = hasher.hash(
        &(0..3)
            .map(|_| BFieldElement::new(prng.next_u64()))
            .collect::<Vec<_>>(),
    );

    let addition_record = mutator_set.commit(&new_item, &randomness);
    let membership_proof = mutator_set.prove(&new_item, &randomness, true);
    mutator_set.add_helper(&addition_record);

    (membership_proof, new_item)
}

pub fn remove_item<H: simple_hasher::Hasher, M: Mmr<H>>(
    mutator_set: &mut SetCommitment<H, M>,
    item: &H::Digest,
    mp: &MsMembershipProof<H>,
) where
    u128: ToDigest<H::Digest>,
    Vec<BFieldElement>: ToDigest<<H as simple_hasher::Hasher>::Digest>,
{
    let removal_record: RemovalRecord<H> = mutator_set.drop(item, mp);
    mutator_set.remove_helper(&removal_record);
}
