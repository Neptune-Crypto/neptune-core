use rand::{thread_rng, RngCore};
use rusty_leveldb::DB;

use crate::util_types::mutator_set::{
    archival_mutator_set::ArchivalMutatorSet, ms_membership_proof::MsMembershipProof,
    removal_record::RemovalRecord, set_commitment::SetCommitment,
};
use twenty_first::{
    shared_math::{b_field_element::BFieldElement, traits::GetRandomElements},
    util_types::{
        mmr::mmr_trait::Mmr,
        simple_hasher::{Hashable, Hasher},
    },
};

pub fn empty_archival_ms<H>() -> ArchivalMutatorSet<H>
where
    H: Hasher,
    u128: Hashable<<H as Hasher>::T>,
    Vec<BFieldElement>: Hashable<<H as Hasher>::T>,
{
    let opt: rusty_leveldb::Options = rusty_leveldb::in_memory();
    let chunks_db = DB::open("chunks", opt.clone()).unwrap();
    let aocl_db = DB::open("aocl", opt.clone()).unwrap();
    let swbf_db = DB::open("swbf", opt).unwrap();
    ArchivalMutatorSet::new_empty(aocl_db, swbf_db, chunks_db)
}

pub fn insert_item<H, M>(mutator_set: &mut SetCommitment<H, M>) -> (MsMembershipProof<H>, H::Digest)
where
    H: Hasher,
    M: Mmr<H>,
    u128: Hashable<<H as Hasher>::T>,
    Vec<BFieldElement>: Hashable<<H as Hasher>::T>,
    <H as Hasher>::T: GetRandomElements,
{
    let mut prng = thread_rng();
    let hasher = H::new();

    let random_elements = H::T::random_elements(3, &mut prng);
    let new_item: H::Digest = hasher.hash_sequence(&random_elements[0..3]);
    let randomness: H::Digest = hasher.hash_sequence(&random_elements[3..6]);

    let mut addition_record = mutator_set.commit(&new_item, &randomness);
    let membership_proof = mutator_set.prove(&new_item, &randomness, true);
    mutator_set.add_helper(&mut addition_record);

    (membership_proof, new_item)
}

pub fn remove_item<H, M>(
    mutator_set: &mut SetCommitment<H, M>,
    item: &H::Digest,
    mp: &MsMembershipProof<H>,
) where
    H: Hasher,
    M: Mmr<H>,
    u128: Hashable<<H as Hasher>::T>,
    Vec<BFieldElement>: Hashable<<H as Hasher>::T>,
{
    let removal_record: RemovalRecord<H> = mutator_set.drop(item, mp);
    mutator_set.remove_helper(&removal_record);
}
