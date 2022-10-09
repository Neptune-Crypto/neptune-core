use rand::distributions::Standard;
use rand::prelude::Distribution;
use rand::RngCore;
use rusty_leveldb::DB;

use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::shared_math::other::random_elements;
use twenty_first::shared_math::rescue_prime_regular::RescuePrimeRegular;
use twenty_first::util_types::blake3_wrapper::Blake3Hash;
use twenty_first::util_types::mmr::mmr_trait::Mmr;
use twenty_first::util_types::simple_hasher::{Hashable, Hasher};

use crate::util_types::mutator_set::{
    archival_mutator_set::ArchivalMutatorSet, ms_membership_proof::MsMembershipProof,
    removal_record::RemovalRecord, set_commitment::SetCommitment,
};

pub fn make_item_and_randomness_for_blake3() -> (Blake3Hash, Blake3Hash) {
    let mut rng = rand::thread_rng();

    let mut entropy1: [u8; 32] = [0u8; 32];
    rng.fill_bytes(&mut entropy1);
    let mut entropy2: [u8; 32] = [0u8; 32];
    rng.fill_bytes(&mut entropy2);

    (entropy1.into(), entropy2.into())
}

pub fn make_item_and_randomness_for_rp() -> ([BFieldElement; 5], [BFieldElement; 5]) {
    type H = RescuePrimeRegular;

    let random_elements = random_elements(6);
    let item: <H as Hasher>::Digest = H::new().hash_sequence(&random_elements[0..3]);
    let randomness: <H as Hasher>::Digest = H::new().hash_sequence(&random_elements[3..6]);

    (item, randomness)
}

pub fn empty_archival_ms<H>() -> ArchivalMutatorSet<H>
where
    H: Hasher,
    u128: Hashable<<H as Hasher>::T>,
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
    Standard: Distribution<<H as Hasher>::T>,
{
    let random_elements = random_elements(6);
    let new_item: H::Digest = H::new().hash_sequence(&random_elements[0..3]);
    let randomness: H::Digest = H::new().hash_sequence(&random_elements[3..6]);

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
{
    let removal_record: RemovalRecord<H> = mutator_set.drop(item, mp);
    mutator_set.remove_helper(&removal_record);
}
