use rand::Rng;
use rusty_leveldb::DB;

use twenty_first::shared_math::rescue_prime_digest::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use twenty_first::util_types::mmr::mmr_trait::Mmr;

use crate::util_types::mutator_set::archival_mutator_set::ArchivalMutatorSet;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::removal_record::RemovalRecord;
use crate::util_types::mutator_set::set_commitment::SetCommitment;

pub fn make_item_and_randomness() -> (Digest, Digest) {
    let mut rng = rand::thread_rng();
    let item: Digest = rng.gen();
    let randomness: Digest = rng.gen();
    (item, randomness)
}

pub fn empty_archival_ms<H: AlgebraicHasher>() -> ArchivalMutatorSet<H> {
    let opt: rusty_leveldb::Options = rusty_leveldb::in_memory();
    let chunks_db = DB::open("chunks", opt.clone()).unwrap();
    let aocl_db = DB::open("aocl", opt.clone()).unwrap();
    let swbf_db = DB::open("swbf", opt).unwrap();
    ArchivalMutatorSet::new_empty(aocl_db, swbf_db, chunks_db)
}

pub fn insert_item<H: AlgebraicHasher, M: Mmr<H>>(
    mutator_set: &mut SetCommitment<H, M>,
) -> (MsMembershipProof<H>, Digest) {
    let (new_item, randomness) = make_item_and_randomness();

    let mut addition_record = mutator_set.commit(&new_item, &randomness);
    let membership_proof = mutator_set.prove(&new_item, &randomness, true);
    mutator_set.add_helper(&mut addition_record);

    (membership_proof, new_item)
}

pub fn remove_item<H: AlgebraicHasher, M: Mmr<H>>(
    mutator_set: &mut SetCommitment<H, M>,
    item: &Digest,
    mp: &MsMembershipProof<H>,
) {
    let removal_record: RemovalRecord<H> = mutator_set.drop(item, mp);
    mutator_set.remove_helper(&removal_record);
}
