use std::sync::{Arc, Mutex};

use rand::Rng;
use rusty_leveldb::DB;

use twenty_first::shared_math::rescue_prime_digest::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use twenty_first::util_types::mmr::archival_mmr::ArchivalMmr;
use twenty_first::util_types::mmr::mmr_trait::Mmr;
use twenty_first::util_types::storage_vec::{RustyLevelDbVec, StorageVec};

use crate::util_types::mutator_set::active_window::ActiveWindow;
use crate::util_types::mutator_set::archival_mutator_set::ArchivalMutatorSet;
use crate::util_types::mutator_set::chunk::Chunk;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::mutator_set_kernel::MutatorSetKernel;
use crate::util_types::mutator_set::removal_record::RemovalRecord;
use crate::util_types::mutator_set::rusty_archival_mutator_set::{AOCL_KEY, CHUNK_KEY, SWBFI_KEY};
use crate::util_types::mutator_set::shared::CHUNK_SIZE;

pub fn get_all_indices_with_duplicates<
    H: AlgebraicHasher,
    MmrStorage: StorageVec<Digest>,
    ChunkStorage: StorageVec<Chunk>,
>(
    archival_mutator_set: &mut ArchivalMutatorSet<H, MmrStorage, ChunkStorage>,
) -> Vec<u128> {
    let mut ret: Vec<u128> = vec![];

    for index in archival_mutator_set.kernel.swbf_active.sbf.iter() {
        ret.push(*index as u128);
    }

    let chunk_count = archival_mutator_set.chunks.len();
    for chunk_index in 0..chunk_count {
        let chunk = archival_mutator_set.chunks.get(chunk_index);
        for index in chunk.relative_indices.iter() {
            ret.push(*index as u128 + CHUNK_SIZE as u128 * chunk_index as u128);
        }
    }

    ret
}

pub fn make_item_and_randomness() -> (Digest, Digest) {
    let mut rng = rand::thread_rng();
    let item: Digest = rng.gen();
    let randomness: Digest = rng.gen();
    (item, randomness)
}

#[allow(clippy::type_complexity)]
pub fn empty_rustyleveldbvec_ams<H: AlgebraicHasher>() -> (
    ArchivalMutatorSet<H, RustyLevelDbVec<Digest>, RustyLevelDbVec<Chunk>>,
    Arc<Mutex<DB>>,
) {
    let opt: rusty_leveldb::Options = rusty_leveldb::in_memory();
    let db = DB::open("unit test ams", opt).unwrap();
    let db = Arc::new(Mutex::new(db));
    let aocl_storage = RustyLevelDbVec::new(db.clone(), AOCL_KEY, "aocl");
    let swbfi = RustyLevelDbVec::new(db.clone(), SWBFI_KEY, "swbfi");
    let chunks = RustyLevelDbVec::new(db.clone(), CHUNK_KEY, "chunks");
    let kernel = MutatorSetKernel {
        aocl: ArchivalMmr::new(aocl_storage),
        swbf_inactive: ArchivalMmr::new(swbfi),
        swbf_active: ActiveWindow::default(),
    };
    (ArchivalMutatorSet { kernel, chunks }, db)
}

pub fn insert_item<H: AlgebraicHasher, M: Mmr<H>>(
    mutator_set: &mut MutatorSetKernel<H, M>,
) -> (MsMembershipProof<H>, Digest) {
    let (new_item, randomness) = make_item_and_randomness();

    let mut addition_record = mutator_set.commit(&new_item, &randomness);
    let membership_proof = mutator_set.prove(&new_item, &randomness, true);
    mutator_set.add_helper(&mut addition_record);

    (membership_proof, new_item)
}

pub fn remove_item<H: AlgebraicHasher, M: Mmr<H>>(
    mutator_set: &mut MutatorSetKernel<H, M>,
    item: &Digest,
    mp: &MsMembershipProof<H>,
) {
    let removal_record: RemovalRecord<H> = mutator_set.drop(item, mp);
    mutator_set.remove_helper(&removal_record);
}
