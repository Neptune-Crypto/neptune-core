use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use itertools::Itertools;
use rand::{thread_rng, Rng};
use rand_core::RngCore;
use rusty_leveldb::DB;

use twenty_first::shared_math::other::random_elements;
use twenty_first::shared_math::tip5::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use twenty_first::util_types::mmr::archival_mmr::ArchivalMmr;
use twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
use twenty_first::util_types::mmr::mmr_trait::Mmr;
use twenty_first::util_types::storage_vec::{RustyLevelDbVec, StorageVec};

use crate::util_types::mutator_set::active_window::ActiveWindow;
use crate::util_types::mutator_set::archival_mutator_set::ArchivalMutatorSet;
use crate::util_types::mutator_set::chunk::Chunk;
use crate::util_types::mutator_set::chunk_dictionary::ChunkDictionary;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::mutator_set_kernel::MutatorSetKernel;
use crate::util_types::mutator_set::mutator_set_trait::commit;
use crate::util_types::mutator_set::removal_record::{AbsoluteIndexSet, RemovalRecord};
use crate::util_types::mutator_set::shared::{CHUNK_SIZE, NUM_TRIALS};

pub fn random_chunk_dictionary<H: AlgebraicHasher>() -> ChunkDictionary<H> {
    let mut rng = thread_rng();

    let mut dictionary = HashMap::new();
    for _ in 0..37 {
        let key = rng.next_u64();
        let authpath: Vec<Digest> = random_elements(rng.next_u32() as usize % 6);
        let chunk: Vec<u32> = random_elements(rng.next_u32() as usize % 17);

        dictionary.insert(
            key,
            (
                MmrMembershipProof::new(key, authpath),
                Chunk {
                    relative_indices: chunk,
                },
            ),
        );
    }
    ChunkDictionary::<H>::new(dictionary)
}

pub fn random_removal_record<H: AlgebraicHasher>() -> RemovalRecord<H> {
    let mut rng = thread_rng();
    let absolute_indices = AbsoluteIndexSet::new(
        &(0..NUM_TRIALS as usize)
            .map(|_| ((rng.next_u64() as u128) << 64) ^ rng.next_u64() as u128)
            .collect_vec()
            .try_into()
            .unwrap(),
    );
    let target_chunks = random_chunk_dictionary();

    RemovalRecord {
        absolute_indices,
        target_chunks,
    }
}

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

pub fn make_item_and_randomnesses() -> (Digest, Digest, Digest) {
    let mut rng = rand::thread_rng();
    let item: Digest = rng.gen();
    let sender_randomness: Digest = rng.gen();
    let receiver_preimage: Digest = rng.gen();
    (item, sender_randomness, receiver_preimage)
}

#[allow(clippy::type_complexity)]
pub fn empty_rustyleveldbvec_ams<H: AlgebraicHasher>() -> (
    ArchivalMutatorSet<H, RustyLevelDbVec<Digest>, RustyLevelDbVec<Chunk>>,
    Arc<Mutex<DB>>,
) {
    const AOCL_KEY: u8 = 0;
    const SWBFI_KEY: u8 = 1;
    const CHUNK_KEY: u8 = 2;
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

pub fn insert_mock_item<H: AlgebraicHasher, M: Mmr<H>>(
    mutator_set: &mut MutatorSetKernel<H, M>,
) -> (MsMembershipProof<H>, Digest) {
    let (new_item, sender_randomness, receiver_preimage) = make_item_and_randomnesses();

    let addition_record = commit::<H>(
        &new_item,
        &sender_randomness,
        &receiver_preimage.hash::<H>(),
    );
    let membership_proof = mutator_set.prove(&new_item, &sender_randomness, &receiver_preimage);
    mutator_set.add_helper(&addition_record);

    (membership_proof, new_item)
}

pub fn remove_mock_item<H: AlgebraicHasher, M: Mmr<H>>(
    mutator_set: &mut MutatorSetKernel<H, M>,
    item: &Digest,
    mp: &MsMembershipProof<H>,
) {
    let removal_record: RemovalRecord<H> = mutator_set.drop(item, mp);
    mutator_set.remove_helper(&removal_record);
}
