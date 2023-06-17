use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use itertools::Itertools;
use rand::rngs::StdRng;
use rand::{random, thread_rng, Rng, RngCore, SeedableRng};
use rusty_leveldb::DB;

use twenty_first::shared_math::bfield_codec::BFieldCodec;
use twenty_first::shared_math::other::random_elements;
use twenty_first::shared_math::tip5::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use twenty_first::util_types::mmr::archival_mmr::ArchivalMmr;
use twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
use twenty_first::util_types::mmr::mmr_trait::Mmr;
use twenty_first::util_types::storage_vec::{RustyLevelDbVec, StorageVec};

use crate::util_types::mutator_set::active_window::ActiveWindow;
use crate::util_types::mutator_set::archival_mutator_set::ArchivalMutatorSet;
use crate::util_types::mutator_set::chunk::Chunk;
use crate::util_types::mutator_set::chunk_dictionary::ChunkDictionary;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::mutator_set_kernel::MutatorSetKernel;
use crate::util_types::mutator_set::mutator_set_trait::commit;
use crate::util_types::mutator_set::removal_record::{AbsoluteIndexSet, RemovalRecord};
use crate::util_types::mutator_set::shared::{CHUNK_SIZE, NUM_TRIALS, WINDOW_SIZE};

pub fn pseudorandom_chunk_dictionary<H: AlgebraicHasher>(seed: [u8; 32]) -> ChunkDictionary<H> {
    let mut rng: StdRng = SeedableRng::from_seed(seed);

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

pub fn random_chunk_dictionary<H: AlgebraicHasher>() -> ChunkDictionary<H> {
    let mut rng = thread_rng();
    pseudorandom_chunk_dictionary(rng.gen::<[u8; 32]>())
}

pub fn get_all_indices_with_duplicates<
    H: AlgebraicHasher + BFieldCodec,
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
pub fn empty_rustyleveldbvec_ams<H: AlgebraicHasher + BFieldCodec>() -> (
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

pub fn insert_mock_item<H: AlgebraicHasher + BFieldCodec, M: Mmr<H>>(
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

pub fn remove_mock_item<H: AlgebraicHasher + BFieldCodec, M: Mmr<H>>(
    mutator_set: &mut MutatorSetKernel<H, M>,
    item: &Digest,
    mp: &MsMembershipProof<H>,
) {
    let removal_record: RemovalRecord<H> = mutator_set.drop(item, mp);
    mutator_set.remove_helper(&removal_record);
}

/// Generate a random MSA. For serialization testing. Might not be a consistent or valid object.
pub fn random_mutator_set_accumulator<H: AlgebraicHasher + BFieldCodec>() -> MutatorSetAccumulator<H>
{
    let kernel = random_mutator_set_kernel();
    MutatorSetAccumulator { kernel }
}

/// Generate a random MSK. For serialization testing. Might not be a consistent or valid object.
pub fn random_mutator_set_kernel<H: AlgebraicHasher + BFieldCodec>(
) -> MutatorSetKernel<H, MmrAccumulator<H>> {
    let aocl = random_mmra();
    let swbf_inactive = random_mmra();
    let swbf_active = random_swbf_active();
    MutatorSetKernel {
        aocl,
        swbf_inactive,
        swbf_active,
    }
}

/// Generate a random MMRA. For serialization testing. Might not be a consistent or valid object.
pub fn random_mmra<H: AlgebraicHasher>() -> MmrAccumulator<H> {
    let leaf_count = thread_rng().next_u32() as u64;
    let peaks: Vec<Digest> = random_elements((thread_rng().next_u32() % 10) as usize);
    MmrAccumulator::init(peaks, leaf_count)
}

pub fn random_swbf_active<H: AlgebraicHasher + BFieldCodec>() -> ActiveWindow<H> {
    let mut rng = thread_rng();
    let num_indices = 10 + (rng.next_u32() % 100) as usize;

    let mut aw = ActiveWindow::<H>::new();
    for _ in 0..num_indices {
        aw.insert(rng.next_u32() % WINDOW_SIZE);
    }

    aw
}

pub fn random_mmr_membership_proof<H: AlgebraicHasher>() -> MmrMembershipProof<H> {
    let leaf_index: u64 = random();
    let authentication_path: Vec<Digest> = random_elements((thread_rng().next_u32() % 15) as usize);
    MmrMembershipProof {
        leaf_index,
        authentication_path,
        _hasher: PhantomData,
    }
}

/// Generate a random MsMembershipProof. For serialization testing. Might not be a consistent or valid object.
pub fn random_mutator_set_membership_proof<H: AlgebraicHasher>() -> MsMembershipProof<H> {
    let sender_randomness: Digest = random();
    let receiver_preimage: Digest = random();
    let auth_path_aocl: MmrMembershipProof<H> = random_mmr_membership_proof::<H>();
    let target_chunks: ChunkDictionary<H> = random_chunk_dictionary();
    MsMembershipProof {
        sender_randomness,
        receiver_preimage,
        auth_path_aocl,
        target_chunks,
    }
}

pub fn random_removal_record<H: AlgebraicHasher>() -> RemovalRecord<H> {
    let mut rng = thread_rng();
    pseudorandom_removal_record(rng.gen::<[u8; 32]>())
}

pub fn pseudorandom_removal_record<H: AlgebraicHasher>(seed: [u8; 32]) -> RemovalRecord<H> {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let absolute_indices = AbsoluteIndexSet::new(
        &(0..NUM_TRIALS as usize)
            .map(|_| ((rng.next_u64() as u128) << 64) ^ rng.next_u64() as u128)
            .collect_vec()
            .try_into()
            .unwrap(),
    );
    let target_chunks = pseudorandom_chunk_dictionary(rng.gen::<[u8; 32]>());

    RemovalRecord {
        absolute_indices,
        target_chunks,
    }
}

#[cfg(test)]
mod shared_tests_test {
    use twenty_first::shared_math::tip5::Tip5;

    use super::*;

    #[test]
    fn can_call() {
        type H = Tip5;
        let rcd = random_chunk_dictionary::<H>();
        assert!(!rcd.dictionary.is_empty());
        let _ = random_removal_record::<H>();
        let (mut ams, _) = empty_rustyleveldbvec_ams::<H>();
        let _ = get_all_indices_with_duplicates(&mut ams);
        let _ = make_item_and_randomnesses();
        let _ = insert_mock_item(&mut ams.kernel);
    }
}
