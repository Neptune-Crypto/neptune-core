use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use itertools::Itertools;
use rand::rngs::StdRng;
use rand::{thread_rng, Rng, RngCore, SeedableRng};
use rusty_leveldb::DB;

use twenty_first::shared_math::bfield_codec::BFieldCodec;
use twenty_first::shared_math::other::log_2_ceil;
use twenty_first::shared_math::tip5::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use twenty_first::util_types::mmr::archival_mmr::ArchivalMmr;
use twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
use twenty_first::util_types::mmr::mmr_trait::Mmr;
use twenty_first::util_types::mmr::shared_basic::leaf_index_to_mt_index_and_peak_index;
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
        let authpath: Vec<Digest> = (0..rng.gen_range(0..6)).map(|_| rng.gen()).collect_vec();
        let chunk: Vec<u32> = (0..rng.gen_range(0..17)).map(|_| rng.gen()).collect_vec();

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

/// Generate a random MMRA. For testing. Might not be a consistent or valid object.
pub fn random_mmra<H: AlgebraicHasher>() -> MmrAccumulator<H> {
    pseudorandom_mmra(thread_rng().gen())
}

pub fn pseudorandom_mmra<H: AlgebraicHasher>(seed: [u8; 32]) -> MmrAccumulator<H> {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let leaf_count = rng.next_u32() as u64;
    let num_peaks = rng.next_u32() % 10;
    let peaks: Vec<Digest> = (0..num_peaks).map(|_| rng.gen()).collect_vec();
    MmrAccumulator::init(peaks, leaf_count)
}

pub fn pseudorandom_mmra_with_mp<H: AlgebraicHasher>(
    seed: [u8; 32],
    leaf: Digest,
) -> (MmrAccumulator<H>, MmrMembershipProof<H>) {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let leaf_count = rng.next_u64();
    let num_peaks = leaf_count.count_ones();
    let leaf_index = rng.next_u64() % leaf_count;
    let (inner_index, peak_index) = leaf_index_to_mt_index_and_peak_index(leaf_index, leaf_count);
    let tree_height = log_2_ceil(inner_index as u128 + 1u128) - 1;
    let authentication_path: Vec<Digest> = (0..tree_height).map(|_| rng.gen()).collect_vec();
    let mut root = leaf;
    let mut shift = 0;
    while (inner_index >> shift) > 1 {
        if (inner_index >> shift) & 1 == 1 {
            root = H::hash_pair(&authentication_path[shift], &root);
        } else {
            root = H::hash_pair(&root, &authentication_path[shift]);
        }
        shift += 1;
    }
    let peaks: Vec<Digest> = (0..num_peaks)
        .map(|i| if i == peak_index { root } else { rng.gen() })
        .collect_vec();
    let membership_proof = MmrMembershipProof::<H> {
        leaf_index,
        authentication_path,
        _hasher: PhantomData,
    };
    let mmr_accumulator = MmrAccumulator::<H>::init(peaks, leaf_count);
    (mmr_accumulator, membership_proof)
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

pub fn _random_mmr_membership_proof<H: AlgebraicHasher>() -> MmrMembershipProof<H> {
    pseudorandom_mmr_membership_proof(thread_rng().gen())
}

pub fn pseudorandom_mmr_membership_proof<H: AlgebraicHasher>(
    seed: [u8; 32],
) -> MmrMembershipProof<H> {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let leaf_index: u64 = rng.gen();
    let authentication_path: Vec<Digest> =
        (0..rng.gen_range(0..15)).map(|_| rng.gen()).collect_vec();
    MmrMembershipProof {
        leaf_index,
        authentication_path,
        _hasher: PhantomData,
    }
}

/// Generate a random MsMembershipProof. For serialization testing. Might not be a consistent or valid object.
pub fn random_mutator_set_membership_proof<H: AlgebraicHasher>() -> MsMembershipProof<H> {
    pseudorandom_mutator_set_membership_proof(thread_rng().gen())
}

pub fn pseudorandom_mutator_set_membership_proof<H: AlgebraicHasher>(
    seed: [u8; 32],
) -> MsMembershipProof<H> {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let sender_randomness: Digest = rng.gen();
    let receiver_preimage: Digest = rng.gen();
    let auth_path_aocl: MmrMembershipProof<H> = pseudorandom_mmr_membership_proof::<H>(rng.gen());
    let target_chunks: ChunkDictionary<H> = pseudorandom_chunk_dictionary(rng.gen());
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

    #[test]
    fn test_pseudorandom_mmra_with_mp() {
        type H = Tip5;
        let mut rng = thread_rng();
        let leaf: Digest = rng.gen();
        let (mmra, mp) = pseudorandom_mmra_with_mp::<H>(rng.gen(), leaf);
        assert!(mp.verify(&mmra.get_peaks(), &leaf, mmra.count_leaves()).0);
    }
}
