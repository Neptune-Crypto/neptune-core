use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use itertools::Itertools;
use rand::rngs::StdRng;
use rand::{thread_rng, Rng, RngCore, SeedableRng};
use rusty_leveldb::DB;

use twenty_first::shared_math::bfield_codec::BFieldCodec;
use twenty_first::shared_math::other::{log_2_ceil, log_2_floor};
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
use crate::util_types::mutator_set::chunk_dictionary::{
    pseudorandom_chunk_dictionary, ChunkDictionary,
};
use crate::util_types::mutator_set::ms_membership_proof::{
    pseudorandom_mmr_membership_proof, pseudorandom_mutator_set_membership_proof, MsMembershipProof,
};
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::mutator_set_kernel::MutatorSetKernel;
use crate::util_types::mutator_set::mutator_set_trait::commit;
use crate::util_types::mutator_set::removal_record::{pseudorandom_removal_record, RemovalRecord};
use crate::util_types::mutator_set::shared::{CHUNK_SIZE, WINDOW_SIZE};

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

    let (root, authentication_paths) = pseudorandom_merkle_root_with_authentication_paths::<H>(
        rng.gen(),
        tree_height as usize,
        &[(leaf, inner_index)],
    );
    let authentication_path = authentication_paths[0].clone();

    assert_eq!(authentication_path.len(), tree_height as usize);
    assert!(
        merkle_verify_tester_helper::<H>(root, inner_index, &authentication_path, leaf),
        "root: ({root})\nindex: {inner_index}\nauth path len: {}\nauth path: ({})",
        authentication_path.len(),
        authentication_path.iter().join("), (")
    );

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

pub fn pseudorandom_mmra_with_mps<H: AlgebraicHasher>(
    seed: [u8; 32],
    leafs: &[Digest],
) -> (MmrAccumulator<H>, Vec<MmrMembershipProof<H>>) {
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    // sample size of MMR
    let mut leaf_count = rng.next_u64();
    while leaf_count < leafs.len() as u64 {
        leaf_count = rng.next_u64();
    }
    let num_peaks = leaf_count.count_ones();

    // sample mmr leaf indices and calculate matching derived indices
    let leaf_indices = leafs
        .iter()
        .enumerate()
        .map(|(original_index, _leaf)| (original_index, rng.next_u64() % leaf_count))
        .map(|(original_index, mmr_index)| {
            let (mt_index, peak_index) =
                leaf_index_to_mt_index_and_peak_index(mmr_index, leaf_count);
            (original_index, mmr_index, mt_index, peak_index)
        })
        .collect_vec();
    let leafs_and_indices = leafs
        .iter()
        .copied()
        .zip(leaf_indices.into_iter())
        .collect_vec();

    // iterate over all trees
    let mut peaks = vec![];
    let dummy_mp = MmrMembershipProof::new(0u64, vec![]);
    let mut mps: Vec<MmrMembershipProof<H>> =
        (0..leafs.len()).map(|_| dummy_mp.clone()).collect_vec();
    for tree in 0..num_peaks {
        // select all leafs and merkle tree indices for this tree
        let leafs_and_mt_indices = leafs_and_indices
            .iter()
            .copied()
            .filter(
                |(_leaf, (_original_index, _mmr_index, _mt_index, peak_index))| *peak_index == tree,
            )
            .map(
                |(leaf, (original_index, _mmr_index, mt_index, _peak_index))| {
                    (leaf, mt_index, original_index)
                },
            )
            .collect_vec();
        if leafs_and_mt_indices.is_empty() {
            peaks.push(rng.gen());
            continue;
        }

        // generate root and authentication paths
        let tree_height =
            log_2_floor(*leafs_and_mt_indices.first().map(|(_l, i, _o)| i).unwrap() as u128)
                as usize;
        let (root, authentication_paths) = pseudorandom_merkle_root_with_authentication_paths::<H>(
            rng.gen(),
            tree_height,
            &leafs_and_mt_indices
                .iter()
                .map(|(l, i, _o)| (*l, *i))
                .collect_vec(),
        );

        // sanity check
        for ((leaf, mt_index, _original_index), auth_path) in
            leafs_and_mt_indices.iter().zip(authentication_paths.iter())
        {
            assert!(merkle_verify_tester_helper::<H>(
                root, *mt_index, auth_path, *leaf
            ));
        }

        // update peaks list
        peaks.push(root);

        // generate membership proof objects
        let membership_proofs = leafs_and_indices
            .iter()
            .copied()
            .filter(
                |(_leaf, (_original_index, _mmr_index, _mt_index, peak_index))| *peak_index == tree,
            )
            .zip(authentication_paths.into_iter())
            .map(
                |(
                    (_leaf, (_original_index, mmr_index, _mt_index, _peak_index)),
                    authentication_path,
                )| { MmrMembershipProof::<H>::new(mmr_index, authentication_path) },
            )
            .collect_vec();

        // sanity check: test if membership proofs agree with peaks list (up until now)
        let dummy_remainder: Vec<Digest> = (peaks.len()..num_peaks as usize)
            .map(|_| rng.gen())
            .collect_vec();
        let dummy_peaks = [peaks.clone(), dummy_remainder].concat();
        for ((leaf, _mt_index, _original_index), mp) in
            leafs_and_mt_indices.iter().zip(membership_proofs.iter())
        {
            assert!(mp.verify(&dummy_peaks, leaf, leaf_count).0);
        }

        // collect membership proofs in vector, with indices matching those of the supplied leafs
        for ((_leaf, _mt_index, original_index), mp) in
            leafs_and_mt_indices.iter().zip(membership_proofs.iter())
        {
            mps[*original_index] = mp.clone();
        }
    }

    let mmra = MmrAccumulator::<H>::init(peaks, leaf_count);

    // sanity check
    for (leaf, mp) in leafs.iter().zip(mps.iter()) {
        assert!(mp.verify(&mmra.get_peaks(), leaf, mmra.count_leaves()).0);
    }

    (mmra, mps)
}

pub fn pseudorandom_merkle_root_with_authentication_paths<H: AlgebraicHasher>(
    seed: [u8; 32],
    tree_height: usize,
    leafs_and_indices: &[(Digest, u64)],
) -> (Digest, Vec<Vec<Digest>>) {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let mut nodes: HashMap<u64, Digest> = HashMap::new();

    // populate nodes dictionary with leafs
    for (leaf, index) in leafs_and_indices.iter() {
        nodes.insert(*index, *leaf);
    }

    // walk up tree layer by layer
    // when we need nodes not already present, sample at random
    let mut depth = tree_height + 1;
    while depth > 0 {
        let mut working_indices = nodes
            .keys()
            .copied()
            .filter(|i| (*i as u128) < (1u128 << (depth)) && (*i as u128) >= (1u128 << (depth - 1)))
            .collect_vec();
        working_indices.sort();
        working_indices.dedup();
        for wi in working_indices {
            let wi_odd = wi | 1;
            if nodes.get(&wi_odd).is_none() {
                nodes.insert(wi_odd, rng.gen::<Digest>());
            }
            let wi_even = wi_odd ^ 1;
            if nodes.get(&wi_even).is_none() {
                nodes.insert(wi_even, rng.gen::<Digest>());
            }
            let hash = H::hash_pair(nodes.get(&wi_even).unwrap(), nodes.get(&wi_odd).unwrap());
            nodes.insert(wi >> 1, hash);
        }
        depth -= 1;
    }

    // read out root
    let root = *nodes.get(&1).unwrap_or(&rng.gen());

    // read out paths
    let paths = leafs_and_indices
        .iter()
        .map(|(_d, i)| {
            (0..tree_height)
                .map(|j| *nodes.get(&((*i >> j) ^ 1)).unwrap())
                .collect_vec()
        })
        .collect_vec();

    (root, paths)
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

/// Generate a random MsMembershipProof. For serialization testing. Might not be a consistent or valid object.
pub fn random_mutator_set_membership_proof<H: AlgebraicHasher>() -> MsMembershipProof<H> {
    pseudorandom_mutator_set_membership_proof(thread_rng().gen())
}

pub fn random_removal_record<H: AlgebraicHasher>() -> RemovalRecord<H> {
    let mut rng = thread_rng();
    pseudorandom_removal_record(rng.gen::<[u8; 32]>())
}

fn merkle_verify_tester_helper<H: AlgebraicHasher>(
    root: Digest,
    index: u64,
    path: &[Digest],
    leaf: Digest,
) -> bool {
    let mut acc = leaf;
    for (shift, p) in path.iter().enumerate() {
        if (index >> shift) & 1 == 1 {
            acc = H::hash_pair(p, &acc);
        } else {
            acc = H::hash_pair(&acc, p);
        }
    }
    acc == root
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
    fn test_pseudorandom_mmra_with_single_mp() {
        type H = Tip5;
        let mut rng = thread_rng();
        let leaf: Digest = rng.gen();
        let (mmra, mp) = pseudorandom_mmra_with_mp::<H>(rng.gen(), leaf);
        assert!(mp.verify(&mmra.get_peaks(), &leaf, mmra.count_leaves()).0);
    }

    #[test]
    fn test_pseudorandom_root_with_authentication_paths() {
        type H = Tip5;
        let seed: [u8; 32] = thread_rng().gen();
        let mut outer_rng: StdRng = SeedableRng::from_seed(seed);
        for num_leafs in 0..20 {
            let inner_seed: [u8; 32] = outer_rng.gen();
            let mut inner_rng: StdRng = SeedableRng::from_seed(inner_seed);
            let mut tree_height = 0;
            while num_leafs > (1u64 << tree_height) {
                tree_height = inner_rng.next_u32() as usize % 64;
            }
            let mut indices = vec![];
            while indices.len() != num_leafs as usize {
                let index = (inner_rng.next_u64() % (1u64 << tree_height)) + (1u64 << tree_height);
                if !indices.contains(&index) {
                    indices.push(index);
                }
            }
            let leafs: Vec<Digest> = (0..num_leafs).map(|_| inner_rng.gen()).collect_vec();
            let leafs_and_indices = leafs.into_iter().zip(indices.into_iter()).collect_vec();
            let (root, paths) = pseudorandom_merkle_root_with_authentication_paths::<H>(
                inner_rng.gen(),
                tree_height,
                &leafs_and_indices,
            );
            for ((leaf, index), path) in leafs_and_indices.into_iter().zip(paths.into_iter()) {
                assert!(
                    merkle_verify_tester_helper::<H>(root, index, &path, leaf),
                    "failure observed for num_leafs: {num_leafs} and seed: {inner_seed:?}"
                );
            }
        }
    }

    #[test]
    fn test_pseudorandom_mmra_with_mps() {
        type H = Tip5;
        let seed: [u8; 32] = thread_rng().gen();
        let mut outer_rng: StdRng = SeedableRng::from_seed(seed);
        for num_leafs in 0..20 {
            let inner_seed: [u8; 32] = outer_rng.gen();
            let mut inner_rng: StdRng = SeedableRng::from_seed(inner_seed);

            let leafs: Vec<Digest> = (0..num_leafs).map(|_| inner_rng.gen()).collect_vec();
            let (mmra, mps) = pseudorandom_mmra_with_mps::<H>(inner_rng.gen(), &leafs);
            for (leaf, mp) in leafs.iter().zip(mps.iter()) {
                assert!(
                    mp.verify(&mmra.get_peaks(), leaf, mmra.count_leaves()).0,
                    "failure observed for num_leafs: {num_leafs} and seed: {inner_seed:?}"
                );
            }
        }
    }
}
