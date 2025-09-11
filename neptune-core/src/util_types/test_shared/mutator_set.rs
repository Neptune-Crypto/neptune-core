use std::collections::HashMap;

use itertools::Itertools;
use rand::rngs::StdRng;
use rand::Rng;
use rand::RngCore;
use rand::SeedableRng;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::tip5::digest::Digest;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;
use tasm_lib::twenty_first::util_types::mmr::shared_basic::leaf_index_to_mt_index_and_peak_index;

use crate::application::database::storage::storage_vec::traits::*;
use crate::application::database::NeptuneLevelDb;
use crate::util_types::mutator_set::active_window::ActiveWindow;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::archival_mutator_set::ArchivalMutatorSet;
use crate::util_types::mutator_set::commit;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::removal_record::chunk::Chunk;
use crate::util_types::mutator_set::removal_record::RemovalRecord;
use crate::util_types::mutator_set::rusty_archival_mutator_set::RustyArchivalMutatorSet;
use crate::util_types::mutator_set::shared::CHUNK_SIZE;
use crate::util_types::mutator_set::shared::WINDOW_SIZE;

pub async fn get_all_indices_with_duplicates<
    MmrStorage: StorageVec<Digest> + Send + Sync,
    ChunkStorage: StorageVec<Chunk> + Send + Sync,
>(
    archival_mutator_set: &mut ArchivalMutatorSet<MmrStorage, ChunkStorage>,
) -> Vec<u128> {
    let mut ret: Vec<u128> = vec![];

    for index in &archival_mutator_set.swbf_active.sbf {
        ret.push(u128::from(*index));
    }

    let chunk_count = archival_mutator_set.chunks.len().await;
    for chunk_index in 0..chunk_count {
        let chunk = archival_mutator_set.chunks.get(chunk_index).await;
        for index in &chunk.relative_indices {
            ret.push(u128::from(*index) + u128::from(CHUNK_SIZE) * u128::from(chunk_index));
        }
    }

    ret
}

pub(crate) fn mock_item_and_randomnesses() -> (Digest, Digest, Digest) {
    let mut rng = rand::rng();
    let item: Digest = rng.random();
    let sender_randomness: Digest = rng.random();
    let receiver_preimage: Digest = rng.random();
    (item, sender_randomness, receiver_preimage)
}

pub(crate) fn mock_item_mp_rr_for_init_msa() -> (Digest, MsMembershipProof, RemovalRecord) {
    let accumulator: MutatorSetAccumulator = MutatorSetAccumulator::default();
    let (item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();
    let mp: MsMembershipProof = accumulator.prove(item, sender_randomness, receiver_preimage);
    let removal_record: RemovalRecord = accumulator.drop(item, &mp);
    (item, mp, removal_record)
}

pub async fn empty_rusty_mutator_set() -> RustyArchivalMutatorSet {
    let db = NeptuneLevelDb::open_new_test_database(true, None, None, None)
        .await
        .unwrap();
    let rusty_mutator_set: RustyArchivalMutatorSet = RustyArchivalMutatorSet::connect(db).await;
    rusty_mutator_set
}

pub fn insert_mock_item(mutator_set: &mut MutatorSetAccumulator) -> (MsMembershipProof, Digest) {
    let (new_item, sender_randomness, receiver_preimage) = mock_item_and_randomnesses();

    let addition_record = commit(new_item, sender_randomness, receiver_preimage.hash());
    let membership_proof = mutator_set.prove(new_item, sender_randomness, receiver_preimage);
    mutator_set.add_helper(&addition_record);

    (membership_proof, new_item)
}

pub fn remove_mock_item(
    mutator_set: &mut MutatorSetAccumulator,
    item: Digest,
    mp: &MsMembershipProof,
) {
    let removal_record: RemovalRecord = mutator_set.drop(item, mp);
    mutator_set.remove_helper(&removal_record);
}

/// Generate a random MSA. For serialization testing. Might not be a consistent or valid object.
pub fn random_mutator_set_accumulator() -> MutatorSetAccumulator {
    let aocl = random_mmra();
    let swbf_inactive = random_mmra();
    let swbf_active = random_swbf_active();
    MutatorSetAccumulator {
        aocl,
        swbf_inactive,
        swbf_active,
    }
}

/// Generate a random MMRA. For testing. Might not be a consistent or valid object.
pub fn random_mmra() -> MmrAccumulator {
    pseudorandom_mmra(rand::rng().random())
}

pub fn pseudorandom_addition_record(seed: [u8; 32]) -> AdditionRecord {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let ar: Digest = rng.random();
    AdditionRecord {
        canonical_commitment: ar,
    }
}

pub fn pseudorandom_mmra(seed: [u8; 32]) -> MmrAccumulator {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let leaf_count = u64::from(rng.next_u32());
    let num_peaks = rng.next_u32() % 10;
    let peaks: Vec<Digest> = (0..num_peaks).map(|_| rng.random()).collect_vec();
    MmrAccumulator::init(peaks, leaf_count)
}

pub fn pseudorandom_mmra_with_mp_and_index(
    seed: [u8; 32],
    leaf: Digest,
) -> (MmrAccumulator, MmrMembershipProof, u64) {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let leaf_count = rng.next_u64();
    let num_peaks = leaf_count.count_ones();
    let leaf_index = rng.next_u64() % leaf_count;
    let (inner_index, peak_index) = leaf_index_to_mt_index_and_peak_index(leaf_index, leaf_count);
    let tree_height = (u128::from(inner_index) + 1u128)
        .next_power_of_two()
        .ilog2()
        - 1;

    let (root, authentication_paths) = pseudorandom_merkle_root_with_authentication_paths(
        rng.random(),
        tree_height as usize,
        &[(leaf, inner_index)],
    );
    let authentication_path = authentication_paths[0].clone();

    assert_eq!(authentication_path.len(), tree_height as usize);
    assert!(
        merkle_verify_tester_helper(root, inner_index, &authentication_path, leaf),
        "root: ({root})\nindex: {inner_index}\nauth path len: {}\nauth path: ({})",
        authentication_path.len(),
        authentication_path.iter().join("), (")
    );

    let peaks: Vec<Digest> = (0..num_peaks)
        .map(|i| if i == peak_index { root } else { rng.random() })
        .collect_vec();
    let membership_proof = MmrMembershipProof {
        authentication_path,
    };
    let mmr_accumulator = MmrAccumulator::init(peaks, leaf_count);
    (mmr_accumulator, membership_proof, leaf_index)
}

pub fn pseudorandom_mmra_with_mps_and_indices(
    seed: [u8; 32],
    leafs: &[Digest],
) -> (MmrAccumulator, Vec<MmrMembershipProof>, Vec<u64>) {
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    // sample size of MMR
    let mut leaf_count = rng.next_u64();
    while leaf_count < leafs.len() as u64 {
        leaf_count = rng.next_u64();
    }
    let num_peaks = leaf_count.count_ones();

    // sample mmr leaf indices and calculate matching derived indices
    let leaf_index_tuples = leafs
        .iter()
        .enumerate()
        .map(|(original_index, _leaf)| (original_index, rng.next_u64() % leaf_count))
        .map(|(original_index, mmr_index)| {
            let (mt_index, peak_index) =
                leaf_index_to_mt_index_and_peak_index(mmr_index, leaf_count);
            (original_index, mmr_index, mt_index, peak_index)
        })
        .collect_vec();
    let mmr_leaf_indices = leaf_index_tuples
        .iter()
        .map(|(_oi, mmri, _mti, _pi)| *mmri)
        .collect_vec();
    let leafs_and_index_tuples = leafs.iter().copied().zip(leaf_index_tuples).collect_vec();

    // iterate over all trees
    let mut peaks = vec![];
    let dummy_mp = MmrMembershipProof::new(vec![]);
    let mut mps = (0..leafs.len()).map(|_| dummy_mp.clone()).collect_vec();
    for tree in 0..num_peaks {
        // select all leafs and merkle tree indices for this tree
        let leafs_and_mt_indices = leafs_and_index_tuples
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
            peaks.push(rng.random());
            continue;
        }

        // generate root and authentication paths
        let tree_height = u128::from(*leafs_and_mt_indices.first().map(|(_l, i, _o)| i).unwrap())
            .ilog2() as usize;
        let (root, authentication_paths) = pseudorandom_merkle_root_with_authentication_paths(
            rng.random(),
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
            assert!(merkle_verify_tester_helper(
                root, *mt_index, auth_path, *leaf
            ));
        }

        // update peaks list
        peaks.push(root);

        // generate membership proof objects
        let indices_and_membership_proofs = leafs_and_index_tuples
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
                )| { (mmr_index, MmrMembershipProof::new(authentication_path)) },
            )
            .collect_vec();

        // sanity check: test if membership proofs agree with peaks list (up until now)
        let dummy_remainder: Vec<Digest> = (peaks.len()..num_peaks as usize)
            .map(|_| rng.random())
            .collect_vec();
        let dummy_peaks = [peaks.clone(), dummy_remainder].concat();
        for (&(leaf, _mt_index, _original_index), (idx, mp)) in leafs_and_mt_indices
            .iter()
            .zip(indices_and_membership_proofs.iter())
        {
            assert!(mp.verify(*idx, leaf, &dummy_peaks, leaf_count));
        }

        // collect membership proofs in vector, with indices matching those of the supplied leafs
        for ((_leaf, _mt_index, original_index), (_idx, mp)) in leafs_and_mt_indices
            .iter()
            .zip(indices_and_membership_proofs.iter())
        {
            mps[*original_index] = mp.clone();
        }
    }

    let mmra = MmrAccumulator::init(peaks, leaf_count);

    // sanity check
    for ((&leaf, mp), li) in leafs.iter().zip(mps.iter()).zip(mmr_leaf_indices.iter()) {
        assert!(mp.verify(*li, leaf, &mmra.peaks(), mmra.num_leafs()));
    }

    (mmra, mps, mmr_leaf_indices)
}

pub fn pseudorandom_merkle_root_with_authentication_paths(
    seed: [u8; 32],
    tree_height: usize,
    leafs_and_indices: &[(Digest, u64)],
) -> (Digest, Vec<Vec<Digest>>) {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let mut nodes: HashMap<u64, Digest> = HashMap::new();

    // populate nodes dictionary with leafs
    for (leaf, index) in leafs_and_indices {
        nodes.insert(*index, *leaf);
    }

    // walk up tree layer by layer
    // when we need nodes not already present, sample at random
    let mut depth = tree_height + 1;
    while depth > 0 {
        let mut working_indices = nodes
            .keys()
            .copied()
            .filter(|i| {
                u128::from(*i) < (1u128 << (depth)) && u128::from(*i) >= (1u128 << (depth - 1))
            })
            .collect_vec();
        working_indices.sort();
        working_indices.dedup();
        for wi in working_indices {
            let wi_odd = wi | 1;
            nodes
                .entry(wi_odd)
                .or_insert_with(|| rng.random::<Digest>());
            let wi_even = wi_odd ^ 1;
            nodes
                .entry(wi_even)
                .or_insert_with(|| rng.random::<Digest>());
            let hash = Tip5::hash_pair(nodes[&wi_even], nodes[&wi_odd]);
            nodes.insert(wi >> 1, hash);
        }
        depth -= 1;
    }

    // read out root
    let root = *nodes.get(&1).unwrap_or(&rng.random());

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

pub fn random_swbf_active() -> ActiveWindow {
    let mut rng = rand::rng();
    let num_indices = 10 + (rng.next_u32() % 100) as usize;

    let mut aw = ActiveWindow::new();
    for _ in 0..num_indices {
        aw.insert(rng.next_u32() % WINDOW_SIZE);
    }

    aw
}

fn merkle_verify_tester_helper(root: Digest, index: u64, path: &[Digest], leaf: Digest) -> bool {
    let mut acc = leaf;
    for (shift, &p) in path.iter().enumerate() {
        if (index >> shift) & 1 == 1 {
            acc = Tip5::hash_pair(p, acc);
        } else {
            acc = Tip5::hash_pair(acc, p);
        }
    }
    acc == root
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use macro_rules_attr::apply;

    use super::*;
    use crate::tests::shared_tokio_runtime;

    #[apply(shared_tokio_runtime)]
    async fn can_call() {
        let mut rms = empty_rusty_mutator_set().await;
        let ams = rms.ams_mut();
        let _ = get_all_indices_with_duplicates(ams).await;
        let _ = mock_item_and_randomnesses();
        let _ = insert_mock_item(&mut ams.accumulator().await);
    }

    #[test]
    fn test_pseudorandom_mmra_with_single_mp() {
        let mut rng = rand::rng();
        let leaf: Digest = rng.random();
        let (mmra, mp, index) = pseudorandom_mmra_with_mp_and_index(rng.random(), leaf);
        assert!(mp.verify(index, leaf, &mmra.peaks(), mmra.num_leafs()));
    }

    #[test]
    fn test_pseudorandom_root_with_authentication_paths() {
        let seed: [u8; 32] = rand::rng().random();
        let mut outer_rng: StdRng = SeedableRng::from_seed(seed);
        for num_leafs in 0..20 {
            let inner_seed: [u8; 32] = outer_rng.random();
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
            let leafs: Vec<Digest> = (0..num_leafs).map(|_| inner_rng.random()).collect_vec();
            let leafs_and_indices = leafs.into_iter().zip(indices.into_iter()).collect_vec();
            let (root, paths) = pseudorandom_merkle_root_with_authentication_paths(
                inner_rng.random(),
                tree_height,
                &leafs_and_indices,
            );
            for ((leaf, index), path) in leafs_and_indices.into_iter().zip(paths.into_iter()) {
                assert!(
                    merkle_verify_tester_helper(root, index, &path, leaf),
                    "failure observed for num_leafs: {num_leafs} and seed: {inner_seed:?}"
                );
            }
        }
    }

    #[test]
    fn test_pseudorandom_mmra_with_mps() {
        let seed: [u8; 32] = rand::rng().random();
        let mut outer_rng: StdRng = SeedableRng::from_seed(seed);
        for num_leafs in 0..20 {
            let inner_seed: [u8; 32] = outer_rng.random();
            let mut inner_rng: StdRng = SeedableRng::from_seed(inner_seed);

            let leafs: Vec<Digest> = (0..num_leafs).map(|_| inner_rng.random()).collect_vec();
            let (mmra, mps, lis) =
                pseudorandom_mmra_with_mps_and_indices(inner_rng.random(), &leafs);
            for ((leaf, mp), li) in leafs.into_iter().zip(mps).zip(lis) {
                assert!(
                    mp.verify(li, leaf, &mmra.peaks(), mmra.num_leafs()),
                    "failure observed for num_leafs: {num_leafs} and seed: {inner_seed:?}"
                );
            }
        }
    }
}
