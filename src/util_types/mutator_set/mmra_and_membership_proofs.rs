use itertools::Itertools;
use proptest::{
    arbitrary::Arbitrary,
    collection::vec,
    strategy::{BoxedStrategy, Just, Strategy},
};
use proptest_arbitrary_interop::arb;
use tasm_lib::twenty_first::util_types::mmr::shared_basic::leaf_index_to_mt_index_and_peak_index;
use tasm_lib::{
    twenty_first::util_types::mmr::{
        mmr_accumulator::MmrAccumulator, mmr_membership_proof::MmrMembershipProof,
    },
    Digest,
};

use crate::models::blockchain::shared::Hash;

use super::root_and_paths::RootAndPaths;

#[derive(Debug, Clone)]
pub struct MmraAndMembershipProofs {
    pub mmra: MmrAccumulator<Hash>,
    pub membership_proofs: Vec<MmrMembershipProof<Hash>>,
}

impl Arbitrary for MmraAndMembershipProofs {
    type Parameters = Vec<Digest>;

    fn arbitrary_with(leafs_proper: Self::Parameters) -> Self::Strategy {
        let total_leaf_count_strategy = (leafs_proper.len() as u64)..u64::MAX;
        let index_strategy =
            (arb::<u64>(), total_leaf_count_strategy.clone()).prop_map(|(i, m)| i % m);
        let indices_strategy = vec(index_strategy, leafs_proper.len());
        let leafs_strategy = Just(leafs_proper);
        let digest_strategy = vec(arb::<Digest>(), 3 * 64);
        (
            total_leaf_count_strategy,
            leafs_strategy,
            indices_strategy,
            digest_strategy,
        )
            .prop_flat_map(|(total_leaf_count, leafs, mut indices, mut digests)| {
                let num_peaks = total_leaf_count.count_ones();

                // sample mmr leaf indices and calculate matching derived indices
                let leaf_indices = leafs
                    .iter()
                    .enumerate()
                    .map(|(original_index, _leaf)| (original_index, indices.pop().unwrap()))
                    .map(|(original_index, mmr_index)| {
                        let (mt_index, peak_index) =
                            leaf_index_to_mt_index_and_peak_index(mmr_index, total_leaf_count);
                        (original_index, mmr_index, mt_index, peak_index)
                    })
                    .collect_vec();
                let leafs_and_indices = leafs.iter().copied().zip(leaf_indices).collect_vec();

                // iterate over all trees
                let mut peaks_strategy: Vec<BoxedStrategy<Digest>> = vec![];
                let dummy_mp = MmrMembershipProof::new(0u64, vec![]);
                let mut mps_strategy =
                    Just((0..leafs.len()).map(|_| dummy_mp.clone()).collect_vec()).boxed();
                for tree in 0..num_peaks {
                    // select all leafs and merkle tree indices for this tree
                    let leafs_and_mt_indices = leafs_and_indices
                        .clone()
                        .iter()
                        .copied()
                        .filter(
                            |(_leaf, (_original_index, _mmr_index, _mt_index, peak_index))| {
                                *peak_index == tree
                            },
                        )
                        .map(
                            |(leaf, (original_index, _mmr_index, mt_index, _peak_index))| {
                                (leaf, mt_index, original_index)
                            },
                        )
                        .collect_vec();
                    if leafs_and_mt_indices.is_empty() {
                        peaks_strategy.push(Just(digests.pop().unwrap()).boxed());
                        continue;
                    }

                    // generate root and authentication paths
                    let tree_height = (*leafs_and_mt_indices.first().map(|(_l, i, _o)| i).unwrap()
                        as u128)
                        .ilog2() as usize;

                    let root_and_paths_strategy = RootAndPaths::arbitrary_with((
                        tree_height,
                        leafs_and_mt_indices
                            .iter()
                            .map(|&(l, i, _o)| (i, l))
                            .collect_vec(),
                    ));
                    let root_strategy = root_and_paths_strategy.clone().prop_map(|rp| rp.root);
                    let paths_strategy = root_and_paths_strategy.prop_map(|rp| rp.paths);

                    // update peaks list
                    peaks_strategy.push(root_strategy.boxed());

                    // generate membership proof objects
                    let other_leafs_and_indices = leafs_and_indices.clone();
                    let membership_proofs_strategy = paths_strategy
                        .prop_map(move |authentication_paths| {
                            other_leafs_and_indices
                                .iter()
                                .copied()
                                .filter(
                                    |(
                                        _leaf,
                                        (_original_index, _mmr_index, _mt_index, peak_index),
                                    )| { *peak_index == tree },
                                )
                                .zip(authentication_paths.into_iter())
                                .map(
                                    |(
                                        (
                                            _leaf,
                                            (_original_index, mmr_index, _mt_index, _peak_index),
                                        ),
                                        authentication_path,
                                    )| {
                                        MmrMembershipProof::<Hash>::new(
                                            mmr_index,
                                            authentication_path,
                                        )
                                    },
                                )
                                .collect_vec()
                        })
                        .boxed();

                    // collect membership proofs in vector, with indices matching those of the supplied leafs
                    mps_strategy = (mps_strategy.clone(), membership_proofs_strategy)
                        .prop_map(move |(mps, membership_proofs)| {
                            let mut new_mps = mps.clone();
                            for ((_leaf, _mt_index, original_index), membership_proof) in
                                leafs_and_mt_indices.iter().zip(membership_proofs.iter())
                            {
                                new_mps[*original_index] = membership_proof.clone();
                            }
                            new_mps
                        })
                        .boxed();
                }

                let mmra_strategy = peaks_strategy
                    .prop_map(move |peaks| MmrAccumulator::<Hash>::init(peaks, total_leaf_count));

                (mps_strategy, mmra_strategy).prop_map(|(membership_proofs, mmra)| {
                    MmraAndMembershipProofs {
                        membership_proofs,
                        mmra,
                    }
                })
            })
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}
