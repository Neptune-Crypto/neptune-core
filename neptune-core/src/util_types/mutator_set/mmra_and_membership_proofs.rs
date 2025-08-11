use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;

#[derive(Debug, Clone)]
pub struct MmraAndMembershipProofs {
    pub mmra: MmrAccumulator,
    pub membership_proofs: Vec<MmrMembershipProof>,
    pub leaf_indices: Vec<u64>,
}

#[cfg(any(test, feature = "arbitrary-impls"))]
pub mod neptune_arbitrary {
    use itertools::Itertools;
    use proptest::arbitrary::Arbitrary;
    use proptest::strategy::BoxedStrategy;
    use proptest::strategy::Just;
    use proptest::strategy::Strategy;
    use tasm_lib::prelude::Digest;
    use tasm_lib::twenty_first::util_types::mmr::shared_basic::leaf_index_to_mt_index_and_peak_index;

    use super::super::root_and_paths::RootAndPaths;
    use super::*;

    impl Arbitrary for MmraAndMembershipProofs {
        type Parameters = (Vec<(u64, Digest)>, u64);

        fn arbitrary_with(parameters: Self::Parameters) -> Self::Strategy {
            let (indices_and_leafs, total_leaf_count) = parameters;
            let indices = indices_and_leafs.iter().map(|(i, _d)| *i).collect_vec();
            let leafs = indices_and_leafs.iter().map(|(_i, d)| *d).collect_vec();
            let num_paths = leafs.len() as u64;

            let num_peaks = total_leaf_count.count_ones();
            let mut tree_heights = vec![];
            for shift in (0..64).rev() {
                if total_leaf_count & (1u64 << shift) != 0 {
                    tree_heights.push(shift);
                }
            }

            // sample mmr leaf indices and calculate matching derived indices
            let index_sets = leafs
                .iter()
                .enumerate()
                .map(|(enumeration_index, _leaf)| (enumeration_index, indices[enumeration_index]))
                .map(|(enumeration_index, mmr_leaf_index)| {
                    let (mt_node_index, peak_index) =
                        leaf_index_to_mt_index_and_peak_index(mmr_leaf_index, total_leaf_count);
                    (enumeration_index, mt_node_index, mmr_leaf_index, peak_index)
                })
                .collect_vec();
            let leafs_and_indices = leafs
                .iter()
                .copied()
                .zip(index_sets.iter().copied())
                .collect_vec();

            // segregate by tree
            let mut indices_and_leafs_by_tree = vec![];
            for tree in 0..num_peaks {
                let local_indices_and_leafs = leafs_and_indices
                    .iter()
                    .filter(
                        |(
                            _leaf,
                            (_enumeration_index, _mt_node_index, _mmr_leaf_index, peak_index),
                        )| { *peak_index == tree },
                    )
                    .copied()
                    .map(
                        |(
                            leaf,
                            (enumeration_index, mt_node_index, mmr_leaf_index, _peak_index),
                        )| {
                            (enumeration_index, mt_node_index, mmr_leaf_index, leaf)
                        },
                    )
                    .collect_vec();

                indices_and_leafs_by_tree.push(local_indices_and_leafs);
            }

            // for each tree generate root and paths
            let mut root_and_paths_strategies = vec![];
            for (tree, local_indices_and_leafs) in indices_and_leafs_by_tree.iter().enumerate() {
                let tree_height = tree_heights[tree];
                let root_and_paths_strategy = RootAndPaths::arbitrary_with((
                    tree_height,
                    local_indices_and_leafs
                        .iter()
                        .copied()
                        .map(|(_ei, mtni, _mmri, leaf)| (mtni ^ (1 << tree_height), leaf))
                        .collect_vec(),
                ));
                root_and_paths_strategies.push(root_and_paths_strategy);
            }

            // unwrap vector of roots and pathses
            (root_and_paths_strategies, Just(indices_and_leafs_by_tree))
                .prop_map(move |(roots_and_pathses, indices_and_leafs_by_tree_)| {
                    // extract peaks
                    let peaks = roots_and_pathses
                        .iter()
                        .map(|root_and_paths| root_and_paths.root)
                        .collect_vec();

                    // prepare to extract membership proofs
                    let mut membership_proofs = vec![
                        MmrMembershipProof {
                            authentication_path: vec![],
                        };
                        num_paths as usize
                    ];
                    let mut leaf_indices = vec![0; num_paths as usize];

                    // loop over all leaf indices and look up membership proof
                    for (root_and_paths, indices_and_leafs_) in roots_and_pathses
                        .into_iter()
                        .zip(indices_and_leafs_by_tree_.iter())
                    {
                        let paths = root_and_paths.paths;
                        for (path, &(enumeration_index, _merkle_tree_index, mmr_index, _leaf)) in
                            paths.into_iter().zip(indices_and_leafs_.iter())
                        {
                            membership_proofs[enumeration_index].authentication_path = path;
                            leaf_indices[enumeration_index] = mmr_index;
                        }
                    }

                    // sanity check
                    for ((mmr_mp, leaf), leaf_index) in membership_proofs
                        .iter()
                        .zip(leafs.iter())
                        .zip(leaf_indices.iter())
                    {
                        let (_mti, _pi) =
                            leaf_index_to_mt_index_and_peak_index(*leaf_index, total_leaf_count);
                        assert!(mmr_mp.verify(*leaf_index, *leaf, &peaks, total_leaf_count));
                    }

                    MmraAndMembershipProofs {
                        mmra: MmrAccumulator::init(peaks, total_leaf_count),
                        membership_proofs,
                        leaf_indices,
                    }
                })
                .boxed()
        }

        type Strategy = BoxedStrategy<Self>;
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use itertools::Itertools;
    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;
    use test_strategy::proptest;

    use super::*;
    use crate::twenty_first::prelude::Digest;

    fn indices_and_leafs_strategy(max: u64, num: usize) -> BoxedStrategy<Vec<(u64, Digest)>> {
        vec((0u64..max, arb::<Digest>()), num)
            .prop_filter("indices must all be unique", |indices_and_leafs| {
                indices_and_leafs.iter().map(|(i, _l)| *i).all_unique()
            })
            .boxed()
    }

    #[proptest(cases = 20)]
    fn integrity(
        #[strategy(1usize..10)] _num_paths: usize,
        #[strategy(0..u64::MAX)] _total_leaf_count: u64,
        #[strategy(indices_and_leafs_strategy(#_total_leaf_count, #_num_paths))]
        indices_and_leafs: Vec<(u64, Digest)>,
        #[strategy(
            MmraAndMembershipProofs::arbitrary_with((#indices_and_leafs, #_total_leaf_count))
        )]
        mmra_and_membership_proofs: MmraAndMembershipProofs,
    ) {
        for ((index, leaf), mp) in indices_and_leafs
            .into_iter()
            .zip(mmra_and_membership_proofs.membership_proofs)
        {
            prop_assert!(mp.verify(
                index,
                leaf,
                &mmra_and_membership_proofs.mmra.peaks(),
                mmra_and_membership_proofs.mmra.num_leafs(),
            ));
        }
    }
}
