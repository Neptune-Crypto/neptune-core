use tasm_lib::prelude::Digest;

#[derive(Debug, Clone, Default)]
pub struct RootAndPaths {
    pub root: Digest,
    pub paths: Vec<Vec<Digest>>,
}

#[cfg(any(test, feature = "arbitrary-impls"))]
pub mod neptune_arbitrary {
    use std::collections::hash_map::Entry;
    use std::collections::HashMap;

    use itertools::Itertools;
    use proptest::arbitrary::Arbitrary;
    use proptest::collection::vec;
    use proptest::strategy::BoxedStrategy;
    use proptest::strategy::Just;
    use proptest::strategy::Strategy;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::prelude::Tip5;

    use super::*;

    impl Arbitrary for RootAndPaths {
        type Parameters = (usize, Vec<(u64, Digest)>);
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(parameters: Self::Parameters) -> Self::Strategy {
            let (tree_height_proper, indices_and_leafs_proper) = parameters;
            assert!(
                indices_and_leafs_proper
                    .iter()
                    .map(|(idx, _)| idx)
                    .all_unique(),
                "indices are not all unique"
            );
            assert!(
                indices_and_leafs_proper
                    .iter()
                    .all(|(i, _l)| u128::from(*i) < 1u128 << tree_height_proper),
                "some or all indices are too large; don't fit in a tree of height {tree_height_proper}"
            );
            let upper_bound_num_digests = tree_height_proper * indices_and_leafs_proper.len() + 1;

            let tree_height_strategy = Just(tree_height_proper);
            let indices_and_leafs_strategy = Just(indices_and_leafs_proper);
            let vec_digest_strategy = vec(arb::<Digest>(), upper_bound_num_digests);
            (
                tree_height_strategy,
                indices_and_leafs_strategy,
                vec_digest_strategy,
            )
                .prop_map(|(tree_height, indices_and_leafs, mut digests)| {
                    assert!(indices_and_leafs.iter().all(|(i, _l)| u128::from(*i) < (1u128 << tree_height)), "indices too large for tree of height: {}", tree_height);
                    // populate nodes dictionary with leafs
                    let mut nodes = HashMap::new();
                    for &(index, leaf) in &indices_and_leafs {
                        let node_index = u128::from(index) + (1u128 << tree_height);
                        nodes.insert(node_index, leaf);
                    }

                    let by_layer = |index: u128, layer: usize| {
                        let sub_tree_height = tree_height - layer;
                        let layer_start = 1u128 << sub_tree_height;
                        let layer_stop = 1u128 << (sub_tree_height + 1);
                        index >= layer_start && index < layer_stop
                    };

                    // walk up tree layer by layer
                    // when we need nodes not already present, sample at random
                    for layer in 0..tree_height {
                        let mut working_indices = nodes
                            .keys()
                            .copied()
                            .filter(|&i| by_layer(i, layer))
                            .collect_vec();
                        working_indices.sort();
                        working_indices.dedup();
                        for wi in working_indices {
                            let wi_odd = wi | 1;
                            if let Entry::Vacant(entry) = nodes.entry(wi_odd) {
                                entry.insert(digests.pop().unwrap());
                            }
                            let wi_even = wi_odd ^ 1;
                            if let Entry::Vacant(entry) = nodes.entry(wi_even) {
                                entry.insert(digests.pop().unwrap());
                            }
                            let hash = Tip5::hash_pair(nodes[&wi_even], nodes[&wi_odd]);
                            nodes.insert(wi >> 1, hash);
                        }
                    }

                    // read out root, even if no paths were traversed
                    let root = *nodes.get(&1).unwrap_or(&digests.pop().unwrap());

                    // read out paths
                    let paths = indices_and_leafs
                        .iter()
                        .map(|(leaf_idx, _)| u128::from(*leaf_idx) + (1u128 << tree_height))
                        .map(|node_idx| {
                            (0..tree_height)
                                .map(|layer_idx| {
                                    nodes
                                        .get(&((node_idx >> layer_idx) ^ 1u128))
                                        .unwrap_or_else(|| {
                                            panic!(
                                                "node index \n{} \nnot present in node dictionary!\ndo have indices:\n{}",
                                                (node_idx >> layer_idx) ^ 1,
                                                nodes.keys().join("\n")
                                            )
                                        })
                                })
                                .copied()
                                .collect_vec()
                        })
                        .collect_vec();

                    RootAndPaths { root, paths }
                })
                .boxed()
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use itertools::Itertools;
    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::twenty_first::util_types::merkle_tree::MerkleTreeInclusionProof;
    use test_strategy::proptest;

    use super::*;

    #[proptest(cases = 20)]
    fn correct(
        // max tree height is 32 as per twenty-first (to be changed)
        #[strategy(1usize..32)] tree_height: usize,
        #[strategy(vec((0..(1u64 << #tree_height), arb()), 0..100))]
        #[filter(#indexed_leafs.iter().map(|(idx, _)| idx).all_unique())]
        indexed_leafs: Vec<(u64, Digest)>,
        #[strategy(RootAndPaths::arbitrary_with((#tree_height, #indexed_leafs)))]
        root_and_paths: RootAndPaths,
    ) {
        let indexed_leafs = indexed_leafs
            .into_iter()
            .map(|(idx, digest)| (idx as usize, digest));
        for (path, indexed_leaf) in root_and_paths.paths.into_iter().zip(indexed_leafs) {
            let inclusion_proof = MerkleTreeInclusionProof {
                tree_height: tree_height.try_into().unwrap(),
                indexed_leafs: vec![indexed_leaf],
                authentication_structure: path,
            };
            prop_assert!(inclusion_proof.verify(root_and_paths.root));
        }
    }

    #[proptest(cases = 20)]
    fn no_fail(
        // try max tree height 64 here
        #[strategy(1usize..64)] _tree_height: usize,
        #[strategy(vec((0..(1u64 << #_tree_height), arb()), 0..100))]
        #[filter(#_indexed_leafs.iter().map(|(idx, _)| idx).all_unique())]
        _indexed_leafs: Vec<(u64, Digest)>,
        #[strategy(RootAndPaths::arbitrary_with((#_tree_height, #_indexed_leafs)))]
        _root_and_paths: RootAndPaths,
    ) {
        prop_assert!(true);
    }

    #[proptest(cases = 20)]
    #[should_panic]
    fn indices_too_large(
        // try max tree height 64 here
        #[strategy(1usize..64)] _tree_height: usize,
        #[strategy(vec(((1u64 << #_tree_height)..u64::MAX, arb()), 0..100))]
        #[filter(#_indexed_leafs.iter().map(|(idx, _)| idx).all_unique())]
        _indexed_leafs: Vec<(u64, Digest)>,
        #[strategy(RootAndPaths::arbitrary_with((#_tree_height, #_indexed_leafs)))]
        _root_and_paths: RootAndPaths,
    ) {
        prop_assert!(true);
    }
}
