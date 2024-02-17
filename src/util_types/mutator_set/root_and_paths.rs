use std::collections::hash_map::Entry;
use std::collections::HashMap;

use itertools::Itertools;
use proptest::collection::vec;
use proptest::{
    arbitrary::Arbitrary,
    strategy::{BoxedStrategy, Just, Strategy},
};
use proptest_arbitrary_interop::arb;
use tasm_lib::{twenty_first::util_types::algebraic_hasher::AlgebraicHasher, Digest};

use crate::models::blockchain::shared::Hash;

#[derive(Debug, Clone, Default)]
pub struct RootAndPaths {
    pub root: Digest,
    pub paths: Vec<Vec<Digest>>,
}

impl Arbitrary for RootAndPaths {
    type Parameters = (usize, Vec<(u64, Digest)>);
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(parameters: Self::Parameters) -> Self::Strategy {
        let (tree_height_proper, indices_and_leafs_proper) = parameters;
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
                let mut nodes = HashMap::new();

                // populate nodes dictionary with leafs
                for &(index, leaf) in &indices_and_leafs {
                    let node_index = (index as u128) + (1u128 << tree_height);
                    nodes.insert(node_index, leaf);
                }

                // walk up tree layer by layer
                // when we need nodes not already present, sample at random
                // note: depth 1 is the layer containing only the root
                let by_layer = |index, layer| {
                    let sub_tree_height = tree_height - layer;
                    let layer_start = 1u128 << sub_tree_height;
                    let layer_stop = 1u128 << (sub_tree_height + 1);
                    index >= layer_start && index < layer_stop
                };
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
                        let hash = Hash::hash_pair(nodes[&wi_even], nodes[&wi_odd]);
                        nodes.insert(wi >> 1, hash);
                    }
                }

                // read out root, even if no paths were traversed
                let root = *nodes.get(&1).unwrap_or(&digests.pop().unwrap());

                // read out paths
                let paths = indices_and_leafs
                    .iter()
                    .map(|(leaf_idx, _)| (*leaf_idx as u128) + (1u128 << tree_height))
                    .map(|node_idx| {
                        (0..tree_height)
                            .map(|layer_idx| nodes[&((node_idx >> layer_idx) ^ 1)])
                            .collect_vec()
                    })
                    .collect_vec();

                RootAndPaths { root, paths }
            })
            .boxed()
    }
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;
    use tasm_lib::twenty_first::util_types::merkle_tree::MerkleTreeInclusionProof;
    use test_strategy::proptest;

    use super::*;

    #[proptest(cases = 20)]
    fn integrity(
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
            let inclusion_proof = MerkleTreeInclusionProof::<Hash> {
                tree_height,
                indexed_leaves: vec![indexed_leaf],
                authentication_structure: path,
                ..Default::default()
            };
            prop_assert!(inclusion_proof.verify(root_and_paths.root));
        }
    }
}
