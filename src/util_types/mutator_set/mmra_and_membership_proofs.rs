use std::marker::PhantomData;

use itertools::Itertools;
use proptest::{
    arbitrary::Arbitrary,
    strategy::{BoxedStrategy, Just, Strategy},
};
use tasm_lib::twenty_first::util_types::{
    merkle_tree::MerkleTreeInclusionProof, mmr::shared_basic::leaf_index_to_mt_index_and_peak_index,
};
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
    type Parameters = (Vec<(u64, Digest)>, u64);

    fn arbitrary_with(parameters: Self::Parameters) -> Self::Strategy {
        let (indices_and_leafs, total_leaf_count) = parameters;
        let indices = indices_and_leafs.iter().map(|(i, d)| *i).collect_vec();
        let max_index = indices.iter().max().copied().unwrap_or(0u64);
        let leafs = indices_and_leafs.iter().map(|(i, d)| *d).collect_vec();
        let num_paths = leafs.len() as u64;

        let num_peaks = total_leaf_count.count_ones();
        let mut tree_heights = vec![];
        for shift in (0..63).rev() {
            if total_leaf_count & (1u64 << shift) != 0 {
                tree_heights.push(shift);
            }
        }

        // sample mmr leaf indices and calculate matching derived indices
        let index_sets = leafs
            .iter()
            .enumerate()
            .map(|(enumeration_index, _leaf)| (enumeration_index, indices.pop().unwrap()))
            .map(|(enumeration_index, mmr_leaf_index)| {
                let (mt_node_index, peak_index) =
                    leaf_index_to_mt_index_and_peak_index(mmr_leaf_index, total_leaf_count);
                (enumeration_index, mt_node_index, mmr_leaf_index, peak_index)
            })
            .collect_vec();
        let leafs_and_indices = leafs
            .iter()
            .copied()
            .zip(index_sets.iter().cloned())
            .collect_vec();

        // segregate by tree
        let mut indices_and_leafs_by_tree = vec![];
        for tree in 0..num_peaks {
            let local_indices_and_leafs = leafs_and_indices
                .iter()
                .filter(
                    |(_leaf, (_enumeration_index, _mt_node_index, _mmr_leaf_index, peak_index))| {
                        *peak_index == tree
                    },
                )
                .cloned()
                .map(
                    |(leaf, (enumeration_index, mt_node_index, mmr_leaf_index, _peak_index))| {
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
                // sanity check for roots and pathses
                for (root_and_paths, indices_and_leafs) in roots_and_pathses
                    .iter()
                    .zip(indices_and_leafs_by_tree_.iter())
                {
                    let root = root_and_paths.root;
                    for (path, (_enumeration_index, merkle_tree_node_index, _mmr_index, leaf)) in
                        root_and_paths.paths.iter().zip(indices_and_leafs.iter())
                    {
                        let mip = MerkleTreeInclusionProof {
                            tree_height: path.len(),
                            indexed_leaves: vec![(
                                *merkle_tree_node_index as usize ^ (1 << path.len()),
                                *leaf,
                            )],
                            authentication_structure: path.clone(),
                            _hasher: PhantomData::<Hash>,
                        };
                        assert!(mip.verify(root));
                    }
                }

                // extract peaks
                let peaks = roots_and_pathses
                    .iter()
                    .map(|root_and_paths| root_and_paths.root)
                    .collect_vec();

                // prepare to extract membership proofs
                let mut membership_proofs = vec![
                    MmrMembershipProof {
                        leaf_index: 0,
                        authentication_path: vec![],
                        _hasher: std::marker::PhantomData::<Hash>
                    };
                    num_paths as usize
                ];

                // loop over all leaf indices and look up membership proof
                for (root_and_paths, indices_and_leafs) in roots_and_pathses
                    .into_iter()
                    .zip(indices_and_leafs_by_tree_.iter())
                {
                    let paths = root_and_paths.paths;
                    for (path, &(enumeration_index, _merkle_tree_index, mmr_index, _leaf)) in
                        paths.into_iter().zip(indices_and_leafs.iter())
                    {
                        membership_proofs[enumeration_index].authentication_path = path;
                        membership_proofs[enumeration_index].leaf_index = mmr_index;
                    }
                }

                // sanity check
                for (mmr_mp, leaf) in membership_proofs.iter().zip(leafs.iter()) {
                    let (_mti, _pi) =
                        leaf_index_to_mt_index_and_peak_index(mmr_mp.leaf_index, total_leaf_count);
                    assert!(mmr_mp.verify(&peaks, *leaf, total_leaf_count).0);
                }

                MmraAndMembershipProofs {
                    mmra: MmrAccumulator::init(peaks, total_leaf_count),
                    membership_proofs,
                }
            })
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::twenty_first::shared_math::tip5::Digest;
    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;
    use test_strategy::proptest;

    fn indices_and_leafs_strategy(num: usize) -> BoxedStrategy<Vec<(u64, Digest)>> {
        vec(arb::<(u64, Digest)>(), num)
            .prop_filter("indices must all be unique", |indices_and_leafs| {
                indices_and_leafs.iter().map(|(i, l)| *i).all_unique()
            })
            .boxed()
    }

    #[proptest(cases = 20)]
    fn integrity(
        #[strategy(1usize..10)] _num_paths: usize,
        #[strategy(indices_and_leafs_strategy(#_num_paths))] indices_and_leafs: Vec<(u64, Digest)>,
        #[filter(#indices_and_leafs.iter().map(|(i,_l)|*i).max().unwrap() < #_total_leaf_count)]
        #[strategy(0..u64::MAX)]
        _total_leaf_count: u64,
        #[strategy(MmraAndMembershipProofs::arbitrary_with((#indices_and_leafs, #_total_leaf_count)))]
        mmra_and_membership_proofs: MmraAndMembershipProofs,
    ) {
        for ((index, leaf), mp) in indices_and_leafs
            .into_iter()
            .zip(mmra_and_membership_proofs.membership_proofs)
        {
            prop_assert!(
                mp.verify(
                    &mmra_and_membership_proofs.mmra.get_peaks(),
                    leaf,
                    mmra_and_membership_proofs.mmra.count_leaves(),
                )
                .0
            );
        }
    }
}
