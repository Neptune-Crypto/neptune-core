use std::collections::HashMap;

use super::{
    active_window::ActiveWindow,
    chunk::Chunk,
    chunk_dictionary::ChunkDictionary,
    get_swbf_indices,
    mmra_and_membership_proofs::MmraAndMembershipProofs,
    ms_membership_proof::MsMembershipProof,
    mutator_set_accumulator::MutatorSetAccumulator,
    removal_record::{AbsoluteIndexSet, RemovalRecord},
    shared::{BATCH_SIZE, CHUNK_SIZE},
};
use crate::{util_types::mutator_set::commit, Hash};
use itertools::Itertools;
use proptest::collection::vec;
use proptest::{
    arbitrary::Arbitrary,
    strategy::{BoxedStrategy, Strategy},
};
use proptest_arbitrary_interop::arb;
use tasm_lib::{
    twenty_first::util_types::{
        algebraic_hasher::AlgebraicHasher,
        mmr::{mmr_membership_proof::MmrMembershipProof, mmr_trait::Mmr},
    },
    Digest,
};

#[derive(Debug, Clone)]
pub struct MsaAndRecords {
    pub mutator_set_accumulator: MutatorSetAccumulator,
    pub removal_records: Vec<RemovalRecord>,
    pub membership_proofs: Vec<MsMembershipProof>,
}

impl MsaAndRecords {
    pub fn verify(&self, items: &[Digest]) -> bool {
        let all_removal_records_can_remove = self
            .removal_records
            .iter()
            .all(|rr| self.mutator_set_accumulator.can_remove(rr));
        assert!(
            all_removal_records_can_remove,
            "Some removal records cannot be removed!"
        );
        let all_membership_proofs_are_valid = self
            .membership_proofs
            .iter()
            .zip_eq(items.iter())
            .all(|(mp, item)| self.mutator_set_accumulator.verify(*item, mp));
        assert!(
            all_membership_proofs_are_valid,
            "some membership proofs are not valid!"
        );
        all_removal_records_can_remove && all_membership_proofs_are_valid
    }
}

impl Arbitrary for MsaAndRecords {
    /// Parameters:
    ///  - removables : Vec<(Digest, Digest, Digest)> where each triple contains:
    ///     - an item
    ///     - sender randomness
    ///     - receiver preimage
    ///  - aocl_size : u64 which counts the total number of items added to the mutator
    ///    set.
    type Parameters = (Vec<(Digest, Digest, Digest)>, u64);
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(parameters: Self::Parameters) -> Self::Strategy {
        let (removables, aocl_size) = parameters;

        // compute the canonical commitments that were added to the aocl at some prior,
        // as this is information needed to produce membership proofs for the items that
        // are going to be removed
        let removable_commitments = removables
            .iter()
            .map(|(item, sender_randomness, receiver_preimage)| {
                commit(*item, *sender_randomness, receiver_preimage.hash::<Hash>())
            })
            .collect_vec();

        let removable_commitments = removable_commitments.clone();

        // sample random aocl indices
        vec(0u64..aocl_size, removables.len())
            .prop_flat_map(move |removed_aocl_indices| {

            // prepare unwrap
            let removables = removables.clone();

            // bundle all indices and leafs for pseudorandom aocl
            let all_aocl_indices_and_leafs = removed_aocl_indices.into_iter().zip(removable_commitments.iter().map(|ar|ar.canonical_commitment)).collect_vec();

            // unwrap random aocl mmr with membership proofs
            MmraAndMembershipProofs::arbitrary_with((all_aocl_indices_and_leafs, aocl_size))
            .prop_flat_map(move |aocl_mmra_and_membership_proofs| {
                let aocl_mmra = aocl_mmra_and_membership_proofs.mmra;
                let aocl_membership_proofs = aocl_mmra_and_membership_proofs.membership_proofs;
                let aocl_leaf_indices = aocl_mmra_and_membership_proofs.leaf_indices;

                // assemble all indices of all removal records
                let all_index_sets = removables
                    .iter()
                    .zip(aocl_leaf_indices.iter())
                    .map(
                        |((item, sender_randomness, receiver_preimage), aocl_leaf_index)| {
                            get_swbf_indices(
                                *item,
                                *sender_randomness,
                                *receiver_preimage,
                                *aocl_leaf_index,
                            )
                        },
                    )
                    .collect_vec();
                let mut all_bloom_indices = all_index_sets.iter().flatten().cloned().collect_vec();
                all_bloom_indices.sort();

                // assemble all chunk indices
                let mut all_chunk_indices = all_bloom_indices
                    .iter()
                    .map(|index| *index / (CHUNK_SIZE as u128))
                    .map(|index| index as u64)
                    .collect_vec();
                all_chunk_indices.sort();
                all_chunk_indices.dedup();

                // filter by swbf mmr size
                let swbf_mmr_size = aocl_mmra.count_leaves() / (BATCH_SIZE as u64);
                let mmr_chunk_indices = all_chunk_indices
                    .iter()
                    .cloned()
                    .filter(|ci| *ci < swbf_mmr_size)
                    .collect_vec();

                // prepare to unwrap
                let aocl_mmra = aocl_mmra.clone();
                let swbf_chunk_indices = mmr_chunk_indices.clone();
                let all_index_sets = all_index_sets.clone();
                let aocl_membership_proofs = aocl_membership_proofs.clone();
                let removables = removables.clone();

                // unwrap random swbf chunks
                swbf_chunk_indices.iter()
                    .map(|_| arb::<Chunk>())
                    .collect_vec()
                    .prop_flat_map(move |swbf_chunks| {
                        // prepare input to pseudorandom mmr generator
                        let swbf_leafs = swbf_chunks.iter().map(Hash::hash).collect_vec();
                        let swbf_indices_and_leafs = swbf_chunk_indices.iter().copied().zip(swbf_leafs.iter().copied()).collect_vec();

                        // prepare to unwrap
                        let aocl_mmra = aocl_mmra.clone();
                        let swbf_chunk_indices = swbf_chunk_indices.clone();
                        let all_index_sets = all_index_sets.clone();
                        let aocl_membership_proofs = aocl_membership_proofs.clone();
                        let removables = removables.clone();
                        let swbf_mmr_leaf_count = aocl_mmra.count_leaves() / (BATCH_SIZE as u64);
                        let aocl_leaf_indices = aocl_leaf_indices.clone();

                        // unwrap random swbf mmra and membership proofs
                        MmraAndMembershipProofs::arbitrary_with((
                            swbf_indices_and_leafs, swbf_mmr_leaf_count
                        )).prop_flat_map(move |swbf_mmr_and_paths| {
                                let swbf_mmra = swbf_mmr_and_paths.mmra;
                                let swbf_membership_proofs = swbf_mmr_and_paths.membership_proofs;

                                let universal_chunk_dictionary: HashMap<u64, (MmrMembershipProof<Hash>, Chunk)> =
                                    swbf_chunk_indices
                                        .iter()
                                        .cloned()
                                        .zip(
                                            swbf_membership_proofs
                                                .into_iter()
                                                .zip(swbf_chunks.iter().cloned())
                                            )
                                        .collect();
                                let personalized_chunk_dictionaries = all_index_sets
                                    .iter()
                                    .map(|index_set| {
                                        let mut is = index_set
                                            .iter()
                                            .map(|index| *index / (CHUNK_SIZE as u128))
                                            .map(|index| index as u64)
                                            .collect_vec();
                                        is.sort();
                                        is.dedup();
                                        is
                                    })
                                    .map(|chunk_indices| {
                                        ChunkDictionary::new(
                                            chunk_indices
                                            .iter()
                                            .filter(|chunk_index| **chunk_index < swbf_mmr_size)
                                            .map(|chunk_index| {
                                                (
                                                    chunk_index,
                                                    universal_chunk_dictionary
                                                        .get(
                                                            chunk_index,
                                                        ).unwrap_or_else(|| panic!("Could not find chunk index {chunk_index} in universal chunk dictionary"))
                                                )
                                            })
                                            .map(|(chunk_index, (membership_proof, chunk))| (*chunk_index, (membership_proof.clone(), chunk.clone())))
                                            .collect(),
                                        )
                                    })
                                    .collect_vec();
                                let membership_proofs = removables
                                    .clone()
                                    .iter()
                                    .zip(aocl_membership_proofs.iter())
                                    .zip(personalized_chunk_dictionaries.iter())
                                    .zip(aocl_leaf_indices.iter())
                                    .map(|((((item, sender_randomness, receiver_preimage), aocl_auth_path), target_chunks), aocl_leaf_index)| {
                                        let leaf = commit(*item, *sender_randomness, receiver_preimage.hash::<Hash>()).canonical_commitment;
                                        assert!(aocl_auth_path.verify(&aocl_mmra.get_peaks(), leaf, aocl_mmra.count_leaves()));
                                        (sender_randomness, receiver_preimage, aocl_auth_path, target_chunks, aocl_leaf_index)
                                    })
                                    .map(
                                        |
                                            (sender_randomness, receiver_preimage, aocl_auth_path,
                                            target_chunks, aocl_leaf_index)
                                        | {
                                            MsMembershipProof {
                                                sender_randomness: *sender_randomness,
                                                receiver_preimage: *receiver_preimage,
                                                auth_path_aocl: aocl_auth_path.clone(),
                                                target_chunks: target_chunks.clone(),
                                                aocl_leaf_index: *aocl_leaf_index,
                                            }
                                        },
                                    )
                                    .collect_vec();

                                let removal_records = all_index_sets
                                    .iter()
                                    .zip(personalized_chunk_dictionaries.iter())
                                    .map(|(index_set, target_chunks)| RemovalRecord {
                                        absolute_indices: AbsoluteIndexSet::new(index_set),
                                        target_chunks: target_chunks.clone(),
                                    })
                                    .collect_vec();

                                // prepare to unwrap
                                let aocl_mmra = aocl_mmra.clone();
                                let swbf_mmra = swbf_mmra.clone();
                                let removal_records = removal_records.clone();
                                let membership_proofs = membership_proofs.clone();

                                // unwrap random active window
                                arb::<ActiveWindow>()
                                    .prop_map(move |active_window| {
                                        let mutator_set_accumulator = MutatorSetAccumulator {
                                                aocl: aocl_mmra.clone(),
                                                swbf_inactive: swbf_mmra.clone(),
                                                swbf_active: active_window,
                                        };

                                        MsaAndRecords {
                                            mutator_set_accumulator,
                                            removal_records: removal_records.clone(),
                                            membership_proofs: membership_proofs.clone(),
                                        }
                                    })
                                    .boxed()
                            })
                            .boxed()
                    })
                    .boxed()
            })
            .boxed()
        })
        .boxed()
    }
}

#[cfg(test)]
mod test {
    use itertools::Itertools;
    use proptest::collection::vec;
    use proptest::prop_assert;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::Digest;
    use test_strategy::proptest;

    use super::MsaAndRecords;

    #[proptest(cases = 1)]
    fn msa_and_records_is_valid(
        #[strategy(0usize..10)] _num_removals: usize,
        #[strategy(0u64..=u64::MAX)] _aocl_size: u64,
        #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_removals))]
        removables: Vec<(Digest, Digest, Digest)>,
        #[strategy(MsaAndRecords::arbitrary_with((#removables, #_aocl_size)))]
        msa_and_records: MsaAndRecords,
    ) {
        prop_assert!(msa_and_records.verify(
            &removables
                .iter()
                .map(|(item, _sr, _rp)| *item)
                .collect_vec()
        ));
    }
}
