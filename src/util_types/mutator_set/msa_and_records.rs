use std::collections::HashMap;

use itertools::Itertools;
use proptest::{
    arbitrary::Arbitrary,
    strategy::{BoxedStrategy, Just, Strategy},
};
use proptest_arbitrary_interop::arb;
use tasm_lib::{
    twenty_first::util_types::{
        algebraic_hasher::AlgebraicHasher,
        mmr::{mmr_membership_proof::MmrMembershipProof, mmr_trait::Mmr},
    },
    Digest,
};

use crate::models::blockchain::shared::Hash;

use super::{
    active_window::ActiveWindow,
    addition_record::AdditionRecord,
    chunk::Chunk,
    chunk_dictionary::ChunkDictionary,
    mmra_and_membership_proofs::MmraAndMembershipProofs,
    ms_membership_proof::MsMembershipProof,
    mutator_set_accumulator::MutatorSetAccumulator,
    mutator_set_kernel::{get_swbf_indices, MutatorSetKernel},
    mutator_set_trait::{commit, MutatorSet},
    removal_record::{AbsoluteIndexSet, RemovalRecord},
    shared::{BATCH_SIZE, CHUNK_SIZE},
};
use proptest::collection::vec;

#[derive(Debug, Clone)]
pub struct MsaAndRecords {
    pub mutator_set_accumulator: MutatorSetAccumulator,
    pub addition_records: Vec<AdditionRecord>,
    pub removal_records: Vec<RemovalRecord>,
    pub membership_proofs: Vec<MsMembershipProof>,
}

impl MsaAndRecords {
    pub fn verify(&self, items: &[Digest]) -> bool {
        self.removal_records
            .iter()
            .all(|rr| self.mutator_set_accumulator.kernel.can_remove(rr))
            && self
                .membership_proofs
                .iter()
                .zip_eq(items.iter())
                .all(|(mp, item)| self.mutator_set_accumulator.verify(*item, mp))
    }
}

impl Arbitrary for MsaAndRecords {
    type Parameters = (Vec<(Digest, Digest, Digest)>, Vec<(Digest, Digest, Digest)>);
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(parameters: Self::Parameters) -> Self::Strategy {
        let (removables, addeds) = parameters;

        let removable_commitments = removables
            .iter()
            .map(|(item, sender_randomness, receiver_preimage)| {
                commit(*item, *sender_randomness, Hash::hash(receiver_preimage))
            })
            .collect_vec();

        // unwrap aocl indices
        let aocl_size = (1u64 << 33);
        vec(0u64..aocl_size, addeds.len()).prop_flat_map(|aocl_indices| {

        // unwrap random aocl mmr with membership proofs
        MmraAndMembershipProofs::arbitrary_with((
            aocl_indices.iter().zip(removable_commitments
                .iter())
                .map(|(i, ar)| (*i, ar.canonical_commitment))
                .collect_vec(),aocl_size))
        .prop_flat_map(move |aocl_mmra_and_membership_proofs| {
            let aocl_mmra = aocl_mmra_and_membership_proofs.mmra;
            let aocl_membership_proofs = aocl_mmra_and_membership_proofs.membership_proofs;
            let all_index_sets = removables
                .iter()
                .zip(aocl_membership_proofs.iter())
                .map(
                    |((item, sender_randomness, receiver_preimage), authentication_path)| {
                        get_swbf_indices(
                            *item,
                            *sender_randomness,
                            *receiver_preimage,
                            authentication_path.leaf_index,
                        )
                    },
                )
                .collect_vec();
            let mut all_indices = all_index_sets.iter().flatten().cloned().collect_vec();
            all_indices.sort();
            let mut all_chunk_indices = all_indices
                .iter()
                .map(|index| *index / (CHUNK_SIZE as u128))
                .map(|index| index as u64)
                .collect_vec();
            all_chunk_indices.sort();
            all_chunk_indices.dedup();
            let mmr_chunk_indices = all_chunk_indices
                .iter()
                .cloned()
                .filter(|ci| *ci < aocl_mmra.count_leaves() / (BATCH_SIZE as u64))
                .collect_vec();

            // prepare to unwrap
            let aocl_mmra = aocl_mmra.clone();
            let mmr_chunk_indices = mmr_chunk_indices.clone();
            let all_index_sets = all_index_sets.clone();
            let aocl_membership_proofs = aocl_membership_proofs.clone();
            let removables = removables.clone();
            let addeds = addeds.clone();

            // unwrap random mmr_chunks
            mmr_chunk_indices.into_iter()
                .map(|index| (Just(index), arb::<Chunk>()))
                .collect_vec()
                .prop_flat_map(move |mmr_indices_and_chunks| {
                    // prepare to unwrap
                    let aocl_mmra = aocl_mmra.clone();
                    let mmr_chunk_indices = mmr_chunk_indices.clone();
                    let all_index_sets = all_index_sets.clone();
                    let aocl_membership_proofs = aocl_membership_proofs.clone();
                    let removables = removables.clone();
                    let addeds = addeds.clone();
                    let swbf_mmr_leaf_count = aocl_mmra.count_leaves() / (BATCH_SIZE as u64);

                    // unwrap random swbf mmra and membership proofs
                    let swbf_strategy = MmraAndMembershipProofs::arbitrary_with((
                        mmr_indices_and_chunks.iter().map(|(i, c)| (*i, Hash::hash(c))).collect_vec(), swbf_mmr_leaf_count
                    ));
                    let mmr_indices_and_chunks = mmr_indices_and_chunks.clone();
                    swbf_strategy
                        .prop_flat_map(move |swbf_mmr_and_paths| {
                            let swbf_mmra = swbf_mmr_and_paths.mmra;
                            let swbf_membership_proofs = swbf_mmr_and_paths.membership_proofs;

                            let chunk_dictionary: HashMap<u64, (MmrMembershipProof<Hash>, Chunk)> =
                                mmr_chunk_indices
                                    .iter()
                                    .cloned()
                                    .zip(
                                        swbf_membership_proofs
                                            .into_iter()
                                            .zip(mmr_indices_and_chunks.iter().cloned()),
                                    )
                                    .collect();
                                println!("made chunk dictionary with indices: {} where aocl mmra leaf count is {}", chunk_dictionary.keys().join(", "), aocl_mmra.count_leaves());
                            let personalized_chunk_dictionaries = all_index_sets
                                .iter()
                                .map(|index_set| {
                                    let mut is = index_set
                                        .iter()
                                        .map(|index| *index / (BATCH_SIZE as u128))
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
                                        .map(|chunk_index| {
                                            (
                                                *chunk_index,
                                                chunk_dictionary
                                                    .get(
                                                        chunk_index,
                                                    )
                                            ).filter(|r|r.is_some()).cloned()
                                        })
                                        .collect::<HashMap<
                                            u64,
                                            (
                                                MmrMembershipProof<
                                                    Hash,
                                                >,
                                                Chunk,
                                            ),
                                        >>(
                                        ),
                                    )
                                })
                                .collect_vec();
                            let membership_proofs = removables
                                .clone()
                                .iter()
                                .zip(aocl_membership_proofs.iter())
                                .zip(personalized_chunk_dictionaries.iter())
                                .map(
                                    |(
                                        ((_item, sender_randomness, receiver_preimage), auth_path),
                                        target_chunks,
                                    )| {
                                        MsMembershipProof {
                                            sender_randomness: *sender_randomness,
                                            receiver_preimage: *receiver_preimage,
                                            auth_path_aocl: auth_path.clone(),
                                            target_chunks: target_chunks.clone(),
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

                            let addition_records = addeds
                                .iter()
                                .map(|(item, sender_randomness, receiver_preimage)| {
                                    commit(*item, *sender_randomness, Hash::hash(receiver_preimage))
                                })
                                .collect_vec();

                            // prepare to unwrap
                            let aocl_mmra = aocl_mmra.clone();
                            let swbf_mmra = swbf_mmra.clone();
                            let addition_records = addition_records.clone();
                            let removal_records = removal_records.clone();
                            let membership_proofs = membership_proofs.clone();

                            // unwrap random active window
                            arb::<ActiveWindow>()
                                .prop_map(move |active_window| {
                                    let mutator_set_accumulator = MutatorSetAccumulator {
                                        kernel: MutatorSetKernel {
                                            aocl: aocl_mmra.clone(),
                                            swbf_inactive: swbf_mmra.clone(),
                                            swbf_active: active_window,
                                        },
                                    };
                                    MsaAndRecords {
                                        mutator_set_accumulator,
                                        addition_records: addition_records.clone(),
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
    }).boxed()
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

    #[proptest]
    fn msa_and_records_is_valid(
        #[strategy(0usize..10)] _num_removals: usize,
        #[strategy(0usize..10)] _num_additions: usize,
        #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_removals))]
        removables: Vec<(Digest, Digest, Digest)>,
        #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_additions))]
        _addeds: Vec<(Digest, Digest, Digest)>,
        #[strategy(MsaAndRecords::arbitrary_with((#removables, #_addeds)))]
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
