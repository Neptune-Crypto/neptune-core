use itertools::Itertools;
use tasm_lib::prelude::Digest;

use super::ms_membership_proof::MsMembershipProof;
use super::mutator_set_accumulator::MutatorSetAccumulator;
use super::removal_record::RemovalRecord;
use crate::util_types::mutator_set::removal_record::removal_record_list::RemovalRecordList;

/// A [`MutatorSetAccumulator`] with matching [`RemovalRecord`]s.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MsaAndRecords {
    pub mutator_set_accumulator: MutatorSetAccumulator,

    /// Not packed removal records
    removal_records: Vec<RemovalRecord>,
    pub membership_proofs: Vec<MsMembershipProof>,
}

impl MsaAndRecords {
    pub(crate) fn new(
        mutator_set_accumulator: MutatorSetAccumulator,
        unpacked_removal_records: Vec<RemovalRecord>,
        membership_proofs: Vec<MsMembershipProof>,
    ) -> Self {
        assert_eq!(unpacked_removal_records.len(), membership_proofs.len());
        Self {
            mutator_set_accumulator,
            removal_records: unpacked_removal_records,
            membership_proofs,
        }
    }

    pub(crate) fn unpacked_removal_records(&self) -> Vec<RemovalRecord> {
        self.removal_records.clone()
    }

    pub(crate) fn packed_removal_records(&self) -> Vec<RemovalRecord> {
        RemovalRecordList::pack(self.removal_records.clone())
    }

    pub fn verify(&self, items: &[Digest]) -> bool {
        let all_removal_records_can_remove = self
            .removal_records
            .iter()
            .all(|rr| self.mutator_set_accumulator.can_remove(rr));
        let all_membership_proofs_are_valid = self
            .membership_proofs
            .iter()
            .zip_eq(items.iter())
            .all(|(mp, item)| self.mutator_set_accumulator.verify(*item, mp));

        // Verify that mutator set has expected number of elements in Bloom
        // filter MMR, and other qualities of the mutator set.
        let ms_is_consistent = self.mutator_set_accumulator.is_consistent();

        all_removal_records_can_remove && all_membership_proofs_are_valid && ms_is_consistent
    }
}

#[cfg(any(test, feature = "arbitrary-impls"))]
pub mod neptune_arbitrary {
    use std::collections::HashMap;
    use std::collections::HashSet;

    use proptest::arbitrary::Arbitrary;
    use proptest::collection::vec;
    use proptest::strategy::BoxedStrategy;
    use proptest::strategy::Strategy;
    use proptest_arbitrary_interop::arb;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tasm_lib::prelude::Tip5;
    use tasm_lib::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
    use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;

    use super::super::active_window::ActiveWindow;
    use super::super::mmra_and_membership_proofs::MmraAndMembershipProofs;
    use super::super::removal_record::absolute_index_set::AbsoluteIndexSet;
    use super::super::removal_record::chunk::Chunk;
    use super::super::removal_record::chunk_dictionary::ChunkDictionary;
    use super::super::shared::CHUNK_SIZE;
    use super::*;
    use crate::util_types::mutator_set::commit;

    #[cfg(any(test, feature = "arbitrary-impls"))]
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

        // Returns unpacked removal records. Caller must handle packing.
        fn arbitrary_with(parameters: Self::Parameters) -> Self::Strategy {
            let (removables, aocl_size) = parameters;
            assert!(
                removables.len() <= usize::try_from(aocl_size).unwrap(),
                "Cannot remove more elements than are present. aocl_size: {aocl_size}; #removables: {}", removables.len()
            );

            // compute the canonical commitments that were added to the aocl at some prior,
            // as this is information needed to produce membership proofs for the items that
            // are going to be removed
            let removable_commitments = removables
                .iter()
                .map(|(item, sender_randomness, receiver_preimage)| {
                    commit(*item, *sender_randomness, receiver_preimage.hash())
                })
                .collect_vec();

            let removable_commitments = removable_commitments.clone();

            // sample random aocl indices
            vec(0u64..aocl_size, removables.len())
                .prop_flat_map(move |removed_aocl_indices| {

                // Ensure AOCL indices are unique. Just add indices
                // deterministically if they are not. All Hell would break
                // loose if we didn't use deterministic RNG here.
                let mut removed_aocl_indices: HashSet<_> = removed_aocl_indices.into_iter().collect();
                let rng_seed: [u8; Digest::BYTES] = Tip5::hash(&removables).into();
                let rng_seed: [u8; 32] = rng_seed.into_iter().take(32).collect_vec().try_into().unwrap();
                let mut rng: StdRng = SeedableRng::from_seed(rng_seed);
                while removed_aocl_indices.len() < removables.len() {
                    let rand: u64 = rng.random();
                    removed_aocl_indices.insert(rand % aocl_size);
                }

                // prepare unwrap
                let removables = removables.clone();

                // bundle all indices and leafs for pseudorandom aocl
                let all_aocl_indices_and_leafs = removed_aocl_indices.into_iter().sorted().zip_eq(removable_commitments.iter().map(|ar|ar.canonical_commitment)).collect_vec();

                // unwrap random aocl mmr with membership proofs
                MmraAndMembershipProofs::arbitrary_with((all_aocl_indices_and_leafs, aocl_size))
                .prop_flat_map(move |aocl_mmra_and_membership_proofs| {
                    use crate::util_types::mutator_set::aocl_to_swbfi_leaf_counts;

                    let aocl_mmra = aocl_mmra_and_membership_proofs.mmra;
                    let aocl_membership_proofs = aocl_mmra_and_membership_proofs.membership_proofs;
                    let aocl_leaf_indices = aocl_mmra_and_membership_proofs.leaf_indices;

                    // assemble all indices of all removal records
                    let all_index_sets = removables
                        .iter()
                        .zip(aocl_leaf_indices.iter())
                        .map(
                            |((item, sender_randomness, receiver_preimage), aocl_leaf_index)| {
                                AbsoluteIndexSet::compute(
                                    *item,
                                    *sender_randomness,
                                    *receiver_preimage,
                                    *aocl_leaf_index,
                                )
                            },
                        )
                        .collect_vec();
                    let mut all_bloom_indices = all_index_sets.iter().flat_map(|ais|ais.to_array()).collect_vec();
                    all_bloom_indices.sort();

                    // assemble all chunk indices
                    let mut all_chunk_indices = all_bloom_indices
                        .iter()
                        .map(|index| *index / u128::from(CHUNK_SIZE))
                        .map(|index| index as u64)
                        .collect_vec();
                    all_chunk_indices.sort();
                    all_chunk_indices.dedup();

                    // filter by swbf mmr size
                    let swbf_mmr_num_leafs = aocl_to_swbfi_leaf_counts(aocl_mmra.num_leafs());
                    let mmr_chunk_indices = all_chunk_indices
                        .iter()
                        .copied()
                        .filter(|ci| *ci < swbf_mmr_num_leafs)
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
                            let swbf_leafs = swbf_chunks.iter().map(Tip5::hash).collect_vec();
                            let swbf_indices_and_leafs = swbf_chunk_indices.iter().copied().zip(swbf_leafs.iter().copied()).collect_vec();

                            // prepare to unwrap
                            let aocl_mmra = aocl_mmra.clone();
                            let swbf_chunk_indices = swbf_chunk_indices.clone();
                            let all_index_sets = all_index_sets.clone();
                            let aocl_membership_proofs = aocl_membership_proofs.clone();
                            let removables = removables.clone();
                            let aocl_leaf_indices = aocl_leaf_indices.clone();

                            // unwrap random swbf mmra and membership proofs
                            MmraAndMembershipProofs::arbitrary_with((
                                swbf_indices_and_leafs, swbf_mmr_num_leafs
                            )).prop_flat_map(move |swbf_mmr_and_paths| {
                                    let swbf_mmra = swbf_mmr_and_paths.mmra;
                                    let swbf_membership_proofs = swbf_mmr_and_paths.membership_proofs;

                                    let universal_chunk_dictionary: HashMap<u64, (MmrMembershipProof, Chunk)> =
                                        swbf_chunk_indices
                                            .iter()
                                            .copied()
                                            .zip(
                                                swbf_membership_proofs
                                                    .into_iter()
                                                    .zip(swbf_chunks.iter().cloned())
                                                )
                                            .collect();
                                    let personalized_chunk_dictionaries = all_index_sets
                                        .iter()
                                        .map(|index_set| {
                                            let mut is = index_set.to_vec()
                                                .iter()
                                                .map(|index| *index / u128::from(CHUNK_SIZE))
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
                                                .filter(|chunk_index| **chunk_index < swbf_mmr_num_leafs)
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
                                            let leaf = commit(*item, *sender_randomness, receiver_preimage.hash()).canonical_commitment;
                                            assert!(aocl_auth_path.verify(*aocl_leaf_index, leaf, &aocl_mmra.peaks(), aocl_mmra.num_leafs()));
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
                                            absolute_indices: index_set.to_owned(),
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
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use itertools::Itertools;
    use proptest::collection::vec;
    use proptest::prelude::Arbitrary;
    use proptest::prelude::Strategy;
    use proptest::prop_assert;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestCaseError;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tasm_lib::prelude::Digest;
    use tasm_lib::twenty_first::prelude::Mmr;

    use super::MsaAndRecords;
    use crate::tests::shared::strategies;
    use crate::util_types::mutator_set::commit;
    use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
    use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
    use crate::util_types::mutator_set::removal_record::RemovalRecord;

    impl MsaAndRecords {
        /// Split an [MsaAndRecords] into multiple instances of the same type.
        ///
        /// input argument specifies the length of each returned instance.
        ///
        /// # Panics
        /// Panics if input argument does not sum to the number of membership proofs
        /// and removal records.
        pub(crate) fn split_by<const N: usize>(&self, lengths: [usize; N]) -> [Self; N] {
            let resulting_size: usize = lengths.into_iter().sum();
            assert_eq!(self.membership_proofs.len(), resulting_size);
            assert_eq!(self.removal_records.len(), resulting_size);

            let ret = Self {
                mutator_set_accumulator: self.mutator_set_accumulator.to_owned(),
                ..Default::default()
            };
            let mut ret = vec![ret.clone(); N];

            let mut counter = 0;
            for (length, elem) in lengths.into_iter().zip(ret.iter_mut()) {
                for _ in 0..length {
                    elem.membership_proofs
                        .push(self.membership_proofs[counter].clone());
                    elem.removal_records
                        .push(self.removal_records[counter].clone());
                    counter += 1;
                }
            }

            ret.try_into().unwrap()
        }
    }

    fn state_updates_prop(
        removables: Vec<(Digest, Digest, Digest)>,
        msa_and_records: MsaAndRecords,
        mut additions: Vec<(Digest, Digest, Digest)>,
        rng_seed: u64,
    ) -> std::result::Result<(), TestCaseError> {
        fn assert_valid(
            msa: &MutatorSetAccumulator,
            rrs: &[RemovalRecord],
            msmps: &[MsMembershipProof],
            items: &[Digest],
            new_msmps: &[MsMembershipProof],
            inserted_items: &[Digest],
        ) -> std::result::Result<(), TestCaseError> {
            prop_assert!(msa.is_consistent());
            for rr in rrs {
                prop_assert!(msa.can_remove(rr));
            }
            for (msmp, item) in msmps
                .iter()
                .chain(new_msmps.iter())
                .zip_eq(items.iter().chain(inserted_items))
            {
                prop_assert!(msa.verify(*item, msmp));
            }

            Ok(())
        }

        let mut items = removables
            .into_iter()
            .map(|(item, _, _)| item)
            .collect_vec();
        let mut rrs = msa_and_records.unpacked_removal_records();
        let mut msmps = msa_and_records.membership_proofs;
        let mut msa = msa_and_records.mutator_set_accumulator;
        let mut new_msmps = vec![];
        let mut inserted_items = vec![];

        // Ensure initial validity
        assert_valid(&msa, &rrs, &msmps, &items, &new_msmps, &inserted_items).unwrap();

        let mut rng: StdRng = SeedableRng::seed_from_u64(rng_seed);

        // Apply all removals and addition records, while keeping proof-data
        // updated and verifying validity after each operation.
        while !(additions.is_empty() && rrs.is_empty()) {
            if rng.random_bool(0.5f64) {
                // Add an element to the MSA
                let Some((new_item, sr, rp)) = additions.pop() else {
                    continue;
                };

                // Update all MSMPS
                let addition = commit(new_item, sr, rp.hash());

                MsMembershipProof::batch_update_from_addition(
                    &mut msmps.iter_mut().chain(new_msmps.iter_mut()).collect_vec(),
                    &items
                        .iter()
                        .chain(inserted_items.iter())
                        .copied()
                        .collect_vec(),
                    &msa,
                    &addition,
                )
                .unwrap();

                // Update all removal records
                RemovalRecord::batch_update_from_addition(&mut rrs.iter_mut().collect_vec(), &msa);

                // Apply the addition
                let new_msmp = msa.prove(new_item, sr, rp);
                new_msmps.push(new_msmp);
                inserted_items.push(new_item);

                msa.add(&addition);
            } else {
                // Remove an element from the MSA
                let Some(rr) = rrs.pop() else {
                    continue;
                };

                // Update all MSMPS
                MsMembershipProof::batch_update_from_remove(
                    &mut msmps.iter_mut().chain(new_msmps.iter_mut()).collect_vec(),
                    &rr,
                )
                .unwrap();

                // Update all removal records
                RemovalRecord::batch_update_from_remove(&mut rrs.iter_mut().collect_vec(), &rr);

                prop_assert!(msa.can_remove(&rr));
                msa.remove(&rr);
                prop_assert!(!msa.can_remove(&rr));

                // Remove the item and MSMP for the applied removal record from
                // corresponding lists. Otherwise later validity checks fail.
                msmps.pop().unwrap();
                items.pop().unwrap();
            }

            // Ensure validity after operation
            assert_valid(&msa, &rrs, &msmps, &items, &new_msmps, &inserted_items).unwrap();
        }

        Ok(())
    }

    #[test_strategy::proptest(cases = 4)]
    fn state_updates_small_aocl_size(
        #[strategy(0usize..30_usize)] _num_removals: usize,
        #[strategy((#_num_removals as u64)..=u64::from(u8::MAX))] _aocl_size: u64,
        #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_removals))]
        removables: Vec<(Digest, Digest, Digest)>,
        #[strategy(MsaAndRecords::arbitrary_with((#removables.clone(), #_aocl_size)))]
        msa_and_records: MsaAndRecords,
        #[strategy(0usize..=(u8::MAX as usize))] _num_additions: usize,
        #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_additions))]
        additions: Vec<(Digest, Digest, Digest)>,
        #[strategy(arb())] rng_seed: u64,
    ) {
        prop_assert!(state_updates_prop(removables, msa_and_records, additions, rng_seed).is_ok())
    }

    #[test_strategy::proptest(cases = 3)]
    fn state_updates_midi_aocl_size(
        #[strategy(0u64..=u64::from(u16::MAX))] _aocl_size: u64,
        #[strategy(0usize..20_usize)]
        #[filter(#_aocl_size >= (#_num_removals as u64))]
        _num_removals: usize,
        #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_removals))]
        removables: Vec<(Digest, Digest, Digest)>,
        #[strategy(MsaAndRecords::arbitrary_with((#removables.clone(), #_aocl_size)))]
        msa_and_records: MsaAndRecords,
        #[strategy(0usize..=(u8::MAX as usize))] _num_additions: usize,
        #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_additions))]
        additions: Vec<(Digest, Digest, Digest)>,
        #[strategy(arb())] rng_seed: u64,
    ) {
        prop_assert!(state_updates_prop(removables, msa_and_records, additions, rng_seed).is_ok())
    }

    #[test_strategy::proptest(cases = 3)]
    fn state_updates_medium_aocl_size(
        #[strategy(0u64..=u64::from(u32::MAX))] _aocl_size: u64,
        #[strategy(0usize..20_usize)]
        #[filter(#_aocl_size >= (#_num_removals as u64))]
        _num_removals: usize,
        #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_removals))]
        removables: Vec<(Digest, Digest, Digest)>,
        #[strategy(MsaAndRecords::arbitrary_with((#removables.clone(), #_aocl_size)))]
        msa_and_records: MsaAndRecords,
        #[strategy(0usize..=100usize)] _num_additions: usize,
        #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_additions))]
        additions: Vec<(Digest, Digest, Digest)>,
        #[strategy(arb())] rng_seed: u64,
    ) {
        prop_assert!(state_updates_prop(removables, msa_and_records, additions, rng_seed).is_ok())
    }

    #[test_strategy::proptest(cases = 2)]
    fn state_updates_big_aocl_size(
        #[strategy(0u64..=u64::MAX / 2)] _aocl_size: u64,
        #[strategy(0usize..10_usize)]
        #[filter(#_aocl_size >= (#_num_removals as u64))]
        _num_removals: usize,
        #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_removals))]
        removables: Vec<(Digest, Digest, Digest)>,
        #[strategy(MsaAndRecords::arbitrary_with((#removables.clone(), #_aocl_size)))]
        msa_and_records: MsaAndRecords,
        #[strategy(0usize..=100usize)] _num_additions: usize,
        #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_additions))]
        additions: Vec<(Digest, Digest, Digest)>,
        #[strategy(arb())] rng_seed: u64,
    ) {
        prop_assert!(state_updates_prop(removables, msa_and_records, additions, rng_seed).is_ok())
    }

    #[test_strategy::proptest(cases = 10)]
    fn msa_and_records_is_valid_big_aocl(
        #[strategy(0usize..60)] _num_removals: usize,
        #[strategy(0u64..=u64::MAX / 2)] _aocl_size: u64,
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

    #[test_strategy::proptest]
    fn msa_and_records_is_valid_small_aocl(
        #[strategy(0u64..=u64::from(u8::MAX))] _aocl_size: u64,
        #[strategy(0usize..=#_aocl_size as usize)] _num_removals: usize,
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

    #[test_strategy::proptest(cases = 6)]
    fn msa_and_records_invalid_on_one_too_many_swbf_leaf(
        #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), 30usize))]
        removables: Vec<(Digest, Digest, Digest)>,
        #[strategy(MsaAndRecords::arbitrary_with((#removables, 100u64)))]
        msa_and_records: MsaAndRecords,
        #[strategy(arb())] new_leaf: Digest,
    ) {
        let mut msa_and_records = msa_and_records;
        prop_assert!(msa_and_records.verify(
            &removables
                .iter()
                .map(|(item, _sr, _rp)| *item)
                .collect_vec()
        ));
        msa_and_records
            .mutator_set_accumulator
            .swbf_inactive
            .append(new_leaf);
        prop_assert!(!msa_and_records.verify(
            &removables
                .iter()
                .map(|(item, _sr, _rp)| *item)
                .collect_vec()
        ));
    }

    #[test]
    fn split_msa_and_records() {
        proptest::proptest!(|(data in vec((strategies::removalrecord(), strategies::msmembershipproof()), 1))| split_prop([1], data));
        proptest::proptest!(|(data in vec((strategies::removalrecord(), strategies::msmembershipproof()), 0))| split_prop([0], data));
        proptest::proptest!(|(data in vec((strategies::removalrecord(), strategies::msmembershipproof()), 5))| split_prop([0, 5], data));
        proptest::proptest!(|(data in vec((strategies::removalrecord(), strategies::msmembershipproof()), 7))| split_prop([3, 4], data));
        proptest::proptest!(|(data in vec((strategies::removalrecord(), strategies::msmembershipproof()), 19))| split_prop([12, 2, 5], data));
    }

    fn split_prop<const N: usize>(
        split: [usize; N],
        mut data: Vec<(RemovalRecord, MsMembershipProof)>,
    ) {
        let mut original = MsaAndRecords::default();
        let total = split.into_iter().sum::<usize>();
        for _ in 0..total {
            let datum = data.pop().unwrap();
            original.removal_records.push(datum.0);
            original.membership_proofs.push(datum.1);
        }

        let split_msa_and_records = original.split_by(split);
        for elem in &split_msa_and_records {
            assert_eq!(
                elem.mutator_set_accumulator,
                original.mutator_set_accumulator
            );
        }

        let mut running_sum = 0;
        for (i, count) in split.into_iter().enumerate() {
            assert_eq!(
                original.removal_records[running_sum..running_sum + count].to_vec(),
                split_msa_and_records[i].removal_records.to_vec()
            );
            assert_eq!(
                original.membership_proofs[running_sum..running_sum + count].to_vec(),
                split_msa_and_records[i].membership_proofs.to_vec()
            );
            running_sum += count;
        }

        assert_eq!(running_sum, total);
    }

    #[test]
    fn arbitrary_msa_and_records_is_deterministic() {
        let deterministic_msa = |num_removals, num_items| {
            let mut test_runner = TestRunner::deterministic();
            let removables = vec(
                (arb::<Digest>(), arb::<Digest>(), arb::<Digest>()),
                num_removals,
            )
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
            MsaAndRecords::arbitrary_with((removables, num_items))
                .new_tree(&mut test_runner)
                .unwrap()
                .current()
        };

        let num_removals = 50;
        let num_items = 100;
        assert_eq!(
            deterministic_msa(num_removals, num_items),
            deterministic_msa(num_removals, num_items)
        );
    }
}
