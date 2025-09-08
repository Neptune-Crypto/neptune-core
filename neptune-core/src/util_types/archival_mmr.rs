use std::ops::RangeInclusive;

use itertools::Itertools;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::tip5::digest::Digest;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::LeafMutation;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;
use tasm_lib::twenty_first::util_types::mmr::shared_advanced;
use tasm_lib::twenty_first::util_types::mmr::shared_advanced::get_authentication_path_node_indices;
use tasm_lib::twenty_first::util_types::mmr::shared_advanced::get_peak_heights_and_peak_node_indices;
use tasm_lib::twenty_first::util_types::mmr::shared_advanced::leaf_index_to_node_index;
use tasm_lib::twenty_first::util_types::mmr::shared_advanced::node_index_to_leaf_index;
use tasm_lib::twenty_first::util_types::mmr::shared_basic::leaf_index_to_mt_index_and_peak_index;
use tasm_lib::twenty_first::util_types::mmr::shared_basic::right_lineage_length_from_leaf_index;

use crate::application::database::storage::storage_schema::DbtVec;
use crate::application::database::storage::storage_vec::traits::*;

/// A Merkle Mountain Range is a datastructure for storing a list of hashes.
///
/// Merkle Mountain Ranges only know about hashes. When values are to be associated with
/// MMRs, these values must be stored by the caller, or in a wrapper to this data structure.
#[derive(Debug, Clone)]
pub struct ArchivalMmr<Storage: StorageVec<Digest>> {
    digests: Storage,
}

impl<Storage> ArchivalMmr<Storage>
where
    Storage: StorageVec<Digest>,
{
    /// Calculate the root for the entire MMR
    pub async fn bag_peaks(&self) -> Digest {
        let peaks: Vec<Digest> = self.peaks().await;
        let num_leafs = self.num_leafs().await;
        MmrAccumulator::init(peaks, num_leafs).bag_peaks()
    }

    /// Return the digests of the peaks of the MMR
    pub async fn peaks(&self) -> Vec<Digest> {
        let leaf_count = self.num_leafs().await;
        let (_, peak_node_indices) = get_peak_heights_and_peak_node_indices(leaf_count);
        self.digests.get_many(&peak_node_indices).await
    }

    /// Whether the MMR is empty. Note that since indexing starts at
    /// 1, the `digests` contain must always contain at least one
    /// element: a dummy digest.
    pub async fn is_empty(&self) -> bool {
        self.digests.len().await == 1
    }

    /// Return the number of leaves in the tree
    pub async fn num_leafs(&self) -> u64 {
        node_index_to_leaf_index(self.digests.len().await).unwrap()
    }

    /// Append an element to the archival MMR, return the membership proof of the newly added leaf.
    pub async fn append(&mut self, new_leaf: Digest) -> MmrMembershipProof {
        let mut node_index = self.digests.len().await;
        let leaf_index = node_index_to_leaf_index(node_index).unwrap();
        let right_lineage_length = right_lineage_length_from_leaf_index(leaf_index);
        self.digests.push(new_leaf).await;

        let mut returned_auth_path = vec![];
        let mut acc_hash = new_leaf;
        for height in 0..right_lineage_length {
            let left_sibling_hash = self
                .digests
                .get(shared_advanced::left_sibling(node_index, height))
                .await;
            returned_auth_path.push(left_sibling_hash);
            acc_hash = Tip5::hash_pair(left_sibling_hash, acc_hash);
            self.digests.push(acc_hash).await;
            node_index += 1;
        }

        MmrMembershipProof {
            authentication_path: returned_auth_path,
        }
    }

    /// Mutate an existing leaf.
    pub async fn mutate_leaf(&mut self, leaf_index: u64, new_leaf: Digest) {
        // 1. change the leaf value
        let mut node_index = shared_advanced::leaf_index_to_node_index(leaf_index);
        self.digests.set(node_index, new_leaf).await;
        // leaf_index_to_mt_index_and_peak_index

        // While parent exists in MMR, update parent
        let mut parent_index = shared_advanced::parent(node_index);
        let mut acc_hash = new_leaf;
        while parent_index < self.digests.len().await {
            let (right_lineage_count, height) =
                shared_advanced::right_lineage_length_and_own_height(node_index);
            acc_hash = if right_lineage_count != 0 {
                // node is right child
                Tip5::hash_pair(
                    self.digests
                        .get(shared_advanced::left_sibling(node_index, height))
                        .await,
                    acc_hash,
                )
            } else {
                // node is left child
                Tip5::hash_pair(
                    acc_hash,
                    self.digests
                        .get(shared_advanced::right_sibling(node_index, height))
                        .await,
                )
            };
            self.digests.set(parent_index, acc_hash).await;
            node_index = parent_index;
            parent_index = shared_advanced::parent(parent_index);
        }
    }

    /// Modify a bunch of leafs and keep a set of membership proofs in sync. Notice that this
    /// function is not just the application of `mutate_leaf` multiple times, as it also preserves
    /// a list of membership proofs.
    pub async fn batch_mutate_leaf_and_update_mps(
        &mut self,
        membership_proofs: &mut [&mut MmrMembershipProof],
        mutation_data: Vec<(u64, Digest)>,
    ) -> Vec<usize> {
        assert!(
            mutation_data.iter().map(|md| md.0).all_unique(),
            "Duplicated leaves are not allowed in membership proof updater"
        );

        for (leaf_index, digest) in &mutation_data {
            self.mutate_leaf(*leaf_index, *digest).await;
        }

        let mut modified_mps: Vec<usize> = vec![];
        for ((i, mp), (leaf_index, _old_leaf)) in membership_proofs
            .iter_mut()
            .enumerate()
            .zip(mutation_data.iter())
        {
            let new_mp = self.prove_membership_async(*leaf_index).await;
            if new_mp != **mp {
                modified_mps.push(i);
            }

            **mp = new_mp
        }

        modified_mps
    }

    pub async fn verify_batch_update(
        &self,
        new_peaks: &[Digest],
        appended_leafs: &[Digest],
        leaf_mutations: &[LeafMutation],
    ) -> bool {
        let accumulator: MmrAccumulator = self.to_accumulator_async().await;
        accumulator.verify_batch_update(new_peaks, appended_leafs, leaf_mutations.to_vec())
    }

    pub async fn to_accumulator_async(&self) -> MmrAccumulator {
        MmrAccumulator::init(self.peaks().await, self.num_leafs().await)
    }
}

impl<Storage: StorageVec<Digest>> ArchivalMmr<Storage> {
    /// Create a new archival MMR, or restore one from a database.
    pub async fn new(pv: Storage) -> Self {
        let mut ret = Self { digests: pv };
        ret.fix_dummy_async().await;
        ret
    }

    /// Inserts a dummy digest into the `digests` container. Due to
    /// 1-indexation, this structure must always contain one element
    /// (even if it is never used). Due to the persistence layer,
    /// this data structure can be set to the default vector, which
    /// is the empty vector. This method fixes that.
    pub async fn fix_dummy_async(&mut self) {
        if self.digests.len().await == 0 {
            self.digests.push(Digest::default()).await;
        }
    }

    /// Get a leaf from the MMR, will panic if index is out of range.
    ///
    /// # Panics
    ///
    /// panics if the leaf-index is out-of-bounds.
    pub async fn get_leaf_async(&self, leaf_index: u64) -> Digest {
        // Use debug-assert here to limit this lookup to *one* db-lookup in
        // production. Otherwise, it would be two lookups.
        debug_assert!(
            leaf_index < self.num_leafs().await,
            "Leaf index out-of-bounds. Got leaf index {leaf_index} but num_leafs was {}",
            self.num_leafs().await
        );
        let node_index = shared_advanced::leaf_index_to_node_index(leaf_index);
        self.digests.get(node_index).await
    }

    /// Get a range of leafs from the MMR.
    ///
    /// # Panics
    ///
    ///  - If the range contains out-of-bound indices.
    pub async fn get_leaf_range_inclusive_async(
        &self,
        leaf_index_range: RangeInclusive<u64>,
    ) -> Vec<Digest> {
        // Use debug-assert here to limit this lookup to *one* db-lookup in
        // production. Otherwise, it would be two lookups.
        debug_assert!(
            *leaf_index_range.end() < self.num_leafs().await,
            "Leaf index out-of-bounds. Got leaf index {} but num_leafs was {}",
            leaf_index_range.end(),
            self.num_leafs().await
        );

        let indices = leaf_index_range
            .into_iter()
            .map(shared_advanced::leaf_index_to_node_index)
            .collect_vec();
        self.digests.get_many(&indices).await
    }

    /// Get a leaf from the MMR, returns `None` if index is out of range.
    pub async fn try_get_leaf(&self, leaf_index: u64) -> Option<Digest> {
        if leaf_index >= self.num_leafs().await {
            None
        } else {
            Some(self.get_leaf_async(leaf_index).await)
        }
    }

    /// Return membership proof, as it looks relative to a smaller version of
    /// the MMR which only has `num_leafs` leafs. `num_leafs` may not exceed
    /// the actual number of leafs.
    pub(crate) async fn prove_membership_relative_to_smaller_mmr(
        &self,
        leaf_index: u64,
        num_leafs: u64,
    ) -> MmrMembershipProof {
        // TODO: Replace this local function with the one in `twenty_first` once
        // available through never version.
        fn auth_path_node_indices(num_leafs: u64, leaf_index: u64) -> Vec<u64> {
            assert!(
                leaf_index < num_leafs,
                "Leaf index out-of-bounds: {leaf_index}/{num_leafs}"
            );

            let (mut merkle_tree_index, _) =
                leaf_index_to_mt_index_and_peak_index(leaf_index, num_leafs);
            let mut node_index = leaf_index_to_node_index(leaf_index);
            let mut height = 0;
            let tree_height = u64::BITS - merkle_tree_index.leading_zeros() - 1;
            let mut ret = Vec::with_capacity(tree_height as usize);
            while merkle_tree_index > 1 {
                let is_left_sibling = merkle_tree_index & 1 == 0;
                let height_pow = 1u64 << (height + 1);
                let as_1_or_minus_1: u64 = (2 * i64::from(is_left_sibling) - 1) as u64;
                let signed_height_pow = height_pow.wrapping_mul(as_1_or_minus_1);
                let sibling = node_index
                    .wrapping_add(signed_height_pow)
                    .wrapping_sub(as_1_or_minus_1);

                node_index += 1 << ((height + 1) * u32::from(is_left_sibling));

                ret.push(sibling);
                merkle_tree_index >>= 1;
                height += 1;
            }

            debug_assert_eq!(tree_height, ret.len() as u32, "Allocation must be optimal");

            ret
        }

        assert!(
            num_leafs <= self.num_leafs().await,
            "Cannot find membership proofs relative to bigger MMR"
        );

        let node_indices = auth_path_node_indices(num_leafs, leaf_index);
        let ap_elements = self.digests.get_many(&node_indices).await;

        MmrMembershipProof {
            authentication_path: ap_elements,
        }
    }

    /// Return membership proof
    pub async fn prove_membership_async(&self, leaf_index: u64) -> MmrMembershipProof {
        // A proof consists of an authentication path
        // and a list of peaks
        let num_leafs = self.num_leafs().await;
        assert!(
            leaf_index < num_leafs,
            "Cannot prove membership of leaf outside of range. Got leaf_index {leaf_index}. Leaf count is {}", self.num_leafs().await
        );

        let node_index = shared_advanced::leaf_index_to_node_index(leaf_index);
        let (_, own_index_into_peaks_list) =
            leaf_index_to_mt_index_and_peak_index(leaf_index, num_leafs);
        let (_, peak_indices) = get_peak_heights_and_peak_node_indices(num_leafs);
        let num_nodes = self.digests.len().await;
        let sibling_indices = get_authentication_path_node_indices(
            node_index,
            peak_indices[own_index_into_peaks_list as usize],
            num_nodes,
        )
        .unwrap();

        let authentication_path = self.digests.get_many(&sibling_indices).await;

        MmrMembershipProof::new(authentication_path)
    }

    /// Returns the right-most leaf of the MMR, the leaf that was added the
    /// latest.
    pub(crate) async fn get_latest_leaf(&self) -> Option<Digest> {
        if self.is_empty().await {
            return None;
        }

        let node_index = self.digests.len().await - 1;
        let (_, height) = shared_advanced::right_lineage_length_and_own_height(node_index);
        let node_index = node_index - u64::from(height);

        Some(self.digests.get(node_index).await)
    }

    /// Remove the last leaf from the archival MMR
    pub async fn remove_last_leaf_async(&mut self) -> Option<Digest> {
        if self.is_empty().await {
            return None;
        }

        let node_index = self.digests.len().await - 1;
        let mut ret = self.digests.pop().await.unwrap();
        let (_, mut height) = shared_advanced::right_lineage_length_and_own_height(node_index);
        while height > 0 {
            ret = self.digests.pop().await.unwrap();
            height -= 1;
        }

        Some(ret)
    }

    /// Remove the last leafs of the MMR such that only the specified number
    /// of leafs remain. If initial number of leafs is less than requested,
    /// this MMR is not mutated.
    pub(crate) async fn prune_to_num_leafs(&mut self, num_leafs: u64) {
        let index_of_last_removal = leaf_index_to_node_index(num_leafs);

        while self.digests.len().await > index_of_last_removal {
            // TODO: It would be faster to be able to prune here,
            self.digests.pop().await.unwrap();
        }
    }
}

impl ArchivalMmr<DbtVec<Digest>> {
    /// Delete ephemeral (cache) values, without persisting them.
    ///
    /// Can be used to roll-back ephemeral values to a persisted state.
    pub(crate) async fn delete_cache(&mut self) {
        self.digests.delete_cache().await;
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {

    use std::cmp;

    use itertools::*;
    use macro_rules_attr::apply;
    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest_arbitrary_interop::arb;
    use rand::random;
    use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
    use tasm_lib::twenty_first::math::other::*;
    use tasm_lib::twenty_first::tip5::Tip5;
    use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
    use test_strategy::proptest;

    use super::*;
    use crate::application::database::storage::storage_schema::traits::*;
    use crate::application::database::storage::storage_schema::SimpleRustyStorage;
    use crate::application::database::storage::storage_vec::OrdinaryVec;
    use crate::application::database::NeptuneLevelDb;
    use crate::tests::shared_tokio_runtime;

    type Storage = OrdinaryVec<Digest>;

    pub(crate) mod mock {
        use super::*;

        /// Return an empty ArchivalMmR for testing purposes.
        /// Does *not* have a unique ID, so you can't expect multiple of these
        /// instances to behave independently unless you understand the
        /// underlying data structure.
        pub async fn get_empty_ammr() -> ArchivalMmr<Storage> {
            let pv: Storage = Default::default();
            ArchivalMmr::new(pv).await
        }

        pub async fn get_ammr_from_digests(digests: Vec<Digest>) -> ArchivalMmr<Storage> {
            let mut ammr = get_empty_ammr().await;
            for digest in digests {
                ammr.append(digest).await;
            }
            ammr
        }
    }

    impl<Storage: StorageVec<Digest>> ArchivalMmr<Storage> {
        /// Return the number of nodes in all the trees in the MMR
        async fn count_nodes(&self) -> u64 {
            self.digests.len().await - 1
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn prune_to_num_leafs_unit_test() {
        let mut archival_mmr: ArchivalMmr<Storage> =
            mock::get_ammr_from_digests(vec![Digest::default(); 7]).await;
        assert_eq!(7, archival_mmr.num_leafs().await as usize);
        archival_mmr.prune_to_num_leafs(2).await;
        assert_eq!(2, archival_mmr.num_leafs().await as u64);
    }

    #[apply(shared_tokio_runtime)]
    async fn prune_to_num_leafs_empty() {
        for init_size in 0..3 {
            let mut archival_mmr: ArchivalMmr<Storage> =
                mock::get_ammr_from_digests(vec![Digest::default(); init_size]).await;
            assert_eq!(init_size, archival_mmr.num_leafs().await as usize);
            archival_mmr.prune_to_num_leafs(2).await;
            assert_eq!(
                cmp::min(2, init_size as u64),
                archival_mmr.num_leafs().await
            );
        }
    }

    #[proptest(cases = 8, async = "tokio")]
    async fn prune_to_num_leafs_pbt(
        #[strategy(1u64..200)] init_num_leafs: u64,
        #[strategy(vec(arb(), #init_num_leafs as usize))] digests: Vec<Digest>,
        #[strategy(0u64..#init_num_leafs)] final_num_leafs: u64,
    ) {
        let mut archival_mmr: ArchivalMmr<Storage> = mock::get_ammr_from_digests(digests).await;
        prop_assert_eq!(init_num_leafs, archival_mmr.num_leafs().await as u64);
        archival_mmr.prune_to_num_leafs(final_num_leafs).await;
        prop_assert_eq!(final_num_leafs, archival_mmr.num_leafs().await as u64);
    }

    #[apply(shared_tokio_runtime)]
    async fn empty_mmr_behavior_test() {
        let mut archival_mmr: ArchivalMmr<Storage> = mock::get_empty_ammr().await;
        let mut accumulator_mmr: MmrAccumulator = MmrAccumulator::new_from_leafs(vec![]);

        assert_eq!(0, archival_mmr.num_leafs().await);
        assert_eq!(0, accumulator_mmr.num_leafs());
        assert_eq!(archival_mmr.peaks().await, accumulator_mmr.peaks());
        assert_eq!(Vec::<Digest>::new(), accumulator_mmr.peaks());
        assert_eq!(archival_mmr.bag_peaks().await, accumulator_mmr.bag_peaks());
        assert_eq!(0, archival_mmr.count_nodes().await);
        assert!(accumulator_mmr.is_empty());
        assert!(archival_mmr.is_empty().await);

        // Test behavior of appending to an empty MMR
        let new_leaf = random();

        let mut archival_mmr_appended = mock::get_empty_ammr().await;
        {
            let leaf_index = archival_mmr_appended.num_leafs().await;
            let archival_membership_proof = archival_mmr_appended.append(new_leaf).await;

            // Verify that the MMR update can be validated
            assert!(
                archival_mmr
                    .verify_batch_update(&archival_mmr_appended.peaks().await, &[new_leaf], &[])
                    .await
            );

            // Verify that failing MMR update for empty MMR fails gracefully
            assert!(
                !archival_mmr
                    .verify_batch_update(
                        &archival_mmr_appended.peaks().await,
                        &[],
                        &[LeafMutation::new(
                            leaf_index,
                            new_leaf,
                            archival_membership_proof
                        )]
                    )
                    .await
            );
        }

        // Make the append and verify that the new peaks match the one from the proofs
        let leaf_index = accumulator_mmr.num_leafs();
        let archival_membership_proof = archival_mmr.append(new_leaf).await;
        let accumulator_membership_proof = accumulator_mmr.append(new_leaf);
        assert_eq!(
            archival_mmr.peaks().await,
            archival_mmr_appended.peaks().await
        );
        assert_eq!(accumulator_mmr.peaks(), archival_mmr_appended.peaks().await);

        // Verify that the appended value matches the one stored in the archival MMR
        assert_eq!(new_leaf, archival_mmr.get_leaf_async(0).await);

        // Verify that the membership proofs for the inserted leafs are valid and that they agree
        assert_eq!(
            archival_membership_proof, accumulator_membership_proof,
            "accumulator and archival membership proofs must agree"
        );
        assert!(
            archival_membership_proof.verify(
                leaf_index,
                new_leaf,
                &archival_mmr.peaks().await,
                archival_mmr.num_leafs().await
            ),
            "membership proof from arhival MMR must validate"
        );
    }

    #[apply(shared_tokio_runtime)]
    async fn verify_against_correct_peak_test() {
        // This test addresses a bug that was discovered late in the development process
        // where it was possible to fake a verification proof by providing a valid leaf
        // and authentication path but lying about the data index. This error occurred
        // because the derived hash was compared against all of the peaks to find a match
        // and it wasn't verified that the accumulated hash matched the *correct* peak.
        // This error was fixed and this test fails without that fix.
        let leaf_hashes: Vec<Digest> = random_elements(3);

        // let archival_mmr = ArchivalMmr::<Hasher>::new(leaf_hashes.clone());
        let archival_mmr = mock::get_ammr_from_digests(leaf_hashes.clone()).await;
        let peaks = archival_mmr.peaks().await;
        let membership_proof = archival_mmr.prove_membership_async(0).await;

        // Verify that the accumulated hash in the verifier is compared against the **correct** hash,
        // not just **any** hash in the peaks list.
        assert!(membership_proof.verify(0, leaf_hashes[0], &peaks, 3,));
        assert!(!membership_proof.verify(2, leaf_hashes[0], &peaks, 3,));

        // verify the same behavior in the accumulator MMR
        let accumulator_mmr = MmrAccumulator::new_from_leafs(leaf_hashes.clone());
        assert!(membership_proof.verify(
            0,
            leaf_hashes[0],
            &accumulator_mmr.peaks(),
            accumulator_mmr.num_leafs()
        ));
        assert!(!membership_proof.verify(
            2,
            leaf_hashes[0],
            &accumulator_mmr.peaks(),
            accumulator_mmr.num_leafs()
        ));
    }

    #[apply(shared_tokio_runtime)]
    async fn mutate_leaf_archival_test() {
        type H = Tip5;

        // Create ArchivalMmr

        let leaf_count = 3;
        let leaf_hashes: Vec<Digest> = random_elements(leaf_count);
        let mut archival_mmr = mock::get_ammr_from_digests(leaf_hashes.clone()).await;

        let leaf_index: u64 = 2;
        let old_peaks = archival_mmr.peaks().await;
        let mp1 = archival_mmr.prove_membership_async(leaf_index).await;

        // Verify single leaf

        let mp1_verifies = mp1.verify(
            leaf_index,
            leaf_hashes[leaf_index as usize],
            &old_peaks,
            leaf_count as u64,
        );
        assert!(mp1_verifies);

        // Create copy of ArchivalMmr, recreate membership proof

        let mut other_archival_mmr: ArchivalMmr<Storage> =
            mock::get_ammr_from_digests(leaf_hashes.clone()).await;

        let mp2 = other_archival_mmr.prove_membership_async(leaf_index).await;

        // Mutate leaf + mutate leaf raw, assert that they're equivalent

        let mutated_leaf = H::hash(&BFieldElement::new(10000));
        other_archival_mmr
            .mutate_leaf(leaf_index, mutated_leaf)
            .await;

        let new_peaks_one = other_archival_mmr.peaks().await;
        archival_mmr.mutate_leaf(leaf_index, mutated_leaf).await;

        let new_peaks_two = archival_mmr.peaks().await;
        assert_eq!(
            new_peaks_two, new_peaks_one,
            "peaks for two update leaf method calls must agree"
        );

        // Verify that peaks have changed as expected

        let expected_num_peaks = 2;
        assert_ne!(old_peaks[1], new_peaks_two[1]);
        assert_eq!(old_peaks[0], new_peaks_two[0]);
        assert_eq!(expected_num_peaks, new_peaks_two.len());
        assert_eq!(expected_num_peaks, old_peaks.len());

        let mp2_verifies_non_mutated_leaf = mp2.verify(
            leaf_index,
            leaf_hashes[leaf_index as usize],
            &new_peaks_two,
            leaf_count as u64,
        );
        assert!(!mp2_verifies_non_mutated_leaf);

        let mp2_verifies_mutated_leaf =
            mp2.verify(leaf_index, mutated_leaf, &new_peaks_two, leaf_count as u64);
        assert!(mp2_verifies_mutated_leaf);

        // Create a new archival MMR with the same leaf hashes as in the
        // modified MMR, and verify that the two MMRs are equivalent

        let archival_mmr_new: ArchivalMmr<Storage> = mock::get_ammr_from_digests(leaf_hashes).await;
        assert_eq!(
            archival_mmr.digests.len().await,
            archival_mmr_new.digests.len().await
        );

        for i in 0..leaf_count {
            assert_eq!(
                archival_mmr.digests.get(i as u64).await,
                archival_mmr_new.digests.get(i as u64).await
            );
        }
    }

    async fn bag_peaks_gen() {
        // Verify that archival and accumulator MMR produce the same root
        let leaf_hashes_tip5: Vec<Digest> = random_elements(3);
        let archival_mmr_small: ArchivalMmr<Storage> =
            mock::get_ammr_from_digests(leaf_hashes_tip5.clone()).await;
        let accumulator_mmr_small = MmrAccumulator::new_from_leafs(leaf_hashes_tip5);
        assert_eq!(
            archival_mmr_small.bag_peaks().await,
            accumulator_mmr_small.bag_peaks()
        );
        assert!(!accumulator_mmr_small
            .peaks()
            .iter()
            .any(|peak| *peak == accumulator_mmr_small.bag_peaks()));
    }

    #[apply(shared_tokio_runtime)]
    async fn bag_peaks_tip5_test() {
        bag_peaks_gen().await;
    }

    #[apply(shared_tokio_runtime)]
    async fn compare_batch_and_individual_leaf_mutation() {
        use rand::prelude::IndexedRandom;

        let mut rng = rand::rng();
        for size in 0..25 {
            let init_digests = random_elements(size);
            let mut archival_batch_mut: ArchivalMmr<Storage> =
                mock::get_ammr_from_digests(init_digests.clone()).await;
            let mut archival_individual_mut = mock::get_ammr_from_digests(init_digests).await;

            for max_mutation_count in 0..size {
                let all_indices = (0..size as u64).collect_vec();
                let mutated_indices = (0..max_mutation_count)
                    .map(|_| *all_indices.choose(&mut rng).unwrap())
                    .collect_vec();
                let mutated_indices = mutated_indices.into_iter().unique().collect_vec();
                let new_leafs = random_elements(max_mutation_count);
                let mutation_data = mutated_indices
                    .clone()
                    .into_iter()
                    .zip(new_leafs.into_iter())
                    .collect_vec();

                archival_batch_mut
                    .batch_mutate_leaf_and_update_mps(&mut [], mutation_data.clone())
                    .await;

                for (index, new_leaf) in mutation_data {
                    archival_individual_mut.mutate_leaf(index, new_leaf).await;
                }

                assert_eq!(
                    archival_batch_mut.peaks().await,
                    archival_individual_mut.peaks().await
                );
            }
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn accumulator_mmr_mutate_leaf_test() {
        // Verify that updating leafs in archival and in accumulator MMR results in the same peaks
        // and verify that updating all leafs in an MMR results in the expected MMR
        for size in 1..150 {
            let new_leaf: Digest = random();
            let leaf_hashes_tip5: Vec<Digest> = random_elements(size);

            let mut acc = MmrAccumulator::new_from_leafs(leaf_hashes_tip5.clone());
            let mut archival: ArchivalMmr<Storage> =
                mock::get_ammr_from_digests(leaf_hashes_tip5.clone()).await;
            let archival_end_state: ArchivalMmr<Storage> =
                mock::get_ammr_from_digests(vec![new_leaf; size]).await;
            for i in 0..size {
                let i = i as u64;
                let mp = archival.prove_membership_async(i).await;
                acc.mutate_leaf(LeafMutation::new(i, new_leaf, mp));
                archival.mutate_leaf(i, new_leaf).await;
                let new_archival_peaks = archival.peaks().await;
                assert_eq!(new_archival_peaks, acc.peaks());
            }

            assert_eq!(archival_end_state.peaks().await, acc.peaks());
        }
    }

    #[proptest(async = "tokio")]
    async fn prove_membership_relative_to_smaller_mmr_test(
        #[strategy(1u64..200)] _num_leafs: u64,
        #[strategy(vec(arb(), #_num_leafs as usize))] digests: Vec<Digest>,
        #[strategy(1u64..=#_num_leafs)] reduced_num_leafs: u64,
        #[strategy(0u64..#reduced_num_leafs)] leaf_index: u64,
    ) {
        let leaf = digests[leaf_index as usize];
        let smaller_mmr =
            MmrAccumulator::new_from_leafs(digests[0..reduced_num_leafs as usize].to_vec());
        let ammr = mock::get_ammr_from_digests(digests).await;
        let mp = ammr
            .prove_membership_relative_to_smaller_mmr(leaf_index, reduced_num_leafs)
            .await;
        prop_assert!(mp.verify(
            leaf_index,
            leaf,
            &smaller_mmr.peaks(),
            smaller_mmr.num_leafs()
        ));
    }

    #[apply(shared_tokio_runtime)]
    async fn mmr_prove_verify_leaf_mutation_test() {
        for size in 1u64..150 {
            let new_leaf: Digest = random();
            let bad_leaf: Digest = random();
            let leaf_hashes_tip5: Vec<Digest> = random_elements(size as usize);
            let mut acc = MmrAccumulator::new_from_leafs(leaf_hashes_tip5.clone());
            let mut archival: ArchivalMmr<Storage> =
                mock::get_ammr_from_digests(leaf_hashes_tip5.clone()).await;
            let archival_end_state: ArchivalMmr<Storage> =
                mock::get_ammr_from_digests(vec![new_leaf; size as usize]).await;
            for i in 0..size {
                let peaks_before_update = archival.peaks().await;
                let mp = archival.prove_membership_async(i).await;
                assert_eq!(
                    mp,
                    archival
                        .prove_membership_relative_to_smaller_mmr(i, size)
                        .await,
                    "Two ways of getting MMRMPs must agree"
                );

                assert_eq!(archival.peaks().await, peaks_before_update);

                // Verify the update operation using the batch verifier
                archival.mutate_leaf(i, new_leaf).await;
                assert!(
                    acc.verify_batch_update(
                        &archival.peaks().await,
                        &[],
                        vec![LeafMutation::new(i, new_leaf, mp.clone())]
                    ),
                    "Valid batch update parameters must succeed"
                );
                assert!(
                    !acc.verify_batch_update(
                        &archival.peaks().await,
                        &[],
                        vec![LeafMutation::new(i, bad_leaf, mp.clone())]
                    ),
                    "Invalid batch update parameters must fail"
                );

                acc.mutate_leaf(LeafMutation::new(i, new_leaf, mp));
                let new_archival_peaks = archival.peaks().await;
                assert_eq!(new_archival_peaks, acc.peaks());
                assert_eq!(size, archival.num_leafs().await);
                assert_eq!(size, acc.num_leafs());
            }
            assert_eq!(archival_end_state.peaks().await, acc.peaks());
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn mmr_append_test() {
        // Verify that building an MMR iteratively or in *one* function call results in the same MMR
        for size in 1..260 {
            let leaf_hashes_tip5: Vec<Digest> = random_elements(size);
            let mut archival_iterative: ArchivalMmr<Storage> =
                mock::get_ammr_from_digests(vec![]).await;
            let archival_batch: ArchivalMmr<Storage> =
                mock::get_ammr_from_digests(leaf_hashes_tip5.clone()).await;
            let mut accumulator_iterative = MmrAccumulator::new_from_leafs(vec![]);
            let accumulator_batch = MmrAccumulator::new_from_leafs(leaf_hashes_tip5.clone());
            for leaf_hash in leaf_hashes_tip5.clone() {
                let leaf_index = archival_iterative.num_leafs().await;
                let archival_membership_proof = archival_iterative.append(leaf_hash).await;
                let accumulator_membership_proof = accumulator_iterative.append(leaf_hash);

                // Verify membership proofs returned from the append operation
                assert_eq!(
                    accumulator_membership_proof, archival_membership_proof,
                    "membership proofs from append operation must agree"
                );
                assert!(archival_membership_proof.verify(
                    leaf_index,
                    leaf_hash,
                    &archival_iterative.peaks().await,
                    archival_iterative.num_leafs().await
                ));

                // Verify that membership proofs are the same as generating them from an archival MMR
                let archival_membership_proof_direct = archival_iterative
                    .prove_membership_async(leaf_index as u64)
                    .await;
                assert_eq!(archival_membership_proof_direct, archival_membership_proof);
            }

            // Verify that the MMRs built iteratively from `append` and in *one* batch are the same
            assert_eq!(accumulator_batch.peaks(), accumulator_iterative.peaks());
            assert_eq!(
                accumulator_batch.num_leafs(),
                accumulator_iterative.num_leafs()
            );
            assert_eq!(size as u64, accumulator_iterative.num_leafs());
            assert_eq!(
                archival_iterative.peaks().await,
                accumulator_iterative.peaks()
            );

            // Run a batch-append verification on the entire mutation of the MMR and verify that it succeeds
            let empty_accumulator = MmrAccumulator::new_from_leafs(vec![]);
            assert!(empty_accumulator.verify_batch_update(
                &archival_batch.peaks().await,
                &leaf_hashes_tip5,
                vec![],
            ));
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn one_input_mmr_test() {
        type H = Tip5;

        let input_hash = H::hash(&BFieldElement::new(14));
        let new_input_hash = H::hash(&BFieldElement::new(201));
        let mut mmr: ArchivalMmr<Storage> = mock::get_ammr_from_digests(vec![input_hash]).await;
        let original_mmr: ArchivalMmr<Storage> =
            mock::get_ammr_from_digests(vec![input_hash]).await;
        let mmr_after_append: ArchivalMmr<Storage> =
            mock::get_ammr_from_digests(vec![input_hash, new_input_hash]).await;
        assert_eq!(1, mmr.num_leafs().await);
        assert_eq!(1, mmr.count_nodes().await);

        let original_peaks: Vec<Digest> = mmr.peaks().await;
        assert_eq!(1, original_peaks.len());

        {
            let leaf_index = 0;
            let peaks = mmr.peaks().await;
            let membership_proof = mmr.prove_membership_async(leaf_index).await;
            let valid_res = membership_proof.verify(leaf_index, input_hash, &peaks, 1);
            assert!(valid_res);
        }

        mmr.append(new_input_hash).await;
        assert_eq!(2, mmr.num_leafs().await);
        assert_eq!(3, mmr.count_nodes().await);

        let new_peaks = mmr.peaks().await;
        assert_eq!(1, new_peaks.len());

        assert!(
            original_mmr
                .verify_batch_update(&new_peaks, &[new_input_hash], &[])
                .await,
            "verify batch update must succeed for a single append"
        );

        // let mmr_after_append = mmr.clone();
        let new_leaf: Digest = H::hash(&BFieldElement::new(987223));

        // When verifying the batch update with two consecutive leaf mutations, we must get the
        // membership proofs prior to all mutations. This is because the `verify_batch_update` method
        // updates the membership proofs internally to account for the mutations.
        let leaf_mutation_data =
            futures::future::join_all((0..2).map(|i| mmr_after_append.prove_membership_async(i)))
                .await
                .into_iter()
                .enumerate()
                .map(|(i, p)| (i as u64, new_leaf, p))
                .collect_vec();
        let leaf_mutations = leaf_mutation_data
            .iter()
            .map(|(leaf_index, leaf_after_modification, membership_proof)| {
                LeafMutation::new(
                    *leaf_index,
                    *leaf_after_modification,
                    membership_proof.clone(),
                )
            })
            .collect_vec();

        for leaf_index in [0u64, 1] {
            mmr.mutate_leaf(leaf_index, new_leaf).await;
            assert_eq!(
                new_leaf,
                mmr.get_leaf_async(leaf_index).await,
                "fetched leaf must match what we put in"
            );
            assert_eq!(
                new_leaf,
                mmr.try_get_leaf(leaf_index).await.unwrap(),
                "fetched leaf through try-getter must match what we put in"
            );
        }

        assert!(
            mmr_after_append
                .verify_batch_update(&mmr.peaks().await, &[], &leaf_mutations)
                .await,
            "The batch update of two leaf mutations must verify"
        );
    }

    #[apply(shared_tokio_runtime)]
    async fn two_input_mmr_test() {
        let num_leaves: u64 = 3;
        let input_digests: Vec<Digest> = random_elements(num_leaves as usize);

        let mut mmr: ArchivalMmr<Storage> =
            mock::get_ammr_from_digests(input_digests.clone()).await;
        assert_eq!(num_leaves, mmr.num_leafs().await);
        assert_eq!(1 + num_leaves, mmr.count_nodes().await);

        let original_peaks: Vec<Digest> = mmr.peaks().await;
        let expected_peaks = 2;
        assert_eq!(expected_peaks, original_peaks.len());

        {
            let mut leaf_index = 0u64;
            let input_digest = input_digests[leaf_index as usize];
            let peaks = mmr.peaks().await;
            let membership_proof = mmr.prove_membership_async(leaf_index).await;

            let mp_verifies_1 =
                membership_proof.verify(leaf_index, input_digest, &peaks, num_leaves);
            assert!(mp_verifies_1);

            // Negative test for verify membership
            leaf_index += 1;

            let mp_verifies_2 =
                membership_proof.verify(leaf_index, input_digest, &peaks, num_leaves);
            assert!(!mp_verifies_2);
        }

        let new_leaf_hash: Digest = Tip5::hash(&BFieldElement::new(201));
        mmr.append(new_leaf_hash).await;

        let expected_num_leaves = 1 + num_leaves;
        assert_eq!(expected_num_leaves, mmr.num_leafs().await);

        let expected_node_count = 3 + expected_num_leaves;
        assert_eq!(expected_node_count, mmr.count_nodes().await);

        for leaf_index in 0..num_leaves {
            let new_leaf: Digest = Tip5::hash(&BFieldElement::new(987223));
            mmr.mutate_leaf(leaf_index, new_leaf).await;
            assert_eq!(new_leaf, mmr.get_leaf_async(leaf_index).await);
            assert_eq!(new_leaf, mmr.try_get_leaf(leaf_index).await.unwrap());
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn variable_size_tip5_mmr_test() {
        type H = Tip5;

        let leaf_counts: Vec<u64> = (1..34).collect();
        let node_counts: Vec<u64> = vec![
            1, 3, 4, 7, 8, 10, 11, 15, 16, 18, 19, 22, 23, 25, 26, 31, 32, 34, 35, 38, 39, 41, 42,
            46, 47, 49, 50, 53, 54, 56, 57, 63, 64,
        ];
        let peak_counts: Vec<u64> = vec![
            1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4,
            4, 5, 1, 2,
        ];

        for (leaf_count, node_count, peak_count) in izip!(leaf_counts, node_counts, peak_counts) {
            let input_hashes: Vec<Digest> = random_elements(leaf_count as usize);
            let mmr: ArchivalMmr<Storage> = mock::get_ammr_from_digests(input_hashes.clone()).await;

            assert_eq!(leaf_count, mmr.num_leafs().await);
            assert_eq!(node_count, mmr.count_nodes().await);

            let original_peaks = mmr.peaks().await;
            let actual_peak_count = original_peaks.len() as u64;
            assert_eq!(peak_count, actual_peak_count);

            // Verify that MMR root from odd number of digests and MMR bagged peaks agree
            let ammr_root = mmr.bag_peaks().await;
            let mmra_root = MmrAccumulator::new_from_leafs(input_hashes.clone()).bag_peaks();
            assert_eq!(ammr_root, mmra_root);

            // Get an authentication path for **all** values in MMR,
            // verify that it is valid
            for index in 0..leaf_count {
                let membership_proof = mmr.prove_membership_async(index).await;
                let valid_res = membership_proof.verify(
                    index,
                    input_hashes[index as usize],
                    &original_peaks,
                    leaf_count,
                );

                assert!(valid_res);
            }

            // Make a new MMR where we append with a value and run the verify_append
            let mut mmr = mmr;
            let new_leaf_hash = H::hash(&BFieldElement::new(201));
            let li = mmr.num_leafs().await;
            let mp = mmr.append(new_leaf_hash).await;
            assert!(
                mp.verify(li, new_leaf_hash, &mmr.peaks().await, leaf_count + 1),
                "Returned membership proof from append must verify"
            );
            assert_ne!(
                original_peaks,
                mmr.peaks().await,
                "peaks must change when appending"
            );
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn remove_last_leaf_test() {
        let input_digests: Vec<Digest> = random_elements(12);
        let mut mmr: ArchivalMmr<Storage> =
            mock::get_ammr_from_digests(input_digests.clone()).await;
        assert_eq!(22, mmr.count_nodes().await);
        assert_eq!(Some(input_digests[11]), mmr.get_latest_leaf().await);
        assert_eq!(Some(input_digests[11]), mmr.remove_last_leaf_async().await);
        assert_eq!(19, mmr.count_nodes().await);
        assert_eq!(Some(input_digests[10]), mmr.get_latest_leaf().await);
        assert_eq!(Some(input_digests[10]), mmr.remove_last_leaf_async().await);
        assert_eq!(18, mmr.count_nodes().await);
        assert_eq!(Some(input_digests[9]), mmr.remove_last_leaf_async().await);
        assert_eq!(16, mmr.count_nodes().await);
        assert_eq!(Some(input_digests[8]), mmr.remove_last_leaf_async().await);
        assert_eq!(15, mmr.count_nodes().await);
        assert_eq!(Some(input_digests[7]), mmr.remove_last_leaf_async().await);
        assert_eq!(11, mmr.count_nodes().await);
        assert_eq!(Some(input_digests[6]), mmr.remove_last_leaf_async().await);
        assert_eq!(10, mmr.count_nodes().await);
        assert_eq!(Some(input_digests[5]), mmr.remove_last_leaf_async().await);
        assert_eq!(8, mmr.count_nodes().await);
        assert_eq!(Some(input_digests[4]), mmr.remove_last_leaf_async().await);
        assert_eq!(7, mmr.count_nodes().await);
        assert_eq!(Some(input_digests[3]), mmr.remove_last_leaf_async().await);
        assert_eq!(4, mmr.count_nodes().await);
        assert_eq!(Some(input_digests[2]), mmr.remove_last_leaf_async().await);
        assert_eq!(3, mmr.count_nodes().await);
        assert_eq!(Some(input_digests[1]), mmr.remove_last_leaf_async().await);
        assert_eq!(1, mmr.count_nodes().await);
        assert_eq!(Some(input_digests[0]), mmr.get_latest_leaf().await);
        assert_eq!(Some(input_digests[0]), mmr.remove_last_leaf_async().await);
        assert_eq!(0, mmr.count_nodes().await);
        assert!(mmr.is_empty().await);
        assert!(mmr.remove_last_leaf_async().await.is_none());
        assert!(mmr.get_latest_leaf().await.is_none());
    }

    #[apply(shared_tokio_runtime)]
    async fn remove_last_leaf_pbt() {
        let small_size: usize = 100;
        let big_size: usize = 350;
        let input_digests_big: Vec<Digest> = random_elements(big_size);
        let input_digests_small: Vec<Digest> = input_digests_big[0..small_size].to_vec();

        let mmr_small: ArchivalMmr<Storage> =
            mock::get_ammr_from_digests(input_digests_small).await;
        let mut mmr_big: ArchivalMmr<Storage> =
            mock::get_ammr_from_digests(input_digests_big).await;

        for _ in 0..(big_size - small_size) {
            mmr_big.remove_last_leaf_async().await;
        }

        assert_eq!(mmr_big.peaks().await, mmr_small.peaks().await);
        assert_eq!(mmr_big.bag_peaks().await, mmr_small.bag_peaks().await);
        assert_eq!(mmr_big.num_leafs().await, mmr_small.num_leafs().await);
        assert_eq!(mmr_big.count_nodes().await, mmr_small.count_nodes().await);
    }

    #[apply(shared_tokio_runtime)]
    async fn variable_size_tip5_mmr_test2() {
        let node_counts: Vec<u64> = vec![
            1, 3, 4, 7, 8, 10, 11, 15, 16, 18, 19, 22, 23, 25, 26, 31, 32, 34, 35, 38, 39, 41, 42,
            46, 47, 49, 50, 53, 54, 56, 57, 63, 64,
        ];
        let peak_counts: Vec<u64> = vec![
            1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4,
            4, 5, 1, 2,
        ];
        let leaf_counts: Vec<usize> = (1..34).collect();
        for (leaf_count, node_count, peak_count) in izip!(leaf_counts, node_counts, peak_counts) {
            let size = leaf_count as u64;
            let input_digests: Vec<Digest> = random_elements(leaf_count);
            let mut mmr: ArchivalMmr<Storage> =
                mock::get_ammr_from_digests(input_digests.clone()).await;
            let mmr_original: ArchivalMmr<Storage> =
                mock::get_ammr_from_digests(input_digests.clone()).await;
            assert_eq!(size, mmr.num_leafs().await);
            assert_eq!(node_count, mmr.count_nodes().await);
            let original_peaks: Vec<Digest> = mmr.peaks().await;
            assert_eq!(peak_count, original_peaks.len() as u64);

            // Verify that MMR root from odd number of digests and MMR bagged peaks agree
            let ammr_root = mmr.bag_peaks().await;
            let mmra_root = MmrAccumulator::new_from_leafs(input_digests.clone()).bag_peaks();
            assert_eq!(ammr_root, mmra_root);

            // Get an authentication path for **all** values in MMR,
            // verify that it is valid
            for leaf_index in 0..size {
                let peaks = mmr.peaks().await;
                let membership_proof = mmr.prove_membership_async(leaf_index).await;
                let valid_res = membership_proof.verify(
                    leaf_index,
                    input_digests[leaf_index as usize],
                    &peaks,
                    size,
                );
                assert!(valid_res);
                let new_leaf: Digest = random();

                // The below verify_modify tests should only fail if `wrong_leaf_index` is
                // different than `leaf_index`.
                let wrong_leaf_index = (leaf_index + 1) % mmr.num_leafs().await;
                assert!(
                    wrong_leaf_index == leaf_index
                        || !membership_proof.verify(wrong_leaf_index, new_leaf, &peaks, size)
                );

                // Modify an element in the MMR and run prove/verify for membership
                let old_leaf = input_digests[leaf_index as usize];
                mmr.mutate_leaf(leaf_index, new_leaf).await;

                let new_peaks = mmr.peaks().await;
                let new_mp = mmr.prove_membership_async(leaf_index).await;
                assert!(new_mp.verify(leaf_index, new_leaf, &new_peaks, size));
                assert!(!new_mp.verify(leaf_index, old_leaf, &new_peaks, size));

                // Return the element to its former value and run prove/verify for membership
                mmr.mutate_leaf(leaf_index, old_leaf).await;
                let old_peaks = mmr.peaks().await;
                let old_mp = mmr.prove_membership_async(leaf_index).await;
                assert!(!old_mp.verify(leaf_index, new_leaf, &old_peaks, size));
                assert!(old_mp.verify(leaf_index, old_leaf, &old_peaks, size));
            }

            // Make a new MMR where we append with a value and run the verify_append
            let new_leaf_hash: Digest = random();
            mmr.append(new_leaf_hash).await;
            assert!(
                mmr_original
                    .verify_batch_update(&mmr.peaks().await, &[new_leaf_hash], &[])
                    .await
            );
        }
    }

    #[proptest(cases = 4, async = "tokio")]
    async fn get_and_try_get_agree(
        #[strategy(0u64..200)] num_leafs: u64,
        #[strategy(vec(arb(), #num_leafs as usize))] digests: Vec<Digest>,
    ) {
        let ammr = mock::get_ammr_from_digests(digests.clone()).await;
        for i in 0..num_leafs {
            prop_assert_eq!(digests[i as usize], ammr.get_leaf_async(i).await);
            prop_assert_eq!(digests[i as usize], ammr.try_get_leaf(i).await.unwrap());
        }

        for i in num_leafs..num_leafs + 10 {
            prop_assert!(ammr.try_get_leaf(i).await.is_none());
        }
    }

    #[cfg(debug_assertions)] // this tests get_leaf_async() use of debug_assert!()
    #[apply(shared_tokio_runtime)]
    #[should_panic(expected = "Leaf index out-of-bounds. Got leaf index 17 but num_leafs was 17")]
    async fn get_panics_when_out_of_bounds() {
        let digests = vec![Digest::default(); 17];
        let ammr = mock::get_ammr_from_digests(digests.clone()).await;
        ammr.get_leaf_async(17).await;
    }

    #[apply(shared_tokio_runtime)]
    async fn leveldb_persist_storage_schema_test() {
        let db = NeptuneLevelDb::open_new_test_database(true, None, None, None)
            .await
            .unwrap();
        let mut storage = SimpleRustyStorage::new(db);
        let ammr0 = storage
            .schema
            .new_vec::<Digest>("ammr-nodes-digests-0")
            .await;
        let mut ammr0: ArchivalMmr<_> = ArchivalMmr::new(ammr0).await;
        let ammr1 = storage
            .schema
            .new_vec::<Digest>("ammr-nodes-digests-1")
            .await;
        let mut ammr1: ArchivalMmr<_> = ArchivalMmr::new(ammr1).await;

        let digest0: Digest = random();
        ammr0.append(digest0).await;

        let digest1: Digest = random();
        ammr1.append(digest1).await;
        assert_eq!(digest0, ammr0.get_leaf_async(0).await);
        assert_eq!(digest1, ammr1.get_leaf_async(0).await);
        storage.persist().await;

        assert_eq!(digest0, ammr0.get_leaf_async(0).await);
        assert_eq!(digest1, ammr1.get_leaf_async(0).await);
    }
}
