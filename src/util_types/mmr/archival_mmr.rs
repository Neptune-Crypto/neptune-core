use crate::database::storage::storage_vec::traits::*;
use crate::prelude::twenty_first;

use twenty_first::shared_math::digest::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use twenty_first::util_types::shared::bag_peaks;

use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;

use itertools::Itertools;

use super::traits::*;
use super::MmrAccumulator;
use twenty_first::util_types::mmr::{
    mmr_membership_proof::MmrMembershipProof, shared_advanced, shared_basic,
};

/// A Merkle Mountain Range is a datastructure for storing a list of hashes.
///
/// Merkle Mountain Ranges only know about hashes. When values are to be associated with
/// MMRs, these values must be stored by the caller, or in a wrapper to this data structure.
pub struct ArchivalMmr<H: AlgebraicHasher, Storage: StorageVec<Digest> + Send + Sync> {
    digests: Storage,
    _hasher: PhantomData<H>,
}

impl<H, Storage> Mmr<H> for ArchivalMmr<H, Storage>
where
    H: AlgebraicHasher + Send + Sync,
    Storage: StorageVec<Digest> + Send + Sync,
{
    /// Calculate the root for the entire MMR
    async fn bag_peaks(&self) -> Digest {
        let peaks: Vec<Digest> = self.get_peaks().await;
        bag_peaks::<H>(&peaks)
    }

    /// Return the digests of the peaks of the MMR
    async fn get_peaks(&self) -> Vec<Digest> {
        let peaks_and_heights = self.get_peaks_with_heights().await;
        peaks_and_heights.into_iter().map(|x| x.0).collect()
    }

    /// Whether the MMR is empty. Note that since indexing starts at
    /// 1, the `digests` contain must always contain at least one
    /// element: a dummy digest.
    async fn is_empty(&self) -> bool {
        self.digests.len().await == 1
    }

    /// Return the number of leaves in the tree
    async fn count_leaves(&self) -> u64 {
        let peaks_and_heights: Vec<(_, u32)> = self.get_peaks_with_heights().await;
        let mut acc = 0;
        for (_, height) in peaks_and_heights {
            acc += 1 << height
        }

        acc
    }

    /// Append an element to the archival MMR, return the membership proof of the newly added leaf.
    /// The membership proof is returned here since the accumulater MMR has no other way of
    /// retrieving a membership proof for a leaf. And the archival and accumulator MMR share
    /// this interface.
    async fn append(&mut self, new_leaf: Digest) -> MmrMembershipProof<H> {
        let node_index = self.digests.len().await;
        let leaf_index = shared_advanced::node_index_to_leaf_index(node_index).unwrap();
        self.append_raw(new_leaf).await;
        self.prove_membership(leaf_index).await.0
    }

    /// Mutate an existing leaf. It is the caller's responsibility that the
    /// membership proof is valid. If the membership proof is wrong, the MMR
    /// will end up in a broken state.
    async fn mutate_leaf(
        &mut self,
        old_membership_proof: &MmrMembershipProof<H>,
        new_leaf: Digest,
    ) {
        // Sanity check
        let real_membership_proof: MmrMembershipProof<H> = self
            .prove_membership(old_membership_proof.leaf_index)
            .await
            .0;
        assert_eq!(
            real_membership_proof.authentication_path, old_membership_proof.authentication_path,
            "membership proof argument list must match internally calculated"
        );

        self.mutate_leaf_raw(real_membership_proof.leaf_index, new_leaf.to_owned())
            .await
    }

    async fn batch_mutate_leaf_and_update_mps(
        &mut self,
        membership_proofs: &mut [&mut MmrMembershipProof<H>],
        mutation_data: Vec<(MmrMembershipProof<H>, Digest)>,
    ) -> Vec<usize> {
        assert!(
            mutation_data.iter().map(|md| md.0.leaf_index).all_unique(),
            "Duplicated leaves are not allowed in membership proof updater"
        );

        for (mp, digest) in mutation_data.iter() {
            self.mutate_leaf_raw(mp.leaf_index, *digest).await;
        }

        let mut modified_mps: Vec<usize> = vec![];
        for (i, mp) in membership_proofs.iter_mut().enumerate() {
            let new_mp = self.prove_membership(mp.leaf_index).await.0;
            if new_mp != **mp {
                modified_mps.push(i);
            }

            **mp = new_mp
        }

        modified_mps
    }

    async fn verify_batch_update(
        &self,
        new_peaks: &[Digest],
        appended_leafs: &[Digest],
        leaf_mutations: &[(Digest, MmrMembershipProof<H>)],
    ) -> bool {
        let accumulator: MmrAccumulator<H> = self.to_accumulator().await;
        accumulator
            .verify_batch_update(new_peaks, appended_leafs, leaf_mutations)
            .await
    }

    async fn to_accumulator(&self) -> MmrAccumulator<H> {
        MmrAccumulator::init(self.get_peaks().await, self.count_leaves().await)
    }
}

impl<H: AlgebraicHasher, Storage: StorageVec<Digest> + Send + Sync> ArchivalMmr<H, Storage> {
    /// Create a new archival MMR, or restore one from a database.
    pub async fn new(pv: Storage) -> Self {
        let mut ret = Self {
            digests: pv,
            _hasher: PhantomData,
        };
        ret.fix_dummy().await;
        ret
    }

    /// Inserts a dummy digest into the `digests` container. Due to
    /// 1-indexation, this structure must always contain one element
    /// (even if it is never used). Due to the persistence layer,
    /// this data structure can be set to the default vector, which
    /// is the empty vector. This method fixes that.
    pub async fn fix_dummy(&mut self) {
        if self.digests.len().await == 0 {
            self.digests.push(Digest::default()).await;
        }
    }

    /// Get a leaf from the MMR, will panic if index is out of range
    pub async fn get_leaf(&self, leaf_index: u64) -> Digest {
        let node_index = shared_advanced::leaf_index_to_node_index(leaf_index);
        self.digests.get(node_index).await
    }

    /// Update a hash in the existing archival MMR
    pub async fn mutate_leaf_raw(&mut self, leaf_index: u64, new_leaf: Digest) {
        // 1. change the leaf value
        let mut node_index = shared_advanced::leaf_index_to_node_index(leaf_index);
        self.digests.set(node_index, new_leaf).await;

        // 2. Calculate hash changes for all parents
        let mut parent_index = shared_advanced::parent(node_index);
        let mut acc_hash = new_leaf;

        // While parent exists in MMR, update parent
        while parent_index < self.digests.len().await {
            let (right_lineage_count, height) =
                shared_advanced::right_lineage_length_and_own_height(node_index);
            acc_hash = if right_lineage_count != 0 {
                // node is right child
                H::hash_pair(
                    self.digests
                        .get(shared_advanced::left_sibling(node_index, height))
                        .await,
                    acc_hash,
                )
            } else {
                // node is left child
                H::hash_pair(
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

    /// Return (membership_proof, peaks)
    pub async fn prove_membership(&self, leaf_index: u64) -> (MmrMembershipProof<H>, Vec<Digest>) {
        // A proof consists of an authentication path
        // and a list of peaks
        assert!(
            leaf_index < self.count_leaves().await,
            "Cannot prove membership of leaf outside of range. Got leaf_index {leaf_index}. Leaf count is {}", self.count_leaves().await
        );

        // Find out how long the authentication path is
        let node_index = shared_advanced::leaf_index_to_node_index(leaf_index);
        let mut top_height: i32 = -1;
        let mut parent_index = node_index;
        while parent_index < self.digests.len().await {
            parent_index = shared_advanced::parent(parent_index);
            top_height += 1;
        }

        // Build the authentication path
        let mut authentication_path: Vec<Digest> = vec![];
        let mut index = node_index;
        let (mut right_ancestor_count, mut index_height): (u32, u32) =
            shared_advanced::right_lineage_length_and_own_height(index);
        while index_height < top_height as u32 {
            if right_ancestor_count != 0 {
                // index is right child
                let left_sibling_index = shared_advanced::left_sibling(index, index_height);
                authentication_path.push(self.digests.get(left_sibling_index).await);

                // parent of right child is index + 1
                index += 1;
            } else {
                // index is left child
                let right_sibling_index = shared_advanced::right_sibling(index, index_height);
                authentication_path.push(self.digests.get(right_sibling_index).await);

                // parent of left child:
                index += 1 << (index_height + 1);
            }
            let next_index_info = shared_advanced::right_lineage_length_and_own_height(index);
            right_ancestor_count = next_index_info.0;
            index_height = next_index_info.1;
        }

        let peaks: Vec<Digest> = self
            .get_peaks_with_heights()
            .await
            .iter()
            .map(|x| x.0)
            .collect();

        let membership_proof = MmrMembershipProof::new(leaf_index, authentication_path);

        (membership_proof, peaks)
    }

    /// Return a list of tuples (peaks, height)
    pub async fn get_peaks_with_heights(&self) -> Vec<(Digest, u32)> {
        if self.is_empty().await {
            return vec![];
        }

        // 1. Find top peak
        // 2. Jump to right sibling (will not be included)
        // 3. Take left child of sibling, continue until a node in tree is found
        // 4. Once new node is found, jump to right sibling (will not be included)
        // 5. Take left child of sibling, continue until a node in tree is found
        let mut peaks_and_heights: Vec<(Digest, u32)> = vec![];
        let (mut top_peak, mut top_height) =
            shared_advanced::leftmost_ancestor(self.digests.len().await - 1);
        if top_peak > self.digests.len().await - 1 {
            top_peak = shared_basic::left_child(top_peak, top_height);
            top_height -= 1;
        }

        peaks_and_heights.push((self.digests.get(top_peak).await, top_height));
        let mut height = top_height;
        let mut candidate = shared_advanced::right_sibling(top_peak, height);
        'outer: while height > 0 {
            '_inner: while candidate > self.digests.len().await && height > 0 {
                candidate = shared_basic::left_child(candidate, height);
                height -= 1;
                if candidate < self.digests.len().await {
                    peaks_and_heights.push((self.digests.get(candidate).await, height));
                    candidate = shared_advanced::right_sibling(candidate, height);
                    continue 'outer;
                }
            }
        }

        peaks_and_heights
    }

    /// Append an element to the archival MMR
    pub fn append_raw(
        &mut self,
        new_leaf: Digest,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let node_index = self.digests.len().await;
            self.digests.push(new_leaf).await;
            let (right_parent_count, own_height) =
                shared_advanced::right_lineage_length_and_own_height(node_index);

            // This function could be rewritten with a while-loop instead of being recursive.
            if right_parent_count != 0 {
                let left_sibling_hash = self
                    .digests
                    .get(shared_advanced::left_sibling(node_index, own_height))
                    .await;
                let parent_hash: Digest = H::hash_pair(left_sibling_hash, new_leaf);
                self.append_raw(parent_hash).await;
            }
        })
    }

    /// Remove the last leaf from the archival MMR
    pub async fn remove_last_leaf(&mut self) -> Option<Digest> {
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
}

#[cfg(test)]
pub(crate) mod mmr_test {

    use super::*;

    use itertools::*;
    use rand::random;
    use test_strategy::proptest;

    use crate::database::storage::storage_schema::traits::*;
    use crate::database::storage::storage_schema::SimpleRustyStorage;
    use crate::database::storage::storage_vec::OrdinaryVec;
    use crate::database::NeptuneLevelDb;
    use crate::util_types::mmr::MmrAccumulator;
    use twenty_first::shared_math::b_field_element::BFieldElement;
    use twenty_first::shared_math::other::*;
    use twenty_first::shared_math::tip5::Tip5;
    use twenty_first::util_types::merkle_tree::*;
    use twenty_first::util_types::merkle_tree_maker::MerkleTreeMaker;
    use twenty_first::util_types::mmr::shared_advanced::get_peak_heights_and_peak_node_indices;

    type Storage = OrdinaryVec<Digest>;

    pub(crate) mod mock {
        use super::*;

        /// Return an empty ArchivalMmR for testing purposes.
        /// Does *not* have a unique ID, so you can't expect multiple of these
        /// instances to behave independently unless you understand the
        /// underlying data structure.
        pub async fn get_empty_ammr<H: AlgebraicHasher>() -> ArchivalMmr<H, Storage> {
            let pv: Storage = Default::default();
            ArchivalMmr::new(pv).await
        }

        pub async fn get_ammr_from_digests<H>(digests: Vec<Digest>) -> ArchivalMmr<H, Storage>
        where
            H: AlgebraicHasher,
        {
            let mut ammr = get_empty_ammr().await;
            for digest in digests {
                ammr.append_raw(digest).await;
            }
            ammr
        }
    }

    mod test_tree {
        use super::*;
        use proptest_arbitrary_interop::arb;

        /// Test helper to deduplicate generation of Merkle trees.
        #[derive(Debug, Clone, test_strategy::Arbitrary)]
        pub(crate) struct MerkleTreeToTest {
            #[strategy(arb())]
            pub tree: MerkleTree<Tip5>,
        }
    }

    impl<H: AlgebraicHasher, Storage: StorageVec<Digest> + Send + Sync> ArchivalMmr<H, Storage> {
        /// Return the number of nodes in all the trees in the MMR
        async fn count_nodes(&mut self) -> u64 {
            self.digests.len().await - 1
        }
    }

    /// Calculate a Merkle root from a list of digests of arbitrary length.
    pub fn root_from_arbitrary_number_of_digests<H: AlgebraicHasher>(digests: &[Digest]) -> Digest {
        let mut trees = vec![];
        let mut num_processed_digests = 0;
        for tree_height in indices_of_set_bits(digests.len() as u64) {
            let num_leaves_in_tree = 1 << tree_height;
            let leaf_digests =
                &digests[num_processed_digests..num_processed_digests + num_leaves_in_tree];
            let tree: MerkleTree<H> = CpuParallel::from_digests(leaf_digests).unwrap();
            num_processed_digests += num_leaves_in_tree;
            trees.push(tree);
        }
        let roots = trees.iter().map(|t| t.root()).collect_vec();
        bag_peaks::<H>(&roots)
    }

    /// A block can contain an empty list of addition or removal records.
    #[test]
    fn computing_mmr_root_for_no_leaves_produces_some_digest() {
        root_from_arbitrary_number_of_digests::<Tip5>(&[]);
    }

    #[proptest(cases = 30)]
    fn mmr_root_of_arbitrary_number_of_leaves_is_merkle_root_when_number_of_leaves_is_a_power_of_two(
        test_tree: test_tree::MerkleTreeToTest,
    ) {
        let root = root_from_arbitrary_number_of_digests::<Tip5>(test_tree.tree.leaves());
        assert_eq!(test_tree.tree.root(), root);
    }

    #[tokio::test]
    async fn empty_mmr_behavior_test() {
        type H = blake3::Hasher;

        let mut archival_mmr: ArchivalMmr<H, Storage> = mock::get_empty_ammr().await;
        let mut accumulator_mmr: MmrAccumulator<H> = MmrAccumulator::<H>::default();

        assert_eq!(0, archival_mmr.count_leaves().await);
        assert_eq!(0, accumulator_mmr.count_leaves().await);
        assert_eq!(
            archival_mmr.get_peaks().await,
            accumulator_mmr.get_peaks().await
        );
        assert_eq!(Vec::<Digest>::new(), accumulator_mmr.get_peaks().await);
        assert_eq!(
            archival_mmr.bag_peaks().await,
            accumulator_mmr.bag_peaks().await
        );
        assert_eq!(
            archival_mmr.bag_peaks().await,
            root_from_arbitrary_number_of_digests::<H>(&[]),
            "Bagged peaks for empty MMR must agree with MT root finder"
        );
        assert_eq!(0, archival_mmr.count_nodes().await);
        assert!(accumulator_mmr.is_empty().await);
        assert!(archival_mmr.is_empty().await);

        // Test behavior of appending to an empty MMR
        let new_leaf = random();

        let mut archival_mmr_appended = mock::get_empty_ammr().await;
        {
            let archival_membership_proof = archival_mmr_appended.append(new_leaf).await;

            // Verify that the MMR update can be validated
            assert!(
                archival_mmr
                    .verify_batch_update(&archival_mmr_appended.get_peaks().await, &[new_leaf], &[])
                    .await
            );

            // Verify that failing MMR update for empty MMR fails gracefully
            assert!(
                !archival_mmr
                    .verify_batch_update(
                        &archival_mmr_appended.get_peaks().await,
                        &[],
                        &[(new_leaf, archival_membership_proof)]
                    )
                    .await
            );
        }

        // Make the append and verify that the new peaks match the one from the proofs
        let archival_membership_proof = archival_mmr.append(new_leaf).await;
        let accumulator_membership_proof = accumulator_mmr.append(new_leaf).await;
        assert_eq!(
            archival_mmr.get_peaks().await,
            archival_mmr_appended.get_peaks().await
        );
        assert_eq!(
            accumulator_mmr.get_peaks().await,
            archival_mmr_appended.get_peaks().await
        );

        // Verify that the appended value matches the one stored in the archival MMR
        assert_eq!(new_leaf, archival_mmr.get_leaf(0).await);

        // Verify that the membership proofs for the inserted leafs are valid and that they agree
        assert_eq!(
            archival_membership_proof, accumulator_membership_proof,
            "accumulator and archival membership proofs must agree"
        );
        assert!(
            archival_membership_proof
                .verify(
                    &archival_mmr.get_peaks().await,
                    new_leaf,
                    archival_mmr.count_leaves().await,
                )
                .0,
            "membership proof from arhival MMR must validate"
        );
    }

    #[tokio::test]
    async fn verify_against_correct_peak_test() {
        type H = blake3::Hasher;

        // This test addresses a bug that was discovered late in the development process
        // where it was possible to fake a verification proof by providing a valid leaf
        // and authentication path but lying about the data index. This error occurred
        // because the derived hash was compared against all of the peaks to find a match
        // and it wasn't verified that the accumulated hash matched the *correct* peak.
        // This error was fixed and this test fails without that fix.
        let leaf_hashes: Vec<Digest> = random_elements(3);

        // let archival_mmr = ArchivalMmr::<Hasher>::new(leaf_hashes.clone());
        let archival_mmr = mock::get_ammr_from_digests::<H>(leaf_hashes.clone()).await;
        let (mut membership_proof, peaks): (MmrMembershipProof<H>, Vec<Digest>) =
            archival_mmr.prove_membership(0).await;

        // Verify that the accumulated hash in the verifier is compared against the **correct** hash,
        // not just **any** hash in the peaks list.
        assert!(membership_proof.verify(&peaks, leaf_hashes[0], 3,).0);
        membership_proof.leaf_index = 2;
        assert!(!membership_proof.verify(&peaks, leaf_hashes[0], 3,).0);
        membership_proof.leaf_index = 0;

        // verify the same behavior in the accumulator MMR
        let accumulator_mmr = MmrAccumulator::<H>::new(leaf_hashes.clone()).await;
        assert!(
            membership_proof
                .verify(
                    &accumulator_mmr.get_peaks().await,
                    leaf_hashes[0],
                    accumulator_mmr.count_leaves().await
                )
                .0
        );
        membership_proof.leaf_index = 2;
        assert!(
            !membership_proof
                .verify(
                    &accumulator_mmr.get_peaks().await,
                    leaf_hashes[0],
                    accumulator_mmr.count_leaves().await,
                )
                .0
        );
    }

    #[tokio::test]
    async fn mutate_leaf_archival_test() {
        type H = Tip5;

        // Create ArchivalMmr

        let leaf_count = 3;
        let leaf_hashes: Vec<Digest> = random_elements(leaf_count);
        let mut archival_mmr = mock::get_ammr_from_digests::<H>(leaf_hashes.clone()).await;

        let leaf_index: usize = 2;
        let (mp1, old_peaks): (MmrMembershipProof<H>, Vec<Digest>) =
            archival_mmr.prove_membership(leaf_index as u64).await;

        // Verify single leaf

        let (mp1_verifies, _acc_hash_1) =
            mp1.verify(&old_peaks, leaf_hashes[leaf_index], leaf_count as u64);
        assert!(mp1_verifies);

        // Create copy of ArchivalMmr, recreate membership proof

        let mut other_archival_mmr: ArchivalMmr<H, Storage> =
            mock::get_ammr_from_digests::<H>(leaf_hashes.clone()).await;

        let (mp2, _acc_hash_2) = other_archival_mmr.prove_membership(leaf_index as u64).await;

        // Mutate leaf + mutate leaf raw, assert that they're equivalent

        let mutated_leaf = H::hash(&BFieldElement::new(10000));
        other_archival_mmr.mutate_leaf(&mp2, mutated_leaf).await;

        let new_peaks_one = other_archival_mmr.get_peaks().await;
        archival_mmr
            .mutate_leaf_raw(leaf_index as u64, mutated_leaf)
            .await;

        let new_peaks_two = archival_mmr.get_peaks().await;
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

        let (mp2_verifies_non_mutated_leaf, _acc_hash_3) =
            mp2.verify(&new_peaks_two, leaf_hashes[leaf_index], leaf_count as u64);
        assert!(!mp2_verifies_non_mutated_leaf);

        let (mp2_verifies_mutated_leaf, _acc_hash_4) =
            mp2.verify(&new_peaks_two, mutated_leaf, leaf_count as u64);
        assert!(mp2_verifies_mutated_leaf);

        // Create a new archival MMR with the same leaf hashes as in the
        // modified MMR, and verify that the two MMRs are equivalent

        let archival_mmr_new: ArchivalMmr<H, Storage> =
            mock::get_ammr_from_digests::<H>(leaf_hashes).await;
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

    async fn bag_peaks_gen<H: AlgebraicHasher>() {
        // Verify that archival and accumulator MMR produce the same root
        let leaf_hashes_blake3: Vec<Digest> = random_elements(3);
        let archival_mmr_small: ArchivalMmr<H, Storage> =
            mock::get_ammr_from_digests::<H>(leaf_hashes_blake3.clone()).await;
        let accumulator_mmr_small = MmrAccumulator::<H>::new(leaf_hashes_blake3).await;
        assert_eq!(
            archival_mmr_small.bag_peaks().await,
            accumulator_mmr_small.bag_peaks().await
        );
        assert_eq!(
            archival_mmr_small.bag_peaks().await,
            bag_peaks::<H>(&accumulator_mmr_small.get_peaks().await)
        );
        let acc_small_bag_peaks = accumulator_mmr_small.bag_peaks().await;
        assert!(!accumulator_mmr_small
            .get_peaks()
            .await
            .iter()
            .any(|peak| *peak == acc_small_bag_peaks));
    }

    #[tokio::test]
    async fn bag_peaks_blake3_test() {
        bag_peaks_gen::<blake3::Hasher>().await;
        bag_peaks_gen::<Tip5>().await;
    }

    #[tokio::test]
    async fn accumulator_mmr_mutate_leaf_test() {
        type H = blake3::Hasher;

        // Verify that upating leafs in archival and in accumulator MMR results in the same peaks
        // and verify that updating all leafs in an MMR results in the expected MMR
        for size in 1..150 {
            let new_leaf: Digest = random();
            let leaf_hashes_blake3: Vec<Digest> = random_elements(size);

            let mut acc = MmrAccumulator::<H>::new(leaf_hashes_blake3.clone()).await;
            let mut archival: ArchivalMmr<H, Storage> =
                mock::get_ammr_from_digests::<H>(leaf_hashes_blake3.clone()).await;
            let archival_end_state: ArchivalMmr<H, Storage> =
                mock::get_ammr_from_digests::<H>(vec![new_leaf; size]).await;
            for i in 0..size {
                let i = i as u64;
                let (mp, _archival_peaks) = archival.prove_membership(i).await;
                assert_eq!(i, mp.leaf_index);
                acc.mutate_leaf(&mp, new_leaf).await;
                archival.mutate_leaf_raw(i, new_leaf).await;
                let new_archival_peaks = archival.get_peaks().await;
                assert_eq!(new_archival_peaks, acc.get_peaks().await);
            }

            assert_eq!(archival_end_state.get_peaks().await, acc.get_peaks().await);
        }
    }

    #[tokio::test]
    async fn mmr_prove_verify_leaf_mutation_test() {
        type H = blake3::Hasher;

        for size in 1..150 {
            let new_leaf: Digest = random();
            let bad_leaf: Digest = random();
            let leaf_hashes_blake3: Vec<Digest> = random_elements(size);
            let mut acc = MmrAccumulator::<H>::new(leaf_hashes_blake3.clone()).await;
            let mut archival: ArchivalMmr<H, Storage> =
                mock::get_ammr_from_digests::<H>(leaf_hashes_blake3.clone()).await;
            let archival_end_state: ArchivalMmr<H, Storage> =
                mock::get_ammr_from_digests::<H>(vec![new_leaf; size]).await;
            for i in 0..size {
                let i = i as u64;
                let (mp, peaks_before_update) = archival.prove_membership(i).await;
                assert_eq!(archival.get_peaks().await, peaks_before_update);

                // Verify the update operation using the batch verifier
                archival.mutate_leaf_raw(i, new_leaf).await;
                assert!(
                    acc.verify_batch_update(
                        &archival.get_peaks().await,
                        &[],
                        &[(new_leaf, mp.clone())]
                    )
                    .await,
                    "Valid batch update parameters must succeed"
                );
                assert!(
                    !acc.verify_batch_update(
                        &archival.get_peaks().await,
                        &[],
                        &[(bad_leaf, mp.clone())]
                    )
                    .await,
                    "Inalid batch update parameters must fail"
                );

                acc.mutate_leaf(&mp, new_leaf).await;
                let new_archival_peaks = archival.get_peaks().await;
                assert_eq!(new_archival_peaks, acc.get_peaks().await);
                assert_eq!(size as u64, archival.count_leaves().await);
                assert_eq!(size as u64, acc.count_leaves().await);
            }
            assert_eq!(archival_end_state.get_peaks().await, acc.get_peaks().await);
        }
    }

    #[tokio::test]
    async fn mmr_append_test() {
        type H = blake3::Hasher;

        // Verify that building an MMR iteratively or in *one* function call results in the same MMR
        for size in 1..260 {
            let leaf_hashes_blake3: Vec<Digest> = random_elements(size);
            let mut archival_iterative: ArchivalMmr<H, Storage> =
                mock::get_ammr_from_digests::<H>(vec![]).await;
            let archival_batch: ArchivalMmr<H, Storage> =
                mock::get_ammr_from_digests::<H>(leaf_hashes_blake3.clone()).await;
            let mut accumulator_iterative = MmrAccumulator::<H>::default();
            let accumulator_batch = MmrAccumulator::<H>::new(leaf_hashes_blake3.clone()).await;
            for (leaf_index, leaf_hash) in leaf_hashes_blake3.clone().into_iter().enumerate() {
                let archival_membership_proof: MmrMembershipProof<H> =
                    archival_iterative.append(leaf_hash).await;
                let accumulator_membership_proof = accumulator_iterative.append(leaf_hash).await;

                // Verify membership proofs returned from the append operation
                assert_eq!(
                    accumulator_membership_proof, archival_membership_proof,
                    "membership proofs from append operation must agree"
                );
                assert!(
                    archival_membership_proof
                        .verify(
                            &archival_iterative.get_peaks().await,
                            leaf_hash,
                            archival_iterative.count_leaves().await
                        )
                        .0
                );

                // Verify that membership proofs are the same as generating them from an archival MMR
                let archival_membership_proof_direct = archival_iterative
                    .prove_membership(leaf_index as u64)
                    .await
                    .0;
                assert_eq!(archival_membership_proof_direct, archival_membership_proof);
            }

            // Verify that the MMRs built iteratively from `append` and in *one* batch are the same
            assert_eq!(
                accumulator_batch.get_peaks().await,
                accumulator_iterative.get_peaks().await
            );
            assert_eq!(
                accumulator_batch.count_leaves().await,
                accumulator_iterative.count_leaves().await
            );
            assert_eq!(size as u64, accumulator_iterative.count_leaves().await);
            assert_eq!(
                archival_iterative.get_peaks().await,
                accumulator_iterative.get_peaks().await
            );

            // Run a batch-append verification on the entire mutation of the MMR and verify that it succeeds
            let empty_accumulator = MmrAccumulator::<H>::default();
            assert!(
                empty_accumulator
                    .verify_batch_update(
                        &archival_batch.get_peaks().await,
                        &leaf_hashes_blake3,
                        &[],
                    )
                    .await
            );
        }
    }

    #[tokio::test]
    async fn one_input_mmr_test() {
        type H = Tip5;

        let input_hash = H::hash(&BFieldElement::new(14));
        let new_input_hash = H::hash(&BFieldElement::new(201));
        let mut mmr: ArchivalMmr<H, Storage> =
            mock::get_ammr_from_digests::<H>(vec![input_hash]).await;
        let original_mmr: ArchivalMmr<H, Storage> =
            mock::get_ammr_from_digests::<H>(vec![input_hash]).await;
        let mmr_after_append: ArchivalMmr<H, Storage> =
            mock::get_ammr_from_digests::<H>(vec![input_hash, new_input_hash]).await;
        assert_eq!(1, mmr.count_leaves().await);
        assert_eq!(1, mmr.count_nodes().await);

        let original_peaks_and_heights: Vec<(Digest, u32)> = mmr.get_peaks_with_heights().await;
        assert_eq!(1, original_peaks_and_heights.len());
        assert_eq!(0, original_peaks_and_heights[0].1);

        {
            let leaf_index = 0;
            let (membership_proof, peaks) = mmr.prove_membership(leaf_index).await;
            let valid_res = membership_proof.verify(&peaks, input_hash, 1);
            assert!(valid_res.0);
            assert!(valid_res.1.is_some());
        }

        mmr.append(new_input_hash).await;
        assert_eq!(2, mmr.count_leaves().await);
        assert_eq!(3, mmr.count_nodes().await);

        let new_peaks_and_heights = mmr.get_peaks_with_heights().await;
        assert_eq!(1, new_peaks_and_heights.len());
        assert_eq!(1, new_peaks_and_heights[0].1);

        let new_peaks: Vec<Digest> = new_peaks_and_heights.iter().map(|x| x.0).collect();
        assert!(
            original_mmr
                .verify_batch_update(&new_peaks, &[new_input_hash], &[])
                .await,
            "verify batch update must succeed for a single append"
        );

        // let mmr_after_append = mmr.clone();
        let new_leaf: Digest = H::hash(&BFieldElement::new(987223));

        // When verifying the batch update with two consequtive leaf mutations, we must get the
        // membership proofs prior to all mutations. This is because the `verify_batch_update` method
        // updates the membership proofs internally to account for the mutations.
        let leaf_mutations: Vec<(Digest, MmrMembershipProof<H>)> =
            futures::future::join_all((0..2).map(|i| mmr_after_append.prove_membership(i)))
                .await
                .into_iter()
                .map(|p| (new_leaf, p.0))
                .collect();

        for &leaf_index in &[0u64, 1] {
            let mp = mmr.prove_membership(leaf_index).await.0;
            mmr.mutate_leaf(&mp, new_leaf).await;
            assert_eq!(
                new_leaf,
                mmr.get_leaf(leaf_index).await,
                "fetched leaf must match what we put in"
            );
        }

        assert!(
            mmr_after_append
                .verify_batch_update(&mmr.get_peaks().await, &[], &leaf_mutations)
                .await,
            "The batch update of two leaf mutations must verify"
        );
    }

    #[tokio::test]
    async fn two_input_mmr_test() {
        type H = Tip5;

        let num_leaves: u64 = 3;
        let input_digests: Vec<Digest> = random_elements(num_leaves as usize);

        let mut mmr: ArchivalMmr<H, Storage> =
            mock::get_ammr_from_digests::<H>(input_digests.clone()).await;
        assert_eq!(num_leaves, mmr.count_leaves().await);
        assert_eq!(1 + num_leaves, mmr.count_nodes().await);

        let original_peaks_and_heights: Vec<(Digest, u32)> = mmr.get_peaks_with_heights().await;
        let expected_peaks = 2;
        assert_eq!(expected_peaks, original_peaks_and_heights.len());

        {
            let leaf_index = 0;
            let input_digest = input_digests[leaf_index];
            let (mut membership_proof, peaks) = mmr.prove_membership(leaf_index as u64).await;

            let (mp_verifies_1, acc_hash_1) =
                membership_proof.verify(&peaks, input_digest, num_leaves);
            assert!(mp_verifies_1);
            assert!(acc_hash_1.is_some());

            // Negative test for verify membership
            membership_proof.leaf_index += 1;

            let (mp_verifies_2, acc_hash_2) =
                membership_proof.verify(&peaks, input_digest, num_leaves);
            assert!(!mp_verifies_2);
            assert!(acc_hash_2.is_none());
        }

        let new_leaf_hash: Digest = H::hash(&BFieldElement::new(201));
        mmr.append(new_leaf_hash).await;

        let expected_num_leaves = 1 + num_leaves;
        assert_eq!(expected_num_leaves, mmr.count_leaves().await);

        let expected_node_count = 3 + expected_num_leaves;
        assert_eq!(expected_node_count, mmr.count_nodes().await);

        for leaf_index in 0..num_leaves {
            let new_leaf: Digest = H::hash(&BFieldElement::new(987223));
            let (mp, _acc_hash) = mmr.prove_membership(leaf_index).await;
            mmr.mutate_leaf(&mp, new_leaf).await;
            assert_eq!(new_leaf, mmr.get_leaf(leaf_index).await);
        }
    }

    #[tokio::test]
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
            let mut mmr: ArchivalMmr<H, Storage> =
                mock::get_ammr_from_digests::<H>(input_hashes.clone()).await;

            assert_eq!(leaf_count, mmr.count_leaves().await);
            assert_eq!(node_count, mmr.count_nodes().await);

            let original_peaks_and_heights = mmr.get_peaks_with_heights().await;
            let peak_heights_1: Vec<u32> = original_peaks_and_heights.iter().map(|x| x.1).collect();

            let (peak_heights_2, _) = get_peak_heights_and_peak_node_indices(leaf_count);
            assert_eq!(peak_heights_1, peak_heights_2);

            let actual_peak_count = original_peaks_and_heights.len() as u64;
            assert_eq!(peak_count, actual_peak_count);

            // Verify that MMR root from odd number of digests and MMR bagged peaks agree
            let mmra_root = mmr.bag_peaks().await;
            let mt_root = root_from_arbitrary_number_of_digests::<H>(&input_hashes);

            assert_eq!(
                mmra_root, mt_root,
                "MMRA bagged peaks and MT root must agree"
            );

            // Get an authentication path for **all** values in MMR,
            // verify that it is valid
            for index in 0..leaf_count {
                let (membership_proof, peaks) = mmr.prove_membership(index).await;
                let valid_res =
                    membership_proof.verify(&peaks, input_hashes[index as usize], leaf_count);

                assert!(valid_res.0);
                assert!(valid_res.1.is_some());
            }

            // // Make a new MMR where we append with a value and run the verify_append
            let new_leaf_hash = H::hash(&BFieldElement::new(201));
            let orignal_peaks = mmr.get_peaks().await;
            let mp = mmr.append(new_leaf_hash).await;
            assert!(
                mp.verify(&mmr.get_peaks().await, new_leaf_hash, leaf_count + 1)
                    .0,
                "Returned membership proof from append must verify"
            );
            assert_ne!(
                orignal_peaks,
                mmr.get_peaks().await,
                "peaks must change when appending"
            );
        }
    }

    #[tokio::test]
    async fn remove_last_leaf_test() {
        type H = blake3::Hasher;

        let input_digests: Vec<Digest> = random_elements(12);
        let mut mmr: ArchivalMmr<H, Storage> =
            mock::get_ammr_from_digests::<H>(input_digests.clone()).await;
        assert_eq!(22, mmr.count_nodes().await);
        assert_eq!(Some(input_digests[11]), mmr.remove_last_leaf().await);
        assert_eq!(19, mmr.count_nodes().await);
        assert_eq!(Some(input_digests[10]), mmr.remove_last_leaf().await);
        assert_eq!(18, mmr.count_nodes().await);
        assert_eq!(Some(input_digests[9]), mmr.remove_last_leaf().await);
        assert_eq!(16, mmr.count_nodes().await);
        assert_eq!(Some(input_digests[8]), mmr.remove_last_leaf().await);
        assert_eq!(15, mmr.count_nodes().await);
        assert_eq!(Some(input_digests[7]), mmr.remove_last_leaf().await);
        assert_eq!(11, mmr.count_nodes().await);
        assert_eq!(Some(input_digests[6]), mmr.remove_last_leaf().await);
        assert_eq!(10, mmr.count_nodes().await);
        assert_eq!(Some(input_digests[5]), mmr.remove_last_leaf().await);
        assert_eq!(8, mmr.count_nodes().await);
        assert_eq!(Some(input_digests[4]), mmr.remove_last_leaf().await);
        assert_eq!(7, mmr.count_nodes().await);
        assert_eq!(Some(input_digests[3]), mmr.remove_last_leaf().await);
        assert_eq!(4, mmr.count_nodes().await);
        assert_eq!(Some(input_digests[2]), mmr.remove_last_leaf().await);
        assert_eq!(3, mmr.count_nodes().await);
        assert_eq!(Some(input_digests[1]), mmr.remove_last_leaf().await);
        assert_eq!(1, mmr.count_nodes().await);
        assert_eq!(Some(input_digests[0]), mmr.remove_last_leaf().await);
        assert_eq!(0, mmr.count_nodes().await);
        assert!(mmr.is_empty().await);
        assert!(mmr.remove_last_leaf().await.is_none());
    }

    #[tokio::test]
    async fn remove_last_leaf_pbt() {
        type H = blake3::Hasher;

        let small_size: usize = 100;
        let big_size: usize = 350;
        let input_digests_big: Vec<Digest> = random_elements(big_size);
        let input_digests_small: Vec<Digest> = input_digests_big[0..small_size].to_vec();

        let mut mmr_small: ArchivalMmr<H, Storage> =
            mock::get_ammr_from_digests::<H>(input_digests_small).await;
        let mut mmr_big: ArchivalMmr<H, Storage> =
            mock::get_ammr_from_digests::<H>(input_digests_big).await;

        for _ in 0..(big_size - small_size) {
            mmr_big.remove_last_leaf().await;
        }

        assert_eq!(mmr_big.get_peaks().await, mmr_small.get_peaks().await);
        assert_eq!(mmr_big.bag_peaks().await, mmr_small.bag_peaks().await);
        assert_eq!(mmr_big.count_leaves().await, mmr_small.count_leaves().await);
        assert_eq!(mmr_big.count_nodes().await, mmr_small.count_nodes().await);
    }

    #[tokio::test]
    async fn variable_size_blake3_mmr_test() {
        type H = blake3::Hasher;

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
            let mut mmr: ArchivalMmr<H, Storage> =
                mock::get_ammr_from_digests::<H>(input_digests.clone()).await;
            let mmr_original: ArchivalMmr<H, Storage> =
                mock::get_ammr_from_digests::<H>(input_digests.clone()).await;
            assert_eq!(size, mmr.count_leaves().await);
            assert_eq!(node_count, mmr.count_nodes().await);
            let original_peaks_and_heights: Vec<(Digest, u32)> = mmr.get_peaks_with_heights().await;
            let peak_heights_1: Vec<u32> = original_peaks_and_heights.iter().map(|x| x.1).collect();
            let (peak_heights_2, _) = get_peak_heights_and_peak_node_indices(size);
            assert_eq!(peak_heights_1, peak_heights_2);
            assert_eq!(peak_count, original_peaks_and_heights.len() as u64);

            // Verify that MMR root from odd number of digests and MMR bagged peaks agree
            let mmra_root = mmr.bag_peaks().await;
            let mt_root = root_from_arbitrary_number_of_digests::<H>(&input_digests);
            assert_eq!(
                mmra_root, mt_root,
                "MMRA bagged peaks and MT root must agree"
            );

            // Get an authentication path for **all** values in MMR,
            // verify that it is valid
            for leaf_index in 0..size {
                let (mut membership_proof, peaks) = mmr.prove_membership(leaf_index).await;
                let valid_res =
                    membership_proof.verify(&peaks, input_digests[leaf_index as usize], size);
                assert!(valid_res.0);
                assert!(valid_res.1.is_some());

                let new_leaf: Digest = random();

                // The below verify_modify tests should only fail if `wrong_leaf_index` is
                // different than `leaf_index`.
                let wrong_leaf_index = (leaf_index + 1) % mmr.count_leaves().await;
                membership_proof.leaf_index = wrong_leaf_index;
                assert!(
                    wrong_leaf_index == leaf_index
                        || !membership_proof.verify(&peaks, new_leaf, size).0
                );
                membership_proof.leaf_index = leaf_index;

                // Modify an element in the MMR and run prove/verify for membership
                let old_leaf = input_digests[leaf_index as usize];
                mmr.mutate_leaf_raw(leaf_index, new_leaf).await;

                let (new_mp, new_peaks) = mmr.prove_membership(leaf_index).await;
                assert!(new_mp.verify(&new_peaks, new_leaf, size).0);
                assert!(!new_mp.verify(&new_peaks, old_leaf, size).0);

                // Return the element to its former value and run prove/verify for membership
                mmr.mutate_leaf_raw(leaf_index, old_leaf).await;
                let (old_mp, old_peaks) = mmr.prove_membership(leaf_index).await;
                assert!(!old_mp.verify(&old_peaks, new_leaf, size).0);
                assert!(old_mp.verify(&old_peaks, old_leaf, size).0);
            }

            // Make a new MMR where we append with a value and run the verify_append
            let new_leaf_hash: Digest = random();
            mmr.append(new_leaf_hash).await;
            assert!(
                mmr_original
                    .verify_batch_update(&mmr.get_peaks().await, &[new_leaf_hash], &[])
                    .await
            );
        }
    }

    #[tokio::test]
    async fn leveldb_persist_storage_schema_test() {
        type H = blake3::Hasher;

        let db = NeptuneLevelDb::open_new_test_database(true, None, None, None)
            .await
            .unwrap();
        let mut storage = SimpleRustyStorage::new(db);
        let ammr0 = storage
            .schema
            .new_vec::<Digest>("ammr-nodes-digests-0")
            .await;
        let mut ammr0: ArchivalMmr<H, _> = ArchivalMmr::new(ammr0).await;
        let ammr1 = storage
            .schema
            .new_vec::<Digest>("ammr-nodes-digests-1")
            .await;
        let mut ammr1: ArchivalMmr<H, _> = ArchivalMmr::new(ammr1).await;

        let digest0: Digest = random();
        ammr0.append(digest0).await;

        let digest1: Digest = random();
        ammr1.append(digest1).await;
        assert_eq!(digest0, ammr0.get_leaf(0).await);
        assert_eq!(digest1, ammr1.get_leaf(0).await);
        storage.persist().await;

        assert_eq!(digest0, ammr0.get_leaf(0).await);
        assert_eq!(digest1, ammr1.get_leaf(0).await);
    }
}
