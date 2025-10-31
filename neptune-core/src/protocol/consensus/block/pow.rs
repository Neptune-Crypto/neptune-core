use std::fmt::Display;
use std::mem::MaybeUninit;
use std::num::NonZeroUsize;

use get_size2::GetSize;
use itertools::Itertools;
use rand::distr::Distribution;
use rand::distr::StandardUniform;
use rand::Rng;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelIterator;
use rayon::iter::IntoParallelRefMutIterator;
use rayon::iter::ParallelIterator;
use rayon::slice::ParallelSlice;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::twenty_first::bfe_array;

use crate::application::loops::channel::Cancelable;
use crate::protocol::consensus::block::block_header::BlockHeader;
use crate::protocol::consensus::block::block_kernel::BlockKernel;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::BFieldElement;

/// Determines the number of leafs in the Merkle tree in the guesser buffer.
#[cfg(not(test))]
pub(crate) const POW_MEMORY_PARAMETER: usize = 1 << 29;
#[cfg(test)] // Set to smaller value to allow for testing of PoW
pub(crate) const POW_MEMORY_PARAMETER: usize = 1 << 10;

pub(crate) const POW_MEMORY_TREE_HEIGHT: usize = POW_MEMORY_PARAMETER.ilog2() as usize;

/// The number of hash steps before checking for channel cancellation.
const CHECKPOINT_DISTANCE: usize = 1 << 19;

const NUM_INDEX_REPETITIONS: u32 = 63;
const NUM_BUD_LAYERS: usize = 5; // 5 => 63 Tip5 permutations per leaf
const BUDS_PER_LEAF: usize = 1 << NUM_BUD_LAYERS;

/// Merkle tree, tailored to the `pow` module.
///
/// Note that `twenty-first` has a Merkle tree module that is perfectly adequate
/// for most applications; you probably want to use that unless in the specific
/// context of proof-of-work.
///
/// Differences relative to `twenty-first`'s Merkle tree:
///
///  - Constructor takes ownership of pre-allocated vector.
///  - Constructor is interruptible.
///  - Implements `GetSize`.
#[derive(
    Debug, Clone, Serialize, Deserialize, PartialEq, Eq, BFieldCodec, TasmObject, GetSize, Default,
)]
pub struct MTree {
    leafs: Vec<Digest>,
    internal_nodes: Vec<Digest>,
}

impl MTree {
    /// Build a Merkle tree without reallocation.
    ///
    /// Takes a vector of `Digest`s of length some power of two and whose second
    /// half represents the Merkle tree's leafs. Also takes an optional cancel
    /// channel, which enables mid-process abortion.
    pub fn build_inplace(
        leafs: Vec<Digest>,
        mut internal_nodes: Vec<Digest>,
        cancel_channel: Option<&dyn Cancelable>,
    ) -> Self {
        let height = leafs.len().ilog2() as usize;
        let num_sequential_layers = usize::min(height, 8);
        let seq_cutoff_height = usize::max(1, height - num_sequential_layers);

        // the first layer connects the leafs to the internal nodes, so special
        let range_layer_0 = (1 << (height - 1))..(1 << height);
        Self::par_merkle_zip(&mut internal_nodes[range_layer_0], &leafs, cancel_channel);

        if cancel_channel.is_some_and(|channel| channel.is_canceled()) {
            return Default::default();
        }

        // remaining layers connect internal nodes to internal nodes
        for layer in 1..seq_cutoff_height {
            let parents_start = 1 << (height - 1 - layer);
            let mid_point = 1 << (height - layer);
            let (parents, children) = internal_nodes.split_at_mut(mid_point);
            Self::par_merkle_zip(&mut parents[parents_start..], children, cancel_channel);

            if cancel_channel.is_some_and(|channel| channel.is_canceled()) {
                return Default::default();
            }
        }

        // do top of tree sequentially
        for layer in seq_cutoff_height..height {
            let parents_start = 1 << (height - 1 - layer);
            let mid_point = 1 << (height - layer);
            let (parents, children) = internal_nodes.split_at_mut(mid_point);
            Self::merkle_zip(&mut parents[parents_start..], children);
        }

        Self {
            leafs,
            internal_nodes,
        }
    }

    fn merkle_zip(parents: &mut [Digest], children: &[Digest]) {
        for (p, ch) in parents.iter_mut().zip(children.chunks(2)) {
            *p = Tip5::hash_pair(ch[0], ch[1]);
        }
    }

    fn par_merkle_zip(
        parents: &mut [Digest],
        children: &[Digest],
        cancel_channel: Option<&dyn Cancelable>,
    ) {
        let checkpoint_distance = usize::min(CHECKPOINT_DISTANCE, parents.len());
        let num_checkpoints = parents.len() / checkpoint_distance;
        for i in 0..num_checkpoints {
            parents
                .par_iter_mut()
                .skip(checkpoint_distance * i)
                .take(checkpoint_distance)
                .zip(
                    children
                        .par_chunks(2)
                        .skip(checkpoint_distance * i)
                        .take(checkpoint_distance),
                )
                .for_each(|(p, ch)| {
                    *p = Tip5::hash_pair(ch[0], ch[1]);
                });

            if cancel_channel.is_some_and(|channel| channel.is_canceled()) {
                return;
            }
        }
    }

    pub fn root(&self) -> Digest {
        self.internal_nodes.get(1).copied().unwrap_or_default()
    }

    pub fn path(&self, index: usize) -> Vec<Digest> {
        let mut running_index = index + self.leafs.len();
        let mut path = vec![self.leafs[index ^ 1]];
        for _ in 1..(self.leafs.len().ilog2()) {
            running_index >>= 1;
            path.push(self.internal_nodes[running_index ^ 1]);
        }
        path
    }

    pub fn verify(root: Digest, index: usize, path: &[Digest], element: Digest) -> bool {
        // if index out of bounds, reject early
        if index > 1 << path.len() {
            return false;
        }

        let mut running_index = index;
        let mut running_digest = element;
        for sibling in path {
            if running_index & 1 == 1 {
                running_digest = Tip5::hash_pair(*sibling, running_digest);
            } else {
                running_digest = Tip5::hash_pair(running_digest, *sibling);
            }
            running_index >>= 1;
        }

        running_digest == root
    }
}

#[derive(
    Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec, TasmObject, GetSize,
)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(arbitrary::Arbitrary))]
pub struct Pow<const MERKLE_TREE_HEIGHT: usize> {
    pub root: Digest,

    #[serde(with = "serde_arrays")]
    pub path_a: [Digest; MERKLE_TREE_HEIGHT],

    #[serde(with = "serde_arrays")]
    pub path_b: [Digest; MERKLE_TREE_HEIGHT],

    // The nonce comes at the end, so in the `BFieldCodec` encoding it comes
    // first. Therefore, you cannot store partial hashes of paths.
    pub nonce: Digest,
}

#[derive(Clone, Debug, Copy, Serialize, Deserialize, BFieldCodec, Default, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(arbitrary::Arbitrary))]
pub struct PowMastPaths {
    pub(super) pow: [Digest; BlockHeader::MAST_HEIGHT],
    pub(super) header: [Digest; BlockKernel::MAST_HEIGHT],
    pub(super) kernel: [Digest; Block::MAST_HEIGHT],
}

impl PowMastPaths {
    fn commit(&self) -> Digest {
        Tip5::hash_varlen(
            &[
                self.pow.to_vec(),
                self.header.to_vec(),
                self.kernel.to_vec(),
            ]
            .into_iter()
            .flatten()
            .flat_map(|d| d.values())
            .collect_vec(),
        )
    }

    pub fn fast_mast_hash<const MERKLE_TREE_HEIGHT: usize>(
        self,
        pow: Pow<MERKLE_TREE_HEIGHT>,
    ) -> Digest {
        // 39 permutations to get the block hash, when Merkle tree height is
        // 29. num_permutations = 10 + tree height.
        let header_mast_hash = Tip5::hash_pair(Tip5::hash_varlen(&pow.encode()), self.pow[0]);
        let header_mast_hash = Tip5::hash_pair(header_mast_hash, self.pow[1]);
        let header_mast_hash = Tip5::hash_pair(self.pow[2], header_mast_hash);

        let kernel_mast_hash = Tip5::hash_pair(
            Tip5::hash_varlen(&header_mast_hash.encode()),
            self.header[0],
        );
        let kernel_mast_hash = Tip5::hash_pair(kernel_mast_hash, self.header[1]);

        Tip5::hash_pair(
            Tip5::hash_varlen(&kernel_mast_hash.encode()),
            self.kernel[0],
        )
    }
}

impl<const MERKLE_TREE_HEIGHT: usize> Default for Pow<MERKLE_TREE_HEIGHT> {
    fn default() -> Self {
        Self {
            root: Default::default(),
            path_a: [Digest::default(); MERKLE_TREE_HEIGHT],
            path_b: [Digest::default(); MERKLE_TREE_HEIGHT],
            nonce: Default::default(),
        }
    }
}

impl<const MERKLE_TREE_HEIGHT: usize> Display for Pow<MERKLE_TREE_HEIGHT> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = format!(
            "nonce: {:x}\n\
            root: {:x}\n\
            paths: [{}]\n[{}]\n",
            self.nonce,
            self.root,
            self.path_a.iter().map(|d| format!("{d:x}")).join(","),
            self.path_b.iter().map(|d| format!("{d:x}")).join(","),
        );

        write!(f, "{}", string)
    }
}

/// Data structure that must be stored in memory for efficient guessing.
/// Independent of the nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuesserBuffer<const MERKLE_TREE_HEIGHT: usize> {
    merkle_tree: MTree,

    /// The hash of the parent block of this guesser buffer.
    prev_block_digest: Digest,
}

impl<const MERKLE_TREE_HEIGHT: usize> GuesserBuffer<MERKLE_TREE_HEIGHT> {
    /// A commitment that refers to both the Merkle tree of the guesser buffer
    /// and the current proposal being guessed on, designed in such a way that
    /// the Merkle tree root must be known before indices can be picked.
    /// Combined with a nonce, the opened indices can be derived from this
    /// value.
    fn index_picker_preimage_from_root(
        merkle_tree_root: Digest,
        mast_auth_paths: &PowMastPaths,
    ) -> Digest {
        Tip5::hash_pair(merkle_tree_root, mast_auth_paths.commit())
    }

    /// A commitment to everything in the block except for the nonce and the
    /// authentication paths of the pow structure.
    ///
    /// The return value is hashed together with the nonce to calculate the
    /// indices which are opened into the guesser buffer's Merkle tree.
    pub fn index_picker_preimage(&self, mast_auth_paths: &PowMastPaths) -> Digest {
        Self::index_picker_preimage_from_root(self.merkle_tree.root(), mast_auth_paths)
    }
}

impl<const MERKLE_TREE_HEIGHT: usize> Default for GuesserBuffer<MERKLE_TREE_HEIGHT> {
    fn default() -> Self {
        Self {
            merkle_tree: MTree::default(),
            prev_block_digest: Default::default(),
        }
    }
}

impl<const MERKLE_TREE_HEIGHT: usize> Pow<MERKLE_TREE_HEIGHT> {
    pub const MERKLE_TREE_HEIGHT: usize = MERKLE_TREE_HEIGHT;
    pub const NUM_LEAFS: usize = 1_usize << Self::MERKLE_TREE_HEIGHT;

    fn bud(commitment: Digest, index: u64) -> Digest {
        Tip5::hash_pair(commitment, Digest::new(bfe_array![index, 0, 0, 0, 0]))
    }

    fn leaf(commitment: Digest, index: u64) -> Digest {
        let buds = (index..(index + BUDS_PER_LEAF as u64))
            .map(|i| Self::bud(commitment, i % Self::NUM_LEAFS as u64))
            .collect_vec();

        let internal_nodes = buds.clone();
        MTree::build_inplace(buds, internal_nodes, None).root()
    }

    fn indices(hash: Digest, nonce: Digest) -> (u64, u64) {
        let mut indexer = Tip5::hash_pair(hash, nonce);
        for _ in 1..NUM_INDEX_REPETITIONS {
            indexer = Tip5::hash_pair(indexer, Digest::default());
        }

        let index_a = indexer.values()[0].value() % (1_u64 << Self::MERKLE_TREE_HEIGHT);
        let index_b = indexer.values()[1].value() % (1_u64 << Self::MERKLE_TREE_HEIGHT);
        (index_a, index_b)
    }

    const fn bitreverse(mut k: u32, log2_n: u32) -> u32 {
        k = ((k & 0x55555555) << 1) | ((k & 0xaaaaaaaa) >> 1);
        k = ((k & 0x33333333) << 2) | ((k & 0xcccccccc) >> 2);
        k = ((k & 0x0f0f0f0f) << 4) | ((k & 0xf0f0f0f0) >> 4);
        k = ((k & 0x00ff00ff) << 8) | ((k & 0xff00ff00) >> 8);
        k = k.rotate_right(16);
        k >> ((32 - log2_n) & 0x1f)
    }

    fn swap_indices(len: usize) -> Vec<Option<NonZeroUsize>> {
        let log_2_len = len.checked_ilog2().unwrap_or(0);
        (0..len)
            .map(|k| {
                let rev_k = Self::bitreverse(k as u32, log_2_len);

                // 0 >= bitreverse(0, log_2_len) == 0 => unwrap is fine
                ((k as u32) < rev_k).then(|| NonZeroUsize::new(rev_k as usize).unwrap())
            })
            .collect()
    }

    pub(crate) fn preprocess(
        mast_auth_paths: PowMastPaths,
        cancel_channel: Option<&dyn Cancelable>,
        consensus_rule_set: ConsensusRuleSet,
        prev_block_digest: Digest,
    ) -> GuesserBuffer<MERKLE_TREE_HEIGHT> {
        let bud_prefix = if consensus_rule_set == ConsensusRuleSet::Reboot {
            // Commitment to all the fields in the block that are not pow
            mast_auth_paths.commit()
        } else {
            // Commitment only to previous block hash such that preprocessing
            // can be reused across different block proposals with the same
            // parent.
            prev_block_digest
        };

        // number steps between checking channel cancellation
        let checkpoint_distance: usize =
            usize::min(1 << (Self::MERKLE_TREE_HEIGHT - 1), CHECKPOINT_DISTANCE);
        let num_checkpoints: usize = (1 << Self::MERKLE_TREE_HEIGHT) / checkpoint_distance;

        // fill the buffer with buds
        let mut ins = Vec::<MaybeUninit<Digest>>::with_capacity(Self::NUM_LEAFS);
        // SAFETY:
        //  - new_len must be less than or equal to [capacity()].
        //    -> OK because new_len == capacity() == Self::NUM_LEAFS.
        //  - The elements at old_len..new_len must be initialized.
        //    -> OK because either
        //        - all are initialized in the loop below; or
        //        - we abort early and drop the data structure.
        unsafe {
            ins.set_len(Self::NUM_LEAFS);
        }
        for j in 0..num_checkpoints {
            let range = (j * checkpoint_distance)..((j + 1) * checkpoint_distance);

            range
                .clone()
                .into_par_iter()
                .zip(ins[range].par_iter_mut())
                .for_each(|(i, bud)| {
                    bud.write(Self::bud(bud_prefix, i as u64));
                });

            if cancel_channel.is_some_and(|channel| channel.is_canceled()) {
                return Default::default();
            }
        }
        // SAFETY:
        //  - `Vec<MaybeUninit<Digest>>` and `Vec<Digest>` are byte-by-byte
        //    identical; `MaybeUninit` guarantees this.
        let mut ins: Vec<Digest> = unsafe { std::mem::transmute(ins) };

        // iterate log-many times over the buffer to compute leafs from buds
        let mut outs = ins.clone();
        let mut buds = &mut ins;
        let mut resulting_leafs = &mut outs;
        let mut num_swaps = 0;
        for i in 0..NUM_BUD_LAYERS {
            for j in 0..num_checkpoints {
                let range = (j * checkpoint_distance)..((j + 1) * checkpoint_distance);
                range
                    .clone()
                    .into_par_iter()
                    .zip(resulting_leafs[range].par_iter_mut())
                    .for_each(|(k, leaf)| {
                        *leaf = Tip5::hash_pair(buds[k], buds[(k + (1 << i)) % Self::NUM_LEAFS]);
                    });

                if cancel_channel.is_some_and(|channel| channel.is_canceled()) {
                    return Default::default();
                }
            }
            std::mem::swap(&mut resulting_leafs, &mut buds);
            num_swaps += 1;
        }

        std::mem::swap(&mut resulting_leafs, &mut buds);
        num_swaps += 1;

        let (mut leafs, internal_nodes) = if num_swaps & 1 == 1 {
            (ins, outs)
        } else {
            (outs, ins)
        };

        if consensus_rule_set != ConsensusRuleSet::Reboot {
            // The index swapping could be done here, or in each guess. Since
            // we're optimizing for fast guessing, the index swapping is done
            // here.
            let swap_indices = Self::swap_indices(leafs.len());
            for (k, maybe_rev_k) in swap_indices.iter().enumerate() {
                if let Some(rev_k) = maybe_rev_k {
                    leafs.swap(k, rev_k.get());
                }
            }
        };

        let merkle_tree = MTree::build_inplace(leafs, internal_nodes, cancel_channel);

        GuesserBuffer::<MERKLE_TREE_HEIGHT> {
            merkle_tree,
            prev_block_digest,
        }
    }

    pub fn guess(
        buffer: &GuesserBuffer<MERKLE_TREE_HEIGHT>,
        mast_auth_paths: &PowMastPaths,
        index_picker_preimage: Digest,
        nonce: Digest,
        target: Digest,
    ) -> Option<Self> {
        let root = buffer.merkle_tree.root();

        let (index_a, index_b) = Self::indices(index_picker_preimage, nonce);

        let path_a = buffer
            .merkle_tree
            .path(index_a as usize)
            .try_into()
            .unwrap();

        let path_b = buffer
            .merkle_tree
            .path(index_b as usize)
            .try_into()
            .unwrap();

        let pow = Pow {
            nonce,
            root,
            path_a,
            path_b,
        };

        let pow_digest = mast_auth_paths.fast_mast_hash(pow);
        if pow_digest > target {
            None
        } else {
            Some(pow)
        }
    }

    pub(super) fn validate(
        self,
        auth_paths: PowMastPaths,
        target: Digest,
        consensus_rule_set: ConsensusRuleSet,
        parent_digest: Digest,
    ) -> Result<(), PowValidationError> {
        let leaf_prefix = match consensus_rule_set {
            ConsensusRuleSet::Reboot => auth_paths.commit(),
            ConsensusRuleSet::HardforkAlpha => parent_digest,
        };
        let index_picker_preimage = Tip5::hash_pair(self.root, auth_paths.commit());
        let (index_a, index_b) = Self::indices(index_picker_preimage, self.nonce);

        let (leaf_a, leaf_b) = if consensus_rule_set == ConsensusRuleSet::Reboot {
            (
                Self::leaf(leaf_prefix, index_a),
                Self::leaf(leaf_prefix, index_b),
            )
        } else {
            let index_a = u64::from(Self::bitreverse(
                index_a.try_into().unwrap(),
                Self::MERKLE_TREE_HEIGHT as u32,
            ));
            let index_b = u64::from(Self::bitreverse(
                index_b.try_into().unwrap(),
                Self::MERKLE_TREE_HEIGHT as u32,
            ));
            (
                Self::leaf(leaf_prefix, index_a),
                Self::leaf(leaf_prefix, index_b),
            )
        };

        if !MTree::verify(self.root, index_a as usize, &self.path_a, leaf_a) {
            return Err(PowValidationError::PathAInvalid);
        }
        if !MTree::verify(self.root, index_b as usize, &self.path_b, leaf_b) {
            return Err(PowValidationError::PathBInvalid);
        }

        let pow_digest = auth_paths.fast_mast_hash(self);
        let meets_threshold = pow_digest <= target;
        if !meets_threshold {
            return Err(PowValidationError::ThresholdNotMet);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PowValidationError {
    PathAInvalid,
    PathBInvalid,
    ThresholdNotMet,
}

// Not under test flag since it's used in both tests and benchmarks
impl Distribution<PowMastPaths> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> PowMastPaths {
        PowMastPaths {
            pow: rng.random(),
            header: rng.random(),
            kernel: rng.random(),
        }
    }
}

// Not under test flag since it's used in both tests and benchmarks
impl<const MERKLE_TREE_HEIGHT: usize> Distribution<Pow<MERKLE_TREE_HEIGHT>> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Pow<MERKLE_TREE_HEIGHT> {
        Pow {
            root: rng.random(),
            path_a: rng.random(),
            path_b: rng.random(),
            nonce: rng.random(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Instant;

    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use rand::rng;
    use strum::IntoEnumIterator;
    use tasm_lib::twenty_first::bfe;
    use test_strategy::proptest;

    use super::*;
    use crate::api::export::Network;
    use crate::protocol::consensus::block::difficulty_control::Difficulty;
    use crate::protocol::consensus::block::tests::DIFFICULTY_LIMIT_FOR_TESTS;
    use crate::tests::shared::blocks::invalid_empty_block;

    impl MTree {
        fn num_leafs(&self) -> usize {
            self.leafs.len()
        }

        fn leaf(&self, index: usize) -> Digest {
            self.leafs[index]
        }
    }

    #[test]
    fn leafs_agree_with_bud_trees() {
        const MERKLE_TREE_HEIGHT: usize = 10;
        const MERKLE_TREE_NUM_LEAFS: usize = 1usize << 10;
        let mut rng = rng();
        let auth_paths = rng.random::<PowMastPaths>();
        let prev_block_digest = rng.random();
        let buffer = Pow::<MERKLE_TREE_HEIGHT>::preprocess(
            auth_paths,
            None,
            ConsensusRuleSet::default(),
            prev_block_digest,
        );

        let index = rng.random_range(0..MERKLE_TREE_NUM_LEAFS);
        let expensive_leaf = Pow::<MERKLE_TREE_HEIGHT>::leaf(auth_paths.commit(), index as u64);
        let amortized_leaf = buffer.merkle_tree.leaf(index);
        assert_eq!(amortized_leaf, expensive_leaf);
    }

    #[test]
    #[ignore = "benchmark of memory and time requirements of preprocess for guessing"]
    fn benchmark_memory_requirements() {
        fn report<const MERKLE_TREE_HEIGHT: usize>(
            auth_paths: PowMastPaths,
            parent_block_hash: Digest,
        ) {
            let start = Instant::now();
            let buffer = Pow::<MERKLE_TREE_HEIGHT>::preprocess(
                auth_paths,
                None,
                ConsensusRuleSet::default(),
                parent_block_hash,
            );
            let duration = start.elapsed();
            let estimated_mt_size = buffer.merkle_tree.num_leafs() * 2 * Digest::BYTES;
            println!("Merkle tree height: {MERKLE_TREE_HEIGHT}");
            println!("estimated_mt_size: {}GB", estimated_mt_size / 1_000_000_000);
            println!("preprocess time: {} seconds\n", duration.as_secs());
        }

        let mut rng = rng();
        let auth_paths = rng.random::<PowMastPaths>();
        let parent_block_hash = rng.random::<Digest>();
        report::<25>(auth_paths, parent_block_hash);
        report::<26>(auth_paths, parent_block_hash);
        report::<27>(auth_paths, parent_block_hash);
        report::<28>(auth_paths, parent_block_hash);
        report::<29>(auth_paths, parent_block_hash);
    }

    #[test]
    fn nonce_comes_first_in_pow_encoding() {
        // Ensures that auth path hashes cannot be pre-calculated (i.e., before
        // the nonce is known). Otherwise the user might be able to get around
        // the magical 41 required permutations for one guess-equivalent.
        let pow = Pow::<10> {
            nonce: Digest::new(bfe_array![1;5]),
            ..Default::default()
        };
        let encoding = pow.encode();
        for item in encoding.iter().take(Digest::LEN) {
            assert_eq!(bfe!(1), *item);
        }
        for item in encoding.iter().skip(Digest::LEN) {
            assert_eq!(bfe!(0), *item);
        }
    }

    #[test]
    fn fast_mast_hash_agrees_with_block_hash() {
        let network = Network::Main;
        let invalid_block = invalid_empty_block(&Block::genesis(network), network);
        let block_pow = invalid_block.header().pow;
        let hash_from_fast_mast = invalid_block.pow_mast_paths().fast_mast_hash(block_pow);
        assert_eq!(invalid_block.hash(), hash_from_fast_mast);
    }

    #[test]
    fn bitreverse_unit_test() {
        assert_eq!(7, Pow::<10>::bitreverse(7, 3));
        assert_eq!(14, Pow::<10>::bitreverse(7, 4));
        assert_eq!(3, Pow::<10>::bitreverse(7, 2));
        assert_eq!(1, Pow::<10>::bitreverse(7, 1));
        assert_eq!(7, Pow::<10>::bitreverse(14, 4));
        assert_eq!(3, Pow::<10>::bitreverse(12, 4));
        assert_eq!(19, Pow::<10>::bitreverse(100, 7));
    }

    #[proptest]
    fn bitreverse_is_symmetric(k: u32, #[strategy(1u32..=32)] log2_n: u32) {
        let mask = u32::MAX >> (32 - log2_n);

        let r = Pow::<10>::bitreverse(k, log2_n);

        // result must be within [0, 2^log2_n)
        prop_assert!(r <= mask);

        // applying bitreverse again recovers the masked original
        let rr = Pow::<10>::bitreverse(r, log2_n);
        prop_assert_eq!(rr, k & mask);
    }

    #[test]
    fn happy_path() {
        const MERKLE_TREE_HEIGHT: usize = 10;
        let mut rng = rng();
        let auth_paths = rng.random::<PowMastPaths>();
        let prev_block_digest = rng.random();

        for consensus_rule_set in ConsensusRuleSet::iter() {
            let buffer = Pow::<MERKLE_TREE_HEIGHT>::preprocess(
                auth_paths,
                None,
                consensus_rule_set,
                prev_block_digest,
            );

            for difficulty in [2_u32, 4] {
                let difficulty = Difficulty::from(difficulty);
                let successful_guess = solve(&buffer, &auth_paths, difficulty);
                assert!(successful_guess
                    .validate(
                        auth_paths,
                        difficulty.target(),
                        consensus_rule_set,
                        prev_block_digest
                    )
                    .is_ok());
            }
        }
    }

    /// Ensure that indices cannot be reused over two proposals that share the
    /// same parent.
    #[proptest(cases = 1)]
    fn indices_depend_on_concrete_proposal_hardfork_alpha(
        #[strategy(arb())] prev_block_digest: Digest,
        #[strategy(arb())] auth_paths_1: PowMastPaths,
        #[strategy(arb())] auth_paths_2: PowMastPaths,
        #[strategy(arb())] nonce: Digest,
    ) {
        const MERKLE_TREE_HEIGHT: usize = 10;
        let buffer = Pow::<MERKLE_TREE_HEIGHT>::preprocess(
            auth_paths_1,
            None,
            ConsensusRuleSet::HardforkAlpha,
            prev_block_digest,
        );
        let indices_1 =
            Pow::<MERKLE_TREE_HEIGHT>::indices(buffer.index_picker_preimage(&auth_paths_1), nonce);
        let indices_2 =
            Pow::<MERKLE_TREE_HEIGHT>::indices(buffer.index_picker_preimage(&auth_paths_2), nonce);
        assert_ne!(indices_1, indices_2);
    }

    #[proptest(cases = 6)]
    fn guesser_buffer_can_be_reused_after_hardfork_alpha(
        #[strategy(arb())] prev_block_digest: Digest,
        #[strategy(arb())] auth_paths_1: PowMastPaths,
        #[strategy(arb())] auth_paths_2: PowMastPaths,
    ) {
        const MERKLE_TREE_HEIGHT: usize = 10;

        let buffer = Pow::<MERKLE_TREE_HEIGHT>::preprocess(
            auth_paths_1,
            None,
            ConsensusRuleSet::HardforkAlpha,
            prev_block_digest,
        );
        assert_eq!(
            buffer,
            Pow::<MERKLE_TREE_HEIGHT>::preprocess(
                auth_paths_2,
                None,
                ConsensusRuleSet::HardforkAlpha,
                prev_block_digest,
            ),
            "After hardfork, buffer must only depend on previous block hash"
        );

        // Verify that 1st block proposal can be solved
        let difficulty = Difficulty::from(2u32);
        let correct_guess_1 = solve(&buffer, &auth_paths_1, difficulty);
        assert!(correct_guess_1
            .validate(
                auth_paths_1,
                difficulty.target(),
                ConsensusRuleSet::HardforkAlpha,
                prev_block_digest
            )
            .is_ok());

        // Verify that old solution does not work when auth paths change.
        assert_eq!(
            PowValidationError::PathAInvalid,
            correct_guess_1
                .validate(
                    auth_paths_2,
                    difficulty.target(),
                    ConsensusRuleSet::HardforkAlpha,
                    prev_block_digest
                )
                .unwrap_err(),
            "2nd set of auth paths must make 1st PoW solution invalid, as pow's\
            Merkle authentication path becomes invalid"
        );

        // Verify that a 2nd proposal can use the same `buffer` value to create
        // a successful guess, and that only the `auth_paths` value needs to
        // change.
        let correct_guess_2 = solve(&buffer, &auth_paths_2, difficulty);
        assert!(correct_guess_2
            .validate(
                auth_paths_2,
                difficulty.target(),
                ConsensusRuleSet::HardforkAlpha,
                prev_block_digest
            )
            .is_ok());
    }

    fn solve<const N: usize>(
        buffer: &GuesserBuffer<N>,
        auth_paths: &PowMastPaths,
        difficulty: Difficulty,
    ) -> Pow<N> {
        assert!(
            difficulty < Difficulty::from(DIFFICULTY_LIMIT_FOR_TESTS),
            "Let's not make tests run too long"
        );

        let target = difficulty.target();
        let mut rng = rand::rng();
        let index_picker_preimage = buffer.index_picker_preimage(auth_paths);
        loop {
            let nonce = rng.random();
            if let Some(solution) =
                Pow::guess(buffer, auth_paths, index_picker_preimage, nonce, target)
            {
                break solution;
            }
        }
    }

    mod async_tests {
        use std::time::Duration;

        use futures::channel::oneshot;
        use macro_rules_attr::apply;

        use super::*;
        use crate::tests::shared_tokio_runtime;

        #[apply(shared_tokio_runtime)]
        async fn can_cancel_preprocess_within_one_second() {
            const MERKLE_TREE_HEIGHT: usize = 25; // 2.5 GB
            let mut rng = rng();
            let (tx, mut rx) = oneshot::channel::<()>();
            let mast_auth_paths = rng.random::<PowMastPaths>();

            // spawn preprocess task
            let prev_block_digest = rng.random();
            let join_handle = tokio::task::spawn_blocking(move || {
                Pow::<MERKLE_TREE_HEIGHT>::preprocess(
                    mast_auth_paths,
                    Some(&tx),
                    ConsensusRuleSet::default(),
                    prev_block_digest,
                )
            });

            // wait 0.5 millis
            tokio::time::sleep(Duration::from_micros(500)).await;

            // cancel channel
            rx.close();
            let tick = Instant::now();

            // wait 0.5 seconds
            tokio::time::sleep(Duration::from_millis(500)).await;

            // wait until preprocessing is finished
            let guesser_buffer = join_handle
                .await
                .expect("preprocessing should have aborted by now");

            // assert not too much time passed
            let elapsed = tick.elapsed();
            assert!(
                elapsed < Duration::from_secs(1),
                "elapsed time between channel-cancellation and task finish: {:?} > 1 s",
                elapsed
            );

            // assert that preprocessing was indeed aborted
            assert_eq!(guesser_buffer, GuesserBuffer::default());
        }

        #[apply(shared_tokio_runtime)]
        async fn can_cancel_merkle_tree_construction_within_two_seconds() {
            const MERKLE_TREE_HEIGHT: usize = 25; // 2.5 GB
            let num_leafs = 1 << MERKLE_TREE_HEIGHT;
            let (cancel_tx, mut cancel_rx) = oneshot::channel::<()>();
            let (start_tx, mut start_rx) = oneshot::channel::<()>();

            // spawn preprocess task
            let join_handle = tokio::task::spawn_blocking(move || {
                let leafs = vec![Digest::default(); num_leafs];
                let internal_nodes = leafs.clone();
                start_tx.send(()).unwrap();
                MTree::build_inplace(leafs, internal_nodes, Some(&cancel_tx))
            });

            // wait until we are sure the task started
            while start_rx.try_recv().unwrap().is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            // cancel channel
            cancel_rx.close();
            let tick = Instant::now();

            // wait until task is finished
            let mtree = join_handle
                .await
                .expect("preprocessing should have aborted by now");

            // assert not too much time passed
            let elapsed = tick.elapsed();
            assert!(
                elapsed < Duration::from_secs(2),
                "elapsed time between channel-cancellation and task finish: {:?} > 2 s",
                elapsed
            );

            // assert that merkle tree construction did not finish
            assert_eq!(mtree.num_leafs(), 0);
        }
    }

    mod merkle_tree_tests {
        use rand::rngs::StdRng;
        use rand::SeedableRng;
        use tasm_lib::twenty_first::prelude::MerkleTree;

        use super::*;

        #[test]
        fn roots_agree() {
            let mut rng = rng();
            let height = 10;
            let num_leafs = 1 << height;
            let leafs = (0..num_leafs).map(|_| rng.random::<Digest>()).collect_vec();
            let merkle_tree =
                MerkleTree::sequential_new(&leafs).expect("must not forget to unwrap");
            let internal_nodes = vec![Digest::default(); num_leafs];
            let mtree = MTree::build_inplace(leafs, internal_nodes, None);

            assert_eq!(mtree.root(), merkle_tree.root());
        }

        #[test]
        fn authentication_paths_agree() {
            let mut rng = rng();
            let height = 10;
            let num_leafs = 1 << height;
            let leafs = (0..num_leafs).map(|_| rng.random::<Digest>()).collect_vec();
            let index = rng.random_range(0..num_leafs);
            let merkle_tree =
                MerkleTree::sequential_new(&leafs).expect("must not forget to unwrap");
            let internal_nodes = vec![Digest::default(); num_leafs];
            let mtree = MTree::build_inplace(leafs, internal_nodes, None);

            assert_eq!(
                mtree.path(index),
                merkle_tree
                    .authentication_structure(&[index])
                    .expect("must not forget to unwrap")
            );
        }

        fn valid_root_index_path_element_tuple(
            tree_height: usize,
            seed: [u8; 32],
        ) -> (Digest, usize, Vec<Digest>, Digest) {
            let mut rng = StdRng::from_seed(seed);
            let num_leafs = 1 << tree_height;

            let leafs = (0..num_leafs).map(|_| rng.random::<Digest>()).collect_vec();
            let index = rng.random_range(0..num_leafs);
            let element = leafs[index];
            let internal_nodes = vec![Digest::default(); num_leafs];
            let mtree = MTree::build_inplace(leafs, internal_nodes, None);
            let root = mtree.root();
            let path = mtree.path(index);

            (root, index, path, element)
        }

        #[test]
        fn can_verify() {
            let mut rng = rng();
            for height in [1, 5, 10] {
                let (root, index, path, element) =
                    valid_root_index_path_element_tuple(height, rng.random());
                assert!(MTree::verify(root, index, &path, element));
            }
        }

        #[test]
        fn verify_fails_on_wrong_root() {
            let mut rng = rng();
            let height = 10;
            let (_root, index, path, element) =
                valid_root_index_path_element_tuple(height, rng.random());

            let root = rng.random();

            assert!(!MTree::verify(root, index, &path, element));
        }

        #[test]
        fn verify_fails_on_wrong_index() {
            let mut rng = rng();
            let height = 10;
            let (root, index, path, element) =
                valid_root_index_path_element_tuple(height, rng.random());

            let translation = rng.random_range(0..((1 << height) - 1));
            let index = (index + translation) % (1 << height);

            assert!(!MTree::verify(root, index, &path, element));
        }

        #[test]
        fn verify_fails_on_index_out_of_bounds() {
            let mut rng = rng();
            let height = 10;
            let (root, index, path, element) =
                valid_root_index_path_element_tuple(height, rng.random());

            let index = index + (1 << height);

            assert!(!MTree::verify(root, index, &path, element));
        }

        #[test]
        fn verify_fails_on_wrong_path() {
            let mut rng = rng();
            let height = 10;
            let (root, index, mut path, element) =
                valid_root_index_path_element_tuple(height, rng.random());

            path[rng.random_range(0..height)] = rng.random();

            assert!(!MTree::verify(root, index, &path, element));
        }

        #[test]
        fn verify_fails_on_path_too_long() {
            let mut rng = rng();
            let height = 10;
            let (root, index, mut path, element) =
                valid_root_index_path_element_tuple(height, rng.random());

            path.push(rng.random());

            assert!(!MTree::verify(root, index, &path, element));
        }

        #[test]
        fn verify_fails_on_path_too_short() {
            let mut rng = rng();
            let height = 10;
            let (root, index, mut path, element) =
                valid_root_index_path_element_tuple(height, rng.random());

            path.pop();

            assert!(!MTree::verify(root, index, &path, element));
        }

        #[test]
        fn verify_fails_on_wrong_element() {
            let mut rng = rng();
            let height = 10;
            let (root, index, path, _element) =
                valid_root_index_path_element_tuple(height, rng.random());

            let element = rng.random();

            assert!(!MTree::verify(root, index, &path, element));
        }
    }
}
