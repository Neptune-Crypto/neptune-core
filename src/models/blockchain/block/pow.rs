use std::fmt::Display;

use get_size2::GetSize;
use itertools::Itertools;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelIterator;
use rayon::iter::IntoParallelRefMutIterator;
use rayon::iter::ParallelIterator;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::twenty_first::bfe_array;
use tasm_lib::twenty_first::prelude::MerkleTree;
use tasm_lib::twenty_first::prelude::MerkleTreeInclusionProof;

use crate::models::blockchain::block::block_header::BlockHeader;
use crate::models::blockchain::block::block_kernel::BlockKernel;
use crate::models::blockchain::block::Block;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::BFieldElement;

/// Determines the number of leafs in the Merkle tree in the guesser buffer.
pub(crate) const POW_MEMORY_PARAMETER: usize = 1 << 29;
pub(crate) const POW_MEMORY_TREE_HEIGHT: usize = POW_MEMORY_PARAMETER.ilog2() as usize;
const NUM_INDEX_REPETITIONS: u32 = 63;
const NUM_BUD_LAYERS: usize = 5; // 5 => 63 Tip5 permutations per leaf
const BUDS_PER_LEAF: usize = 1 << NUM_BUD_LAYERS;

#[derive(
    Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec, TasmObject, GetSize,
)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(arbitrary::Arbitrary))]
pub struct Pow<const MERKLE_TREE_HEIGHT: usize> {
    pub(super) root: Digest,

    #[serde(with = "serde_arrays")]
    pub(super) path_a: [Digest; MERKLE_TREE_HEIGHT],

    #[serde(with = "serde_arrays")]
    pub(super) path_b: [Digest; MERKLE_TREE_HEIGHT],

    // The nonce comes at the end, so in the `BFieldCodec` encoding it comes
    // first. Therefore, you cannot store partial hashes of paths.
    pub(crate) nonce: Digest,
}

#[derive(Debug, Clone, Copy)]
pub struct PowMastPaths {
    pub(super) pow: [Digest; BlockHeader::MAST_HEIGHT],
    pub(super) header: [Digest; BlockKernel::MAST_HEIGHT],
    pub(super) kernel: [Digest; Block::MAST_HEIGHT],
}

impl PowMastPaths {
    pub(super) fn commit(&self) -> Digest {
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

    fn fast_mast_hash<const MERKLE_TREE_HEIGHT: usize>(
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
#[derive(Debug, Clone)]
pub struct GuesserBuffer<const MERKLE_TREE_HEIGHT: usize> {
    merkle_tree: MerkleTree,

    hash: Digest,

    /// Authentication paths for all fields but the PoW field
    mast_auth_paths: PowMastPaths,
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

        MerkleTree::sequential_new(&buds).unwrap().root()
    }

    fn indices(hash: Digest, nonce: Digest) -> (u64, u64) {
        let mut indexer = Tip5::hash_pair(hash, nonce);
        for _ in 1..NUM_INDEX_REPETITIONS {
            indexer = Tip5::hash_pair(indexer, Digest::default());
        }

        let index_a = indexer.values()[0].value() % (1_u64 << MERKLE_TREE_HEIGHT);
        let index_b = indexer.values()[1].value() % (1_u64 << MERKLE_TREE_HEIGHT);
        (index_a, index_b)
    }

    pub(super) fn preprocess(mast_auth_paths: PowMastPaths) -> GuesserBuffer<MERKLE_TREE_HEIGHT> {
        // Commitment to all the fields in the block that are not pow
        let commitment = mast_auth_paths.commit();

        // iterate log-many times over the buffer to compute leafs from buds
        let mut ins = (0..(1 << MERKLE_TREE_HEIGHT))
            .into_par_iter()
            .map(|i| Self::bud(commitment, i as u64))
            .collect::<Vec<_>>();
        let mut outs = ins.clone();
        let mut buds = &mut ins;
        let mut leafs = &mut outs;
        for i in 0..NUM_BUD_LAYERS {
            leafs.par_iter_mut().enumerate().for_each(|(j, leaf)| {
                *leaf = Tip5::hash_pair(buds[j], buds[(j + (1 << i)) % Self::NUM_LEAFS]);
            });
            std::mem::swap(&mut leafs, &mut buds);
        }

        std::mem::swap(&mut leafs, &mut buds);
        let merkle_tree = MerkleTree::par_new(leafs).expect("Merkle tree generation must succeeed");

        let hash = Tip5::hash_pair(merkle_tree.root(), commitment);

        GuesserBuffer::<MERKLE_TREE_HEIGHT> {
            merkle_tree,
            hash,
            mast_auth_paths,
        }
    }

    pub fn guess(
        buffer: &GuesserBuffer<MERKLE_TREE_HEIGHT>,
        nonce: Digest,
        target: Digest,
    ) -> Option<Self> {
        let root = buffer.merkle_tree.root();

        let (index_a, index_b) = Self::indices(buffer.hash, nonce);

        let path_a: [Digest; MERKLE_TREE_HEIGHT] = buffer
            .merkle_tree
            .authentication_structure(&[index_a as usize])
            .unwrap()
            .try_into()
            .unwrap();

        let path_b = buffer
            .merkle_tree
            .authentication_structure(&[index_b as usize])
            .unwrap()
            .try_into()
            .unwrap();

        let pow = Pow {
            nonce,
            root,
            path_a,
            path_b,
        };

        let pow_digest = buffer.mast_auth_paths.fast_mast_hash(pow);
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
    ) -> Result<(), PowValidationError> {
        let commitment = auth_paths.commit();
        let buffer_hash = Tip5::hash_pair(self.root, commitment);
        let (index_a, index_b) = Self::indices(buffer_hash, self.nonce);

        let path_a = MerkleTreeInclusionProof {
            tree_height: MERKLE_TREE_HEIGHT as u32,
            indexed_leafs: [(index_a as usize, Self::leaf(commitment, index_a))].to_vec(),
            authentication_structure: self.path_a.to_vec(),
        };
        if !path_a.verify(self.root) {
            return Err(PowValidationError::PathAInvalid);
        }

        let path_b = MerkleTreeInclusionProof {
            tree_height: MERKLE_TREE_HEIGHT as u32,
            indexed_leafs: [(index_b as usize, Self::leaf(commitment, index_b))].to_vec(),
            authentication_structure: self.path_b.to_vec(),
        };
        if !path_b.verify(self.root) {
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

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Instant;

    use rand::distr::Distribution;
    use rand::distr::StandardUniform;
    use rand::rng;
    use rand::Rng;
    use tasm_lib::twenty_first::bfe;

    use crate::models::blockchain::block::difficulty_control::Difficulty;

    use super::*;

    impl Distribution<PowMastPaths> for StandardUniform {
        fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> PowMastPaths {
            PowMastPaths {
                pow: rng.random(),
                header: rng.random(),
                kernel: rng.random(),
            }
        }
    }

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

    #[test]
    fn leafs_agree_with_bud_trees() {
        const MERKLE_TREE_HEIGHT: usize = 10;
        const MERKLE_TREE_NUM_LEAFS: usize = 1usize << 10;
        let mut rng = rng();
        let auth_paths = rng.random::<PowMastPaths>();
        let buffer = Pow::<MERKLE_TREE_HEIGHT>::preprocess(auth_paths);

        let index = rng.random_range(0..MERKLE_TREE_NUM_LEAFS);
        let expensive_leaf = Pow::<MERKLE_TREE_HEIGHT>::leaf(auth_paths.commit(), index as u64);
        let amortized_leaf = buffer.merkle_tree.leaf(index).unwrap();
        assert_eq!(amortized_leaf, expensive_leaf);
    }

    #[test]
    #[ignore = "benchmark of memory and time requirements of preprocess for guessing"]
    fn benchmark_memory_requirements() {
        fn report<const MERKLE_TREE_HEIGHT: usize>(auth_paths: PowMastPaths) {
            let start = Instant::now();
            let buffer = Pow::<MERKLE_TREE_HEIGHT>::preprocess(auth_paths);
            let duration = start.elapsed();
            let estimated_mt_size = buffer.merkle_tree.num_leafs() * 2 * Digest::BYTES;
            println!("Merkle tree height: {MERKLE_TREE_HEIGHT}");
            println!("estimated_mt_size: {}GB", estimated_mt_size / 1_000_000_000);
            println!("preprocess time: {} seconds\n", duration.as_secs());
        }

        let mut rng = rng();
        let auth_paths = rng.random::<PowMastPaths>();
        report::<25>(auth_paths);
        report::<26>(auth_paths);
        report::<27>(auth_paths);
        report::<28>(auth_paths);
        report::<29>(auth_paths);
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
    fn happy_path() {
        const MERKLE_TREE_HEIGHT: usize = 10;
        let mut rng = rng();
        let auth_paths = rng.random::<PowMastPaths>();
        let buffer = Pow::<MERKLE_TREE_HEIGHT>::preprocess(auth_paths);

        for difficulty in [2_u32, 4] {
            let target = Difficulty::from(difficulty).target();
            let mut successful_guess = None;
            'inner_loop: for _ in 0..120 {
                let nonce = rng.random();
                if let Some(solution) = Pow::guess(&buffer, nonce, target) {
                    successful_guess = Some(solution);
                    break 'inner_loop;
                }
            }

            assert_eq!(
                Ok(()),
                successful_guess.unwrap().validate(auth_paths, target)
            );
        }
    }
}
