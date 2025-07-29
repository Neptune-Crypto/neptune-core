use std::fmt::Display;

use get_size2::GetSize;
use itertools::Itertools;
use rayon::iter::IntoParallelIterator;
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
pub(crate) const POW_MEMORY_PARAMETER: usize = 1 << 31;
pub(crate) const POW_MEMORY_TREE_HEIGHT: usize = POW_MEMORY_PARAMETER.ilog2() as usize;
const NUM_LEAF_REPETITIONS: u32 = 41;
const NUM_INDEX_REPETITIONS: u32 = 41;

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
        // 41 permutations to get the block hash
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

    fn leaf(commitment: Digest, index: u64) -> Digest {
        let mut digest = Tip5::hash_pair(commitment, Digest::new(bfe_array![index, 0, 0, 0, 0]));
        for _ in 1..NUM_LEAF_REPETITIONS {
            digest = Tip5::hash_pair(digest, Digest::default());
        }

        digest
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

        let leafs = (0..(1 << MERKLE_TREE_HEIGHT))
            .into_par_iter()
            .map(|i| Self::leaf(commitment, i as u64))
            .collect::<Vec<_>>();

        let merkle_tree =
            MerkleTree::par_new(&leafs).expect("Merkle tree generation must succeeed");

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
    use rand::distr::{Distribution, StandardUniform};
    use rand::{rng, Rng};
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
    fn nonce_comes_first_in_pow_encoding() {
        // Ensures that auth path hashes cannot be pre-calculated (i.e., before
        // the nonce is known). Otherwise the user might be able to get around
        // the magical 41 required permutations for one guess-equivalent.
        let pow = Pow::<10> {
            nonce: Digest::new(bfe_array![1;5]),
            ..Default::default()
        };
        let encoding = pow.encode();
        for i in 0..Digest::LEN {
            assert_eq!(bfe!(1), encoding[i]);
        }
        for i in Digest::LEN..encoding.len() {
            assert_eq!(bfe!(0), encoding[i]);
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
