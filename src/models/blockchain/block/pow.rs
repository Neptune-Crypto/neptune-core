use std::fmt::Display;

use get_size2::GetSize;
use itertools::Itertools;
use rand::distr::Distribution;
use rand::distr::StandardUniform;
use rand::Rng;
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
use crate::models::blockchain::block::block_header::BlockHeaderField;
use crate::models::blockchain::block::block_kernel::BlockKernel;
use crate::models::blockchain::block::block_kernel::BlockKernelField;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::block::BlockField;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::BFieldElement;

/// Determines the number of leafs in the Merkle tree in the guesser buffer.
pub(crate) const POW_MEMORY_PARAMETER: usize = 1 << 31;
const NUM_LEAF_REPETITIONS: u32 = 41;
const NUM_INDEX_REPETITIONS: u32 = 41;

#[derive(
    Copy,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    BFieldCodec,
    TasmObject,
    GetSize,
    Default,
)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(arbitrary::Arbitrary))]
pub struct Pow {
    pub(super) root: Digest,
    pub(super) paths: [[Digest; POW_MEMORY_PARAMETER.ilog2() as usize]; 2],
    pub(crate) nonce: Digest,
}

impl Distribution<Pow> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Pow {
        Pow {
            root: rng.random(),
            paths: rng.random(),
            nonce: rng.random(),
        }
    }
}

impl Display for Pow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = format!(
            "nonce: {}\n\
            root: {}\n\
            paths: {}\n{}\n",
            self.nonce.to_hex(),
            self.root.to_hex(),
            self.paths[0].iter().join(","),
            self.paths[1].iter().join(","),
        );

        write!(f, "{}", string)
    }
}

pub struct GuesserBuffer {
    merkle_tree: MerkleTree,

    hash: Digest,
}

fn leaf(body_mast_hash: Digest, index: u64) -> Digest {
    let mut digest = Tip5::hash_pair(body_mast_hash, Digest::new(bfe_array![index, 0, 0, 0, 0]));
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

    let index_a = indexer.values()[0].value() % (POW_MEMORY_PARAMETER as u64);
    let index_b = indexer.values()[1].value() % (POW_MEMORY_PARAMETER as u64);
    (index_a, index_b)
}

fn auth_paths_from_block(
    block: &Block,
) -> (
    [Digest; BlockHeader::MAST_HEIGHT],
    [Digest; BlockKernel::MAST_HEIGHT],
    [Digest; Block::MAST_HEIGHT],
) {
    let auth_path_pow = BlockHeader::mast_path(block.header(), BlockHeaderField::Pow)
        .try_into()
        .unwrap();
    let auth_path_header = BlockKernel::mast_path(&block.kernel, BlockKernelField::Header)
        .try_into()
        .unwrap();
    let auth_path_kernel = Block::mast_path(block, BlockField::Kernel)
        .try_into()
        .unwrap();

    (auth_path_pow, auth_path_header, auth_path_kernel)
}

fn commitment_from_block(block_template: &Block) -> Digest {
    let (auth_path_pow, auth_path_header, auth_path_kernel) = auth_paths_from_block(block_template);
    commitment_from_auth_paths(auth_path_pow, auth_path_header, auth_path_kernel)
}

fn commitment_from_auth_paths(
    auth_path_pow: [Digest; BlockHeader::MAST_HEIGHT],
    auth_path_header: [Digest; BlockKernel::MAST_HEIGHT],
    auth_path_kernel: [Digest; Block::MAST_HEIGHT],
) -> Digest {
    Tip5::hash_varlen(
        &[
            auth_path_pow.to_vec(),
            auth_path_header.to_vec(),
            auth_path_kernel.to_vec(),
        ]
        .into_iter()
        .flatten()
        .flat_map(|d| d.values())
        .collect_vec(),
    )
}

fn preprocess(
    body_mast_hash: Digest,
    auth_path_pow: [Digest; BlockHeader::MAST_HEIGHT],
    auth_path_header: [Digest; BlockKernel::MAST_HEIGHT],
    auth_path_kernel: [Digest; Block::MAST_HEIGHT],
) -> GuesserBuffer {
    let body_as_mt_leaf = Tip5::hash_varlen(&body_mast_hash.encode());
    let leafs = (0..(POW_MEMORY_PARAMETER / 2))
        .into_par_iter()
        .map(|i| leaf(body_as_mt_leaf, i as u64))
        .collect::<Vec<_>>();

    let merkle_tree = MerkleTree::par_new(&leafs).expect("Merkle tree generation must succeeed");

    // Commitment to all the fields in the block that are not pow
    let commitment = commitment_from_auth_paths(auth_path_pow, auth_path_header, auth_path_kernel);

    let hash = Tip5::hash_pair(merkle_tree.root(), commitment);

    GuesserBuffer { merkle_tree, hash }
}

fn preprocess_from_block(block_template: &Block) -> GuesserBuffer {
    let body_mast_hash = block_template.body().mast_hash();
    let (auth_path_pow, auth_path_header, auth_path_kernel) = auth_paths_from_block(block_template);
    preprocess(
        body_mast_hash,
        auth_path_pow,
        auth_path_header,
        auth_path_kernel,
    )
}

fn block_hash_from_pow(
    auth_path_pow: [Digest; BlockHeader::MAST_HEIGHT],
    auth_path_header: [Digest; BlockKernel::MAST_HEIGHT],
    auth_path_kernel: [Digest; Block::MAST_HEIGHT],
    pow: Pow,
) -> Digest {
    // 41 permutations to get the block hash
    let header_mast_hash = Tip5::hash_pair(Tip5::hash_varlen(&pow.encode()), auth_path_pow[0]);
    let header_mast_hash = Tip5::hash_pair(header_mast_hash, auth_path_pow[1]);
    let header_mast_hash = Tip5::hash_pair(auth_path_pow[2], header_mast_hash);

    let kernel_mast_hash = Tip5::hash_pair(
        Tip5::hash_varlen(&header_mast_hash.encode()),
        auth_path_header[0],
    );
    let kernel_mast_hash = Tip5::hash_pair(kernel_mast_hash, auth_path_header[1]);

    Tip5::hash_pair(
        Tip5::hash_varlen(&kernel_mast_hash.encode()),
        auth_path_kernel[0],
    )
}

fn guess(
    auth_path_pow: [Digest; BlockHeader::MAST_HEIGHT],
    auth_path_header: [Digest; BlockKernel::MAST_HEIGHT],
    auth_path_kernel: [Digest; Block::MAST_HEIGHT],
    buffer: &GuesserBuffer,
    nonce: Digest,
    target: Digest,
) -> Option<[[Digest; POW_MEMORY_PARAMETER.ilog2() as usize]; 2]> {
    let root = buffer.merkle_tree.root();

    let (index_a, index_b) = indices(buffer.hash, nonce);

    let path_a = buffer
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
        paths: [path_a, path_b],
    };

    let pow_digest = block_hash_from_pow(auth_path_pow, auth_path_header, auth_path_kernel, pow);
    if pow_digest > target {
        None
    } else {
        Some([path_a.try_into().unwrap(), path_b.try_into().unwrap()])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowValidationError {
    PathAInvalid,
    PathBInvalid,
    ThresholdNotMet,
}

fn validate(
    auth_path_pow: [Digest; BlockHeader::MAST_HEIGHT],
    auth_path_header: [Digest; BlockKernel::MAST_HEIGHT],
    auth_path_kernel: [Digest; Block::MAST_HEIGHT],
    pow: Pow,
    target: Digest,
) -> Result<(), PowValidationError> {
    let body_as_sibling = auth_path_header[0];
    let commitment = commitment_from_auth_paths(auth_path_pow, auth_path_header, auth_path_kernel);
    let buffer_hash = Tip5::hash_pair(pow.root, commitment);
    let (index_a, index_b) = indices(buffer_hash, pow.nonce);

    let path_a = MerkleTreeInclusionProof {
        tree_height: POW_MEMORY_PARAMETER.ilog2(),
        indexed_leafs: [(index_a as usize, leaf(body_as_sibling, index_a))].to_vec(),
        authentication_structure: pow.paths[0].to_vec(),
    };
    if !path_a.verify(pow.root) {
        return Err(PowValidationError::PathAInvalid);
    }

    let path_b = MerkleTreeInclusionProof {
        tree_height: POW_MEMORY_PARAMETER.ilog2(),
        indexed_leafs: [(index_b as usize, leaf(body_as_sibling, index_b))].to_vec(),
        authentication_structure: pow.paths[1].to_vec(),
    };
    if !path_b.verify(pow.root) {
        return Err(PowValidationError::PathBInvalid);
    }

    let block_hash = block_hash_from_pow(auth_path_pow, auth_path_header, auth_path_kernel, pow);
    let meets_threshold = block_hash <= target;
    if !meets_threshold {
        return Err(PowValidationError::ThresholdNotMet);
    }

    Ok(())
}

fn verify_from_block(block: &Block, target: Digest) -> bool {
    let auth_path_pow = block
        .header()
        .mast_path(BlockHeaderField::Pow)
        .try_into()
        .unwrap();
    let auth_path_header = block
        .kernel
        .mast_path(BlockKernelField::Header)
        .try_into()
        .unwrap();
    let auth_path_kernel = block.mast_path(BlockField::Kernel).try_into().unwrap();
    let pow = block.header().pow;
    validate(
        auth_path_pow,
        auth_path_header,
        auth_path_kernel,
        pow,
        target,
    )
    .is_ok()
}
