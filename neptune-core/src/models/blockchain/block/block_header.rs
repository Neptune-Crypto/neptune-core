use std::fmt::Display;

#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use get_size2::GetSize;
use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumCount;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::bfe_array;
use tasm_lib::twenty_first::prelude::MerkleTree;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::math::bfield_codec::BFieldCodec;
use twenty_first::math::digest::Digest;

use super::block_height::BlockHeight;
use super::difficulty_control::difficulty_control;
use super::difficulty_control::Difficulty;
use super::difficulty_control::ProofOfWork;
use super::Block;
use crate::config_models::network::Network;
use crate::models::proof_abstractions::mast_hash::HasDiscriminant;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::prelude::twenty_first;

/// Desired/average time between blocks.
///
/// 588000 milliseconds equals 9.8 minutes.
pub(crate) const TARGET_BLOCK_INTERVAL: Timestamp = Timestamp::millis(588000);

/// Minimum time between blocks.
///
/// Blocks spaced apart by less than this amount of time are not valid.
pub(crate) const MINIMUM_BLOCK_TIME: Timestamp = Timestamp::seconds(60);

/// Controls how long to wait before the difficulty for the *next* block is
/// reduced.
///
/// Typically, the difficulty of the block's predecessor is used to determine
/// whether the new block has enough proof-of-work. But if the time difference
/// (relative to the target block interval) exceeds this parameter, the
/// difficulty is effectively reduced by a factor
/// [`ADVANCE_DIFFICULTY_CORRECTION_FACTOR`]. Consequently, if for whatever
/// reason the difficulty is set too high for the available mining power to find
/// blocks, then the network has to wait some time (without needing to find
/// blocks) before the difficulty is automatically lowered.
///
/// This parameter must be a power of two.
pub(crate) const ADVANCE_DIFFICULTY_CORRECTION_WAIT: usize = 128;

/// Controls by how much the advance difficulty correction reduces the effective
/// difficulty by.
///
/// Typically, the difficulty of the block's predecessor is used to determine
/// whether the new block has enough proof-of-work. But if the time difference
/// (relative to the target block interval) exceeds parameter
/// [`ADVANCE_DIFFICULTY_CORRECTION_WAIT`], the
/// difficulty is effectively reduced by this amount. Consequently, if for
/// whatever reason the difficulty is set too high for the available mining
/// power to find blocks, then the network has to wait some time (without
/// needing to find blocks) before the difficulty is automatically lowered.
///
/// This parameter must be a power of two.
pub(crate) const ADVANCE_DIFFICULTY_CORRECTION_FACTOR: usize = 4;

pub(crate) const BLOCK_HEADER_VERSION: BFieldElement = BFieldElement::new(0);

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec, GetSize)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(Arbitrary))]
pub struct BlockHeader {
    pub version: BFieldElement,
    pub height: BlockHeight,
    pub prev_block_digest: Digest,

    /// Time since unix epoch, in milliseconds
    pub timestamp: Timestamp,

    pub nonce: Digest,

    /// Total proof-of-work accumulated by this chain
    pub cumulative_proof_of_work: ProofOfWork,

    /// The difficulty for the *next* block. Unit: expected # hashes
    pub difficulty: Difficulty,

    /// The lock after-image for the guesser fee UTXOs
    pub(crate) guesser_digest: Digest,
}

impl Display for BlockHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = format!(
            "Height: {}\n\
            Timestamp: {}\n\
            Prev. Digest: {}\n\
            Cumulative Proof-of-Work: {}\n\
            Difficulty: {}\n\
            Version: {}\n",
            self.height,
            self.timestamp.standard_format(),
            self.prev_block_digest.to_hex(),
            self.cumulative_proof_of_work,
            self.difficulty,
            self.version
        );

        write!(f, "{}", string)
    }
}

impl BlockHeader {
    pub(crate) fn genesis(network: Network) -> Self {
        Self {
            version: BFieldElement::zero(),
            height: BFieldElement::zero().into(),
            prev_block_digest: Default::default(),
            timestamp: network.launch_date(),

            nonce: Digest::new(bfe_array![
                0x0000000000000000u64,
                0x0001db42f3edf187u64,
                0xf91d2dd95e6975deu64,
                0x272fa07267136a84u64,
                0
            ]),
            cumulative_proof_of_work: ProofOfWork::zero(),

            #[cfg(not(test))]
            difficulty: Difficulty::new([1_000_000_000, 0, 0, 0, 0]),

            // Avoid setting this too high when running tests, otherwise CI
            // fails and tests take forever.
            #[cfg(test)]
            difficulty: Difficulty::MINIMUM,

            guesser_digest: Digest::new(bfe_array![
                0x49742773206E6F6Fu64,
                0x6E20736F6D657768u64,
                0x6572652E0Au64,
                0,
                0
            ]),
        }
    }

    pub(crate) fn template_header(
        predecessor_header: &BlockHeader,
        predecessor_digest: Digest,
        timestamp: Timestamp,
        target_block_interval: Option<Timestamp>,
    ) -> BlockHeader {
        let difficulty = difficulty_control(
            timestamp,
            predecessor_header.timestamp,
            predecessor_header.difficulty,
            target_block_interval,
            predecessor_header.height,
        );

        let new_cumulative_proof_of_work: ProofOfWork =
            predecessor_header.cumulative_proof_of_work + predecessor_header.difficulty;
        Self {
            version: BLOCK_HEADER_VERSION,
            height: predecessor_header.height.next(),
            prev_block_digest: predecessor_digest,
            timestamp,
            nonce: Digest::default(),
            cumulative_proof_of_work: new_cumulative_proof_of_work,
            difficulty,
            guesser_digest: Digest::default(),
        }
    }
}

#[derive(Debug, Clone, EnumCount)]
pub enum BlockHeaderField {
    Version,
    Height,
    PrevBlockDigest,
    Timestamp,
    Nonce,
    CumulativeProofOfWork,
    Difficulty,
    GusserDigest,
}

impl HasDiscriminant for BlockHeaderField {
    fn discriminant(&self) -> usize {
        self.clone() as usize
    }
}

impl MastHash for BlockHeader {
    type FieldEnum = BlockHeaderField;

    fn mast_sequences(&self) -> Vec<Vec<BFieldElement>> {
        vec![
            self.version.encode(),
            self.height.encode(),
            self.prev_block_digest.encode(),
            self.timestamp.encode(),
            self.nonce.encode(),
            self.cumulative_proof_of_work.encode(),
            self.difficulty.encode(),
            self.guesser_digest.encode(),
        ]
    }
}

/// The data needed to calculate the block hash, apart from the data present
/// in the block header.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeaderToBlockHashWitness {
    /// The "body" leaf of the Merkle tree from which block hash is calculated.
    body_leaf: Digest,

    /// The "appendix" leaf of the Merkle tree from which block hash is
    /// calculated.
    appendix_leaf: Digest,
}

impl From<&Block> for HeaderToBlockHashWitness {
    fn from(value: &Block) -> Self {
        Self {
            body_leaf: Tip5::hash_varlen(&value.body().mast_hash().encode()),
            appendix_leaf: Tip5::hash_varlen(&value.appendix().encode()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct BlockHeaderWithBlockHashWitness {
    pub(crate) header: BlockHeader,
    witness: HeaderToBlockHashWitness,
}

impl BlockHeaderWithBlockHashWitness {
    pub(crate) fn new(header: BlockHeader, witness: HeaderToBlockHashWitness) -> Self {
        Self { header, witness }
    }

    pub(crate) fn hash(&self) -> Digest {
        let block_header_leaf = Tip5::hash_varlen(&self.header.mast_hash().encode());
        let leafs = [
            block_header_leaf,
            self.witness.body_leaf,
            self.witness.appendix_leaf,
            Digest::default(),
        ];
        MerkleTree::sequential_new(&leafs).unwrap().root()
    }

    pub(crate) fn is_successor_of(&self, parent: &Self) -> bool {
        self.header.prev_block_digest == parent.hash()
    }
}

#[cfg(test)]
pub(crate) mod block_header_tests {
    use rand::Rng;

    use super::*;
    use crate::models::blockchain::block::validity::block_primitive_witness::test::deterministic_block_primitive_witness;

    pub fn random_block_header() -> BlockHeader {
        let mut rng = rand::rng();
        BlockHeader {
            version: rng.random(),
            height: BlockHeight::from(rng.random::<u64>()),
            prev_block_digest: rng.random(),
            timestamp: rng.random(),
            nonce: rng.random(),
            cumulative_proof_of_work: ProofOfWork::new(
                rng.random::<[u32; ProofOfWork::NUM_LIMBS]>(),
            ),
            difficulty: Difficulty::new(rng.random::<[u32; Difficulty::NUM_LIMBS]>()),
            guesser_digest: rng.random(),
        }
    }
    #[test]
    pub fn test_block_header_decode() {
        let block_header = random_block_header();
        let encoded = block_header.encode();
        let decoded = *BlockHeader::decode(&encoded).unwrap();
        assert_eq!(block_header, decoded);
    }

    #[test]
    fn advance_difficulty_correction_parameters_are_powers_of_two() {
        assert_eq!(
            ADVANCE_DIFFICULTY_CORRECTION_WAIT,
            1 << ADVANCE_DIFFICULTY_CORRECTION_WAIT.ilog2()
        );
        assert_eq!(
            ADVANCE_DIFFICULTY_CORRECTION_FACTOR,
            1 << ADVANCE_DIFFICULTY_CORRECTION_FACTOR.ilog2()
        );
    }

    #[test]
    fn witness_agrees_with_block_hash() {
        let block_primitive_witness = deterministic_block_primitive_witness();
        let block = Block::block_template_invalid_proof_from_witness(
            block_primitive_witness,
            Timestamp::now(),
            None,
        );
        let expected = block.hash();
        let witness: HeaderToBlockHashWitness = (&block).into();
        let calculated = BlockHeaderWithBlockHashWitness::new(*block.header(), witness).hash();
        assert_eq!(expected, calculated);
    }
}
