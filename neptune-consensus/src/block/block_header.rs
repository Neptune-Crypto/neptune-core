use std::fmt::Display;

#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use get_size2::GetSize;
use neptune_primitives::block_height::BlockHeight;
use neptune_primitives::difficulty_control::difficulty_control;
use neptune_primitives::difficulty_control::Difficulty;
use neptune_primitives::difficulty_control::ProofOfWork;
use neptune_primitives::mast_hash::HasDiscriminant;
use neptune_primitives::mast_hash::MastHash;
use neptune_primitives::network::Network;
use neptune_primitives::timestamp::Timestamp;
use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumCount;
use tasm_lib::prelude::TasmObject;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::bfe_array;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::prelude::MerkleTree;
use tasm_lib::twenty_first::tip5::digest::Digest;

use super::Block;
use super::BlockField;
use crate::block::block_kernel::BlockKernelField;
use crate::block::guesser_receiver_data::GuesserReceiverData;
use crate::block::pow::Pow;
use crate::block::pow::PowMastPaths;
use crate::consensus_rule_set::ConsensusRuleSet;

pub const BLOCK_HEADER_VERSION: BFieldElement = BFieldElement::new(0);

pub type BlockPow = Pow<{ crate::block::pow::POW_MEMORY_TREE_HEIGHT }>;

#[derive(
    Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec, TasmObject, GetSize,
)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(Arbitrary))]
pub struct BlockHeader {
    pub version: BFieldElement,
    pub height: BlockHeight,
    pub prev_block_digest: Digest,

    /// Time since unix epoch, in milliseconds
    pub timestamp: Timestamp,

    pub pow: BlockPow,

    /// Total proof-of-work accumulated by this chain
    pub cumulative_proof_of_work: ProofOfWork,

    /// The difficulty for the *next* block. Unit: expected # hashes
    pub difficulty: Difficulty,

    /// Information for the guesser to take custody of the guesser UTXOs.
    pub guesser_receiver_data: GuesserReceiverData,
}

impl Display for BlockHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = format!(
            "Height: {}\n\
            Timestamp: {}\n\
            Prev. Digest: {:x}\n\
            Cumulative Proof-of-Work: {}\n\
            Difficulty: {}\n\
            Version: {}\n\
            Guesser receiver digest: {:x}\n\
            Guesser lock script hash: {:x}\n\
            pow: {}\n",
            self.height,
            self.timestamp.standard_format(),
            self.prev_block_digest,
            self.cumulative_proof_of_work,
            self.difficulty,
            self.version,
            self.guesser_receiver_data.receiver_digest,
            self.guesser_receiver_data.lock_script_hash,
            self.pow
        );

        write!(f, "{}", string)
    }
}

impl BlockHeader {
    pub fn genesis(network: Network) -> Self {
        Self {
            version: BFieldElement::zero(),
            height: BFieldElement::zero().into(),
            prev_block_digest: Default::default(),
            timestamp: network.launch_date(),

            pow: Pow {
                // Bitcoin block at height 908766
                nonce: Digest::new(bfe_array![
                    0x0000000000000000u64,
                    0x0000fcefca46c809u64,
                    0xda3f97528a19e8c3u64,
                    0xf3a1a10f3888004du64,
                    0
                ]),
                path_a: [Digest::default(); BlockPow::MERKLE_TREE_HEIGHT],
                path_b: [Digest::default(); BlockPow::MERKLE_TREE_HEIGHT],
                // 49b65c974fa81f3e6f2f87aec83ada68236af11c284ed263c5965b6ae3644d100f5a2b594d4b810a
                // is mutator set hash after block 21310 on legacy chain
                root: Digest::new(bfe_array![
                    0x49b65c974fa81f3eu64,
                    0x6f2f87aec83ada68u64,
                    0x236af11c284ed263u64,
                    0xc5965b6ae3644d10u64,
                    0x0f5a2b594d4b810au64
                ]),
            },
            cumulative_proof_of_work: ProofOfWork::zero(),

            difficulty: network.genesis_difficulty(),

            guesser_receiver_data: GuesserReceiverData {
                receiver_digest: Digest::new(bfe_array![
                    0x5472756D7020746Fu64,
                    0x20546F7572204665u64,
                    0x646572616C205265u64,
                    0x73657276652C2052u64,
                    0x616D70696E672055u64
                ]),
                lock_script_hash: Digest::new(bfe_array![
                    0x7020507265737375u64,
                    0x72652043616D7061u64,
                    0x69676E206F6E2050u64,
                    0x6F77656C6C000000u64,
                    0x0A57534A00000000u64
                ]),
            },
        }
    }

    pub fn template_header(
        predecessor_header: &BlockHeader,
        predecessor_digest: Digest,
        timestamp: Timestamp,
        target_block_interval: Timestamp,
        network: Network,
    ) -> BlockHeader {
        let difficulty = difficulty_control(
            timestamp,
            predecessor_header.timestamp,
            predecessor_header.difficulty,
            target_block_interval,
            predecessor_header.height,
        );

        let new_height = predecessor_header.height.next();
        let consensus_rules = ConsensusRuleSet::infer_from(network, new_height);
        let delta_cum_pow = if consensus_rules.use_parent_difficulty() {
            predecessor_header.difficulty
        } else {
            difficulty
        };
        let new_cumulative_proof_of_work: ProofOfWork =
            predecessor_header.cumulative_proof_of_work + delta_cum_pow;
        Self {
            version: BLOCK_HEADER_VERSION,
            height: new_height,
            prev_block_digest: predecessor_digest,
            timestamp,
            pow: Pow::default(),
            cumulative_proof_of_work: new_cumulative_proof_of_work,
            difficulty,
            guesser_receiver_data: GuesserReceiverData {
                receiver_digest: Digest::default(),
                lock_script_hash: Digest::default(),
            },
        }
    }

    pub fn was_guessed_by(&self, guesser_receiver_data: &GuesserReceiverData) -> bool {
        self.guesser_receiver_data == *guesser_receiver_data
    }
}

#[derive(Debug, Copy, Clone, EnumCount)]
pub enum BlockHeaderField {
    Version,
    Height,
    PrevBlockDigest,
    Timestamp,
    Pow,
    CumulativeProofOfWork,
    Difficulty,
    GuesserReceiverData,
}

impl HasDiscriminant for BlockHeaderField {
    fn discriminant(&self) -> usize {
        *self as usize
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
            self.pow.encode(),
            self.cumulative_proof_of_work.encode(),
            self.difficulty.encode(),
            self.guesser_receiver_data.encode(),
        ]
    }
}

/// The data needed to calculate the block hash, apart from the data present
/// in the block header.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeaderToBlockHashWitness {
    /// The "body" leaf of the Merkle tree from which block kernel MAST hash is
    /// calculated.
    body_leaf: Digest,

    /// The "appendix" leaf of the Merkle tree from which block kernel MAST hash
    /// is calculated.
    appendix_leaf: Digest,

    /// The "proof" leaf of the Merkle tree from which block hash is calculated.
    proof_leaf: Digest,
}

impl From<&Block> for HeaderToBlockHashWitness {
    fn from(value: &Block) -> Self {
        Self {
            body_leaf: Tip5::hash_varlen(&value.body().mast_hash().encode()),
            appendix_leaf: Tip5::hash_varlen(&value.appendix().encode()),
            proof_leaf: Tip5::hash_varlen(&value.proof.encode()),
        }
    }
}

impl HeaderToBlockHashWitness {
    pub fn proof_leaf(&self) -> Digest {
        self.proof_leaf
    }
}

/// The reasons why a block header, with a witness to its block hash, can fail
/// [validation against its parent](BlockHeaderWithBlockHashWitness::validate_against_parent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BlockHeaderValidationError {
    #[error("block height must equal that of predecessor plus one")]
    BlockHeight,
    #[error("target difficulty must be updated correctly")]
    Difficulty,
    #[error("block cumulative proof-of-work must be updated correctly")]
    CumulativeProofOfWork,
    #[error("block must have sufficient proof of work")]
    ProofOfWork,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockHeaderWithBlockHashWitness {
    pub(crate) header: BlockHeader,
    witness: HeaderToBlockHashWitness,
}

impl BlockHeaderWithBlockHashWitness {
    pub fn new(header: BlockHeader, witness: HeaderToBlockHashWitness) -> Self {
        Self { header, witness }
    }

    /// The MAST authentication paths that verifying the proof of work needs.
    /// Agree with [`Block::pow_mast_paths`] for the block the witness is from.
    fn pow_mast_paths(&self) -> PowMastPaths {
        let pow = self
            .header
            .mast_path(BlockHeaderField::Pow)
            .try_into()
            .unwrap();

        let block_header_leaf = Tip5::hash_varlen(&self.header.mast_hash().encode());
        let kernel_tree = MerkleTree::sequential_new(&[
            block_header_leaf,
            self.witness.body_leaf,
            self.witness.appendix_leaf,
            Digest::default(),
        ])
        .unwrap();
        let header = kernel_tree
            .authentication_structure(&[BlockKernelField::Header.discriminant()])
            .unwrap()
            .try_into()
            .unwrap();

        let block_tree = MerkleTree::sequential_new(&[
            Tip5::hash_varlen(&kernel_tree.root().encode()),
            self.witness.proof_leaf,
        ])
        .unwrap();
        let kernel = block_tree
            .authentication_structure(&[BlockField::Kernel.discriminant()])
            .unwrap()
            .try_into()
            .unwrap();

        PowMastPaths {
            pow,
            header,
            kernel,
        }
    }

    /// Check what the header and the witness can vouch for about the block:
    /// that height, difficulty and cumulative proof of work follow from the
    /// parent's, and that the proof of work meets the target. Says nothing
    /// about the block's body or proof.
    ///
    /// `parent` must be the header of the block that `prev_block_digest`
    /// refers to; this is not checked here. Only blocks whose own difficulty
    /// dictates the target, as all blocks since
    /// [`ConsensusRuleSet::HardforkBeta`] do, are handled.
    pub fn validate_against_parent(
        &self,
        parent: &BlockHeader,
        network: Network,
    ) -> Result<(), BlockHeaderValidationError> {
        let header = &self.header;
        if parent.height.next() != header.height {
            return Err(BlockHeaderValidationError::BlockHeight);
        }

        let difficulty_is_reset =
            Block::should_reset_difficulty(network, header.timestamp, parent.timestamp);
        let expected_difficulty = if difficulty_is_reset {
            network.genesis_difficulty()
        } else {
            difficulty_control(
                header.timestamp,
                parent.timestamp,
                parent.difficulty,
                network.target_block_interval(),
                parent.height,
            )
        };
        if header.difficulty != expected_difficulty {
            return Err(BlockHeaderValidationError::Difficulty);
        }

        if header.cumulative_proof_of_work != parent.cumulative_proof_of_work + header.difficulty {
            return Err(BlockHeaderValidationError::CumulativeProofOfWork);
        }

        // Like `Block::has_proof_of_work`, demand no proof of work from a block
        // that resets the difficulty.
        if difficulty_is_reset {
            return Ok(());
        }
        let target = header.difficulty.target();
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, header.height);
        let has_proof_of_work = if network.allows_mock_pow() {
            self.hash() <= target
        } else {
            header
                .pow
                .validate(
                    self.pow_mast_paths(),
                    target,
                    consensus_rule_set,
                    header.prev_block_digest,
                )
                .is_ok()
        };
        if !has_proof_of_work {
            return Err(BlockHeaderValidationError::ProofOfWork);
        }

        Ok(())
    }

    /// The block header.
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// Mutable access to the block header.
    pub fn header_mut(&mut self) -> &mut BlockHeader {
        &mut self.header
    }

    pub fn hash(&self) -> Digest {
        let block_header_leaf = Tip5::hash_varlen(&self.header.mast_hash().encode());
        let kernel_leafs = [
            block_header_leaf,
            self.witness.body_leaf,
            self.witness.appendix_leaf,
            Digest::default(),
        ];
        let kernel_hash = MerkleTree::sequential_frugal_root(&kernel_leafs).unwrap();
        let block_leafs = [
            Tip5::hash_varlen(&kernel_hash.encode()),
            self.witness.proof_leaf,
        ];
        MerkleTree::sequential_frugal_root(&block_leafs).unwrap()
    }

    pub fn is_successor_of(&self, parent: &Self) -> bool {
        self.header.prev_block_digest == parent.hash()
    }
}

#[cfg(any(feature = "mock-rpc", feature = "test-helpers", test))]
impl rand::distr::Distribution<BlockHeader> for rand::distr::StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> BlockHeader {
        use rand::RngExt;
        BlockHeader {
            version: rng.random(),
            height: rng.random(),
            prev_block_digest: rng.random(),
            timestamp: rng.random(),
            pow: rng.random(),
            cumulative_proof_of_work: rng.random(),
            difficulty: rng.random(),
            guesser_receiver_data: rng.random(),
        }
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl BlockHeader {
    pub fn arbitrary_with_height_and_difficulty(
        height: BlockHeight,
        difficulty: Difficulty,
    ) -> proptest::prelude::BoxedStrategy<Self> {
        use proptest::prelude::Strategy;
        use proptest_arbitrary_interop::arb;

        let version = arb::<BFieldElement>();
        let prev_block_digest = arb::<Digest>();
        let timestamp = arb::<Timestamp>();
        let pow = arb::<BlockPow>();
        let cumulative_proof_of_work = arb::<ProofOfWork>();
        let guesser_receiver_data = arb::<GuesserReceiverData>();

        (
            version,
            prev_block_digest,
            timestamp,
            pow,
            cumulative_proof_of_work,
            guesser_receiver_data,
        )
            .prop_map(
                move |(
                    version,
                    prev_block_digest,
                    timestamp,
                    pow,
                    cumulative_proof_of_work,
                    guesser_receiver_data,
                )| {
                    BlockHeader {
                        version,
                        height,
                        prev_block_digest,
                        timestamp,
                        pow,
                        cumulative_proof_of_work,
                        difficulty,
                        guesser_receiver_data,
                    }
                },
            )
            .boxed()
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl BlockHeader {
    pub fn set_nonce(&mut self, nonce: Digest) {
        self.pow.nonce = nonce;
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use rand::rng;
    use rand::RngExt;

    use super::*;
    use crate::block::test_helpers::invalid_empty_block;
    use crate::block::test_helpers::invalid_empty_block_with_proof_size;

    proptest::proptest! {
        #[test]
        fn test_block_header_decode(block_header in proptest_arbitrary_interop::arb::<BlockHeader>()) {
            let encoded = block_header.encode();
            let decoded = *BlockHeader::decode(&encoded).unwrap();
            assert_eq!(block_header, decoded);
        }
    }

    #[test]
    fn header_with_witness_is_validated_against_parent() {
        let network = Network::Testnet(42);
        let genesis = Block::genesis(network);
        let parent = genesis.header();
        let mut block = invalid_empty_block(&genesis, network);
        let with_witness =
            |block: &Block| BlockHeaderWithBlockHashWitness::new(*block.header(), block.into());
        let target = block.header().difficulty.target();

        let mut insufficient_pow = with_witness(&block);
        while insufficient_pow.hash() <= target {
            insufficient_pow.header.pow.nonce = rng().random();
        }
        assert_eq!(
            Err(BlockHeaderValidationError::ProofOfWork),
            insufficient_pow.validate_against_parent(parent, network)
        );

        let consensus_rule_set = ConsensusRuleSet::infer_from(network, block.header().height);
        block.satisfy_pow(parent.difficulty, consensus_rule_set);
        assert!(block.has_proof_of_work(network, parent));
        let valid = with_witness(&block);
        assert_eq!(Ok(()), valid.validate_against_parent(parent, network));

        // The proof of work commits to the whole block, so a different body
        // invalidates it.
        let mut other_body = valid.clone();
        while other_body.hash() <= target {
            other_body.witness.body_leaf = rng().random();
        }
        assert_eq!(
            Err(BlockHeaderValidationError::ProofOfWork),
            other_body.validate_against_parent(parent, network)
        );

        let mut wrong_height = valid.clone();
        wrong_height.header.height = valid.header.height.next();
        assert_eq!(
            Err(BlockHeaderValidationError::BlockHeight),
            wrong_height.validate_against_parent(parent, network)
        );

        let mut wrong_difficulty = valid.clone();
        wrong_difficulty.header.difficulty = Difficulty::new([u32::MAX, 0, 0, 0, 0]);
        assert_eq!(
            Err(BlockHeaderValidationError::Difficulty),
            wrong_difficulty.validate_against_parent(parent, network)
        );

        let mut wrong_cumulative_pow = valid.clone();
        wrong_cumulative_pow.header.cumulative_proof_of_work = parent.cumulative_proof_of_work;
        assert_eq!(
            Err(BlockHeaderValidationError::CumulativeProofOfWork),
            wrong_cumulative_pow.validate_against_parent(parent, network)
        );
    }

    #[test]
    fn witness_agrees_with_block_hash() {
        let network = Network::Main;
        let genesis = Block::genesis(network);
        let mut rng = rng();

        // Use non-empty proof to ensure the proof is correctly accounted for
        // in calculated block hash.
        let proof_size = rng.random_range(0..100);
        let block = invalid_empty_block_with_proof_size(&genesis, network, proof_size);
        let expected = block.hash();
        let witness: HeaderToBlockHashWitness = (&block).into();
        let calculated = BlockHeaderWithBlockHashWitness::new(*block.header(), witness).hash();
        assert_eq!(expected, calculated);
    }

    #[test]
    fn block_header_display_impl() {
        let block_header = rng().random::<BlockHeader>();
        println!("{block_header}");
    }
}
