use std::fmt::Display;

#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use get_size2::GetSize;
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

use super::block_height::BlockHeight;
use super::difficulty_control::difficulty_control;
use super::difficulty_control::Difficulty;
use super::difficulty_control::ProofOfWork;
use super::Block;
use crate::api::export::ReceivingAddress;
use crate::application::config::network::Network;
use crate::protocol::consensus::block::guesser_receiver_data::GuesserReceiverData;
use crate::protocol::consensus::block::pow::Pow;
use crate::protocol::proof_abstractions::mast_hash::HasDiscriminant;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::protocol::proof_abstractions::timestamp::Timestamp;

pub(crate) const BLOCK_HEADER_VERSION: BFieldElement = BFieldElement::new(0);

pub type BlockPow = Pow<{ crate::protocol::consensus::block::pow::POW_MEMORY_TREE_HEIGHT }>;

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
    pub(crate) fn genesis(network: Network) -> Self {
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

            #[cfg(not(test))]
            difficulty: network.genesis_difficulty(),

            // Avoid setting this too high when running tests, otherwise CI
            // fails and tests take forever.
            #[cfg(test)]
            difficulty: Difficulty::MINIMUM,

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

    pub(crate) fn template_header(
        predecessor_header: &BlockHeader,
        predecessor_digest: Digest,
        timestamp: Timestamp,
        target_block_interval: Timestamp,
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
            pow: Pow::default(),
            cumulative_proof_of_work: new_cumulative_proof_of_work,
            difficulty,
            guesser_receiver_data: GuesserReceiverData {
                receiver_digest: Digest::default(),
                lock_script_hash: Digest::default(),
            },
        }
    }

    pub fn was_guessed_by(&self, address: &ReceivingAddress) -> bool {
        let address_receiver_digest = address.privacy_digest();
        let address_lock_script_hash = address.lock_script_hash();
        self.guesser_receiver_data.receiver_digest == address_receiver_digest
            && self.guesser_receiver_data.lock_script_hash == address_lock_script_hash
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

    pub(crate) fn is_successor_of(&self, parent: &Self) -> bool {
        self.header.prev_block_digest == parent.hash()
    }
}

#[cfg(any(test, feature = "arbitrary-impls"))]
impl BlockHeader {
    pub(crate) fn arbitrary_with_height_and_difficulty(
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

#[cfg(feature = "mock-rpc")]
impl rand::distr::Distribution<BlockHeader> for rand::distr::StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> BlockHeader {
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use rand::rng;
    use rand::Rng;

    use super::*;
    use crate::tests::shared::blocks::invalid_empty_block_with_proof_size;

    impl BlockHeader {
        pub(crate) fn set_nonce(&mut self, nonce: Digest) {
            self.pow.nonce = nonce;
        }
    }

    pub(crate) fn random_block_header() -> BlockHeader {
        let mut rng = rand::rng();
        BlockHeader {
            version: rng.random(),
            height: BlockHeight::from(rng.random::<u64>()),
            prev_block_digest: rng.random(),
            timestamp: rng.random(),
            pow: rng.random(),
            cumulative_proof_of_work: ProofOfWork::new(
                rng.random::<[u32; ProofOfWork::NUM_LIMBS]>(),
            ),
            difficulty: Difficulty::new(rng.random::<[u32; Difficulty::NUM_LIMBS]>()),
            guesser_receiver_data: GuesserReceiverData {
                receiver_digest: rng.random(),
                lock_script_hash: rng.random(),
            },
        }
    }

    proptest::proptest! {
        #[test]
        fn test_block_header_decode(block_header in proptest_arbitrary_interop::arb::<BlockHeader>()) {
            let encoded = block_header.encode();
            let decoded = *BlockHeader::decode(&encoded).unwrap();
            assert_eq!(block_header, decoded);
        }
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
        let block_header = random_block_header();
        println!("{block_header}");
    }
}
