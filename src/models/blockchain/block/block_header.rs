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
use crate::config_models::network::Network;
use crate::models::blockchain::block::guesser_receiver_data::GuesserReceiverData;
use crate::models::blockchain::block::pow::Pow;
use crate::models::blockchain::block::pow::POW_MEMORY_PARAMETER;
use crate::models::blockchain::block::pow::POW_MEMORY_TREE_HEIGHT;
use crate::models::proof_abstractions::mast_hash::HasDiscriminant;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::timestamp::Timestamp;

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

    pub pow: Pow<POW_MEMORY_TREE_HEIGHT>,

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
            Prev. Digest: {}\n\
            Cumulative Proof-of-Work: {}\n\
            Difficulty: {}\n\
            Version: {}\n\
            Guesser receiver digest: {}\n\
            Guesser lock script hash: {}\n\
            pow: {}\n",
            self.height,
            self.timestamp.standard_format(),
            self.prev_block_digest.to_hex(),
            self.cumulative_proof_of_work,
            self.difficulty,
            self.version,
            self.guesser_receiver_data.receiver_digest.to_hex(),
            self.guesser_receiver_data.lock_script_hash.to_hex(),
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
                // Bitcoin block at height 906975
                // TODO: Update me right before reboot
                nonce: Digest::new(bfe_array![
                    0x0000000000000000u64,
                    0x0001ff452761dd02u64,
                    0x9696bf75719bdc65u64,
                    0xa6b0088b8822e794u64,
                    0
                ]),
                path_a: [Digest::default(); POW_MEMORY_PARAMETER.ilog2() as usize],
                path_b: [Digest::default(); POW_MEMORY_PARAMETER.ilog2() as usize],
                root: Digest::default(),
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

    pub(crate) fn was_guessed_by(&self, address: ReceivingAddress) -> bool {
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

#[cfg(any(test, feature = "arbitrary-impls"))]
impl BlockHeader {
    pub(crate) fn arbitrary_with_height(
        block_height: BlockHeight,
    ) -> proptest::prelude::BoxedStrategy<Self> {
        use proptest::prelude::Strategy;
        use proptest_arbitrary_interop::arb;

        let version = arb::<BFieldElement>();
        let prev_block_digest = arb::<Digest>();
        let timestamp = arb::<Timestamp>();
        let pow = arb::<Pow<POW_MEMORY_TREE_HEIGHT>>();
        let cumulative_proof_of_work = arb::<ProofOfWork>();
        let difficulty = arb::<Difficulty>();
        let guesser_receiver_data = arb::<GuesserReceiverData>();

        (
            version,
            prev_block_digest,
            timestamp,
            pow,
            cumulative_proof_of_work,
            difficulty,
            guesser_receiver_data,
        )
            .prop_map(
                move |(
                    version,
                    prev_block_digest,
                    timestamp,
                    pow,
                    cumulative_proof_of_work,
                    difficulty,
                    guesser_receiver_data,
                )| {
                    BlockHeader {
                        version,
                        height: block_height,
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use rand::Rng;

    use super::*;
    use crate::models::blockchain::block::validity::block_primitive_witness::tests::deterministic_block_primitive_witness;

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
        let network = Network::Main;
        let block_primitive_witness = deterministic_block_primitive_witness();
        let block = Block::block_template_invalid_proof_from_witness(
            block_primitive_witness,
            Timestamp::now(),
            network.target_block_interval(),
        );
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
