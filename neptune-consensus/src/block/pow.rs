use std::fmt::Display;

use get_size2::GetSize;
use itertools::Itertools;
use neptune_primitives::mast_hash::MastHash;
use rand::distr::Distribution;
use rand::distr::StandardUniform;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::twenty_first::bfe_array;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;

use crate::block::block_header::BlockHeader;
use crate::block::block_kernel::BlockKernel;
use crate::block::Block;
use crate::consensus_rule_set::ConsensusRuleSet;
use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

#[derive(Debug, Clone, Copy, PartialEq, Eq, BFieldCodec, TasmObject, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-helpers"), derive(Default))]
pub struct LustrationStatus {
    /// Remaining number of coins that can pass through the lustration barrier.
    pub counter: NativeCurrencyAmount,

    /// An upper limit of which AOCL leafs that need to lustrate.
    ///
    /// All AOCL leaf indices at or below this threshold must lustrate.
    ///
    /// All indices above this value do not have to lustrate.
    pub max_lustrating_aocl_leaf_index: u64,
}

impl std::fmt::Display for LustrationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "counter: {}; AOCL threshold: {}",
            self.counter, self.max_lustrating_aocl_leaf_index,
        )
    }
}

/// Determines the number of leafs in the Merkle tree in the guesser buffer.
pub(crate) const POW_MEMORY_PARAMETER: usize = 1 << 29;

pub const POW_MEMORY_TREE_HEIGHT: usize = POW_MEMORY_PARAMETER.ilog2() as usize;

const NUM_INDEX_REPETITIONS: u32 = 63;
const NUM_BUD_LAYERS: usize = 5; // 5 => 63 Tip5 permutations per leaf
const BUDS_PER_LEAF: usize = 1 << NUM_BUD_LAYERS;

/// Merkle-tree authentication-path verification, tailored to the `pow` module.
///
/// Only path verification is needed here: memory-hard proof-of-work solving —
/// the only thing that required building a full tree — is no longer supported.
/// Historical blocks are verified by checking authentication paths, which is
/// cheap. To build a Merkle tree, use `twenty-first`'s Merkle tree module.
#[derive(Debug, Clone, Copy)]
pub struct MTree;

impl MTree {
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
    pub pow: [Digest; BlockHeader::MAST_HEIGHT],
    pub header: [Digest; BlockKernel::MAST_HEIGHT],
    pub kernel: [Digest; Block::MAST_HEIGHT],
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

impl<const MERKLE_TREE_HEIGHT: usize> Pow<MERKLE_TREE_HEIGHT> {
    pub const MERKLE_TREE_HEIGHT: usize = MERKLE_TREE_HEIGHT;
    pub const NUM_LEAFS: usize = 1_usize << Self::MERKLE_TREE_HEIGHT;

    fn bud(commitment: Digest, index: u64) -> Digest {
        Tip5::hash_pair(commitment, Digest::new(bfe_array![index, 0, 0, 0, 0]))
    }

    fn leaf(commitment: Digest, index: u64) -> Digest {
        // A leaf is the root of a small (height-`NUM_BUD_LAYERS`) Merkle tree over
        // `BUDS_PER_LEAF` buds. Since it is now only computed during verification,
        // build it with a plain bottom-up pairwise hash rather than the
        // memory-hard guesser's Merkle-tree machinery.
        let mut layer = (index..(index + BUDS_PER_LEAF as u64))
            .map(|i| Self::bud(commitment, i % Self::NUM_LEAFS as u64))
            .collect_vec();
        while layer.len() > 1 {
            layer = layer
                .chunks_exact(2)
                .map(|pair| Tip5::hash_pair(pair[0], pair[1]))
                .collect();
        }
        layer[0]
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

    /// Return the lustration status set in the PoW field of the block header.
    pub fn lustration_status(&self) -> Result<LustrationStatus, PowValidationError> {
        let [e0, e1, e2, e3, e4] = self.path_a[MERKLE_TREE_HEIGHT - 2].values();
        let e5 = self.path_a[MERKLE_TREE_HEIGHT - 1].values()[0];

        let Ok(lustration_status) = LustrationStatus::decode(&[e0, e1, e2, e3, e4, e5]) else {
            return Err(PowValidationError::CannotParseLustrationCounter);
        };

        Ok(*lustration_status)
    }

    fn set_lustration_status_raw(&mut self, raw_values: [BFieldElement; 6]) {
        let [e0, e1, e2, e3, e4, e5] = raw_values;

        // This encoding leaves nine free B field elements free after the
        // the lustration encoding. Those **nine** elements can be used to
        // encode other data, without negatively affecting optimized mining
        // hardware or software.
        self.path_a[MERKLE_TREE_HEIGHT - 2] = Digest([e0, e1, e2, e3, e4]);
        let [_prev_e0, prev_e1, prev_e2, prev_e3, prev_e4] =
            self.path_a[MERKLE_TREE_HEIGHT - 1].values();
        self.path_a[MERKLE_TREE_HEIGHT - 1] = Digest([e5, prev_e1, prev_e2, prev_e3, prev_e4]);
    }

    /// Set the lustration status to the specified value in the PoW field.
    pub(super) fn set_lustration_status(&mut self, value: LustrationStatus) {
        let encoding = value.encode();
        let encoding: [BFieldElement; 6] = encoding
            .try_into()
            .expect("Lustration status encoding must have size six elements");
        self.set_lustration_status_raw(encoding);
    }

    pub(super) fn version_in_pow(&self) -> BFieldElement {
        let [_, _, _, _, version] = self.path_a[MERKLE_TREE_HEIGHT - 3].values();

        version
    }

    pub(super) fn set_version_in_pow(&mut self, value: BFieldElement) {
        let [prev_e0, prev_e1, prev_e2, prev_e3, _prev_e4] =
            self.path_a[MERKLE_TREE_HEIGHT - 3].values();
        self.path_a[MERKLE_TREE_HEIGHT - 3] = Digest([prev_e0, prev_e1, prev_e2, prev_e3, value]);
    }

    pub fn guess(
        mast_auth_paths: &PowMastPaths,
        nonce: Digest,
        target: Digest,
        lustration_status: Option<LustrationStatus>,
        version: Option<BFieldElement>,
    ) -> Option<Self> {
        let mut pow = Pow {
            nonce,
            root: Default::default(),
            path_a: [Digest::default(); MERKLE_TREE_HEIGHT],
            path_b: [Digest::default(); MERKLE_TREE_HEIGHT],
        };

        if let Some(lustration) = lustration_status {
            pow.set_lustration_status(lustration);
        }

        if let Some(version) = version {
            pow.set_version_in_pow(version);
        }

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
        let pow_digest = auth_paths.fast_mast_hash(self);
        let meets_threshold = pow_digest <= target;
        let leaf_prefix = match consensus_rule_set {
            ConsensusRuleSet::Reboot => auth_paths.commit(),
            ConsensusRuleSet::HardforkAlpha | ConsensusRuleSet::TvmProofVersion1 => parent_digest,
            ConsensusRuleSet::HardforkBeta | ConsensusRuleSet::HardforkGamma => {
                if !meets_threshold {
                    return Err(PowValidationError::ThresholdNotMet);
                }

                return Ok(());
            }
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

        if !meets_threshold {
            return Err(PowValidationError::ThresholdNotMet);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowValidationError {
    PathAInvalid,
    PathBInvalid,
    ThresholdNotMet,
    CannotParseLustrationCounter,
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

#[cfg(any(test, feature = "test-helpers"))]
impl<const MERKLE_TREE_HEIGHT: usize> Pow<MERKLE_TREE_HEIGHT> {
    pub fn set_unparseable_lustration_status(&mut self) {
        let elements = bfe_array![
            1u64 << 32,
            1u64 << 33,
            1u64 << 34,
            1u64 << 35,
            1u64 << 36,
            1u64 << 37
        ];
        self.set_lustration_status_raw(elements);
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use num_traits::Zero;
    use proptest::prelude::TestCaseError;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use rand::rng;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use strum::IntoEnumIterator;
    use tasm_lib::twenty_first::bfe;
    use test_strategy::proptest;

    use super::*;
    use crate::block::difficulty_control::Difficulty;
    use crate::block::test_helpers::invalid_empty_block;
    use crate::block::DIFFICULTY_LIMIT_FOR_TESTS;
    use crate::network::Network;
    use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

    #[test]
    fn lustration_encoding_error_on_invalid_amount() {
        // Last four elements encode amount
        let mut pow = Pow::<29>::default();
        pow.set_lustration_status_raw(bfe_array![0, 0, 0, 0, 1u64 << 32, 0]);
        assert_eq!(
            PowValidationError::CannotParseLustrationCounter,
            pow.lustration_status().unwrap_err()
        );
    }

    #[test]
    fn lustration_encoding_error_on_invalid_threshold() {
        // First two elements encode leaf index threshold
        let mut pow = Pow::<29>::default();
        pow.set_lustration_status_raw(bfe_array![1u64 << 32, 0, 0, 0, 0, 0]);
        assert_eq!(
            PowValidationError::CannotParseLustrationCounter,
            pow.lustration_status().unwrap_err()
        );
    }

    #[test]
    fn lustration_counter_is_followed_by_9_unbound_elems_in_encoding() {
        // Leaving 9 unbound b field elements after the lustration counter
        // allows for the insertion of more data into the PoW field (through
        // later forks) without punishing heavily optimized guesser hardware
        // or software.
        let amount = NativeCurrencyAmount::from_raw_i128(u128::MAX as i128);
        assert_eq!(
            i128::BITS,
            amount.to_nau().count_ones(),
            "Test value must be all ones"
        );
        let mut pow = Pow::<10>::default();
        pow.set_lustration_status(LustrationStatus {
            counter: amount,
            max_lustrating_aocl_leaf_index: u64::MAX,
        });
        let encoding = pow.encode();
        let mut iterator = encoding.iter().peekable();

        while iterator.peek().is_some_and(|x| x.is_zero()) {
            iterator.next();
        }
        for _ in 0..6 {
            assert_eq!(bfe!(u32::MAX), *iterator.next().unwrap());
        }

        // Next 9 B-field elements are zero
        for _ in 0..9 {
            assert!(iterator.next().unwrap().is_zero());
        }

        assert!(iterator.next().is_none());
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
    fn happy_path_all_consensus_rule_sets() {
        const MERKLE_TREE_HEIGHT: usize = 8;
        let mut rng = rng();
        let auth_paths = rng.random::<PowMastPaths>();
        let prev_block_digest = rng.random();

        for consensus_rule_set in ConsensusRuleSet::iter() {
            // Solving memory-hard (pre-hardfork-beta) PoW is no longer supported.
            if consensus_rule_set.memory_hard_pow() {
                continue;
            }

            for difficulty in [2_u32, 8] {
                let difficulty = Difficulty::from(difficulty);
                let successful_guess = solve::<MERKLE_TREE_HEIGHT>(
                    &auth_paths,
                    prev_block_digest,
                    difficulty,
                    None,
                    None,
                );
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

    fn lustration_encoding_prop(lustration_status: LustrationStatus) -> Result<(), TestCaseError> {
        let mut pow = Pow::<29>::default();
        pow.set_lustration_status(lustration_status);
        let read = pow.lustration_status().unwrap();
        prop_assert_eq!(lustration_status, read);

        Ok(())
    }

    #[proptest(cases = 20)]
    fn lustration_encoding_consistency_u64(
        #[strategy(arb())] amount: NativeCurrencyAmount,
        #[strategy(arb())] aocl_leaf_index: u64,
    ) {
        lustration_encoding_prop(LustrationStatus {
            counter: amount,
            max_lustrating_aocl_leaf_index: aocl_leaf_index,
        })?;
    }

    #[proptest(cases = 20)]
    fn lustration_encoding_consistency_u32(
        #[strategy(arb())] amount: NativeCurrencyAmount,
        #[strategy(arb())] aocl_leaf_index: u32,
    ) {
        lustration_encoding_prop(LustrationStatus {
            counter: amount,
            max_lustrating_aocl_leaf_index: aocl_leaf_index.into(),
        })?;
    }

    #[proptest(cases = 20)]
    fn version_encoding_consistency(#[strategy(arb())] version: BFieldElement) {
        let mut pow = Pow::<29>::default();
        pow.set_version_in_pow(version);
        let read = pow.version_in_pow();
        prop_assert_eq!(version, read);
    }

    fn solve<const N: usize>(
        auth_paths: &PowMastPaths,
        prev_block_digest: Digest,
        difficulty: Difficulty,
        lustration_status: Option<LustrationStatus>,
        version: Option<BFieldElement>,
    ) -> Pow<N> {
        assert!(
            difficulty < Difficulty::from(DIFFICULTY_LIMIT_FOR_TESTS),
            "Let's not make tests run too long"
        );

        let target = difficulty.target();
        let mut rng = StdRng::seed_from_u64(
            prev_block_digest.values()[0].value() ^ auth_paths.commit().values()[0].value(),
        );
        loop {
            let nonce = rng.random();
            if let Some(solution) =
                Pow::guess(auth_paths, nonce, target, lustration_status, version)
            {
                break solution;
            }
        }
    }

    mod merkle_tree_tests {
        use rand::rngs::StdRng;
        use rand::SeedableRng;
        use tasm_lib::twenty_first::prelude::MerkleTree;

        use super::*;

        fn valid_root_index_path_element_tuple(
            tree_height: usize,
            seed: [u8; 32],
        ) -> (Digest, usize, Vec<Digest>, Digest) {
            let mut rng = StdRng::from_seed(seed);
            let num_leafs = 1 << tree_height;

            let leafs = (0..num_leafs).map(|_| rng.random::<Digest>()).collect_vec();
            let index = rng.random_range(0..num_leafs);
            let element = leafs[index];
            let merkle_tree =
                MerkleTree::sequential_new(&leafs).expect("must not forget to unwrap");
            let root = merkle_tree.root();
            let path = merkle_tree
                .authentication_structure(&[index])
                .expect("must not forget to unwrap");

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

            let translation = rng.random_range(1..((1 << height) - 1));
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
