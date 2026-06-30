use neptune_primitives::timestamp::Timestamp;
use num_traits::Zero;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;

use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::block_height::NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT;
use crate::protocol::consensus::block::pow::LustrationStatus;
use crate::protocol::consensus::block::INITIAL_BLOCK_SUBSIDY;
use crate::protocol::consensus::block::MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS;
use crate::protocol::consensus::block::PREMINE_MAX_SIZE;
use crate::protocol::consensus::network::Network;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

/// Height of 1st block that follows the alpha consensus ruleset, for main net.
pub const BLOCK_HEIGHT_HARDFORK_ALPHA_MAIN_NET: BlockHeight =
    BlockHeight::new(BFieldElement::new(15_000u64));

/// Height of 1st block that follows the alpha consensus ruleset, for test net.
pub const BLOCK_HEIGHT_HARDFORK_ALPHA_TESTNET: BlockHeight =
    BlockHeight::new(BFieldElement::new(120u64));

/// Height of 1st block that follows the alpha consensus ruleset, for test net.
pub const BLOCK_HEIGHT_HARDFORK_TVMV_PROOF_V1_TESTNET: BlockHeight =
    BlockHeight::new(BFieldElement::new(3571u64));

/// Height of 1st block that uses Triton VM with proof version 1.
pub const BLOCK_HEIGHT_HARDFORK_TVMV_PROOF_V1_MAIN_NET: BlockHeight =
    BlockHeight::new(BFieldElement::new(23_401u64));

/// Height of 1st block changing PoW algorithm to drop memory hardness
pub const BLOCK_HEIGHT_HARDFORK_BETA_MAIN_NET: BlockHeight =
    BlockHeight::new(BFieldElement::new(38_000u64));

/// Height of 1st block changing PoW algorithm to drop memory hardness, for test
/// net.
pub const BLOCK_HEIGHT_HARDFORK_BETA_TESTNET: BlockHeight =
    BlockHeight::new(BFieldElement::new(3_669));

/// Height of the first block after hard fork gamma, which fixes the June 2026
/// soundness issues, on main net.
pub const BLOCK_HEIGHT_HARDFORK_GAMMA_MAIN_NET: BlockHeight =
    BlockHeight::new(BFieldElement::new(40_300u64));

/// Height of the first block after hard fork gamma, which fixes the June 2026
/// soundness issue, on test net.
pub const BLOCK_HEIGHT_HARDFORK_GAMMA_TESTNET: BlockHeight =
    BlockHeight::new(BFieldElement::new(4_650));

/// Transactions that are more than three days older than the block are
/// disallowed. Only enforced from hardfork gamma and onwards.
pub const TX_BACKDATING_LIMIT: Timestamp = Timestamp::days(3);

/// Enumerates all possible sets of consensus rules.
///
/// Specifically, this enum captures *differences* between consensus rules,
/// across
///  - networks, and
///  - hard and soft forks triggered by blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::EnumIter, Default, strum::Display)]
pub enum ConsensusRuleSet {
    /// First rule set after reboot
    Reboot,

    /// Allow reuse of preprocessing step for new block proposals
    HardforkAlpha,

    /// Upgrade from Triton VM proof version v0 to v1
    #[default]
    TvmProofVersion1,

    /// Remove memory hardness from PoW algorithm, add lustration barrier for
    /// old inputs, compare difficulty to own block header instead of parent's
    /// block header.
    HardforkBeta,

    /// Fix June 2026 soundness issue in recursive proof verifier upstream in
    /// tasm-lib. Fix June 2026 soundness issue in Triton VM's
    /// sponge_mem_absorb instruction, as well as other under-constrained trace
    /// values.
    ///
    /// Also restarts the lustration counting since all past proofs have been
    /// found to be unsound.
    HardforkGamma,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::Display)]
pub enum TritonProofVersion {
    V0,
    V1,
    V5,
}

impl TritonProofVersion {
    /// The version value used in Triton VM's claim
    pub(crate) fn version(&self) -> u32 {
        match self {
            TritonProofVersion::V0 => 0,
            TritonProofVersion::V1 => 1,
            TritonProofVersion::V5 => 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LustrationRule {
    Initial(LustrationStatus),
    Updated {
        // This data is actually redundant but allows for a security-in-depth
        // extra sanity check.
        initial_counter: NativeCurrencyAmount,
    },
}

impl ConsensusRuleSet {
    /// Infer the [`ConsensusRuleSet`] from the [`Network`] and the
    /// [`BlockHeight`]. The second argument is necessary to take into account
    /// planned hard or soft forks that activate at a given height. The first
    /// argument is necessary because the forks can activate at different
    /// heights based on the network.
    pub fn infer_from(network: Network, block_height: BlockHeight) -> Self {
        let first_lustration_block = Self::first_lustration_block(network);
        match network {
            Network::Main => {
                if block_height < BLOCK_HEIGHT_HARDFORK_ALPHA_MAIN_NET {
                    ConsensusRuleSet::Reboot
                } else if block_height < BLOCK_HEIGHT_HARDFORK_TVMV_PROOF_V1_MAIN_NET {
                    ConsensusRuleSet::HardforkAlpha
                } else if block_height < first_lustration_block {
                    ConsensusRuleSet::TvmProofVersion1
                } else if block_height < BLOCK_HEIGHT_HARDFORK_GAMMA_MAIN_NET {
                    ConsensusRuleSet::HardforkBeta
                } else {
                    ConsensusRuleSet::HardforkGamma
                }
            }
            Network::Testnet(0) => {
                if block_height < BLOCK_HEIGHT_HARDFORK_ALPHA_TESTNET {
                    ConsensusRuleSet::Reboot
                } else if block_height < BLOCK_HEIGHT_HARDFORK_TVMV_PROOF_V1_TESTNET {
                    ConsensusRuleSet::HardforkAlpha
                } else if block_height < first_lustration_block {
                    ConsensusRuleSet::TvmProofVersion1
                } else if block_height < BLOCK_HEIGHT_HARDFORK_GAMMA_TESTNET {
                    ConsensusRuleSet::HardforkBeta
                } else {
                    ConsensusRuleSet::HardforkGamma
                }
            }
            _ => ConsensusRuleSet::HardforkGamma,
        }
    }

    pub(crate) fn memory_hard_pow(&self) -> bool {
        match self {
            ConsensusRuleSet::Reboot => true,
            ConsensusRuleSet::HardforkAlpha => true,
            ConsensusRuleSet::TvmProofVersion1 => true,
            ConsensusRuleSet::HardforkBeta => false,
            ConsensusRuleSet::HardforkGamma => false,
        }
    }

    /// Returns true if PoW threshold is defined relative to parent difficulty,
    /// and false if it is defined relative to own difficulty value.
    pub fn use_parent_difficulty(&self) -> bool {
        match self {
            ConsensusRuleSet::Reboot => true,
            ConsensusRuleSet::HardforkAlpha => true,
            ConsensusRuleSet::TvmProofVersion1 => true,
            ConsensusRuleSet::HardforkBeta => false,
            ConsensusRuleSet::HardforkGamma => false,
        }
    }

    pub fn requires_lustration_status_in_block_header(&self) -> bool {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::TvmProofVersion1 => false,
            ConsensusRuleSet::HardforkBeta => true,
            ConsensusRuleSet::HardforkGamma => true,
        }
    }

    pub(crate) fn requires_version_in_pow(&self) -> bool {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::TvmProofVersion1 => false,
            ConsensusRuleSet::HardforkBeta => true,
            ConsensusRuleSet::HardforkGamma => true,
        }
    }

    pub fn transaction_backdating_threshold(&self) -> Option<Timestamp> {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::TvmProofVersion1
            | ConsensusRuleSet::HardforkBeta => None,
            ConsensusRuleSet::HardforkGamma => Some(TX_BACKDATING_LIMIT),
        }
    }

    /// Return a boolean whether or not the double-counting issue in the
    /// update of the lustration counter should be fixed.
    ///
    /// Must be false for some block heights due to consensus-preservation
    /// logic of historical blocks. Otherwise, a huge rollback would be needed.
    /// Cf.:
    /// <https://talk.neptune.cash/t/small-bug-in-lustration-counter-update-logic/286>
    ///
    /// # Panics
    /// - If called on a consensus rule set that does not require lustration.
    pub fn fix_lustration_double_counting(&self) -> bool {
        // TODO: Move this boolean to LustrationRule
        match self {
            ConsensusRuleSet::Reboot => unreachable!("Lustration not active"),
            ConsensusRuleSet::HardforkAlpha => unreachable!("Lustration not active"),
            ConsensusRuleSet::TvmProofVersion1 => unreachable!("Lustration not active"),
            ConsensusRuleSet::HardforkBeta => false,
            ConsensusRuleSet::HardforkGamma => true,
        }
    }

    /// The proof version used by this consensus rule set.
    pub fn triton_proof_version(&self) -> TritonProofVersion {
        match self {
            ConsensusRuleSet::Reboot => TritonProofVersion::V0,
            ConsensusRuleSet::HardforkAlpha => TritonProofVersion::V0,
            ConsensusRuleSet::TvmProofVersion1 => TritonProofVersion::V1,
            ConsensusRuleSet::HardforkBeta => TritonProofVersion::V1,
            ConsensusRuleSet::HardforkGamma => TritonProofVersion::V5,
        }
    }

    /// Maximum block size in number of BFieldElements
    pub const fn max_block_size(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::TvmProofVersion1
            | ConsensusRuleSet::HardforkBeta
            | ConsensusRuleSet::HardforkGamma => {
                // This size is 8MB which should keep it feasible to run archival nodes for
                // many years without requiring excessive disk space.
                1_000_000
            }
        }
    }

    pub fn max_num_inputs(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::TvmProofVersion1
            | ConsensusRuleSet::HardforkBeta
            | ConsensusRuleSet::HardforkGamma => MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS,
        }
    }
    pub fn max_num_outputs(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::TvmProofVersion1
            | ConsensusRuleSet::HardforkBeta
            | ConsensusRuleSet::HardforkGamma => MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS,
        }
    }
    pub fn max_num_announcements(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::TvmProofVersion1
            | ConsensusRuleSet::HardforkBeta
            | ConsensusRuleSet::HardforkGamma => MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS,
        }
    }

    pub fn first_lustration_block(network: Network) -> BlockHeight {
        match network {
            Network::Main => BLOCK_HEIGHT_HARDFORK_BETA_MAIN_NET,
            Network::Testnet(0) => BLOCK_HEIGHT_HARDFORK_BETA_TESTNET,
            // Using block height one means that all blocks must lustrate,
            // except for the genesis block and block 1, and that only AOCL
            // leafs indistinguishable from premine AOCLs and those produced in
            // block 1 must lustrate.
            _ => BlockHeight::genesis().next(),
        }
    }

    pub fn latest_checkpoint(network: Network) -> BlockHeight {
        match network {
            Network::Main => BLOCK_HEIGHT_HARDFORK_GAMMA_MAIN_NET.previous().unwrap(),
            Network::Testnet(0) => BLOCK_HEIGHT_HARDFORK_GAMMA_TESTNET.previous().unwrap(),
            _ => BlockHeight::genesis(),
        }
    }

    pub(crate) fn lustration_rule(
        network: Network,
        block_height: BlockHeight,
        last_aocl_leaf_index: u64,
    ) -> Option<LustrationRule> {
        let premine = PREMINE_MAX_SIZE;
        let claims_pool = INITIAL_BLOCK_SUBSIDY
            .scalar_mul(u32::try_from(NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT).unwrap());

        let first_hf_beta_block = Self::first_lustration_block(network);
        let first_hf_gamma_block = Self::hardfork_gamma_activation_block_height(network);

        assert!(
            first_hf_beta_block.get_generation().is_zero()
                && first_hf_gamma_block.get_generation().is_zero(),
            "This calculation assumes all transparency gateways start at generation zero."
        );

        let mined_at_hf_beta_activation =
            INITIAL_BLOCK_SUBSIDY.scalar_mul(u32::try_from(first_hf_beta_block.value()).unwrap());
        let mined_at_hf_gamma_activation =
            INITIAL_BLOCK_SUBSIDY.scalar_mul(u32::try_from(first_hf_gamma_block.value()).unwrap());
        let initial_counter_beta = premine + claims_pool + mined_at_hf_beta_activation;
        let initial_counter_gamma = premine + claims_pool + mined_at_hf_gamma_activation;

        if block_height < first_hf_beta_block {
            None
        } else if block_height == first_hf_beta_block {
            Some(LustrationRule::Initial(LustrationStatus {
                counter: initial_counter_beta,
                max_lustrating_aocl_leaf_index: last_aocl_leaf_index,
            }))
        } else if block_height < first_hf_gamma_block {
            Some(LustrationRule::Updated {
                initial_counter: initial_counter_beta,
            })
        } else if block_height == first_hf_gamma_block {
            Some(LustrationRule::Initial(LustrationStatus {
                counter: initial_counter_gamma,
                max_lustrating_aocl_leaf_index: last_aocl_leaf_index,
            }))
        } else {
            Some(LustrationRule::Updated {
                initial_counter: initial_counter_gamma,
            })
        }
    }

    fn hardfork_gamma_activation_block_height(network: Network) -> BlockHeight {
        let one = BlockHeight::genesis().next();
        match network {
            Network::Main => BLOCK_HEIGHT_HARDFORK_GAMMA_MAIN_NET,
            Network::Testnet(0) => BLOCK_HEIGHT_HARDFORK_GAMMA_TESTNET,
            Network::Testnet(_) => one,
            Network::TestnetMock => one,
            Network::RegTest => one,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use tasm_lib::twenty_first::bfe;
    use tracing_test::traced_test;

    use super::*;
    use crate::protocol::consensus::block::difficulty_control::Difficulty;
    use crate::protocol::consensus::block::validity::block_primitive_witness::BlockPrimitiveWitness;
    use crate::protocol::consensus::block::Block;
    use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use crate::protocol::proof_abstractions::test_runtime::tokio_runtime;

    #[test]
    fn lustration_counter_has_expected_initial_value() {
        let network = Network::Main;
        let first_lustration = ConsensusRuleSet::lustration_rule(
            network,
            BLOCK_HEIGHT_HARDFORK_BETA_MAIN_NET,
            100_000,
        )
        .unwrap();
        let LustrationRule::Initial(first_lustration) = first_lustration else {
            panic!("First lustration rule must be of type 'initial'");
        };

        // premine + redemption pool + miner rewards up to hard fork activation
        assert_eq!(
            NativeCurrencyAmount::coins(8_423_168),
            first_lustration.counter
        );
        assert_eq!(100_000, first_lustration.max_lustrating_aocl_leaf_index);

        let second_lustration = ConsensusRuleSet::lustration_rule(
            network,
            BLOCK_HEIGHT_HARDFORK_GAMMA_MAIN_NET,
            200_000,
        )
        .unwrap();
        let LustrationRule::Initial(second_lustration) = second_lustration else {
            panic!("Restarted lustration rule must be of type 'initial'");
        };
        assert_eq!(
            NativeCurrencyAmount::coins(8_717_568),
            second_lustration.counter
        );
        assert_eq!(200_000, second_lustration.max_lustrating_aocl_leaf_index);

        assert!(
            matches!(
                ConsensusRuleSet::lustration_rule(
                    network,
                    BLOCK_HEIGHT_HARDFORK_GAMMA_MAIN_NET.next(),
                    200_000,
                )
                .unwrap(),
                LustrationRule::Updated { .. },
            ),
            "Updated lustration rule must follow initial"
        );
    }

    #[test]
    fn future_and_past_memory_hardness() {
        assert!(ConsensusRuleSet::infer_from(Network::Main, 1_000u64.into()).memory_hard_pow());
        assert!(!ConsensusRuleSet::infer_from(Network::Main, 100_000u64.into()).memory_hard_pow());
    }

    #[test]
    fn future_and_past_lustration_rule() {
        let dummy_count = 55647;
        let network = Network::Main;
        assert!(
            ConsensusRuleSet::lustration_rule(network, 10_000u64.into(), dummy_count).is_none()
        );
        assert!(matches!(
            ConsensusRuleSet::lustration_rule(network, 100_000u64.into(), dummy_count).unwrap(),
            LustrationRule::Updated { .. }
        ));
    }

    #[test]
    fn expected_use_parent_difficulty() {
        assert!(ConsensusRuleSet::Reboot.use_parent_difficulty());
        assert!(ConsensusRuleSet::HardforkAlpha.use_parent_difficulty());
        assert!(ConsensusRuleSet::TvmProofVersion1.use_parent_difficulty());
        assert!(!ConsensusRuleSet::HardforkBeta.use_parent_difficulty());
        assert!(!ConsensusRuleSet::HardforkGamma.use_parent_difficulty());
    }

    #[test]
    fn expected_tvm_proof_versions() {
        assert_eq!(0, ConsensusRuleSet::Reboot.triton_proof_version().version());
        assert_eq!(
            0,
            ConsensusRuleSet::HardforkAlpha
                .triton_proof_version()
                .version()
        );
        assert_eq!(
            1,
            ConsensusRuleSet::TvmProofVersion1
                .triton_proof_version()
                .version()
        );
        assert_eq!(
            1,
            ConsensusRuleSet::HardforkBeta
                .triton_proof_version()
                .version()
        );
        assert_eq!(
            5,
            ConsensusRuleSet::HardforkGamma
                .triton_proof_version()
                .version(),
        );
    }

    #[test]
    fn tvm_v1_preceeds_hf_beta() {
        let network = Network::Main;
        let first_lustration_block = ConsensusRuleSet::first_lustration_block(network);
        assert_eq!(
            ConsensusRuleSet::TvmProofVersion1,
            ConsensusRuleSet::infer_from(network, first_lustration_block.previous().unwrap())
        );
        assert_eq!(
            ConsensusRuleSet::HardforkBeta,
            ConsensusRuleSet::infer_from(network, first_lustration_block)
        );

        let dummy_count = 55647;
        assert!(ConsensusRuleSet::lustration_rule(
            network,
            first_lustration_block.previous().unwrap(),
            dummy_count
        )
        .is_none(),);
        assert!(matches!(
            ConsensusRuleSet::lustration_rule(network, first_lustration_block, dummy_count),
            Some(LustrationRule::Initial(_)),
        ));
        assert!(matches!(
            ConsensusRuleSet::lustration_rule(network, first_lustration_block.next(), dummy_count),
            Some(LustrationRule::Updated { .. }),
        ));
    }

    #[traced_test]
    #[test]
    fn allow_non_zero_version() {
        // Start well into hardfork gamma
        let init_block_heigth = BlockHeight::from(59998u64);
        let bpw = BlockPrimitiveWitness::deterministic_with_block_height_and_difficulty(
            init_block_heigth,
            Difficulty::MINIMUM,
        );

        tokio_runtime().block_on(new_block_allow_non_zero_version(bpw));

        async fn new_block_allow_non_zero_version(block_primitive_witness: BlockPrimitiveWitness) {
            let network = Network::Main;
            let (invalid_block, mut valid_successor) =
                Block::fake_block_pair_genesis_and_child_from_witness(block_primitive_witness)
                    .await;

            assert!(
                valid_successor
                    .is_valid(&invalid_block, valid_successor.header().timestamp, network)
                    .await
            );

            valid_successor.set_version_consistently(bfe!(5550001));
            assert!(
                valid_successor
                    .is_valid(&invalid_block, valid_successor.header().timestamp, network)
                    .await
            );

            let consensus_rule_set = ConsensusRuleSet::HardforkGamma;
            assert_eq!(
                consensus_rule_set,
                ConsensusRuleSet::infer_from(network, valid_successor.header().height)
            );

            valid_successor.satisfy_pow(invalid_block.header().difficulty, consensus_rule_set);
            assert!(
                valid_successor
                    .is_valid(&invalid_block, valid_successor.header().timestamp, network)
                    .await
            );
            assert!(valid_successor.has_proof_of_work(network, invalid_block.header()));
        }
    }
}
