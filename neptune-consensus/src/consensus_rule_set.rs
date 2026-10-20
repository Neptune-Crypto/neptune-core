use neptune_primitives::block_height::BlockHeight;
use neptune_primitives::block_height::NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT;
use neptune_primitives::network::Network;
use neptune_primitives::timestamp::Timestamp;
use num_traits::Zero;
use tasm_lib::twenty_first::bfe;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;

use crate::block::pow::LustrationStatus;
use crate::block::validity::block_program::BlockProgram;
use crate::block::validity::epoch_table::Epoch;
use crate::block::validity::epoch_table::EpochTable;
use crate::block::validity::swbf_update::aggregation::SwbfUpdateAggregation;
use crate::block::INITIAL_BLOCK_SUBSIDY;
use crate::block::MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS;
use crate::block::PREMINE_MAX_SIZE;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::transaction::validity::single_proof::SingleProof;
use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

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

/// Height of the first block after hard fork delta, which activates
/// transaction chaining, on main net.
pub const BLOCK_HEIGHT_HARDFORK_DELTA_MAIN_NET: BlockHeight =
    BlockHeight::new(BFieldElement::new(55_000u64));

/// Height of the first block after hard fork delta, which activates
/// transaction chaining, on test net.
pub const BLOCK_HEIGHT_HARDFORK_DELTA_TESTNET: BlockHeight =
    BlockHeight::new(BFieldElement::new(5_400));

/// Height of the first block that uses the epsilon ruleset, on main net.
pub const BLOCK_HEIGHT_SOFTFORK_EPSILON_MAIN_NET: BlockHeight =
    BlockHeight::new(BFieldElement::new(61_000u64));

/// Height of the first block that uses the epsilon ruleset, on testnet-0.
pub const BLOCK_HEIGHT_SOFTFORK_EPSILON_TESTNET: BlockHeight =
    BlockHeight::new(BFieldElement::new(6_260u64));

/// Transactions that are more than three days older than the block are
/// disallowed. Only enforced from hardfork gamma and onwards.
pub const TX_BACKDATING_LIMIT: Timestamp = Timestamp::days(3);

/// Enumerates all possible sets of consensus rules.
///
/// Specifically, this enum captures *differences* between consensus rules,
/// across
///  - networks, and
///  - hard and soft forks triggered by blocks.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, strum::EnumIter, strum::EnumCount, Default, strum::Display,
)]
pub enum ConsensusRuleSet {
    /// First rule set after reboot
    Reboot,

    /// Allow reuse of preprocessing step for new block proposals
    HardforkAlpha,

    /// Upgrade from Triton VM proof version v0 to v1
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

    /// Activate transaction chaining: `SingleProof` gains the `Fix` and `Weld`
    /// branches, which recursively verify a `LinkProof` and so let a chained
    /// transaction (`LinkTx`) become a block-borne `Transaction`.
    ///
    /// New branches are a new program, hence a new program digest, hence a
    /// different claim about every transaction. See
    /// [`Self::has_chain_branches`].
    ///
    /// Also bumps the Triton VM version.
    #[default]
    HardforkDelta,

    /// Succinct block validation.
    ///
    /// A block must prove the `PredecessorIsValid` claim, the SWBF update
    /// claim, and a claim proving knowledge of the mutator set. The guesser
    /// must reveal an SWBF leaf to prove access to the archival mutator set.
    ///
    /// A soft fork because adding more required claims is accepted by old
    /// nodes, and because the guesser reveal goes into previously unbound data.
    SoftforkEpsilon,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::Display)]
pub enum TritonProofVersion {
    V0,
    V1,
    V5,
    V8,
}

impl TritonProofVersion {
    /// The version value used in Triton VM's claim
    pub(crate) fn version(&self) -> u32 {
        match self {
            TritonProofVersion::V0 => 0,
            TritonProofVersion::V1 => 1,
            TritonProofVersion::V5 => 5,
            TritonProofVersion::V8 => 8,
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
                } else if block_height < BLOCK_HEIGHT_HARDFORK_DELTA_MAIN_NET {
                    ConsensusRuleSet::HardforkGamma
                } else if block_height < BLOCK_HEIGHT_SOFTFORK_EPSILON_MAIN_NET {
                    ConsensusRuleSet::HardforkDelta
                } else {
                    ConsensusRuleSet::SoftforkEpsilon
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
                } else if block_height < BLOCK_HEIGHT_HARDFORK_DELTA_TESTNET {
                    ConsensusRuleSet::HardforkGamma
                } else if block_height < BLOCK_HEIGHT_SOFTFORK_EPSILON_TESTNET {
                    ConsensusRuleSet::HardforkDelta
                } else {
                    ConsensusRuleSet::SoftforkEpsilon
                }
            }
            _ => ConsensusRuleSet::SoftforkEpsilon,
        }
    }

    /// The first height at which a block must contain the proof that the
    /// archival mutator set is known.
    pub fn knows_mutator_set_activation_height(network: Network) -> BlockHeight {
        Self::epsilon_activation_block_height(network)
    }

    /// The first block that must contain the succinctness claims
    pub fn epsilon_activation_block_height(network: Network) -> BlockHeight {
        match network {
            Network::Main => BLOCK_HEIGHT_SOFTFORK_EPSILON_MAIN_NET,
            Network::Testnet(0) => BLOCK_HEIGHT_SOFTFORK_EPSILON_TESTNET,
            _ => BlockHeight::genesis().next(),
        }
    }

    /// Whether a block must carry the `PredecessorIsValid` claim about its
    /// parent, and the claims and reveal that come with it.
    pub fn requires_predecessor_claim(&self) -> bool {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::TvmProofVersion1
            | ConsensusRuleSet::HardforkBeta
            | ConsensusRuleSet::HardforkGamma
            | ConsensusRuleSet::HardforkDelta => false,
            ConsensusRuleSet::SoftforkEpsilon => true,
        }
    }

    /// Whether the miners, composer and guesser, must prove knowledge of the
    /// archival mutator set.
    pub fn miners_must_prove_ams_knowledge(&self, network: Network) -> bool {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::TvmProofVersion1
            | ConsensusRuleSet::HardforkBeta
            | ConsensusRuleSet::HardforkGamma
            | ConsensusRuleSet::HardforkDelta => false,
            ConsensusRuleSet::SoftforkEpsilon => {
                // Testnet(1) is excluded from this rule to allow for the
                // construction of "genesis blocks" with another block height
                // than 0. Without this exclusion, all tests would have to start
                // from height 0 since that's the only way to know the archival
                // mutator set.
                !network.use_mock_proof() && network != Network::Testnet(1)
            }
        }
    }

    /// Minimum proving work associated with the SWBF update claim.
    ///
    /// A minimum value for the sum of padded heights of all leaf proofs in the
    /// SWBF update tree. Enforced to avoid that the composer who build empty
    /// blocks can build the block proposal faster than those who include
    /// transactions.
    pub fn min_swbf_padded_rows(&self, network: Network) -> u64 {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::TvmProofVersion1
            | ConsensusRuleSet::HardforkBeta
            | ConsensusRuleSet::HardforkGamma
            | ConsensusRuleSet::HardforkDelta => 0,
            ConsensusRuleSet::SoftforkEpsilon => match network {
                Network::Main | Network::Testnet(0) => 1 << 23,
                Network::Testnet(1) => 1 << 22,
                _ if network.use_mock_proof() => 0,
                _ => 1 << 21,
            },
        }
    }

    /// The table a network's blocks carry in the `PredecessorIsValid` claim
    /// from hard fork epsilon on, with the parameters of the latest rule set.
    pub fn epoch_table(network: Network) -> EpochTable {
        let activation_height = Self::epsilon_activation_block_height(network);
        let rule_set = Self::infer_from(network, activation_height);
        let initial_counter = Self::lustration_counter_initial(network, activation_height)
            .expect("all hard fork epsilon blocks lustrate");
        let epoch_resets_lustration = Self::resets_lustration_status(network, activation_height);
        EpochTable::new(&[Epoch {
            height: activation_height.into(),
            minimum_block_time: network.minimum_block_time(),
            target_block_interval: network.target_block_interval(),
            max_num_inputs: bfe!(rule_set.max_num_inputs() as u64),
            max_num_outputs: bfe!(rule_set.max_num_outputs() as u64),
            max_num_announcements: bfe!(rule_set.max_num_announcements() as u64),
            max_block_size: bfe!(rule_set.max_block_size() as u64),
            transaction_backdating_threshold: rule_set
                .transaction_backdating_threshold()
                .expect("epsilon limits backdating"),
            lustration_counter_initial: initial_counter,
            resets_lustration_status: bfe!(u64::from(epoch_resets_lustration)),
            min_swbf_padded_rows: bfe!(rule_set.min_swbf_padded_rows(network)),
            requires_mutator_set_reveals: bfe!(u64::from(
                rule_set.miners_must_prove_ams_knowledge(network)
            )),
            block_program_digest: BlockProgram.hash(),
            single_proof_digest: SingleProof::new(rule_set).hash(),
            swbf_aggregation_digest: SwbfUpdateAggregation::new().hash(),
        }])
    }

    pub fn memory_hard_pow(&self) -> bool {
        match self {
            ConsensusRuleSet::Reboot => true,
            ConsensusRuleSet::HardforkAlpha => true,
            ConsensusRuleSet::TvmProofVersion1 => true,
            ConsensusRuleSet::HardforkBeta => false,
            ConsensusRuleSet::HardforkGamma => false,
            ConsensusRuleSet::HardforkDelta => false,
            ConsensusRuleSet::SoftforkEpsilon => false,
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
            ConsensusRuleSet::HardforkDelta => false,
            ConsensusRuleSet::SoftforkEpsilon => false,
        }
    }

    pub fn requires_lustration_status_in_block_header(&self) -> bool {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::TvmProofVersion1 => false,
            ConsensusRuleSet::HardforkBeta => true,
            ConsensusRuleSet::HardforkGamma => true,
            ConsensusRuleSet::HardforkDelta => true,
            ConsensusRuleSet::SoftforkEpsilon => true,
        }
    }

    pub(crate) fn requires_version_in_pow(&self) -> bool {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::TvmProofVersion1 => false,
            ConsensusRuleSet::HardforkBeta => true,
            ConsensusRuleSet::HardforkGamma => true,
            ConsensusRuleSet::HardforkDelta => true,
            ConsensusRuleSet::SoftforkEpsilon => true,
        }
    }

    pub fn transaction_backdating_threshold(&self) -> Option<Timestamp> {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::TvmProofVersion1
            | ConsensusRuleSet::HardforkBeta => None,
            ConsensusRuleSet::HardforkGamma
            | ConsensusRuleSet::HardforkDelta
            | ConsensusRuleSet::SoftforkEpsilon => Some(TX_BACKDATING_LIMIT),
        }
    }

    /// Whether the consensus rule set allows transactions to become retired,
    /// i.e. unmineable after a specified timestamp.
    ///
    /// If true, then the consensus rule set disallows transactions that carry
    /// announcements of the type
    /// `[[RETIREMENT_FLAGS; 2], retirement_timestamp]` from being
    /// mined after `retirement_timestamp`. Enforced through the transaction
    /// timestamp: if the tranasction timestamp *exceeds* the
    /// `retirement_timestamp`, the block containing the transaction is
    /// invalid.
    pub fn enforce_transaction_retirement(&self) -> bool {
        match self {
            ConsensusRuleSet::Reboot => false,
            ConsensusRuleSet::HardforkAlpha => false,
            ConsensusRuleSet::TvmProofVersion1 => false,
            ConsensusRuleSet::HardforkBeta => false,
            ConsensusRuleSet::HardforkGamma => false,
            ConsensusRuleSet::HardforkDelta | ConsensusRuleSet::SoftforkEpsilon => true,
        }
    }

    /// Whether the `SingleProof` program carries the
    /// [`Fix`](crate::transaction::validity::tasm::single_proof::fix_branch::FixBranch)
    /// and
    /// [`Weld`](crate::transaction::validity::tasm::single_proof::weld_branch::WeldBranch),
    /// which recursively verify a `LinkProof` -- i.e. whether a chained
    /// transaction can become block-borne.
    ///
    /// These two branches are the one difference between the gamma and delta
    /// `SingleProof` programs, and hence the reason there are two of them: two
    /// branches more is a program hash more, and a claim about a transaction is
    /// about whichever program the block height selects.
    pub fn has_chain_branches(&self) -> bool {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::TvmProofVersion1
            | ConsensusRuleSet::HardforkBeta
            | ConsensusRuleSet::HardforkGamma => false,
            ConsensusRuleSet::HardforkDelta | ConsensusRuleSet::SoftforkEpsilon => true,
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
            ConsensusRuleSet::HardforkDelta | ConsensusRuleSet::SoftforkEpsilon => true,
        }
    }

    /// Whether a packed [`Chunk`](neptune_mutator_set::removal_record::chunk::Chunk)
    /// may use the extended, 23-bit length indicator, and must encode that
    /// indicator canonically.
    ///
    /// Before hardfork delta the indicator is a single `u12`, capping a chunk
    /// at 4095 indices -- a ceiling an attacker can drive a chunk past by
    /// grinding `sender_randomness`, freezing every UTXO with an index in that
    /// chunk. Widening it is what fixes that, but a node that accepted the wide
    /// form early would accept blocks its peers reject, so the attacker would
    /// pick the moment of the split. Hence the gate.
    pub fn allow_big_chunks(&self) -> bool {
        match self {
            ConsensusRuleSet::Reboot => false,
            ConsensusRuleSet::HardforkAlpha => false,
            ConsensusRuleSet::TvmProofVersion1 => false,
            ConsensusRuleSet::HardforkBeta => false,
            ConsensusRuleSet::HardforkGamma => false,
            ConsensusRuleSet::HardforkDelta | ConsensusRuleSet::SoftforkEpsilon => true,
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
            ConsensusRuleSet::HardforkDelta | ConsensusRuleSet::SoftforkEpsilon => {
                TritonProofVersion::V8
            }
        }
    }

    /// Maximum block size in number of BFieldElements
    pub const fn max_block_size(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::TvmProofVersion1
            | ConsensusRuleSet::HardforkBeta
            | ConsensusRuleSet::HardforkGamma
            | ConsensusRuleSet::HardforkDelta
            | ConsensusRuleSet::SoftforkEpsilon => {
                // This size is 8MB which should keep it feasible to run archival nodes for
                // many years without requiring excessive disk space.
                1_000_000
            }
        }
    }

    /// Conservative max size of the encoded length of the transaction kernel
    /// of a block transaction.
    ///
    /// If you attempt to construct blocks with transaction kernels bigger than
    /// this, then you risk making a block proposal that exceed the maximum
    /// allowed size.
    pub fn max_recommended_block_tx_kernel_size(&self) -> usize {
        /// Conservative upper range of the number of b-field elements in a
        /// block proof. Normal proof size at the time of writing is  ~130,000
        /// b-field elements, so a value of 160,000 is very conservative.
        const BIG_BLOCK_PROOF_LEN: usize = 160_000;

        self.max_block_size()
            .checked_sub(BIG_BLOCK_PROOF_LEN)
            .expect("Max block size cannot be less than that of a big proof")
    }

    pub fn max_num_inputs(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::TvmProofVersion1
            | ConsensusRuleSet::HardforkBeta
            | ConsensusRuleSet::HardforkGamma
            | ConsensusRuleSet::HardforkDelta
            | ConsensusRuleSet::SoftforkEpsilon => MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS,
        }
    }
    pub fn max_num_outputs(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::TvmProofVersion1
            | ConsensusRuleSet::HardforkBeta
            | ConsensusRuleSet::HardforkGamma
            | ConsensusRuleSet::HardforkDelta
            | ConsensusRuleSet::SoftforkEpsilon => MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS,
        }
    }
    pub fn max_num_announcements(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::TvmProofVersion1
            | ConsensusRuleSet::HardforkBeta
            | ConsensusRuleSet::HardforkGamma
            | ConsensusRuleSet::HardforkDelta
            | ConsensusRuleSet::SoftforkEpsilon => MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS,
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
            Network::Main => BLOCK_HEIGHT_HARDFORK_DELTA_MAIN_NET.previous().unwrap(),
            Network::Testnet(0) => BLOCK_HEIGHT_HARDFORK_DELTA_TESTNET.previous().unwrap(),
            _ => BlockHeight::genesis(),
        }
    }

    pub(crate) fn lustration_rule(
        network: Network,
        block_height: BlockHeight,
        last_aocl_leaf_index: u64,
    ) -> Option<LustrationRule> {
        let initial_counter = Self::lustration_counter_initial(network, block_height)?;
        let rule = if Self::resets_lustration_status(network, block_height) {
            LustrationRule::Initial(LustrationStatus {
                counter: initial_counter,
                max_lustrating_aocl_leaf_index: last_aocl_leaf_index,
            })
        } else {
            LustrationRule::Updated { initial_counter }
        };
        Some(rule)
    }

    /// Whether a block at this height resets the lustration status: the
    /// first block of hard fork beta and of hard fork gamma.
    pub(crate) fn resets_lustration_status(network: Network, block_height: BlockHeight) -> bool {
        block_height == Self::first_lustration_block(network)
            || block_height == Self::hardfork_gamma_activation_block_height(network)
    }

    /// The value the lustration counter started from at the last reset by
    /// this height: the premine, the claims pool and the subsidy mined by
    /// the reset. None before lustration began.
    pub(crate) fn lustration_counter_initial(
        network: Network,
        block_height: BlockHeight,
    ) -> Option<NativeCurrencyAmount> {
        let first_hf_beta_block = Self::first_lustration_block(network);
        let first_hf_gamma_block = Self::hardfork_gamma_activation_block_height(network);
        assert!(
            first_hf_beta_block.get_generation().is_zero()
                && first_hf_gamma_block.get_generation().is_zero(),
            "This calculation assumes all transparency gateways start at generation zero."
        );
        let reset = if block_height < first_hf_beta_block {
            return None;
        } else if block_height < first_hf_gamma_block {
            first_hf_beta_block
        } else {
            first_hf_gamma_block
        };

        let premine = PREMINE_MAX_SIZE;
        let claims_pool = INITIAL_BLOCK_SUBSIDY
            .scalar_mul(u32::try_from(NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT).unwrap());
        let mined_by_reset =
            INITIAL_BLOCK_SUBSIDY.scalar_mul(u32::try_from(reset.value()).unwrap());
        Some(premine + claims_pool + mined_by_reset)
    }

    fn hardfork_gamma_activation_block_height(network: Network) -> BlockHeight {
        let one = BlockHeight::genesis().next();
        match network {
            Network::Main => BLOCK_HEIGHT_HARDFORK_GAMMA_MAIN_NET,
            Network::Testnet(0) => BLOCK_HEIGHT_HARDFORK_GAMMA_TESTNET,
            Network::Testnet(_) => one,
            Network::TestnetMock => one,
            Network::RegTest => one,
            _ => one,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use neptune_primitives::difficulty_control::Difficulty;
    use tasm_lib::twenty_first::bfe;
    use tracing_test::traced_test;

    use super::*;
    use crate::block::validity::block_primitive_witness::BlockPrimitiveWitness;
    use crate::block::Block;
    use crate::proof_abstractions::test_runtime::tokio_runtime;
    use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

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

    /// The predecessor claim is required from the epsilon heights on, and
    /// from height 1 on the networks that are always on epsilon.
    #[test]
    fn ruleset_epsilon_activates_the_predecessor_claim() {
        let requires = |network, height: u64| {
            ConsensusRuleSet::infer_from(network, height.into()).requires_predecessor_claim()
        };
        for network in [Network::Testnet(1), Network::TestnetMock, Network::RegTest] {
            assert!(requires(network, 1));
            assert_eq!(
                BlockHeight::from(1u64),
                ConsensusRuleSet::epsilon_activation_block_height(network)
            );
        }
        for network in [Network::Main, Network::Testnet(0)] {
            let activation = ConsensusRuleSet::epsilon_activation_block_height(network);
            assert!(requires(network, activation.value()));
            assert!(!requires(network, activation.value() - 1));
        }
    }

    #[test]
    fn epsilon_sets_the_floor_and_the_reveals_per_network() {
        let delta = ConsensusRuleSet::HardforkDelta;
        let epsilon = ConsensusRuleSet::SoftforkEpsilon;
        assert_eq!(0, delta.min_swbf_padded_rows(Network::Main));
        assert!(!delta.miners_must_prove_ams_knowledge(Network::Main));
        assert_eq!(1 << 23, epsilon.min_swbf_padded_rows(Network::Main));
        assert_eq!(1 << 23, epsilon.min_swbf_padded_rows(Network::Testnet(0)));
        assert_eq!(1 << 22, epsilon.min_swbf_padded_rows(Network::Testnet(1)));
        assert_eq!(1 << 21, epsilon.min_swbf_padded_rows(Network::Testnet(42)));
        assert!(epsilon.miners_must_prove_ams_knowledge(Network::Testnet(0)));
        assert!(epsilon.miners_must_prove_ams_knowledge(Network::Testnet(42)));
        assert!(!epsilon.miners_must_prove_ams_knowledge(Network::Testnet(1)));
        for network in Network::all_networks() {
            assert_eq!(
                network.use_mock_proof() || network == Network::Testnet(1),
                !epsilon.miners_must_prove_ams_knowledge(network)
            );
            assert_eq!(
                network.use_mock_proof(),
                epsilon.min_swbf_padded_rows(network) == 0
            );
        }
    }

    #[test]
    fn epoch_on_main_net() {
        let table = ConsensusRuleSet::epoch_table(Network::Main);
        let expected = Epoch {
            height: bfe!(BLOCK_HEIGHT_SOFTFORK_EPSILON_MAIN_NET.value()),
            minimum_block_time: Timestamp::seconds(60),
            target_block_interval: Timestamp::millis(588_000),
            max_num_inputs: bfe!(1 << 14),
            max_num_outputs: bfe!(1 << 14),
            max_num_announcements: bfe!(1 << 14),
            max_block_size: bfe!(1_000_000),
            transaction_backdating_threshold: Timestamp::days(3),
            lustration_counter_initial: NativeCurrencyAmount::coins(8_717_568),
            resets_lustration_status: bfe!(0),
            min_swbf_padded_rows: bfe!(1u64 << 23),
            requires_mutator_set_reveals: bfe!(1),
            block_program_digest: BlockProgram.hash(),
            single_proof_digest: SingleProof::new(ConsensusRuleSet::SoftforkEpsilon).hash(),
            swbf_aggregation_digest: SwbfUpdateAggregation::new().hash(),
        };
        assert_eq!(EpochTable::new(&[expected]), table);
        assert_eq!(
            expected,
            table.in_force_at(BLOCK_HEIGHT_SOFTFORK_EPSILON_MAIN_NET)
        );
        assert_eq!(expected, table.in_force_at(1_000_000.into()));
    }

    #[test]
    fn epoch_on_testnet_0() {
        let table = ConsensusRuleSet::epoch_table(Network::Testnet(0));
        let expected = Epoch {
            height: bfe!(6_260),
            lustration_counter_initial: NativeCurrencyAmount::coins(4_154_368),
            ..ConsensusRuleSet::epoch_table(Network::Main).in_force_at(65_000.into())
        };
        assert_eq!(EpochTable::new(&[expected]), table);
    }

    #[test]
    fn network_table_activates_with_epsilon() {
        for network in Network::all_networks() {
            let table = ConsensusRuleSet::epoch_table(network);
            let height = table.activation_height();
            let rule_set = ConsensusRuleSet::infer_from(network, height);
            assert!(rule_set.requires_predecessor_claim());
            let before = height.previous().unwrap();
            assert_eq!(
                before.is_genesis(),
                ConsensusRuleSet::infer_from(network, before).requires_predecessor_claim()
            );
            let epoch = table.in_force_at(height);
            assert_eq!(
                bfe!(rule_set.min_swbf_padded_rows(network)),
                epoch.min_swbf_padded_rows
            );
            assert_eq!(
                bfe!(u64::from(rule_set.miners_must_prove_ams_knowledge(network))),
                epoch.requires_mutator_set_reveals
            );
        }
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
        assert!(!ConsensusRuleSet::HardforkDelta.use_parent_difficulty());
    }

    #[test]
    fn expected_tx_retirement_rule() {
        assert!(!ConsensusRuleSet::Reboot.enforce_transaction_retirement());
        assert!(!ConsensusRuleSet::HardforkAlpha.enforce_transaction_retirement());
        assert!(!ConsensusRuleSet::TvmProofVersion1.enforce_transaction_retirement());
        assert!(!ConsensusRuleSet::HardforkBeta.enforce_transaction_retirement());
        assert!(!ConsensusRuleSet::HardforkGamma.enforce_transaction_retirement());
        assert!(ConsensusRuleSet::HardforkDelta.enforce_transaction_retirement());
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
        assert_eq!(
            8,
            ConsensusRuleSet::HardforkDelta
                .triton_proof_version()
                .version(),
        );
    }

    /// The newest rule set must name the version the *linked* Triton VM uses.
    #[test]
    fn newest_rule_set_tracks_the_linked_triton_vm() {
        use tasm_lib::triton_vm::proof::CURRENT_VERSION;

        assert_eq!(
            CURRENT_VERSION,
            ConsensusRuleSet::HardforkDelta
                .triton_proof_version()
                .version(),
        );
        assert_eq!(
            5,
            ConsensusRuleSet::HardforkGamma
                .triton_proof_version()
                .version(),
            "gamma's version is history and must never move"
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
        // Start well into hardfork delta, before epsilon
        let init_block_heigth = BlockHeight::from(60_000u64);
        let network = Network::Main;
        let bpw = BlockPrimitiveWitness::deterministic_with_block_height_and_difficulty(
            init_block_heigth,
            Difficulty::MINIMUM,
            network,
        );

        tokio_runtime().block_on(new_block_allow_non_zero_version(bpw, network));

        async fn new_block_allow_non_zero_version(
            block_primitive_witness: BlockPrimitiveWitness,
            network: Network,
        ) {
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

            let consensus_rule_set =
                ConsensusRuleSet::infer_from(network, valid_successor.header().height);
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
