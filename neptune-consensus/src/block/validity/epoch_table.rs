use neptune_primitives::block_height::BlockHeight;
use neptune_primitives::network::Network;
use neptune_primitives::timestamp::Timestamp;
use num_traits::Zero;
use tasm_lib::prelude::TasmObject;
use tasm_lib::triton_vm::prelude::*;

use crate::consensus_rule_set::ConsensusRuleSet;
use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

/// The consensus parameters in force from a block height on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BFieldCodec, TasmObject)]
pub struct Epoch {
    /// The first block height the parameters apply to. An entry of an
    /// [`EpochTable`] that is all zeros is unused.
    pub height: BFieldElement,
    pub minimum_block_time: Timestamp,
    pub target_block_interval: Timestamp,
    pub max_num_inputs: BFieldElement,
    pub max_num_outputs: BFieldElement,
    pub max_num_announcements: BFieldElement,

    /// Maximum block size in number of BFieldElements.
    pub max_block_size: BFieldElement,

    /// How far a block's transaction may be backdated relative to the block.
    pub transaction_backdating_threshold: Timestamp,

    /// The value the lustration counter started from; no block's counter may
    /// exceed it.
    pub lustration_counter_initial: NativeCurrencyAmount,

    /// Whether the epoch's first block resets the lustration status, to the
    /// initial counter and its own last AOCL leaf index as the threshold: 1
    /// if so, 0 otherwise.
    pub resets_lustration_status: BFieldElement,

    /// The least the padded heights of the leaf proofs beneath a block's
    /// SWBF update claim may sum to: proving work a block carries whatever
    /// its inputs, so that leaving transactions out saves the composer
    /// nothing. Zero for no floor.
    pub min_swbf_padded_rows: BFieldElement,
    /// Whether a block must reveal the mutator set after its parent: the
    /// guesser a leaf of the inactive SWBF's first Merkle tree in the
    /// proof-of-work field, the composer two chunks and an AOCL leaf through
    /// a claim in the appendix. 1 if so, 0 otherwise.
    pub requires_mutator_set_reveals: BFieldElement,
}

/// Number of entries in an [`EpochTable`], used or not.
pub const NUM_EPOCHS: usize = 8;

/// The epochs since this claim's activation, in order of height, followed by
/// unused entries.
///
/// Public input of the claim that binds the program execution to the network
/// rules, without hardcoding values that might differ per network, or might
/// change in a future fork. A fork appends an epoch; to revise an epoch that
/// has not started, it appends one at the same height, which takes
/// precedence. The recursion accepts that: a block's claim must hold a prefix
/// of its successor's table, short only of epochs that had not started by
/// the block's height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BFieldCodec)]
pub struct EpochTable([Epoch; NUM_EPOCHS]);

impl EpochTable {
    /// # Panics
    ///
    /// If there is no epoch or more than fit, if they are not in order of
    /// height, or if one starts at genesis.
    pub fn new(epochs: &[Epoch]) -> Self {
        assert!(!epochs.is_empty(), "the program's gate is the first epoch");
        assert!(epochs.len() <= NUM_EPOCHS, "too many epochs");
        assert!(
            epochs.iter().all(|epoch| !epoch.height.is_zero()),
            "epoch cannot start at genesis"
        );
        assert!(
            epochs
                .windows(2)
                .all(|pair| pair[0].height.value() <= pair[1].height.value()),
            "epochs must be in order of height"
        );

        let mut table = [Epoch::default(); NUM_EPOCHS];
        table[..epochs.len()].copy_from_slice(epochs);

        Self(table)
    }

    /// The table a network's blocks carry from hard fork epsilon on, with
    /// the parameters of the latest rule set.
    pub fn for_network(network: Network) -> Self {
        let activation_height = ConsensusRuleSet::hardfork_epsilon_activation_block_height(network);
        let rule_set = ConsensusRuleSet::infer_from(network, activation_height);
        let initial_counter =
            ConsensusRuleSet::lustration_counter_initial(network, activation_height)
                .expect("all hard fork epsilon blocks lustrate");
        let epoch_resets_lustration =
            ConsensusRuleSet::resets_lustration_status(network, activation_height);
        // Two leaf proofs' worth on the networks that matter; one on the
        // other real-proof networks, for faster tests; none with mock proofs.
        let min_swbf_padded_rows = match network {
            Network::Main | Network::Testnet(0) => 1u64 << 23,
            Network::Testnet(1) => 1u64 << 22,
            _ if network.use_mock_proof() => 0,
            _ => 1 << 21,
        };
        Self::new(&[Epoch {
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
            min_swbf_padded_rows: bfe!(min_swbf_padded_rows),
            requires_mutator_set_reveals: bfe!(1),
        }])
    }

    /// The height from which blocks must carry this claim.
    pub fn activation_height(&self) -> BlockHeight {
        self.0[0].height.into()
    }

    /// Whether the epoch has started by this height. Unused entries never
    /// have.
    fn has_started(epoch: &Epoch, height: BlockHeight) -> bool {
        !epoch.height.is_zero() && epoch.height.value() <= height.value()
    }

    /// The epoch in force at this height.
    ///
    /// The epoch in force at this height is the last entry that has already
    /// started. So the last entry with a height less than or equal to current
    /// block height.
    ///
    /// # Panics
    ///
    /// If the height precedes activation.
    pub fn in_force_at(&self, height: BlockHeight) -> Epoch {
        *self
            .0
            .iter()
            .rev()
            .find(|epoch| Self::has_started(epoch, height))
            .expect("height must not precede activation")
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    impl EpochTable {
        /// Whether the other table holds all of this table's epochs, and any
        /// epochs it holds beyond those had not started by this height.
        pub(in crate::block::validity) fn is_prefix_of_up_to(
            &self,
            other: &Self,
            height: BlockHeight,
        ) -> bool {
            self.0.iter().zip(&other.0).all(|(own, others)| {
                own == others || (*own == Epoch::default() && !Self::has_started(others, height))
            })
        }
    }

    fn epoch(height: u64, minimum_block_time: u64) -> Epoch {
        Epoch {
            height: bfe!(height),
            minimum_block_time: Timestamp::millis(minimum_block_time),
            ..Epoch::default()
        }
    }

    #[test]
    fn last_started_epoch_is_in_force() {
        let table = EpochTable::new(&[epoch(10, 1), epoch(20, 2), epoch(30, 3), epoch(30, 4)]);
        assert_eq!(epoch(10, 1), table.in_force_at(10.into()));
        assert_eq!(epoch(10, 1), table.in_force_at(19.into()));
        assert_eq!(epoch(20, 2), table.in_force_at(20.into()));
        assert_eq!(epoch(30, 4), table.in_force_at(1_000.into()));
    }

    #[test]
    #[should_panic(expected = "height must not precede activation")]
    fn no_epoch_is_in_force_before_activation() {
        EpochTable::new(&[epoch(10, 1)]).in_force_at(9.into());
    }

    #[test]
    fn table_is_a_prefix_of_its_extension_by_unstarted_epochs() {
        let short = EpochTable::new(&[epoch(10, 1)]);
        let long = EpochTable::new(&[epoch(10, 1), epoch(20, 2)]);
        let other = EpochTable::new(&[epoch(10, 1), epoch(20, 3)]);

        assert!(short.is_prefix_of_up_to(&long, 19.into()));
        assert!(!short.is_prefix_of_up_to(&long, 20.into()));
        assert!(!long.is_prefix_of_up_to(&short, 19.into()));
        assert!(long.is_prefix_of_up_to(&long, 1_000.into()));
        assert!(!long.is_prefix_of_up_to(&other, 19.into()));
    }

    #[test]
    fn unused_entry_must_be_all_zeros() {
        let table = EpochTable::new(&[epoch(10, 1)]);
        let mut with_junk = table;
        with_junk.0[1].minimum_block_time = Timestamp::millis(1);

        assert!(table.is_prefix_of_up_to(&with_junk, 1_000.into()));
        assert!(!with_junk.is_prefix_of_up_to(&table, 1_000.into()));
    }

    /// Main net's one epoch, every field against a number derived by hand:
    /// the counter is the premine, 128 coins for each of the 21,310 blocks
    /// skipped at the reboot, and 128 for each of the 40,300 blocks mined by
    /// the gamma reset.
    #[test]
    fn epoch_on_main_net() {
        let table = EpochTable::for_network(Network::Main);
        let expected = Epoch {
            height: bfe!(65_000),
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
        };
        assert_eq!(EpochTable::new(&[expected]), table);
        assert_eq!(expected, table.in_force_at(65_000.into()));
        assert_eq!(expected, table.in_force_at(1_000_000.into()));
    }

    /// Testnet-0's one epoch: the same but for the heights and the counter,
    /// whose gamma reset mined 4,650 blocks.
    #[test]
    fn epoch_on_testnet_0() {
        let table = EpochTable::for_network(Network::Testnet(0));
        let expected = Epoch {
            height: bfe!(6_260),
            lustration_counter_initial: NativeCurrencyAmount::coins(4_154_368),
            ..EpochTable::for_network(Network::Main).in_force_at(65_000.into())
        };
        assert_eq!(EpochTable::new(&[expected]), table);
    }

    #[test]
    fn network_table_activates_with_hardfork_epsilon() {
        for network in Network::all_networks() {
            let table = EpochTable::for_network(network);
            let height = table.activation_height();
            assert!(ConsensusRuleSet::infer_from(network, height).requires_predecessor_claim());
            let before = height.previous().unwrap();
            assert_eq!(
                before.is_genesis(),
                ConsensusRuleSet::infer_from(network, before).requires_predecessor_claim()
            );
            let epoch = table.in_force_at(height);
            assert_eq!(bfe!(1), epoch.requires_mutator_set_reveals);
            assert_eq!(
                network.use_mock_proof(),
                epoch.min_swbf_padded_rows.is_zero()
            );
            let two_leaves = matches!(network, Network::Main | Network::Testnet(0));
            assert_eq!(two_leaves, epoch.min_swbf_padded_rows == bfe!(1u64 << 23));
        }
    }

    #[test]
    #[should_panic(expected = "the program's gate is the first epoch")]
    fn table_must_hold_an_epoch() {
        EpochTable::new(&[]);
    }

    #[test]
    #[should_panic(expected = "in order of height")]
    fn epochs_must_be_in_order_of_height() {
        EpochTable::new(&[epoch(20, 1), epoch(10, 2)]);
    }
}
