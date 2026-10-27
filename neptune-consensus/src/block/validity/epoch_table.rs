use neptune_primitives::block_height::BlockHeight;
use neptune_primitives::block_height::BLOCKS_PER_GENERATION;
use neptune_primitives::block_height::NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT;
use neptune_primitives::timestamp::Timestamp;
use num_traits::Zero;
use tasm_lib::prelude::TasmObject;
use tasm_lib::triton_vm::prelude::*;

use crate::block::INITIAL_BLOCK_SUBSIDY;
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

    /// How many times the block interval has halved since genesis. The
    /// emission schedule follows: a block's subsidy is the original
    /// schedule's at the block's equivalent height, halved this many times.
    pub speedup_log2: BFieldElement,

    /// Let the equivalent block height be the height the block would have had
    /// at the original block target interval: the block height which gives the
    /// correct subsidy assuming the original number of blocks per generation.
    ///
    /// The equivalent height of a block at height `h` is `h >> speedup_log2`
    /// plus this offset: the height the block would have at the original
    /// block interval. The offset makes the equivalent height continuous
    /// across epochs.
    ///
    /// Example:
    ///   - Interval 588 s becomes 294 s.
    ///   - ebh(100,000) = 100,000, by continuity with the first epoch
    ///   - ebh(150,000) = 100,000 + 50,000 / 2 = 125,000
    ///   - Offset: 125,000 − (150,000 >> 1) = 50,000
    ///
    /// In general the offset is start − (start >> s) when no earlier epoch had
    /// a speedup.
    ///
    /// The emission per unit of equivalent height is invariant: after a
    /// speedup, 2^s blocks share one equivalent height, and each pays the
    /// original schedule's subsidy for that height divided by 2^s.
    pub equivalent_height_offset: BFieldElement,

    /// The value the lustration counter started from; no block's counter may
    /// exceed it.
    pub lustration_counter_initial: NativeCurrencyAmount,

    /// Whether the epoch's first block resets the lustration status, to the
    /// initial counter and its own last AOCL leaf index as the threshold: 1
    /// if so, 0 otherwise.
    pub resets_lustration_status: BFieldElement,

    /// Bar for proving complexity that the composer must pass when
    /// constructing the SWBF update proof.
    ///
    /// The least the padded heights of the leaf proofs beneath a block's
    /// SWBF update claim may sum to: proving work a block carries whatever
    /// its inputs, so that leaving transactions out saves the composer
    /// nothing. Zero for no floor.
    pub min_swbf_padded_rows: BFieldElement,

    /// The digest of the program a block's proof attests.
    pub block_program_digest: Digest,

    /// The digest of the program the transaction claim in a block's appendix
    /// is about.
    pub single_proof_digest: Digest,

    /// Program digest of the SWBF update
    pub swbf_aggregation_digest: Digest,
}

impl Epoch {
    /// The height a block at this height would have at the original block
    /// interval.
    fn equivalent_height(&self, height: BlockHeight) -> u64 {
        self.equivalent_height_offset.value() + (height.value() >> self.speedup_log2.value())
    }

    /// The block subsidy at this height: the original schedule's at the
    /// equivalent height, counting the blocks skipped at the reboot, halved
    /// once more per speedup.
    pub fn block_subsidy(&self, height: BlockHeight) -> NativeCurrencyAmount {
        let generation = self
            .equivalent_height(height)
            .saturating_add(NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT)
            / BLOCKS_PER_GENERATION;
        let halvings = generation.saturating_add(self.speedup_log2.value());
        let mut subsidy = INITIAL_BLOCK_SUBSIDY;
        for _ in 0..std::cmp::min(halvings, 127) {
            subsidy.div_two();
        }
        subsidy
    }
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
    /// height, if one starts at genesis, if the first epoch changes the
    /// emission schedule, if a speedup exceeds 63 halvings, or if the
    /// equivalent height jumps between epochs.
    pub fn new(epochs: &[Epoch]) -> Self {
        assert!(!epochs.is_empty(), "the program's gate is the first epoch");
        assert!(epochs.len() <= NUM_EPOCHS, "too many epochs");
        assert!(
            epochs.iter().all(|epoch| !epoch.height.is_zero()),
            "epoch cannot start at genesis"
        );
        assert!(
            epochs[0].speedup_log2.is_zero() && epochs[0].equivalent_height_offset.is_zero(),
            "the first epoch keeps the original emission schedule"
        );
        assert!(
            epochs.iter().all(|epoch| epoch.speedup_log2.value() < 64),
            "a speedup is fewer than 64 halvings"
        );
        assert!(
            epochs.windows(2).all(|pair| {
                let start = pair[1].height.into();
                pair[0].equivalent_height(start) == pair[1].equivalent_height(start)
            }),
            "the equivalent height is continuous across epochs"
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

    /// The height from which blocks must carry this claim.
    pub fn activation_height(&self) -> BlockHeight {
        self.0[0].height.into()
    }

    /// Whether the epoch has started by this height. Unused entries never
    /// have.
    fn has_started(epoch: &Epoch, height: BlockHeight) -> bool {
        !epoch.height.is_zero() && epoch.height.value() <= height.value()
    }

    /// The epoch in force at this height: the last entry that has started,
    /// or the first entry for a height before activation, whose program
    /// digests apply to the block before the first one with this claim.
    pub fn in_force_at(&self, height: BlockHeight) -> Epoch {
        *self
            .0
            .iter()
            .rev()
            .find(|epoch| Self::has_started(epoch, height))
            .unwrap_or(&self.0[0])
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
    fn first_epoch_is_in_force_before_activation() {
        let table = EpochTable::new(&[epoch(10, 1), epoch(20, 2)]);
        assert_eq!(epoch(10, 1), table.in_force_at(9.into()));
        assert_eq!(epoch(10, 1), table.in_force_at(0.into()));
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
