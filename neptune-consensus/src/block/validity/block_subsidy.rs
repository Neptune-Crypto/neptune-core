use neptune_primitives::block_height::BLOCKS_PER_GENERATION;
use neptune_primitives::block_height::NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT;
use tasm_lib::arithmetic::i128::shift_right::ShiftRight as I128ShiftRight;
use tasm_lib::arithmetic::u64::add::Add as U64Add;
use tasm_lib::arithmetic::u64::shift_right::ShiftRight as U64ShiftRight;
use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use super::epoch_table::Epoch;
use crate::block::INITIAL_BLOCK_SUBSIDY;

/// The block subsidy at the given block height under the epoch, as
/// `Epoch::block_subsidy` computes: the original schedule's subsidy at the
/// block's equivalent height, halved once more per speedup.
///
/// ```text
/// BEFORE: _ *epoch height
/// AFTER:  _ [block_subsidy: i128]
/// ```
#[derive(Debug, Copy, Clone)]
pub(super) struct BlockSubsidy;

impl BasicSnippet for BlockSubsidy {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*epoch".to_string()),
            (DataType::Bfe, "height".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(DataType::I128, "block_subsidy".to_string())]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_subsidy".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let u64_shift_right = library.import(Box::new(U64ShiftRight));
        let u64_add = library.import(Box::new(U64Add));
        let i128_shift_right = library.import(Box::new(I128ShiftRight));
        let read_log2_speedup = triton_asm!({&field!(Epoch::speedup_log2)} read_mem 1 pop 1);

        triton_asm!(
            // BEFORE: _ *epoch height
            // AFTER:  _ [block_subsidy: i128]
            {self.entrypoint()}:
                split
                dup 2 {&read_log2_speedup}
                call {u64_shift_right}
                // _ *epoch [height >> speedup]

                dup 2 {&field!(Epoch::equivalent_height_offset)} read_mem 1 pop 1 split
                call {u64_add}
                push 0 push {NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT}
                call {u64_add}
                // _ *epoch hi lo

                push {BLOCKS_PER_GENERATION} swap 1 div_mod pop 1
                // _ *epoch hi generation_of_lo

                dup 2 {&read_log2_speedup} add
                // _ *epoch hi halvings_of_lo

                dup 0 push 127 lt
                // _ *epoch hi halvings_of_lo (127 < halvings_of_lo)

                dup 0 push 127 mul place 2 push 0 eq mul add
                // _ *epoch hi min(halvings_of_lo, 127)

                pick 1 push 0 eq
                // _ *epoch min(halvings_of_lo, 127) (hi == 0)

                dup 0 push 0 eq
                // _ *epoch min(halvings_of_lo, 127) (hi == 0) (hi != 0)

                push 127 mul
                // _ *epoch min(halvings_of_lo, 127) (hi == 0) ((hi != 0) * 127)

                place 2
                // _ *epoch ((hi != 0) * 127) min(halvings_of_lo, 127) (hi == 0)

                mul
                // _ *epoch ((hi != 0) * 127) (min(halvings_of_lo, 127) * (hi == 0))

                add
                // _ *epoch (hi == 0 ? min(halvings_of_lo, 127) : 127)
                // _ *epoch shift_amount

                pick 1 pop 1
                {&INITIAL_BLOCK_SUBSIDY.push_to_stack()}
                pick 4
                // _ [initial_block_subsidy] shift_amount

                call {i128_shift_right}
                // _ [block_subsidy]

                return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use neptune_primitives::block_height::BlockHeight;
    use neptune_primitives::block_height::BLOCKS_PER_GENERATION;
    use neptune_primitives::network::Network;
    use neptune_primitives::timestamp::Timestamp;
    use num_traits::Zero;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
    use tasm_lib::triton_vm::vm::VM;

    use super::*;
    use crate::block::validity::epoch_table::EpochTable;
    use crate::block::Block;
    use crate::consensus_rule_set::ConsensusRuleSet;
    use crate::consensus_rule_set::BLOCK_HEIGHT_SOFTFORK_EPSILON_MAIN_NET;
    use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

    /// An epoch without speedup, whose schedule is the one
    /// `Block::block_subsidy` hardcodes.
    fn epoch() -> Epoch {
        Epoch::default()
    }

    fn block_subsidy_in_vm_under(epoch: &Epoch, height: u64) -> NativeCurrencyAmount {
        let mut library = Library::new();
        let block_subsidy = library.import(Box::new(BlockSubsidy));
        let program = Program::new(&triton_asm!(
            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            read_io 1
            call {block_subsidy}
            {&DataType::I128.write_value_to_stdout()}
            halt
            {&library.all_imports()}
        ));

        let input = PublicInput::new(vec![bfe!(height)]);
        let mut nondeterminism = NonDeterminism::default();
        encode_to_memory(
            &mut nondeterminism.ram,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            epoch,
        );
        let output = VM::run(program, input, nondeterminism).unwrap();

        *NativeCurrencyAmount::decode(&output).unwrap()
    }

    fn block_subsidy_in_vm(height: u64) -> NativeCurrencyAmount {
        block_subsidy_in_vm_under(&epoch(), height)
    }

    #[test]
    fn speedup_halves_the_subsidy_and_stretches_the_generations() {
        // Blocks come four times as fast from height 1000 on, so the
        // equivalent height of 1000 is 1000 and grows by one per four blocks.
        let epoch = Epoch {
            speedup_log2: bfe!(2),
            equivalent_height_offset: bfe!(750),
            ..Epoch::default()
        };
        let quarter = |amount: NativeCurrencyAmount| amount.half().half();
        for height in [1_000, 1_001, 1 << 20, (1 << 32) + 7, 1 << 40] {
            let equivalent = BlockHeight::from(750 + (height >> 2));
            let expected = quarter(Block::block_subsidy(equivalent));
            assert_eq!(
                expected,
                epoch.block_subsidy(height.into()),
                "height {height}"
            );
            assert_eq!(expected, block_subsidy_in_vm_under(&epoch, height));
        }
        let first_halving = 4 * (BLOCKS_PER_GENERATION - NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT - 750);
        assert_eq!(
            quarter(INITIAL_BLOCK_SUBSIDY),
            epoch.block_subsidy((first_halving - 1).into())
        );
        assert_eq!(
            quarter(INITIAL_BLOCK_SUBSIDY).half(),
            epoch.block_subsidy(first_halving.into())
        );
    }

    #[test]
    fn main_net_epochs_with_two_halvings_of_the_block_interval() {
        let activation = BLOCK_HEIGHT_SOFTFORK_EPSILON_MAIN_NET.value();
        let initial = ConsensusRuleSet::epoch_table(Network::Main).in_force_at(activation.into());
        assert_eq!(Timestamp::millis(588_000), initial.target_block_interval);

        // Blocks come twice as fast from four blocks past activation on, so
        // the equivalent height of that block is its own height.
        let halving = activation + 4;
        let halved = Epoch {
            height: bfe!(halving),
            target_block_interval: Timestamp::millis(294_000),
            speedup_log2: bfe!(1),
            equivalent_height_offset: bfe!(halving - (halving >> 1)),
            ..initial
        };

        // Blocks come four times as fast from four blocks later on, by which
        // point the equivalent height trails the height by two.
        let second_halving = halving + 4;
        let equivalent = second_halving - 2;
        let quartered = Epoch {
            height: bfe!(second_halving),
            target_block_interval: Timestamp::millis(147_000),
            speedup_log2: bfe!(2),
            equivalent_height_offset: bfe!(equivalent - (second_halving >> 2)),
            ..initial
        };
        let table = EpochTable::new(&[initial, halved, quartered]);

        let half = INITIAL_BLOCK_SUBSIDY.half();
        let quarter = half.half();
        for (height, epoch, expected) in [
            (activation, initial, INITIAL_BLOCK_SUBSIDY),
            (halving - 1, initial, INITIAL_BLOCK_SUBSIDY),
            (halving, halved, half),
            (second_halving - 1, halved, half),
            (second_halving, quartered, quarter),
            (second_halving + 1, quartered, quarter),
            (second_halving + 4_000, quartered, quarter),
        ] {
            assert_eq!(epoch, table.in_force_at(height.into()), "height {height}");
            assert_eq!(
                expected,
                epoch.block_subsidy(height.into()),
                "height {height}"
            );
            assert_eq!(expected, block_subsidy_in_vm_under(&epoch, height));
        }

        // The four blocks sharing an equivalent height pay what the one
        // block at that height would have.
        let shared: Vec<_> = (second_halving..second_halving + 4)
            .map(|height| quartered.block_subsidy(height.into()))
            .collect();
        assert_eq!(
            Block::block_subsidy(equivalent.into()),
            shared.into_iter().sum::<NativeCurrencyAmount>()
        );

        // The generation ends when the equivalent height reaches the original
        // boundary: four times as many blocks past the second halving.
        let offset = quartered.equivalent_height_offset.value();
        let boundary = 4 * (BLOCKS_PER_GENERATION - NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT - offset);
        assert_eq!(quarter, block_subsidy_in_vm_under(&quartered, boundary - 1));
        assert_eq!(
            quarter.half(),
            block_subsidy_in_vm_under(&quartered, boundary)
        );
    }

    #[test]
    fn simple_speedup() {
        let single = Epoch::default();
        for height in 1u64..20 {
            let expected = NativeCurrencyAmount::coins(128);
            let in_vm = block_subsidy_in_vm_under(&single, height);
            assert_eq!(expected, in_vm);
        }

        // At block height 40, the block target interval is halved. The block
        // subsidy must also be halved.
        let double = Epoch {
            speedup_log2: bfe!(1),
            equivalent_height_offset: bfe!(20),
            ..Epoch::default()
        };

        for height in 40u64..50 {
            let expected = NativeCurrencyAmount::coins(64);
            let in_vm = block_subsidy_in_vm_under(&double, height);
            assert_eq!(expected, in_vm);
        }

        // And the block subsidy stays half the original longer than the blocks
        // per generation constant would dictate.
        assert_eq!(
            NativeCurrencyAmount::coins(64),
            block_subsidy_in_vm_under(&double, BLOCKS_PER_GENERATION + 2000)
        );
    }

    #[test]
    fn agrees_with_host_at_generation_boundaries() {
        let first_boundary = BLOCKS_PER_GENERATION - NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT;
        let mut heights = vec![0, 1, first_boundary - 1, first_boundary, first_boundary + 1];
        for generation in 1..130 {
            let boundary = generation * BLOCKS_PER_GENERATION - NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT;
            heights.extend([boundary - 1, boundary, boundary + 1]);
        }

        for height in heights {
            let expected = Block::block_subsidy(BlockHeight::from(height));
            assert_eq!(expected, block_subsidy_in_vm(height), "height {height}");
        }
    }

    #[test]
    fn subsidy_is_zero_far_in_the_future() {
        for height in [
            BLOCKS_PER_GENERATION * 127,
            BLOCKS_PER_GENERATION * 128,
            1 << 32,
            (1 << 32) + 7,
            u64::from(u32::MAX) * 3,
            1 << 62,
        ] {
            assert!(Block::block_subsidy(BlockHeight::from(height)).is_zero());
            assert!(block_subsidy_in_vm(height).is_zero());
        }
    }

    #[test]
    fn subsidy_halves_each_generation() {
        let mut previous = block_subsidy_in_vm(0);
        assert_eq!(INITIAL_BLOCK_SUBSIDY, previous);
        for generation in 1..10 {
            let current = block_subsidy_in_vm(generation * BLOCKS_PER_GENERATION);
            assert_eq!(previous.half(), current);
            previous = current;
        }
    }
}
