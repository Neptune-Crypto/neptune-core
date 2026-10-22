use neptune_primitives::block_height::BLOCKS_PER_GENERATION;
use neptune_primitives::block_height::NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT;
use tasm_lib::arithmetic::i128::shift_right::ShiftRight as I128ShiftRight;
use tasm_lib::data_type::DataType;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use crate::block::INITIAL_BLOCK_SUBSIDY;

/// The block subsidy at the given block height, as `Block::block_subsidy`
/// computes: the initial subsidy halved once per generation.
///
/// ```text
/// BEFORE: _ height
/// AFTER:  _ [block_subsidy: i128]
/// ```
#[derive(Debug, Copy, Clone)]
pub(super) struct BlockSubsidy;

impl BasicSnippet for BlockSubsidy {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![(DataType::Bfe, "height".to_string())]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(DataType::I128, "block_subsidy".to_string())]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_subsidy".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let i128_shift_right = library.import(Box::new(I128ShiftRight));

        triton_asm!(
            // BEFORE: _ height
            // AFTER:  _ [block_subsidy: i128]
            {self.entrypoint()}:
                addi {NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT} split
                // _ hi lo

                push {BLOCKS_PER_GENERATION} swap 1 div_mod pop 1
                // _ hi generation_of_lo

                dup 0 push 127 lt
                // _ hi generation_of_lo (127 < generation_of_lo)

                dup 0 push 127 mul place 2 push 0 eq mul add
                // _ hi min(generation_of_lo, 127)

                pick 1 push 0 eq
                // _ min(generation_of_lo, 127) (hi == 0)

                dup 0 push 0 eq
                // _ min(generation_of_lo, 127) (hi == 0) (hi != 0)

                push 127 mul
                // _ min(generation_of_lo, 127) (hi == 0) ((hi != 0) * 127)

                place 2
                // _ ((hi != 0) * 127) min(generation_of_lo, 127) (hi == 0)

                mul
                // _ ((hi != 0) * 127) (min(generation_of_lo, 127) * (hi == 0))

                add
                // _ hi == 0 ? min(generation_of_lo, 127) : 127
                // _ min(num_generations, 127)
                // _ shift_amount <-- rename

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
    use num_traits::Zero;
    use tasm_lib::triton_vm::vm::VM;

    use super::*;
    use crate::block::Block;
    use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

    fn block_subsidy_in_vm(height: u64) -> NativeCurrencyAmount {
        let mut library = Library::new();
        let block_subsidy = library.import(Box::new(BlockSubsidy));
        let program = Program::new(&triton_asm!(
            read_io 1
            call {block_subsidy}
            {&DataType::I128.write_value_to_stdout()}
            halt
            {&library.all_imports()}
        ));

        let input = PublicInput::new(vec![bfe!(height)]);
        let output = VM::run(program, input, NonDeterminism::default()).unwrap();

        *NativeCurrencyAmount::decode(&output).unwrap()
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
