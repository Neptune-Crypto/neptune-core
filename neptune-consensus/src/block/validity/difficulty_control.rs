use neptune_primitives::block_height::BlockHeight;
use neptune_primitives::timestamp::Timestamp;
use tasm_lib::arithmetic::u128::lt::Lt as U128Lt;
use tasm_lib::arithmetic::u160::lt::Lt as U160Lt;
use tasm_lib::arithmetic::u320::mul_u160::U320MulU160;
use tasm_lib::arithmetic::u64::add::Add as U64Add;
use tasm_lib::arithmetic::u64::lt::Lt as U64Lt;
use tasm_lib::arithmetic::u64::mul_two_u64s_to_u128::MulTwoU64sToU128;
use tasm_lib::arithmetic::u64::safe_mul::SafeMul as U64SafeMul;
use tasm_lib::arithmetic::u64::shift_right::ShiftRight as U64ShiftRight;
use tasm_lib::arithmetic::u64::sub::Sub as U64Sub;
use tasm_lib::data_type::DataType;
use tasm_lib::library::StaticAllocation;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

/// The difficulty of the block after the given one, like
/// [`difficulty_control`](neptune_primitives::difficulty_control::difficulty_control).
///
/// ```text
/// BEFORE: _ [old_difficulty: u160] [target_block_interval: u64] [old_timestamp: u64] [new_timestamp: u64] previous_block_height
/// AFTER:  _ [new_difficulty: u160]
/// ```
///
/// The host computes a signed, clamped relative error. Here the sign is
/// split off first, so that everything else is unsigned: the error's
/// magnitude is clamped, shifted, and applied to `2^32` in the direction the
/// sign dictates.
///
/// The one division takes its quotient and remainder from secret input, see
/// [`Self::divined_tokens`].
#[derive(Debug, Copy, Clone)]
pub(super) struct DifficultyControl;

impl DifficultyControl {
    const REMAINDER_NOT_BELOW_DIVISOR_ERROR: i128 = 1_000_420;
    const QUOTIENT_DOES_NOT_DIVIDE_ERROR: i128 = 1_000_421;

    const NUM_DIFFICULTY_LIMBS: usize = 5;
    const MINIMUM_DIFFICULTY_LIMB: u64 = 6000;
    const ONE: u64 = 1 << 32;
    const CLAMP_BELOW: u64 = 1 << 32;
    const CLAMP_ABOVE: u64 = 4 << 32;

    /// Divine-ine quotient and remainder of a u64 div/mod operation, rather
    /// than performing the very expensive u64 div/mod algorithm on a u32-worded
    /// machine.
    /// Empty when previous block height is genesis since parent difficulty is
    /// just carried over in that case.
    pub(super) fn divined_tokens(
        target_block_interval: Timestamp,
        previous_block_height: BlockHeight,
    ) -> Vec<BFieldElement> {
        if previous_block_height.is_genesis() {
            return Vec::new();
        }

        let target = target_block_interval.to_millis();
        let scale = Self::ONE.checked_div(target).unwrap_or(0);
        let remainder = Self::ONE.wrapping_sub(scale.wrapping_mul(target));

        let u64_words = |value: u64| [bfe!(value >> 32), bfe!(value & u64::from(u32::MAX))];
        [u64_words(scale), u64_words(remainder)].concat()
    }
}

impl BasicSnippet for DifficultyControl {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::U160, "old_difficulty".to_string()),
            (DataType::U64, "target_block_interval".to_string()),
            (DataType::U64, "old_timestamp".to_string()),
            (DataType::U64, "new_timestamp".to_string()),
            (DataType::Bfe, "previous_block_height".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(DataType::U160, "new_difficulty".to_string())]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_difficulty_control".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let entrypoint = self.entrypoint();
        let u64_sub = library.import(Box::new(U64Sub));
        let u64_add = library.import(Box::new(U64Add));
        let u64_lt = library.import(Box::new(U64Lt));
        let u64_safe_mul = library.import(Box::new(U64SafeMul));
        let u64_shift_right = library.import(Box::new(U64ShiftRight));
        let u160_lt = library.import(Box::new(U160Lt));
        let u128_lt = library.import(Box::new(U128Lt));
        let mul_two_u64s_to_u128 = library.import(Box::new(MulTwoU64sToU128));
        let u320_mul_u160 = library.import(Box::new(U320MulU160));

        let target = library.kmalloc(2);
        let delta = library.kmalloc(2);
        let scale = library.kmalloc(2);
        let sign = library.kmalloc(1);
        let clamp = library.kmalloc(2);
        let below_clamp = library.kmalloc(1);
        let one_plus_p_times_error = library.kmalloc(2);
        let overflow = library.kmalloc(1);
        let candidate = library.kmalloc(5);
        let above_minimum = library.kmalloc(1);

        let read = |alloc: &StaticAllocation| triton_asm!(push {alloc.read_address()} read_mem {alloc.num_words()} pop 1);
        let write = |alloc: &StaticAllocation| triton_asm!(push {alloc.write_address()} write_mem {alloc.num_words()} pop 1);
        let push_u64 =
            |value: u64| triton_asm!(push {value >> 32} push {value & u64::from(u32::MAX)});

        // Keep `a` if the flag is set, else `b`.
        // BEFORE: _ [a; n] [b; n] flag
        // AFTER:  _ [flag ? a : b; n]
        let select = |n: usize, name: &str| {
            let take_a = format!("{entrypoint}_{name}_take_a");
            let take_b = format!("{entrypoint}_{name}_take_b");
            let drop_a = (0..n)
                .flat_map(|i| triton_asm!(pick {2 * n - 1 - i} pop 1))
                .collect::<Vec<_>>();
            let call = triton_asm!(
                push 1 dup 1 push 0 eq skiz call {take_b} skiz call {take_a}
            );
            let subroutines = triton_asm!(
                // BEFORE: _ [a] [b] flag 1
                // AFTER:  _ [b] 0
                {take_b}:
                    pop 2
                    {&drop_a}
                    push 0
                    return

                // BEFORE: _ [a] [b] flag
                // AFTER:  _ [a]
                {take_a}:
                    pop 1
                    pop {n}
                    return
            );
            (call, subroutines)
        };
        let (select_u64, select_u64_code) = select(2, "u64");
        let (select_u160, select_u160_code) = select(5, "u160");

        let push_maximum_difficulty =
            vec![triton_asm!(push {u32::MAX}); Self::NUM_DIFFICULTY_LIMBS].concat();
        let push_minimum_difficulty = triton_asm!(
            push 0 push 0 push 0 push 0 push {Self::MINIMUM_DIFFICULTY_LIMB}
        );

        let genesis = format!("{entrypoint}_genesis");
        let adjust = format!("{entrypoint}_adjust");
        let divide = format!("{entrypoint}_divide");

        triton_asm!(
            // BEFORE: _ [old_difficulty] [target] [old_timestamp] [new_timestamp] previous_block_height
            // AFTER:  _ [new_difficulty]
            {entrypoint}:
                push 1 dup 1 push 0 eq skiz call {genesis} skiz call {adjust}
                return

            // BEFORE: _ [old_difficulty] [target] [old_timestamp] [new_timestamp] previous_block_height 1
            // AFTER:  _ [old_difficulty] 0
            {genesis}:
                pop 2 pop 4 pop 2
                push 0
                return

            // BEFORE: _ [old_difficulty] [target] [old_timestamp] [new_timestamp] previous_block_height
            // AFTER:  _ [new_difficulty]
            {adjust}:
                pop 1
                call {u64_sub}
                // _ [old_difficulty] [target] [delta]

                {&write(&delta)} {&write(&target)}
                // _ [old_difficulty]

                {&push_u64(Self::ONE)} {&read(&target)}
                // _ [old_difficulty] [1] [target]

                call {divide}
                // _ [old_difficulty] [1 / target]

                {&write(&scale)}
                // scale = 2^32 / target
                // _ [old_difficulty]

                {&read(&target)} {&read(&delta)} call {u64_lt}
                {&write(&sign)}
                // sign = delta < target

                {&read(&delta)} {&read(&target)} {&read(&sign)} {&select_u64}
                {&read(&target)} {&read(&delta)} {&read(&sign)} {&select_u64}
                call {u64_sub}
                // _ [old_difficulty] [distance]

                {&push_u64(Self::CLAMP_BELOW)} {&push_u64(Self::CLAMP_ABOVE)}
                {&read(&sign)} {&select_u64}
                {&write(&clamp)}
                // _ [old_difficulty] [distance]

                {&read(&scale)} call {mul_two_u64s_to_u128}
                // _ [old_difficulty] [error: u128]

                push 0 push 0 {&read(&clamp)}
                // _ [old_difficulty] [error] [clamp: u128]

                dup 7 dup 7 dup 7 dup 7 call {u128_lt}
                {&write(&below_clamp)}
                // _ [old_difficulty] [error]

                pick 3 pop 1 pick 2 pop 1
                // _ [old_difficulty] [error mod 2^64]

                {&read(&clamp)} {&read(&below_clamp)} {&select_u64}
                // _ [old_difficulty] [clamped_error]

                dup 1 dup 1 {&push_u64(15)} call {u64_add}
                {&read(&sign)} {&select_u64}
                push 4 call {u64_shift_right}
                // _ [old_difficulty] [p_times_error]

                dup 1 dup 1 {&push_u64(Self::ONE)} call {u64_add}
                pick 3 pick 3 {&push_u64(Self::ONE)} call {u64_sub}
                {&read(&sign)} {&select_u64}
                // _ [old_difficulty] [one_plus_p_times_error]

                {&write(&one_plus_p_times_error)}
                push 0 push 0 push 0 push 0 push 0 push 0 push 0 push 0
                {&read(&one_plus_p_times_error)}
                // _ [old_difficulty] [one_plus_p_times_error: u320]

                call {u320_mul_u160}
                pop 1
                // _ [product_limbs_14..=1]

                // The multiplier is at most 2^32 + 2^28, so the product is
                // below 2^193: limb 6 is the only one that can overflow.
                dup 5 push 0 eq push 0 eq
                {&write(&overflow)}
                // _ [product_limbs_14..=1]

                {&write(&candidate)}
                pop 5 pop 4
                // _

                {&push_maximum_difficulty} {&read(&candidate)} {&read(&overflow)} {&select_u160}
                {&write(&candidate)}
                // candidate = overflow ? maximum : product / 2^32

                {&read(&candidate)} push 0 push 0 push 0 push 0 push {Self::MINIMUM_DIFFICULTY_LIMB}
                call {u160_lt}
                {&write(&above_minimum)}
                // _

                {&read(&candidate)} {&push_minimum_difficulty} {&read(&above_minimum)} {&select_u160}
                // _ [new_difficulty]

                return

            // Divide by taking quotient and remainder from secret input.
            // BEFORE: _ [numerator] [denominator]
            // AFTER:  _ [quotient]
            // SECIN:  [quotient] [remainder]
            {divide}:
                divine 2
                divine 2
                // _ [numerator] [denominator] [quotient] [remainder]

                /* Ensure both divined values are valid u64 representations */
                dup 3 pop_count pop 1
                dup 2 pop_count pop 1
                dup 1 pop_count pop 1
                dup 0 pop_count pop 1
                // _ [numerator] [denominator] [quotient] [remainder]

                dup 5 dup 5 dup 3 dup 3 call {u64_lt}
                assert error_id {Self::REMAINDER_NOT_BELOW_DIVISOR_ERROR}
                // _ [numerator] [denominator] [quotient] [remainder]

                dup 3 dup 3 dup 7 dup 7
                // _ [numerator] [denominator] [quotient] [remainder] [quotient] [denominator]

                call {u64_safe_mul}
                dup 3 dup 3 call {u64_add}
                // _ [numerator] [denominator] [quotient] [remainder] [quotient * denominator + remainder]

                dup 9 dup 9 {&DataType::U64.compare()}
                assert error_id {Self::QUOTIENT_DOES_NOT_DIVIDE_ERROR}
                // _ [numerator] [denominator] [quotient] [remainder]

                pop 2
                pick 5 pop 1 pick 4 pop 1 pick 3 pop 1 pick 2 pop 1
                // _ [quotient]

                return

            {&select_u64_code}
            {&select_u160_code}
        )
    }
}

/// Run [`DifficultyControl`] in Triton VM on these inputs.
#[cfg(any(test, feature = "test-helpers"))]
pub fn difficulty_control_in_vm(
    old_difficulty: neptune_primitives::difficulty_control::Difficulty,
    target_block_interval: Timestamp,
    old_timestamp: Timestamp,
    new_timestamp: Timestamp,
    previous_block_height: BlockHeight,
) -> neptune_primitives::difficulty_control::Difficulty {
    use num_bigint::BigUint;

    let nondeterminism = NonDeterminism::new(DifficultyControl::divined_tokens(
        target_block_interval,
        previous_block_height,
    ));
    let output = run_in_vm(
        old_difficulty,
        target_block_interval,
        old_timestamp,
        new_timestamp,
        previous_block_height,
        nondeterminism,
    )
    .unwrap();

    let limbs = output
        .iter()
        .map(|word| u32::try_from(word.value()).unwrap())
        .collect::<Vec<_>>();
    neptune_primitives::difficulty_control::Difficulty::from_biguint(BigUint::new(limbs)).unwrap()
}

#[cfg(any(test, feature = "test-helpers"))]
fn run_in_vm(
    old_difficulty: neptune_primitives::difficulty_control::Difficulty,
    target_block_interval: Timestamp,
    old_timestamp: Timestamp,
    new_timestamp: Timestamp,
    previous_block_height: BlockHeight,
    nondeterminism: NonDeterminism,
) -> Result<Vec<BFieldElement>, tasm_lib::triton_vm::error::VMError> {
    use num_bigint::BigUint;
    use tasm_lib::triton_vm::vm::VM;

    let mut library = Library::new();
    let snippet = library.import(Box::new(DifficultyControl));
    let program = Program::new(&triton_asm!(
        read_io 5 read_io 2 read_io 2 read_io 2 read_io 1
        call {snippet}
        write_io 5
        halt
        {&library.all_imports()}
    ));

    let u64_words = |value: u64| [bfe!(value >> 32), bfe!(value & u64::from(u32::MAX))];
    let mut difficulty_limbs = BigUint::from(old_difficulty).to_u32_digits();
    difficulty_limbs.resize(DifficultyControl::NUM_DIFFICULTY_LIMBS, 0);
    let input = difficulty_limbs
        .iter()
        .rev()
        .map(|&limb| bfe!(limb))
        .chain(u64_words(target_block_interval.to_millis()))
        .chain(u64_words(old_timestamp.to_millis()))
        .chain(u64_words(new_timestamp.to_millis()))
        .chain([previous_block_height.into()])
        .collect::<Vec<_>>();
    VM::run(program, PublicInput::new(input), nondeterminism)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use neptune_primitives::difficulty_control::difficulty_control;
    use neptune_primitives::difficulty_control::Difficulty;
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use test_strategy::proptest;

    use super::*;

    fn assert_agrees_with_host(
        old_difficulty: Difficulty,
        target_block_interval: Timestamp,
        old_timestamp: Timestamp,
        new_timestamp: Timestamp,
        previous_block_height: BlockHeight,
    ) {
        let host = difficulty_control(
            new_timestamp,
            old_timestamp,
            old_difficulty,
            target_block_interval,
            previous_block_height,
        );
        let vm = difficulty_control_in_vm(
            old_difficulty,
            target_block_interval,
            old_timestamp,
            new_timestamp,
            previous_block_height,
        );
        assert_eq!(
            host, vm,
            "old {old_difficulty}, target {target_block_interval}, \
             old timestamp {old_timestamp}, new timestamp {new_timestamp}"
        );
    }

    #[test]
    fn agrees_with_host_on_random_inputs() {
        let mut rng = StdRng::seed_from_u64(0);
        let targets = [588_000u64, 294_000, 147_000, 60_000, 1_000, 1];
        for _ in 0..200 {
            let num_limbs = rng.random_range(1..=5);
            let mut limbs = [0u32; 5];
            limbs[..num_limbs].fill_with(|| rng.random());
            let old_difficulty = Difficulty::new(limbs);

            let target = targets[rng.random_range(0..targets.len())];
            let old_timestamp = rng.random_range(0..1u64 << 40);
            let delta = match rng.random_range(0..4) {
                0 => rng.random_range(60_000..target.max(60_001)),
                1 => rng.random_range(target..2 * target + 1),
                2 => rng.random_range(2 * target..100 * target + 1),
                _ => rng.random_range(60_000..1u64 << 40),
            };
            let height = BlockHeight::from(rng.random_range(1..4 * u64::from(u32::MAX)));

            assert_agrees_with_host(
                old_difficulty,
                Timestamp::millis(target),
                Timestamp::millis(old_timestamp),
                Timestamp::millis(old_timestamp + delta),
                height,
            );
        }
    }

    #[test]
    fn agrees_with_host_at_the_corners() {
        let target = Timestamp::millis(588_000);
        let old_timestamp = Timestamp::millis(1_000_000);
        let height = BlockHeight::from(100u64);
        for old_difficulty in [
            Difficulty::MINIMUM,
            Difficulty::new([6001, 0, 0, 0, 0]),
            Difficulty::new([0, 1, 0, 0, 0]),
            Difficulty::new([u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX >> 5]),
            Difficulty::MAXIMUM,
        ] {
            for delta in [
                60_000u64,
                587_999,
                588_000,
                588_001,
                2 * 588_000,
                5 * 588_000 - 1,
                5 * 588_000,
                5 * 588_000 + 1,
                1 << 40,
            ] {
                assert_agrees_with_host(
                    old_difficulty,
                    target,
                    old_timestamp,
                    old_timestamp + Timestamp::millis(delta),
                    height,
                );
            }
        }
    }

    #[proptest(cases = 100)]
    fn agrees_with_host_on_arbitrary_inputs_small_heights(
        old_difficulty_limbs: [u32; 5],
        #[strategy(1u64..=1 << 33)] target: u64,
        #[strategy(0u64..1 << 62)] old_timestamp: u64,
        #[strategy(0u64..1 << 41)] delta: u64,
        #[strategy(1u64..400_000)] height: u64,
    ) {
        assert_agrees_with_host(
            Difficulty::new(old_difficulty_limbs),
            Timestamp::millis(target),
            Timestamp::millis(old_timestamp),
            Timestamp::millis(old_timestamp + delta),
            BlockHeight::from(height),
        );
    }

    #[proptest(cases = 100)]
    fn agrees_with_host_on_arbitrary_inputs_big_heights(
        old_difficulty_limbs: [u32; 5],
        #[strategy(1u64..=1 << 33)] target: u64,
        #[strategy(0u64..1 << 62)] old_timestamp: u64,
        #[strategy(0u64..1 << 41)] delta: u64,
        #[strategy(1u64..4 * u64::from(u32::MAX))] height: u64,
    ) {
        assert_agrees_with_host(
            Difficulty::new(old_difficulty_limbs),
            Timestamp::millis(target),
            Timestamp::millis(old_timestamp),
            Timestamp::millis(old_timestamp + delta),
            BlockHeight::from(height),
        );
    }

    #[test]
    fn forged_quotient_or_remainder_is_rejected() {
        use tasm_lib::triton_vm::error::InstructionError;
        use tasm_lib::triton_vm::isa::instruction::AssertionError;

        let target = 588_000u64;
        let interval = Timestamp::millis(target);
        let height = BlockHeight::from(100u64);
        let [scale_hi, scale_lo, remainder_hi, remainder_lo]: [BFieldElement; 4] =
            DifficultyControl::divined_tokens(interval, height)
                .try_into()
                .unwrap();
        let remainder_not_below = DifficultyControl::REMAINDER_NOT_BELOW_DIVISOR_ERROR;
        let does_not_divide = DifficultyControl::QUOTIENT_DOES_NOT_DIVIDE_ERROR;

        for (tokens, error_id) in [
            (
                vec![scale_hi, scale_lo, remainder_hi, remainder_lo + bfe!(1)],
                does_not_divide,
            ),
            (
                vec![scale_hi, scale_lo + bfe!(1), remainder_hi, remainder_lo],
                does_not_divide,
            ),
            (
                vec![scale_hi, scale_lo, remainder_hi, bfe!(target)],
                remainder_not_below,
            ),
            (
                vec![
                    scale_hi,
                    scale_lo - bfe!(1),
                    remainder_hi,
                    remainder_lo + bfe!(target),
                ],
                remainder_not_below,
            ),
        ] {
            let error = run_in_vm(
                Difficulty::new([100_000_000, 0, 0, 0, 0]),
                interval,
                Timestamp::millis(1_000_000),
                Timestamp::millis(1_000_000 + target + 1),
                height,
                NonDeterminism::new(tokens.clone()),
            )
            .unwrap_err();
            assert!(
                matches!(
                    error.source,
                    InstructionError::AssertionFailed(AssertionError { id, .. })
                        if id == Some(error_id)
                ),
                "{tokens:?}: {}",
                error.source
            );
        }
    }

    #[test]
    fn invalid_encodings_are_rejected() {
        use tasm_lib::triton_vm::error::InstructionError;
        use tasm_lib::triton_vm::error::OpStackError;

        let target = 588_000u64;
        for remainder in [0u64, 1, 4_000, target - 1] {
            // target * quotient + remainder == 2^32 in the field, with the
            // quotient's low word far outside u32.
            let quotient_lo =
                (bfe!(DifficultyControl::ONE) - bfe!(remainder)) * bfe!(target).inverse();
            assert!(quotient_lo.value() > u64::from(u32::MAX));
            let forged = vec![bfe!(0), quotient_lo, bfe!(0), bfe!(remainder)];

            let error = run_in_vm(
                Difficulty::new([100_000_000, 0, 0, 0, 0]),
                Timestamp::millis(target),
                Timestamp::millis(1_000_000),
                Timestamp::millis(1_000_000 + target + 1),
                BlockHeight::from(100u64),
                NonDeterminism::new(forged),
            )
            .unwrap_err();
            assert!(
                matches!(
                    error.source,
                    InstructionError::OpStackError(OpStackError::FailedU32Conversion(word))
                        if word == quotient_lo
                ),
                "remainder {remainder}: {}",
                error.source
            );
        }
    }

    #[test]
    fn genesis_predecessor_keeps_the_difficulty() {
        let old_difficulty = Difficulty::new([1, 2, 3, 4, 5]);
        assert_agrees_with_host(
            old_difficulty,
            Timestamp::millis(588_000),
            Timestamp::millis(0),
            Timestamp::millis(1),
            BlockHeight::genesis(),
        );
    }
}
