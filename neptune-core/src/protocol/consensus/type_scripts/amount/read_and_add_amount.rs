use tasm_lib::field;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::isa::triton_asm;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::prelude::LabelledInstruction;

use crate::api::export::NativeCurrencyAmount;
use crate::protocol::consensus::transaction::utxo::Coin;
use crate::protocol::consensus::type_scripts::amount::BAD_STATE_SIZE_ERROR;
use crate::protocol::consensus::type_scripts::native_currency::NativeCurrency;

/// Add the amount of a native currency coin to a running sum.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReadAndAddAmount;

impl BasicSnippet for ReadAndAddAmount {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*coin_si".to_string()),
            (DataType::U128, "amount".to_string()),
            (DataType::U128, "timelocked_amount".to_string()),
            (DataType::U128, "utxo_amount".to_string()),
            (DataType::Bool, "utxo_is_timelocked".to_string()),
        ]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*coin_si".to_string()),
            (DataType::U128, "amount".to_string()),
            (DataType::U128, "timelocked_amount".to_string()),
            (DataType::U128, "utxo_amount'".to_string()),
            (DataType::Bool, "utxo_is_timelocked".to_string()),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_type_script_amount_read_and_add_amount".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let field_state = field!(Coin::state);

        let u128_safe_add = library.import(Box::new(tasm_lib::arithmetic::u128::safe_add::SafeAdd));
        let u128_lt = library.import(Box::new(tasm_lib::arithmetic::u128::lt::Lt));

        let coin_size = NativeCurrencyAmount::static_length().unwrap();
        let push_max_amount = NativeCurrencyAmount::max().push_to_stack();

        triton_asm! {
                // BEFORE: _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked
                // AFTER:  _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked
                {self.entrypoint()}:
                    hint utxo_is_timelocked = stack[0]
                    hint utxo_amount = stack[1..5]
                    hint timelocked_amount = stack[5..9]

                    dup 13 addi 1
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked *coins[j]

                    {&field_state}
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked *state
                    hint state_ptr = stack[0]

                    read_mem 1
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked state_size (*state-1)

                    addi {coin_size+1}
                    hint state_last_ptr = stack[0]
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked state_size *state[last]

                    swap 1 push {coin_size} eq
                    assert error_id {BAD_STATE_SIZE_ERROR}
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked *state[last]

                    read_mem {coin_size} pop 1
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked [coin_amount]

                    /* assert 0 <= coin_amount <= max */
                    dup 3
                    dup 3
                    dup 3
                    dup 3
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked [coin_amount] [coin_amount]

                    {&push_max_amount}
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked [coin_amount] [coin_amount] [max_amount]

                    call {u128_lt}
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked [coin_amount] (max_amount < coin_amount)

                    push 0 eq
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked [coin_amount] (max_amount >= coin_amount)

                    assert error_id {NativeCurrency::INVALID_COIN_AMOUNT}
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked [coin_amount]

                    pick 8 pick 8 pick 8 pick 8
                    // _ *coins[j]_si [amount] [timelocked_amount] utxo_is_timelocked [coin_amount] [utxo_amount]

                    call {u128_safe_add}
                    // _ *coins[j]_si [amount] [timelocked_amount] utxo_is_timelocked [utxo_amount']

                    pick 4
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked

                    return
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::prelude::TasmObject;
    use tasm_lib::push_encodable;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::test_helpers::test_assertion_failure;
    use tasm_lib::traits::accessor::Accessor;
    use tasm_lib::traits::accessor::AccessorInitialState;
    use tasm_lib::traits::accessor::ShadowedAccessor;
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tasm_lib::triton_vm::prelude::BFieldElement;
    use tasm_lib::twenty_first::bfe;

    use super::*;
    use crate::tests::shared::pop_encodable;

    #[test]
    fn snippet_agrees_with_rust_shadowing() {
        for _ in 0..4 {
            ShadowedAccessor::new(ReadAndAddAmount).test();
        }
    }

    mod negative_tests {
        use super::*;

        #[test]
        fn overflow_crashes_vm() {
            // Verify that a negative amount can never become positive through
            // overflow. Only u128 overflow is checked, meaning that a negative
            // number cannot become positive through the addition of another
            // term, but the running sum is allowed to become negative, as that
            // is caught further out in the call graph.
            const ADD_OVERFLOW_ERROR_CODE: i128 = 170;

            let utxo_amount = (NativeCurrencyAmount::max().to_nau() as u128 * 2) as i128;
            let coin_amount = NativeCurrencyAmount::max().to_nau();
            let overflow_in_add = ReadAndAddAmount.init_state(
                bfe!(4),
                Default::default(),
                Default::default(),
                utxo_amount,
                false,
                coin_amount,
            );
            test_assertion_failure(
                &ShadowedAccessor::new(ReadAndAddAmount),
                overflow_in_add.into(),
                &[ADD_OVERFLOW_ERROR_CODE],
            );
        }

        #[test]
        fn negative_coin_amounts_crashes_vm() {
            let negative_coin_amount = ReadAndAddAmount.init_state(
                bfe!(4),
                Default::default(),
                Default::default(),
                NativeCurrencyAmount::coins(2).to_nau(),
                false,
                -NativeCurrencyAmount::coins(2).to_nau(),
            );
            test_assertion_failure(
                &ShadowedAccessor::new(ReadAndAddAmount),
                negative_coin_amount.into(),
                &[NativeCurrency::INVALID_COIN_AMOUNT],
            );
        }
    }

    impl ReadAndAddAmount {
        fn init_state(
            &self,
            coin_si_ptr: BFieldElement,
            amount: i128,
            timelocked_amount: i128,
            utxo_amount: i128,
            utxo_is_timelocked: bool,
            coin_amount: i128,
        ) -> AccessorInitialState {
            let mut stack = self.init_stack_for_isolated_run();
            let mut memory = HashMap::default();

            let state_size_ptr = coin_si_ptr + bfe!(2);
            memory.insert(state_size_ptr, bfe!(4));
            encode_to_memory(&mut memory, state_size_ptr + bfe!(1), &coin_amount);

            push_encodable(&mut stack, &coin_si_ptr);
            push_encodable(&mut stack, &amount);
            push_encodable(&mut stack, &timelocked_amount);
            push_encodable(&mut stack, &utxo_amount);
            push_encodable(&mut stack, &utxo_is_timelocked);

            AccessorInitialState { stack, memory }
        }
    }

    impl Accessor for ReadAndAddAmount {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &HashMap<BFieldElement, BFieldElement>,
        ) {
            let utxo_is_timelocked: bool = pop_encodable(stack);
            let utxo_amount: u128 = pop_encodable(stack);
            let timelocked_amount: u128 = pop_encodable(stack);
            let amount: u128 = pop_encodable(stack);
            let coin_si_ptr: BFieldElement = pop_encodable(stack);

            let coin_size = NativeCurrencyAmount::static_length().unwrap();
            let state_size = memory
                .get(&(coin_si_ptr + bfe!(2)))
                .copied()
                .unwrap_or_default();
            assert_eq!(coin_size as u64, state_size.value());

            let coin_amount = *u128::decode_from_memory(memory, coin_si_ptr + bfe!(3)).unwrap();

            assert!(coin_amount <= NativeCurrencyAmount::max().to_nau().try_into().unwrap());

            let utxo_amount = utxo_amount.checked_add(coin_amount).unwrap();

            push_encodable(stack, &coin_si_ptr);
            push_encodable(stack, &amount);
            push_encodable(stack, &timelocked_amount);
            push_encodable(stack, &utxo_amount);
            push_encodable(stack, &utxo_is_timelocked);
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            _bench_case: Option<BenchmarkCase>,
        ) -> AccessorInitialState {
            let mut rng = StdRng::from_seed(seed);

            let coin_si_ptr: BFieldElement = bfe!(rng.random_range(0..u32::MAX / 2));
            let coin_amount =
                rng.random_range(0..((NativeCurrencyAmount::max().to_nau() / 2) as u128));
            let amount = rng.random_range(0..((NativeCurrencyAmount::max().to_nau() / 2) as u128));
            let utxo_amount: u128 =
                rng.random_range(0..((NativeCurrencyAmount::max().to_nau() / 2) as u128));
            let timelocked_amount = rng.random_range(0..utxo_amount);

            let utxo_is_timelocked: bool = rng.random();

            self.init_state(
                coin_si_ptr,
                amount as i128,
                timelocked_amount as i128,
                utxo_amount as i128,
                utxo_is_timelocked,
                coin_amount as i128,
            )
        }
    }
}
