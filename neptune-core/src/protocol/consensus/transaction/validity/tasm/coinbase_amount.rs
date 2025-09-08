use tasm_lib::data_type::DataType;
use tasm_lib::library::Library;
use tasm_lib::traits::basic_snippet::BasicSnippet;
use tasm_lib::triton_vm::prelude::*;

use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

pub(crate) struct CoinbaseAmount;

impl CoinbaseAmount {
    pub(crate) const ILLEGAL_COINBASE_AMOUNT_ERROR: i128 = 1_000_200;
}

/// Map a pointer to a coinbase object to its amount (if some) or (if none)
/// zero.
///
/// Panics if coinbase amount is negative.
impl BasicSnippet for CoinbaseAmount {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "*coinbase".to_owned())]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![(DataType::U128, "coinbase_amount".to_owned())]
    }

    fn entrypoint(&self) -> String {
        "tasm_neptune_coinbase_amount".to_owned()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let entrypoint = self.entrypoint();

        // `Coinbase` has type `Option<NativeCurrencyAmount>` where the
        // discriminant from `Option` is one word, and `NativeCurrencyAmount` is
        // four words, as it is represented by a u128.
        let size_minus_one = NativeCurrencyAmount::static_length().unwrap();

        let push_max_amount = NativeCurrencyAmount::max().push_to_stack();
        let u128_lt = library.import(Box::new(tasm_lib::arithmetic::u128::lt::Lt));

        let has_coinbase_label = format!("{entrypoint}_has_coinbase");
        let has_coinbase = triton_asm!(
            {has_coinbase_label}:
                // _ *coinbase 1

                pop 1
                push {size_minus_one}
                add
                // _ *coinbase_lw

                read_mem {size_minus_one}
                pop 1
                // _ [coinbase_amount]

                /* assert 0 <= coinbase < max_amount */
                dup 3
                dup 3
                dup 3
                dup 3
                {&push_max_amount}
                call {u128_lt}
                push 0 eq
                // _ [coinbase_amount] (coinbase_amount <= max)

                assert error_id {Self::ILLEGAL_COINBASE_AMOUNT_ERROR}
                // _ [coinbase_amount]

                push 0
                // _ [coinbase_amount] 0

                return
        );

        let no_coinbase_label = format!("{entrypoint}_no_coinbase");
        let no_coinbase = triton_asm!(
            {no_coinbase_label}:
                // _ *coinbase

                pop 1
                // _

                push 0
                push 0
                push 0
                push 0
                // _ [0]

                return
        );

        let assert_discriminant = triton_asm!(
            // _ coinbase_discriminant

            dup 0
            push 0
            eq
            // _ coinbase_discriminant (coinbase_discriminant == 0)

            swap 1
            push 1
            eq
            // _ (coinbase_discriminant == 0) (coinbase_discriminant == 1)

            add
            // _ (coinbase_discriminant == 0 || coinbase_discriminant == 1)

            assert
            // _
        );

        triton_asm!(
            {entrypoint}:
                // _ *coinbase

                dup 0
                read_mem 1
                pop 1
                // _ *coinbase coinbase_discriminant

                dup 0
                {&assert_discriminant}
                // _ *coinbase coinbase_discriminant

                push 1
                swap 1
                // _ *coinbase 1 coinbase_discriminant

                skiz call {has_coinbase_label}
                skiz call {no_coinbase_label}
                // _ [coinbase_amount]

                return

                {&has_coinbase}
                {&no_coinbase}
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;

    use arbitrary::Unstructured;
    use num_traits::Zero;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::push_encodable;
    use tasm_lib::test_helpers::test_assertion_failure;
    use tasm_lib::traits::function::Function;
    use tasm_lib::traits::function::FunctionInitialState;
    use tasm_lib::traits::function::ShadowedFunction;
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tasm_lib::InitVmState;

    use super::*;

    #[test]
    fn coinbase_amount_pbt() {
        let shadowed_function = ShadowedFunction::new(CoinbaseAmount);
        shadowed_function.test();
    }

    #[test]
    fn panic_on_negative_amount() {
        fn set_up_test_stack(coinbase_ptr: BFieldElement) -> Vec<BFieldElement> {
            let mut stack = CoinbaseAmount.init_stack_for_isolated_run();
            push_encodable(&mut stack, &coinbase_ptr);
            stack
        }

        let coinbase = Some(-NativeCurrencyAmount::coins(2));
        let coinbase_ptr: BFieldElement = bfe!(14);
        let mut memory = HashMap::default();
        encode_to_memory(&mut memory, coinbase_ptr, &coinbase);
        let stack = set_up_test_stack(coinbase_ptr);

        test_assertion_failure(
            &ShadowedFunction::new(CoinbaseAmount),
            InitVmState::with_stack_and_memory(stack, memory),
            &[CoinbaseAmount::ILLEGAL_COINBASE_AMOUNT_ERROR],
        );
    }

    impl Function for CoinbaseAmount {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut std::collections::HashMap<BFieldElement, BFieldElement>,
        ) {
            type CoinbaseAmount = Option<NativeCurrencyAmount>;

            let coinbase_ptr = stack.pop().unwrap();

            let size = match memory[&coinbase_ptr].value() {
                0 => 1,
                1 => 5,
                _ => panic!("Option<T> discriminant must be either 0 or 1"),
            };
            let mut coinbase_encoded = vec![];
            for i in 0..size {
                coinbase_encoded.push(
                    memory
                        .get(&(coinbase_ptr + BFieldElement::new(i as u64)))
                        .unwrap()
                        .to_owned(),
                );
            }

            let coinbase = *CoinbaseAmount::decode(&coinbase_encoded).unwrap();

            let coinbase_amount = coinbase.unwrap_or_else(NativeCurrencyAmount::zero);

            assert!(!coinbase_amount.is_negative());

            for word in coinbase_amount.encode().into_iter().rev() {
                stack.push(word)
            }
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            _bench_case: Option<tasm_lib::snippet_bencher::BenchmarkCase>,
        ) -> FunctionInitialState {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let new_seed: [u8; 32] = rng.random();

            let mut u = Unstructured::new(&new_seed);
            let coinbase: Option<NativeCurrencyAmount> = u
                .arbitrary::<Option<NativeCurrencyAmount>>()
                .unwrap()
                .map(|c| c.abs());
            let coinbase_ptr: BFieldElement = rng.random();

            let mut memory = HashMap::default();
            encode_to_memory(&mut memory, coinbase_ptr, &coinbase);

            FunctionInitialState {
                stack: [self.init_stack_for_isolated_run(), vec![coinbase_ptr]].concat(),
                memory,
            }
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod benches {
    use tasm_lib::traits::function::ShadowedFunction;
    use tasm_lib::traits::rust_shadow::RustShadow;

    use super::*;

    #[test]
    fn coinbase_amount_benchmark() {
        let shadowed_function = ShadowedFunction::new(CoinbaseAmount);
        shadowed_function.bench();
    }
}
