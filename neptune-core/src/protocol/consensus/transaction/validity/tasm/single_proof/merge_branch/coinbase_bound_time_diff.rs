use tasm_lib::data_type::DataType;
use tasm_lib::field_with_size;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::isa::triton_asm;
use tasm_lib::triton_vm::prelude::LabelledInstruction;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::validity::tasm::single_proof::merge_branch::bound_time_diff::BoundTimeDiff;

/// If `new_tx` is coinbase and timestamp difference between the two merged
/// transactions is too big, then crash execution.
#[derive(Clone, Debug)]
pub(crate) struct CoinbaseTimestampDiffBounded;

impl BasicSnippet for CoinbaseTimestampDiffBounded {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "left_tx_kernel".to_owned()),
            (DataType::VoidPointer, "right_tx_kernel".to_owned()),
            (DataType::VoidPointer, "new_tx_kernel".to_owned()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "left_tx_kernel".to_owned()),
            (DataType::VoidPointer, "right_tx_kernel".to_owned()),
            (DataType::VoidPointer, "new_tx_kernel".to_owned()),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_transaction_merge_coinbase_bound_time_diff".to_owned()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        const DISCRIMINANT_SIZE: usize = 1;

        let entrypoint = self.entrypoint();

        let kernel_field_coinbase_and_size = field_with_size!(TransactionKernel::coinbase);
        let some_coinbase_field_size =
            NativeCurrencyAmount::static_length().unwrap() + DISCRIMINANT_SIZE;

        let bound_time_diff = library.import(Box::new(BoundTimeDiff));
        triton_asm! {
            {entrypoint}:
                // *l_txk *r_txk *n_txk

                dup 0
                {&kernel_field_coinbase_and_size}
                // *l_txk *r_txk *n_txk *new_coinbase new_cb_size

                swap 1
                pop 1
                // *l_txk *r_txk *n_txk new_cb_size

                push {some_coinbase_field_size}
                eq
                // *l_txk *r_txk *n_txk (new_coinbase.is_some())

                dup 3
                dup 3
                pick 2
                // *l_txk *r_txk *n_txk *l_txk *r_txk (new_coinbase.is_some())

                skiz
                    call {bound_time_diff}
                // *l_txk *r_txk *n_txk *l_txk *r_txk

                pop 2

                // *l_txk *r_txk *n_txk
                return
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::collections::VecDeque;

    use neptune_primitives::timestamp::Timestamp;
    use num_traits::Zero;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
    use tasm_lib::prelude::TasmObject;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::test_helpers::test_assertion_failure;
    use tasm_lib::test_helpers::test_rust_equivalence_given_execution_state;
    use tasm_lib::traits::read_only_algorithm::ReadOnlyAlgorithm;
    use tasm_lib::traits::read_only_algorithm::ReadOnlyAlgorithmInitialState;
    use tasm_lib::traits::read_only_algorithm::ShadowedReadOnlyAlgorithm;
    use tasm_lib::traits::rust_shadow::RustShadowError;
    use tasm_lib::triton_vm::prelude::BFieldElement;
    use tasm_lib::triton_vm::prelude::Digest;
    use tasm_lib::triton_vm::vm::NonDeterminism;

    use super::*;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelProxy;
    use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

    #[test]
    fn small_time_diff_ok() {
        let now = Timestamp::now();
        for cb_value in [None, Some(NativeCurrencyAmount::coins(2))] {
            let early = dummy_tx_kernel(now, cb_value);
            let snippet = CoinbaseTimestampDiffBounded;

            for allowed_time_diff in [
                Timestamp::hours(0),
                Timestamp::hours(1),
                Timestamp::hours(2),
                Timestamp::hours(3),
                Timestamp::hours(11),
                Timestamp::hours(12) - Timestamp::millis(1),
                Timestamp::hours(12),
            ] {
                let late = dummy_tx_kernel(now + allowed_time_diff, cb_value);
                let new = late.clone();
                let case_a = snippet.init_state(&early, &late, &new).into();
                let case_b = snippet.init_state(&late, &early, &new).into();
                let snippet = ShadowedReadOnlyAlgorithm::new(snippet.clone());
                test_rust_equivalence_given_execution_state(&snippet, case_a);
                test_rust_equivalence_given_execution_state(&snippet, case_b);
            }
        }
    }

    #[test]
    fn too_big_time_diff() {
        let now = Timestamp::now();
        for cb_value in [None, Some(NativeCurrencyAmount::coins(2))] {
            let early = dummy_tx_kernel(now, cb_value);
            let snippet = CoinbaseTimestampDiffBounded;

            for disallowed_time_diff in [
                Timestamp::hours(13),
                Timestamp::days(30),
                Timestamp::days(90),
                Timestamp::days(1001),
                Timestamp::years(90),
                Timestamp::years(1000),
                Timestamp::millis(1u64 << 31),
                Timestamp::millis(1u64 << 32),
                Timestamp::millis(1u64 << 33),
                Timestamp::millis(1u64 << 60),
            ] {
                let late = dummy_tx_kernel(now + disallowed_time_diff, cb_value);
                let new = late.clone();
                let case_a = snippet.init_state(&early, &late, &new).into();
                let case_b = snippet.init_state(&late, &early, &new).into();
                let snippet = ShadowedReadOnlyAlgorithm::new(snippet.clone());
                if cb_value.is_some() {
                    test_assertion_failure(
                        &snippet,
                        case_a,
                        &[BoundTimeDiff::TIMESTAMP_DIFF_EXCEEDS_MAX_ALLOWED],
                    );
                    test_assertion_failure(
                        &snippet,
                        case_b,
                        &[BoundTimeDiff::TIMESTAMP_DIFF_EXCEEDS_MAX_ALLOWED],
                    );
                } else {
                    test_rust_equivalence_given_execution_state(&snippet, case_a);
                    test_rust_equivalence_given_execution_state(&snippet, case_b);
                }
            }
        }
    }

    fn dummy_tx_kernel(
        timestamp: Timestamp,
        coinbase: Option<NativeCurrencyAmount>,
    ) -> TransactionKernel {
        TransactionKernelProxy {
            inputs: vec![],
            outputs: vec![],
            announcements: vec![],
            fee: NativeCurrencyAmount::zero(),
            coinbase,
            timestamp,
            mutator_set_hash: Digest::default(),
            merge_bit: false,
        }
        .into_kernel()
    }

    impl CoinbaseTimestampDiffBounded {
        fn init_state(
            &self,
            left_kernel: &TransactionKernel,
            right_kernel: &TransactionKernel,
            new_kernel: &TransactionKernel,
        ) -> ReadOnlyAlgorithmInitialState {
            let mut memory = HashMap::default();

            let left_ptr = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
            let right_ptr = encode_to_memory(&mut memory, left_ptr, left_kernel);
            let new_ptr = encode_to_memory(&mut memory, right_ptr, right_kernel);

            let _ = encode_to_memory(&mut memory, new_ptr, new_kernel);

            let nondeterminism = NonDeterminism::default().with_ram(memory);
            let stack = [
                self.init_stack_for_isolated_run(),
                vec![left_ptr, right_ptr, new_ptr],
            ]
            .concat();
            ReadOnlyAlgorithmInitialState {
                stack,
                nondeterminism,
            }
        }
    }

    impl ReadOnlyAlgorithm for CoinbaseTimestampDiffBounded {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &HashMap<BFieldElement, BFieldElement>,
            _nd_tokens: VecDeque<BFieldElement>,
            _nd_digests: VecDeque<Digest>,
        ) -> Result<(), RustShadowError> {
            let new_ptr = stack.pop().unwrap();
            let new = *TransactionKernel::decode_from_memory(memory, new_ptr).unwrap();

            let right_ptr = stack.pop().unwrap();
            let right = *TransactionKernel::decode_from_memory(memory, right_ptr).unwrap();

            let left_ptr = stack.pop().unwrap();
            let left = *TransactionKernel::decode_from_memory(memory, left_ptr).unwrap();

            let left_ts = left.timestamp;
            let right_ts = right.timestamp;
            let min_timestamp = std::cmp::min(left_ts, right_ts);
            let max_timestamp = std::cmp::max(left_ts, right_ts);
            let diff_timestamp = max_timestamp - min_timestamp;
            if diff_timestamp > BoundTimeDiff::MAX_TIMESTAMP_DIFF && new.coinbase.is_some() {
                return Err(RustShadowError::AssertionError(
                    BoundTimeDiff::TIMESTAMP_DIFF_EXCEEDS_MAX_ALLOWED,
                ));
            }

            stack.push(left_ptr);
            stack.push(right_ptr);
            stack.push(new_ptr);

            Ok(())
        }

        fn pseudorandom_initial_state(
            &self,
            _seed: [u8; 32],
            _bench_case: Option<BenchmarkCase>,
        ) -> ReadOnlyAlgorithmInitialState {
            unimplemented!()
        }
    }
}
