use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::isa::triton_asm;
use tasm_lib::triton_vm::prelude::LabelledInstruction;

use crate::api::export::Timestamp;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;

/// Crash execution if the difference in timestamp in the two transactions
/// exceeds 12 hours
#[derive(Clone, Debug)]
pub(crate) struct BoundTimeDiff;

impl BoundTimeDiff {
    pub(crate) const MAX_TIMESTAMP_DIFF: Timestamp = Timestamp::hours(12);
    pub(super) const TIMESTAMP_DIFF_EXCEEDS_MAX_ALLOWED: i128 = 1_000_072;
}

impl BasicSnippet for BoundTimeDiff {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "left_tx_kernel".to_owned()),
            (DataType::VoidPointer, "right_tx_kernel".to_owned()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "left_tx_kernel".to_owned()),
            (DataType::VoidPointer, "right_tx_kernel".to_owned()),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_transaction_merge_bound_time_diff".to_owned()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let entrypoint = self.entrypoint();

        let timestamp = field!(TransactionKernel::timestamp);

        // Disallow the merge operation from bumping the timestamp of the
        // earliest timestamp by more than 12 hours. Without this constraint,
        // a coinbase transaction can be back-dated such that all mining rewards
        // are released at the time of mining, at the transaction's timestamp
        // set to now through a merge.
        let max_timestamp_diff = Self::MAX_TIMESTAMP_DIFF.to_millis();
        let lt_u64 = library.import(Box::new(tasm_lib::arithmetic::u64::lt::Lt));

        let assert_timestamp_diff_leq_four_hours = triton_asm! {
            // _ left_timestamp right_timestamp (r<l)
            dup 2
            dup 1
            mul
            dup 2
            dup 2
            push 0
            eq
            mul
            // _ left_timestamp right_timestamp (r<l) ((r<l)*left_timestamp) ((r>=l)*right_timestamp)

            add
            // _ left_timestamp right_timestamp (r<l) max_timestamp

            dup 2
            dup 2
            mul
            dup 4
            dup 3
            push 0
            eq
            mul
            // _ left_timestamp right_timestamp (r<l) max_timestamp ((r<l)*right_timestamp) ((r>=l)*left_timestamp)

            add
            // _ left_timestamp right_timestamp (r<l) max_timestamp min_timestamp

            push -1
            mul
            add
            // _ left_timestamp right_timestamp (r<l) (max_timestamp - min_timestamp)
            // _ left_timestamp right_timestamp (r<l) diff

            split
            // _ left_timestamp right_timestamp (r<l) [diff: u64]

            push {max_timestamp_diff}
            split
            call {lt_u64}
            // _ left_timestamp right_timestamp (r<l) (diff > max_diff)

            push 0
            eq
            // _ left_timestamp right_timestamp (r<l) (diff <= max_diff)

            assert error_id {Self::TIMESTAMP_DIFF_EXCEEDS_MAX_ALLOWED}
            // _ left_timestamp right_timestamp (r<l)
        };

        let timestamp_size = 1;
        triton_asm!(
            {entrypoint}:
                // _ *left_tx_kernel *right_tx_kernel

                dup 1
                {&timestamp}
                read_mem {timestamp_size}
                pop 1
                // _ *left_tx_kernel *right_tx_kernel left_ts

                dup 1
                {&timestamp}
                read_mem {timestamp_size}
                pop 1
                // _ *left_tx_kernel *right_tx_kernel left_ts right_ts

                dup 1
                split
                // _ *left_tx_kernel *right_tx_kernel left_ts right_ts [left_ts: u64]

                dup 2
                split
                // _ *left_tx_kernel *right_tx_kernel left_ts right_ts [left_ts: u64] [right_ts: u64]

                call {lt_u64}
                // _ *left_tx_kernel *right_tx_kernel left_ts right_ts (r<l)

                {&assert_timestamp_diff_leq_four_hours}
                // _ *left_tx_kernel *right_tx_kernel left_ts right_ts

                pop 3
                // _ *left_tx_kernel *right_tx_kernel

                return
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::collections::VecDeque;

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
    use crate::api::export::NativeCurrencyAmount;
    use crate::protocol::consensus::transaction::TransactionKernelProxy;
    use crate::protocol::proof_abstractions::timestamp::Timestamp;

    #[test]
    fn small_time_diff_ok() {
        let now = Timestamp::now();
        let early = dummy_tx_kernel(now);
        let snippet = BoundTimeDiff;

        for allowed_time_diff in [
            Timestamp::hours(0),
            Timestamp::hours(1),
            Timestamp::hours(2),
            Timestamp::hours(9),
            Timestamp::hours(12) - Timestamp::millis(1),
            Timestamp::hours(12),
        ] {
            let late = dummy_tx_kernel(now + allowed_time_diff);
            let case_a = snippet.init_state(&early, &late).into();
            let case_b = snippet.init_state(&late, &early).into();
            let snippet = ShadowedReadOnlyAlgorithm::new(snippet.clone());
            test_rust_equivalence_given_execution_state(&snippet, case_a);
            test_rust_equivalence_given_execution_state(&snippet, case_b);
        }
    }

    #[test]
    fn too_big_time_diff() {
        let now = Timestamp::now();
        let early = dummy_tx_kernel(now);
        let snippet = BoundTimeDiff;

        for disallowed_time_diff in [
            Timestamp::hours(12) + Timestamp::millis(1),
            Timestamp::hours(13),
            Timestamp::days(30),
            Timestamp::days(90),
            Timestamp::years(90),
            Timestamp::years(1000),
            Timestamp::millis(1u64 << 31),
            Timestamp::millis(1u64 << 32),
            Timestamp::millis(1u64 << 33),
            Timestamp::millis(1u64 << 60),
        ] {
            let late = dummy_tx_kernel(now + disallowed_time_diff);
            let case_a = snippet.init_state(&early, &late).into();
            let case_b = snippet.init_state(&late, &early).into();
            let snippet = ShadowedReadOnlyAlgorithm::new(snippet.clone());
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
        }
    }

    fn dummy_tx_kernel(timestamp: Timestamp) -> TransactionKernel {
        TransactionKernelProxy {
            inputs: vec![],
            outputs: vec![],
            announcements: vec![],
            fee: NativeCurrencyAmount::zero(),
            coinbase: None,
            timestamp,
            mutator_set_hash: Digest::default(),
            merge_bit: false,
        }
        .into_kernel()
    }

    impl BoundTimeDiff {
        fn init_state(
            &self,
            left_kernel: &TransactionKernel,
            right_kernel: &TransactionKernel,
        ) -> ReadOnlyAlgorithmInitialState {
            let mut memory = HashMap::default();

            let left_ptr = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
            let right_ptr = encode_to_memory(&mut memory, left_ptr, left_kernel);
            let _next_addr = encode_to_memory(&mut memory, right_ptr, right_kernel);

            let stack = [
                self.init_stack_for_isolated_run(),
                vec![left_ptr, right_ptr],
            ]
            .concat();
            let nondeterminism = NonDeterminism::default().with_ram(memory);
            ReadOnlyAlgorithmInitialState {
                stack,
                nondeterminism,
            }
        }
    }

    impl ReadOnlyAlgorithm for BoundTimeDiff {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &HashMap<BFieldElement, BFieldElement>,
            _nd_tokens: VecDeque<BFieldElement>,
            _nd_digests: VecDeque<Digest>,
        ) -> Result<(), RustShadowError> {
            let right_txk_ptr = stack.pop().unwrap();
            let right_txk = *TransactionKernel::decode_from_memory(memory, right_txk_ptr).unwrap();

            let left_txk_ptr = stack.pop().unwrap();
            let left_txk = *TransactionKernel::decode_from_memory(memory, left_txk_ptr).unwrap();

            let left_ts = left_txk.timestamp;
            let right_ts = right_txk.timestamp;
            let min_timestamp = std::cmp::min(left_ts, right_ts);
            let max_timestamp = std::cmp::max(left_ts, right_ts);
            let diff_timestamp = max_timestamp - min_timestamp;
            if diff_timestamp > Self::MAX_TIMESTAMP_DIFF {
                return Err(RustShadowError::AssertionError(
                    Self::TIMESTAMP_DIFF_EXCEEDS_MAX_ALLOWED,
                ));
            }

            stack.push(left_txk_ptr);
            stack.push(right_txk_ptr);

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
