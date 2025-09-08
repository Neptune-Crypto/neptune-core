use tasm_lib::data_type::DataType;
use tasm_lib::field_with_size;
use tasm_lib::library::StaticAllocation;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::isa::triton_asm;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::prelude::Digest;
use tasm_lib::triton_vm::prelude::LabelledInstruction;

use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelField;
use crate::protocol::consensus::transaction::validity::tasm::authenticate_txk_field::AuthenticateTxkField;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

const UNEQUAL_DISCRIMINANT_ERROR: i128 = 1_000_020;
const UNEQUAL_VALUE_ERROR: i128 = 1_000_021;
const RIGHT_INPUT_COINBASE_ERROR: i128 = 1_000_022;

/// Authenticate coinbase fields of left, right, and new kernels. Verify that
/// at most one from (left, right) is set. Verify that the one that is set (if
/// any) matches new.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AuthenticateCoinbaseFields {
    left_txk_mast_hash_alloc: StaticAllocation,
    right_txk_mast_hash_alloc: StaticAllocation,
    new_txk_mast_hash_alloc: StaticAllocation,
}

impl AuthenticateCoinbaseFields {
    pub(crate) fn new(
        left_txk_mast_hash_alloc: StaticAllocation,
        right_txk_mast_hash_alloc: StaticAllocation,
        new_txk_mast_hash_alloc: StaticAllocation,
    ) -> Self {
        assert_eq!(Digest::LEN as u32, left_txk_mast_hash_alloc.num_words());
        assert_eq!(Digest::LEN as u32, right_txk_mast_hash_alloc.num_words());
        assert_eq!(Digest::LEN as u32, new_txk_mast_hash_alloc.num_words());
        Self {
            left_txk_mast_hash_alloc,
            right_txk_mast_hash_alloc,
            new_txk_mast_hash_alloc,
        }
    }
}

impl BasicSnippet for AuthenticateCoinbaseFields {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "left_tx_kernel".to_owned()),
            (DataType::VoidPointer, "right_tx_kernel".to_owned()),
            (DataType::VoidPointer, "new_tx_kernel".to_owned()),
        ]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![]
    }

    fn entrypoint(&self) -> String {
        "neptune_transaction_merge_authenticate_coinbase_fields".to_owned()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        const DISCRIMINANT_SIZE: usize = 1;

        let entrypoint = self.entrypoint();

        let kernel_field_coinbase_and_size = field_with_size!(TransactionKernel::coinbase);

        let authenticate_txk_coinbase_field = library.import(Box::new(AuthenticateTxkField(
            TransactionKernelField::Coinbase,
        )));

        let some_coinbase_field_size =
            NativeCurrencyAmount::static_length().unwrap() + DISCRIMINANT_SIZE;
        let compare_some_coinbases = DataType::compare_elem_of_stack_size(some_coinbase_field_size);

        let assert_coinbase_equality_label = format!("{entrypoint}_assert_eq");
        let assert_coinbase_equality = triton_asm!(
            // BEFORE: _  *coinbase_a *coinbase_b
            // AFTER:  _  *coinbase_a *coinbase_b
            {assert_coinbase_equality_label}:
                // _ *coinbase_a *coinbase_b

                /* Assert discriminant equality */
                read_mem 1
                addi 1
                // _  *coinbase_a b_discriminant *coinbase_b

                swap 2
                read_mem 1
                addi 1
                // _  *coinbase_b b_discriminant a_discriminant *coinbase_a

                place 3
                // _  *coinbase_a *coinbase_b b_discriminant a_discriminant

                dup 1
                eq
                assert error_id {UNEQUAL_DISCRIMINANT_ERROR}
                // _  *coinbase_a *coinbase_b discriminant

                /* If discriminant == 0, we are done (coinbase == None) */
                push 0
                eq
                skiz
                    return

                /* Coinbase is Some(cb); assert value equality */
                // _  *coinbase_a *coinbase_b

                dup 1
                addi {some_coinbase_field_size - 1}
                read_mem {some_coinbase_field_size}
                pop 1
                // _  *coinbase_a *coinbase_b [coinbase_a; 5]

                dup 5
                addi {some_coinbase_field_size - 1}
                read_mem {some_coinbase_field_size}
                pop 1
                // _  *coinbase_a *coinbase_b [coinbase_a; 5] [coinbase_b; 5]

                {&compare_some_coinbases}
                // _ *coinbase_a *coinbase_b (coinbase_a == coinbase_b)

                assert error_id {UNEQUAL_VALUE_ERROR}
                // _ *coinbase_a *coinbase_b

                return
        );

        let assert_coinbases_right_not_set = triton_asm! {
                // _ *new_txk *left_coinbase *right_coinbase
                dup 0
                read_mem 1
                pop 1
                // _ *new_txk *left_coinbase *right_coinbase right_coinbase_discriminant

                push 0
                eq
                // _ *new_txk *left_coinbase *right_coinbase right_coinbase.is_none()

                assert error_id {RIGHT_INPUT_COINBASE_ERROR}
                // _ *new_txk *left_coinbase *right_coinbase
        };

        triton_asm!(
            {entrypoint}:
                /*
                    1. Get left coinbase field and authenticate
                    2. Get right coinbase field and authenticate
                    3. Assert that not both coinbase fields are set (Genesis)
                    3. Assert that right coinbase is not set (HardFork2)
                    4. Verify that the one set (if set) matches new
                    5. Authenticate calculated new against new_txkmh
                 */

                // _ *left_txk *right_txk *new_txk


                /* 1. */
                push {self.left_txk_mast_hash_alloc.read_address()}
                read_mem {Digest::LEN}
                pop 1
                pick 7
                // _ *right_txk *new_txk [left_txkmh] *left_txk

                {&kernel_field_coinbase_and_size}
                // _ *right_txk *new_txk [left_txkmh] *left_coinbase size

                dup 1
                place 7
                // _ *right_txk *new_txk *left_coinbase [left_txkmh] *left_coinbase size

                call {authenticate_txk_coinbase_field}
                // _ *right_txk *new_txk *left_coinbase


                /* 2. */
                push {self.right_txk_mast_hash_alloc.read_address()}
                read_mem {Digest::LEN}
                pop 1
                // _ *right_txk *new_txk *left_coinbase [right_txkmh]

                pick 7
                // _ *new_txk *left_coinbase [right_txkmh] *right_txk

                {&kernel_field_coinbase_and_size}
                // _ *new_txk *left_coinbase [right_txkmh] *right_coinbase size

                dup 1
                place 7
                // _ *new_txk *left_coinbase *right_coinbase [right_txkmh] *right_coinbase size

                call {authenticate_txk_coinbase_field}
                // _ *new_txk *left_coinbase *right_coinbase


                /* 3. */
                {&assert_coinbases_right_not_set}
                // _ *new_txk *left_coinbase *right_coinbase


                /*  Goal: Put the `maybe` coinbase on top */
                pop 1
                // _ *new_txk *maybe_coinbase

                /* maybe_coinbase must match that in `new_txk` */
                swap 1
                // _ *maybe_coinbase *new_txk

                {&kernel_field_coinbase_and_size}
                // _ *maybe_coinbase *new_coinbase new_cb_size

                place 2
                // _ new_cb_size *maybe_coinbase *new_coinbase

                /* Assert equality */
                call {assert_coinbase_equality_label}
                // _ new_cb_size *new_coinbase *new_coinbase

                pop 1
                // _ new_cb_size *new_coinbase

                /* Authenticate new_coinbase against txkmh */
                push {self.new_txk_mast_hash_alloc.read_address()}
                read_mem {Digest::LEN}
                pop 1
                // _ new_cb_size *new_coinbase [new_txkmh]

                pick 5
                pick 6
                // _ [new_txkmh] *new_coinbase new_cb_size

                call {authenticate_txk_coinbase_field}
                // _

                return

                {&assert_coinbase_equality}
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;
    use std::collections::VecDeque;

    use num_traits::Zero;
    use proptest::prelude::Strategy;
    use proptest::test_runner::TestRunner;
    use rand::random;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use strum::EnumCount;
    use tasm_lib::hashing::merkle_verify::MerkleVerify;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
    use tasm_lib::prelude::TasmObject;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::test_helpers::test_assertion_failure;
    use tasm_lib::test_helpers::test_rust_equivalence_given_execution_state;
    use tasm_lib::traits::read_only_algorithm::ReadOnlyAlgorithm;
    use tasm_lib::traits::read_only_algorithm::ReadOnlyAlgorithmInitialState;
    use tasm_lib::traits::read_only_algorithm::ShadowedReadOnlyAlgorithm;
    use tasm_lib::triton_vm::prelude::BFieldElement;
    use tasm_lib::triton_vm::prelude::Digest;
    use tasm_lib::triton_vm::prelude::Tip5;
    use tasm_lib::triton_vm::vm::NonDeterminism;
    use tasm_lib::twenty_first::bfe;
    use tasm_lib::twenty_first::prelude::MerkleTreeInclusionProof;

    use super::*;
    use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
    use crate::protocol::consensus::transaction::TransactionKernelProxy;
    use crate::protocol::proof_abstractions::mast_hash::MastHash;
    use crate::protocol::proof_abstractions::timestamp::Timestamp;

    fn dummy_snippet_for_test() -> AuthenticateCoinbaseFields {
        let mut mock_library = Library::default();
        let left_txk_mast_hash_alloc = mock_library.kmalloc(Digest::LEN as u32);
        let right_txk_mast_hash_alloc = mock_library.kmalloc(Digest::LEN as u32);
        let new_txk_mast_hash_alloc = mock_library.kmalloc(Digest::LEN as u32);
        AuthenticateCoinbaseFields {
            left_txk_mast_hash_alloc,
            right_txk_mast_hash_alloc,
            new_txk_mast_hash_alloc,
        }
    }

    fn dummy_tx_kernel(cb: Option<NativeCurrencyAmount>) -> TransactionKernel {
        TransactionKernelProxy {
            inputs: vec![],
            outputs: vec![],
            announcements: vec![],
            fee: NativeCurrencyAmount::zero(),
            coinbase: cb,
            timestamp: Timestamp::now(),
            mutator_set_hash: Digest::default(),
            merge_bit: false,
        }
        .into_kernel()
    }

    #[test]
    fn authenticate_coinbase_fields_for_merge_test() {
        let snippet = dummy_snippet_for_test();
        let init_state = snippet.pseudorandom_initial_state(random(), None);
        test_rust_equivalence_given_execution_state(
            &ShadowedReadOnlyAlgorithm::new(snippet),
            init_state.into(),
        );
    }

    fn prop(
        left_cb: Option<NativeCurrencyAmount>,
        right_cb: Option<NativeCurrencyAmount>,
        new_cb: Option<NativeCurrencyAmount>,
    ) {
        let new_cb_is_legal = match (left_cb, right_cb, new_cb) {
            (None, None, None) => Ok(()),
            (Some(o), None, Some(n)) if o == n => Ok(()),
            (_, Some(_), _) => Err(RIGHT_INPUT_COINBASE_ERROR),
            (Some(_), None, Some(_)) => Err(UNEQUAL_VALUE_ERROR),
            (Some(_), None, None) | (None, None, Some(_)) => Err(UNEQUAL_DISCRIMINANT_ERROR),
        };

        let snippet = dummy_snippet_for_test();
        let left = dummy_tx_kernel(left_cb);
        let right = dummy_tx_kernel(right_cb);
        let new = dummy_tx_kernel(new_cb);

        let init_state = snippet.init_state(&left, &right, &new).into();
        let snippet = ShadowedReadOnlyAlgorithm::new(snippet);
        if let Err(error_id) = new_cb_is_legal {
            test_assertion_failure(&snippet, init_state, &[error_id]);
        } else {
            test_rust_equivalence_given_execution_state(&snippet, init_state);
        };
    }

    #[test]
    fn cannot_change_cb_amount() {
        prop(
            Some(NativeCurrencyAmount::coins(2)),
            None,
            Some(NativeCurrencyAmount::coins(3)),
        );
        prop(
            Some(NativeCurrencyAmount::coins(3)),
            None,
            Some(NativeCurrencyAmount::coins(2)),
        );
        prop(
            None,
            Some(NativeCurrencyAmount::coins(2)),
            Some(NativeCurrencyAmount::coins(3)),
        );
        prop(
            None,
            Some(NativeCurrencyAmount::coins(3)),
            Some(NativeCurrencyAmount::coins(2)),
        );
        prop(
            Some(NativeCurrencyAmount::coins(3)),
            Some(NativeCurrencyAmount::coins(3)),
            Some(NativeCurrencyAmount::coins(6)),
        );

        // Verify that the entire u128 is checked, not just a top-limb
        prop(
            Some(NativeCurrencyAmount::from_nau(3.into())),
            None,
            Some(NativeCurrencyAmount::from_nau(3 + (1_i128 << 32))),
        );
        prop(
            Some(NativeCurrencyAmount::from_nau((3).into())),
            None,
            Some(NativeCurrencyAmount::from_nau(3 + (1_i128 << 64))),
        );
        prop(
            Some(NativeCurrencyAmount::from_nau((3).into())),
            None,
            Some(NativeCurrencyAmount::from_nau(3 + (1_i128 << 96))),
        );
    }

    #[test]
    fn test_all_cb_combinations() {
        let options = [None, Some(NativeCurrencyAmount::coins(1))];
        for left_cb in options {
            for right_cb in options {
                for new_cb in options {
                    prop(left_cb, right_cb, new_cb);
                }
            }
        }
    }

    #[test]
    fn negative_test_bad_ap() {
        let left = dummy_tx_kernel(None);
        let right = dummy_tx_kernel(None);
        let new = dummy_tx_kernel(None);

        let snippet = dummy_snippet_for_test();
        let mut init_state = snippet.init_state(&left, &right, &new);
        let nd_digests_len = init_state.nondeterminism.digests.len();

        for mutated_index in 0..nd_digests_len {
            init_state.nondeterminism.digests[mutated_index] = random();
            test_assertion_failure(
                &ShadowedReadOnlyAlgorithm::new(snippet),
                init_state.clone().into(),
                &[MerkleVerify::ROOT_MISMATCH_ERROR_ID],
            );
        }
    }

    impl AuthenticateCoinbaseFields {
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

            // insert TXK mast hashes into static memory
            encode_to_memory(
                &mut memory,
                self.left_txk_mast_hash_alloc.write_address(),
                &left_kernel.mast_hash(),
            );
            encode_to_memory(
                &mut memory,
                self.right_txk_mast_hash_alloc.write_address(),
                &right_kernel.mast_hash(),
            );
            encode_to_memory(
                &mut memory,
                self.new_txk_mast_hash_alloc.write_address(),
                &new_kernel.mast_hash(),
            );

            let digests = [
                left_kernel.mast_path(TransactionKernelField::Coinbase),
                right_kernel.mast_path(TransactionKernelField::Coinbase),
                new_kernel.mast_path(TransactionKernelField::Coinbase),
            ]
            .concat();

            let nondeterminism = NonDeterminism::default()
                .with_digests(digests)
                .with_ram(memory);

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

    impl ReadOnlyAlgorithm for AuthenticateCoinbaseFields {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &HashMap<BFieldElement, BFieldElement>,
            _nd_tokens: VecDeque<BFieldElement>,
            mut nd_digests: VecDeque<Digest>,
        ) {
            let read_digest_from_memory = |alloc: StaticAllocation| {
                let read_address = alloc.read_address();
                Digest::new([
                    memory[&(read_address - bfe!(4))],
                    memory[&(read_address - bfe!(3))],
                    memory[&(read_address - bfe!(2))],
                    memory[&(read_address - bfe!(1))],
                    memory[&read_address],
                ])
            };

            let new_txk_ptr = stack.pop().unwrap();
            let new_txk = *TransactionKernel::decode_from_memory(memory, new_txk_ptr).unwrap();
            let new_txk_mast_hash = read_digest_from_memory(self.new_txk_mast_hash_alloc);

            let right_txk_ptr = stack.pop().unwrap();
            let right_txk = *TransactionKernel::decode_from_memory(memory, right_txk_ptr).unwrap();
            let right_txk_mast_hash = read_digest_from_memory(self.right_txk_mast_hash_alloc);

            let left_txk_ptr = stack.pop().unwrap();
            let left_txk = *TransactionKernel::decode_from_memory(memory, left_txk_ptr).unwrap();
            let left_txk_mast_hash = read_digest_from_memory(self.left_txk_mast_hash_alloc);

            let mut assert_coinbase_integrity = move |merkle_root, coinbase| {
                let leaf_index = TransactionKernelField::Coinbase as u32;
                let tree_height = TransactionKernelField::COUNT.next_power_of_two().ilog2();
                let mut authentication_structure = vec![];
                for _ in 0..tree_height {
                    authentication_structure.push(nd_digests.pop_front().unwrap());
                }
                let leaf = Tip5::hash(coinbase);
                let merkle_auth_proof = MerkleTreeInclusionProof {
                    tree_height,
                    indexed_leafs: vec![(leaf_index as usize, leaf)],
                    authentication_structure,
                };
                assert!(merkle_auth_proof.verify(merkle_root));
            };

            assert_coinbase_integrity(left_txk_mast_hash, &left_txk.coinbase);
            assert_coinbase_integrity(right_txk_mast_hash, &right_txk.coinbase);
            assert_coinbase_integrity(new_txk_mast_hash, &new_txk.coinbase);

            // Assert that right is not set
            assert!(right_txk.coinbase.is_none());

            let maybe_coinbase = &left_txk.coinbase;

            assert_eq!(&new_txk.coinbase, maybe_coinbase);
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            _bench_case: Option<BenchmarkCase>,
        ) -> ReadOnlyAlgorithmInitialState {
            let mut rng = StdRng::from_seed(seed);
            let [primitive_witness_left, primitive_witness_right] =
                PrimitiveWitness::arbitrary_tuple_with_matching_mutator_sets([
                    (2, 2, 2),
                    (2, 2, 2),
                ])
                .new_tree(&mut TestRunner::deterministic())
                .unwrap()
                .current();

            let left_kernel = &primitive_witness_left.kernel;
            let right_kernel = &primitive_witness_right.kernel;

            let new_kernel = if left_kernel.coinbase.is_some() || rng.random() {
                left_kernel
            } else {
                right_kernel
            };

            self.init_state(left_kernel, right_kernel, new_kernel)
        }
    }
}
