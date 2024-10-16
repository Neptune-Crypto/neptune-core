use tasm_lib::data_type::DataType;
use tasm_lib::field_with_size;
use tasm_lib::library::StaticAllocation;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::isa::triton_asm;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::prelude::Digest;
use tasm_lib::triton_vm::prelude::LabelledInstruction;

use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelField;
use crate::models::blockchain::transaction::validity::tasm::authenticate_txk_field::AuthenticateTxkField;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;

/// Authenticate coinbase fields against TX kernel mast hash check at most one
/// is set.
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
        let entrypoint = self.entrypoint();

        let kernel_field_coinbase_and_size = field_with_size!(TransactionKernel::coinbase);

        let authenticate_txk_coinbase_field = library.import(Box::new(AuthenticateTxkField(
            TransactionKernelField::Coinbase,
        )));

        const DISCRIMINANT_SIZE: usize = 1;
        let some_coinbase_field_size = NeptuneCoins::static_length().unwrap() + DISCRIMINANT_SIZE;
        let compare_coinbases = DataType::compare_elem_of_stack_size(some_coinbase_field_size);

        let assert_coinbase_equality_label = format!("{entrypoint}_assert_eq");
        let assert_coinbase_equality = triton_asm!(
            // BEFORE: _  *coinbase_a *coinbase_b
            // AFTER: _  *coinbase_a *coinbase_b
            {assert_coinbase_equality_label}:
                // _ *coinbase_a *coinbase_b

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
                assert
                // _  *coinbase_a *coinbase_b discriminant

                /* If discriminant == 0, we are done (coinbase == None) */
                push 0
                eq
                skiz
                    return

                /* Coinbase is Some(cb), so we must verify that they contain same value */
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

                {&compare_coinbases}
                // _ *coinbase_a *coinbase_b (coinbase_a == coinbase_b)

                assert
                // _ *coinbase_a *coinbase_b

                return
        );

        triton_asm!(
            {entrypoint}:
                /*
                    1. Get left coinbase field and authenticate
                    2. Get right coinbase field and authenticate
                    3. Assert that not both coinbase fields are set
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


                /* Assert that either left or right coinbase is *not* set */
                dup 1
                read_mem 1
                pop 1
                // _ *new_txk *left_coinbase *right_coinbase left_coinbase_discriminant

                dup 1
                read_mem 1
                pop 1
                // _ *new_txk *left_coinbase *right_coinbase left_coinbase_discriminant right_coinbase_discriminant

                push 1
                eq
                swap 1
                push 1
                eq
                // _ *new_txk *left_coinbase *right_coinbase (right_coinbase_discriminant == 1) (left_coinbase_discriminant == 1)
                // _ *new_txk *left_coinbase *right_coinbase (right_coinbase.is_some()) (left_coinbase.is_some())

                mul
                push 0
                eq
                // _ *new_txk *left_coinbase *right_coinbase !(right_coinbase.is_some() && left_coinbase.is_some())

                assert
                // _ *new_txk *left_coinbase *right_coinbase


                /*  Goal: Put the `maybe` coinbase on top */
                read_mem 1
                addi 1
                swap 1
                // _ *new_txk *left_coinbase *right_coinbase right_coinbase_discriminant

                push 0
                eq
                // _ *new_txk *left_coinbase *right_coinbase (right_coinbase.is_none())

                skiz
                    swap 1
                // _ *new_txk *not_coinbase *maybe_coinbase


                /* maybe_coinbase must match that in `new_txk` */
                place 2
                pop 1
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
mod tests {
    use std::collections::HashMap;
    use std::collections::VecDeque;

    use num_bigint::BigInt;
    use num_traits::FromPrimitive;
    use num_traits::Zero;
    use proptest::prelude::Strategy;
    use proptest::test_runner::TestRunner;
    use rand::random;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use strum::EnumCount;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
    use tasm_lib::prelude::TasmObject;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::test_helpers::negative_test;
    use tasm_lib::test_helpers::test_rust_equivalence_given_execution_state;
    use tasm_lib::traits::read_only_algorithm::ReadOnlyAlgorithm;
    use tasm_lib::traits::read_only_algorithm::ReadOnlyAlgorithmInitialState;
    use tasm_lib::traits::read_only_algorithm::ShadowedReadOnlyAlgorithm;
    use tasm_lib::triton_vm::error::InstructionError;
    use tasm_lib::triton_vm::prelude::BFieldElement;
    use tasm_lib::triton_vm::prelude::Digest;
    use tasm_lib::triton_vm::prelude::Tip5;
    use tasm_lib::triton_vm::vm::NonDeterminism;
    use tasm_lib::twenty_first::bfe;
    use tasm_lib::twenty_first::prelude::AlgebraicHasher;
    use tasm_lib::twenty_first::prelude::MerkleTreeInclusionProof;

    use super::*;
    use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
    use crate::models::proof_abstractions::mast_hash::MastHash;
    use crate::models::proof_abstractions::timestamp::Timestamp;

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

    fn dummy_tx_kernel(cb: Option<NeptuneCoins>) -> TransactionKernel {
        TransactionKernel {
            inputs: vec![],
            outputs: vec![],
            public_announcements: vec![],
            fee: NeptuneCoins::zero(),
            coinbase: cb,
            timestamp: Timestamp::now(),
            mutator_set_hash: Digest::default(),
        }
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
        left_cb: Option<NeptuneCoins>,
        right_cb: Option<NeptuneCoins>,
        new_cb: Option<NeptuneCoins>,
    ) {
        let legal = !(left_cb.is_some() && right_cb.is_some());
        let legal = legal
            && if left_cb.is_some() {
                new_cb == left_cb
            } else {
                new_cb == right_cb
            };

        let snippet = dummy_snippet_for_test();
        let left = dummy_tx_kernel(left_cb);
        let right = dummy_tx_kernel(right_cb);
        let new = dummy_tx_kernel(new_cb);
        let init_state = snippet.init_state(&left, &right, &new);
        if legal {
            test_rust_equivalence_given_execution_state(
                &ShadowedReadOnlyAlgorithm::new(snippet),
                init_state.into(),
            );
        } else {
            negative_test(
                &ShadowedReadOnlyAlgorithm::new(snippet),
                init_state.clone().into(),
                &[InstructionError::AssertionFailed],
            );
        }
    }

    #[test]
    fn cannot_change_cb_amount() {
        prop(Some(NeptuneCoins::new(2)), None, Some(NeptuneCoins::new(3)));
        prop(Some(NeptuneCoins::new(3)), None, Some(NeptuneCoins::new(2)));
        prop(None, Some(NeptuneCoins::new(2)), Some(NeptuneCoins::new(3)));
        prop(None, Some(NeptuneCoins::new(3)), Some(NeptuneCoins::new(2)));
        prop(
            Some(NeptuneCoins::new(3)),
            Some(NeptuneCoins::new(3)),
            Some(NeptuneCoins::new(6)),
        );

        // Verify that the entire u128 is checked, not just a top-limb
        prop(
            Some(NeptuneCoins::from_nau(BigInt::from_u128(3).unwrap()).unwrap()),
            None,
            Some(NeptuneCoins::from_nau(BigInt::from_u128(3 + (1 << 32)).unwrap()).unwrap()),
        );
        prop(
            Some(NeptuneCoins::from_nau(BigInt::from_u128(3).unwrap()).unwrap()),
            None,
            Some(NeptuneCoins::from_nau(BigInt::from_u128(3 + (1 << 64)).unwrap()).unwrap()),
        );
        prop(
            Some(NeptuneCoins::from_nau(BigInt::from_u128(3).unwrap()).unwrap()),
            None,
            Some(NeptuneCoins::from_nau(BigInt::from_u128(3 + (1 << 96)).unwrap()).unwrap()),
        );
    }

    #[test]
    fn test_all_cb_combinations() {
        let options = [None, Some(NeptuneCoins::one())];
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
            negative_test(
                &ShadowedReadOnlyAlgorithm::new(snippet),
                init_state.clone().into(),
                &[InstructionError::VectorAssertionFailed(0)],
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
                let tree_height =
                    TransactionKernelField::COUNT.next_power_of_two().ilog2() as usize;
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

            // Assert that either left or right is not set
            assert!(left_txk.coinbase.is_none() || right_txk.coinbase.is_none());

            let maybe_coinbase = if left_txk.coinbase.is_none() {
                &right_txk.coinbase
            } else {
                &left_txk.coinbase
            };

            assert_eq!(&new_txk.coinbase, maybe_coinbase);
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            _bench_case: Option<BenchmarkCase>,
        ) -> ReadOnlyAlgorithmInitialState {
            let mut test_runner = TestRunner::deterministic();
            let [primitive_witness_left, primitive_witness_right] =
                PrimitiveWitness::arbitrary_tuple_with_matching_mutator_sets([
                    (2, 2, 2),
                    (2, 2, 2),
                ])
                .new_tree(&mut test_runner)
                .unwrap()
                .current();

            let left_kernel = &primitive_witness_left.kernel;
            let right_kernel = &primitive_witness_right.kernel;

            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let new_kernel = if left_kernel.coinbase.is_some() || rng.gen_bool(0.5) {
                left_kernel
            } else {
                right_kernel
            };

            self.init_state(left_kernel, right_kernel, new_kernel)
        }
    }
}
