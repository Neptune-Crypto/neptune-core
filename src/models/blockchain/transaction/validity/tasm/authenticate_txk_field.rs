use tasm_lib::data_type::DataType;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelField;
use crate::models::proof_abstractions::mast_hash::MastHash;

#[derive(Debug, Clone, Copy)]
pub(crate) struct AuthenticateTxkField(pub(crate) TransactionKernelField);

impl BasicSnippet for AuthenticateTxkField {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "transaction_kernel_mast_hash".to_owned()),
            (DataType::VoidPointer, "field".to_owned()),
            (DataType::U32, "field_size".to_owned()),
        ]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![]
    }

    fn entrypoint(&self) -> String {
        format!(
            "neptune_transaction_authenticate_field_{}_against_txk_mast_hash",
            self.0
        )
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let entrypoint = self.entrypoint();

        let hash_varlen = library.import(Box::new(HashVarlen));
        let merkle_verify = library.import(Box::new(MerkleVerify));

        triton_asm!(
            {entrypoint}:
                // _ [root] *field field_size

                push {self.0 as u32}
                swap 1
                // _ [root] *field leaf_index field_size

                push {TransactionKernel::MAST_HEIGHT}
                swap 3
                swap 1
                // _ [root] height leaf_index *field field_size

                call {hash_varlen}
                // _ [root] height leaf_index [field_hash]

                call {merkle_verify}
                // _

                return
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use itertools::Itertools;
    use num_traits::ConstZero;
    use prop::test_runner::RngAlgorithm;
    use prop::test_runner::TestRng;
    use prop::test_runner::TestRunner;
    use proptest::prelude::*;
    use rand::random;
    use strum::EnumCount;
    use strum::VariantArray;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::test_helpers::test_assertion_failure;
    use tasm_lib::traits::read_only_algorithm::ReadOnlyAlgorithm;
    use tasm_lib::traits::read_only_algorithm::ReadOnlyAlgorithmInitialState;
    use tasm_lib::traits::read_only_algorithm::ShadowedReadOnlyAlgorithm;
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tasm_lib::twenty_first::bfe;
    use tasm_lib::twenty_first::prelude::*;
    use tasm_lib::Digest;

    use super::*;
    use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
    use crate::models::blockchain::transaction::PublicAnnouncement;
    use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
    use crate::models::proof_abstractions::timestamp::Timestamp;
    use crate::util_types::mutator_set::addition_record::AdditionRecord;
    use crate::util_types::mutator_set::removal_record::RemovalRecord;

    impl AuthenticateTxkField {
        fn load_kernel(
            &self,
            kernel: &TransactionKernel,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
            address: BFieldElement,
        ) -> [(usize, usize); TransactionKernelField::COUNT] {
            encode_to_memory(memory, address, kernel);
            let mut field_offsets_and_sizes = vec![];

            // for all transaction fields in reverse order, accumulate offset and record size
            let mut offset = 0;

            // pub mutator_set_hash: Digest,
            if let Some(static_length) = Digest::static_length() {
                field_offsets_and_sizes.push((offset, static_length));
                offset += static_length;
            } else {
                unreachable!("mutator set hash should have static length 5");
            }

            // pub timestamp: Timestamp,
            if let Some(static_length) = Timestamp::static_length() {
                field_offsets_and_sizes.push((offset, static_length));
                offset += static_length;
            } else {
                unreachable!("timestamp should have static length 1");
            }

            // pub coinbase: Option<NeptuneCoins>,
            if let Some(_static_length) = Option::<NeptuneCoins>::static_length() {
                unreachable!("coinbase should not have static length");
            } else {
                offset += 1;
                let encoding = kernel.coinbase.encode();
                let dynamic_length = encoding.len();
                field_offsets_and_sizes.push((offset, dynamic_length));
                offset += dynamic_length;
            }

            // pub fee: NeptuneCoins,
            if let Some(static_length) = NeptuneCoins::static_length() {
                field_offsets_and_sizes.push((offset, static_length));
                offset += static_length;
            } else {
                unreachable!("fee should have static length 4");
            }

            // pub public_announcements: Vec<PublicAnnouncement>,
            if let Some(_static_length) = Vec::<PublicAnnouncement>::static_length() {
                unreachable!("public announcements should not have static length");
            } else {
                offset += 1;
                let encoding = kernel.public_announcements.encode();
                let dynamic_length = encoding.len();
                field_offsets_and_sizes.push((offset, dynamic_length));
                offset += dynamic_length;
            }

            // pub outputs: Vec<AdditionRecord>,
            if let Some(_static_length) = Vec::<AdditionRecord>::static_length() {
                unreachable!("outputs should not have static length");
            } else {
                offset += 1;
                let encoding = kernel.outputs.encode();
                let dynamic_length = encoding.len();
                field_offsets_and_sizes.push((offset, dynamic_length));
                offset += dynamic_length;
            }

            // pub inputs: Vec<RemovalRecord>,
            if let Some(_static_length) = Vec::<RemovalRecord>::static_length() {
                unreachable!("inputs should not have static length");
            } else {
                offset += 1;
                let encoding = kernel.inputs.encode();
                let dynamic_length = encoding.len();
                field_offsets_and_sizes.push((offset, dynamic_length));
                // offset += dynamic_length;
            }

            field_offsets_and_sizes.reverse();
            field_offsets_and_sizes.try_into().unwrap()
        }

        fn correct_initial_state(
            &self,
            kernel_ptr: BFieldElement,
            primitive_witness: PrimitiveWitness,
        ) -> ReadOnlyAlgorithmInitialState {
            let tx_kernel = &primitive_witness.kernel;
            let tx_kernel_digest = tx_kernel.mast_hash();
            let mut memory = HashMap::default();
            let field_offsets_and_sizes = self.load_kernel(tx_kernel, &mut memory, kernel_ptr);
            let field_size = field_offsets_and_sizes[self.0 as usize].1;
            let field_ptr = kernel_ptr + bfe!(field_offsets_and_sizes[self.0 as usize].0 as u64);

            let stack = [
                self.init_stack_for_isolated_run(),
                tx_kernel_digest.reversed().values().to_vec(),
                vec![field_ptr, bfe!(field_size as u64)],
            ]
            .concat();
            let digests = primitive_witness.kernel.mast_path(self.0);
            let nondeterminism = NonDeterminism::default()
                .with_ram(memory)
                .with_digests(digests);

            ReadOnlyAlgorithmInitialState {
                stack,
                nondeterminism,
            }
        }
    }

    impl ReadOnlyAlgorithm for AuthenticateTxkField {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &HashMap<BFieldElement, BFieldElement>,
            _nd_tokens: std::collections::VecDeque<BFieldElement>,
            nd_digests: std::collections::VecDeque<Digest>,
        ) {
            let field_size = stack.pop().unwrap().value();
            let field_ptr = stack.pop().unwrap();
            let txk_digest = Digest::new([
                stack.pop().unwrap(),
                stack.pop().unwrap(),
                stack.pop().unwrap(),
                stack.pop().unwrap(),
                stack.pop().unwrap(),
            ]);

            let field = (0..field_size)
                .map(|i| {
                    memory
                        .get(&(bfe!(i) + field_ptr))
                        .copied()
                        .unwrap_or(BFieldElement::ZERO)
                })
                .collect_vec();
            let field_digest = Tip5::hash_varlen(&field);

            let tree_height = TransactionKernel::MAST_HEIGHT;
            let auth_path = (0..tree_height).map(|i| nd_digests[i]).collect_vec();

            let mt_proof = MerkleTreeInclusionProof {
                tree_height,
                indexed_leafs: vec![(self.0 as usize, field_digest)],
                authentication_structure: auth_path,
            };
            assert!(mt_proof.verify(txk_digest));
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            _bench_case: Option<BenchmarkCase>,
        ) -> ReadOnlyAlgorithmInitialState {
            let mut rng: TestRng = TestRng::from_seed(RngAlgorithm::ChaCha, &seed);
            let inputs_ptr: BFieldElement = bfe!(rng.gen_range(0..(1 << 30)));

            let primitive_witness = PrimitiveWitness::arbitrary_with((2, 2, 2))
                .new_tree(&mut TestRunner::new_with_rng(Default::default(), rng))
                .unwrap()
                .current();
            self.correct_initial_state(inputs_ptr, primitive_witness)
        }
    }

    #[test]
    fn test() {
        for &field in TransactionKernelField::VARIANTS {
            println!("testing txk field {} ...", field);
            ShadowedReadOnlyAlgorithm::new(AuthenticateTxkField(field)).test();
        }
    }

    #[test]
    fn negative_test_bad_auth_path() {
        for &field in TransactionKernelField::VARIANTS {
            let snippet = AuthenticateTxkField(field);
            let inputs_ptr: BFieldElement = random();
            let primitive_witness = PrimitiveWitness::arbitrary_with((2, 2, 2))
                .new_tree(&mut TestRunner::deterministic())
                .unwrap()
                .current();
            let mut bad_auth_path = snippet.correct_initial_state(inputs_ptr, primitive_witness);
            bad_auth_path.nondeterminism.digests[0].0[0].increment();

            test_assertion_failure(
                &ShadowedReadOnlyAlgorithm::new(AuthenticateTxkField(field)),
                bad_auth_path.into(),
                &[],
            );
        }
    }
}
