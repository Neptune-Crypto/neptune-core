use tasm_lib::data_type::DataType;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Library;

use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelField;
use crate::protocol::consensus::transaction::TransactionKernel;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::triton_vm::prelude::*;

/// Authenticate transaction inputs against the transaction kernel mast hash.
///
/// Crashes the VM if the inputs and provided non-determinism does not match
/// the MAST hash.
#[derive(Debug, Clone, Copy)]
pub struct AuthenticateInputsAgainstTxk;

impl BasicSnippet for AuthenticateInputsAgainstTxk {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "transaction_kernel_mast_hash".to_owned()),
            // Type of `inputs` is Vec<RemovalRecord>
            (DataType::VoidPointer, "inputs".to_owned()),
            (DataType::U32, "inputs_size".to_owned()),
        ]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![]
    }

    fn entrypoint(&self) -> String {
        "neptune_transaction_authenticate_inputs_against_txk"
            .to_owned()
            .to_owned()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let entrypoint = self.entrypoint();

        let hash_varlen = library.import(Box::new(HashVarlen));
        let merkle_verify = library.import(Box::new(MerkleVerify));

        triton_asm!(
            {entrypoint}:
                // _ [root] *inputs inputs_size

                push {TransactionKernelField::Inputs as u32}
                swap 1
                // _ [root] *inputs leaf_index inputs_size

                push {TransactionKernel::MAST_HEIGHT}
                swap 3
                swap 1
                // _ [root] height leaf_index *inputs inputs_size

                call {hash_varlen}
                // _ [root] height leaf_index [inputs_hash]

                call {merkle_verify}
                // _

                return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;

    use itertools::Itertools;
    use prop::test_runner::RngAlgorithm;
    use prop::test_runner::TestRng;
    use prop::test_runner::TestRunner;
    use proptest::prelude::*;
    use proptest::strategy::ValueTree;
    use rand::random;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tasm_lib::hashing::merkle_verify::MerkleVerify;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::prelude::TasmObject;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::test_helpers::test_assertion_failure;
    use tasm_lib::traits::read_only_algorithm::ReadOnlyAlgorithm;
    use tasm_lib::traits::read_only_algorithm::ReadOnlyAlgorithmInitialState;
    use tasm_lib::traits::read_only_algorithm::ShadowedReadOnlyAlgorithm;
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tasm_lib::twenty_first::prelude::MerkleTreeInclusionProof;

    use super::*;
    use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
    use crate::util_types::mutator_set::removal_record::RemovalRecord;

    impl AuthenticateInputsAgainstTxk {
        fn correct_init_state(
            &self,
            inputs_ptr: BFieldElement,
            primitive_witness: PrimitiveWitness,
        ) -> ReadOnlyAlgorithmInitialState {
            let tx_kernel = &primitive_witness.kernel;
            let tx_kernel_digest = tx_kernel.mast_hash();
            let mut memory = HashMap::default();
            let next_free_address = encode_to_memory(&mut memory, inputs_ptr, &tx_kernel.inputs);
            let inputs_size = next_free_address - inputs_ptr;

            let stack = [
                self.init_stack_for_isolated_run(),
                tx_kernel_digest.reversed().values().to_vec(),
                vec![inputs_ptr, inputs_size],
            ]
            .concat();
            let digests = primitive_witness
                .kernel
                .mast_path(TransactionKernelField::Inputs);
            let nondeterminism = NonDeterminism::default()
                .with_ram(memory)
                .with_digests(digests);

            ReadOnlyAlgorithmInitialState {
                stack,
                nondeterminism,
            }
        }
    }

    impl ReadOnlyAlgorithm for AuthenticateInputsAgainstTxk {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &std::collections::HashMap<BFieldElement, BFieldElement>,
            _nd_tokens: std::collections::VecDeque<BFieldElement>,
            nd_digests: std::collections::VecDeque<Digest>,
        ) {
            let _inputs_size = stack.pop().unwrap();
            let inputs_ptr = stack.pop().unwrap();
            let txk_digest = Digest::new([
                stack.pop().unwrap(),
                stack.pop().unwrap(),
                stack.pop().unwrap(),
                stack.pop().unwrap(),
                stack.pop().unwrap(),
            ]);
            let inputs = *Vec::<RemovalRecord>::decode_from_memory(memory, inputs_ptr).unwrap();
            let inputs_digest = Tip5::hash(&inputs);

            let tree_height = TransactionKernel::MAST_HEIGHT;
            let auth_path = (0..tree_height).map(|i| nd_digests[i]).collect_vec();

            let mt_proof = MerkleTreeInclusionProof {
                tree_height: tree_height.try_into().unwrap(),
                indexed_leafs: vec![(TransactionKernelField::Inputs as usize, inputs_digest)],
                authentication_structure: auth_path,
            };
            assert!(mt_proof.verify(txk_digest));
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            _bench_case: Option<BenchmarkCase>,
        ) -> ReadOnlyAlgorithmInitialState {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let inputs_ptr: BFieldElement = bfe!(rng.random_range(0..(1 << 30)));

            let primitive_witness: PrimitiveWitness = {
                let seedd: [u8; 32] = rng.random();
                let mut test_runner = TestRunner::new_with_rng(
                    Default::default(),
                    TestRng::from_seed(RngAlgorithm::ChaCha, &seedd),
                );
                PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 2)
                    .new_tree(&mut test_runner)
                    .unwrap()
                    .current()
            };
            self.correct_init_state(inputs_ptr, primitive_witness)
        }
    }

    #[test]
    fn test() {
        ShadowedReadOnlyAlgorithm::new(AuthenticateInputsAgainstTxk).test();
    }

    #[test]
    fn negative_test_bad_auth_path() {
        let snippet = AuthenticateInputsAgainstTxk;
        let inputs_ptr: BFieldElement = random();
        let primitive_witness: PrimitiveWitness = {
            let mut test_runner = TestRunner::deterministic();
            PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 2)
                .new_tree(&mut test_runner)
                .unwrap()
                .current()
        };
        let mut bad_auth_path = snippet.correct_init_state(inputs_ptr, primitive_witness);
        bad_auth_path.nondeterminism.digests[0] =
            bad_auth_path.nondeterminism.digests[0].reversed();

        test_assertion_failure(
            &ShadowedReadOnlyAlgorithm::new(AuthenticateInputsAgainstTxk),
            bad_auth_path.into(),
            &[MerkleVerify::ROOT_MISMATCH_ERROR_ID],
        );
    }
}
