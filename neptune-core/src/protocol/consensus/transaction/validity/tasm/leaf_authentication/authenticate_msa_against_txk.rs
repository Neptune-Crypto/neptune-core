use tasm_lib::data_type::DataType;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::mmr::bag_peaks::BagPeaks;
use tasm_lib::prelude::*;
use tasm_lib::twenty_first::prelude::Digest;

use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelField;
use crate::protocol::consensus::transaction::TransactionKernel;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::triton_vm::prelude::*;

/// Authenticate a mutator set accumulator against a transaction-kernel mast hash
///
/// Crashes the VM if the mutator set does not belong in the Merkle tree from
/// which the transaction-kernel mast hash was built.
#[derive(Debug, Clone, Copy)]
pub struct AuthenticateMsaAgainstTxk;

impl BasicSnippet for AuthenticateMsaAgainstTxk {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "aocl_mmr".to_owned()),
            (DataType::VoidPointer, "swbfi_bagged_ptr".to_owned()),
            (DataType::VoidPointer, "swbfa_digest_ptr".to_owned()),
            (DataType::Digest, "transaction_kernel_digest".to_owned()),
        ]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![]
    }

    fn entrypoint(&self) -> String {
        "neptune_transaction_authenticate_msa_against_txk".to_owned()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let entrypoint = self.entrypoint();
        let load_digest = triton_asm!(
            // _ *digest

            addi {Digest::LEN - 1}
            // _ *digest_lw

            read_mem {Digest::LEN}
            pop 1
            // _ [digest]
        );

        let swap_top_two_digests = triton_asm!(
            swap 5
            swap 4
            swap 9
            swap 4
            swap 3
            swap 8
            swap 3
            swap 2
            swap 7
            swap 2
            swap 1
            swap 6
            swap 1
        );

        let merkle_verify = library.import(Box::new(MerkleVerify));

        let bag_mmr_peaks = library.import(Box::new(BagPeaks));
        triton_asm!(
            {entrypoint}:
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash]

                push {TransactionKernel::MAST_HEIGHT}
                push {TransactionKernelField::MutatorSetHash as u32}
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i

                dup 8
                {&load_digest}
                hint swbfi_bagged: Digest = stack[0..5]
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i [swbfi_bagged]

                dup 14
                call {bag_mmr_peaks}
                hint aocl_bagged: Digest = stack[0..5]
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i [swbfi_bagged] [aocl_mmr_bagged]

                hash
                hint left: Digest = stack[0..5]
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i [left]

                push 0
                push 0
                push 0
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i [left] 0 0 0

                dup 15
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i [left] 0 0 0 *swbfa_digest

                push 0
                push 0
                swap 2
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i [left] [0; digest] *swbfa_digest
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i [left] [default_digest] *swbfa_digest

                {&load_digest}
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i [left] [default_digest] [swbfa_digest]

                hash
                hint right: Digest = stack[0..5]
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i [left] [right]

                {&swap_top_two_digests}
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i [right] [left]

                hash
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i [msah]

                push 0
                push 0
                push 0
                push 0
                push 1
                {&swap_top_two_digests}
                sponge_init
                sponge_absorb
                sponge_squeeze
                swap 5 pop 1
                swap 5 pop 1
                swap 5 pop 1
                swap 5 pop 1
                swap 5 pop 1
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i [msah_digest]

                call {merkle_verify}
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest

                pop 3
                // _

                return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;
    use std::collections::VecDeque;

    use itertools::Itertools;
    use prop::test_runner::RngAlgorithm;
    use prop::test_runner::TestRng;
    use prop::test_runner::TestRunner;
    use proptest::prelude::*;
    use rand::random;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use strum::EnumCount;
    use tasm_lib::hashing::merkle_verify::MerkleVerify;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::test_helpers::test_assertion_failure;
    use tasm_lib::traits::mem_preserver::MemPreserver;
    use tasm_lib::traits::mem_preserver::MemPreserverInitialState;
    use tasm_lib::traits::mem_preserver::ShadowedMemPreserver;
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tasm_lib::twenty_first::prelude::MerkleTreeInclusionProof;
    use tasm_lib::twenty_first::prelude::Mmr;
    use tasm_lib::twenty_first::prelude::Sponge;
    use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

    use super::*;
    use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;

    impl MemPreserver for AuthenticateMsaAgainstTxk {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &HashMap<BFieldElement, BFieldElement>,
            _nd_tokens: VecDeque<BFieldElement>,
            nd_digests: VecDeque<Digest>,
            _stdin: VecDeque<BFieldElement>,
            sponge: &mut Option<Tip5>,
        ) -> Vec<BFieldElement> {
            let txk_digest = Digest::new([
                stack.pop().unwrap(),
                stack.pop().unwrap(),
                stack.pop().unwrap(),
                stack.pop().unwrap(),
                stack.pop().unwrap(),
            ]);
            let swbfa_digest_ptr = stack.pop().unwrap();
            let swbfi_bagged_ptr = stack.pop().unwrap();
            let aocl_mmr_ptr = stack.pop().unwrap();

            let swbfa_digest = *Digest::decode_from_memory(memory, swbfa_digest_ptr).unwrap();
            let swbfi_bagged = *Digest::decode_from_memory(memory, swbfi_bagged_ptr).unwrap();
            let aocl_mmr = *MmrAccumulator::decode_from_memory(memory, aocl_mmr_ptr).unwrap();
            let aocl_mmr_bagged = aocl_mmr.bag_peaks();

            let left: Digest = Tip5::hash_pair(aocl_mmr_bagged, swbfi_bagged);
            let right: Digest = Tip5::hash_pair(swbfa_digest, Digest::default());
            let msah: Digest = Tip5::hash_pair(left, right);

            // Manual `hash_varlen` impl to mirror sponge state
            *sponge = Some(Tip5::init());
            sponge.as_mut().unwrap().pad_and_absorb_all(&msah.values());
            let randomness = sponge.as_mut().unwrap().squeeze();
            let msah_digest = Digest::new([
                randomness[0],
                randomness[1],
                randomness[2],
                randomness[3],
                randomness[4],
            ]);

            let tree_height = TransactionKernelField::COUNT.next_power_of_two().ilog2() as usize;
            let auth_path = (0..tree_height).map(|i| nd_digests[i]).collect_vec();

            let mt_proof = MerkleTreeInclusionProof {
                tree_height: tree_height.try_into().unwrap(),
                indexed_leafs: vec![(TransactionKernelField::MutatorSetHash as usize, msah_digest)],
                authentication_structure: auth_path,
            };
            assert!(mt_proof.verify(txk_digest));

            vec![]
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            _bench_case: Option<BenchmarkCase>,
        ) -> MemPreserverInitialState {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let swbfi_digest_ptr = rng.random_range(0..(1 << 30));
            let swbfa_digest_ptr = swbfi_digest_ptr + rng.random_range(5..(1 << 25));
            let aocl_mmr_address: u32 = rng.random_range(0..(1 << 30));
            let swbfi_digest_ptr = bfe!(swbfi_digest_ptr as u64);
            let swbfa_digest_ptr = bfe!(swbfa_digest_ptr as u64);

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

            let aocl_mmr = &primitive_witness.mutator_set_accumulator.aocl;
            let swbfa_digest = Tip5::hash(&primitive_witness.mutator_set_accumulator.swbf_active);
            let swbfi_digest = primitive_witness
                .mutator_set_accumulator
                .swbf_inactive
                .bag_peaks();

            let aocl_mmr_address = bfe!(u64::from(aocl_mmr_address));

            let mut memory = HashMap::default();
            encode_to_memory(&mut memory, aocl_mmr_address, aocl_mmr);
            encode_to_memory(&mut memory, swbfi_digest_ptr, &swbfi_digest);
            encode_to_memory(&mut memory, swbfa_digest_ptr, &swbfa_digest);

            let transaction_kernel_digest = primitive_witness.kernel.mast_hash();
            let stack = [
                self.init_stack_for_isolated_run(),
                vec![aocl_mmr_address, swbfi_digest_ptr, swbfa_digest_ptr],
                transaction_kernel_digest.reversed().values().to_vec(),
            ]
            .concat();

            let digests = primitive_witness
                .kernel
                .mast_path(TransactionKernelField::MutatorSetHash);

            let nondeterminism = NonDeterminism::default()
                .with_ram(memory)
                .with_digests(digests);
            MemPreserverInitialState {
                stack,
                nondeterminism,
                public_input: VecDeque::default(),
                sponge_state: None,
            }
        }
    }

    #[test]
    fn test() {
        ShadowedMemPreserver::new(AuthenticateMsaAgainstTxk).test();
    }

    #[test]
    fn negative_test_bad_auth_path() {
        let seed: [u8; 32] = random();
        let mut bad_auth_path = AuthenticateMsaAgainstTxk.pseudorandom_initial_state(seed, None);
        bad_auth_path.nondeterminism.digests[1] = random();

        test_assertion_failure(
            &ShadowedMemPreserver::new(AuthenticateMsaAgainstTxk),
            bad_auth_path.into(),
            &[MerkleVerify::ROOT_MISMATCH_ERROR_ID],
        );
    }
}
