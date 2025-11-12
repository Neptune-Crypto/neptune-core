use std::collections::HashMap;
use std::sync::OnceLock;

use field_count::FieldCount;
use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::library::Library;
use tasm_lib::list;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::bfieldcodec_derive::BFieldCodec;

use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::primitive_witness::SaltedUtxos;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelField;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::SecretWitness;

#[derive(
    Clone,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    GetSize,
    BFieldCodec,
    FieldCount,
    TasmObject,
)]
pub struct KernelToOutputsWitness {
    pub output_utxos: SaltedUtxos,
    pub sender_randomnesses: Vec<Digest>,
    pub receiver_digests: Vec<Digest>,
    pub kernel: TransactionKernel,
}

/// Contains the parts of the witness that the VM reads from memory
#[derive(Clone, Debug, PartialEq, Eq, BFieldCodec, TasmObject)]
struct KernelToOutputsWitnessMemory {
    pub output_utxos: SaltedUtxos,
    pub sender_randomnesses: Vec<Digest>,
    pub receiver_digests: Vec<Digest>,
}

impl From<&KernelToOutputsWitness> for KernelToOutputsWitnessMemory {
    fn from(value: &KernelToOutputsWitness) -> Self {
        Self {
            output_utxos: value.output_utxos.to_owned(),
            sender_randomnesses: value.sender_randomnesses.to_owned(),
            receiver_digests: value.receiver_digests.to_owned(),
        }
    }
}

impl From<&PrimitiveWitness> for KernelToOutputsWitness {
    fn from(primitive_witness: &PrimitiveWitness) -> Self {
        Self {
            output_utxos: primitive_witness.output_utxos.clone(),
            sender_randomnesses: primitive_witness.output_sender_randomnesses.clone(),
            receiver_digests: primitive_witness.output_receiver_digests.clone(),
            kernel: primitive_witness.kernel.clone(),
        }
    }
}

impl SecretWitness for KernelToOutputsWitness {
    fn standard_input(&self) -> PublicInput {
        PublicInput::new(self.kernel.mast_hash().reversed().values().to_vec())
    }

    fn output(&self) -> Vec<BFieldElement> {
        Tip5::hash(&self.output_utxos).values().to_vec()
    }

    fn program(&self) -> Program {
        KernelToOutputs.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        // set memory
        let mut memory = HashMap::default();
        let witness_for_memory: KernelToOutputsWitnessMemory = self.into();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            &witness_for_memory,
        );

        // set authentication path digests
        let digests = self.kernel.mast_path(TransactionKernelField::Outputs);

        NonDeterminism::default()
            .with_ram(memory)
            .with_digests(digests)
    }
}

#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, GetSize, FieldCount, BFieldCodec,
)]
pub struct KernelToOutputs;

impl KernelToOutputs {
    const JUMP_OUT_OF_BOUNDS_ERROR: i128 = 1_000_270;
    const INCONSISTENT_INDICATED_SALTED_OUTPUT_UTXOS_SIZE: i128 = 1_000_271;
    const INCONSISTENT_LENGTHS: i128 = 1_000_272;
}

impl ConsensusProgram for KernelToOutputs {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        const MAX_JUMP_LENGTH: usize = 2_000_000;

        const SIZE_OF_SALT: usize = 3;
        const SIZE_INDICATOR_SIZE: usize = 1;
        const LENGTH_INDICATOR_SIZE: usize = 1;

        let mut library = Library::new();

        let new_list = library.import(Box::new(list::new::New));
        let get_digest = library.import(Box::new(list::get::Get::new(DataType::Digest)));
        let compute_canonical_commitment =
            library.import(Box::new(tasm_lib::neptune::mutator_set::commit::Commit));
        let hash_varlen = library.import(Box::new(
            tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen,
        ));
        let merkle_verify =
            library.import(Box::new(tasm_lib::hashing::merkle_verify::MerkleVerify));
        let field_salted_output_utxos = field!(KernelToOutputsWitnessMemory::output_utxos);
        let field_sender_randomnesses = field!(KernelToOutputsWitnessMemory::sender_randomnesses);
        let field_receiver_digests = field!(KernelToOutputsWitnessMemory::receiver_digests);
        let field_utxos = field!(SaltedUtxos::utxos);

        let calculate_canonical_commitments =
            "kernel_to_outputs_calculate_canonical_commitments".to_string();

        let audit_preloaded_data = library.import(Box::new(VerifyNdSiIntegrity::<
            KernelToOutputsWitnessMemory,
        >::default()));

        let tasm = triton_asm! {
            read_io 5       // _ [txkmh]
            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
                            // _ [txkmh] *kernel_to_outputs_witness

            dup 0
            call {audit_preloaded_data}
            pop 1
                            // _ [txkmh] *kernel_to_outputs_witness

            dup 0
            {&field_salted_output_utxos}    // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos
            dup 0
            {&field_utxos}                  // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos
            addi 1                          // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len

            dup 2
            {&field_sender_randomnesses}    // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses

            dup 3
            {&field_receiver_digests}       // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests

            read_mem 1
            addi {1 + Digest::LEN}
            swap 1
            dup 0
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests[0]_lw N N

            dup 5
            {&field_utxos}
            read_mem 1
            pop 1
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests[0]_lw N N utxos_len

            dup 1
            eq
            assert error_id {Self::INCONSISTENT_LENGTHS}
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests[0]_lw N N

            call {new_list}
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests[0]_lw N N *canonical_commitments

            write_mem 1
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests[0]_lw N *canonical_commitments[0]

            swap 1
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests[0]_lw *canonical_commitments[0] N

            push 0
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests[0]_lw *canonical_commitments[0] N 0

            dup 5
            place 6
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *utxos[0]_len *sender_randomnesses *receiver_digests[0]_lw *canonical_commitments[0] N 0


            call {calculate_canonical_commitments}
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len  *utxos[N]_len *sender_randomnesses *receiver_digests[N] *canonical_commitments[N] N N

            pop 1
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len  *utxos[N]_len *sender_randomnesses *receiver_digests[N] *canonical_commitments[N] N

            push {-(Digest::LEN as isize)} mul addi -1 add
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len  *utxos[N]_len *sender_randomnesses *receiver_digests[N] *canonical_commitments

            dup 0 read_mem 1 pop 1
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len  *utxos[N]_len *sender_randomnesses *receiver_digests[N] *canonical_commitments N

            push {Digest::LEN} mul addi 1
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len  *utxos[N]_len *sender_randomnesses *receiver_digests[N] *canonical_commitments (5*N+1)

            call {hash_varlen}
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len  *utxos[N]_len *sender_randomnesses *receiver_digests[N] [cc_digest]

            // r h i l
            dup 15 dup 15 dup 15 dup 15 dup 15
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len  *utxos[N]_len *sender_randomnesses *receiver_digests[N] [cc_digest] [txkmh]

            push {TransactionKernel::MAST_HEIGHT}
            push {TransactionKernelField::Outputs as u32}
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len  *utxos[N]_len *sender_randomnesses *receiver_digests[N] [cc_digest] [txkmh] h i

            dup 11 dup 11 dup 11 dup 11 dup 11
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len  *utxos[N]_len *sender_randomnesses *receiver_digests[N] [cc_digest] [txkmh] h i [cc_digest]

            call {merkle_verify}
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len  *utxos[N]_len *sender_randomnesses *receiver_digests[N] [cc_digest]


            pop 5 pop 2
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len  *utxos[N]_len

            swap 1
            push -1 mul
            add
            addi {SIZE_OF_SALT + SIZE_INDICATOR_SIZE + LENGTH_INDICATOR_SIZE}
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos (*utxos[N]_len - *utxos[0]_len + 5)
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos calculated_salted_utxos_len

            swap 1
            // _ [txkmh] *kernel_to_outputs_witness calculated_salted_utxos_len *salted_output_utxos

            addi -1
            // _ [txkmh] *kernel_to_outputs_witness calculated_salted_utxos_len *salted_output_utxos_size

            read_mem 1
            // _ [txkmh] *kernel_to_outputs_witness calculated_salted_utxos_len size (*salted_output_utxos_size-1)

            place 2
            // _ [txkmh] *kernel_to_outputs_witness  (*salted_output_utxos_size-1) calculated_salted_utxos_len size

            dup 1
            eq
            assert error_id {Self::INCONSISTENT_INDICATED_SALTED_OUTPUT_UTXOS_SIZE}
            // _ [txkmh] *kernel_to_outputs_witness  (*salted_output_utxos_size-1) size

            swap 1
             // _ [txkmh] *kernel_to_outputs_witness size (*salted_output_utxos_size-1)

            addi 2
            // _ [txkmh] *kernel_to_outputs_witness size *salted_output_utxos

            swap 1
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos size

            call {hash_varlen}
            // _ [txkmh] *kernel_to_outputs_witness [salted_outputs_hash]

            write_io {Digest::LEN}
            // _ [txkmh] *kernel_to_outputs_witness

            pop 5
            pop 1
            // _

            halt

            // INVARIANT: _ *utxos[i]_len *sender_randomnesses *receiver_digests[i]_lw *canonical_commitments[i] N i
            {calculate_canonical_commitments}:
                /* Loop's end-condition: N == i */
                dup 1 dup 1 eq
                skiz return
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests[i]_lw *canonical_commitments[i] N i

                dup 3
                read_mem {Digest::LEN}
                addi {2 * Digest::LEN}
                swap 9
                pop 1
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i] N i [receiver_digests[i]]

                dup 9 dup 6 call {get_digest}
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i] N i [receiver_digests[i]] [sender_randomnesses[i]]

                dup 15
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i] N i [receiver_digests[i]] [sender_randomnesses[i]] *utxos[i]_len

                read_mem 1 addi 2 swap 1
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i] N i [receiver_digests[i]] [sender_randomnesses[i]] *utxos[i] utxos[i]_len

                call {hash_varlen}
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i] N i [receiver_digests[i]] [sender_randomnesses[i]] [item]

                call {compute_canonical_commitment}
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i] N i [canonical_commitment]

                dup 7 write_mem 5
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i] N i *canonical_commitments[i+1]

                swap 3 pop 1
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i+1] N i

                dup 5
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i+1] N i *utxos[i]_len

                read_mem 1
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i+1] N i utxos[i]_len (*utxos[i]_len-1)

                push {MAX_JUMP_LENGTH}
                dup 2
                lt
                assert error_id {Self::JUMP_OUT_OF_BOUNDS_ERROR}

                addi 2 add
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i+1] N i utxos[i+1]_len

                swap 6 pop 1
                // _ *utxos[i+1]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i+1] N i

                addi 1
                // _ *utxos[i+1]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i+1] N (i+1)

                recurse
        };

        let dependencies = library.all_imports();

        let code = triton_asm!(
            {&tasm}
            {&dependencies}
        );

        (library, code)
    }

    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use proptest::prop_assert_eq;
    use proptest::strategy::Strategy;
    use proptest::test_runner::TestRunner;
    use rand::random;
    use tasm_lib::triton_vm;
    use test_strategy::proptest;

    use super::*;
    use crate::protocol::consensus::transaction::utxo::Utxo;
    use crate::protocol::proof_abstractions::tasm::builtins as tasm;
    use crate::protocol::proof_abstractions::tasm::program::tests::test_program_snapshot;
    use crate::protocol::proof_abstractions::tasm::program::tests::ConsensusProgramSpecification;
    use crate::triton_vm::proof::Claim;
    use crate::triton_vm::stark::Stark;
    use crate::util_types::mutator_set::addition_record::AdditionRecord;
    use crate::util_types::mutator_set::commit;

    impl ConsensusProgramSpecification for KernelToOutputs {
        fn source(&self) {
            let txk_digest: Digest = tasm::tasmlib_io_read_stdin___digest();
            let start_address: BFieldElement =
                FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
            let ktow: KernelToOutputsWitnessMemory = tasm::decode_from_memory(start_address);

            // divine in the salted output UTXOs with hash
            let salted_output_utxos: &SaltedUtxos = &ktow.output_utxos;
            let output_utxos: &Vec<Utxo> = &salted_output_utxos.utxos;

            // divine in the commitment randomness
            let sender_randomnesses: &Vec<Digest> = &ktow.sender_randomnesses;
            let receiver_digests: &Vec<Digest> = &ktow.receiver_digests;

            let n = receiver_digests.len();
            assert!(n == output_utxos.len());

            // compute the canonical commitments (= addition records)
            let mut addition_records: Vec<AdditionRecord> = Vec::default();
            let mut i = 0;
            while i < n {
                let addition_record: AdditionRecord = commit(
                    Tip5::hash(&output_utxos[i]),
                    sender_randomnesses[i],
                    receiver_digests[i],
                );
                addition_records.push(addition_record);
                i += 1;
            }

            // authenticate the addition records against the txk mast hash
            let addition_records_hash: Digest = Tip5::hash(&addition_records);
            tasm::tasmlib_hashing_merkle_verify(
                txk_digest,
                TransactionKernelField::Outputs as u32,
                addition_records_hash,
                TransactionKernel::MAST_HEIGHT as u32,
            );

            // output hash of salted output UTXOs
            let salted_output_utxos_hash: Digest = Tip5::hash(salted_output_utxos);
            tasm::tasmlib_io_write_to_stdout___digest(salted_output_utxos_hash);
        }
    }

    #[proptest(cases = 30)]
    fn kernel_to_outputs_proptest(
        #[strategy(0usize..7)] _num_outputs: usize,
        #[strategy(0usize..5)] _num_inputs: usize,
        #[strategy(0usize..5)] _num_pub_announcements: usize,
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(Some(#_num_inputs),#_num_outputs,#_num_pub_announcements))]
        primitive_witness: PrimitiveWitness,
    ) {
        let kernel_to_outputs_witness = KernelToOutputsWitness::from(&primitive_witness);
        let expected_output = kernel_to_outputs_witness.output();

        let rust_result = KernelToOutputs
            .run_rust(
                &kernel_to_outputs_witness.standard_input(),
                kernel_to_outputs_witness.nondeterminism(),
            )
            .unwrap();
        prop_assert_eq!(expected_output, rust_result.clone());

        let tasm_result = KernelToOutputs
            .run_tasm(
                &kernel_to_outputs_witness.standard_input(),
                kernel_to_outputs_witness.nondeterminism(),
            )
            .unwrap();
        prop_assert_eq!(rust_result, tasm_result);
    }

    #[test]
    fn inconsistent_lengths() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(3), 2, 2)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let mut witness = KernelToOutputsWitness::from(&primitive_witness);
        witness.receiver_digests.push(random());
        KernelToOutputs
            .test_assertion_failure(
                witness.standard_input(),
                witness.nondeterminism(),
                &[KernelToOutputs::INCONSISTENT_LENGTHS],
            )
            .unwrap();
    }

    #[test]
    fn kernel_to_outputs_unittest() {
        for num_inputs in 0..=2 {
            for num_outputs in 0..=2 {
                let mut test_runner = TestRunner::deterministic();
                let primitive_witness =
                    PrimitiveWitness::arbitrary_with_size_numbers(Some(num_inputs), num_outputs, 2)
                        .new_tree(&mut test_runner)
                        .unwrap()
                        .current();
                let kernel_to_outputs_witness = KernelToOutputsWitness::from(&primitive_witness);
                let std_input = kernel_to_outputs_witness.standard_input();
                let non_determinism = kernel_to_outputs_witness.nondeterminism();
                let tasm_result = KernelToOutputs
                    .run_tasm(&std_input, non_determinism.clone())
                    .unwrap();
                assert_eq!(kernel_to_outputs_witness.output(), tasm_result);

                let rust_result = KernelToOutputs
                    .run_rust(&std_input, non_determinism)
                    .unwrap();
                assert_eq!(rust_result, tasm_result);
            }
        }
    }

    #[test]
    fn kernel_to_outputs_failing_proof() {
        let mut test_runner = TestRunner::deterministic();

        let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 2)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let kernel_to_outputs_witness = KernelToOutputsWitness::from(&primitive_witness);
        let tasm_result = KernelToOutputs
            .run_tasm(
                &kernel_to_outputs_witness.standard_input(),
                kernel_to_outputs_witness.nondeterminism(),
            )
            .unwrap();

        assert_eq!(
            kernel_to_outputs_witness.output(),
            tasm_result.clone(),
            "incorrect output"
        );

        let claim = Claim::new(KernelToOutputs.program().hash())
            .with_input(kernel_to_outputs_witness.standard_input().individual_tokens)
            .with_output(tasm_result);
        let proof = triton_vm::prove(
            Stark::default(),
            &claim,
            KernelToOutputs.program(),
            kernel_to_outputs_witness.nondeterminism(),
        )
        .expect("could not produce proof");
        assert!(
            triton_vm::verify(Stark::default(), &claim, &proof),
            "proof fails"
        );
    }

    test_program_snapshot!(
        KernelToOutputs,
        "7b5cdf881ba64ef4d74245da25f4beb1c4b416922af46eacaa17ebc328021e0249a9301505c3223f"
    );
}
