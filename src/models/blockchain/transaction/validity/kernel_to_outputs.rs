use std::collections::HashMap;

use field_count::FieldCount;
use get_size::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::library::Library;
use tasm_lib::list;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::instruction::LabelledInstruction;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::triton_vm::prelude::Digest;
use tasm_lib::triton_vm::program::NonDeterminism;
use tasm_lib::triton_vm::program::PublicInput;
use tasm_lib::triton_vm::triton_asm;
use tasm_lib::twenty_first::bfieldcodec_derive::BFieldCodec;
use tasm_lib::twenty_first::prelude::AlgebraicHasher;
use tasm_lib::DIGEST_LENGTH;

use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::primitive_witness::SaltedUtxos;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelField;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::builtins as tasmlib;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::SecretWitness;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::commit;

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
    fn standard_input(&self) -> tasm_lib::triton_vm::prelude::PublicInput {
        PublicInput::new(self.kernel.mast_hash().reversed().values().to_vec())
    }

    fn program(&self) -> tasm_lib::triton_vm::prelude::Program {
        KernelToOutputs.program()
    }

    fn nondeterminism(&self) -> tasm_lib::triton_vm::prelude::NonDeterminism {
        // set memory
        let mut memory = HashMap::default();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self.clone(),
        );

        // set digests
        let digests = vec![self.kernel.mast_path(TransactionKernelField::OutputUtxos)].concat();

        NonDeterminism::default()
            .with_ram(memory)
            .with_digests(digests)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, FieldCount, BFieldCodec)]
pub struct KernelToOutputs;

impl ConsensusProgram for KernelToOutputs {
    fn source(&self) {
        let txk_digest: Digest = tasmlib::tasm_io_read_stdin___digest();
        let start_address: BFieldElement = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
        let ktow: KernelToOutputsWitness = tasmlib::decode_from_memory(start_address);

        // divine in the salted output UTXOs with hash
        let salted_output_utxos: &SaltedUtxos = &ktow.output_utxos;
        let output_utxos: &Vec<Utxo> = &salted_output_utxos.utxos;

        // divine in the commitment randomness
        let sender_randomnesses: &Vec<Digest> = &ktow.sender_randomnesses;
        let receiver_digests: &Vec<Digest> = &ktow.receiver_digests;

        // compute the canonical commitments (= addition records)
        let mut addition_records: Vec<AdditionRecord> = Vec::with_capacity(output_utxos.len());
        let mut i = 0;
        while i < output_utxos.len() {
            let addition_record: AdditionRecord = commit(
                Hash::hash(&output_utxos[i]),
                sender_randomnesses[i],
                receiver_digests[i],
            );
            addition_records.push(addition_record);
            i += 1;
        }

        // authenticate the addition records against the txk mast hash
        let addition_records_hash: Digest = Hash::hash(&addition_records);
        tasmlib::tasm_hashing_merkle_verify(
            txk_digest,
            TransactionKernelField::OutputUtxos as u32,
            addition_records_hash,
            TransactionKernel::MAST_HEIGHT as u32,
        );

        // output hash of salted output UTXOs
        let salted_output_utxos_hash: Digest = Hash::hash(salted_output_utxos);
        tasmlib::tasm_io_write_to_stdout___digest(salted_output_utxos_hash);
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        let mut library = Library::new();

        let new_list = library.import(Box::new(list::new::New {
            element_type: DataType::Digest,
        }));
        let get_digest = library.import(Box::new(list::get::Get {
            element_type: DataType::Digest,
        }));
        let len = library.import(Box::new(list::length::Length {
            element_type: DataType::Digest,
        }));
        let compute_canonical_commitment =
            library.import(Box::new(tasm_lib::neptune::mutator_set::commit::Commit));
        let hash_varlen = library.import(Box::new(
            tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen,
        ));
        let merkle_verify =
            library.import(Box::new(tasm_lib::hashing::merkle_verify::MerkleVerify));
        let field_salted_output_utxos = field!(KernelToOutputsWitness::output_utxos);
        let field_sender_randomnesses = field!(KernelToOutputsWitness::sender_randomnesses);
        let field_receiver_digests = field!(KernelToOutputsWitness::receiver_digests);
        let field_utxos = field!(SaltedUtxos::utxos);

        let main_loop = format!("kernel_to_outputs_main_loop");

        let tasm = triton_asm! {
            read_io 5       // [txkmh]
            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
                            // [txkmh] *kernel_to_outputs_witness

            dup 0
            {&field_salted_output_utxos}    // [txkmh] *kernel_to_outputs_witness *salted_output_utxos
            dup 0
            {&field_utxos}                  // [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos
            push 1 add                      // [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len

            dup 2
            {&field_sender_randomnesses}    // [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses

            dup 3
            {&field_receiver_digests}       // [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests

            call {new_list}                 // [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests *canonical_commitments

            dup 1
            call {len}                      // [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests *canonical_commitments N

            dup 0 swap 2                    // [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests N N *canonical_commitments
            write_mem 1 swap 1              // [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests *canonical_commitments[0] N


            push 0                          // [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests *canonical_commitments[0] N 0

            call {main_loop}                // [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests *canonical_commitments[0] N N
            pop 2                           // [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests *canonical_commitments[N]

            dup 1 read_mem 1 pop 1          // [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests *canonical_commitments[N] N
            push {-(DIGEST_LENGTH as isize)} mul push -1 add add
                                            // [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests *canonical_commitments

            dup 1 read_mem 1 pop 1          // [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests *canonical_commitments N
            push {DIGEST_LENGTH} mul push 1 add
            // [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests *canonical_commitments (5*N+1)

            call {hash_varlen}
            // [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests [cc_digest]

            // r h i l
            dup 14 dup 14 dup 14 dup 14 dup 14
            // [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests [cc_digest] [txkmh]

            push {TransactionKernel::MAST_HEIGHT}
            push {TransactionKernelField::OutputUtxos as u32}
            // [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests [cc_digest] [txkmh] h i
            dup 11 dup 11 dup 11 dup 11 dup 11
            // [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests [cc_digest] [txkmh] h i [cc_digest]

            call {merkle_verify}
            // [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests [cc_digest]

            pop 5 pop 3
            // [txkmh] *kernel_to_outputs_witness *salted_output_utxos

            push -1 add
            // [txkmh] *kernel_to_outputs_witness *salted_output_utxos_size

            read_mem 1
            // [txkmh] *kernel_to_outputs_witness size (*salted_output_utxos_size-1)

            push 2 add
            // [txkmh] *kernel_to_outputs_witness size *salted_output_utxos

            swap 1
            // [txkmh] *kernel_to_outputs_witness *salted_output_utxos size

            call {hash_varlen}
            // [txkmh] *kernel_to_outputs_witness [salted_outputs_hash]

            write_io {DIGEST_LENGTH}

            halt

            // INVARIANT: _ *utxos[i]_len *sender_randomnesses *receiver_digests *canonical_commitments[i] N i
            {main_loop}:
                dup 1 dup 1 eq      // _ *utxos[i]_len *sender_randomnesses *receiver_digests *canonical_commitments[i] N i (N==i)
                skiz return

                // _ *utxos[i]_len *sender_randomnesses *receiver_digests *canonical_commitments[i] N i

                dup 3 dup 1 call {get_digest}
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests *canonical_commitments[i] N i [receiver_digests[i]]

                dup 9 dup 6 call {get_digest}
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests *canonical_commitments[i] N i [receiver_digests[i]] [sender_randomnesses[i]]

                dup 15
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests *canonical_commitments[i] N i [receiver_digests[i]] [sender_randomnesses[i]] *utxos[i]_len

                read_mem 1 push 2 add swap 1
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests *canonical_commitments[i] N i [receiver_digests[i]] [sender_randomnesses[i]] *utxos[i] utxos[i]_len

                call {hash_varlen}
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests *canonical_commitments[i] N i [receiver_digests[i]] [sender_randomnesses[i]] [item]

                call {compute_canonical_commitment}
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests *canonical_commitments[i] N i [canonical_commitment]

                dup 7 write_mem 5
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests *canonical_commitments[i] N i *canonical_commitments[i+1]

                swap 3 pop 1
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests *canonical_commitments[i+1] N i

                dup 5
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests *canonical_commitments[i+1] N i *utxos[i]_len

                read_mem 1
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests *canonical_commitments[i+1] N i utxos[i]_len (*utxos[i]_len-1)

                push 2 add add
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests *canonical_commitments[i+1] N i utxos[i+1]_len

                swap 6 pop 1
                // _ *utxos[i+1]_len *sender_randomnesses *receiver_digests *canonical_commitments[i+1] N i

                push 1 add
                // _ *utxos[i+1]_len *sender_randomnesses *receiver_digests *canonical_commitments[i+1] N (i+1)

                recurse

        };

        let dependencies = library.all_imports();

        triton_asm!(
            {&tasm}
            {&dependencies}
        )
    }
}

#[cfg(test)]
mod test {
    use crate::models::blockchain::shared::Hash;
    use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
    use crate::models::blockchain::transaction::validity::kernel_to_outputs::KernelToOutputs;
    use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
    use crate::models::proof_abstractions::SecretWitness;
    use proptest::arbitrary::Arbitrary;
    use proptest::prop_assert;
    use proptest::strategy::Strategy;
    use proptest::test_runner::TestRunner;
    use tasm_lib::triton_vm::prelude::BFieldCodec;
    use tasm_lib::twenty_first::prelude::AlgebraicHasher;
    use test_strategy::proptest;

    use super::KernelToOutputsWitness;

    #[proptest(cases = 5)]
    fn derived_witness_generates_accepting_program_proptest(
        #[strategy(PrimitiveWitness::arbitrary_with((2,2,2)))] primitive_witness: PrimitiveWitness,
    ) {
        let kernel_to_outputs_witness = KernelToOutputsWitness::from(&primitive_witness);
        let result = KernelToOutputs.run_rust(
            &kernel_to_outputs_witness.standard_input(),
            kernel_to_outputs_witness.nondeterminism(),
        );
        prop_assert!(result.is_ok());
    }

    #[test]
    fn derived_witness_generates_accepting_tasm_program_unittest() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = PrimitiveWitness::arbitrary_with((2, 2, 2))
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let kernel_to_outputs_witness = KernelToOutputsWitness::from(&primitive_witness);
        let result = KernelToOutputs
            .run_tasm(
                &kernel_to_outputs_witness.standard_input(),
                kernel_to_outputs_witness.nondeterminism(),
            )
            .unwrap();

        assert_eq!(
            Hash::hash_varlen(&primitive_witness.output_utxos.encode())
                .values()
                .to_vec(),
            result
        );
    }
}
