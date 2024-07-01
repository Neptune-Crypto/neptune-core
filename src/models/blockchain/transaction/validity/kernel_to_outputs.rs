use std::collections::HashMap;

use field_count::FieldCount;
use get_size::GetSize;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumCount;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::triton_vm::prelude::Digest;
use tasm_lib::triton_vm::program::NonDeterminism;
use tasm_lib::triton_vm::program::PublicInput;
use tasm_lib::twenty_first::bfieldcodec_derive::BFieldCodec;
use tasm_lib::twenty_first::prelude::AlgebraicHasher;

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
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );

        // output hash of salted output UTXOs
        let salted_output_utxos_hash: Digest = Hash::hash(salted_output_utxos);
        tasmlib::tasm_io_write_to_stdout___digest(salted_output_utxos_hash);
    }

    fn code(&self) -> Vec<tasm_lib::triton_vm::prelude::LabelledInstruction> {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
    use crate::models::blockchain::transaction::validity::kernel_to_outputs::KernelToOutputs;
    use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
    use crate::models::proof_abstractions::SecretWitness;
    use proptest::prop_assert;
    use test_strategy::proptest;

    use super::KernelToOutputsWitness;

    #[proptest(cases = 5)]
    fn derived_witness_generates_accepting_program_proptest(
        #[strategy(PrimitiveWitness::arbitrary_with((2,2,2)))] primitive_witness: PrimitiveWitness,
    ) {
        let kernel_to_outputs_witness = KernelToOutputsWitness::from(&primitive_witness);
        let result = KernelToOutputs.run(
            &kernel_to_outputs_witness.standard_input(),
            kernel_to_outputs_witness.nondeterminism(),
        );
        prop_assert!(result.is_ok());
    }
}
