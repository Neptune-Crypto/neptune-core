use std::collections::HashMap;

use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::primitive_witness::{PrimitiveWitness, SaltedUtxos};
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::proof_abstractions::tasm::builtins as tasmlib;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::prelude::{triton_vm, twenty_first};

use crate::models::proof_abstractions::SecretWitness;
use get_size::GetSize;
use serde::{Deserialize, Serialize};
use tasm_lib::memory::{encode_to_memory, FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS};
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::instruction::LabelledInstruction;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use tasm_lib::Digest;
use triton_vm::prelude::NonDeterminism;
use triton_vm::prelude::PublicInput;
use twenty_first::math::bfield_codec::BFieldCodec;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec, TasmObject)]
pub struct CollectLockScriptsWitness {
    salted_input_utxos: SaltedUtxos,
}

impl SecretWitness for CollectLockScriptsWitness {
    fn nondeterminism(&self) -> NonDeterminism {
        // set memory
        let mut memory = HashMap::default();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self.clone(),
        );

        NonDeterminism::default().with_ram(memory)
    }

    fn standard_input(&self) -> PublicInput {
        PublicInput::new(
            Hash::hash(&self.salted_input_utxos)
                .reversed()
                .values()
                .to_vec(),
        )
    }

    fn program(&self) -> triton_vm::prelude::Program {
        CollectLockScripts.program()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct CollectLockScripts;

impl ConsensusProgram for CollectLockScripts {
    fn source(&self) {
        let siu_digest: Digest = tasmlib::tasm_io_read_stdin___digest();
        let start_address: BFieldElement = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
        let clsw: CollectLockScriptsWitness = tasmlib::decode_from_memory(start_address);

        // divine in the salted input UTXOs with hash
        let salted_input_utxos: &SaltedUtxos = &clsw.salted_input_utxos;
        let input_utxos: &Vec<Utxo> = &salted_input_utxos.utxos;

        // verify that the divined data matches with the explicit input digest
        let salted_input_utxos_hash: Digest = Hash::hash(salted_input_utxos);
        assert_eq!(siu_digest, salted_input_utxos_hash);

        // iterate over all input UTXOs and collect the lock script hashes
        let mut lock_script_hashes: Vec<Digest> = Vec::with_capacity(input_utxos.len());
        let mut i = 0;
        while i < input_utxos.len() {
            lock_script_hashes.push(input_utxos[i].lock_script_hash);
            i += 1;
        }

        // output all lock script hashes
        i = 0;
        while i < input_utxos.len() {
            tasmlib::tasm_io_write_to_stdout___digest(lock_script_hashes[i]);
            i += 1;
        }
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        todo!()
    }
}

impl From<&PrimitiveWitness> for CollectLockScriptsWitness {
    fn from(primitive_witness: &PrimitiveWitness) -> Self {
        Self {
            salted_input_utxos: primitive_witness.input_utxos.clone(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
    use crate::models::blockchain::transaction::validity::collect_lock_scripts::CollectLockScripts;
    use crate::models::blockchain::transaction::validity::collect_lock_scripts::CollectLockScriptsWitness;
    use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
    use crate::models::proof_abstractions::SecretWitness;
    use itertools::Itertools;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use test_strategy::proptest;

    #[proptest(cases = 5)]
    fn derived_witness_generates_accepting_program_proptest(
        #[strategy(PrimitiveWitness::arbitrary_with((2,2,2)))] primitive_witness: PrimitiveWitness,
    ) {
        let collect_lock_scripts_witness = CollectLockScriptsWitness::from(&primitive_witness);
        let result = CollectLockScripts.run_rust(
            &collect_lock_scripts_witness.standard_input(),
            collect_lock_scripts_witness.nondeterminism(),
        );
        prop_assert!(result.is_ok());
        prop_assert_eq!(
            result.unwrap().clone(),
            collect_lock_scripts_witness
                .salted_input_utxos
                .utxos
                .into_iter()
                .flat_map(|utxo| utxo.lock_script_hash.values())
                .collect_vec()
        );
    }
}
