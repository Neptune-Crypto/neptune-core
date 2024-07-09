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
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::hashing::eq_digest::EqDigest;
use tasm_lib::library::Library;
use tasm_lib::memory::{encode_to_memory, FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS};
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::instruction::LabelledInstruction;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::triton_vm::triton_asm;
use tasm_lib::twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use tasm_lib::{field, field_with_size, Digest, DIGEST_LENGTH};
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

        // iterate over all input UTXOs and output the lock script hashes
        let mut i = 0;
        while i < input_utxos.len() {
            tasmlib::tasm_io_write_to_stdout___digest(input_utxos[i].lock_script_hash);
            i += 1;
        }
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        let mut library = Library::new();
        // let field_salted_input_utxos = field!(CollectLockScriptsWitness::salted_input_utxos);
        let field_with_size_salted_input_utxos =
            field_with_size!(CollectLockScriptsWitness::salted_input_utxos);
        let field_utxos = field!(SaltedUtxos::utxos);
        let field_lock_script_hash = field!(Utxo::lock_script_hash);
        let hash_varlen = library.import(Box::new(HashVarlen));
        let eq_digest = library.import(Box::new(EqDigest));
        let write_all_lock_script_digests = format!(
            "neptune_consensus_transaction_collect_lock_scripts_write_all_lock_script_digests"
        );
        let payload = triton_asm! {

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            // _ *clsw

            {&field_with_size_salted_input_utxos}
            // _ *salted_input_utxos size

            dup 1 swap 1
            // _ *salted_input_utxos *salted_input_utxos size

            call {hash_varlen}
            // _ *salted_input_utxos [salted_input_utxos_hash]

            read_io 5
            // _ *salted_input_utxos [salted_input_utxos_hash] [siud]

            call {eq_digest} assert
            // _ *salted_input_utxos

            {&field_utxos}
            // _ *utxos_li

            read_mem 1 push 2 add
            // _ N *utxos[0]_si

            push 0 swap 1
            // _ N 0 *utxos[0]_si

            call {write_all_lock_script_digests}
            // _ N N *

            halt

            // INVARIANT: _ N i *utxos[i]_si
            {write_all_lock_script_digests}:
                dup 2 dup 2 eq
                // _ N i *utxos[i]_si (N==i)

                skiz return
                // _ N i *utxos[i]_si

                dup 0 push 1 add {&field_lock_script_hash}
                // _ N i *utxos[i]_si *lock_script_hash

                push {DIGEST_LENGTH-1} add read_mem {DIGEST_LENGTH} pop 1
                // _ N i *utxos[i]_si [lock_script_hash]

                write_io 5
                // _ N i *utxos[i]_si

                read_mem 1 push 2 add
                // _ N i size *utxos[i]

                add
                // _ N i *utxos[i+1]_si

                swap 1 push 1 add swap 1
                // _ N (i+1) *utxos[i+1]_si

                recurse


        };
        triton_asm! {
            {&payload}
            {&library.all_imports()}
        }
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
    use proptest::arbitrary::Arbitrary;
    use proptest::prop_assert_eq;
    use proptest::strategy::Strategy;
    use proptest::test_runner::TestCaseError;
    use proptest::test_runner::TestRunner;
    use test_strategy::proptest;

    fn prop(primitive_witness: PrimitiveWitness) -> std::result::Result<(), TestCaseError> {
        let collect_lock_scripts_witness = CollectLockScriptsWitness::from(&primitive_witness);
        let expected_lock_script_hashes = collect_lock_scripts_witness
            .salted_input_utxos
            .utxos
            .iter()
            .flat_map(|utxo| utxo.lock_script_hash.values())
            .collect_vec();

        let rust_result = CollectLockScripts
            .run_rust(
                &collect_lock_scripts_witness.standard_input(),
                collect_lock_scripts_witness.nondeterminism(),
            )
            .unwrap();
        prop_assert_eq!(expected_lock_script_hashes, rust_result.clone());

        let tasm_result = CollectLockScripts
            .run_tasm(
                &collect_lock_scripts_witness.standard_input(),
                collect_lock_scripts_witness.nondeterminism(),
            )
            .unwrap();
        prop_assert_eq!(rust_result, tasm_result);

        Ok(())
    }

    #[proptest(cases = 5)]
    fn derived_witness_generates_accepting_program_proptest(
        #[strategy(PrimitiveWitness::arbitrary_with((2,2,2)))] primitive_witness: PrimitiveWitness,
    ) {
        prop(primitive_witness)?;
    }

    #[test]
    fn derived_edge_case_witnesses_generate_accepting_programs_unit() {
        let mut test_runner = TestRunner::deterministic();
        for num_inputs in 0..5 {
            let primitive_witness = PrimitiveWitness::arbitrary_with((num_inputs, 2, 2))
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
            prop(primitive_witness).expect("");
        }
    }
}

#[cfg(test)]
mod bench {
    use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
    use crate::models::proof_abstractions::SecretWitness;
    use crate::tests::shared::bench_consensus_program;
    use proptest::arbitrary::Arbitrary;
    use proptest::strategy::Strategy;
    use proptest::test_runner::TestRunner;
    use tasm_lib::snippet_bencher::BenchmarkCase;

    use super::{CollectLockScripts, CollectLockScriptsWitness};

    #[test]
    fn bench_collect_lock_scripts_common() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = PrimitiveWitness::arbitrary_with((2, 2, 2))
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let collect_lock_scripts_witness = CollectLockScriptsWitness::from(&primitive_witness);
        bench_consensus_program(
            CollectLockScripts,
            &collect_lock_scripts_witness.standard_input(),
            collect_lock_scripts_witness.nondeterminism(),
            "CollectLockScripts",
            BenchmarkCase::CommonCase,
        );
    }
}
