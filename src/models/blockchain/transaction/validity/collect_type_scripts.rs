use std::collections::HashMap;

use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::primitive_witness::{PrimitiveWitness, SaltedUtxos};
use crate::models::blockchain::transaction::utxo::{Coin, Utxo};
use crate::models::proof_abstractions::tasm::builtins as tasmlib;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::prelude::{triton_vm, twenty_first};

use crate::models::proof_abstractions::SecretWitness;
use get_size::GetSize;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tasm_lib::data_type::DataType;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::hashing::eq_digest::EqDigest;
use tasm_lib::library::Library;
use tasm_lib::list::contains::Contains;
use tasm_lib::list::new::New;
use tasm_lib::list::push::Push;
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
pub struct CollectTypeScriptsWitness {
    salted_input_utxos: SaltedUtxos,
    salted_output_utxos: SaltedUtxos,
}

impl SecretWitness for CollectTypeScriptsWitness {
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
            [
                Hash::hash(&self.salted_input_utxos)
                    .reversed()
                    .values()
                    .to_vec(),
                Hash::hash(&self.salted_output_utxos)
                    .reversed()
                    .values()
                    .to_vec(),
            ]
            .concat(),
        )
    }

    fn program(&self) -> triton_vm::prelude::Program {
        CollectTypeScripts.program()
    }

    fn output(&self) -> Vec<BFieldElement> {
        self.salted_input_utxos
            .utxos
            .iter()
            .chain(self.salted_output_utxos.utxos.iter())
            .flat_map(|utxo| utxo.coins.iter().map(|c| c.type_script_hash).collect_vec())
            .unique()
            .flat_map(|d| d.values())
            .collect_vec()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct CollectTypeScripts;

impl ConsensusProgram for CollectTypeScripts {
    fn source(&self) {
        let siu_digest: Digest = tasmlib::tasm_io_read_stdin___digest();
        let sou_digest: Digest = tasmlib::tasm_io_read_stdin___digest();
        let start_address: BFieldElement = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
        let ctsw: CollectTypeScriptsWitness = tasmlib::decode_from_memory(start_address);

        // divine in the salted input UTXOs with hash
        let salted_input_utxos: &SaltedUtxos = &ctsw.salted_input_utxos;
        let input_utxos: &Vec<Utxo> = &salted_input_utxos.utxos;

        // verify that the divined data matches with the explicit input digest
        let salted_input_utxos_hash: Digest = Hash::hash(salted_input_utxos);
        assert_eq!(siu_digest, salted_input_utxos_hash);

        // divine in the salted output UTXOs with hash
        let salted_output_utxos: &SaltedUtxos = &ctsw.salted_output_utxos;
        let output_utxos: &Vec<Utxo> = &salted_output_utxos.utxos;

        // verify that the divined data matches with the explicit input digest
        let salted_output_utxos_hash: Digest = Hash::hash(salted_output_utxos);
        assert_eq!(sou_digest, salted_output_utxos_hash);

        // iterate over all input UTXOs and collect the type script hashes
        let mut type_script_hashes: Vec<Digest> = Vec::with_capacity(input_utxos.len());
        let mut i = 0;
        while i < input_utxos.len() {
            let utxo: &Utxo = &input_utxos[i];

            let mut j = 0;
            while j < utxo.coins.len() {
                let coin: &Coin = &utxo.coins[j];
                if !type_script_hashes.contains(&coin.type_script_hash) {
                    type_script_hashes.push(coin.type_script_hash);
                }
                j += 1;
            }

            i += 1;
        }

        // iterate over all output UTXOs and collect the type script hashes
        i = 0;
        while i < output_utxos.len() {
            let utxo: &Utxo = &output_utxos[i];

            let mut j = 0;
            while j < utxo.coins.len() {
                let coin: &Coin = &utxo.coins[j];
                if !type_script_hashes.contains(&coin.type_script_hash) {
                    type_script_hashes.push(coin.type_script_hash);
                }
                j += 1;
            }

            i += 1;
        }

        // output all type script hashes
        i = 0;
        while i < type_script_hashes.len() {
            tasmlib::tasm_io_write_to_stdout___digest(type_script_hashes[i]);
            i += 1;
        }
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        let mut library = Library::new();
        let field_with_size_salted_input_utxos =
            field_with_size!(CollectTypeScriptsWitness::salted_input_utxos);
        let field_with_size_salted_output_utxos =
            field_with_size!(CollectTypeScriptsWitness::salted_output_utxos);
        let field_utxos = field!(SaltedUtxos::utxos);
        let field_coin = field!(Utxo::coins);
        let field_type_script_hash = field!(Coin::type_script_hash);
        let contains = library.import(Box::new(Contains {
            element_type: DataType::Digest,
        }));
        let new_list = library.import(Box::new(New {
            element_type: DataType::Digest,
        }));
        let push_digest = library.import(Box::new(Push {
            element_type: DataType::Digest,
        }));
        let hash_varlen = library.import(Box::new(HashVarlen));
        let eq_digest = library.import(Box::new(EqDigest));
        let collect_type_script_hashes_from_utxos =
            format!("neptune_consensus_transaction_collect_type_script_hashes_from_utxo");
        let collect_type_script_hashes_from_coins =
            format!("neptune_consensus_transaction_collect_type_script_hashes_from_coin");
        let push_digest_to_list = format!("neptune_consensus_transaction_push_digest_to_list");
        let write_all_digests = format!("netpune_consensus_transaction_write_all_digests");
        let authenticate_salted_utxos_and_collect_hashes = triton_asm! {
            // BEFORE:
            // _ *ctsw *type_script_hashes *salted_utxos size

            dup 1 swap 1
            // _ *ctsw *type_script_hashes *salted_utxos *salted_utxos size

            call {hash_varlen}
            // _ *ctsw *type_script_hashes *salted_utxos [salted_utxos_hash]

            read_io 5
            // _ *ctsw *type_script_hashes *salted_utxos [salted_utxos_hash] [sud]

            call {eq_digest} assert
            // _ *ctsw *type_script_hashes *salted_utxos

            {&field_utxos}
            // _ *ctsw *type_script_hashes *utxos_li

            read_mem 1 push 2 add
            // _ *ctsw *type_script_hashes N *utxos[0]_si

            push 0 swap 1
            // _ *ctsw *type_script_hashes N 0 *utxos[0]_si

            call {collect_type_script_hashes_from_utxos}
            // _ *ctsw *type_script_hashes N N *

            pop 3
            // _ *ctsw *type_script_hashes
        };
        let payload = triton_asm! {

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            // _ *ctsw

            call {new_list}
            // _ *ctsw *type_script_hashes

            dup 1 {&field_with_size_salted_input_utxos}
            // _ *ctsw *type_script_hashes *salted_input_utxos size

            {&authenticate_salted_utxos_and_collect_hashes}
            // _ *ctsw *type_script_hashes

            dup 1 {&field_with_size_salted_output_utxos}
            // _ *ctsw *type_script_hashes *salted_output_utxos size

            {&authenticate_salted_utxos_and_collect_hashes}
            // _ *ctsw *type_script_hashes

            read_mem 1 push 2 add swap 1
            // _ *ctsw *type_script_hashes[0] len

            push {DIGEST_LENGTH} mul
            // _ *ctsw *type_script_hashes[0] size

            dup 1 add
            // _ *ctsw *type_script_hashes[0] *type_script_hashes[N+1]

            call {write_all_digests}
            // _ *ctsw *type_script_hashes[N+1] *type_script_hashes[N+1]

            halt

            // INVARIANT: _ *type_script_hashes N i *utxos[i]_si
            {collect_type_script_hashes_from_utxos}:
                dup 2 dup 2 eq
                // _ *type_script_hashes N i *utxos[i]_si (N==i)

                skiz return
                // _ *type_script_hashes N i *utxos[i]_si

                dup 0 push 1 add {&field_coin}
                // _ *type_script_hashes N i *utxos[i]_si *coin

                read_mem 1 push 2 add
                // _ *type_script_hashes N i *utxos[i]_si len *coin[0]_si

                push 0 swap 1
                // _ *type_script_hashes N i *utxos[i]_si len 0 *coin[0]_si

                call {collect_type_script_hashes_from_coins}
                // _ *type_script_hashes N i *utxos[i]_si len len *coin[len]_si

                pop 3
                // _ *type_script_hashes N i *utxos[i]_si

                read_mem 1 push 2 add
                // _ *type_script_hashes N i size *utxos[i]

                add
                // _ *type_script_hashes N i *utxos[i+1]_si

                swap 1 push 1 add swap 1
                // _ *type_script_hashes N (i+1) *utxos[i+1]_si

                recurse

            // INVARIANT: _ *type_script_hashes * * * len j *coin[j]_si
            {collect_type_script_hashes_from_coins}:
                dup 2 dup 2 eq
                // _ *type_script_hashes * * * len j *coin[j]_si (len==j)

                skiz return
                // _ *type_script_hashes * * * len j *coin[j]_si

                read_mem 1 push 2 add
                // _ *type_script_hashes * * * len j size *coin[j]

                dup 7 dup 0 dup 2 {&field_type_script_hash}
                // _ *type_script_hashes * * * len j size *coin[j] *type_script_hashes *type_script_hashes *digest

                push {DIGEST_LENGTH-1} add read_mem {DIGEST_LENGTH} pop 1
                // _ *type_script_hashes * * * len j size *coin[j] *type_script_hashes *type_script_hashes [digest]

                call {contains}
                // _ *type_script_hashes * * * len j size *coin[j] *type_script_hashes ([digest] in type_script_hashes)

                push 0 eq
                // _ *type_script_hashes * * * len j size *coin[j] *type_script_hashes ([digest] not in type_script_hashes)

                skiz call {push_digest_to_list}
                // _ *type_script_hashes * * * len j size *coin[j] *

                pop 1 add
                // _ *type_script_hashes * * * len j *coin[j+1]_si

                swap 1 push 1 add swap 1
                // _ *type_script_hashes * * * len (j+1) *coin[j+1]_si

                recurse

            // BEFORE: _ *coin[j] *type_script_hashes
            // AFTER: _ *coin[j] *
            {push_digest_to_list}:
                dup 1
                // _ *coin[j] *type_script_hashes *coin[j]

                {&field_type_script_hash}
                // _ *coin[j] *type_script_hashes *digest

                push {DIGEST_LENGTH-1} add read_mem {DIGEST_LENGTH} pop 1
                // _ *coin[j] *type_script_hashes [digest]

                call {push_digest}
                // _ *coin[j]

                push {0x2b00b5}

                return

            // INVARIANT: _ *type_script_hashes[i] *type_script_hashes[N+1]
            {write_all_digests}:

                dup 1 dup 1 eq
                // _ *type_script_hashes[i] *type_script_hashes[N+1] (i==N+1)

                skiz return
                // _ *type_script_hashes[i] *type_script_hashes[N+1]

                dup 1 push {DIGEST_LENGTH-1} add read_mem {DIGEST_LENGTH}
                // _ *type_script_hashes[i] *type_script_hashes[N+1] [type_script_hashes[i]] (*type_script_hashes[i]-1)

                push {DIGEST_LENGTH+1} add swap 7 pop 1
                // _ *type_script_hashes[i+1] *type_script_hashes[N+1] [type_script_hashes[i]]

                write_io 5
                // _ *type_script_hashes[i+1] *type_script_hashes[N+1]

                recurse

        };
        triton_asm! {
            {&payload}
            {&library.all_imports()}
        }
    }
}

impl From<&PrimitiveWitness> for CollectTypeScriptsWitness {
    fn from(primitive_witness: &PrimitiveWitness) -> Self {
        Self {
            salted_input_utxos: primitive_witness.input_utxos.clone(),
            salted_output_utxos: primitive_witness.output_utxos.clone(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
    use crate::models::blockchain::transaction::validity::collect_type_scripts::CollectTypeScripts;
    use crate::models::blockchain::transaction::validity::collect_type_scripts::CollectTypeScriptsWitness;
    use crate::models::blockchain::type_scripts::time_lock::arbitrary_primitive_witness_with_timelocks;
    use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
    use crate::models::proof_abstractions::SecretWitness;
    use proptest::arbitrary::Arbitrary;
    use proptest::prop_assert_eq;
    use proptest::strategy::Strategy;
    use proptest::test_runner::TestCaseError;
    use proptest::test_runner::TestRunner;
    use test_strategy::proptest;

    fn prop(primitive_witness: PrimitiveWitness) -> std::result::Result<(), TestCaseError> {
        let collect_type_scripts_witness = CollectTypeScriptsWitness::from(&primitive_witness);

        let expected_output = collect_type_scripts_witness.output();

        let rust_result = CollectTypeScripts
            .run_rust(
                &collect_type_scripts_witness.standard_input(),
                collect_type_scripts_witness.nondeterminism(),
            )
            .unwrap();
        prop_assert_eq!(expected_output, rust_result.clone());

        let tasm_result = CollectTypeScripts
            .run_tasm(
                &collect_type_scripts_witness.standard_input(),
                collect_type_scripts_witness.nondeterminism(),
            )
            .unwrap();
        prop_assert_eq!(rust_result, tasm_result);

        Ok(())
    }

    #[proptest(cases = 8)]
    fn derived_witness_generates_accepting_program_proptest(
        #[strategy(0usize..5)] _num_outputs: usize,
        #[strategy(0usize..5)] _num_inputs: usize,
        #[strategy(PrimitiveWitness::arbitrary_with((#_num_inputs,#_num_outputs,2)))]
        primitive_witness: PrimitiveWitness,
    ) {
        prop(primitive_witness)?;
    }

    #[proptest(cases = 8)]
    fn derived_witness_with_timelocks_generates_accepting_program_proptest(
        #[strategy(0usize..5)] _num_outputs: usize,
        #[strategy(0usize..5)] _num_inputs: usize,
        #[strategy(arbitrary_primitive_witness_with_timelocks(#_num_inputs,#_num_outputs,2))]
        primitive_witness: PrimitiveWitness,
    ) {
        prop(primitive_witness)?;
    }

    #[test]
    fn derived_edge_case_witnesses_generate_accepting_programs_unit() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = PrimitiveWitness::arbitrary_with((0, 0, 2))
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        prop(primitive_witness).expect("");
    }

    #[test]
    fn derived_edge_case_witnesses_with_timelock_generate_accepting_programs_unit() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = arbitrary_primitive_witness_with_timelocks(1, 1, 2)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        prop(primitive_witness).expect("");
    }
}