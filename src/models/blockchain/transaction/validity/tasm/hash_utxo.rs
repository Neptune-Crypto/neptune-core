use rand::{thread_rng, Rng};
use tasm_lib::{
    hashing::hash_varlen::HashVarlen,
    snippet::{DataType, Snippet},
    ExecutionState,
};
use triton_vm::BFieldElement;
use twenty_first::{
    shared_math::bfield_codec::BFieldCodec, util_types::algebraic_hasher::AlgebraicHasher,
};

use crate::models::blockchain::{shared::Hash, transaction::utxo::Utxo};

/// HashUtxo takes a VoidPointer to a UTXO living in a contiguous
/// list, and hashes it.
pub struct HashUtxo;

impl HashUtxo {
    fn pseudorandom_input_state(_seed: [u8; 32]) -> ExecutionState {
        #[cfg(test)]
        {
            let mut rng: rand::rngs::StdRng = rand::SeedableRng::from_seed(_seed);
            let utxo = crate::tests::shared::pseudorandom_utxo(_seed);
            let address =
                triton_vm::BFieldElement::new(rand::RngCore::next_u64(&mut rng) % (1 << 20));
            let mut stack = tasm_lib::get_init_tvm_stack();
            stack.push(address);
            let mut memory: std::collections::HashMap<
                triton_vm::BFieldElement,
                triton_vm::BFieldElement,
            > = std::collections::HashMap::new();
            let encoded_utxo = twenty_first::shared_math::bfield_codec::BFieldCodec::encode(&utxo);
            memory.insert(
                address - BFieldElement::new(1),
                triton_vm::BFieldElement::new(encoded_utxo.len() as u64),
            );
            for (i, v) in encoded_utxo.iter().enumerate() {
                memory.insert(
                    address + triton_vm::BFieldElement::new(i as u64),
                    v.to_owned(),
                );
            }
            ExecutionState {
                stack,
                std_in: vec![],
                secret_in: vec![],
                memory,
                words_allocated: 1,
            }
        }
        #[cfg(not(test))]
        unimplemented!("Cannot generate test input state when not in testing environment")
    }
}

impl Snippet for HashUtxo {
    fn entrypoint(&self) -> String {
        "tasm_neptune_transaction_hash_utxo".to_string()
    }

    fn inputs(&self) -> Vec<String> {
        vec!["*utxo_field_size_indicator".to_string()]
    }

    fn input_types(&self) -> Vec<tasm_lib::snippet::DataType> {
        vec![DataType::VoidPointer]
    }

    fn output_types(&self) -> Vec<tasm_lib::snippet::DataType> {
        vec![DataType::Digest]
    }

    fn outputs(&self) -> Vec<String> {
        vec![
            "d4".to_string(),
            "d3".to_string(),
            "d2".to_string(),
            "d1".to_string(),
            "d0".to_string(),
        ]
    }

    fn stack_diff(&self) -> isize {
        4
    }

    fn function_code(&self, library: &mut tasm_lib::snippet_state::SnippetState) -> String {
        let entrypoint = self.entrypoint();
        let hash_varlen = library.import(Box::new(HashVarlen));

        format!(
            "
        // BEFORE: _ *utxo
        // AFTER: _ [utxo_digest]
        {entrypoint}:
            push -1 add // _ *utxo_si // because it lives in a contiguous list
            read_mem // _ *utxo_si utxo_size
            swap 1 // _ utxo_size *utxo_si
            push 1 add // _ utxo_size *utxo
            swap 1 // _ *utxo utxo_size

            call {hash_varlen}
            return
            "
        )
    }

    fn crash_conditions(&self) -> Vec<String> {
        vec![]
    }

    fn gen_input_states(&self) -> Vec<tasm_lib::ExecutionState> {
        let mut rng = thread_rng();
        vec![
            Self::pseudorandom_input_state(rng.gen()),
            Self::pseudorandom_input_state(rng.gen()),
            Self::pseudorandom_input_state(rng.gen()),
            Self::pseudorandom_input_state(rng.gen()),
        ]
    }

    fn common_case_input_state(&self) -> tasm_lib::ExecutionState {
        let mut seed = [0u8; 32];
        seed[0] = 0xa1;
        seed[1] = 0x4f;
        Self::pseudorandom_input_state(seed)
    }

    fn worst_case_input_state(&self) -> tasm_lib::ExecutionState {
        let mut seed = [0u8; 32];
        seed[0] = 0xb1;
        seed[1] = 0x5f;
        Self::pseudorandom_input_state(seed)
    }

    fn rust_shadowing(
        &self,
        stack: &mut Vec<triton_vm::BFieldElement>,
        _std_in: Vec<triton_vm::BFieldElement>,
        _secret_in: Vec<triton_vm::BFieldElement>,
        memory: &mut std::collections::HashMap<triton_vm::BFieldElement, triton_vm::BFieldElement>,
    ) {
        // read address
        let address = stack.pop().unwrap();

        // read utxo
        let size = memory
            .get(&(address - BFieldElement::new(1)))
            .unwrap()
            .value() as usize;
        let mut utxo_encoded = vec![];
        for i in 0..size {
            utxo_encoded.push(
                memory
                    .get(&(address + BFieldElement::new(i as u64)))
                    .unwrap()
                    .to_owned(),
            );
        }
        let utxo = *Utxo::decode(&utxo_encoded).unwrap();

        // hash utxo
        let hash = Hash::hash(&utxo);

        // put on stack
        for v in hash.reversed().values() {
            stack.push(v);
        }
    }
}

#[cfg(test)]
mod tests {
    use tasm_lib::test_helpers::test_rust_equivalence_multiple;

    use super::*;

    #[test]
    fn new_prop_test() {
        test_rust_equivalence_multiple(&HashUtxo, false);
    }
}

#[cfg(test)]
mod benches {
    use tasm_lib::snippet_bencher::bench_and_write;

    use super::*;

    #[test]
    fn hash_utxo_benchmark() {
        bench_and_write(HashUtxo)
    }
}
