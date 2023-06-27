use tasm_lib::{
    hashing::hash_varlen::HashVarlen,
    snippet::{DataType, Snippet},
};
use triton_vm::BFieldElement;
use twenty_first::{
    shared_math::bfield_codec::BFieldCodec, util_types::algebraic_hasher::AlgebraicHasher,
};

use crate::models::blockchain::shared::Hash;

pub struct HashIndexSet;

impl HashIndexSet {
    #[cfg(test)]
    fn pseudorandom_init_state(seed: [u8; 32], length: usize) -> tasm_lib::ExecutionState {
        use itertools::Itertools;
        use rand::RngCore;

        let mut rng: rand::rngs::StdRng = rand::SeedableRng::from_seed(seed);
        let mut index_set = Vec::<u128>::with_capacity(length);
        for _ in 0..length {
            index_set.push(
                ((rand::RngCore::next_u64(&mut rng) as u128) << 64)
                    ^ (rand::RngCore::next_u64(&mut rng) as u128),
            );
        }

        let address = BFieldElement::new(rng.next_u64() % (1u64 << 20));

        let mut memory: std::collections::HashMap<BFieldElement, BFieldElement> =
            std::collections::HashMap::new();
        let index_set_encoded =
            twenty_first::shared_math::bfield_codec::BFieldCodec::encode(&index_set);

        for (i, v) in index_set_encoded.iter().enumerate() {
            memory.insert(address + BFieldElement::new(i as u64), *v);
        }

        let mut stack = tasm_lib::get_init_tvm_stack();
        stack.push(address);

        tasm_lib::ExecutionState {
            stack,
            std_in: vec![],
            secret_in: vec![],
            memory,
            words_allocated: 1,
        }
    }
}

impl Snippet for HashIndexSet {
    fn entrypoint(&self) -> String {
        "tasm_neptune_transaction_hash_index_set".to_string()
    }

    fn inputs(&self) -> Vec<String> {
        vec!["*index_set".to_string()]
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
        let hash_varlen = library.import(Box::new(HashVarlen));
        let entrypoint = self.entrypoint();

        format!(
            "
        // BEFORE: _ *index_set
        // AFTER: _ [digest]
        {entrypoint}:
            read_mem // _ *index_set length
            push 4 mul // _ *index_set length*4
            push 1 add // _ *index_set length*4+1

            call {hash_varlen}
            return"
        )
    }

    fn crash_conditions(&self) -> Vec<String> {
        vec![]
    }

    fn gen_input_states(&self) -> Vec<tasm_lib::ExecutionState> {
        #[cfg(test)]
        {
            vec![
                Self::pseudorandom_init_state(rand::Rng::gen(&mut rand::thread_rng()), 0),
                Self::pseudorandom_init_state(rand::Rng::gen(&mut rand::thread_rng()), 5),
                Self::pseudorandom_init_state(rand::Rng::gen(&mut rand::thread_rng()), 10),
                Self::pseudorandom_init_state(rand::Rng::gen(&mut rand::thread_rng()), 45),
            ]
        }
        #[cfg(not(test))]
        {
            unimplemented!("Cannot generate input states when not in testing environment")
        }
    }

    fn common_case_input_state(&self) -> tasm_lib::ExecutionState {
        #[cfg(test)]
        {
            Self::pseudorandom_init_state(rand::Rng::gen(&mut rand::thread_rng()), 45)
        }
        #[cfg(not(test))]
        {
            unimplemented!("Cannot generate input states when not in testing environment")
        }
    }

    fn worst_case_input_state(&self) -> tasm_lib::ExecutionState {
        #[cfg(test)]
        {
            Self::pseudorandom_init_state(rand::Rng::gen(&mut rand::thread_rng()), 45)
        }
        #[cfg(not(test))]
        {
            unimplemented!("Cannot generate input states when not in testing environment")
        }
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

        // read index set
        let mut index_set_encoded = vec![*memory.get(&address).unwrap()];
        for i in 0..(index_set_encoded[0].value() * 4) {
            index_set_encoded.push(
                *memory
                    .get(&(address + BFieldElement::new(1u64 + i)))
                    .unwrap(),
            );
        }

        // decode index set
        let index_set: Vec<u128> = *Vec::<u128>::decode(&index_set_encoded).unwrap();

        // hash index set
        let digest = Hash::hash(&index_set);

        // populate stack
        stack.push(digest.values()[4]);
        stack.push(digest.values()[3]);
        stack.push(digest.values()[2]);
        stack.push(digest.values()[1]);
        stack.push(digest.values()[0]);
    }
}

#[cfg(test)]
mod tests {
    use tasm_lib::test_helpers::test_rust_equivalence_multiple;

    use super::*;

    #[test]
    fn new_prop_test() {
        test_rust_equivalence_multiple(&HashIndexSet, false);
    }
}

#[cfg(test)]
mod benches {
    use tasm_lib::snippet_bencher::bench_and_write;

    use super::*;

    #[test]
    fn hash_index_set_benchmark() {
        bench_and_write(HashIndexSet)
    }
}
