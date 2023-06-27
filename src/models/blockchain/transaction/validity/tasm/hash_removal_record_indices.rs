use tasm_lib::{
    hashing::hash_varlen::HashVarlen,
    snippet::{DataType, Snippet},
    structure::get_field::GetField,
    ExecutionState,
};
use twenty_first::{
    shared_math::bfield_codec::BFieldCodec, util_types::algebraic_hasher::AlgebraicHasher,
};

use crate::{
    models::blockchain::shared::Hash, util_types::mutator_set::removal_record::RemovalRecord,
};

pub struct HashRemovalRecordIndices;

impl HashRemovalRecordIndices {
    #[cfg(test)]
    fn pseudorandom_init_state(seed: [u8; 32]) -> ExecutionState {
        use std::collections::HashMap;

        use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
        use tasm_lib::get_init_tvm_stack;
        use triton_vm::BFieldElement;

        use crate::util_types::test_shared::mutator_set::pseudorandom_removal_record;

        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let removal_record = pseudorandom_removal_record::<Hash>(rng.gen());
        let address: BFieldElement = BFieldElement::new(rng.next_u64() % (1u64 << 20));

        let mut memory: HashMap<BFieldElement, BFieldElement> = HashMap::new();
        for (i, v) in removal_record.encode().iter().enumerate() {
            memory.insert(address + BFieldElement::new(i as u64), *v);
        }

        let mut stack = get_init_tvm_stack();
        stack.push(address);

        ExecutionState {
            stack,
            std_in: vec![],
            secret_in: vec![],
            memory,
            words_allocated: 1,
        }
    }
}

impl Snippet for HashRemovalRecordIndices {
    fn entrypoint(&self) -> String {
        "tasm_neptune_transaction_hash_removal_record_indices".to_string()
    }

    fn inputs(&self) -> Vec<String> {
        vec!["*removal_record".to_string()]
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
        let get_field = library.import(Box::new(GetField));
        let hash_varlen = library.import(Box::new(HashVarlen));
        let entrypoint = self.entrypoint();

        format!(
            "
        // BEFORE: _ *removal_record
        // AFTER: _ [digest]
        {entrypoint}:
            push 0 // _ *removal_record 0 (= field absolute_index_set)
            call {get_field} // _ *ais_si
            read_mem // _ *ais_si size
            swap 1 push 1 add swap 1 // _ *ais_si+1 size
            call {hash_varlen}
            return"
        )
    }

    fn crash_conditions(&self) -> Vec<String> {
        vec![]
    }

    fn gen_input_states(&self) -> Vec<ExecutionState> {
        #[cfg(test)]
        {
            let mut rng = rand::thread_rng();
            vec![
                Self::pseudorandom_init_state(rand::Rng::gen(&mut rng)),
                Self::pseudorandom_init_state(rand::Rng::gen(&mut rng)),
                Self::pseudorandom_init_state(rand::Rng::gen(&mut rng)),
            ]
        }
        #[cfg(not(test))]
        {
            unimplemented!("Cannot generate input states when not in test environment.")
        }
    }

    fn common_case_input_state(&self) -> tasm_lib::ExecutionState {
        #[cfg(test)]
        {
            let mut seed = [0u8; 32];
            seed[0] = 0x41;
            seed[1] = 0x55;
            Self::pseudorandom_init_state(seed)
        }
        #[cfg(not(test))]
        {
            unimplemented!("Cannot generate input states when not in test environment.")
        }
    }

    fn worst_case_input_state(&self) -> tasm_lib::ExecutionState {
        #[cfg(test)]
        {
            let mut seed = [0u8; 32];
            seed[0] = 0x47;
            seed[1] = 0xf5;
            Self::pseudorandom_init_state(seed)
        }
        #[cfg(not(test))]
        {
            unimplemented!("Cannot generate input states when not in test environment.")
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
        let mut address = stack.pop().unwrap();

        // read object
        let mut encoding = vec![];
        encoding.push(*memory.get(&address).unwrap());
        address.increment();
        let size_field_0 = encoding.last().unwrap().value() as usize;
        for _ in 0..size_field_0 {
            encoding.push(*memory.get(&address).unwrap());
            address.increment();
        }
        encoding.push(*memory.get(&address).unwrap());
        address.increment();
        let size_field_1 = encoding.last().unwrap().value() as usize;
        for _ in 0..size_field_1 {
            encoding.push(*memory.get(&address).unwrap());
            address.increment();
        }
        let removal_record = *RemovalRecord::<Hash>::decode(&encoding).unwrap();

        // hash absolute index set
        let digest = Hash::hash(&removal_record.absolute_indices);

        // write hash to stack
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
        test_rust_equivalence_multiple(&HashRemovalRecordIndices, false);
    }
}

#[cfg(test)]
mod benches {
    use tasm_lib::snippet_bencher::bench_and_write;

    use super::*;

    #[test]
    fn hash_removal_record_indices_benchmark() {
        bench_and_write(HashRemovalRecordIndices)
    }
}
