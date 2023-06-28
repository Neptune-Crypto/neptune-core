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
            // size is 181
            // push -1 add // _ *ais_si size-1
            swap 1 push 1 add swap 1 // _ *ais size-1
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
        let digest = Hash::hash_varlen(&removal_record.absolute_indices.encode()[0..]);

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
    use std::collections::HashMap;

    use itertools::Itertools;
    use num_traits::Zero;
    use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
    use tasm_lib::{
        get_init_tvm_stack,
        list::{
            contiguous_list::get_pointer_list::GetPointerList,
            higher_order::{inner_function::InnerFunction, map::Map},
            ListType,
        },
        rust_shadowing_helper_functions,
        test_helpers::test_rust_equivalence_multiple,
    };
    use triton_vm::{BFieldElement, Digest};
    use twenty_first::shared_math::tip5::DIGEST_LENGTH;

    use crate::util_types::test_shared::mutator_set::pseudorandom_removal_record;

    use super::*;

    #[test]
    fn new_prop_test() {
        test_rust_equivalence_multiple(&HashRemovalRecordIndices, false);
    }

    #[test]
    fn test_map_hash_removal_record_indices() {
        let mut seed = [0u8; 32];
        seed[0] = 0x54;
        seed[1] = 0x10;
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        // generate removal records list
        let num_removal_records = 2;
        let removal_records = (0..num_removal_records)
            .map(|_| pseudorandom_removal_record::<Hash>(rng.gen()))
            .collect_vec();
        let address = BFieldElement::new(rng.next_u64() % (1 << 20));

        // compute digests
        let rust_digests = removal_records
            .iter()
            .map(|rr| Hash::hash_varlen(&rr.absolute_indices.encode()[1..]))
            .collect_vec();
        println!(
            "length of encoding of one absolute index set: {}",
            removal_records[0].absolute_indices.encode().len()
        );
        println!(
            "rr.absolute_indices.encode()[1..]: {}",
            removal_records[0].absolute_indices.encode()[1..]
                .iter()
                .join(",")
        );

        // populate memory
        let mut memory: HashMap<BFieldElement, BFieldElement> = HashMap::new();
        let removal_records_encoded = removal_records.encode();
        for (i, v) in removal_records_encoded.iter().enumerate() {
            memory.insert(address + BFieldElement::new(i as u64), *v);
        }
        // first element of object is number of elements, not size
        // memory.insert(address, BFieldElement::new(removal_records.len() as u64));
        // dynamic allocator points to first free address, but this gets overwritten anyway
        memory.insert(
            BFieldElement::zero(),
            address + BFieldElement::new(removal_records_encoded.len() as u64),
        );

        // populate stack
        let mut stack = get_init_tvm_stack();
        stack.push(address);
        // STACK: 0^16 *removal_record_list_encoding_address

        // transform contiguous list to list of pointers
        let allocated = address.value() as usize + removal_records_encoded.len();
        let get_pointer_list = GetPointerList {
            output_list_type: ListType::Unsafe,
        };
        let vm_output = get_pointer_list.link_and_run_tasm_for_test(
            &mut stack,
            vec![],
            vec![],
            &mut memory,
            allocated,
        );

        let new_dyn_malloc_value = memory[&BFieldElement::zero()].value() as usize;

        // STACK: 0^16 *[*removal_record]

        // read list of pointers from memory
        let pointers_list_address = *stack.last().unwrap();

        let num_pointers = memory.get(&pointers_list_address).unwrap().value() as usize;
        let mut pointers_list = vec![];
        for i in 0..num_pointers {
            pointers_list.push(
                *memory
                    .get(&(pointers_list_address + BFieldElement::new(1 + i as u64)))
                    .unwrap(),
            );
        }

        // read removal records from memory through list of pointers
        let mut read_removal_records = vec![];
        for pointer in pointers_list {
            let size = memory.get(&pointer).unwrap().value() as usize;
            let mut removal_record_encoding = vec![];
            for i in 0..size {
                removal_record_encoding.push(
                    *memory
                        .get(&(pointer + BFieldElement::new(1 + i as u64)))
                        .unwrap(),
                );
            }
            read_removal_records
                .push(*RemovalRecord::<Hash>::decode(&removal_record_encoding).unwrap());
        }

        // assert equality of removal records lists
        assert_eq!(removal_records, read_removal_records);

        // assert length of list
        assert_eq!(
            memory.get(stack.last().unwrap()).unwrap().clone().value() as usize,
            num_removal_records
        );

        // run map snippet
        let map_hash_removal_record_indices = Map {
            list_type: ListType::Unsafe,
            f: InnerFunction::Snippet(Box::new(HashRemovalRecordIndices)),
        };
        println!("stack before 2nd run: {}", stack.iter().join(","));
        let _vm_output_state = map_hash_removal_record_indices.link_and_run_tasm_for_test(
            &mut stack,
            vec![],
            vec![],
            &mut memory,
            new_dyn_malloc_value,
        );
        println!("stack after 2nd run: {}", stack.iter().join(","));
        let new_dyn_malloc_value2 = memory[&BFieldElement::zero()].value() as usize;
        println!("new dyn malloc value: {}", new_dyn_malloc_value2);
        // STACK: 0^16 *[digest]

        // inspect memory
        let output_address = stack.pop().unwrap();
        let length: usize = memory.get(&output_address).unwrap().value() as usize;
        assert_eq!(length, num_removal_records);
        // output_address.increment();
        let mut tasm_digests = vec![];
        for i in 0..length {
            // let mut values = vec![];
            let values = rust_shadowing_helper_functions::unsafe_list::unsafe_list_get(
                output_address,
                i,
                &memory,
                DIGEST_LENGTH,
            );
            tasm_digests.push(Digest::new(values.try_into().unwrap()));
        }

        // assert equality of digest lists
        assert_eq!(
            rust_digests,
            tasm_digests,
            "\nrust digests: ({})\ntasm digests: ({})",
            rust_digests
                .iter()
                .map(|d| d.values().iter().join(","))
                .join(")-("),
            tasm_digests
                .iter()
                .map(|d| d.values().iter().join(","))
                .join(")-("),
        )
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
