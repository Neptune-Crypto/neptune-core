use tasm_lib::{
    hashing::hash_varlen::HashVarlen,
    snippet::{DataType, Snippet},
};
use triton_vm::BFieldElement;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

use crate::models::blockchain::shared::Hash;

pub struct HashIndexList;

impl HashIndexList {
    #[cfg(test)]
    fn pseudorandom_init_state(seed: [u8; 32], length: usize) -> tasm_lib::ExecutionState {
        use rand::RngCore;

        let mut rng: rand::rngs::StdRng = rand::SeedableRng::from_seed(seed);
        let mut index_list = Vec::<u128>::with_capacity(length);
        for _ in 0..length {
            index_list.push(
                ((rand::RngCore::next_u64(&mut rng) as u128) << 64)
                    ^ (rand::RngCore::next_u64(&mut rng) as u128),
            );
        }

        let address = BFieldElement::new(rng.next_u64() % (1u64 << 20));

        let mut memory: std::collections::HashMap<BFieldElement, BFieldElement> =
            std::collections::HashMap::new();
        let index_list_encoded =
            twenty_first::shared_math::bfield_codec::BFieldCodec::encode(&index_list);

        for (i, v) in index_list_encoded.iter().enumerate() {
            memory.insert(address + BFieldElement::new(i as u64), *v);
        }
        memory.insert(address, BFieldElement::new(length as u64));

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

impl Snippet for HashIndexList {
    fn entrypoint(&self) -> String {
        "tasm_neptune_transaction_hash_index_list".to_string()
    }

    fn inputs(&self) -> Vec<String> {
        vec!["*index_list".to_string()]
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
        // BEFORE: _ *index_list
        // AFTER: _ [digest]
        {entrypoint}:

            read_mem // _ *index_list length
            push 4 mul // _ *index_list size

            swap 1 // _ size *index_list 
            push 1 // _ size *index_list 1
            add    // _ size *index_list+1
            swap 1 // _ *index_list+1 size

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
        let mut index_list_encoded = vec![*memory.get(&address).unwrap()];
        for i in 0..(index_list_encoded[0].value() * 4) {
            index_list_encoded.push(
                *memory
                    .get(&(address + BFieldElement::new(1u64 + i)))
                    .unwrap(),
            );
        }

        // hash index set
        let digest = Hash::hash_varlen(&index_list_encoded[1..]);

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
    use std::collections::HashMap;

    use itertools::Itertools;
    use rand::{rngs::StdRng, RngCore, SeedableRng};
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
    use triton_vm::Digest;
    use twenty_first::{
        shared_math::{bfield_codec::BFieldCodec, tip5::DIGEST_LENGTH},
        util_types::emojihash_trait::Emojihash,
    };

    use super::*;

    #[test]
    fn test_hash_index_list() {
        test_rust_equivalence_multiple(&HashIndexList, false);
    }

    #[test]
    fn test_map_hash_index_list() {
        let mut seed = [0u8; 32];
        seed[0] = 0xd2;
        seed[1] = 0x12;
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        // generate list of list of indices
        let num_lists = 5;
        let list_length = 25;
        let meta_list = (0..num_lists)
            .map(|_| {
                (0..list_length)
                    .map(|_| ((rng.next_u64() as u128) << 64) + (rng.next_u64() as u128))
                    .collect_vec()
            })
            .collect_vec();
        let rust_digests = meta_list
            .iter()
            .map(|inner_list| Hash::hash_varlen(&inner_list.encode()[1..]))
            .collect_vec();

        // populate memory
        let address = BFieldElement::new(rng.next_u64() % (1 << 20));
        let mut memory: HashMap<BFieldElement, BFieldElement> = HashMap::new();
        for (i, v) in meta_list.encode().iter().enumerate() {
            memory.insert(address + BFieldElement::new(i as u64), *v);
        }

        // populate stack
        let mut stack = get_init_tvm_stack();
        stack.push(address);

        // transform contiguous list to list of pointers
        let allocated = address.value() as usize + meta_list.encode().len();
        let get_pointer_list = GetPointerList {
            output_list_type: ListType::Unsafe,
        };
        let _vm_output = get_pointer_list.link_and_run_tasm_for_test(
            &mut stack,
            vec![],
            vec![],
            &mut memory,
            allocated,
        );

        assert_eq!(
            *memory.get(stack.last().unwrap()).unwrap(),
            BFieldElement::new(num_lists as u64)
        );

        // run map snippet
        let new_malloc = memory[&BFieldElement::new(0)].value() as usize;
        let map_hash_removal_record_indices = Map {
            list_type: ListType::Unsafe,
            f: InnerFunction::Snippet(Box::new(HashIndexList)),
        };
        let _vm_output_state = map_hash_removal_record_indices.link_and_run_tasm_for_test(
            &mut stack,
            vec![],
            vec![],
            &mut memory,
            new_malloc,
        );

        // inspect memory
        let output_list = stack.pop().unwrap();
        let num_hashes = rust_shadowing_helper_functions::unsafe_list::unsafe_list_get_length(
            output_list,
            &memory,
        );
        assert_eq!(num_hashes, num_lists);
        let mut tasm_digests = vec![];
        for i in 0..num_hashes {
            // let mut values = vec![];
            let values = rust_shadowing_helper_functions::unsafe_list::unsafe_list_get(
                output_list,
                i,
                &memory,
                DIGEST_LENGTH,
            );
            tasm_digests.push(Digest::new(values.try_into().unwrap()));
        }

        assert_eq!(
            tasm_digests,
            rust_digests,
            "\ntasm: ({})\nrust: ({})",
            tasm_digests.iter().map(|d| d.emojihash()).join(", "),
            rust_digests.iter().map(|d| d.emojihash()).join(", ")
        );
    }
}

#[cfg(test)]
mod benches {
    use tasm_lib::snippet_bencher::bench_and_write;

    use super::*;

    #[test]
    fn hash_index_list_benchmark() {
        bench_and_write(HashIndexList)
    }
}
