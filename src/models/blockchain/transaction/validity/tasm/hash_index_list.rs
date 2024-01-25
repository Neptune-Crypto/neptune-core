use crate::prelude::{triton_vm, twenty_first};

use rand::{rngs::StdRng, RngCore, SeedableRng};
use tasm_lib::{
    data_type::DataType,
    hashing::hash_varlen::HashVarlen,
    snippet_bencher::BenchmarkCase,
    traits::basic_snippet::BasicSnippet,
    traits::function::{Function, FunctionInitialState},
};
use triton_vm::prelude::{triton_asm, BFieldElement};
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

use crate::models::blockchain::shared::Hash;
use tasm_lib::library::Library;

/// Hash a list of indices using hash_varlen
#[derive(Debug, Clone)]
pub struct HashIndexList;

impl BasicSnippet for HashIndexList {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "*index_list".to_string())]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![(DataType::Digest, "digest".to_string())]
    }

    fn entrypoint(&self) -> String {
        "tasm_neptune_transaction_hash_index_list".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<triton_vm::instruction::LabelledInstruction> {
        let hash_varlen = library.import(Box::new(HashVarlen));
        let entrypoint = self.entrypoint();

        triton_asm!(
        // BEFORE: _ *index_list
        // AFTER: _ [digest]
        {entrypoint}:

            read_mem 1 // _ length (*index_list - 1)
            push 2 add // _ length (*index_list + 1)
            swap 1     // _ (*index_list + 1) length
            push 4 mul // _ (*index_list + 1) size

            call {hash_varlen}

            return
        )
    }
}

impl Function for HashIndexList {
    fn rust_shadow(
        &self,
        stack: &mut Vec<BFieldElement>,
        memory: &mut std::collections::HashMap<BFieldElement, BFieldElement>,
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

    fn pseudorandom_initial_state(
        &self,
        seed: [u8; 32],
        bench_case: Option<BenchmarkCase>,
    ) -> FunctionInitialState {
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let length = if let Some(case) = bench_case {
            match case {
                BenchmarkCase::CommonCase => 45,
                BenchmarkCase::WorstCase => 200,
            }
        } else {
            ((rng.next_u32() as usize) % 5) * (1 << ((rng.next_u32() as usize) % 5))
        };
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

        let mut stack = tasm_lib::empty_stack();
        stack.push(address);

        FunctionInitialState { stack, memory }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use itertools::Itertools;
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use tasm_lib::test_helpers::{
        link_and_run_tasm_for_test, link_and_run_tasm_for_test_deprecated,
    };
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tasm_lib::{
        empty_stack,
        list::{
            contiguous_list::get_pointer_list::GetPointerList,
            higher_order::{inner_function::InnerFunction, map::Map},
            ListType,
        },
        rust_shadowing_helper_functions,
        traits::function::ShadowedFunction,
    };
    use triton_vm::prelude::{Digest, NonDeterminism};
    use twenty_first::{
        shared_math::{bfield_codec::BFieldCodec, tip5::DIGEST_LENGTH},
        util_types::emojihash_trait::Emojihash,
    };

    use super::*;

    #[test]
    fn test_hash_index_list() {
        let hash_index_list = HashIndexList;
        let wrapper = ShadowedFunction::new(hash_index_list);
        wrapper.test();
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
        let mut stack = empty_stack();
        stack.push(address);

        // transform contiguous list to list of pointers
        let get_pointer_list = GetPointerList {
            output_list_type: ListType::Unsafe,
        };
        let vm_output = link_and_run_tasm_for_test_deprecated(
            &get_pointer_list,
            &mut stack,
            vec![],
            vec![],
            memory,
            0,
        );

        let memory_after_1st_run = vm_output.final_ram;
        assert_eq!(
            *memory_after_1st_run.get(stack.last().unwrap()).unwrap(),
            BFieldElement::new(num_lists as u64)
        );

        // run map snippet
        let map_hash_removal_record_indices = Map {
            list_type: ListType::Unsafe,
            f: InnerFunction::BasicSnippet(Box::new(HashIndexList)),
        };
        let vm_output_state = link_and_run_tasm_for_test(
            &ShadowedFunction::new(map_hash_removal_record_indices),
            &mut stack,
            vec![],
            NonDeterminism::default().with_ram(memory_after_1st_run),
            None,
            0,
        );

        // inspect memory
        let final_memory = vm_output_state.final_ram;
        let output_list = stack.pop().unwrap();
        let num_hashes = rust_shadowing_helper_functions::unsafe_list::unsafe_list_get_length(
            output_list,
            &final_memory,
        );
        assert_eq!(num_hashes, num_lists);
        let mut tasm_digests = vec![];
        for i in 0..num_hashes {
            // let mut values = vec![];
            let values = rust_shadowing_helper_functions::unsafe_list::unsafe_list_get(
                output_list,
                i,
                &final_memory,
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
    use tasm_lib::{traits::function::ShadowedFunction, traits::rust_shadow::RustShadow};

    use super::*;

    #[test]
    fn hash_index_list_benchmark() {
        ShadowedFunction::new(HashIndexList).bench();
    }
}
