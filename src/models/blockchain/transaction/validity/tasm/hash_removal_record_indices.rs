use crate::prelude::{triton_vm, twenty_first};

use std::collections::HashMap;

use rand::{rngs::StdRng, Rng, SeedableRng};
use tasm_lib::{
    data_type::DataType,
    empty_stack,
    hashing::hash_varlen::HashVarlen,
    snippet_bencher::BenchmarkCase,
    traits::basic_snippet::BasicSnippet,
    traits::function::{Function, FunctionInitialState},
};
use triton_vm::prelude::{triton_asm, BFieldElement};
use twenty_first::{
    shared_math::bfield_codec::BFieldCodec, util_types::algebraic_hasher::AlgebraicHasher,
};

use crate::{
    models::blockchain::shared::Hash,
    util_types::mutator_set::removal_record::{pseudorandom_removal_record, RemovalRecord},
};
use tasm_lib::library::Library;

/// Compute the hash (using hash_varlen) of the given removal record indices.
#[derive(Debug, Clone)]
pub struct HashRemovalRecordIndices;

impl BasicSnippet for HashRemovalRecordIndices {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "*removal_record".to_string())]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![(DataType::Digest, "digest".to_string())]
    }

    fn entrypoint(&self) -> String {
        "tasm_neptune_transaction_hash_removal_record_indices".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<triton_vm::instruction::LabelledInstruction> {
        type Rrh = RemovalRecord<Hash>;
        let rr_to_ais_with_size = tasm_lib::field_with_size!(Rrh::absolute_indices);
        let hash_varlen = library.import(Box::new(HashVarlen));
        let entrypoint = self.entrypoint();

        triton_asm! {
        // BEFORE: _ *removal_record
        // AFTER: _ [digest]
        {entrypoint}:

            {&rr_to_ais_with_size}  // *absolute_index_set 180

            // push 0 assert

            call {hash_varlen}

            return
        }
    }
}

impl Function for HashRemovalRecordIndices {
    fn rust_shadow(
        &self,
        stack: &mut Vec<BFieldElement>,
        memory: &mut HashMap<BFieldElement, BFieldElement>,
    ) {
        // read address
        let address = stack.pop().unwrap();

        // read object
        let mut encoding = vec![];
        let size = memory
            .get(&(address - BFieldElement::new(1)))
            .unwrap()
            .value();
        for i in 0..size {
            encoding.push(*memory.get(&(address + BFieldElement::new(i))).unwrap());
        }
        let removal_record = *RemovalRecord::<Hash>::decode(&encoding).unwrap();

        // hash absolute index set
        let digest = Hash::hash_varlen(&removal_record.absolute_indices.encode());

        // write hash to stack
        stack.push(digest.values()[4]);
        stack.push(digest.values()[3]);
        stack.push(digest.values()[2]);
        stack.push(digest.values()[1]);
        stack.push(digest.values()[0]);
    }

    fn pseudorandom_initial_state(
        &self,
        seed: [u8; 32],
        _bench_case: Option<BenchmarkCase>,
    ) -> FunctionInitialState {
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let removal_record = pseudorandom_removal_record::<Hash>(rng.gen());
        let address: BFieldElement = BFieldElement::new(rng.gen_range(2..(1 << 20)));

        let mut memory: HashMap<BFieldElement, BFieldElement> = HashMap::new();
        for (i, v) in removal_record.encode().iter().enumerate() {
            memory.insert(address + BFieldElement::new(i as u64), *v);
        }
        memory.insert(
            address - BFieldElement::new(1),
            BFieldElement::new(removal_record.encode().len() as u64),
        );

        let mut stack = empty_stack();
        stack.push(address);

        FunctionInitialState { stack, memory }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use itertools::Itertools;
    use num_traits::Zero;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use tasm_lib::test_helpers::{
        link_and_run_tasm_for_test, link_and_run_tasm_for_test_deprecated,
    };
    use tasm_lib::{
        empty_stack,
        list::{
            contiguous_list::get_pointer_list::GetPointerList,
            higher_order::{inner_function::InnerFunction, map::Map},
            ListType,
        },
        rust_shadowing_helper_functions,
        traits::function::ShadowedFunction,
        traits::rust_shadow::RustShadow,
    };
    use triton_vm::prelude::{BFieldElement, Digest, NonDeterminism};
    use twenty_first::shared_math::tip5::DIGEST_LENGTH;

    use super::*;

    #[test]
    fn test_hash_removal_record_indices() {
        let hash_removal_record_indices = HashRemovalRecordIndices;
        let wrapper = ShadowedFunction::new(hash_removal_record_indices);
        wrapper.test();
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
        let address = BFieldElement::new(rng.gen_range(2..(1 << 20)));

        // compute digests
        let rust_digests = removal_records
            .iter()
            .map(|rr| Hash::hash_varlen(&rr.absolute_indices.encode()))
            .collect_vec();

        // populate memory
        let mut memory: HashMap<BFieldElement, BFieldElement> = HashMap::new();
        let removal_records_encoded = removal_records.encode();
        Vec::<RemovalRecord<Hash>>::decode(&removal_records_encoded).unwrap();
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
        let mut stack = empty_stack();
        stack.push(address);
        // STACK: 0^16 *removal_record_list_encoding_address

        // transform contiguous list to list of pointers
        let get_pointer_list = GetPointerList {
            output_list_type: ListType::Unsafe,
        };
        let _vm_output = link_and_run_tasm_for_test_deprecated(
            &get_pointer_list,
            &mut stack,
            vec![],
            vec![],
            memory,
            0,
        );

        // STACK: 0^16 *[*removal_record]

        // read list of pointers from memory
        let pointers_list_address = *stack.last().unwrap();

        let memory_after_1st_run = _vm_output.final_ram;
        let num_pointers = memory_after_1st_run
            .get(&pointers_list_address)
            .unwrap()
            .value() as usize;
        let mut pointers_list = vec![];
        for i in 0..num_pointers {
            pointers_list.push(
                *memory_after_1st_run
                    .get(&(pointers_list_address + BFieldElement::new(1 + i as u64)))
                    .unwrap(),
            );
        }

        // read removal records from memory through list of pointers
        let mut read_removal_records = vec![];
        for pointer in pointers_list {
            // Since this pointer list points into a contiguous list, every
            // element is size-prepended, but the pointer points past the size.
            // So move one back to read the size works.
            let size = memory_after_1st_run
                .get(&(pointer - BFieldElement::new(1)))
                .unwrap()
                .value() as usize;
            let mut removal_record_encoding = vec![];
            for i in 0..size {
                removal_record_encoding.push(
                    *memory_after_1st_run
                        .get(&(pointer + BFieldElement::new(i as u64)))
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
            memory_after_1st_run
                .get(stack.last().unwrap())
                .unwrap()
                .clone()
                .value() as usize,
            num_removal_records
        );

        // run map snippet
        let map_hash_removal_record_indices = Map {
            list_type: ListType::Unsafe,
            f: InnerFunction::BasicSnippet(Box::new(HashRemovalRecordIndices)),
        };
        let vm_output_state = link_and_run_tasm_for_test(
            &ShadowedFunction::new(map_hash_removal_record_indices),
            &mut stack,
            vec![],
            NonDeterminism::default().with_ram(memory_after_1st_run),
            None,
            0,
        );
        // STACK: 0^16 *[digest]

        // inspect memory
        let final_memory = vm_output_state.final_ram;
        let output_address = stack.pop().unwrap();
        let length: usize = final_memory.get(&output_address).unwrap().value() as usize;
        assert_eq!(length, num_removal_records);
        // output_address.increment();
        let mut tasm_digests = vec![];
        for i in 0..length {
            // let mut values = vec![];
            let values = rust_shadowing_helper_functions::unsafe_list::unsafe_list_get(
                output_address,
                i,
                &final_memory,
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
    use tasm_lib::{traits::function::ShadowedFunction, traits::rust_shadow::RustShadow};

    use super::*;

    #[test]
    fn hash_removal_record_indices_benchmark() {
        let hash_removal_record_indices = HashRemovalRecordIndices;
        let wrapper = ShadowedFunction::new(hash_removal_record_indices);
        wrapper.bench();
    }
}
