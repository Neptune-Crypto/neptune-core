use tasm_lib::arithmetic;
use tasm_lib::data_type::ArrayType;
use tasm_lib::data_type::StructType;
use tasm_lib::hashing::algebraic_hasher::sample_indices::SampleIndices;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::triton_vm::isa::triton_asm;

use crate::util_types::mutator_set::shared::NUM_TRIALS;
use crate::util_types::mutator_set::shared::WINDOW_SIZE;

const LOG2_BATCH_SIZE: u8 = 3;
const LOG2_CHUNK_SIZE: u8 = 12;

pub(crate) struct ComputeAbsoluteIndices;

impl BasicSnippet for ComputeAbsoluteIndices {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::U64, "aocl_leaf".to_string()),
            (DataType::Digest, "receiver_preimage".to_string()),
            (DataType::Digest, "sender_randomness".to_string()),
            (DataType::Digest, "item".to_string()),
        ]
    }

    fn outputs(&self) -> Vec<(tasm_lib::prelude::DataType, String)> {
        let distances_array = DataType::Array(Box::new(ArrayType {
            element_type: DataType::U32,
            length: NUM_TRIALS as usize,
        }));
        let return_type = StructType {
            name: "AbsoluteIndexSet".to_owned(),
            fields: vec![
                ("minimum".to_owned(), DataType::U128),
                ("distances".to_owned(), distances_array),
            ],
        };

        vec![(
            DataType::StructRef(return_type),
            "*absolute_indices".to_owned(),
        )]
    }

    fn entrypoint(&self) -> String {
        "tasm_neptune_mutator_set_get_swbf_indices_new".to_owned()
    }

    fn code(
        &self,
        library: &mut tasm_lib::prelude::Library,
    ) -> Vec<tasm_lib::triton_vm::prelude::LabelledInstruction> {
        let sample_indices = library.import(Box::new(SampleIndices));
        let divide_by_batch_size = library.import(Box::new(
            arithmetic::u128::shift_right_static::ShiftRightStatic::<LOG2_BATCH_SIZE>,
        ));
        let mul_by_chunk_size = library.import(Box::new(
            arithmetic::u128::shift_left_static::ShiftLeftStatic::<LOG2_CHUNK_SIZE>,
        ));
        let safe_add_u128 = library.import(Box::new(arithmetic::u128::safe_add::SafeAdd));

        let check_one_element_for_minimum = triton_asm! {
            // _ minimum *indices_array[n]
            read_mem 1 // _ minimum array[n] *array[n-1]

            swap 1     // _ minimum *array[n-1] array[n]
            dup 2      // _ minimum *array[n-1] array[n] minimum
            dup 1      // _ minimum *array[n-1] array[n] minimum array[n]
            lt         // _ minimum *array[n-1] array[n] (minimum > array[n])

            skiz
                swap 2
            pop 1
            // _ minimum' *array[n-1]
        };
        let check_all_elements =
            vec![check_one_element_for_minimum.clone(); NUM_TRIALS as usize].concat();

        // Find minimum of an array of `u32`s.
        let find_minimum = triton_asm! {
            // _ *indices_list

            addi {NUM_TRIALS}
            // _ *indices_array[len - 1]

            push {u32::MAX}
            swap 1
            // _ minimum *indices_array[len - 1]

            {&check_all_elements}
            // _ minimum *indices_array[0]

            pop 1
            // _ minimum
        };

        let subtract_minimum_from_one_elem = triton_asm! {
            // _ (-min) *indices_array[n]
            read_mem 1  // _ (-min) array[n] *array[n-1]
            addi 1      // _ (-min) array[n] *array[n]
            swap 1      // _ (-min) *array[n] array[n]
            dup 2
            add         // _ (-min) *array[n] (array[n] - min)
            swap 1      // _ (-min) (array[n] - min) *array[n]
            write_mem 1 // _ (-min) *array[n+1]
        };

        let subtract_from_all_elems =
            vec![subtract_minimum_from_one_elem.clone(); NUM_TRIALS as usize].concat();

        let subtract_from_all_elems = triton_asm! {
            // _ min *indices_list
            addi 1
            swap 1
            // _ *indices_array[0] min

            push -1
            mul
            // _ *indices_array[0] (-min)

            swap 1
            // _ (-min) *indices_array[0]

            {&subtract_from_all_elems}
            // _ (-min) *indices_array[len]
        };

        let minimum_field_size = i32::try_from(NUM_TRIALS).unwrap();
        let size_u128 = i32::try_from(DataType::U128.stack_size()).unwrap();

        // Code for encoding the data structure. Assumes a whole page has
        // already been allocated to the relative indices. Uses this allocation
        // that was already made for the relative indices to avoid having to
        // make a new allocation.
        //
        // Skip the length indicator of the list, now it is an array. Then store
        // the minimum u128 in the right place, immediately followning the
        // array. This BFieldEncoding has a static size: no length or size
        // indicators.
        let encode_absolute_indices_struct = triton_asm! {
             // _ [minimum_absolute: u128] *offsets_list
            addi {minimum_field_size + 1}
            write_mem {size_u128}
            addi {-minimum_field_size-size_u128}
            // _ *offset_array
        };

        let entrypoint = self.entrypoint();
        triton_asm! {
            // BEFORE: _ [leaf_index; u64] [receiver_preimage] [sender_randomness] [item]
            // AFTER:  _ *absolute_indices_struct
            {entrypoint}:
                // _ li_hi li_lo r4 r3 r2 r1 r0 s4 s3 s2 s1 s0 i4 i3 i2 i1 i0
                sponge_init
                sponge_absorb
                // _ li_hi li_lo r4 r3 r2 r1 r0

                /* Goal: 0 0 li_hi li_lo {0 0 1 li_hi li_lo r4 r3 r2 r1 r0} */
                push 0
                place 7
                push 0
                place 7
                // _ 0 0 li_hi li_lo r4 r3 r2 r1 r0

                dup 6
                place 7
                dup 5
                place 7
                // _ 0 0 li_hi li_lo li_hi li_lo r4 r3 r2 r1 r0

                push 0
                place 7
                push 0
                place 7
                push 1
                place 7
                // _ 0 0 li_hi li_lo {0 0 1 li_hi li_lo r4 r3 r2 r1 r0}

                sponge_absorb
                // _ 0 0 li_hi li_lo
                // _ [leaf_index: u128]

                call {divide_by_batch_size}
                call {mul_by_chunk_size}
                // _ [batch_offset: u128]

                push {NUM_TRIALS}
                push {WINDOW_SIZE}
                call {sample_indices}
                // _ [batch_offset: u128] *relative_indices

                dup 0
                {&find_minimum}
                hint minimum_relative_index: u32 = stack[0]
                hint relative_indices_list = stack[1]
                hint batch_offset: u128 = stack[2..6]
                // _ [batch_offset: u128] *relative_indices minimum


                /* Subtract minimum from all relative indices */
                dup 0
                dup 2
                {&subtract_from_all_elems}
                // _ [batch_offset: u128] *offsets minimum garb0 garb1

                pop 2
                hint minimum_relative_index: u32 = stack[0]
                hint offsets_list = stack[1]
                hint batch_offset: u128 = stack[2..6]
                // _ [batch_offset: u128] *offsets minimum

                /* Calculate minimum as absolute index */
                place 1
                place 5
                // _ *offsets [batch_offset: u128] minimum

                push 0
                push 0
                push 0
                swap 3
                // _ *offsets [batch_offset: u128] [minimum: u128]

                call {safe_add_u128}
                hint minimum_absolute: u128 = stack[0..4]
                // _ *offsets [minimum_absolute: u128]

                /* Encode absolute index sets according to `BFieldCodec` */
                pick 4
                // _ [minimum_absolute: u128] *offsets

                {&encode_absolute_indices_struct}
                // _ *offsets_array
                // _ *absolute_indices <-- rename

                return
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::prelude::Digest;
    use tasm_lib::push_encodable;
    use tasm_lib::rust_shadowing_helper_functions;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::traits::function::Function;
    use tasm_lib::traits::function::FunctionInitialState;
    use tasm_lib::traits::function::ShadowedFunction;
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tasm_lib::triton_vm::prelude::BFieldElement;

    use super::*;
    use crate::tests::shared::pop_encodable;
    use crate::twenty_first::bfe;
    use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;

    impl Function for ComputeAbsoluteIndices {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
        ) {
            let item = pop_encodable::<Digest>(stack);
            let sender_randomness = pop_encodable::<Digest>(stack);
            let receiver_preimage = pop_encodable::<Digest>(stack);
            let aocl_leaf_index = pop_encodable::<u64>(stack);

            let absolute_index_set = AbsoluteIndexSet::compute(
                item,
                sender_randomness,
                receiver_preimage,
                aocl_leaf_index,
            );

            // Write struct to memory and return a pointer to it.
            let free_page = rust_shadowing_helper_functions::dyn_malloc::dynamic_allocator(memory);
            let struct_pointer = free_page + bfe!(1);
            encode_to_memory(memory, struct_pointer, &absolute_index_set);

            // Unused artifact left on memory address immediately below struct
            encode_to_memory(memory, free_page, &NUM_TRIALS);

            stack.push(struct_pointer)
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            _bench_case: Option<BenchmarkCase>,
        ) -> FunctionInitialState {
            let mut rng = StdRng::from_seed(seed);
            let mut stack = ComputeAbsoluteIndices.init_stack_for_isolated_run();
            let item: Digest = rng.random();
            let sender_randomness: Digest = rng.random();
            let receiver_preimage: Digest = rng.random();
            let aocl_leaf_index: u64 = rng.random();

            push_encodable(&mut stack, &aocl_leaf_index);
            push_encodable(&mut stack, &receiver_preimage);
            push_encodable(&mut stack, &sender_randomness);
            push_encodable(&mut stack, &item);

            FunctionInitialState {
                stack,
                memory: HashMap::default(),
            }
        }
    }

    #[test]
    fn snippet_agrees_with_rust_shadowing() {
        // Run many times to ensure that e.g. the "min" function can find
        // minimum when lowest relative index is either first or last.
        for _ in 0..40 {
            ShadowedFunction::new(ComputeAbsoluteIndices).test();
        }
    }
}

#[cfg(test)]
mod benches {
    use tasm_lib::traits::function::ShadowedFunction;
    use tasm_lib::traits::rust_shadow::RustShadow;

    use super::*;

    #[test]
    fn benchmark() {
        ShadowedFunction::new(ComputeAbsoluteIndices).bench();
    }
}
