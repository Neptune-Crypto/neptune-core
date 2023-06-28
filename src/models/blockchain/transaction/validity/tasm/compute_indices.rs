use tasm_lib::{
    memory::push_ram_to_stack::PushRamToStack,
    neptune::mutator_set::get_swbf_indices::GetSwbfIndices,
    snippet::{DataType, Snippet},
    structure::get_field::GetField,
};
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::shared_math::tip5::Digest;

use crate::util_types::mutator_set::shared::{NUM_TRIALS, WINDOW_SIZE};

pub(crate) struct ComputeIndices;

impl ComputeIndices {
    #[cfg(test)]
    fn pseudorandom_init_state(seed: [u8; 32]) -> tasm_lib::ExecutionState {
        let mut rng: rand::rngs::StdRng = rand::SeedableRng::from_seed(seed);

        let mut msmp =
            crate::util_types::test_shared::mutator_set::pseudorandom_mutator_set_membership_proof::<
                crate::Hash,
            >(rand::Rng::gen(&mut rng));
        msmp.auth_path_aocl.leaf_index = rand::Rng::gen(&mut rng);

        println!(
            "leaf index lo: {}",
            msmp.auth_path_aocl.leaf_index & u32::MAX as u64
        );
        println!("leaf index hi: {}", msmp.auth_path_aocl.leaf_index >> 32);

        let msmp_encoded = twenty_first::shared_math::bfield_codec::BFieldCodec::encode(&msmp);

        let item: Digest = rand::Rng::gen(&mut rng);
        let mut memory: std::collections::HashMap<BFieldElement, BFieldElement> =
            std::collections::HashMap::new();

        for (i, v) in msmp_encoded.iter().enumerate() {
            memory.insert(BFieldElement::new(1u64 + i as u64), *v);
        }
        memory.insert(
            <BFieldElement as num_traits::Zero>::zero(),
            BFieldElement::new(1u64 + msmp_encoded.len() as u64),
        );

        let mut stack = tasm_lib::get_init_tvm_stack();
        stack.push(item.values()[4]);
        stack.push(item.values()[3]);
        stack.push(item.values()[2]);
        stack.push(item.values()[1]);
        stack.push(item.values()[0]);
        stack.push(BFieldElement::new(1u64));

        tasm_lib::ExecutionState {
            stack,
            std_in: vec![],
            secret_in: vec![],
            memory,
            words_allocated: 1,
        }
    }
}

impl Snippet for ComputeIndices {
    fn entrypoint(&self) -> String {
        "tasm_neptune_transaction_compute_indices".to_string()
    }

    fn inputs(&self) -> Vec<String> {
        vec![
            "i4".to_string(),
            "i3".to_string(),
            "i2".to_string(),
            "i1".to_string(),
            "i0".to_string(),
            "*mp".to_string(),
        ]
    }

    fn input_types(&self) -> Vec<tasm_lib::snippet::DataType> {
        vec![DataType::Pair(
            Box::new(DataType::Digest),
            Box::new(DataType::VoidPointer),
        )]
    }

    fn output_types(&self) -> Vec<tasm_lib::snippet::DataType> {
        vec![DataType::VoidPointer]
    }

    fn outputs(&self) -> Vec<String> {
        vec!["*indices".to_string()]
    }

    fn stack_diff(&self) -> isize {
        -5
    }

    fn function_code(&self, library: &mut tasm_lib::snippet_state::SnippetState) -> String {
        let get_field = library.import(Box::new(GetField));
        let entrypoint = self.entrypoint();
        let read_digest = library.import(Box::new(PushRamToStack {
            output_type: DataType::Digest,
        }));
        let get_swbf_indices = library.import(Box::new(GetSwbfIndices {
            window_size: WINDOW_SIZE,
            num_trials: NUM_TRIALS as usize,
        }));

        format!(
            "
        // BEFORE: _ i4 i3 i2 i1 i0 *mp
        // AFTER: _ *indices
        {entrypoint}:

            // get fields
            dup 0 // _ [item] *mp *mp
            push 0 // _ [item] *mp *mp 0 (= field sender_randomness)
            call {get_field} // _ [item] *mp *sr_si
            push 1 add // _ [item] *mp *sr

            dup 1 // _ [item] *mp *sr *mp
            push 1 // _ [item] *mr *sr *mp 1 (= field receiver_preimage)
            call {get_field} // _ [item] *mp *sr *rp_si
            push 1 add // _ [item] *mp *sr *rp

            swap 2 // _ [item] *rp *sr *mp
            push 2 // _ [item] *rp *sr *mp 2 (= field auth_path_aocl)
            call {get_field} // _ [item] *rp *sr *ap_si
            push 1 add // _ [item] *rp *sr *ap
            push 0 // _ [item] *rp *sr *ap 0 (= field leaf_index)
            call {get_field} // _ [item] *rp *sr *li_si
            // push 1 add // _ [item] *rp *sr *li

            // read leaf index from memory
            read_mem // _ [item] *rp *sr *li li_lo 
            swap 1   // _ [item] *rp *sr li_lo *li
            push 1 add // _ [item] *rp *sr li_lo *li+1
            read_mem // _ [item] *rp *sr li_lo *li+1 li_hi
            swap 1 pop // _ [item] *rp *sr li_lo li_hi

            // re-arrange so that leaf index is deepest in stack
                   // _ i4 i3 i2 i1 i0 *rp *sr li_lo li_hi
            swap 8 // _ li_hi i3 i2 i1 i0 *rp *sr li_lo i4
            swap 1 // _ li_hi i3 i2 i1 i0 *rp *sr i4 li_lo
            swap 7 // _ li_hi li_lo i2 i1 i0 *rp *sr i4 i3
            swap 2 // _ li_hi li_lo i2 i1 i0 *rp i3 i4 *sr
            swap 1 // _ li_hi li_lo i2 i1 i0 *rp i3 *sr i4
            swap 3 // _ li_hi li_lo i2 i1 i0 i4 i3 *sr *rp

            // read receiver_preimage from memory
            call {read_digest} // _ li_hi li_lo i2 i1 i0 i4 i3 *sr [rp]

            // read sender_randomness from memory
            push 1 // _ li_hi li_lo i2 i1 i0 i4 i3 *sr [rp] 1
            swap 6 // _ li_hi li_lo i2 i1 i0 i4 i3 1 [rp] *sr
            call {read_digest} // _ li_hi li_lo i2 i1 i0 i4 i3 1 [rp] [sr]

            // re-arrange stack in anticipation of swbf_get_indices
                    // _ li_hi li_lo i2 i1 i0 i4 i3 1 rp4 rp3 rp2 rp1 rp0 sr4 sr3 sr2 sr1 sr0
            swap 9  // _ li_hi li_lo i2 i1 i0 i4 i3 1 sr0 rp3 rp2 rp1 rp0 sr4 sr3 sr2 sr1 rp4
            swap 15 // _ li_hi li_lo rp4 i1 i0 i4 i3 1 sr0 rp3 rp2 rp1 rp0 sr4 sr3 sr2 sr1 i2
            swap 8  // _ li_hi li_lo rp4 i1 i0 i4 i3 1 sr0 i2 rp2 rp1 rp0 sr4 sr3 sr2 sr1 rp3
            swap 14 // _ li_hi li_lo rp4 rp3 i0 i4 i3 1 sr0 i2 rp2 rp1 rp0 sr4 sr3 sr2 sr1 i1
            swap 7  // _ li_hi li_lo rp4 rp3 i0 i4 i3 1 sr0 i2 i1 rp1 rp0 sr4 sr3 sr2 sr1 rp2
            swap 13 // _ li_hi li_lo rp4 rp3 rp2 i4 i3 1 sr0 i2 i1 rp1 rp0 sr4 sr3 sr2 sr1 i0
            swap 6  // _ li_hi li_lo rp4 rp3 rp2 i4 i3 1 sr0 i2 i1 i0 rp0 sr4 sr3 sr2 sr1 rp1
            swap 12 // _ li_hi li_lo rp4 rp3 rp2 rp1 i3 1 sr0 i2 i1 i0 rp0 sr4 sr3 sr2 sr1 i4
            swap 5  // _ li_hi li_lo rp4 rp3 rp2 rp1 i3 1 sr0 i2 i1 i0 i4 sr4 sr3 sr2 sr1 rp0
            swap 11 // _ li_hi li_lo rp4 rp3 rp2 rp1 rp0 1 sr0 i2 i1 i0 i4 sr4 sr3 sr2 sr1 i3
            swap 4  // _ li_hi li_lo rp4 rp3 rp2 rp1 rp0 1 sr0 i2 i1 i0 i4 i3 sr3 sr2 sr1 sr4
            swap 10 // _ li_hi li_lo rp4 rp3 rp2 rp1 rp0 sr4 sr0 i2 i1 i0 i4 i3 sr3 sr2 sr1 1
            pop     // _ li_hi li_lo rp4 rp3 rp2 rp1 rp0 sr4 sr0 i2 i1 i0 i4 i3 sr3 sr2 sr1
            swap 2  // _ li_hi li_lo rp4 rp3 rp2 rp1 rp0 sr4 sr0 i2 i1 i0 i4 i3 sr1 sr2 sr3
            swap 8  // _ li_hi li_lo rp4 rp3 rp2 rp1 rp0 sr4 sr3 i2 i1 i0 i4 i3 sr1 sr2 sr0
            swap 1  // _ li_hi li_lo rp4 rp3 rp2 rp1 rp0 sr4 sr3 i2 i1 i0 i4 i3 sr1 sr0 sr2
            swap 7  // _ li_hi li_lo rp4 rp3 rp2 rp1 rp0 sr4 sr3 sr2 i1 i0 i4 i3 sr1 sr0 i2
            swap 2  // _ li_hi li_lo rp4 rp3 rp2 rp1 rp0 sr4 sr3 sr2 i1 i0 i4 i3 i2 sr0 sr1
            swap 6  // _ li_hi li_lo rp4 rp3 rp2 rp1 rp0 sr4 sr3 sr2 sr1 i0 i4 i3 i2 sr0 i1
            swap 1  // _ li_hi li_lo rp4 rp3 rp2 rp1 rp0 sr4 sr3 sr2 sr1 i0 i4 i3 i2 i1 sr0
            swap 5  // _ li_hi li_lo rp4 rp3 rp2 rp1 rp0 sr4 sr3 sr2 sr1 sr0 i4 i3 i2 i1 i0
                    // _ li_hi li_lo rp4 rp3 rp2 rp1 rp0 sr4 sr3 sr2 sr1 sr0 i4 i3 i2 i1 i0

            // get indices
            call {get_swbf_indices}

            return
            "
        )
    }

    fn crash_conditions(&self) -> Vec<String> {
        vec![]
    }

    fn gen_input_states(&self) -> Vec<tasm_lib::ExecutionState> {
        #[cfg(test)]
        {
            vec![
                Self::pseudorandom_init_state(rand::Rng::gen(&mut rand::thread_rng())),
                Self::pseudorandom_init_state(rand::Rng::gen(&mut rand::thread_rng())),
                Self::pseudorandom_init_state(rand::Rng::gen(&mut rand::thread_rng())),
            ]
        }
        #[cfg(not(test))]
        {
            unimplemented!("Cannot generate input states when not in testing environment");
        }
    }

    fn common_case_input_state(&self) -> tasm_lib::ExecutionState {
        #[cfg(test)]
        {
            let mut seed = [0u8; 32];
            seed[0] = 0xa8;
            seed[1] = 0xb6;
            Self::pseudorandom_init_state(seed)
        }
        #[cfg(not(test))]
        {
            unimplemented!("Cannot generate input states when not in testing environment");
        }
    }

    fn worst_case_input_state(&self) -> tasm_lib::ExecutionState {
        #[cfg(test)]
        {
            let mut seed = [0u8; 32];
            seed[0] = 0xa3;
            seed[1] = 0xb4;
            Self::pseudorandom_init_state(seed)
        }
        #[cfg(not(test))]
        {
            unimplemented!("Cannot generate input states when not in testing environment");
        }
    }

    fn rust_shadowing(
        &self,
        stack: &mut Vec<triton_vm::BFieldElement>,
        std_in: Vec<triton_vm::BFieldElement>,
        secret_in: Vec<triton_vm::BFieldElement>,
        memory: &mut std::collections::HashMap<triton_vm::BFieldElement, triton_vm::BFieldElement>,
    ) {
        // read address of membership proof
        let mut address = stack.pop().unwrap();

        // read item
        let item = Digest::new([
            stack.pop().unwrap(),
            stack.pop().unwrap(),
            stack.pop().unwrap(),
            stack.pop().unwrap(),
            stack.pop().unwrap(),
        ]);

        // read sender randomness
        address.increment();
        let sr0 = *memory.get(&address).unwrap();
        address.increment();
        let sr1 = *memory.get(&address).unwrap();
        address.increment();
        let sr2 = *memory.get(&address).unwrap();
        address.increment();
        let sr3 = *memory.get(&address).unwrap();
        address.increment();
        let sr4 = *memory.get(&address).unwrap();
        address.increment();
        let sender_randomness = Digest::new([sr0, sr1, sr2, sr3, sr4]);

        // read receiver preimage
        address.increment();
        let rp0 = *memory.get(&address).unwrap();
        address.increment();
        let rp1 = *memory.get(&address).unwrap();
        address.increment();
        let rp2 = *memory.get(&address).unwrap();
        address.increment();
        let rp3 = *memory.get(&address).unwrap();
        address.increment();
        let rp4 = *memory.get(&address).unwrap();
        address.increment();
        let receiver_preimage = Digest::new([rp0, rp1, rp2, rp3, rp4]);

        // read leaf index
        address.increment();
        let leaf_index_lo = memory.get(&address).unwrap().value();
        address.increment();
        let leaf_index_hi = memory.get(&address).unwrap().value();
        address.increment();
        let _aocl_leaf_index = (leaf_index_hi << 32) ^ leaf_index_lo;

        // // compute indices
        // let indices = get_swbf_indices::<Hash>(
        //     &item,
        //     &sender_randomness,
        //     &receiver_preimage,
        //     aocl_leaf_index,
        // );

        // // store to memory as unsafe list
        // let list_pointer = rust_shadowing_helper_functions::dyn_malloc::dynamic_allocator(
        //     4 * indices.len(),
        //     memory,
        // );
        // rust_shadowing_helper_functions::unsafe_list::unsafe_list_new(list_pointer, memory);
        // for index in indices {
        //     let v0 = (index & u32::MAX as u128) as u32;
        //     let v1 = ((index >> 32) & u32::MAX as u128) as u32;
        //     let v2 = ((index >> 64) & u32::MAX as u128) as u32;
        //     let v3 = ((index >> 96) & u32::MAX as u128) as u32;
        //     let value = vec![
        //         BFieldElement::new(v0 as u64),
        //         BFieldElement::new(v1 as u64),
        //         BFieldElement::new(v2 as u64),
        //         BFieldElement::new(v3 as u64),
        //     ];
        //     rust_shadowing_helper_functions::unsafe_list::unsafe_list_push(
        //         list_pointer,
        //         value,
        //         memory,
        //         4,
        //     )
        // }

        // // leave list pointer on stack
        // stack.push(list_pointer);

        stack.push(BFieldElement::new(leaf_index_hi));
        stack.push(BFieldElement::new(leaf_index_lo));
        stack.push(receiver_preimage.values()[4]);
        stack.push(receiver_preimage.values()[3]);
        stack.push(receiver_preimage.values()[2]);
        stack.push(receiver_preimage.values()[1]);
        stack.push(receiver_preimage.values()[0]);
        stack.push(sender_randomness.values()[4]);
        stack.push(sender_randomness.values()[3]);
        stack.push(sender_randomness.values()[2]);
        stack.push(sender_randomness.values()[1]);
        stack.push(sender_randomness.values()[0]);
        stack.push(item.values()[4]);
        stack.push(item.values()[3]);
        stack.push(item.values()[2]);
        stack.push(item.values()[1]);
        stack.push(item.values()[0]);
        let get_swbf_indices = GetSwbfIndices {
            window_size: WINDOW_SIZE,
            num_trials: NUM_TRIALS as usize,
        };
        get_swbf_indices.rust_shadowing(stack, std_in, secret_in, memory);
    }
}

#[cfg(test)]
mod tests {
    use tasm_lib::test_helpers::test_rust_equivalence_multiple;

    use super::*;

    #[test]
    fn new_prop_test() {
        test_rust_equivalence_multiple(&ComputeIndices, false);
    }
}

#[cfg(test)]
mod benches {
    use tasm_lib::snippet_bencher::bench_and_write;

    use super::*;

    #[test]
    fn compute_index_set_benchmark() {
        bench_and_write(ComputeIndices)
    }
}
