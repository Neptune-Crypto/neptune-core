use crate::prelude::{triton_vm, twenty_first};

use std::collections::HashMap;

use crate::models::blockchain::shared::Hash;
use rand::rngs::StdRng;
use rand::SeedableRng;
use tasm_lib::data_type::DataType;
use tasm_lib::library::Library;
use tasm_lib::memory::push_ram_to_stack::PushRamToStack;
use tasm_lib::traits::function::{Function, FunctionInitialState};

use crate::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
use tasm_lib::neptune::mutator_set::get_swbf_indices::GetSwbfIndices;
use tasm_lib::traits::basic_snippet::BasicSnippet;
use triton_vm::triton_asm;
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::shared_math::bfield_codec::BFieldCodec;
use twenty_first::shared_math::tip5::Digest;

use crate::util_types::mutator_set::ms_membership_proof::{
    pseudorandom_mutator_set_membership_proof, MsMembershipProof,
};
use crate::util_types::mutator_set::shared::{NUM_TRIALS, WINDOW_SIZE};

/// Given a mutator set item and its membership proof, compute its removal record indices.
#[derive(Debug, Clone)]
pub(crate) struct ComputeIndices;

impl BasicSnippet for ComputeIndices {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![(
            DataType::Tuple(vec![DataType::Digest, DataType::VoidPointer]),
            "item_with_*membership_proof".to_string(),
        )]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "*indices".to_string())]
    }

    fn entrypoint(&self) -> String {
        "tasm_neptune_transaction_compute_indices".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<triton_vm::instruction::LabelledInstruction> {
        type MsMpH = MsMembershipProof;
        let mp_to_sr = tasm_lib::field!(MsMpH::sender_randomness);
        let mp_to_rp = tasm_lib::field!(MsMpH::receiver_preimage);
        let mp_to_ap = tasm_lib::field!(MsMpH::auth_path_aocl);
        type MmrMpH = MmrMembershipProof<Hash>;
        let ap_to_li = tasm_lib::field!(MmrMpH::leaf_index);
        let entrypoint = self.entrypoint();
        let read_digest = library.import(Box::new(PushRamToStack {
            data_type: DataType::Digest,
        }));
        let read_u64 = library.import(Box::new(PushRamToStack {
            data_type: DataType::U64,
        }));
        let get_swbf_indices = library.import(Box::new(GetSwbfIndices {
            window_size: WINDOW_SIZE,
            num_trials: NUM_TRIALS as usize,
        }));

        triton_asm! {
        // BEFORE: _ i4 i3 i2 i1 i0 *mp
        // AFTER: _ *indices
        {entrypoint}:

            // get fields
            dup 0 // _ [item] *mp *mp
            {&mp_to_sr} // _ [item] *mp *sr

            dup 1 // _ [item] *mp *sr *mp
            {&mp_to_rp} // _ [item] *mp *sr *rp

            swap 2 // _ [item] *rp *sr *mp
            {&mp_to_ap} // _ [item] *rp *sr *ap
            {&ap_to_li} // _ [item] *rp *sr *li

            // read leaf index from memory
            call {read_u64}
            // _ [item] *rp *sr li_hi li_lo
            hint leaf_index: u64 = stack[0..2]

            // re-arrange so that leaf index is deepest in stack
            // _ i4 i3 i2 i1 i0 *rp *sr li_hi li_lo

            swap 7 // _ i4 li_lo i2 i1 i0 *rp *sr li_hi i3
            swap 1 // _ i4 li_lo i2 i1 i0 *rp *sr i3 li_hi
            swap 8 // _ li_hi li_lo i2 i1 i0 *rp *sr i3 i4
            swap 1 // _ li_hi li_lo i2 i1 i0 *rp *sr i4 i3
            swap 2 // _ li_hi li_lo i2 i1 i0 *rp i3 i4 *sr
            swap 1 // _ li_hi li_lo i2 i1 i0 *rp i3 *sr i4
            swap 3 // _ li_hi li_lo i2 i1 i0 i4 i3 *sr *rp

            // read receiver_preimage from memory
            call {read_digest} // _ li_hi li_lo i2 i1 i0 i4 i3 *sr [rp]
            hint rp: Digest = stack[0..5]

            // read sender_randomness from memory
            push 1             // _ li_hi li_lo i2 i1 i0 i4 i3 *sr [rp] 1
            swap 6             // _ li_hi li_lo i2 i1 i0 i4 i3 1 [rp] *sr
            call {read_digest} // _ li_hi li_lo i2 i1 i0 i4 i3 1 [rp] [sr]
            hint sr: Digest = stack[0..5]

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
            pop 1   // _ li_hi li_lo rp4 rp3 rp2 rp1 rp0 sr4 sr0 i2 i1 i0 i4 i3 sr3 sr2 sr1
            swap 2  // _ li_hi li_lo rp4 rp3 rp2 rp1 rp0 sr4 sr0 i2 i1 i0 i4 i3 sr1 sr2 sr3
            swap 8  // _ li_hi li_lo rp4 rp3 rp2 rp1 rp0 sr4 sr3 i2 i1 i0 i4 i3 sr1 sr2 sr0
            swap 1  // _ li_hi li_lo rp4 rp3 rp2 rp1 rp0 sr4 sr3 i2 i1 i0 i4 i3 sr1 sr0 sr2
            swap 7  // _ li_hi li_lo rp4 rp3 rp2 rp1 rp0 sr4 sr3 sr2 i1 i0 i4 i3 sr1 sr0 i2
            swap 2  // _ li_hi li_lo rp4 rp3 rp2 rp1 rp0 sr4 sr3 sr2 i1 i0 i4 i3 i2 sr0 sr1
            swap 6  // _ li_hi li_lo rp4 rp3 rp2 rp1 rp0 sr4 sr3 sr2 sr1 i0 i4 i3 i2 sr0 i1
            swap 1  // _ li_hi li_lo rp4 rp3 rp2 rp1 rp0 sr4 sr3 sr2 sr1 i0 i4 i3 i2 i1 sr0
            swap 5  // _ li_hi li_lo rp4 rp3 rp2 rp1 rp0 sr4 sr3 sr2 sr1 sr0 i4 i3 i2 i1 i0
                    // _ li_hi li_lo rp4 rp3 rp2 rp1 rp0 sr4 sr3 sr2 sr1 sr0 i4 i3 i2 i1 i0

            call {get_swbf_indices}

            return
        }
    }
}

impl Function for ComputeIndices {
    fn rust_shadow(
        &self,
        stack: &mut Vec<BFieldElement>,
        memory: &mut HashMap<BFieldElement, BFieldElement>,
    ) {
        // read address of membership proof
        let _address = stack.pop().unwrap();

        // read item
        let item = Digest::new([
            stack.pop().unwrap(),
            stack.pop().unwrap(),
            stack.pop().unwrap(),
            stack.pop().unwrap(),
            stack.pop().unwrap(),
        ]);

        // read msmp
        let size = memory.get(&BFieldElement::new(1)).unwrap().value();
        let mut sequence = vec![];
        for i in 0..size {
            sequence.push(*memory.get(&BFieldElement::new(2u64 + i)).unwrap());
        }
        let msmp = *MsMembershipProof::decode(&sequence).unwrap();
        let leaf_index = msmp.auth_path_aocl.leaf_index;
        let leaf_index_hi = leaf_index >> 32;
        let leaf_index_lo = leaf_index & (u32::MAX as u64);
        let receiver_preimage = msmp.receiver_preimage;
        let sender_randomness = msmp.sender_randomness;

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
        get_swbf_indices.rust_shadow(stack, memory);
    }

    fn pseudorandom_initial_state(
        &self,
        seed: [u8; 32],
        _bench_case: Option<tasm_lib::snippet_bencher::BenchmarkCase>,
    ) -> FunctionInitialState {
        use rand::RngCore;

        let mut rng: StdRng = SeedableRng::from_seed(seed);

        let mut msmp = pseudorandom_mutator_set_membership_proof(rand::Rng::gen(&mut rng));
        msmp.auth_path_aocl.leaf_index = rng.next_u32() as u64;

        let msmp_encoded = twenty_first::shared_math::bfield_codec::BFieldCodec::encode(&msmp);

        let item: Digest = rand::Rng::gen(&mut rng);
        let mut memory: std::collections::HashMap<BFieldElement, BFieldElement> =
            std::collections::HashMap::new();

        memory.insert(
            BFieldElement::new(1u64),
            BFieldElement::new(msmp_encoded.len() as u64),
        );
        for (i, v) in msmp_encoded.iter().enumerate() {
            memory.insert(BFieldElement::new(2u64 + i as u64), *v);
        }
        // memory.insert(
        //     <BFieldElement as num_traits::Zero>::zero(),
        //     BFieldElement::new(2u64 + msmp_encoded.len() as u64),
        // );

        let mut stack = tasm_lib::empty_stack();
        stack.push(item.values()[4]);
        stack.push(item.values()[3]);
        stack.push(item.values()[2]);
        stack.push(item.values()[1]);
        stack.push(item.values()[0]);
        stack.push(BFieldElement::new(2u64));

        FunctionInitialState { stack, memory }
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::HashMap, rc::Rc};

    use itertools::Itertools;
    use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
    use tasm_lib::{
        empty_stack,
        linker::link_for_isolated_run,
        list::higher_order::{inner_function::InnerFunction, map::Map},
        maybe_write_debuggable_program_to_disk, rust_shadowing_helper_functions,
        test_helpers::link_and_run_tasm_for_test,
        traits::{function::ShadowedFunction, rust_shadow::RustShadow},
        triton_vm::{
            program::{Program, PublicInput},
            vm::VMState,
        },
    };
    use triton_vm::prelude::NonDeterminism;
    use twenty_first::shared_math::bfield_codec::BFieldCodec;

    use crate::util_types::mutator_set::mutator_set_kernel::get_swbf_indices;

    use super::*;

    #[test]
    fn test_compute_indices() {
        ShadowedFunction::new(ComputeIndices).test();
    }

    #[test]
    fn test_map_compute_indices() {
        let mut seed = [0u8; 32];
        seed[0] = 0xa7;
        seed[1] = 0xdf;
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        let num_items = 5;

        // sample membership proofs
        let membership_proofs = (0..num_items)
            .map(|_| pseudorandom_mutator_set_membership_proof(rng.gen()))
            .collect_vec();

        // sample items
        let items: Vec<Digest> = (0..num_items).map(|_| rng.gen()).collect_vec();

        // TODO: Remove this
        let mps_encoded = membership_proofs.encode();
        println!(
            "****** mps_encoded ******\n\n\n\n: {}",
            mps_encoded.iter().take(200).join(",")
        );
        println!(
            "****** mps[0] encoded ******\n\n\n\n: {}",
            membership_proofs[0].encode().iter().take(200).join(",")
        );

        // put membership proofs into memory
        let mut address = BFieldElement::new(rng.next_u64() % (1 << 20));
        let mut memory: HashMap<BFieldElement, BFieldElement> = HashMap::new();
        let mut membership_proof_addresses = vec![];
        for mp in membership_proofs.iter() {
            membership_proof_addresses.push(address);
            for (i, v) in mp.encode().iter().enumerate() {
                if i == 0 {
                    println!("encoding of membership proof, element 0: {}", v);
                }
                memory.insert(address, *v);
                address.increment()
            }
        }

        // zip items with membership proof addresses and store that list to memory
        let main_list_address = address;
        memory.insert(address, BFieldElement::new(num_items as u64));
        address.increment();
        for (item, ptr) in items.iter().zip(membership_proof_addresses.iter()) {
            // Opposite order because stack. (Data is stored in the right order in memory.)
            memory.insert(address, *ptr);
            address.increment();
            memory.insert(address, item.values()[0]);
            address.increment();
            memory.insert(address, item.values()[1]);
            address.increment();
            memory.insert(address, item.values()[2]);
            address.increment();
            memory.insert(address, item.values()[3]);
            address.increment();
            memory.insert(address, item.values()[4]);
            address.increment();
        }

        // populate stack
        let mut stack = empty_stack();
        stack.push(main_list_address);

        // run map snippet
        let shadowed_snippet = ShadowedFunction::new(Map {
            f: InnerFunction::BasicSnippet(Box::new(ComputeIndices)),
        });
        let init_stack = stack.clone();
        let vm_output_state = link_and_run_tasm_for_test(
            &shadowed_snippet,
            &mut stack,
            vec![],
            NonDeterminism::default().with_ram(memory.clone()),
            None,
        );

        // write debug output (maybe)
        let program = Program::new(&link_for_isolated_run(Rc::new(RefCell::new(Map {
            f: InnerFunction::BasicSnippet(Box::new(ComputeIndices)),
        }))));

        let mut vm_state = VMState::new(
            &program,
            PublicInput::new(vec![]),
            NonDeterminism::new(vec![]).with_ram(memory),
        );
        vm_state.op_stack.stack = init_stack;
        maybe_write_debuggable_program_to_disk(&program, &vm_state);

        // inspect memory
        let final_ram = vm_output_state.final_ram;
        let output_list_address = stack.pop().unwrap();
        let output_list_length = final_ram.get(&output_list_address).unwrap().value() as usize;
        assert_eq!(output_list_length, num_items);
        let mut index_set_pointers = vec![];
        for i in 0..output_list_length {
            index_set_pointers.push(
                rust_shadowing_helper_functions::list::list_get(
                    output_list_address,
                    i,
                    &final_ram,
                    1,
                )[0],
            );
        }
        let mut tasm_index_sets = vec![];
        for ptr in index_set_pointers.iter() {
            let mut index_set = vec![];
            for i in 0..NUM_TRIALS as usize {
                index_set.push(
                    rust_shadowing_helper_functions::list::list_get(*ptr, i, &final_ram, 4)
                        .iter()
                        .enumerate()
                        .map(|(j, v)| (v.value() as u128) << (32 * j))
                        .sum::<u128>(),
                );
            }
            tasm_index_sets.push(index_set);
        }

        // test against rust shadow
        let rust_index_sets = items
            .into_iter()
            .zip(membership_proofs)
            .map(|(item, mp)| {
                get_swbf_indices(
                    item,
                    mp.sender_randomness,
                    mp.receiver_preimage,
                    mp.auth_path_aocl.leaf_index,
                )
                .to_vec()
            })
            .collect_vec();

        assert_eq!(
            rust_index_sets,
            tasm_index_sets,
            "\nrust: {}\ntasm: {}",
            rust_index_sets[0]
                .iter()
                .take(2)
                .chain(rust_index_sets[1].iter().take(2))
                .join(","),
            tasm_index_sets[0]
                .iter()
                .take(2)
                .chain(tasm_index_sets[1].iter().take(2))
                .join(",")
        )
    }
}

#[cfg(test)]
mod benches {
    use tasm_lib::{traits::function::ShadowedFunction, traits::rust_shadow::RustShadow};

    use super::*;

    #[test]
    fn compute_index_set_benchmark() {
        ShadowedFunction::new(ComputeIndices).bench()
    }
}
