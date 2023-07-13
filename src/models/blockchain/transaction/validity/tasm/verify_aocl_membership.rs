use crate::{
    models::blockchain::shared::Hash,
    util_types::mutator_set::ms_membership_proof::MsMembershipProof,
};
use itertools::Itertools;
use rand::{rngs::StdRng, Rng, SeedableRng};
use tasm_lib::library::Library;
use tasm_lib::{
    list::ListType,
    mmr::verify_from_memory::MmrVerifyFromMemory,
    snippet::{DataType, Snippet},
    structure::get_field::GetField,
    ExecutionState,
};
use triton_vm::{BFieldElement, Digest};
use twenty_first::shared_math::bfield_codec::BFieldCodec;

pub(crate) struct VerifyAoclMembership;

impl VerifyAoclMembership {
    fn pseudorandom_initial_state(_seed: [u8; 32], _num_leafs: u64) -> ExecutionState {
        #[cfg(test)]
        {
            use crate::util_types::test_shared::mutator_set::pseudorandom_mutator_set_membership_proof;
            use rand::RngCore;
            use std::collections::HashMap;
            use tasm_lib::get_init_tvm_stack;
            use twenty_first::test_shared::mmr::get_rustyleveldb_ammr_from_digests;

            let mut rng: StdRng = SeedableRng::from_seed(_seed);
            let leafs = (0.._num_leafs).map(|_| rng.gen::<Digest>()).collect_vec();
            let mmr = get_rustyleveldb_ammr_from_digests::<Hash>(leafs);

            let leaf_index = rng.next_u64() % _num_leafs;
            let leaf = mmr.get_leaf(leaf_index);
            let (mmr_mp, peaks) = mmr.prove_membership(leaf_index);
            let mut msmp = pseudorandom_mutator_set_membership_proof::<Hash>(rng.gen());
            msmp.auth_path_aocl = mmr_mp;

            // populate memory
            let mut memory: HashMap<BFieldElement, BFieldElement> = HashMap::new();
            let mut address = BFieldElement::new(rng.next_u64() % (1 << 20));

            let peaks_si_ptr = address;
            memory.insert(address, BFieldElement::new(peaks.encode().len() as u64));
            address.increment();
            for v in peaks.encode().iter() {
                memory.insert(address, *v);
                address.increment();
            }

            let msmp_si_ptr = address;
            memory.insert(msmp_si_ptr, BFieldElement::new(msmp.encode().len() as u64));
            address.increment();
            for v in msmp.encode().iter() {
                memory.insert(address, *v);
                address.increment();
            }

            // populate stack
            // *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0
            let mut stack = get_init_tvm_stack();
            stack.push(peaks_si_ptr + BFieldElement::new(1));
            stack.push(BFieldElement::new(_num_leafs >> 32));
            stack.push(BFieldElement::new(_num_leafs & u32::MAX as u64));
            stack.push(rng.gen());
            stack.push(rng.gen());
            stack.push(rng.gen());
            stack.push(msmp_si_ptr + BFieldElement::new(1));
            stack.push(leaf.values()[4]);
            stack.push(leaf.values()[3]);
            stack.push(leaf.values()[2]);
            stack.push(leaf.values()[1]);
            stack.push(leaf.values()[0]);

            ExecutionState {
                stack,
                std_in: vec![],
                secret_in: vec![],
                memory,
                words_allocated: 1,
            }
        }
        #[cfg(not(test))]
        unimplemented!("Cannot generate input state when not in test environment.")
    }
}

impl Snippet for VerifyAoclMembership {
    fn entrypoint(&self) -> String {
        "tasm_neptune_transaction_verify_aocl_membership".to_string()
    }

    fn inputs(&self) -> Vec<String> {
        vec![
            "*msmp".to_string(),
            "c4".to_string(),
            "c3".to_string(),
            "c2".to_string(),
            "c1".to_string(),
            "c0".to_string(),
        ]
    }

    fn input_types(&self) -> Vec<tasm_lib::snippet::DataType> {
        vec![DataType::Pair(
            Box::new(DataType::VoidPointer),
            Box::new(DataType::Digest),
        )]
    }

    fn output_types(&self) -> Vec<tasm_lib::snippet::DataType> {
        vec![DataType::Bool]
    }

    fn outputs(&self) -> Vec<String> {
        vec!["b".to_string()]
    }

    fn stack_diff(&self) -> isize {
        -5
    }

    fn function_code(&self, library: &mut Library) -> String {
        let verify_mmr_membership = library.import(Box::new(MmrVerifyFromMemory {
            list_type: ListType::Unsafe,
        }));
        // We do not need to use get field for MmrMembershipProof because
        // it has a custom implementation of BFieldCodec. However, we do
        // need it for MsMembershipProof.
        let get_field = library.import(Box::new(GetField));
        let entrypoint = self.entrypoint();

        format!(
        "
        // BEFORE: _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0
        // AFTER: _ *peaks leaf_count_hi leaf_count_lo [bu ff er] b
        {entrypoint}:
        
        // get leaf index
            dup 5               // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 *msmp
            push 2              // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 *msmp 2
            call {get_field}    // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 *mp_si
            push 1 add          // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 *mp
            push 1              // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 *li 1
            add                 // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 *li_hi
            read_mem            // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 *li_hi li_hi
            swap 1              // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi *li_hi
            push -1             // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi *li_hi -1
            add                 // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi *li_lo
            read_mem            // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi *li_lo li_lo
            swap 1              // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo *li_lo
            pop                 // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo
                                // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo

            // get auth path
            dup 7               // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo *msmp
            push 2              // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo *msmp 2
            call {get_field}    // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo *mp_si
            push 1 add          // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo *mp

            // We don't need get field because MmrMembershipProof has a custom implementation of BFieldCodec.
            push 2 add          // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo *auth_path

            // dup in correct order
            dup 14  // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo *auth_path | *peaks
            dup 14  // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo *auth_path | *peaks leaf_count_hi
            dup 14  // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo *auth_path | *peaks leaf_count_hi leaf_count_lo
            dup 5   // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo *auth_path | *peaks leaf_count_hi leaf_count_lo li_hi
            dup 5   // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo *auth_path | *peaks leaf_count_hi leaf_count_lo li_hi li_lo
            dup 12  // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo *auth_path | *peaks leaf_count_hi leaf_count_lo li_hi li_lo c4
            dup 12  // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo *auth_path | *peaks leaf_count_hi leaf_count_lo li_hi li_lo c4 c3
            dup 12  // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo *auth_path | *peaks leaf_count_hi leaf_count_lo li_hi li_lo c4 c3 c2
            dup 12  // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo *auth_path | *peaks leaf_count_hi leaf_count_lo li_hi li_lo c4 c3 c2 c1
            dup 12  // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo *auth_path | *peaks leaf_count_hi leaf_count_lo li_hi li_lo c4 c3 c2 c1 c0
            dup 10  // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo *auth_path | *peaks leaf_count_hi leaf_count_lo li_hi li_lo c4 c3 c2 c1 c0 *auth_path

            // BEFORE:   _ *peaks leaf_count_hi leaf_count_lo leaf_index_hi leaf_index_lo [leaf_digest] *auth_path
                call {verify_mmr_membership} 
            // AFTER: _ *auth_path leaf_index_hi leaf_index_lo validation_result
            // _ ... | *auth_path li_hi li_lo validation_result
            // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo *auth_path | *auth_path li_hi li_lo validation_result

            swap 12 // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] validation_result c4 c3 c2 c1 c0 li_hi li_lo *auth_path *auth_path li_hi li_lo *msmp

            pop pop pop pop
            pop pop pop pop
            pop pop pop pop

            // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] validation_result

            return
        "
        )
    }

    fn crash_conditions(&self) -> Vec<String> {
        vec![]
    }

    fn gen_input_states(&self) -> Vec<tasm_lib::ExecutionState> {
        let mut seed = [0u8; 32];
        seed[0] = 0xc3;
        seed[1] = 0x88;
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        vec![
            Self::pseudorandom_initial_state(rng.gen(), 1),
            Self::pseudorandom_initial_state(rng.gen(), 8),
            Self::pseudorandom_initial_state(rng.gen(), 15),
            Self::pseudorandom_initial_state(rng.gen(), 51),
        ]
    }

    fn common_case_input_state(&self) -> tasm_lib::ExecutionState {
        let mut seed = [0u8; 32];
        seed[0] = 0xc4;
        seed[1] = 0x89;
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        Self::pseudorandom_initial_state(rng.gen(), (1 << 8) - 1)
    }

    fn worst_case_input_state(&self) -> tasm_lib::ExecutionState {
        let mut seed = [0u8; 32];
        seed[0] = 0xb3;
        seed[1] = 0x78;
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        Self::pseudorandom_initial_state(rng.gen(), (1 << 12) - 1)
    }

    fn rust_shadowing(
        &self,
        stack: &mut Vec<triton_vm::BFieldElement>,
        _std_in: Vec<triton_vm::BFieldElement>,
        _secret_in: Vec<triton_vm::BFieldElement>,
        memory: &mut std::collections::HashMap<triton_vm::BFieldElement, triton_vm::BFieldElement>,
    ) {
        // read arguments from stack
        // *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0
        let c0 = stack.pop().unwrap();
        let c1 = stack.pop().unwrap();
        let c2 = stack.pop().unwrap();
        let c3 = stack.pop().unwrap();
        let c4 = stack.pop().unwrap();
        let leaf = Digest::new([c0, c1, c2, c3, c4]);
        let mp_ptr = stack.pop().unwrap();
        let _er = stack.pop().unwrap();
        let _ff = stack.pop().unwrap();
        let _bu = stack.pop().unwrap();
        let leaf_count_lo = stack.pop().unwrap().value();
        let leaf_count_hi = stack.pop().unwrap().value();
        let leaf_count = (leaf_count_hi << 32) ^ leaf_count_lo;
        let peaks_ptr = stack.pop().unwrap();

        // read peaks list
        let peaks_size = memory
            .get(&(peaks_ptr - BFieldElement::new(1)))
            .unwrap()
            .value();
        println!("peaks_size: {peaks_size}");
        let mut peaks_list_encoding = vec![];
        for i in 0..peaks_size {
            peaks_list_encoding.push(*memory.get(&(peaks_ptr + BFieldElement::new(i))).unwrap());
        }
        let peaks = *Vec::<Digest>::decode(&peaks_list_encoding).unwrap();
        println!("peaks: {}", peaks.iter().join(","));

        // read authentication path
        let mp_size = memory
            .get(&(mp_ptr - BFieldElement::new(1)))
            .unwrap()
            .value();
        println!("mp_size: {mp_size}");
        let mut mp_encoding = vec![];
        for i in 0..mp_size {
            mp_encoding.push(*memory.get(&(mp_ptr + BFieldElement::new(i))).unwrap());
        }
        let memproof = *MsMembershipProof::<Hash>::decode(&mp_encoding).unwrap();
        println!("memproof li: {}", memproof.auth_path_aocl.leaf_index);
        println!(
            "memproof ap: {}",
            memproof.auth_path_aocl.authentication_path.iter().join(",")
        );

        // verify
        let validation_result = memproof.auth_path_aocl.verify(&peaks, &leaf, leaf_count).0;
        println!("RS validation_result: {validation_result}");

        // repopulate stack
        // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] validation_result
        stack.push(peaks_ptr);
        stack.push(BFieldElement::new(leaf_count_hi));
        stack.push(BFieldElement::new(leaf_count_lo));
        stack.push(_bu);
        stack.push(_ff);
        stack.push(_er);
        stack.push(BFieldElement::new(validation_result as u64));
    }
}

#[cfg(test)]
mod tests {
    use tasm_lib::test_helpers::test_rust_equivalence_multiple;

    use super::*;

    #[test]
    fn test_verify_aocl_membership() {
        test_rust_equivalence_multiple(&VerifyAoclMembership, false);
    }
}

#[cfg(test)]
mod benches {
    use tasm_lib::snippet_bencher::bench_and_write;

    use super::*;

    #[test]
    fn verify_aocl_membership_benchmark() {
        bench_and_write(VerifyAoclMembership)
    }
}
