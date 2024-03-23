use crate::prelude::triton_vm;

use crate::{
    models::blockchain::shared::Hash,
    util_types::mutator_set::ms_membership_proof::MsMembershipProof,
};
use tasm_lib::data_type::DataType;
use tasm_lib::library::Library;
use tasm_lib::mmr::verify_from_memory::MmrVerifyFromMemory;
use tasm_lib::traits::basic_snippet::BasicSnippet;

use triton_vm::triton_asm;

use crate::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;

/// Given a membership proof and a canonical commitment, verify membership in the AOCL.
/// Note that the AOCL MMR accumulator is given deep in the stack, accounting for a 3-wide
/// buffer so that this function can be mapped over.
///
/// input:  _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0
///
/// output: _ *peaks leaf_count_hi leaf_count_lo [bu ff er] validation_result
#[derive(Debug, Clone)]
pub(crate) struct VerifyAoclMembership;

impl BasicSnippet for VerifyAoclMembership {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![(
            DataType::Tuple(vec![DataType::VoidPointer, DataType::Digest]),
            "*msmp_and_commitment".to_string(),
        )]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![(DataType::Bool, "validation_result".to_string())]
    }

    fn entrypoint(&self) -> String {
        "tasm_neptune_transaction_verify_aocl_membership".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<triton_vm::instruction::LabelledInstruction> {
        let verify_mmr_membership = library.import(Box::new(MmrVerifyFromMemory {}));
        // We do not need to use get field for MmrMembershipProof because
        // it has a custom implementation of BFieldCodec. However, we do
        // need it for MsMembershipProof.
        type MsMpH = MsMembershipProof;
        type MmrMpH = MmrMembershipProof<Hash>;
        let msmp_to_mmrmp = tasm_lib::field!(MsMpH::auth_path_aocl);
        let mmr_mp_to_li = tasm_lib::field!(MmrMpH::leaf_index);
        let mmr_mp_to_auth_path = tasm_lib::field!(MmrMpH::authentication_path);
        let entrypoint = self.entrypoint();

        triton_asm! {
        // BEFORE: _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0
        // AFTER: _ *peaks leaf_count_hi leaf_count_lo [bu ff er] b
        {entrypoint}:

        // get leaf index
            dup 5               // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 *msmp
            {&msmp_to_mmrmp}
                                // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 *mmrmp
            {&mmr_mp_to_li}     // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 *li

            push 1              // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 *li 1
            add                 // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 *list_last_word
            read_mem 2          // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo (*li - 1)
            pop 1               // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo

            // get auth path
            dup 7               // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo *msmp
            {&msmp_to_mmrmp}    // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo *mp
            {&mmr_mp_to_auth_path}
                                // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] *msmp c4 c3 c2 c1 c0 li_hi li_lo *auth_path

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

            pop 5
            pop 5
            pop 2

            // _ *peaks leaf_count_hi leaf_count_lo [bu ff er] validation_result

            return
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::util_types::mutator_set::ms_membership_proof::pseudorandom_mutator_set_membership_proof;

    use rand::RngCore;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use tasm_lib::empty_stack;
    use tasm_lib::traits::function::ShadowedFunction;
    use tasm_lib::traits::function::{Function, FunctionInitialState};
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tasm_lib::triton_vm::prelude::BFieldCodec;

    use itertools::Itertools;

    use std::collections::HashMap;

    use triton_vm::prelude::{BFieldElement, Digest};

    use crate::util_types::mmr::mock;

    impl Function for VerifyAoclMembership {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut std::collections::HashMap<BFieldElement, BFieldElement>,
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
                peaks_list_encoding
                    .push(*memory.get(&(peaks_ptr + BFieldElement::new(i))).unwrap());
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
            let memproof = *MsMembershipProof::decode(&mp_encoding).unwrap();
            println!("memproof li: {}", memproof.auth_path_aocl.leaf_index);
            println!(
                "memproof ap: {}",
                memproof.auth_path_aocl.authentication_path.iter().join(",")
            );

            // verify
            let validation_result = memproof.auth_path_aocl.verify(&peaks, leaf, leaf_count).0;
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

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            _bench_case: Option<tasm_lib::snippet_bencher::BenchmarkCase>,
        ) -> FunctionInitialState {
            async fn pseudorandom_initial_state_async(seed: [u8; 32]) -> FunctionInitialState {
                let mut rng: StdRng = SeedableRng::from_seed(seed);
                let num_leafs = rng.gen_range(1..100);
                let leafs = (0..num_leafs).map(|_| rng.gen::<Digest>()).collect_vec();

                let mmr = mock::get_ammr_from_digests::<Hash>(leafs).await;

                let leaf_index = rng.next_u64() % num_leafs;
                let leaf = mmr.get_leaf(leaf_index).await;
                let (mmr_mp, peaks) = mmr.prove_membership(leaf_index).await;
                let mut msmp = pseudorandom_mutator_set_membership_proof(rng.gen());
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
                let mut stack = empty_stack();
                stack.push(peaks_si_ptr + BFieldElement::new(1));
                stack.push(BFieldElement::new(num_leafs >> 32));
                stack.push(BFieldElement::new(num_leafs & u32::MAX as u64));
                stack.push(rng.gen());
                stack.push(rng.gen());
                stack.push(rng.gen());
                stack.push(msmp_si_ptr + BFieldElement::new(1));
                stack.push(leaf.values()[4]);
                stack.push(leaf.values()[3]);
                stack.push(leaf.values()[2]);
                stack.push(leaf.values()[1]);
                stack.push(leaf.values()[0]);

                FunctionInitialState { stack, memory }
            }

            std::thread::scope(|s| {
                s.spawn(|| {
                    let runtime = tokio::runtime::Runtime::new().unwrap();
                    runtime.block_on(pseudorandom_initial_state_async(seed))
                })
                .join()
                .unwrap()
            })
        }
    }

    #[test]
    fn test_verify_aocl_membership() {
        ShadowedFunction::new(VerifyAoclMembership).test();
    }
}

#[cfg(test)]
mod benches {
    use super::*;
    use tasm_lib::traits::function::ShadowedFunction;
    use tasm_lib::traits::rust_shadow::RustShadow;

    #[test]
    fn verify_aocl_membership_benchmark() {
        ShadowedFunction::new(VerifyAoclMembership).bench();
    }
}
