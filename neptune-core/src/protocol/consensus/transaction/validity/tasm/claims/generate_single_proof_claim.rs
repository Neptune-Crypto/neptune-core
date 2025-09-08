use tasm_lib::data_type::DataType;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Library;

use crate::protocol::consensus::transaction::validity::tasm::claims::new_claim::NewClaim;
use crate::triton_vm::prelude::*;

#[derive(Debug, Copy, Clone)]
pub(crate) struct GenerateSingleProofClaim;

impl BasicSnippet for GenerateSingleProofClaim {
    fn inputs(&self) -> Vec<(DataType, String)> {
        let txk_mast_hash = (DataType::Digest, "txk_mast_hash".to_string());
        let program_digest = (DataType::Digest, "single_proof_program_digest".to_string());

        vec![txk_mast_hash, program_digest]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "single_proof_claim".to_string())]
    }

    fn entrypoint(&self) -> String {
        "neptune_transaction_generate_single_proof_claim".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let new_claim = library.import(Box::new(NewClaim));
        let single_proof_digest_alloc = library.kmalloc(u32::try_from(Digest::LEN).unwrap());

        triton_asm!(
            // BEFORE: _ [mast_hash; 5] [single_proof_digest; 5]
            // AFTER:  _ *claim
            {self.entrypoint()}:
            push {single_proof_digest_alloc.write_address()}
            write_mem {Digest::LEN} // _ [mast_hash; 5] *spd
            pop 1                   // _ [mast_hash; 5]

            push {Digest::LEN}      // _ [mast_hash; 5] input_len
            push 0                  // _ [mast_hash; 5] input_len output_len
            call {new_claim}        // _ [mast_hash; 5] *claim *output *input *program_digest

            push {single_proof_digest_alloc.read_address()}
            read_mem {Digest::LEN}  // _ [mast_hash; 5] *claim *output *input *program_digest [spd; 5] *spd
            swap 6                  // _ [mast_hash; 5] *claim *output *input *program_digest *spd [spd; 5] *program_digest
            write_mem {Digest::LEN} // _ [mast_hash; 5] *claim *output *input *spd *program_digest'
            pop 2                   // _ [mast_hash; 5] *claim *output *input

            dup 3
            dup 5
            dup 7
            dup 9
            dup 11                  // _ [mast_hash; 5] *claim *output *input [mast_hash_rev; 5]
            dup 5
            write_mem {Digest::LEN}
            pop 3                   // _ [mast_hash; 5] *claim

            swap 5
            pop 5                   // _ *claim
            return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;

    use rand::prelude::StdRng;
    use rand::Rng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::rust_shadowing_helper_functions;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::traits::algorithm::Algorithm;
    use tasm_lib::traits::algorithm::AlgorithmInitialState;
    use tasm_lib::traits::algorithm::ShadowedAlgorithm;
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tasm_lib::triton_vm::proof::Claim;

    use super::*;
    use crate::prelude::triton_vm::prelude::BFieldElement;
    use crate::prelude::triton_vm::prelude::NonDeterminism;

    impl Algorithm for GenerateSingleProofClaim {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
            _: &NonDeterminism,
        ) {
            fn pop_digest(stack: &mut Vec<BFieldElement>) -> Digest {
                Digest::new([
                    stack.pop().unwrap(),
                    stack.pop().unwrap(),
                    stack.pop().unwrap(),
                    stack.pop().unwrap(),
                    stack.pop().unwrap(),
                ])
            }
            let single_proof_digest_location_isolated_run =
                tasm_lib::library::STATIC_MEMORY_FIRST_ADDRESS
                    - bfe!(u32::try_from(Digest::LEN).unwrap())
                    + bfe!(1);

            let single_proof_digest = pop_digest(stack);
            let mast_hash = pop_digest(stack);

            let claim =
                Claim::new(single_proof_digest).with_input(mast_hash.reversed().values().to_vec());
            let claim_pointer =
                rust_shadowing_helper_functions::dyn_malloc::dynamic_allocator(memory);
            encode_to_memory(memory, claim_pointer, &claim);
            stack.push(claim_pointer);

            // mimic static memory
            encode_to_memory(
                memory,
                single_proof_digest_location_isolated_run,
                &single_proof_digest,
            );
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            _: Option<BenchmarkCase>,
        ) -> AlgorithmInitialState {
            let mut rng: StdRng = rand::prelude::SeedableRng::from_seed(seed);
            let mast_hash = rng.random::<Digest>();
            let single_proof_digest = rng.random::<Digest>();

            let mut stack = self.init_stack_for_isolated_run();
            stack.extend(mast_hash.reversed().values());
            stack.extend(single_proof_digest.reversed().values());

            AlgorithmInitialState {
                stack,
                ..Default::default()
            }
        }
    }

    #[test]
    fn rust_and_tasm_agree() {
        ShadowedAlgorithm::new(GenerateSingleProofClaim).test()
    }
}
