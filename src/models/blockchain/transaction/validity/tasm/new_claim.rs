use tasm_lib::data_type::DataType;
use tasm_lib::prelude::*;
use tasm_lib::triton_vm::prelude::LabelledInstruction;
use tasm_lib::triton_vm::triton_asm;

/// Generates a new Claim object given the lengths of the input and output.
/// Returns pointers to:
///  - the claim
///  - the output
///  - the input
///  - the program digest.
pub struct NewClaim;

impl BasicSnippet for NewClaim {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::U32, "input_length".to_string()),
            (DataType::U32, "output_length".to_string()),
        ]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*claim".to_string()),
            (DataType::VoidPointer, "*output".to_string()),
            (DataType::VoidPointer, "*input".to_string()),
            (DataType::VoidPointer, "*program_digest".to_string()),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_transaction_new_claim".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let entrypoint = self.entrypoint();

        let dyn_malloc = library.import(Box::new(DynMalloc));

        triton_asm! {
            // BEFORE: _ input_length output_length
            // AFTER: _ *claim *output *input *program_digest
            {entrypoint}:

                call {dyn_malloc}
                hint claim = stack[0]
                // _ input_length output_length *claim

                swap 2
                // _ *claim output_length input_length

                dup 1 dup 2 push 1 add
                // _  *claim output_length input_length output_length output_size

                dup 4
                // _  *claim output_length input_length output_length output_size *output_si

                write_mem 2
                hint output = stack[0]
                // _  *claim output_length input_length *output

                dup 0 swap 3
                // _ *claim *output input_length *output output_length

                add
                // _ *claim *output input_length *input_si

                dup 1 dup 2 push 1 add
                // _ *claim *output input_length *input_si input_length input_size

                dup 2 write_mem 2
                hint input = stack[0]
                // _ *claim *output input_length *input_si *input

                swap 1 pop 1
                // _ *claim *output input_length *input

                dup 0 swap 2 add
                hint program_digest = stack[0]
                // _ *claim *output *input *program_digest

                return
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use rand::{rngs::StdRng, Rng, SeedableRng};
    use tasm_lib::{
        prelude::BasicSnippet,
        rust_shadowing_helper_functions,
        snippet_bencher::BenchmarkCase,
        traits::{
            function::{Function, FunctionInitialState, ShadowedFunction},
            rust_shadow::RustShadow,
        },
        triton_vm::prelude::BFieldElement,
        twenty_first::bfe,
    };

    use super::NewClaim;

    impl Function for NewClaim {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
        ) {
            let output_length = stack.pop().unwrap().value() as usize;
            let input_length = stack.pop().unwrap().value() as usize;

            let claim_pointer =
                rust_shadowing_helper_functions::dyn_malloc::dynamic_allocator(memory);

            // We can't use the following because it *sets* memory cells.
            // The fact that the cells are being set to zero doesn't matter
            // for the difference check in tasm-lib.

            // let claim = Claim {
            //     program_digest: Default::default(),
            //     input: vec![BFieldElement::ZERO; input_length],
            //     output: vec![BFieldElement::ZERO; output_length],
            // };
            // encode_to_memory(memory, claim_pointer, &claim);

            memory.insert(claim_pointer, bfe!((output_length + 1) as u64));
            memory.insert(claim_pointer + bfe!(1), bfe!(output_length as u64));
            memory.insert(
                claim_pointer + bfe!(output_length as u64) + bfe!(2),
                bfe!((input_length + 1) as u64),
            );
            memory.insert(
                claim_pointer + bfe!(output_length as u64) + bfe!(3),
                bfe!(input_length as u64),
            );

            let output_pointer = claim_pointer + bfe!(2);
            let input_pointer = output_pointer + bfe!(2) + bfe!(output_length as u64);
            let program_digest_pointer = input_pointer + bfe!(input_length as u64);

            stack.push(claim_pointer);
            stack.push(output_pointer);
            stack.push(input_pointer);
            stack.push(program_digest_pointer);
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            _bench_case: Option<BenchmarkCase>,
        ) -> FunctionInitialState {
            let mut rng: StdRng = SeedableRng::from_seed(seed);

            let input_length = rng.gen_range(0..10);
            let output_length = rng.gen_range(0..10);

            FunctionInitialState {
                stack: [
                    self.init_stack_for_isolated_run(),
                    [bfe!(input_length as u64), bfe!(output_length as u64)].to_vec(),
                ]
                .concat(),
                memory: HashMap::new(),
            }
        }
    }

    #[test]
    fn unit_test() {
        ShadowedFunction::new(NewClaim).test()
    }
}
