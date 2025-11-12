use tasm_lib::data_type::DataType;
use tasm_lib::prelude::*;
use tasm_lib::triton_vm::prelude::*;

/// Generates a new Claim object given the lengths of the input and output.
/// Returns pointers to:
///  - the claim
///  - the output
///  - the input
///  - the program digest.
#[derive(Debug, Copy, Clone)]
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

        let size_empty_claim = Claim::new(Digest::default()).encode().len();
        triton_asm! {
            // BEFORE: _ input_length output_length
            // AFTER:  _ *claim *output *input *program_digest
            {entrypoint}:

                /* Ensure claim lives within one page */
                dup 1
                pop_count
                dup 1
                pop_count
                pop 2
                // _ input_length output_length

                dup 1
                dup 1
                add
                addi {size_empty_claim}
                pop_count
                pop 1

                call {dyn_malloc}
                hint claim = stack[0]
                // _ input_length output_length *claim

                place 2
                // _ *claim input_length output_length

                dup 0 dup 0 addi 1
                // _ *claim input_length output_length output_length output_size

                dup 4
                write_mem 2
                hint output: Pointer = stack[0]
                // _ *claim input_length output_length *output

                dup 0
                place 3
                // _ *claim *output input_length output_length *output

                add
                // _ *claim *output input_length *input_si

                dup 1 dup 2 addi 1
                // _ *claim *output input_length *input_si input_length input_size

                pick 2
                write_mem 2
                hint input: Pointer = stack[0]
                // _ *claim *output input_length *input

                dup 0
                place 2
                add
                hint version: Pointer = stack[0]
                // _ *claim *output *input *version

                push {triton_vm::proof::CURRENT_VERSION}
                pick 1
                write_mem 1
                hint program_digest: Pointer = stack[0]
                // _ *claim *output *input *program_digest

                return
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;

    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tasm_lib::prelude::BasicSnippet;
    use tasm_lib::prelude::Digest;
    use tasm_lib::rust_shadowing_helper_functions;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::traits::function::Function;
    use tasm_lib::traits::function::FunctionInitialState;
    use tasm_lib::traits::function::ShadowedFunction;
    use tasm_lib::traits::rust_shadow::RustShadow;

    use super::*;

    impl Function for NewClaim {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
        ) {
            let output_len = stack.pop().unwrap().value() as usize;
            let input_len = stack.pop().unwrap().value() as usize;

            let claim_pointer =
                rust_shadowing_helper_functions::dyn_malloc::dynamic_allocator(memory);

            // We can't just create a new claim and encode it to memory because that *sets*
            // memory cells. The fact that the cells are being set to zero doesn't matter
            // for the difference check in tasm-lib. Instead, encode it manually:
            //
            // | memory location | name            |       size |
            // |----------------:|:----------------|-----------:|
            // |               0 | output's size   |          1 |
            // |               1 | output's length |          1 |
            // |               2 | output          | output_len |
            // |  output_len + 2 | input's size    |          1 |
            // |  output_len + 3 | input's length  |          1 |
            // |  output_len + 4 | input           |  input_len |
            // |   both_lens + 4 | version         |          1 |
            // |   both_lens + 5 | program_digest  |          5 |

            let output_size_pointer = claim_pointer;
            let output_len_pointer = claim_pointer + bfe!(1);
            let output_pointer = claim_pointer + bfe!(2);
            let input_size_pointer = claim_pointer + bfe!(output_len + 2);
            let input_len_pointer = claim_pointer + bfe!(output_len + 3);
            let input_pointer = claim_pointer + bfe!(output_len + 4);
            let version_pointer = claim_pointer + bfe!(output_len + input_len + 4);
            let program_digest_pointer = claim_pointer + bfe!(output_len + input_len + 5);

            memory.insert(output_size_pointer, bfe!(output_len + 1));
            memory.insert(output_len_pointer, bfe!(output_len));
            memory.insert(input_size_pointer, bfe!(input_len + 1));
            memory.insert(input_len_pointer, bfe!(input_len));
            memory.insert(version_pointer, bfe!(triton_vm::proof::CURRENT_VERSION));

            stack.push(claim_pointer);
            stack.push(output_pointer);
            stack.push(input_pointer);
            stack.push(program_digest_pointer);

            // sanity check
            let the_new_claim = *Claim::decode_from_memory(memory, claim_pointer).unwrap();
            let empty_claim = Claim::new(Digest::default())
                .with_input(bfe_vec![0; input_len])
                .with_output(bfe_vec![0; output_len]);
            assert_eq!(empty_claim, the_new_claim);
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            _bench_case: Option<BenchmarkCase>,
        ) -> FunctionInitialState {
            let mut rng: StdRng = SeedableRng::from_seed(seed);

            let input_length = rng.random_range(0..10);
            let output_length = rng.random_range(0..10);

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
