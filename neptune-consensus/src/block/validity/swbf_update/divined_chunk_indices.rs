use tasm_lib::list::new::New;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use crate::block::block_validation_error::BlockValidationRule;

/// Reads a strictly increasing list of chunk indices from non-determinism:
/// the indices of the chunks the witness carries, which it leaves implicit.
/// The prover supplies them; the checks that use them establish that they
/// are the right ones.
///
/// ```text
/// BEFORE: _ num_chunks
/// AFTER:  _ *chunk_indices
/// ```
///
/// Reads two tokens per chunk index: its high limb, then its low limb.
/// Crashes if a limb is not a u32 or the indices do not strictly increase.
#[derive(Debug, Copy, Clone)]
pub(super) struct DivinedChunkIndices;

impl DivinedChunkIndices {
    fn error_id() -> i128 {
        BlockValidationRule::RemovalRecordsUnpackFailure.error_id()
    }

    /// The tokens the prover supplies for these chunk indices.
    pub(crate) fn divined_tokens(chunk_indices: &[u64]) -> Vec<BFieldElement> {
        chunk_indices
            .iter()
            .flat_map(|index| [bfe!(index >> 32), bfe!(index & u64::from(u32::MAX))])
            .collect()
    }
}

impl BasicSnippet for DivinedChunkIndices {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![(DataType::U32, "num_chunks".to_string())]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(
            DataType::List(Box::new(DataType::U64)),
            "*chunk_indices".to_string(),
        )]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_divined_chunk_indices".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let new_list = library.import(Box::new(New));

        let entrypoint = self.entrypoint();
        let read_first = format!("{entrypoint}_read_first");
        let read_loop = format!("{entrypoint}_loop");
        let u64_size = DataType::U64.stack_size();

        triton_asm!(
            {entrypoint}:
                // _ num_chunks
                call {new_list}
                // _ num_chunks *chunk_indices

                dup 1 dup 1 write_mem 1 pop 1
                // _ num_chunks *chunk_indices

                dup 0 addi 1
                push 0 push 0 push 0
                // _ num_chunks *chunk_indices *chunk_indices[0] [previous] i

                dup 5 push 0 eq push 0 eq skiz call {read_first}
                // _ num_chunks *chunk_indices *chunk_indices[i] [previous] i

                call {read_loop}
                pop 4
                // _ num_chunks *chunk_indices

                place 1 pop 1
                // _ *chunk_indices

                return

            // The first index is not compared with anything.
            // BEFORE: _ num_chunks *chunk_indices *chunk_indices[0] [previous] 0
            // AFTER:  _ num_chunks *chunk_indices *chunk_indices[1] [first] 1
            {read_first}:
                pop 3 divine 2
                // _ num_chunks *chunk_indices *chunk_indices[0] [first]

                // Crashes unless both limbs are u32s.
                dup 1 pop_count pop 1 dup 0 pop_count pop 1

                dup 1 dup 1 dup 4 write_mem {u64_size}
                // _ num_chunks *chunk_indices *chunk_indices[0] [first] *chunk_indices[1]

                pick 3 pop 1 place 2 push 1
                // _ num_chunks *chunk_indices *chunk_indices[1] [first] 1

                return

            // INVARIANT: _ num_chunks *chunk_indices *chunk_indices[i] [previous] i
            {read_loop}:
                dup 5 dup 1 eq skiz return
                // _ num_chunks *chunk_indices *chunk_indices[i] [previous] i

                divine 2
                // _ num_chunks *chunk_indices *chunk_indices[i] [previous] i [current]

                // Strictly increasing: a higher high limb, or the same and a
                // higher low limb.
                dup 1 dup 5 lt
                dup 2 dup 6 eq
                dup 2 dup 6 lt
                mul add assert error_id {Self::error_id()}
                // _ num_chunks *chunk_indices *chunk_indices[i] [previous] i [current]

                dup 1 dup 1 dup 7 write_mem {u64_size}
                // _ num_chunks *chunk_indices *chunk_indices[i] [previous] i [current] *chunk_indices[i + 1]

                pick 6 pop 1 place 5
                // _ num_chunks *chunk_indices *chunk_indices[i + 1] [previous] i [current]

                place 4 place 4 pick 2 pop 1 pick 1 pop 1
                // _ num_chunks *chunk_indices *chunk_indices[i + 1] [current] i

                addi 1
                recurse
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;
    use std::collections::VecDeque;

    use itertools::Itertools;
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::rust_shadowing_helper_functions::dyn_malloc::dynamic_allocator;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::structure::tasm_object::TasmObject;
    use tasm_lib::test_helpers::tasm_final_state;
    use tasm_lib::test_helpers::test_assertion_failure;
    use tasm_lib::test_helpers::test_rust_equivalence_given_execution_state;
    use tasm_lib::traits::procedure::Procedure;
    use tasm_lib::traits::procedure::ProcedureInitialState;
    use tasm_lib::traits::procedure::ShadowedProcedure;
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tasm_lib::traits::rust_shadow::RustShadowError;
    use tasm_lib::InitVmState;

    use super::*;

    impl Procedure for DivinedChunkIndices {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
            nondeterminism: &NonDeterminism,
            _public_input: &[BFieldElement],
            _sponge: &mut Option<Tip5>,
        ) -> Result<Vec<BFieldElement>, RustShadowError> {
            let fail = || RustShadowError::AssertionError(Self::error_id());
            let num_chunks: u32 = stack.pop().unwrap().try_into().unwrap();
            let list = dynamic_allocator(memory);
            memory.insert(list, bfe!(num_chunks));

            let mut tokens: VecDeque<_> = nondeterminism.individual_tokens.clone().into();
            let mut previous = None;
            for i in 0..num_chunks {
                let hi = tokens.pop_front().unwrap();
                let lo = tokens.pop_front().unwrap();
                let hi_u32: u32 = hi.try_into().map_err(|_| fail())?;
                let lo_u32: u32 = lo.try_into().map_err(|_| fail())?;
                let current = (u64::from(hi_u32) << 32) | u64::from(lo_u32);
                if previous.is_some_and(|previous| previous >= current) {
                    return Err(fail());
                }
                previous = Some(current);
                memory.insert(list + bfe!(1 + 2 * u64::from(i)), lo);
                memory.insert(list + bfe!(2 + 2 * u64::from(i)), hi);
            }

            stack.push(list);
            Ok(vec![])
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            bench_case: Option<BenchmarkCase>,
        ) -> ProcedureInitialState {
            let mut rng = StdRng::from_seed(seed);
            let num_chunks = match bench_case {
                Some(BenchmarkCase::CommonCase) => 45,
                Some(BenchmarkCase::WorstCase) => 1_000,
                None => rng.random_range(0..30),
            };
            let chunk_indices = (0..num_chunks)
                .map(|_| rng.random::<u64>() >> rng.random_range(0..64))
                .sorted()
                .dedup()
                .collect::<Vec<_>>();
            self.initial_state(&chunk_indices, Self::divined_tokens(&chunk_indices))
        }

        fn corner_case_initial_states(&self) -> Vec<ProcedureInitialState> {
            [
                vec![],
                vec![0],
                vec![u64::MAX],
                vec![0, 1],
                vec![u64::from(u32::MAX), 1 << 32],
                vec![0, 1, 2, 3, u64::MAX - 1, u64::MAX],
            ]
            .into_iter()
            .map(|chunk_indices| {
                self.initial_state(&chunk_indices, Self::divined_tokens(&chunk_indices))
            })
            .collect()
        }
    }

    impl DivinedChunkIndices {
        fn initial_state(
            &self,
            chunk_indices: &[u64],
            tokens: Vec<BFieldElement>,
        ) -> ProcedureInitialState {
            ProcedureInitialState {
                stack: [
                    self.init_stack_for_isolated_run(),
                    vec![bfe!(chunk_indices.len() as u64)],
                ]
                .concat(),
                nondeterminism: NonDeterminism::new(tokens),
                public_input: vec![],
                sponge: None,
            }
        }
    }

    #[test]
    fn rust_shadow_agrees_with_tasm() {
        ShadowedProcedure::new(DivinedChunkIndices).test();
    }

    #[test]
    fn list_holds_the_divined_indices() {
        for chunk_indices in [vec![], vec![7], vec![3, 1 << 40, u64::MAX]] {
            let final_state = test_rust_equivalence_given_execution_state(
                &ShadowedProcedure::new(DivinedChunkIndices),
                DivinedChunkIndices
                    .initial_state(
                        &chunk_indices,
                        DivinedChunkIndices::divined_tokens(&chunk_indices),
                    )
                    .into(),
            );
            let list = *final_state.op_stack.stack.last().unwrap();
            assert_eq!(
                chunk_indices,
                *Vec::<u64>::decode_from_memory(&final_state.ram, list).unwrap()
            );
        }
    }

    #[test]
    fn non_increasing_indices_are_rejected() {
        for chunk_indices in [vec![5, 5], vec![5, 4], vec![0, 1, 1], vec![u64::MAX, 0]] {
            test_assertion_failure(
                &ShadowedProcedure::new(DivinedChunkIndices),
                DivinedChunkIndices
                    .initial_state(
                        &chunk_indices,
                        DivinedChunkIndices::divined_tokens(&chunk_indices),
                    )
                    .into(),
                &[DivinedChunkIndices::error_id()],
            );
        }
    }

    #[test]
    fn limbs_beyond_u32_are_rejected() {
        // Whichever limb, the VM crashes on the u32 operation that reads it.
        let chunk_indices = [1, 2];
        for bad_token in 0..4 {
            let mut tokens = DivinedChunkIndices::divined_tokens(&chunk_indices);
            tokens[bad_token] = bfe!(1_u64 << 32);
            let initial_state: InitVmState = DivinedChunkIndices
                .initial_state(&chunk_indices, tokens)
                .into();
            let tasm_result = tasm_final_state(
                &ShadowedProcedure::new(DivinedChunkIndices),
                &initial_state.stack,
                &initial_state.public_input,
                initial_state.nondeterminism,
                &initial_state.sponge,
            );
            assert!(tasm_result.is_err());
        }
    }
}
