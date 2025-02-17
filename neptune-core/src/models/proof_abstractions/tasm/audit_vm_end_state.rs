use std::fmt::Debug;
use std::marker::PhantomData;

use itertools::Itertools;
use tasm_lib::data_type::DataType;
use tasm_lib::library::Library;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;

const NUM_TOP_STACK_WORDS_TO_CHECK: usize = 11;

/// Verify that the program ends up in a sane state.
///
/// Ensure that the pre-loaded data has integral size indicators, and that its
/// reported size matches the one given by input (the expected size). Also
/// verifies that the top 11 elements of the stack are zeros. Crashes the VM if
/// any of those checks fail. The expected size should be the one reported by
/// [`VerifyNdSiIntegrity`] at the beginning of program execution.
#[derive(Clone, Debug, Copy)]
pub struct AuditVmEndState<WitnessType: TasmObject + BFieldCodec + Clone + Debug + 'static> {
    _phantom_data: PhantomData<WitnessType>,
}

impl<Witness: TasmObject + BFieldCodec + Clone + Debug + 'static> Default
    for AuditVmEndState<Witness>
{
    fn default() -> Self {
        Self {
            _phantom_data: Default::default(),
        }
    }
}

impl<Witness: TasmObject + BFieldCodec + Clone + Debug + 'static> BasicSnippet
    for AuditVmEndState<Witness>
{
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::U32, "expected_witness_size".to_owned()),
            (DataType::VoidPointer, "witness_ptr".to_owned()),
        ]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![]
    }

    fn entrypoint(&self) -> String {
        "neptune_proof_abstractions_audit_vm_end_state".to_owned()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let entrypoint = self.entrypoint();
        let verify_nd_size_indicator_integrity =
            library.import(Box::new(VerifyNdSiIntegrity::<Witness>::default()));

        let verify_top_11_stack_words_are_zero = (0..NUM_TOP_STACK_WORDS_TO_CHECK)
            .rev()
            .flat_map(|i| {
                triton_asm!(
                    dup {i}
                    push 0
                    eq
                    assert error_id 1000010
                )
            })
            .collect_vec();

        triton_asm!(
            {entrypoint}:
                // _ expected_witness_size *witness

                call {verify_nd_size_indicator_integrity}
                // _ expected_witness_size found_size

                eq
                assert error_id 1000011
                // _

                /* Now, verify that the top 11 stack elements are zero */
                // [program_digest] [0; 11]

                {&verify_top_11_stack_words_are_zero}
                // [program_digest] [0; 11]

                return
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use arbitrary::Arbitrary;
    use arbitrary::Unstructured;
    use isa::op_stack::NUM_OP_STACK_REGISTERS;
    use num_traits::Zero;
    use rand::random;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::test_helpers::test_assertion_failure;
    use tasm_lib::traits::accessor::Accessor;
    use tasm_lib::traits::accessor::AccessorInitialState;
    use tasm_lib::traits::accessor::ShadowedAccessor;
    use tasm_lib::traits::rust_shadow::RustShadow;

    use super::*;
    use crate::models::blockchain::transaction::validity::removal_records_integrity::RemovalRecordsIntegrityWitness;

    impl<T: TasmObject + BFieldCodec + for<'a> Arbitrary<'a> + Debug + Clone> AuditVmEndState<T> {
        fn correct_initial_state(&self, address: BFieldElement, t: T) -> AccessorInitialState {
            let mut memory = HashMap::default();
            encode_to_memory(&mut memory, address, &t);

            let encoding_length: u32 = t.encode().len().try_into().unwrap();

            AccessorInitialState {
                stack: [
                    self.init_stack_for_isolated_run(),
                    vec![bfe!(encoding_length), address],
                ]
                .concat(),
                memory,
            }
        }

        fn prepare_random_object(&self, randomness: &[u8]) -> T {
            let unstructured = Unstructured::new(randomness);
            T::arbitrary_take_rest(unstructured).unwrap()
        }
    }

    impl<Witness: TasmObject + BFieldCodec + Clone + Debug + 'static + for<'a> Arbitrary<'a>>
        Accessor for AuditVmEndState<Witness>
    {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &HashMap<BFieldElement, BFieldElement>,
        ) {
            let witness_ptr = stack.pop().unwrap();
            let expected_size: u32 = stack.pop().unwrap().try_into().unwrap();

            // The decoding will fail if any size indicator is wrong
            let decoded = *Witness::decode_from_memory(memory, witness_ptr).unwrap();
            let decoded_size: u32 = decoded.encode().len().try_into().unwrap();
            assert_eq!(expected_size, decoded_size);

            // Verify top N stack words are 0
            let current_stack_length = stack.len();
            assert!((0..NUM_TOP_STACK_WORDS_TO_CHECK)
                .all(|i| stack[current_stack_length - 1 - i].is_zero()));
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            _bench_case: Option<BenchmarkCase>,
        ) -> AccessorInitialState {
            let mut rng: StdRng = SeedableRng::from_seed(seed);

            let t: Witness = {
                let mut randomness = [0u8; 100000];
                rng.fill(&mut randomness);
                self.prepare_random_object(&randomness)
            };

            let address: u32 = rng.random_range(0..(1 << 30));
            let address = bfe!(address);
            self.correct_initial_state(address, t)
        }
    }

    #[test]
    fn pbt_rri_witness() {
        let snippet = AuditVmEndState::<RemovalRecordsIntegrityWitness>::default();
        ShadowedAccessor::new(snippet).test();
    }

    #[test]
    fn rri_witness_negative_test_report_false_size() {
        let snippet = AuditVmEndState::<RemovalRecordsIntegrityWitness>::default();
        let mut bad_init_state = snippet.pseudorandom_initial_state(random(), None);
        let accessor = ShadowedAccessor::new(snippet);

        let stack_index_expected_size_value = NUM_OP_STACK_REGISTERS;
        bad_init_state.stack[stack_index_expected_size_value] += bfe!(1);
        test_assertion_failure(&accessor, bad_init_state.into(), &[1_000_011]);
    }

    #[test]
    fn rri_witness_negative_test_not_zeros_on_stack() {
        let snippet = AuditVmEndState::<RemovalRecordsIntegrityWitness>::default();
        let good_init_state = snippet.pseudorandom_initial_state(random(), None);
        let accessor = ShadowedAccessor::new(snippet);

        let first_zero = NUM_OP_STACK_REGISTERS - 1;
        for i in 0..NUM_TOP_STACK_WORDS_TO_CHECK {
            let mut bad_init_state = good_init_state.clone();
            bad_init_state.stack[first_zero - i] = random();
            test_assertion_failure(&accessor, bad_init_state.into(), &[1_000_010]);
        }
    }
}
