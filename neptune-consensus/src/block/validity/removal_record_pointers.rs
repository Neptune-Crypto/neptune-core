use tasm_lib::list::new::New;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

/// A table of pointers to the elements of a list of removal records.
///
/// Removal records have dynamic size, so the list holds a size indicator in
/// front of each element. This snippet walks the list once and returns a new
/// list whose `i`th entry points at the `i`th removal record itself, past its
/// size indicator, for random access by index.
///
/// ```text
/// BEFORE: _ *removal_records
/// AFTER:  _ *pointers
/// ```
///
/// Crashes if a size indicator or a derived pointer is not a u32.
#[derive(Debug, Copy, Clone)]
pub(super) struct RemovalRecordPointers;

impl BasicSnippet for RemovalRecordPointers {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "*removal_records".to_string())]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(
            DataType::List(Box::new(DataType::VoidPointer)),
            "*pointers".to_string(),
        )]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_removal_record_pointers".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let new_list = library.import(Box::new(New));
        let entrypoint = self.entrypoint();
        let collect_loop = format!("{entrypoint}_loop");

        triton_asm!(
            {entrypoint}:
                // _ *removal_records
                read_mem 1 addi 2
                // _ n *record[0]_si

                call {new_list}
                place 2
                // _ *pointers n *record[0]_si

                push 0
                call {collect_loop}
                // _ *pointers n *record[n]_si n

                pop 2
                // _ *pointers n

                dup 1 write_mem 1 pop 1
                // _ *pointers

                return

            // INVARIANT: _ *pointers n *record[i]_si i
            {collect_loop}:
                dup 2 dup 1 eq skiz return
                // _ *pointers n *record[i]_si i

                dup 1 addi 1
                // _ *pointers n *record[i]_si i *record[i]

                dup 4 dup 2 add addi 1
                // _ *pointers n *record[i]_si i *record[i] *pointers[i]

                write_mem 1 pop 1
                // _ *pointers n *record[i]_si i

                pick 1 read_mem 1
                // _ *pointers n i record_size (*record[i]_si - 1)

                // Crashes unless the size is a u32.
                dup 1 pop_count pop 1

                addi 2 add
                // _ *pointers n i *record[i + 1]_si

                // Pointers into non-deterministic memory must be u32s; the
                // walk must not leave the first memory page.
                dup 0 pop_count pop 1

                place 1 addi 1
                // _ *pointers n *record[i + 1]_si (i + 1)

                recurse
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) mod tests {
    use std::collections::HashMap;

    use neptune_mutator_set::removal_record::RemovalRecord;
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::rust_shadowing_helper_functions::dyn_malloc::dynamic_allocator;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::structure::tasm_object::TasmObject;
    use tasm_lib::test_helpers::test_rust_equivalence_given_execution_state;
    use tasm_lib::traits::function::Function;
    use tasm_lib::traits::function::FunctionInitialState;
    use tasm_lib::traits::function::ShadowedFunction;
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tasm_lib::traits::rust_shadow::RustShadowError;

    use super::*;

    /// Random removal records, with chunk dictionaries of varying sizes.
    pub(in crate::block::validity) fn random_removal_records(
        rng: &mut StdRng,
        num_records: usize,
    ) -> Vec<RemovalRecord> {
        let bytes = (0..num_records * 10_000)
            .map(|_| rng.random::<u8>())
            .collect::<Vec<_>>();
        let mut unstructured = arbitrary::Unstructured::new(&bytes);
        (0..num_records)
            .map(|_| unstructured.arbitrary().unwrap())
            .collect()
    }

    /// The pointer to each removal record in the list encoded at this
    /// address, past its size indicator.
    pub(in crate::block::validity) fn record_pointers(
        list_pointer: BFieldElement,
        removal_records: &[RemovalRecord],
    ) -> Vec<BFieldElement> {
        let mut pointer = list_pointer + bfe!(1);
        removal_records
            .iter()
            .map(|record| {
                let record_pointer = pointer + bfe!(1);
                pointer += bfe!(record.encode().len() as u64 + 1);
                record_pointer
            })
            .collect()
    }

    impl Function for RemovalRecordPointers {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
        ) -> Result<(), RustShadowError> {
            let list_pointer = stack.pop().unwrap();
            let removal_records = *Vec::<RemovalRecord>::decode_from_memory(memory, list_pointer)
                .map_err(|_| RustShadowError::AssertionError(0))?;

            let pointers = record_pointers(list_pointer, &removal_records);
            let pointers_list = dynamic_allocator(memory);
            memory.insert(pointers_list, bfe!(pointers.len() as u64));
            for (i, pointer) in pointers.into_iter().enumerate() {
                memory.insert(pointers_list + bfe!(i as u64 + 1), pointer);
            }

            stack.push(pointers_list);
            Ok(())
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            bench_case: Option<BenchmarkCase>,
        ) -> FunctionInitialState {
            let mut rng = StdRng::from_seed(seed);
            let num_records = match bench_case {
                Some(BenchmarkCase::CommonCase) => 10,
                Some(BenchmarkCase::WorstCase) => 100,
                None => rng.random_range(0..12),
            };
            self.initial_state(&random_removal_records(&mut rng, num_records))
        }

        fn corner_case_initial_states(&self) -> Vec<FunctionInitialState> {
            vec![self.initial_state(&[])]
        }
    }

    impl RemovalRecordPointers {
        fn initial_state(&self, removal_records: &[RemovalRecord]) -> FunctionInitialState {
            let list_pointer = bfe!(1_000);
            let mut memory = HashMap::new();
            encode_to_memory(&mut memory, list_pointer, &removal_records.to_vec());

            FunctionInitialState {
                stack: [self.init_stack_for_isolated_run(), vec![list_pointer]].concat(),
                memory,
            }
        }
    }

    #[test]
    fn rust_shadow_agrees_with_tasm() {
        ShadowedFunction::new(RemovalRecordPointers).test();
    }

    #[test]
    fn empty_list_yields_empty_table() {
        let final_state = test_rust_equivalence_given_execution_state(
            &ShadowedFunction::new(RemovalRecordPointers),
            RemovalRecordPointers.initial_state(&[]).into(),
        );
        let pointers_list = *final_state.op_stack.stack.last().unwrap();
        assert_eq!(bfe!(0), final_state.ram[&pointers_list]);
    }

    #[test]
    fn table_points_at_index_sets_of_records_of_varying_sizes() {
        let mut rng = StdRng::seed_from_u64(0);
        for num_records in [1, 2, 7] {
            let removal_records = random_removal_records(&mut rng, num_records);
            let final_state = test_rust_equivalence_given_execution_state(
                &ShadowedFunction::new(RemovalRecordPointers),
                RemovalRecordPointers.initial_state(&removal_records).into(),
            );
            let pointers_list = *final_state.op_stack.stack.last().unwrap();
            let pointers =
                *Vec::<BFieldElement>::decode_from_memory(&final_state.ram, pointers_list).unwrap();
            assert_eq!(num_records, pointers.len());
            for (pointer, record) in pointers.into_iter().zip(&removal_records) {
                let decoded =
                    *RemovalRecord::decode_from_memory(&final_state.ram, pointer).unwrap();
                assert_eq!(*record, decoded);
            }
        }
    }
}
