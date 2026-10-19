use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use tasm_lib::arithmetic::u64::popcount::PopCount as U64PopCount;
use tasm_lib::field;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

/// Bags the peaks of an MMR given as a list of peaks and a leaf count, the
/// way [`MmrAccumulator::bag_peaks`] does.
///
/// ```text
/// BEFORE: _ *peaks [leaf_count: u64]
/// AFTER:  _ [bagged_peaks: Digest]
/// ```
///
/// Crashes if the number of peaks is not the popcount of the leaf count.
///
/// [`MmrAccumulator::bag_peaks`]: tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr::bag_peaks
#[derive(Debug, Copy, Clone)]
pub(super) struct BagPeaksFromList;

impl BagPeaksFromList {
    pub(super) const INCONSISTENT_NUM_PEAKS_ERROR_ID: i128 = 1_000_600;
}

impl BasicSnippet for BagPeaksFromList {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (
                DataType::List(Box::new(DataType::Digest)),
                "*peaks".to_string(),
            ),
            (DataType::U64, "leaf_count".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(DataType::Digest, "bagged_peaks".to_string())]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_bag_peaks_from_list".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let popcount = library.import(Box::new(U64PopCount));
        let entrypoint = self.entrypoint();
        let fold_loop = format!("{entrypoint}_loop");

        triton_asm!(
            {entrypoint}:
                // _ *peaks [leaf_count]
                dup 1 dup 1 call {popcount}
                // _ *peaks [leaf_count] popcount

                dup 3 read_mem 1 pop 1 eq
                assert error_id {Self::INCONSISTENT_NUM_PEAKS_ERROR_ID}
                // _ *peaks [leaf_count]

                // The hash of the leaf count padded to ten words, with the
                // count's two limbs as the first two words.
                push 0 push 0 push 0 push 0 push 0 push 0 push 0 push 0
                pick 9 pick 9
                hash
                // _ *peaks [accumulator]

                dup 5 read_mem 1 pop 1
                push {Digest::LEN} mul
                dup 6 add
                // _ *peaks [accumulator] *peaks[n - 1]_last_word

                call {fold_loop}
                // _ *peaks [accumulator] *peaks

                pop 1 pick 5 pop 1
                // _ [bagged_peaks]

                return

            // Folds the peaks from the last to the first into the
            // accumulator. Stops when the pointer reaches the list's length
            // word, which precedes the first peak.
            // INVARIANT: _ *peaks [accumulator] *peaks[i]_last_word
            {fold_loop}:
                dup 6 dup 1 eq skiz return
                // _ *peaks [accumulator] *peaks[i]_last_word

                read_mem {Digest::LEN}
                // _ *peaks [accumulator] [peaks[i]] *peaks[i - 1]_last_word

                place 10
                // _ *peaks *peaks[i - 1]_last_word [accumulator] [peaks[i]]

                hash
                // _ *peaks *peaks[i - 1]_last_word [accumulator']

                pick 5
                // _ *peaks [accumulator'] *peaks[i - 1]_last_word

                recurse
        )
    }
}

/// The hash of a mutator set accumulator given as its components: the
/// active window's encoding, the inactive SWBF's peaks and leaf count, and
/// the AOCL's leaf count and peaks. The layout is the one the snippets that
/// update a mutator set accumulator use.
///
/// The active window is given by a pointer to its encoding, whose first word
/// is the length of the rest, followed by the list of set indices. The
/// components need not sit inside an encoded accumulator.
///
/// ```text
/// BEFORE: _ *window_encoding *swbfi_peaks [swbfi_leaf_count: u64] [aocl_leaf_count: u64] *aocl_peaks
/// AFTER:  _ [hash: Digest]
/// ```
#[derive(Debug, Copy, Clone)]
pub(super) struct MutatorSetHashFromComponents;

impl BasicSnippet for MutatorSetHashFromComponents {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*window_encoding".to_string()),
            (
                DataType::List(Box::new(DataType::Digest)),
                "*swbfi_peaks".to_string(),
            ),
            (DataType::U64, "swbfi_leaf_count".to_string()),
            (DataType::U64, "aocl_leaf_count".to_string()),
            (
                DataType::List(Box::new(DataType::Digest)),
                "*aocl_peaks".to_string(),
            ),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(DataType::Digest, "hash".to_string())]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_mutator_set_hash_from_components".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let bag_peaks = library.import(Box::new(BagPeaksFromList));
        let hash_varlen = library.import(Box::new(HashVarlen));

        triton_asm!(
            {self.entrypoint()}:
                // _ *window_encoding *swbfi_peaks [swbfi_leaf_count] [aocl_leaf_count] *aocl_peaks
                pick 6
                push 0 push 0 push 0 push 0 push 0
                pick 5
                // _ *swbfi_peaks [swbfi_leaf_count] [aocl_leaf_count] *aocl_peaks [default] *window_encoding

                dup 0 read_mem 1 pop 1 addi 1
                // _ *swbfi_peaks [swbfi_leaf_count] [aocl_leaf_count] *aocl_peaks [default] *window_encoding window_encoding_len

                call {hash_varlen}
                // _ *swbfi_peaks [swbfi_leaf_count] [aocl_leaf_count] *aocl_peaks [default] [active_window_hash]

                hash
                // _ *swbfi_peaks [swbfi_leaf_count] [aocl_leaf_count] *aocl_peaks [right]

                pick 10 pick 10 pick 10
                // _ [aocl_leaf_count] *aocl_peaks [right] *swbfi_peaks [swbfi_leaf_count]

                call {bag_peaks}
                // _ [aocl_leaf_count] *aocl_peaks [right] [swbfi_bagged]

                pick 10 pick 12 pick 12
                // _ [right] [swbfi_bagged] *aocl_peaks [aocl_leaf_count]

                call {bag_peaks}
                // _ [right] [swbfi_bagged] [aocl_bagged]

                hash
                // _ [right] [left]

                hash
                // _ [hash]

                return
        )
    }
}

/// The hash of a mutator set accumulator encoded in memory, as
/// [`MutatorSetAccumulator::hash`] computes it.
///
/// ```text
/// BEFORE: _ *mutator_set_accumulator
/// AFTER:  _ [hash: Digest]
/// ```
#[derive(Debug, Copy, Clone)]
pub(super) struct MutatorSetHash;

impl MutatorSetHash {
    /// Reads the components of the accumulator, in the layout
    /// [`MutatorSetHashFromComponents`] takes, consuming the pointer. The
    /// peaks lists are the ones inside the encoding, so they must not be
    /// modified.
    ///
    /// ```text
    /// BEFORE: _ *mutator_set_accumulator
    /// AFTER:  _ *window_encoding *swbfi_peaks [swbfi_leaf_count] [aocl_leaf_count] *aocl_peaks
    /// ```
    pub(super) fn read_components() -> Vec<LabelledInstruction> {
        let read_u64 = triton_asm!(addi 1 read_mem 2 pop 1);

        triton_asm!(
            // _ *msa
            dup 0 {&field!(MutatorSetAccumulator::swbf_active)}
            // _ *msa *window_encoding

            dup 1 {&field!(MutatorSetAccumulator::swbf_inactive)}
            // _ *msa *window_encoding *swbfi

            dup 0 {&field!(MmrAccumulator::peaks)}
            pick 1 {&field!(MmrAccumulator::leaf_count)} {&read_u64}
            // _ *msa *window_encoding *swbfi_peaks [swbfi_leaf_count]

            pick 4 {&field!(MutatorSetAccumulator::aocl)}
            // _ *window_encoding *swbfi_peaks [swbfi_leaf_count] *aocl

            dup 0 {&field!(MmrAccumulator::leaf_count)} {&read_u64}
            pick 2 {&field!(MmrAccumulator::peaks)}
            // _ *window_encoding *swbfi_peaks [swbfi_leaf_count] [aocl_leaf_count] *aocl_peaks
        )
    }
}

impl BasicSnippet for MutatorSetHash {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![(
            DataType::VoidPointer,
            "*mutator_set_accumulator".to_string(),
        )]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(DataType::Digest, "hash".to_string())]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_mutator_set_hash".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let hash_from_components = library.import(Box::new(MutatorSetHashFromComponents));

        triton_asm!(
            {self.entrypoint()}:
                // _ *msa
                {&Self::read_components()}
                // _ *window_encoding *swbfi_peaks [swbfi_leaf_count] [aocl_leaf_count] *aocl_peaks

                call {hash_from_components}
                // _ [hash]

                return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) mod tests {
    use std::collections::HashMap;

    use neptune_mutator_set::addition_record::AdditionRecord;
    use neptune_mutator_set::shared::WINDOW_SIZE;
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::structure::tasm_object::TasmObject;
    use tasm_lib::test_helpers::test_assertion_failure;
    use tasm_lib::test_helpers::test_rust_equivalence_given_execution_state;
    use tasm_lib::traits::function::Function;
    use tasm_lib::traits::function::FunctionInitialState;
    use tasm_lib::traits::function::ShadowedFunction;
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tasm_lib::traits::rust_shadow::RustShadowError;
    use tasm_lib::twenty_first::prelude::Mmr;

    use super::*;

    pub(in crate::block::validity) const MSA_POINTER: BFieldElement = BFieldElement::new(1_000);

    /// A mutator set accumulator with this many items added, and this many
    /// random indices set in the active window.
    pub(in crate::block::validity) fn random_mutator_set_accumulator(
        rng: &mut StdRng,
        num_additions: usize,
        num_window_indices: usize,
    ) -> MutatorSetAccumulator {
        let mut msa = MutatorSetAccumulator::default();
        for _ in 0..num_additions {
            msa.add(&AdditionRecord::new(rng.random()));
        }
        for _ in 0..num_window_indices {
            msa.swbf_active.insert(rng.random_range(0..WINDOW_SIZE));
        }
        msa
    }

    /// The MMR accumulator with this many leafs.
    fn random_mmr(rng: &mut StdRng, num_leafs: usize) -> MmrAccumulator {
        let mut mmr = MmrAccumulator::new_from_leafs(vec![]);
        for _ in 0..num_leafs {
            mmr.append(rng.random());
        }
        mmr
    }

    impl Function for BagPeaksFromList {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
        ) -> Result<(), RustShadowError> {
            let leaf_count_lo: u32 = stack.pop().unwrap().try_into().unwrap();
            let leaf_count_hi: u32 = stack.pop().unwrap().try_into().unwrap();
            let leaf_count = (u64::from(leaf_count_hi) << 32) | u64::from(leaf_count_lo);
            let peaks_pointer = stack.pop().unwrap();
            let peaks = *Vec::<Digest>::decode_from_memory(memory, peaks_pointer).unwrap();
            if peaks.len() != leaf_count.count_ones() as usize {
                return Err(RustShadowError::AssertionError(
                    Self::INCONSISTENT_NUM_PEAKS_ERROR_ID,
                ));
            }

            let bagged = MmrAccumulator::init(peaks, leaf_count).bag_peaks();
            stack.extend(bagged.reversed().values());
            Ok(())
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            bench_case: Option<BenchmarkCase>,
        ) -> FunctionInitialState {
            let mut rng = StdRng::from_seed(seed);
            let num_leafs = match bench_case {
                Some(BenchmarkCase::CommonCase) => 1 << 10,
                Some(BenchmarkCase::WorstCase) => (1 << 20) - 1,
                None => rng.random_range(0..200),
            };
            let mmr = random_mmr(&mut rng, num_leafs);
            self.initial_state(mmr.peaks(), mmr.num_leafs())
        }

        fn corner_case_initial_states(&self) -> Vec<FunctionInitialState> {
            let mut rng = StdRng::seed_from_u64(0);
            [0, 1, 2, 3, 63, 64, 65]
                .map(|num_leafs| random_mmr(&mut rng, num_leafs))
                .map(|mmr| self.initial_state(mmr.peaks(), mmr.num_leafs()))
                .to_vec()
        }
    }

    impl BagPeaksFromList {
        fn initial_state(&self, peaks: Vec<Digest>, leaf_count: u64) -> FunctionInitialState {
            let peaks_pointer = bfe!(1_000);
            let mut memory = HashMap::new();
            encode_to_memory(&mut memory, peaks_pointer, &peaks);

            let stack = [
                self.init_stack_for_isolated_run(),
                vec![peaks_pointer],
                leaf_count.encode().into_iter().rev().collect(),
            ]
            .concat();
            FunctionInitialState { stack, memory }
        }
    }

    #[test]
    fn bag_peaks_rust_shadow_agrees_with_tasm() {
        ShadowedFunction::new(BagPeaksFromList).test();
    }

    #[test]
    fn bag_peaks_with_inconsistent_peak_count_is_rejected() {
        let mut rng = StdRng::seed_from_u64(1);
        for (num_leafs, claimed_leaf_count) in [(0, 1), (1, 0), (1, 3), (3, 1), (4, 5), (2, 3)] {
            let mmr = random_mmr(&mut rng, num_leafs);
            test_assertion_failure(
                &ShadowedFunction::new(BagPeaksFromList),
                BagPeaksFromList
                    .initial_state(mmr.peaks(), claimed_leaf_count)
                    .into(),
                &[BagPeaksFromList::INCONSISTENT_NUM_PEAKS_ERROR_ID],
            );
        }
    }

    impl Function for MutatorSetHash {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
        ) -> Result<(), RustShadowError> {
            let msa_pointer = stack.pop().unwrap();
            let msa = *MutatorSetAccumulator::decode_from_memory(memory, msa_pointer).unwrap();
            stack.extend(msa.hash().reversed().values());
            Ok(())
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            bench_case: Option<BenchmarkCase>,
        ) -> FunctionInitialState {
            let mut rng = StdRng::from_seed(seed);
            let (num_additions, num_window_indices) = match bench_case {
                Some(BenchmarkCase::CommonCase) => (100, 1_000),
                Some(BenchmarkCase::WorstCase) => (1_000, 20_000),
                None => (rng.random_range(0..50), rng.random_range(0..100)),
            };
            let msa = random_mutator_set_accumulator(&mut rng, num_additions, num_window_indices);
            self.initial_state(&msa)
        }

        fn corner_case_initial_states(&self) -> Vec<FunctionInitialState> {
            let mut rng = StdRng::seed_from_u64(0);
            let mut states = vec![self.initial_state(&MutatorSetAccumulator::default())];
            for (num_additions, num_window_indices) in [(1, 0), (0, 1), (8, 0), (9, 3), (16, 1)] {
                let msa =
                    random_mutator_set_accumulator(&mut rng, num_additions, num_window_indices);
                states.push(self.initial_state(&msa));
            }
            states
        }
    }

    impl MutatorSetHash {
        pub(in crate::block::validity) fn initial_state(
            &self,
            msa: &MutatorSetAccumulator,
        ) -> FunctionInitialState {
            let mut memory = HashMap::new();
            encode_to_memory(&mut memory, MSA_POINTER, msa);

            FunctionInitialState {
                stack: [self.init_stack_for_isolated_run(), vec![MSA_POINTER]].concat(),
                memory,
            }
        }
    }

    #[test]
    fn mutator_set_hash_rust_shadow_agrees_with_tasm() {
        ShadowedFunction::new(MutatorSetHash).test();
    }

    #[test]
    fn mutator_set_hash_of_empty_accumulator_agrees_with_tasm() {
        let msa = MutatorSetAccumulator::default();
        let final_state = test_rust_equivalence_given_execution_state(
            &ShadowedFunction::new(MutatorSetHash),
            MutatorSetHash.initial_state(&msa).into(),
        );
        let mut stack = final_state.op_stack.stack;
        let hash = Digest::new([
            stack.pop().unwrap(),
            stack.pop().unwrap(),
            stack.pop().unwrap(),
            stack.pop().unwrap(),
            stack.pop().unwrap(),
        ]);
        assert_eq!(msa.hash(), hash);
    }
}
