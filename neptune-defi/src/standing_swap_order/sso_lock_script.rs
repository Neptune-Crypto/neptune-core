use neptune_consensus::transaction::lock_script::LockScript;
use neptune_consensus::transaction::lock_script::LockScriptAndWitness;
use neptune_consensus::transaction::transaction_kernel::TransactionKernel;
use neptune_consensus::transaction::transaction_kernel::TransactionKernelField;
use neptune_consensus::transaction::validity::tasm::authenticate_txk_field::AuthenticateTxkField;
use neptune_mutator_set::addition_record::AdditionRecord;
use neptune_primitives::mast_hash::MastHash;
use tasm_lib::data_type::DataType;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

/// The lock script of a standing swap order, which admits two spending paths.
///
///  - **Cancel.** The five divined words hash to `cancel_post_image`. This is
///    the standard hash lock.
///  - **Fill.** Some element of `admissible_outputs` is among the
///    transaction's outputs, as authenticated against the kernel MAST hash.
///
/// There is no path selector. The script halts if and only if the divined
/// words hash to `cancel_post_image` or an output of the transaction is
/// admissible, and the fill check is skipped only when the first holds.
///
/// The admissible set is hard-coded, one member per possible payment. A
/// configuration with a fully determined demanded UTXO has one member. SOFuN
/// orders have many.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsoLockScript {
    pub cancel_post_image: Digest,
    pub admissible_outputs: Vec<AdditionRecord>,
}

impl SsoLockScript {
    /// An index into the outputs list that is out of range.
    const OUTPUT_INDEX_ERROR: i128 = 1_000_580;

    /// The output at the divined index is not admissible.
    const FILL_ERROR: i128 = 1_000_581;

    /// Where the fill witness places the encoding of the outputs field.
    const OUTPUTS_ADDRESS: BFieldElement = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;

    pub fn lock_script(&self) -> LockScript {
        let mut library = Library::new();
        let authenticate_outputs = library.import(Box::new(AuthenticateTxkField(
            TransactionKernelField::Outputs,
        )));

        let push_digest = |digest: Digest| {
            digest
                .values()
                .iter()
                .rev()
                .map(|elem| triton_instr!(push elem.value()))
                .collect::<Vec<_>>()
        };
        let compare_digests = DataType::Digest.compare();

        // _ [ar] matches -> _ [ar] (matches + [ar == member])
        let count_match = |member: &AdditionRecord| {
            triton_asm!(
                dup 5 dup 5 dup 5 dup 5 dup 5
                {&push_digest(member.canonical_commitment)}
                {&compare_digests}
                add
            )
        };
        let count_matches = self
            .admissible_outputs
            .iter()
            .flat_map(count_match)
            .collect::<Vec<_>>();

        let outputs_address = Self::OUTPUTS_ADDRESS;
        let last_word_of_first_output = outputs_address + bfe!(Digest::LEN as u64);

        // The comparison below is a value rather than an assertion, so it
        // takes nine words off of the op stack. The five zeros keep the stack
        // above its minimum depth of 16, and they do not change the hash,
        // because the words they cover are zeros at program start.
        let dispatch = triton_asm!(
            push 0 push 0 push 0 push 0 push 0
            divine 5
            hash
            {&push_digest(self.cancel_post_image)}
            {&compare_digests}
            // _ opened

            read_io 5
            pick 5
            // _ [txkmh] opened

            push 0 eq
            skiz call fill
            halt
        );

        let fill = triton_asm!(
            // _ [txkmh] -> _
            fill:
                push {outputs_address}
                divine 1
                // _ [txkmh] *outputs outputs_size

                call {authenticate_outputs}
                // _

                divine 1
                // _ i
                push {outputs_address} read_mem 1 pop 1
                // _ i num_outputs

                dup 1 lt
                assert error_id {Self::OUTPUT_INDEX_ERROR}
                // _ i

                push {Digest::LEN} mul
                push {last_word_of_first_output} add
                read_mem 5 pop 1
                // _ [output[i]]

                push 0
                {&count_matches}
                // _ [output[i]] matches

                push 0 eq push 0 eq
                assert error_id {Self::FILL_ERROR}

                pop 5
                return
        );

        [dispatch, fill, library.all_imports()].concat().into()
    }

    /// The witness for cancelling the order.
    pub fn cancel(&self, preimage: Digest) -> LockScriptAndWitness {
        LockScriptAndWitness::new_with_nondeterminism(
            self.lock_script().program,
            NonDeterminism::new(preimage.reversed().values()),
        )
    }

    /// The witness for filling the order with `kernel`, if one of its outputs
    /// is admissible.
    pub fn fill(&self, kernel: &TransactionKernel) -> Option<LockScriptAndWitness> {
        let output_index = kernel
            .outputs
            .iter()
            .position(|output| self.admissible_outputs.contains(output))?;

        // Any 5-tuple that does not hash to the post-image will do. Even a
        // 5-tuple that does hash to the post-image will do: it generates a
        // Cancel instead of a Fill but either is a valid spend. Harmless. So:
        // no need to take a special argument or check anything; zeros is fine.
        let divined_preimage = Digest::default();
        self.fill_at(kernel, output_index, divined_preimage)
    }

    /// The fill witness pointing at `kernel.outputs[output_index]`, or `None`
    /// if that output does not exist. The witness exists whether or not the
    /// output is admissible; it halts if and only if it is, or if `divined`
    /// happens to be the cancel preimage.
    fn fill_at(
        &self,
        kernel: &TransactionKernel,
        output_index: usize,
        divined: Digest,
    ) -> Option<LockScriptAndWitness> {
        if output_index >= kernel.outputs.len() {
            return None;
        }

        let outputs_size = kernel.outputs.encode().len();
        let tokens = [
            divined.reversed().values().to_vec(),
            bfe_vec![outputs_size as u64, output_index as u64],
        ]
        .concat();

        let mut ram = std::collections::HashMap::new();
        encode_to_memory(&mut ram, Self::OUTPUTS_ADDRESS, &kernel.outputs);

        let nondeterminism = NonDeterminism::new(tokens)
            .with_digests(kernel.mast_path(TransactionKernelField::Outputs))
            .with_ram(ram);

        Some(LockScriptAndWitness::new_with_nondeterminism(
            self.lock_script().program,
            nondeterminism,
        ))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use proptest::collection::vec;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest::prop_assume;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;
    use crate::standing_swap_order::sofun::NUM_GRID_POINTS;

    pub(crate) fn public_input(kernel: &TransactionKernel) -> PublicInput {
        PublicInput::new(kernel.mast_hash().reversed().values().to_vec())
    }

    pub(crate) fn with_outputs(
        kernel: &TransactionKernel,
        outputs: Vec<AdditionRecord>,
    ) -> TransactionKernel {
        neptune_consensus::transaction::transaction_kernel::TransactionKernelModifier::default()
            .outputs(outputs)
            .modify(kernel.clone())
    }

    #[proptest(cases = 20)]
    fn cancel_with_preimage_halts(
        #[strategy(arb())] preimage: Digest,
        #[strategy(arb())] admissible_outputs: Vec<AdditionRecord>,
        #[strategy(arb())] kernel: TransactionKernel,
    ) {
        let order = SsoLockScript {
            cancel_post_image: preimage.hash(),
            admissible_outputs,
        };
        prop_assert!(order
            .cancel(preimage)
            .halts_gracefully(public_input(&kernel)));
    }

    #[proptest(cases = 20)]
    fn cancel_with_wrong_preimage_and_no_fill_crashes(
        #[strategy(arb())] preimage: Digest,
        #[strategy(arb())] wrong_preimage: Digest,
        #[strategy(arb())] admissible_outputs: Vec<AdditionRecord>,
        #[strategy(arb())] kernel: TransactionKernel,
    ) {
        prop_assume!(preimage != wrong_preimage);
        let order = SsoLockScript {
            cancel_post_image: preimage.hash(),
            admissible_outputs,
        };
        let kernel = with_outputs(&kernel, vec![]);
        prop_assert!(!order
            .cancel(wrong_preimage)
            .halts_gracefully(public_input(&kernel)));
    }

    #[proptest(cases = 20)]
    fn fill_halts_iff_an_output_is_admissible(
        #[strategy(arb())] cancel_post_image: Digest,
        #[strategy(vec(arb(), 1..4))] admissible_outputs: Vec<AdditionRecord>,
        #[strategy(arb())] other_outputs: Vec<AdditionRecord>,
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(0..=#other_outputs.len())] position: usize,
        #[strategy(0..#admissible_outputs.len())] member: usize,
    ) {
        let order = SsoLockScript {
            cancel_post_image,
            admissible_outputs,
        };

        let unpaid = with_outputs(&kernel, other_outputs.clone());
        prop_assert!(order.fill(&unpaid).is_none());
        for output_index in 0..other_outputs.len() {
            let witness = order
                .fill_at(&unpaid, output_index, Digest::default())
                .unwrap();
            prop_assert!(!witness.halts_gracefully(public_input(&unpaid)));
        }
        prop_assert!(order
            .fill_at(&unpaid, other_outputs.len(), Digest::default())
            .is_none());

        let mut outputs = other_outputs;
        outputs.insert(position, order.admissible_outputs[member]);
        let paid = with_outputs(&kernel, outputs);
        let witness = order.fill(&paid).unwrap();
        prop_assert!(witness.halts_gracefully(public_input(&paid)));

        // The same witness against another kernel fails authentication.
        prop_assert!(!witness.halts_gracefully(public_input(&unpaid)));
    }

    /// A cancel attempted with the wrong preimage does not fail as a
    /// cancel. It falls through to the fill path, where the same five words
    /// spend the order if the reward is present and fail if it is not.
    #[proptest(cases = 20)]
    fn wrong_preimage_fails_cancel_and_can_pass_fill(
        #[strategy(arb())] preimage: Digest,
        #[strategy(arb())] wrong_preimage: Digest,
        #[strategy(arb())] admissible_output: AdditionRecord,
        #[strategy(arb())] other_outputs: Vec<AdditionRecord>,
        #[strategy(arb())] kernel: TransactionKernel,
    ) {
        prop_assume!(preimage != wrong_preimage);
        prop_assume!(!other_outputs.contains(&admissible_output));
        let order = SsoLockScript {
            cancel_post_image: preimage.hash(),
            admissible_outputs: vec![admissible_output],
        };

        // fill fails
        let unpaid = with_outputs(&kernel, other_outputs.clone());
        prop_assert!(!order
            .cancel(wrong_preimage)
            .halts_gracefully(public_input(&unpaid)));

        // fill passes
        let paid = with_outputs(&kernel, [other_outputs, vec![admissible_output]].concat());
        let index = paid.outputs.len() - 1;
        prop_assert!(order
            .fill_at(&paid, index, wrong_preimage)
            .unwrap()
            .halts_gracefully(public_input(&paid)));
    }

    /// One output fills two orders whose admissible sets meet. The lock
    /// script cannot see the other order, so nothing here rejects it; what
    /// keeps the sets apart is a fresh seed per order, which is a wallet
    /// requirement rather than a script one.
    #[proptest(cases = 20)]
    fn one_output_fills_two_orders(
        #[strategy(arb())] first_post_image: Digest,
        #[strategy(arb())] second_post_image: Digest,
        #[strategy(arb())] shared_output: AdditionRecord,
        #[strategy(arb())] kernel: TransactionKernel,
    ) {
        let order = |cancel_post_image| SsoLockScript {
            cancel_post_image,
            admissible_outputs: vec![shared_output],
        };
        let first = order(first_post_image);
        let second = order(second_post_image);
        prop_assume!(first != second);

        // One reward, paid once.
        let kernel = with_outputs(&kernel, vec![shared_output]);
        for order in [first, second] {
            prop_assert!(order
                .fill(&kernel)
                .unwrap()
                .halts_gracefully(public_input(&kernel)));
        }
    }

    #[proptest(cases = 20)]
    fn reward_set_can_have_one_member(
        #[strategy(arb())] cancel_post_image: Digest,
        #[strategy(arb())] admissible_output: AdditionRecord,
        #[strategy(vec(arb(), 1..4))] other_outputs: Vec<AdditionRecord>,
        #[strategy(arb())] kernel: TransactionKernel,
    ) {
        prop_assume!(!other_outputs.contains(&admissible_output));
        let order = SsoLockScript {
            cancel_post_image,
            admissible_outputs: vec![admissible_output],
        };

        let unpaid = with_outputs(&kernel, other_outputs.clone());
        prop_assert!(order.fill(&unpaid).is_none());

        let paid = with_outputs(&kernel, [other_outputs, vec![admissible_output]].concat());
        prop_assert!(order
            .fill(&paid)
            .unwrap()
            .halts_gracefully(public_input(&paid)));
    }

    /// Proving cost along its two axes: the output count and the size of the
    /// admissible set.
    ///
    /// The output count is the cheaper one. The membership check reads one
    /// output, which is constant, but authenticating the outputs field hashes
    /// it in full, so the trace grows by about one and a half cycles per
    /// output: 254 at one output, 638 at 128.
    ///
    /// The admissible set is the expensive one, at 25 cycles per member. SOFuN's
    /// 26-point grid costs 879 cycles where a one-member general swap order
    /// costs 254, and that carries the padded height from 4096 to 16384 — four
    /// times the proving work. The grid dominates the output count until a
    /// transaction has some four hundred outputs.
    ///
    /// Run with `--ignored --nocapture` to read the table.
    #[proptest(cases = 1)]
    #[ignore = "a measurement, not an assertion"]
    fn fill_cost_by_output_count(#[strategy(arb())] kernel: TransactionKernel) {
        // The general swap order of §1.5, and the SOFuN grid.
        for num_admissible in [1, NUM_GRID_POINTS as usize] {
            let admissible_outputs = (0..num_admissible)
                .map(|i| AdditionRecord::new(Digest::new(bfe_array![i as u64, 0, 0, 0, 0])))
                .collect::<Vec<_>>();
            let paid_with = admissible_outputs[num_admissible - 1];
            let order = SsoLockScript {
                cancel_post_image: Digest::default(),
                admissible_outputs,
            };
            let program = order.lock_script().program;

            println!("{num_admissible} admissible;  outputs  cycles  padded height");
            for log2_num_outputs in 0..8 {
                let num_outputs = 1 << log2_num_outputs;
                let mut outputs = vec![AdditionRecord::new(Digest::default()); num_outputs];
                outputs[num_outputs - 1] = paid_with;

                let kernel = with_outputs(&kernel, outputs);
                let witness = order.fill(&kernel).unwrap();
                let (aet, _) = VM::trace_execution(
                    program.clone(),
                    public_input(&kernel),
                    witness.nondeterminism(),
                )
                .unwrap();
                println!(
                    "               {num_outputs:7}  {:6}  {:13}",
                    aet.processor_trace.nrows(),
                    aet.padded_height()
                );
            }
        }
    }

    /// A spender who points one past the last output, at an admissible record
    /// they placed in memory right after the authenticated outputs, is stopped
    /// by the index check and by nothing else.
    #[proptest(cases = 20)]
    fn fill_past_the_last_output_crashes(
        #[strategy(arb())] cancel_post_image: Digest,
        #[strategy(arb())] admissible_output: AdditionRecord,
        #[strategy(arb())] kernel: TransactionKernel,
    ) {
        let order = SsoLockScript {
            cancel_post_image,
            admissible_outputs: vec![admissible_output],
        };
        prop_assume!(!kernel.outputs.contains(&admissible_output));

        let num_outputs = kernel.outputs.len();
        let outputs_size = kernel.outputs.encode().len();
        let tokens = [
            vec![BFieldElement::new(0); Digest::LEN],
            bfe_vec![outputs_size as u64, num_outputs as u64],
        ]
        .concat();

        let mut ram = std::collections::HashMap::new();
        encode_to_memory(&mut ram, SsoLockScript::OUTPUTS_ADDRESS, &kernel.outputs);
        encode_to_memory(
            &mut ram,
            SsoLockScript::OUTPUTS_ADDRESS + bfe!(outputs_size as u64),
            &admissible_output,
        );

        let nondeterminism = NonDeterminism::new(tokens)
            .with_digests(kernel.mast_path(TransactionKernelField::Outputs))
            .with_ram(ram);

        let error = VM::run(
            order.lock_script().program,
            public_input(&kernel),
            nondeterminism,
        )
        .unwrap_err();
        let InstructionError::AssertionFailed(assertion) = error.source else {
            panic!("expected a failed assertion, got {}", error.source);
        };
        prop_assert_eq!(Some(SsoLockScript::OUTPUT_INDEX_ERROR), assertion.id);
    }
}
