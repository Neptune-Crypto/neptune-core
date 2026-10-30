use itertools::Itertools;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_mutator_set::shared::BATCH_SIZE;
use neptune_mutator_set::shared::CHUNK_SIZE;
use neptune_mutator_set::shared::NUM_TRIALS;
use neptune_mutator_set::shared::WINDOW_SIZE;
use tasm_lib::arithmetic::i128::lt::Lt as I128Lt;
use tasm_lib::arithmetic::u128::lt::Lt as U128Lt;
use tasm_lib::arithmetic::u128::overflowing_add::OverflowingAdd;
use tasm_lib::arithmetic::u128::safe_add::SafeAdd;
use tasm_lib::arithmetic::u128::shift_left_static::ShiftLeftStatic;
use tasm_lib::arithmetic::u128::shift_right_static::ShiftRightStatic;
use tasm_lib::arithmetic::u128::sub::Sub as U128Sub;
use tasm_lib::arithmetic::u64::lt::Lt as U64Lt;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::list::get::Get;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;

use crate::block::block_validation_error::BlockValidationRule;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::transaction::announcement::Announcement;
use crate::transaction::transparent_input::TransparentInput;
use crate::transaction::utxo::Coin;
use crate::transaction::utxo::Utxo;
use crate::transaction::validity::tasm::compute_absolute_indices::ComputeAbsoluteIndices;
use crate::type_scripts::native_currency::NativeCurrency;
use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

/// The amount of native currency a transaction lustrates, as
/// [`TransactionKernel::verified_lustration_amount`] computes it with the
/// double-counting fix: every input whose AOCL range starts at or below the
/// threshold must have a lustration announcement that decodes to a
/// transparent input with the input's index set, and the announced UTXO's
/// native currency counts if its AOCL leaf index is at or below the
/// threshold.
///
/// ```text
/// BEFORE: _ *inputs *lustrations [max_lustrating_aocl_leaf_index: u64]
/// AFTER:  _ [amount: i128]
/// ```
///
/// `*inputs` lists the transaction's removal records, `*lustrations`
/// pointers to the messages of the announcements that carry the lustration
/// flag. The prover supplies, for each input that must lustrate, the
/// position in `*lustrations` of an announcement for it. Any announcement
/// with the input's index set serves, as the index set determines the UTXO.
///
/// The native currency of a UTXO is the sum of the states of its coins
/// under the native currency type script that decode as amounts, wrapping
/// as the archival sum does. Crashes with the error ID of rule 2.o if the
/// announcement at a position does not decode to a transparent input with
/// the input's index set, and with that of the unknown lustration problem
/// if an input's AOCL range is not representable or the amounts do not sum
/// to a representable amount.
///
/// [`TransactionKernel::verified_lustration_amount`]: crate::transaction::transaction_kernel::TransactionKernel::verified_lustration_amount
#[derive(Debug, Copy, Clone)]
pub(super) struct VerifiedLustrationAmount;

impl VerifiedLustrationAmount {
    const INDEX_SET_LEN: u32 = NUM_TRIALS + 4;

    /// The transparent input a lustration announcement's message encodes
    /// after its flag, as the kernel decodes it: the words after the flag
    /// must be exactly one encoding. Crashes with the error ID of rule 2.o
    /// otherwise.
    ///
    /// ```text
    /// BEFORE: _ *message
    /// AFTER:  _ *transparent_input
    /// ```
    fn decode_announcement(library: &mut Library) -> Vec<LabelledInstruction> {
        let audit_transparent_input =
            library.import(Box::new(VerifyNdSiIntegrity::<TransparentInput>::default()));

        triton_asm!(
            read_mem 1 addi 3
            // _ message_length *transparent_input

            dup 0 call {audit_transparent_input}
            // _ message_length *transparent_input size

            pick 2 addi -1 eq assert error_id {BlockValidationRule::MissingLustrationAnnouncement.error_id()}
            // _ *transparent_input
        )
    }

    /// The tokens the prover supplies: for each input whose AOCL range
    /// starts at or below the threshold, the position among the flagged
    /// announcements of the first one that decodes to a transparent input
    /// with the input's index set.
    pub(crate) fn divined_tokens(
        inputs: &[RemovalRecord],
        announcements: &[Announcement],
        max_lustrating_aocl_leaf_index: u64,
    ) -> Vec<BFieldElement> {
        let lustrations = announcements
            .iter()
            .filter(|announcement| announcement.looks_like_lustration())
            .collect_vec();
        let mut tokens = vec![];
        for input in inputs {
            let Ok((range_start, _)) = input.absolute_indices.aocl_range() else {
                break;
            };
            if range_start > max_lustrating_aocl_leaf_index {
                continue;
            }
            let position = lustrations
                .iter()
                .position(|announcement| {
                    TransparentInput::decode(&announcement.message[1..])
                        .is_ok_and(|decoded| decoded.absolute_index_set() == input.absolute_indices)
                })
                .unwrap_or_default();
            tokens.push(bfe!(position as u64));
        }
        tokens
    }
}

impl BasicSnippet for VerifiedLustrationAmount {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (
                DataType::List(Box::new(DataType::VoidPointer)),
                "*inputs".to_string(),
            ),
            (
                DataType::List(Box::new(DataType::VoidPointer)),
                "*lustrations".to_string(),
            ),
            (DataType::U64, "max_lustrating_aocl_leaf_index".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(DataType::I128, "amount".to_string())]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_verified_lustration_amount".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let entrypoint = self.entrypoint();
        let inputs_loop = format!("{entrypoint}_inputs_loop");
        let lustrate = format!("{entrypoint}_lustrate");
        let add_utxo_amount = format!("{entrypoint}_add_utxo_amount");
        let coins_loop = format!("{entrypoint}_coins_loop");
        let add_coin = format!("{entrypoint}_add_coin");
        let checked_add = format!("{entrypoint}_checked_add");
        let aocl_range = format!("{entrypoint}_aocl_range");
        let saturating_sub = format!("{entrypoint}_saturating_sub");
        let saturating_sub_positive = format!("{entrypoint}_saturating_sub_positive");
        let saturating_sub_zero = format!("{entrypoint}_saturating_sub_zero");

        let u64_lt = library.import(Box::new(U64Lt));
        let u128_lt = library.import(Box::new(U128Lt));
        let i128_lt = library.import(Box::new(I128Lt));
        let u128_safe_add = library.import(Box::new(SafeAdd));
        let u128_overflowing_add = library.import(Box::new(OverflowingAdd));
        let u128_sub = library.import(Box::new(U128Sub));
        let shr_log2_chunk_size =
            library.import(Box::new(ShiftRightStatic::<{ CHUNK_SIZE.ilog2() as u8 }>));
        let shl_log2_batch_size =
            library.import(Box::new(ShiftLeftStatic::<{ BATCH_SIZE.ilog2() as u8 }>));
        let hash_varlen = library.import(Box::new(HashVarlen));
        let get_pointer = library.import(Box::new(Get::new(DataType::Bfe)));
        let decode_announcement = Self::decode_announcement(library);
        let compute_absolute_indices = library.import(Box::new(ComputeAbsoluteIndices));

        let index_set_len = Self::INDEX_SET_LEN;
        let minimum_offset = NUM_TRIALS + DataType::U128.stack_size() as u32 - 1;

        let push_u128 = |value: u32| triton_asm!(push 0 push 0 push 0 push {value});
        // A u128 on top of the stack fits in a u64.
        let fits_in_u64 = triton_asm!(
            dup 3 push 0 eq dup 3 push 0 eq mul
            assert error_id {BlockValidationRule::UnknownLustrationProblem.error_id()}
        );
        // The sign bit of the i128 limb on top of the stack.
        let sign = triton_asm!(push {1_u64 << 31} swap 1 lt push 0 eq);
        let native_currency_hash = NativeCurrency
            .hash()
            .values()
            .into_iter()
            .rev()
            .flat_map(|limb| triton_asm!(push { limb }))
            .collect_vec();
        let push_max_amount = NativeCurrencyAmount::max().push_to_stack();
        let push_min_amount = NativeCurrencyAmount::min().push_to_stack();

        // The larger of the running maximum and the distance under the
        // pointer, and the pointer to the previous distance.
        // BEFORE: _ max *distance
        // AFTER:  _ max' *previous_distance
        let max_with_distance = triton_asm!(
            read_mem 1 swap 1
            dup 2 dup 1 lt push 0 eq
            skiz swap 2
            pop 1
        );
        let max_of_distances = vec![max_with_distance; NUM_TRIALS as usize].concat();

        triton_asm!(
            {entrypoint}:
                // _ *inputs *lustrations [threshold]
                push 0 push 0 push 0 push 0
                // _ *inputs *lustrations [threshold] [amount]

                pick 7 read_mem 1 addi 2 place 1 push 0
                // _ *lustrations [threshold] [amount] *inputs[0]_si num_inputs 0

                call {inputs_loop}
                pop 3
                // _ *lustrations [threshold] [amount]

                pick 6 pop 1 pick 5 pop 1 pick 4 pop 1
                // _ [amount]

                return

            // INVARIANT: _ *lustrations [threshold] [amount] *inputs[i]_si num_inputs i
            {inputs_loop}:
                dup 1 dup 1 eq skiz return
                // _ *lustrations [threshold] [amount] *inputs[i]_si num_inputs i

                dup 2 addi 1 {&field!(RemovalRecord::absolute_indices)}
                // _ *lustrations [threshold] [amount] *inputs[i]_si num_inputs i *index_set

                dup 0 call {aocl_range}
                // _ *lustrations [threshold] [amount] *inputs[i]_si num_inputs i *index_set [range_start]

                dup 11 dup 11 call {u64_lt}
                // _ *lustrations [threshold] [amount] *inputs[i]_si num_inputs i *index_set (threshold < range_start)

                push 0 eq
                // _ *lustrations [threshold] [amount] *inputs[i]_si num_inputs i *index_set must_lustrate

                skiz call {lustrate}
                pop 1
                // _ *lustrations [threshold] [amount] *inputs[i]_si num_inputs i

                pick 2 read_mem 1
                // _ *lustrations [threshold] [amount] num_inputs i input_size (*inputs[i]_si - 1)

                // Crashes unless the size is a u32.
                dup 1 pop_count pop 1

                addi 2 add place 2 addi 1
                // _ *lustrations [threshold] [amount] *inputs[i + 1]_si num_inputs (i + 1)

                recurse

            // Adds the native currency of the announcement the prover
            // points to for the input with this index set, if the
            // announcement's AOCL leaf index is at or below the threshold.
            // BEFORE: _ *lustrations [threshold] [amount] *inputs[i]_si num_inputs i *index_set
            // AFTER:  _ *lustrations [threshold] [amount'] *inputs[i]_si num_inputs i *index_set
            {lustrate}:
                divine 1
                // _ ... *index_set position

                dup 11 read_mem 1 pop 1 dup 1 lt
                assert error_id {BlockValidationRule::MissingLustrationAnnouncement.error_id()}
                // _ ... *index_set position

                dup 11 pick 1 call {get_pointer}
                // _ ... *index_set *message

                {&decode_announcement}
                // _ ... *index_set *transparent_input

                dup 0 {&field!(TransparentInput::aocl_leaf_index)} addi 1 read_mem 2 pop 1
                // _ ... *index_set *transparent_input [aocl_leaf_index]

                dup 2 {&field!(TransparentInput::receiver_preimage)} addi 4 read_mem 5 pop 1
                // _ ... *index_set *transparent_input [aocl_leaf_index] [receiver_preimage]

                dup 7 {&field!(TransparentInput::sender_randomness)} addi 4 read_mem 5 pop 1
                // _ ... *index_set *transparent_input [aocl_leaf_index] [receiver_preimage] [sender_randomness]

                dup 12 {&field_with_size!(TransparentInput::utxo)} call {hash_varlen}
                // _ ... *index_set *transparent_input [aocl_leaf_index] [receiver_preimage] [sender_randomness] [item]

                call {compute_absolute_indices}
                // _ ... *index_set *transparent_input *announced_index_set

                push {index_set_len} call {hash_varlen}
                dup 6 push {index_set_len} call {hash_varlen}
                // _ ... *index_set *transparent_input [announced_index_set_digest] [index_set_digest]

                assert_vector error_id {BlockValidationRule::MissingLustrationAnnouncement.error_id()}
                pop 5
                // _ ... *index_set *transparent_input

                dup 0 {&field!(TransparentInput::aocl_leaf_index)} addi 1 read_mem 2 pop 1
                // _ *lustrations [threshold] [amount] *inputs[i]_si num_inputs i *index_set *transparent_input [aocl_leaf_index]

                dup 12 dup 12 call {u64_lt}
                // _ ... *index_set *transparent_input (threshold < aocl_leaf_index)

                push 0 eq
                // _ ... *index_set *transparent_input is_before_barrier

                skiz call {add_utxo_amount}
                pop 1
                // _ ... *index_set

                return

            // BEFORE: _ *lustrations [threshold] [amount] *inputs[i]_si num_inputs i *index_set *transparent_input
            // AFTER:  _ *lustrations [threshold] [amount'] *inputs[i]_si num_inputs i *index_set *transparent_input
            {add_utxo_amount}:
                dup 0 {&field!(TransparentInput::utxo)} {&field!(Utxo::coins)}
                // _ ... *transparent_input *coins

                read_mem 1 addi 2 place 1 push 0
                push 0 push 0 push 0 push 0
                // _ ... *transparent_input *coins[0]_si num_coins 0 [utxo_amount]

                call {coins_loop}
                // _ ... *transparent_input *coins[num_coins]_si num_coins num_coins [utxo_amount]

                pick 6 pop 1 pick 5 pop 1 pick 4 pop 1
                // _ *lustrations [threshold] [amount] *inputs[i]_si num_inputs i *index_set *transparent_input [utxo_amount]

                pick 12 pick 12 pick 12 pick 12
                // _ *lustrations [threshold] *inputs[i]_si num_inputs i *index_set *transparent_input [utxo_amount] [amount]

                call {checked_add}
                // _ *lustrations [threshold] *inputs[i]_si num_inputs i *index_set *transparent_input [amount']

                pick 8 pick 8 pick 8 pick 8 pick 8
                // _ *lustrations [threshold] [amount'] *inputs[i]_si num_inputs i *index_set *transparent_input

                return

            // INVARIANT: _ *coins[j]_si num_coins j [utxo_amount]
            {coins_loop}:
                dup 5 dup 5 eq skiz return
                // _ *coins[j]_si num_coins j [utxo_amount]

                dup 6 addi 1
                // _ *coins[j]_si num_coins j [utxo_amount] *coin

                dup 0 {&field!(Coin::type_script_hash)} addi 4 read_mem 5 pop 1
                {&native_currency_hash}
                {&DataType::Digest.compare()}
                // _ *coins[j]_si num_coins j [utxo_amount] *coin is_native_currency

                skiz call {add_coin}
                pop 1
                // _ *coins[j]_si num_coins j [utxo_amount]

                pick 6 read_mem 1
                // _ num_coins j [utxo_amount] coin_size (*coins[j]_si - 1)

                // Crashes unless the size is a u32.
                dup 1 pop_count pop 1

                addi 2 add place 6
                pick 4 addi 1 place 4
                // _ *coins[j + 1]_si num_coins (j + 1) [utxo_amount]

                recurse

            // Adds the coin's state if it decodes as an amount: four words,
            // each a u32. The sum wraps, as the archival sum does.
            // BEFORE: _ [utxo_amount] *coin
            // AFTER:  _ [utxo_amount'] *coin
            {add_coin}:
                dup 0 {&field!(Coin::state)}
                // _ [utxo_amount] *coin *state

                read_mem 1 swap 1 push 4 eq
                // _ [utxo_amount] *coin (*state - 1) (state_length == 4)

                swap 1 addi 5 read_mem 4 pop 1
                // _ [utxo_amount] *coin (state_length == 4) [value]

                dup 0 split pop 1 push 0 eq
                dup 2 split pop 1 push 0 eq mul
                dup 3 split pop 1 push 0 eq mul
                dup 4 split pop 1 push 0 eq mul
                pick 5 mul
                // _ [utxo_amount] *coin [value] decodes

                dup 0 pick 2 mul place 1
                dup 0 pick 3 mul place 2
                dup 0 pick 4 mul place 3
                dup 0 pick 5 mul place 4
                pop 1
                // _ [utxo_amount] *coin [value * decodes]

                pick 4 place 8
                // _ *coin [utxo_amount] [value * decodes]

                call {u128_overflowing_add} pop 1
                // _ *coin [utxo_amount']

                pick 4
                // _ [utxo_amount'] *coin

                return

            // The sum of two amounts, which must be a representable amount.
            // BEFORE: _ [a: i128] [b: i128]
            // AFTER:  _ [a + b: i128]
            {checked_add}:
                dup 7 {&sign}
                dup 4 {&sign}
                // _ [a] [b] sign_a sign_b

                dup 1 eq place 9 place 9
                // _ sign_a same_sign [a] [b]

                call {u128_overflowing_add} pop 1
                // _ sign_a same_sign [sum]

                dup 3 {&sign} pick 6 eq
                // _ same_sign [sum] (sign_sum == sign_a)

                pick 5 swap 1 push 0 eq mul
                // _ [sum] (same_sign && sign_sum != sign_a)

                push 0 eq assert error_id {BlockValidationRule::UnknownLustrationProblem.error_id()}
                // _ [sum]

                dup 3 dup 3 dup 3 dup 3 {&push_max_amount} call {i128_lt}
                push 0 eq assert error_id {BlockValidationRule::UnknownLustrationProblem.error_id()}
                // _ [sum]

                {&push_min_amount} dup 7 dup 7 dup 7 dup 7 call {i128_lt}
                push 0 eq assert error_id {BlockValidationRule::UnknownLustrationProblem.error_id()}
                // _ [sum]

                return

            // The start of the AOCL range an index set implies, which must be
            // representable along with its end.
            // BEFORE: _ *index_set
            // AFTER:  _ [range_start: u64]
            {aocl_range}:
                dup 0 addi {NUM_TRIALS - 1} push 0 swap 1
                // _ *index_set 0 *distances[last]

                {&max_of_distances}
                pop 1
                // _ *index_set max_offset

                push {WINDOW_SIZE} dup 1 lt assert error_id {BlockValidationRule::UnknownLustrationProblem.error_id()}
                // _ *index_set max_offset

                dup 1 addi {minimum_offset} read_mem 4 pop 1
                push 0 push 0 push 0 pick 7
                // _ *index_set [minimum] [max_offset]

                call {u128_safe_add}
                // _ *index_set [max_index]

                {&push_u128(WINDOW_SIZE - 1)}
                call {saturating_sub}
                {&push_u128(CHUNK_SIZE - 1)}
                call {u128_safe_add}
                call {shr_log2_chunk_size}
                // _ *index_set [first_batch]

                {&fits_in_u64}
                call {shl_log2_batch_size}
                {&fits_in_u64}
                // _ *index_set [range_start: u128]

                pick 3 pop 1 pick 2 pop 1
                // _ *index_set [range_start: u64]

                pick 2 addi {minimum_offset} read_mem 4 pop 1
                // _ [range_start] [minimum]

                {&push_u128(WINDOW_SIZE + CHUNK_SIZE)}
                call {u128_safe_add}
                call {shr_log2_chunk_size}
                {&push_u128(WINDOW_SIZE / CHUNK_SIZE + 1)}
                call {saturating_sub}
                // _ [range_start] [last_batch]

                {&fits_in_u64}
                call {shl_log2_batch_size}
                {&push_u128(BATCH_SIZE - 1)}
                call {u128_safe_add}
                {&fits_in_u64}
                pop 4
                // _ [range_start]

                return

            // BEFORE: _ [minuend: u128] [subtrahend: u128]
            // AFTER:  _ [minuend.saturating_sub(subtrahend): u128]
            {saturating_sub}:
                dup 7 dup 7 dup 7 dup 7
                dup 7 dup 7 dup 7 dup 7
                call {u128_lt}
                // _ [minuend] [subtrahend] (subtrahend < minuend)

                dup 0 skiz call {saturating_sub_positive}
                push 0 eq skiz call {saturating_sub_zero}
                return

            // BEFORE: _ [minuend] [subtrahend] 1
            // AFTER:  _ [minuend - subtrahend] 1
            {saturating_sub_positive}:
                pop 1
                pick 7 pick 7 pick 7 pick 7
                call {u128_sub}
                push 1
                return

            // BEFORE: _ [minuend] [subtrahend]
            // AFTER:  _ [0]
            {saturating_sub_zero}:
                pop 5 pop 3
                push 0 push 0 push 0 push 0
                return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;

    use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
    use neptune_mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
    use neptune_primitives::timestamp::Timestamp;
    use num_traits::Zero;
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::triton_vm::isa::instruction::AssertionError;
    use tasm_lib::triton_vm::isa::instruction::InstructionError;
    use tasm_lib::triton_vm::vm::VMState;

    use super::*;
    use crate::transaction::transaction_kernel::TransactionKernel;
    use crate::transaction::transaction_kernel::TransactionKernelProxy;
    use crate::transaction::transaction_kernel::TransactionLustrationError;
    use crate::transaction::transaction_kernel::LUSTRATION_FLAG;
    use crate::type_scripts::time_lock::TimeLock;

    const INPUTS_POINTER: BFieldElement = BFieldElement::new(1 << 20);
    const LUSTRATIONS_POINTER: BFieldElement = BFieldElement::new(1 << 21);
    const MESSAGES_POINTER: BFieldElement = BFieldElement::new(1 << 22);

    fn transparent_input(rng: &mut StdRng, utxo: Utxo, aocl_leaf_index: u64) -> TransparentInput {
        TransparentInput {
            utxo,
            aocl_leaf_index,
            sender_randomness: rng.random(),
            receiver_preimage: rng.random(),
        }
    }

    fn native_input(
        rng: &mut StdRng,
        amount: NativeCurrencyAmount,
        aocl_leaf_index: u64,
    ) -> TransparentInput {
        let utxo = Utxo::new_native_currency(rng.random(), amount);
        transparent_input(rng, utxo, aocl_leaf_index)
    }

    fn record(input: &TransparentInput) -> RemovalRecord {
        RemovalRecord {
            absolute_indices: input.absolute_index_set(),
            target_chunks: ChunkDictionary::empty(),
        }
    }

    fn kernel(inputs: &[RemovalRecord], announcements: &[Announcement]) -> TransactionKernel {
        TransactionKernelProxy {
            inputs: inputs.to_vec(),
            outputs: vec![],
            announcements: announcements.to_vec(),
            fee: NativeCurrencyAmount::zero(),
            coinbase: None,
            timestamp: Timestamp::now(),
            mutator_set_hash: Digest::default(),
            merge_bit: true,
        }
        .into_kernel()
    }

    fn expected(
        inputs: &[RemovalRecord],
        announcements: &[Announcement],
        threshold: u64,
    ) -> Result<NativeCurrencyAmount, TransactionLustrationError> {
        kernel(inputs, announcements).verified_lustration_amount(threshold, true)
    }

    fn run(
        inputs: &[RemovalRecord],
        announcements: &[Announcement],
        threshold: u64,
    ) -> Result<NativeCurrencyAmount, InstructionError> {
        let mut library = Library::new();
        let snippet = library.import(Box::new(VerifiedLustrationAmount));
        let [threshold_lo, threshold_hi] = threshold.encode().try_into().unwrap();
        let program = Program::new(&triton_asm!(
            push {INPUTS_POINTER} push {LUSTRATIONS_POINTER}
            push {threshold_hi} push {threshold_lo}
            call {snippet}
            write_io 4
            halt
            {&library.all_imports()}
        ));

        let mut ram = HashMap::new();
        encode_to_memory(&mut ram, INPUTS_POINTER, &inputs.to_vec());
        let mut pointers = vec![];
        for (i, announcement) in announcements
            .iter()
            .filter(|announcement| announcement.looks_like_lustration())
            .enumerate()
        {
            let pointer = MESSAGES_POINTER + bfe!((i as u64) << 12);
            encode_to_memory(&mut ram, pointer, &announcement.message);
            pointers.push(pointer);
        }
        encode_to_memory(&mut ram, LUSTRATIONS_POINTER, &pointers);

        let tokens = VerifiedLustrationAmount::divined_tokens(inputs, announcements, threshold);
        let nondeterminism = NonDeterminism::new(tokens).with_ram(ram);
        let mut state = VMState::new(program, PublicInput::default(), nondeterminism);
        state.run()?;
        let amount = NativeCurrencyAmount::decode(&state.public_output).unwrap();
        Ok(*amount)
    }

    fn assert_agrees(inputs: &[RemovalRecord], announcements: &[Announcement], threshold: u64) {
        let expected = expected(inputs, announcements, threshold).unwrap();
        assert_eq!(expected, run(inputs, announcements, threshold).unwrap());
    }

    fn assert_crashes(
        inputs: &[RemovalRecord],
        announcements: &[Announcement],
        threshold: u64,
        error_id: i128,
    ) {
        assert!(expected(inputs, announcements, threshold).is_err());
        let Err(
            InstructionError::AssertionFailed(AssertionError { id, .. })
            | InstructionError::VectorAssertionFailed(_, AssertionError { id, .. }),
        ) = run(inputs, announcements, threshold)
        else {
            panic!("must crash");
        };
        assert_eq!(Some(error_id), id);
    }

    /// Three inputs spending native currency, at increasing AOCL leaf
    /// indices, with their announcements.
    fn three_inputs(rng: &mut StdRng) -> (Vec<TransparentInput>, Vec<Announcement>) {
        let inputs = [(5, 1_000), (7, 1_000_003), (11, 1 << 40)]
            .map(|(coins, aocl_leaf_index)| {
                native_input(rng, NativeCurrencyAmount::coins(coins), aocl_leaf_index)
            })
            .to_vec();
        let announcements = inputs
            .iter()
            .map(Announcement::lustration_announcement)
            .collect_vec();
        (inputs, announcements)
    }

    #[test]
    fn index_set_encodes_distances_then_minimum() {
        let mut rng = StdRng::seed_from_u64(0);
        let input = native_input(&mut rng, NativeCurrencyAmount::coins(1), 77);
        let encoding = input.absolute_index_set().encode();
        assert_eq!(
            VerifiedLustrationAmount::INDEX_SET_LEN as usize,
            encoding.len()
        );
        let minimum = *input.absolute_index_set().to_vec().iter().min().unwrap();
        assert_eq!(
            minimum.encode(),
            encoding[VerifiedLustrationAmount::INDEX_SET_LEN as usize - 4..]
        );
    }

    #[test]
    fn amount_agrees_with_kernel_at_every_threshold() {
        let mut rng = StdRng::seed_from_u64(1);
        let (inputs, announcements) = three_inputs(&mut rng);
        let records = inputs.iter().map(record).collect_vec();
        for threshold in [0, 999, 1_000, 999_999, 1_000_000, 1 << 40, u64::MAX] {
            assert_agrees(&records, &announcements, threshold);
        }
    }

    #[test]
    fn input_at_the_barrier_must_lustrate_but_does_not_count() {
        let mut rng = StdRng::seed_from_u64(2);
        let (inputs, announcements) = three_inputs(&mut rng);
        let records = inputs.iter().map(record).collect_vec();
        let (range_start, _) = records[1].absolute_indices.aocl_range().unwrap();
        assert!(range_start < inputs[1].aocl_leaf_index);
        let threshold = inputs[1].aocl_leaf_index - 1;

        assert_eq!(
            NativeCurrencyAmount::coins(5),
            run(&records, &announcements, threshold).unwrap()
        );
        assert_agrees(&records, &announcements, threshold);
        assert_crashes(
            &records,
            &announcements[..1],
            threshold,
            BlockValidationRule::MissingLustrationAnnouncement.error_id(),
        );
    }

    #[test]
    fn announcements_that_match_no_input_are_ignored() {
        let mut rng = StdRng::seed_from_u64(3);
        let (inputs, announcements) = three_inputs(&mut rng);
        let records = inputs.iter().map(record).collect_vec();
        let stranger = native_input(&mut rng, NativeCurrencyAmount::coins(1000), 3);
        let mut truncated = announcements[0].clone();
        truncated.message.pop();
        let announcements = [
            vec![
                Announcement::new(vec![]),
                Announcement::new(vec![LUSTRATION_FLAG]),
                truncated,
                Announcement::lustration_announcement(&stranger),
                announcements[1].clone(),
                Announcement::new(vec![bfe!(1), bfe!(2)]),
            ],
            announcements,
        ]
        .concat();

        assert_agrees(&records, &announcements, u64::MAX);
    }

    #[test]
    fn missing_or_wrong_announcement_crashes() {
        let mut rng = StdRng::seed_from_u64(4);
        let (inputs, announcements) = three_inputs(&mut rng);
        let records = inputs.iter().map(record).collect_vec();
        let missing = BlockValidationRule::MissingLustrationAnnouncement.error_id();

        assert_crashes(&records, &announcements[1..], u64::MAX, missing);
        assert_crashes(&records, &[], u64::MAX, missing);

        let mut other_amount = inputs[0].clone();
        other_amount.utxo = Utxo::new_native_currency(rng.random(), NativeCurrencyAmount::coins(6));
        let mut announcements = announcements;
        announcements[0] = Announcement::lustration_announcement(&other_amount);
        assert_crashes(&records, &announcements, u64::MAX, missing);
    }

    #[test]
    fn coins_count_as_the_archival_sum_does() {
        let mut rng = StdRng::seed_from_u64(5);
        let native = |amount: NativeCurrencyAmount| Coin {
            type_script_hash: NativeCurrency.hash(),
            state: amount.encode(),
        };
        let coins = vec![
            native(NativeCurrencyAmount::coins(10)),
            Coin {
                type_script_hash: TimeLock.hash(),
                state: NativeCurrencyAmount::coins(100).encode(),
            },
            native(-NativeCurrencyAmount::coins(3)),
            Coin {
                type_script_hash: NativeCurrency.hash(),
                state: vec![bfe!(1), bfe!(2), bfe!(3)],
            },
            Coin {
                type_script_hash: NativeCurrency.hash(),
                state: vec![bfe!(1), bfe!(2), bfe!(3), bfe!(1_u64 << 32)],
            },
            Coin {
                type_script_hash: NativeCurrency.hash(),
                state: vec![],
            },
        ];
        let lock_script_hash = rng.random();
        let input = transparent_input(&mut rng, Utxo::new(lock_script_hash, coins), 9);
        let records = vec![record(&input)];
        let announcements = vec![Announcement::lustration_announcement(&input)];

        assert_eq!(
            NativeCurrencyAmount::coins(7),
            run(&records, &announcements, u64::MAX).unwrap()
        );
        assert_agrees(&records, &announcements, u64::MAX);
    }

    #[test]
    fn unrepresentable_sum_crashes() {
        let mut rng = StdRng::seed_from_u64(6);
        let inputs = [1, 2]
            .map(|aocl_leaf_index| {
                native_input(&mut rng, NativeCurrencyAmount::max(), aocl_leaf_index)
            })
            .to_vec();
        let records = inputs.iter().map(record).collect_vec();
        let announcements = inputs
            .iter()
            .map(Announcement::lustration_announcement)
            .collect_vec();

        assert_agrees(&records[..1], &announcements, u64::MAX);
        assert_crashes(
            &records,
            &announcements,
            u64::MAX,
            BlockValidationRule::UnknownLustrationProblem.error_id(),
        );
    }

    #[test]
    fn index_set_beyond_the_window_crashes() {
        let mut rng = StdRng::seed_from_u64(7);
        let input = native_input(&mut rng, NativeCurrencyAmount::coins(1), 20);
        let mut encoding = input.absolute_index_set().encode();
        encoding[0] = bfe!(WINDOW_SIZE);
        let record = RemovalRecord {
            absolute_indices: *AbsoluteIndexSet::decode(&encoding).unwrap(),
            target_chunks: ChunkDictionary::empty(),
        };
        let announcements = vec![Announcement::lustration_announcement(&input)];

        assert_crashes(
            &[record],
            &announcements,
            u64::MAX,
            BlockValidationRule::UnknownLustrationProblem.error_id(),
        );
    }

    #[test]
    fn range_start_agrees_with_kernel_for_every_aocl_leaf_index() {
        let mut rng = StdRng::seed_from_u64(8);
        for aocl_leaf_index in [
            0,
            1,
            7,
            8,
            255,
            256,
            2047,
            2048,
            2049,
            1 << 32,
            u64::MAX >> 1,
        ] {
            let input = native_input(&mut rng, NativeCurrencyAmount::coins(1), aocl_leaf_index);
            let records = vec![record(&input)];
            let announcements = vec![Announcement::lustration_announcement(&input)];
            let (range_start, _) = records[0].absolute_indices.aocl_range().unwrap();
            for threshold in [range_start.saturating_sub(1), range_start, aocl_leaf_index] {
                assert_agrees(&records, &announcements, threshold);
            }
        }
    }

    /// Whether the program takes the message for a lustration announcement's
    /// whose words after the flag encode a transparent input.
    fn program_decodes(message: &[BFieldElement]) -> bool {
        let mut library = Library::new();
        let decode_announcement = VerifiedLustrationAmount::decode_announcement(&mut library);
        let program = Program::new(&triton_asm!(
            push {MESSAGES_POINTER}
            {&decode_announcement}
            halt
            {&library.all_imports()}
        ));
        let mut ram = HashMap::new();
        encode_to_memory(&mut ram, MESSAGES_POINTER, &message.to_vec());
        let nondeterminism = NonDeterminism::default().with_ram(ram);
        VMState::new(program, PublicInput::default(), nondeterminism)
            .run()
            .is_ok()
    }

    fn kernel_decodes(message: &[BFieldElement]) -> bool {
        TransparentInput::decode(&message[1..]).is_ok()
    }

    fn random_transparent_input(rng: &mut StdRng) -> TransparentInput {
        let coins = (0..rng.random_range(0..4))
            .map(|_| Coin {
                type_script_hash: rng.random(),
                state: (0..rng.random_range(0..6))
                    .map(|_| bfe!(rng.random::<u32>()))
                    .collect(),
            })
            .collect();
        let utxo = Utxo::new(rng.random(), coins);
        let aocl_leaf_index = rng.random();
        transparent_input(rng, utxo, aocl_leaf_index)
    }

    /// The program's decoding must agree with the kernel's on every
    /// announcement the kernel decodes. Where the program accepts and the
    /// kernel does not, the only cause may be a non-canonical limb of the
    /// AOCL leaf index, which the index set recomputation then rejects.
    #[test]
    fn program_decodes_every_announcement_the_kernel_decodes() {
        let mut rng = StdRng::seed_from_u64(10);
        let mut kernel_only_rejections = 0;
        for _ in 0..100 {
            let input = random_transparent_input(&mut rng);
            let message = Announcement::lustration_announcement(&input).message;
            assert!(kernel_decodes(&message));
            assert!(program_decodes(&message));

            let mut other_leaf_index = input.clone();
            other_leaf_index.aocl_leaf_index ^= (1 << 40) | 1;
            let leaf_index_positions = message
                .iter()
                .zip(Announcement::lustration_announcement(&other_leaf_index).message)
                .positions(|(word, other)| *word != other)
                .collect_vec();
            assert_eq!(2, leaf_index_positions.len());

            for _ in 0..10 {
                let mut mutated = message.clone();
                let mut flipped = None;
                match rng.random_range(0..4) {
                    0 => mutated.truncate(rng.random_range(1..message.len())),
                    1 => mutated.push(rng.random()),
                    small_or_random => {
                        let position = rng.random_range(1..message.len());
                        mutated[position] = if small_or_random == 2 {
                            bfe!(rng.random_range(0..8_u64))
                        } else {
                            rng.random()
                        };
                        flipped = Some(position);
                    }
                }

                let kernel = kernel_decodes(&mutated);
                let program = program_decodes(&mutated);
                if kernel {
                    assert!(program, "{mutated:?}");
                }
                if program && !kernel {
                    let position = flipped.expect("only a flipped word decodes differently");
                    assert!(leaf_index_positions.contains(&position), "{mutated:?}");
                    assert!(mutated[position].value() > u64::from(u32::MAX));
                    kernel_only_rejections += 1;
                }
            }
        }
        assert!(kernel_only_rejections > 0);
    }
}
