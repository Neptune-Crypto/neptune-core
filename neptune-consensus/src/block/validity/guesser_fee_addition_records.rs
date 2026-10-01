use tasm_lib::arithmetic::u128::shift_right_static::ShiftRightStatic;
use tasm_lib::arithmetic::u128::sub::Sub as U128Sub;
use tasm_lib::field;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::list::new::New;
use tasm_lib::list::push::Push;
use tasm_lib::neptune::mutator_set::commit::Commit;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use crate::block::block_header::BlockHeader;
use crate::block::block_kernel::BlockKernel;
use crate::block::block_validation_error::BlockValidationRule;
use crate::block::guesser_receiver_data::GuesserReceiverData;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::type_scripts::native_currency::NativeCurrency;
use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::type_scripts::time_lock::TimeLock;

/// The addition records of a block's guesser reward, as
/// [`BlockKernel::guesser_fee_addition_records`] computes them: the
/// commitment to a time-locked UTXO holding half the reward, then to an
/// unlocked UTXO holding the rest. The genesis block has none.
///
/// The UTXOs are built word for word as their encodings, so their hashes
/// agree with the hashes of the [`Utxo`](crate::transaction::utxo::Utxo)s.
///
/// ```text
/// BEFORE: _ *block_header [block_hash: Digest] [reward: NativeCurrencyAmount]
/// AFTER:  _ *addition_records
/// ```
///
/// The reward is the block's transaction fee. Crashes if it is negative.
#[derive(Debug, Copy, Clone)]
pub(super) struct GuesserFeeAdditionRecords;

impl GuesserFeeAdditionRecords {
    /// The encoded length of the unlocked UTXO: a coins field of one native
    /// currency coin, then the lock script hash.
    const UNLOCKED_UTXO_LEN: usize = 19;

    /// The encoded length of the time-locked UTXO: a coins field of a native
    /// currency coin and a time-lock coin, then the lock script hash.
    const LOCKED_UTXO_LEN: usize = 28;

    /// The words that precede the amount in the encoding of a UTXO whose
    /// coins field holds this many words: the size of the coins field, the
    /// number of coins, the size of the native currency coin, the size of its
    /// state, and the length of its state.
    fn native_coin_prefix(coins_field_size: u64, num_coins: u64) -> Vec<LabelledInstruction> {
        let amount_len = NativeCurrencyAmount::static_length().unwrap() as u64;
        triton_asm!(
            push {amount_len}
            push {amount_len + 1}
            push {amount_len + 1 + Digest::LEN as u64 + 1}
            push {num_coins}
            push {coins_field_size}
        )
    }

    /// Pushes the digest such that writing it to memory yields its encoding.
    fn push_digest(digest: Digest) -> Vec<LabelledInstruction> {
        digest
            .values()
            .into_iter()
            .rev()
            .flat_map(|word| triton_asm!(push { word }))
            .collect()
    }
}

impl BasicSnippet for GuesserFeeAdditionRecords {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*block_header".to_string()),
            (DataType::Digest, "block_hash".to_string()),
            (DataType::U128, "reward".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(
            DataType::List(Box::new(DataType::Digest)),
            "*addition_records".to_string(),
        )]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_guesser_fee_addition_records".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let new_list = library.import(Box::new(New));
        let push_digest = library.import(Box::new(Push::new(DataType::Digest)));
        let hash_varlen = library.import(Box::new(HashVarlen));
        let commit = library.import(Box::new(Commit));
        let halve = library.import(Box::new(ShiftRightStatic::<1>));
        let u128_sub = library.import(Box::new(U128Sub));

        let entrypoint = self.entrypoint();
        let non_genesis_branch = format!("{entrypoint}_non_genesis");
        let locked_record = format!("{entrypoint}_locked_record");
        let unlocked_record = format!("{entrypoint}_unlocked_record");

        let amount_len = NativeCurrencyAmount::static_length().unwrap();
        let read_digest = triton_asm!(addi {Digest::LEN - 1} read_mem {Digest::LEN} pop 1);
        let lock_period = BlockKernel::MINER_REWARD_TIME_LOCK_PERIOD.0;

        // The context the subroutines read: the reward, the block hash, the
        // header's pointer and the records list's pointer.
        let block_hash_offset = amount_len;
        let header_offset = block_hash_offset + Digest::LEN;
        let records_offset = header_offset + 1;
        let context_len = records_offset + 1;

        // Where the parts of each UTXO encoding sit in its buffer.
        let amount_offset = 5;
        let native_coin_hash_offset = amount_offset + amount_len;
        let time_lock_coin_offset = native_coin_hash_offset + Digest::LEN;
        let time_lock_hash_offset = time_lock_coin_offset + 4;
        let locked_lock_script_offset = time_lock_hash_offset + Digest::LEN;
        let unlocked_lock_script_offset = time_lock_coin_offset;
        assert_eq!(
            Self::LOCKED_UTXO_LEN,
            locked_lock_script_offset + Digest::LEN
        );
        assert_eq!(
            Self::UNLOCKED_UTXO_LEN,
            unlocked_lock_script_offset + Digest::LEN
        );

        // BEFORE: _ *context
        // AFTER:  _ *context *header
        let read_header_pointer = triton_asm!(dup 0 addi {header_offset} read_mem 1 pop 1);

        // Writes the UTXO's amount, the coins prefix and the native currency
        // coin's type script hash into a fresh buffer.
        // BEFORE: _ *context [amount]
        // AFTER:  _ *context *buffer
        let start_utxo = |coins_field_size: u64, num_coins: u64| {
            triton_asm!(
                call {new_list}
                // _ *context [amount] *buffer

                pick 4 pick 4 pick 4 pick 4
                // _ *context *buffer [amount]

                dup 4 addi {amount_offset} write_mem {amount_len} pop 1
                // _ *context *buffer

                {&Self::native_coin_prefix(coins_field_size, num_coins)}
                dup 5 write_mem 5 pop 1
                // _ *context *buffer

                {&Self::push_digest(NativeCurrency.hash())}
                dup 5 addi {native_coin_hash_offset} write_mem {Digest::LEN} pop 1
                // _ *context *buffer
            )
        };

        // Writes the lock script hash, hashes the buffer into the UTXO's
        // digest, commits to it, and appends the record to the list.
        // BEFORE: _ *context *buffer
        // AFTER:  _ *context
        let finish_utxo = |lock_script_offset: usize, utxo_len: usize| {
            triton_asm!(
                dup 1 {&read_header_pointer} place 1 pop 1
                {&field!(BlockHeader::guesser_receiver_data)}
                {&field!(GuesserReceiverData::lock_script_hash)} {&read_digest}
                dup 5 addi {lock_script_offset} write_mem {Digest::LEN} pop 1
                // _ *context *buffer

                push {utxo_len} call {hash_varlen}
                // _ *context [item]

                dup 5 {&read_header_pointer} place 1 pop 1
                {&field!(BlockHeader::guesser_receiver_data)}
                {&field!(GuesserReceiverData::receiver_digest)} {&read_digest}
                // _ *context [item] [receiver_digest]

                dup 10 addi {block_hash_offset + Digest::LEN - 1} read_mem {Digest::LEN} pop 1
                // _ *context [item] [receiver_digest] [block_hash]

                pick 14 pick 14 pick 14 pick 14 pick 14
                // _ *context [receiver_digest] [block_hash] [item]

                call {commit}
                // _ *context [record]

                dup 5 addi {records_offset} read_mem 1 pop 1
                place 5
                // _ *context *records [record]

                call {push_digest}
                // _ *context
            )
        };

        triton_asm!(
            {entrypoint}:
                // _ *header [block_hash] [reward]
                call {new_list}
                // _ *header [block_hash] [reward] *context

                write_mem {amount_len}
                write_mem {Digest::LEN}
                write_mem 1
                // _ (*context + header_offset + 1)

                call {new_list}
                pick 1 write_mem 1
                // _ (*context + context_len)

                addi {-(context_len as i64)}
                // _ *context

                {&read_header_pointer}
                {&field!(BlockHeader::height)} read_mem 1 pop 1
                push 0 eq push 0 eq
                // _ *context (height != 0)

                skiz call {non_genesis_branch}
                // _ *context

                addi {records_offset} read_mem 1 pop 1
                // _ *records

                return

            // BEFORE: _ *context
            // AFTER:  _ *context
            {non_genesis_branch}:
                dup 0 addi {amount_len - 1} read_mem {amount_len} pop 1
                // _ *context [reward]

                // The reward is the transaction fee, which must not be
                // negative. The sign bit is the top bit of the top limb.
                dup 3 push {1_u64 << 31} swap 1 lt
                assert error_id {BlockValidationRule::NegativeFee.error_id()}
                // _ *context [reward]

                dup 3 dup 3 dup 3 dup 3 call {halve}
                // _ *context [reward] [locked_amount]

                dup 8 place 4
                // _ *context [reward] *context [locked_amount]

                call {locked_record}
                pop 1
                // _ *context [reward]

                dup 3 dup 3 dup 3 dup 3 call {halve}
                pick 7 pick 7 pick 7 pick 7
                call {u128_sub}
                // _ *context [unlocked_amount]

                call {unlocked_record}
                // _ *context

                return

            // BEFORE: _ *context [amount]
            // AFTER:  _ *context
            {locked_record}:
                {&start_utxo(22, 2)}
                // _ *context *buffer

                // The time-lock coin: its size, its state's size, its state's
                // length, and the release date.
                dup 1 {&read_header_pointer} place 1 pop 1
                {&field!(BlockHeader::timestamp)} read_mem 1 pop 1
                addi {lock_period}
                push 1 push 2 push {Digest::LEN + 3}
                dup 4 addi {time_lock_coin_offset} write_mem 4 pop 1
                // _ *context *buffer

                {&Self::push_digest(TimeLock.hash())}
                dup 5 addi {time_lock_hash_offset} write_mem {Digest::LEN} pop 1
                // _ *context *buffer

                {&finish_utxo(locked_lock_script_offset, Self::LOCKED_UTXO_LEN)}
                // _ *context

                return

            // BEFORE: _ *context [amount]
            // AFTER:  _ *context
            {unlocked_record}:
                {&start_utxo(13, 1)}
                {&finish_utxo(unlocked_lock_script_offset, Self::UNLOCKED_UTXO_LEN)}
                return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;

    use neptune_mutator_set::commit;
    use neptune_primitives::block_height::BlockHeight;
    use num_traits::CheckedSub;
    use num_traits::Zero;
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::pop_encodable;
    use tasm_lib::rust_shadowing_helper_functions::dyn_malloc::dynamic_allocator;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::structure::tasm_object::TasmObject;
    use tasm_lib::test_helpers::test_assertion_failure;
    use tasm_lib::test_helpers::test_rust_equivalence_given_execution_state;
    use tasm_lib::traits::function::Function;
    use tasm_lib::traits::function::FunctionInitialState;
    use tasm_lib::traits::function::ShadowedFunction;
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tasm_lib::traits::rust_shadow::RustShadowError;

    use super::*;
    use crate::block::block_appendix::BlockAppendix;
    use crate::block::block_body::BlockBody;
    use crate::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::transaction::utxo::Utxo;

    const HEADER_POINTER: BFieldElement = BFieldElement::new(1_000);

    /// The UTXOs the kernel derives, without needing a body: the reward is
    /// given directly.
    fn guesser_fee_utxos(header: &BlockHeader, reward: NativeCurrencyAmount) -> Vec<Utxo> {
        let mut locked_amount = reward;
        locked_amount.div_two();
        let unlocked_amount = reward.checked_sub(&locked_amount).unwrap();
        let lock_script_hash = header.guesser_receiver_data.lock_script_hash;
        let unlocked = Utxo::new(lock_script_hash, unlocked_amount.to_native_coins());
        let locked = Utxo::new(lock_script_hash, locked_amount.to_native_coins())
            .with_time_lock(header.timestamp + BlockKernel::MINER_REWARD_TIME_LOCK_PERIOD);
        vec![locked, unlocked]
    }

    impl Function for GuesserFeeAdditionRecords {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
        ) -> Result<(), RustShadowError> {
            let reward: NativeCurrencyAmount = pop_encodable(stack)?;
            let block_hash: Digest = pop_encodable(stack)?;
            let header_pointer = stack.pop().unwrap();
            let header = *BlockHeader::decode_from_memory(memory, header_pointer).unwrap();

            let context = dynamic_allocator(memory);
            let records_list = dynamic_allocator(memory);
            let context_words = [
                reward.encode(),
                block_hash.values().to_vec(),
                vec![header_pointer, records_list],
            ]
            .concat();
            for (i, word) in context_words.into_iter().enumerate() {
                memory.insert(context + bfe!(i as u64), word);
            }
            memory.insert(records_list, bfe!(0));
            stack.push(records_list);

            if header.height.is_genesis() {
                return Ok(());
            }
            if reward.is_negative() {
                return Err(RustShadowError::AssertionError(
                    BlockValidationRule::NegativeFee.error_id(),
                ));
            }

            for (i, utxo) in guesser_fee_utxos(&header, reward).into_iter().enumerate() {
                let buffer = dynamic_allocator(memory);
                encode_to_memory(memory, buffer, &utxo);
                let record = commit(
                    Tip5::hash(&utxo),
                    block_hash,
                    header.guesser_receiver_data.receiver_digest,
                );
                encode_to_memory(
                    memory,
                    records_list + bfe!(1 + i as u64 * Digest::LEN as u64),
                    &record.canonical_commitment,
                );
                memory.insert(records_list, bfe!(i as u64 + 1));
            }

            Ok(())
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            _bench_case: Option<BenchmarkCase>,
        ) -> FunctionInitialState {
            let mut rng = StdRng::from_seed(seed);
            let mut header: BlockHeader = rng.random();
            header.height = BlockHeight::from(rng.random_range(1..u64::MAX));
            let reward = NativeCurrencyAmount::from_nau(rng.random_range(0..i128::MAX));
            self.initial_state(&header, rng.random(), reward)
        }

        fn corner_case_initial_states(&self) -> Vec<FunctionInitialState> {
            let mut rng = StdRng::seed_from_u64(0);
            let mut states = vec![];
            for height in [0, 1, 2, u64::MAX] {
                let mut header: BlockHeader = rng.random();
                header.height = BlockHeight::from(height);
                for reward in [
                    NativeCurrencyAmount::zero(),
                    NativeCurrencyAmount::one_nau(),
                    NativeCurrencyAmount::from_nau(2),
                    NativeCurrencyAmount::from_nau(3),
                    NativeCurrencyAmount::coins(42),
                    NativeCurrencyAmount::from_nau(i128::MAX),
                ] {
                    states.push(self.initial_state(&header, rng.random(), reward));
                }
            }
            states
        }
    }

    impl GuesserFeeAdditionRecords {
        fn initial_state(
            &self,
            header: &BlockHeader,
            block_hash: Digest,
            reward: NativeCurrencyAmount,
        ) -> FunctionInitialState {
            let mut memory = HashMap::new();
            encode_to_memory(&mut memory, HEADER_POINTER, header);
            let stack = [
                self.init_stack_for_isolated_run(),
                vec![HEADER_POINTER],
                block_hash.reversed().values().to_vec(),
                reward.encode().into_iter().rev().collect(),
            ]
            .concat();

            FunctionInitialState { stack, memory }
        }
    }

    /// The records the snippet leaves in memory.
    fn records_from_final_state(final_state: &tasm_lib::triton_vm::vm::VMState) -> Vec<Digest> {
        let records_list = *final_state.op_stack.stack.last().unwrap();
        *Vec::<Digest>::decode_from_memory(&final_state.ram, records_list).unwrap()
    }

    #[test]
    fn rust_shadow_agrees_with_tasm() {
        ShadowedFunction::new(GuesserFeeAdditionRecords).test();
    }

    #[test]
    fn records_agree_with_block_kernel() {
        let mut rng = StdRng::seed_from_u64(0);
        for (height, reward) in [
            (1, NativeCurrencyAmount::zero()),
            (1, NativeCurrencyAmount::one_nau()),
            (7, NativeCurrencyAmount::coins(3)),
            (1 << 40, NativeCurrencyAmount::from_nau(i128::MAX)),
        ] {
            let mut header: BlockHeader = rng.random();
            header.height = BlockHeight::from(height);
            let body: BlockBody = rng.random();
            let transaction_kernel = TransactionKernelModifier::default()
                .fee(reward)
                .modify(body.transaction_kernel.clone());
            let body = BlockBody::new(
                transaction_kernel,
                body.mutator_set_accumulator.clone(),
                body.lock_free_mmr_accumulator.clone(),
                body.block_mmr_accumulator.clone(),
            );
            let kernel = BlockKernel::new(header, body, BlockAppendix::new(vec![]));
            let block_hash: Digest = rng.random();
            let expected = kernel
                .guesser_fee_addition_records(block_hash)
                .unwrap()
                .into_iter()
                .map(|record| record.canonical_commitment)
                .collect::<Vec<_>>();

            let final_state = test_rust_equivalence_given_execution_state(
                &ShadowedFunction::new(GuesserFeeAdditionRecords),
                GuesserFeeAdditionRecords
                    .initial_state(&header, block_hash, reward)
                    .into(),
            );
            assert_eq!(expected, records_from_final_state(&final_state));
            assert_eq!(2, expected.len());
        }
    }

    #[test]
    fn genesis_block_has_no_records() {
        let mut rng = StdRng::seed_from_u64(1);
        let mut header: BlockHeader = rng.random();
        header.height = BlockHeight::genesis();
        let final_state = test_rust_equivalence_given_execution_state(
            &ShadowedFunction::new(GuesserFeeAdditionRecords),
            GuesserFeeAdditionRecords
                .initial_state(&header, rng.random(), NativeCurrencyAmount::coins(5))
                .into(),
        );
        assert!(records_from_final_state(&final_state).is_empty());
    }

    #[test]
    fn negative_reward_is_rejected() {
        let mut rng = StdRng::seed_from_u64(2);
        let mut header: BlockHeader = rng.random();
        header.height = BlockHeight::from(5);
        for reward in [
            -NativeCurrencyAmount::one_nau(),
            -NativeCurrencyAmount::coins(1),
            NativeCurrencyAmount::from_nau(i128::MIN),
        ] {
            test_assertion_failure(
                &ShadowedFunction::new(GuesserFeeAdditionRecords),
                GuesserFeeAdditionRecords
                    .initial_state(&header, rng.random(), reward)
                    .into(),
                &[BlockValidationRule::NegativeFee.error_id()],
            );
        }
    }

    #[test]
    fn negative_reward_at_genesis_yields_no_records() {
        let mut rng = StdRng::seed_from_u64(3);
        let mut header: BlockHeader = rng.random();
        header.height = BlockHeight::genesis();
        let final_state = test_rust_equivalence_given_execution_state(
            &ShadowedFunction::new(GuesserFeeAdditionRecords),
            GuesserFeeAdditionRecords
                .initial_state(&header, rng.random(), -NativeCurrencyAmount::coins(1))
                .into(),
        );
        assert!(records_from_final_state(&final_state).is_empty());
    }
}
