use std::collections::HashMap;
use std::sync::OnceLock;

use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_static_size::HashStaticSize;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Library;
use tasm_lib::prelude::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;

use super::amount::total_amount_main_loop::DigestSource;
use super::amount::total_amount_main_loop::TotalAmountMainLoop;
use super::native_currency_amount::NativeCurrencyAmount;
use super::TypeScript;
use super::TypeScriptWitness;
use crate::protocol::consensus::block::MINING_REWARD_TIME_LOCK_PERIOD;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::primitive_witness::SaltedUtxos;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelField;
use crate::protocol::consensus::transaction::validity::tasm::coinbase_amount::CoinbaseAmount;
use crate::protocol::consensus::type_scripts::BFieldCodec;
use crate::protocol::consensus::type_scripts::TypeScriptAndWitness;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::protocol::proof_abstractions::SecretWitness;

impl NativeCurrency {
    pub(crate) const BAD_COINBASE_SIZE_ERROR: i128 = 1_000_030;
    pub(crate) const BAD_SALTED_UTXOS_ERROR: i128 = 1_000_031;
    pub(crate) const NO_INFLATION_VIOLATION: i128 = 1_000_032;
    pub(crate) const COINBASE_TIMELOCK_INSUFFICIENT: i128 = 1_000_033;
    pub(crate) const FEE_EXCEEDS_MAX: i128 = 1_000_034;
    pub(crate) const FEE_EXCEEDS_MIN: i128 = 1_000_035;
    pub(crate) const SUM_OF_OUTPUTS_EXCEEDS_MAX: i128 = 1_000_036;
    pub(crate) const SUM_OF_OUTPUTS_IS_NEGATIVE: i128 = 1_000_037;
    pub(crate) const COINBASE_IS_SET_AND_FEE_IS_NEGATIVE: i128 = 1_000_038;
    pub(crate) const INVALID_COIN_AMOUNT: i128 = 1_000_039;
    pub(crate) const INVALID_COINBASE_DISCRIMINANT: i128 = 1_000_040;
}

/// `NativeCurrency` is the type script that governs Neptune's native currency,
/// Neptune coins.
///
/// The arithmetic for amounts is defined by the struct `NativeCurrencyAmount`.
/// This type script is responsible for checking that transactions that transfer
/// Neptune are balanced, *i.e.*,
///
///  sum inputs  +  (optional: coinbase)  ==  sum outputs  +  fee .
///
/// Transactions that are not balanced in this way are invalid. Furthermore, the
/// type script checks that no overflow occurs while computing the sums.
///
/// Lastly, if the coinbase is set then at least half of this amount must be
/// time-locked for 3 years.
///
/// This consensus program assumes that coinbase transactions can never be
/// merged with negative-fee paying transactions, as the timelock of the
/// coinbase reward could otherwise be circumvented.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, BFieldCodec, GetSize, PartialEq, Eq)]
pub struct NativeCurrency;

impl ConsensusProgram for NativeCurrency {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        let mut library = Library::new();
        let field_with_size_coinbase = field_with_size!(NativeCurrencyWitnessMemory::coinbase);
        let field_fee = field!(NativeCurrencyWitnessMemory::fee);
        let field_timestamp = field!(NativeCurrencyWitnessMemory::timestamp);
        let field_with_size_salted_input_utxos =
            field_with_size!(NativeCurrencyWitnessMemory::salted_input_utxos);
        let field_with_size_salted_output_utxos =
            field_with_size!(NativeCurrencyWitnessMemory::salted_output_utxos);
        let field_utxos = field!(SaltedUtxos::utxos);

        let hash_varlen = library.import(Box::new(HashVarlen));
        let merkle_verify =
            library.import(Box::new(tasm_lib::hashing::merkle_verify::MerkleVerify));
        let coin_size = NativeCurrencyAmount::static_length().unwrap();
        let hash_fee = library.import(Box::new(HashStaticSize { size: coin_size }));
        let compare_coin_amount = DataType::compare_elem_of_stack_size(coin_size);
        let timestamp_size = 1;
        let hash_timestamp = library.import(Box::new(HashStaticSize {
            size: timestamp_size,
        }));
        let u128_overflowing_add = library.import(Box::new(
            tasm_lib::arithmetic::u128::overflowing_add::OverflowingAdd,
        ));
        let i128_shr = library.import(Box::new(
            tasm_lib::arithmetic::i128::shift_right::ShiftRight,
        ));
        let u128_lt = library.import(Box::new(tasm_lib::arithmetic::u128::lt::Lt));
        let i128_lt = library.import(Box::new(tasm_lib::arithmetic::i128::lt::Lt));
        let shift_right_one_u128 = library.import(Box::new(
            tasm_lib::arithmetic::u128::shift_right_static::ShiftRightStatic::<1>,
        ));
        let coinbase_pointer_to_amount = library.import(Box::new(CoinbaseAmount));
        let audit_preloaded_data = library.import(Box::new(VerifyNdSiIntegrity::<
            NativeCurrencyWitnessMemory,
        >::default()));

        let own_program_digest_alloc = library.kmalloc(Digest::LEN as u32);
        let coinbase_release_date_alloc = library.kmalloc(1);

        let loop_utxos_add_amounts_label = library.import(Box::new(TotalAmountMainLoop {
            digest_source: DigestSource::StaticMemory(own_program_digest_alloc),
            release_date: coinbase_release_date_alloc,
        }));

        let store_own_program_digest = triton_asm!(
            // _

            dup 15 dup 15 dup 15 dup 15 dup 15
            // _ [own_program_digest]

            push {own_program_digest_alloc.write_address()}
            write_mem {Digest::LEN}
            pop 1
            // _
        );

        let store_coinbase_release_date = triton_asm!(
            // _ release_date
            push {coinbase_release_date_alloc.write_address()}
            write_mem 1
            pop 1
            // _
        );

        let assert_coinbase_size = triton_asm!(
            // _ coinbase_size

            dup 0
            push 1
            eq
            // _ coinbase_size (coinbase_size == 1)

            dup 1
            push 5
            eq
            // _ coinbase_size (coinbase_size == 1) (coinbase_size == 5)

            add
            assert error_id {Self::BAD_COINBASE_SIZE_ERROR}
            // _ coinbase_size
        );

        let push_max_amount = NativeCurrencyAmount::max().push_to_stack();
        let push_min_amount = NativeCurrencyAmount::min().push_to_stack();

        let digest_eq = DataType::Digest.compare();

        let authenticate_salted_utxos = triton_asm! {
            // BEFORE:
            // _ *salted_utxos size

            dup 1 swap 1
            // _ *salted_utxos *salted_utxos size

            call {hash_varlen}
            // _ *salted_utxos [salted_utxos_hash]

            read_io 5
            // _ *salted_utxos [salted_utxos_hash] [sud]

            {&digest_eq}
            assert error_id {Self::BAD_SALTED_UTXOS_ERROR}
            // _ *salted_utxos
        };

        let assert_half_output_amount_timelocked_label =
            "neptune_core_native_currency_assert_half_output_amount_timelocked";
        let assert_half_output_amount_timelocked = triton_asm! {
            {assert_half_output_amount_timelocked_label}:
            // _ [total_output] [timelocked_amount]

            dup 7
            dup 7
            dup 7
            dup 7
            // _ [total_output] [timelocked_amount] [total_output]

            call {shift_right_one_u128}
            // _ [total_output] [timelocked_amount] [total_output / 2]

            dup 7
            dup 7
            dup 7
            dup 7
            // _ [total_output] [timelocked_amount] [total_output / 2] [timelocked_amount]

            call {u128_lt}
            // _ [total_output] [timelocked_amount] (total_output / 2 > timelocked_amount)

            push 0
            eq
            // _ [total_output] [timelocked_amount] (total_output / 2 <= timelocked_amount)

            assert error_id {Self::COINBASE_TIMELOCK_INSUFFICIENT}
            // _ [total_output] [timelocked_amount]

            return
        };

        let main_code = triton_asm! {
            // _

            {&store_own_program_digest}
            // _

            read_io {Digest::LEN}
            hint txkmh: Digest = stack[0..5]
            // _ [txkmh]

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            hint native_currency_witness_ptr = stack[0]
            // _ [txkmh] *ncw

            dup 0
            call {audit_preloaded_data}
            // _ [txkmh] *ncw witness_size

            pop 1
            // _ [txkmh] *ncw

            /* Divine and authenticate coinbase field */
            dup 0
            {&field_with_size_coinbase}
            hint coinbase_ptr = stack[1]
            hint coinbase_size = stack[0]
            // _ [txkmh] *ncw *coinbase coinbase_size

            {&assert_coinbase_size}
            // _ [txkmh] *ncw *coinbase coinbase_size

            dup 7 dup 7 dup 7 dup 7 dup 7
            // _ [txkmh] *ncw *coinbase coinbase_size [txkmh]

            push {TransactionKernel::MAST_HEIGHT}
            push {TransactionKernelField::Coinbase as u32}
            // _ [txkmh] *ncw *coinbase coinbase_size [txkmh] h i

            dup 8 dup 8
            // _ [txkmh] *ncw *coinbase coinbase_size [txkmh] h i *coinbase coinbase_size

            call {hash_varlen}
            hint coinbase_hash: Digest = stack[0..5]
            // _ [txkmh] *ncw *coinbase coinbase_size [txkmh] h i [coinbase_digest]

            call {merkle_verify}
            // _ [txkmh] *ncw *coinbase coinbase_size

            pop 1
            // _ [txkmh] *ncw *coinbase


            /* Divine and authenticate fee field */
            dup 1
            // _ [txkmh] *ncw *coinbase *ncw

            {&field_fee}
            hint fee_ptr = stack[0]
            // _ [txkmh] *ncw *coinbase *fee

            dup 7
            dup 7
            dup 7
            dup 7
            dup 7
            // _ [txkmh] *ncw *coinbase *fee [txkmh]

            push {TransactionKernel::MAST_HEIGHT}
            push {TransactionKernelField::Fee as u32}
            // _ [txkmh] *ncw *coinbase *fee [txkmh] h i

            dup 7
            // _ [txkmh] *ncw *coinbase *fee [txkmh] h i *fee

            call {hash_fee} pop 1
            // _ [txkmh] *ncw *coinbase *fee [txkmh] h i [fee_digest]

            call {merkle_verify}
            // _ [txkmh] *ncw *coinbase *fee


            /* Verify that fee is non-negative when coinbase is set */
            dup 1
            read_mem 1 pop 1
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant

            dup 0 push 0 eq
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant (coinbase_discriminant == 0)

            dup 1 push 1 eq
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant (coinbase_discriminant == 0) (coinbase_discriminant == 1)

            add assert error_id {Self::INVALID_COINBASE_DISCRIMINANT}
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant

            dup 1 addi {coin_size-1} read_mem {coin_size} pop 1
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant [fee]

            push 127 call {i128_shr}
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant [fee >> 127]
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant signs signs signs signs

            /* Top bit of fee is 0 for positive fee, 1 for negative.
               Shifting the fee right by 127 (sign-preserving shift) means
               *all* bits are either 1 or 0. So all `signs` limbs are also the
               same. So we only need to inspect one of them.
            */

            pop 3
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant signs

            push 2 place 1 div_mod
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant quotient sign

            place 1 pop 1
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant sign

            add
            // _ [txkmh] *ncw *coinbase *fee (coinbase_discriminant + sign)

            /* Possible values of top stack element: {0, 1, 2}.
               Allowed: {0, 1} */

            push 2 eq
            // _ [txkmh] *ncw *coinbase *fee (coinbase_discriminant && sign)

            push 0 eq
            // _ [txkmh] *ncw *coinbase *fee (!coinbase_discriminant || !sign)

            assert error_id {Self::COINBASE_IS_SET_AND_FEE_IS_NEGATIVE}
            // _ [txkmh] *ncw *coinbase *fee


            /* Divine and authenticate timestamp */
            dup 7 dup 7 dup 7 dup 7 dup 7
            // _ [txkmh] *ncw *coinbase *fee [txkmh]

            push {TransactionKernel::MAST_HEIGHT}
            push {TransactionKernelField::Timestamp as u32}
            // _ [txkmh] *ncw *coinbase *fee [txkmh] height index
            hint index = stack[0]
            hint height = stack[1]

            dup 9 {&field_timestamp}
            // _ [txkmh] *ncw *coinbase *fee [txkmh] h i *timestamp
            hint timestamp_ptr = stack[0]

            dup 0
            read_mem 1 pop 1
            // _ [txkmh] *ncw *coinbase *fee [txkmh] h i *timestamp timestamp

            push {MINING_REWARD_TIME_LOCK_PERIOD}
            add
            // _ [txkmh] *ncw *coinbase *fee [txkmh] h i *timestamp coinbase_release_date

            {&store_coinbase_release_date}
            // _ [txkmh] *ncw *coinbase *fee [txkmh] h i *timestamp

            call {hash_timestamp}
            // _ [txkmh] *ncw *coinbase *fee [txkmh] h i [timestamp_hash] *next_field

            pop 1
            // _ [txkmh] *ncw *coinbase *fee [txkmh] h i [timestamp_hash]

            call {merkle_verify}
            // _ [txkmh] *ncw *coinbase *fee
            hint fee_ptr = stack[0]


            /* Divine and authenticate salted input and output UTXOs */
            dup 2 {&field_with_size_salted_input_utxos}
            // _ [txkmh] *ncw *coinbase *fee *salted_input_utxos size

            {&authenticate_salted_utxos}
            // _ [txkmh] *ncw *coinbase *fee *salted_input_utxos

            dup 3 {&field_with_size_salted_output_utxos}
            // _ [txkmh] *ncw *coinbase *fee *salted_input_utxos *salted_output_utxos size

            {&authenticate_salted_utxos}
            // _ [txkmh] *ncw *coinbase *fee *salted_input_utxos *salted_output_utxos


            /* Compute left-hand side: sum inputs + (optional coinbase) */
            swap 1 {&field_utxos}
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos *input_utxos

            read_mem 1 push 2 add
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N *input_utxos[0]_si

            push 0 swap 1
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N 0 *input_utxos[0]_si

            push 0 push 0 push 0
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N 0 *input_utxos[0]_si 0 0 0

            dup 8
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N 0 *input_utxos[0]_si 0 0 0 *coinbase

            call {coinbase_pointer_to_amount}
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N 0 *input_utxos[0]_si 0 0 0 [coinbase]

            hint coinbase = stack[0..4]
            hint enn = stack[9]
            hint i = stack[8]
            hint utxos_i = stack[7]

            push 0 push 0 push 0 push 0
            hint timelocked_amount = stack[0..4]
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N 0 *input_utxos[0]_si 0 0 0 [coinbase] [timelocked_amount]

            call {loop_utxos_add_amounts_label}
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] [timelocked_amount]

            pop 4
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input]

            hint total_input : u128 = stack[0..4]


            /* Compute right-hand side: fee + sum outputs */
            dup 11 dup 11
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee *salted_output_utxos

            {&field_utxos}
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee *output_utxos

            read_mem 1 push 2 add
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N *output_utxos[0]_si
            hint utxos_0_si = stack[0]

            push 0 swap 1
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N 0 *output_utxos[0]_si

            push 0 push 0 push 0
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N 0 *output_utxos[0]_si 0 0 0

            push 0
            push 0
            push 0
            push 0
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N 0 *output_utxos[0]_si 0 0 0 [total_output]

            hint total_output = stack[0..4]
            hint utxos_i_si = stack[7]
            hint i = stack[8]
            hint enn = stack[9]

            push 0 push 0 push 0 push 0
            hint timelocked_amount = stack[0..4]
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N 0 *output_utxos[0]_si 0 0 0 [total_output] [timelocked_amount]

            call {loop_utxos_add_amounts_label}
            hint timelocked_amount = stack[0..4]
            hint total_output = stack[4..8]
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N N *output_utxos[N]_si * * * [total_output] [timelocked_amount]

            // sanity check total output
            dup 7
            dup 7
            dup 7
            dup 7
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N N *output_utxos[N]_si * * * [total_output] [timelocked_amount] [total_output]

            {&push_max_amount}
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N N *output_utxos[N]_si * * * [total_output] [timelocked_amount] [total_output] [max_nau]

            call {i128_lt}
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N N *output_utxos[N]_si * * * [total_output] [timelocked_amount] (max_nau < total_output)

            push 0 eq
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N N *output_utxos[N]_si * * * [total_output] [timelocked_amount] (max_nau >= total_output)

            assert error_id {Self::SUM_OF_OUTPUTS_EXCEEDS_MAX}

            push 0
            push 0
            push 0
            push 0
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N N *output_utxos[N]_si * * * [total_output] [timelocked_amount] [0]

            dup 11
            dup 11
            dup 11
            dup 11
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N N *output_utxos[N]_si * * * [total_output] [timelocked_amount] [0] [total_output]

            call {i128_lt}
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N N *output_utxos[N]_si * * * [total_output] [timelocked_amount] (total_output < 0)

            push 0 eq
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N N *output_utxos[N]_si * * * [total_output] [timelocked_amount] (total_output >= 0)

            assert error_id {Self::SUM_OF_OUTPUTS_IS_NEGATIVE}
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N N *output_utxos[N]_si * * * [total_output] [timelocked_amount]


            /* Verify that coinbase transactions timelock half their output amount */
            pick 8 pop 1
            pick 8 pop 1
            pick 8 pop 1
            pick 8 pop 1
            pick 8 pop 1
            pick 8 pop 1
            pick 8 pop 1
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] [total_output] [timelocked_amount]

            pick 12 pop 1
            pick 12 pop 1
            pick 12 pop 1
            pick 12 pop 1
            pick 12 pop 1
            pick 12 pop 1
            pick 12 pop 1
            // _ [txkmh] *ncw *coinbase *fee [total_input] [total_output] [timelocked_amount]

            pick 13
            call {coinbase_pointer_to_amount}
            hint coinbase = stack[0..4]
            // _ [txkmh] *ncw *fee [total_input] [total_output] [timelocked_amount] [coinbase]

            /* If coinbase is non-zero assert that at least half of total output is timelocked */
            push 0
            push 0
            push 0
            push 0
            call {u128_lt}
            // _ [txkmh] *ncw *fee [total_input] [total_output] [timelocked_amount] (coinbase > 0)

            skiz
                call {assert_half_output_amount_timelocked_label}
            // _ [txkmh] *ncw *fee [total_input] [total_output] [timelocked_amount]

            pop {coin_size}
            // _ [txkmh] *ncw *fee [total_input] [total_output]

            pick 8 addi {coin_size-1}
            read_mem {coin_size}
            pop 1
            hint fee = stack[0..4]
            // _ [txkmh] *ncw [total_input] [total_output] [fee]

            dup 3
            dup 3
            dup 3
            dup 3
            {&push_max_amount}
            hint max_amount = stack[0..4]
            // _ [txkmh] *ncw [total_input] [total_output] [fee] [fee] [max_amount]

            call {i128_lt}
            // _ [txkmh] *ncw [total_input] [total_output] [fee] (max_amount < fee)

            push 0 eq
            // _ [txkmh] *ncw [total_input] [total_output] [fee] (fee <= max_amount)

            assert error_id {Self::FEE_EXCEEDS_MAX}
            // _ [txkmh] *ncw [total_input] [total_output] [fee]

            {&push_min_amount}
            hint min_amount = stack[0..4]
            // _ [txkmh] *ncw [total_input] [total_output] [fee] [min_amount]

            dup 7
            dup 7
            dup 7
            dup 7
            // _ [txkmh] *ncw [total_input] [total_output] [fee] [min_amount] [fee]

            call {i128_lt}
            // _ [txkmh] *ncw [total_input] [total_output] [fee] (fee < min_amount)

            push 0 eq
            // _ [txkmh] *ncw [total_input] [total_output] [fee] (fee >= min_amount)

            assert error_id {Self::FEE_EXCEEDS_MIN}
            // _ [txkmh] *ncw [total_input] [total_output] [fee]

            call {u128_overflowing_add}
            pop 1
            // _ [txkmh] *ncw [total_input] [total_output']

            {&compare_coin_amount}
            // _ [txkmh] *ncw (total_input == total_output')

            assert error_id {Self::NO_INFLATION_VIOLATION}
            // _ [txkmh] *ncw

            pop 1
            pop 5
            // _

            halt
        };

        let imports = library.all_imports();

        let code = triton_asm!(
            {&main_code}
            {&assert_half_output_amount_timelocked}
            {&imports}
        );

        (library, code)
    }

    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }
}

impl TypeScript for NativeCurrency {
    type State = NativeCurrencyAmount;
}

#[derive(Debug, Clone, Deserialize, Serialize, BFieldCodec, GetSize, PartialEq, Eq, TasmObject)]
pub struct NativeCurrencyWitness {
    pub salted_input_utxos: SaltedUtxos,
    pub salted_output_utxos: SaltedUtxos,
    pub kernel: TransactionKernel,
}

impl From<PrimitiveWitness> for NativeCurrencyWitness {
    fn from(primitive_witness: PrimitiveWitness) -> Self {
        NativeCurrencyWitness {
            salted_input_utxos: primitive_witness.input_utxos,
            salted_output_utxos: primitive_witness.output_utxos,
            kernel: primitive_witness.kernel,
        }
    }
}

/// The part of witness data that is read from memory
///
/// Factored out since this makes auditing the preloaded data much cheaper as
/// we avoid having to audit the [TransactionKernel].
#[derive(Debug, Clone, BFieldCodec, TasmObject)]
struct NativeCurrencyWitnessMemory {
    salted_input_utxos: SaltedUtxos,
    salted_output_utxos: SaltedUtxos,
    coinbase: Option<NativeCurrencyAmount>,
    fee: NativeCurrencyAmount,
    timestamp: Timestamp,
}

impl From<&NativeCurrencyWitness> for NativeCurrencyWitnessMemory {
    fn from(value: &NativeCurrencyWitness) -> Self {
        Self {
            salted_input_utxos: value.salted_input_utxos.clone(),
            salted_output_utxos: value.salted_output_utxos.clone(),
            coinbase: value.kernel.coinbase,
            fee: value.kernel.fee,
            timestamp: value.kernel.timestamp,
        }
    }
}

impl TypeScriptWitness for NativeCurrencyWitness {
    fn new(
        transaction_kernel: TransactionKernel,
        salted_input_utxos: SaltedUtxos,
        salted_output_utxos: SaltedUtxos,
    ) -> Self {
        Self {
            salted_input_utxos,
            salted_output_utxos,
            kernel: transaction_kernel,
        }
    }

    fn transaction_kernel(&self) -> TransactionKernel {
        self.kernel.clone()
    }

    fn salted_input_utxos(&self) -> SaltedUtxos {
        self.salted_input_utxos.clone()
    }

    fn salted_output_utxos(&self) -> SaltedUtxos {
        self.salted_output_utxos.clone()
    }

    fn type_script_and_witness(&self) -> TypeScriptAndWitness {
        TypeScriptAndWitness::new_with_nondeterminism(
            NativeCurrency.program(),
            self.nondeterminism(),
        )
    }
}

impl SecretWitness for NativeCurrencyWitness {
    fn program(&self) -> Program {
        NativeCurrency.program()
    }

    fn standard_input(&self) -> PublicInput {
        self.type_script_standard_input()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        // set memory
        let mut memory = HashMap::default();
        let memory_part_of_witness: NativeCurrencyWitnessMemory = self.into();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            &memory_part_of_witness,
        );

        // individual tokens
        let individual_tokens = vec![];

        // digests
        let mast_paths = [
            self.kernel.mast_path(TransactionKernelField::Coinbase),
            self.kernel.mast_path(TransactionKernelField::Fee),
            self.kernel.mast_path(TransactionKernelField::Timestamp),
        ]
        .concat();

        // put everything together
        NonDeterminism::new(individual_tokens)
            .with_digests(mast_paths)
            .with_ram(memory)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod tests {
    use std::panic;

    use macro_rules_attr::apply;
    use num_traits::CheckedAdd;
    use num_traits::Zero;
    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::triton_vm::proof::Claim;
    use test_strategy::proptest;

    use super::*;
    use crate::application::config::network::Network;
    use crate::application::triton_vm_job_queue::TritonVmJobPriority;
    use crate::application::triton_vm_job_queue::TritonVmJobQueue;
    use crate::protocol::consensus::transaction::announcement::Announcement;
    use crate::protocol::consensus::transaction::lock_script::LockScriptAndWitness;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::protocol::consensus::transaction::utxo::Utxo;
    use crate::protocol::consensus::type_scripts::native_currency_amount::tests::invalid_positive_amount;
    use crate::protocol::consensus::type_scripts::time_lock::neptune_arbitrary::arbitrary_primitive_witness_with_active_timelocks;
    use crate::protocol::consensus::type_scripts::time_lock::TimeLock;
    use crate::protocol::proof_abstractions::tasm::builtins as tasm;
    use crate::protocol::proof_abstractions::tasm::program::tests::test_program_snapshot;
    use crate::protocol::proof_abstractions::tasm::program::tests::ConsensusProgramSpecification;
    use crate::protocol::proof_abstractions::tasm::program::ConsensusError;
    use crate::protocol::proof_abstractions::timestamp::Timestamp;
    use crate::protocol::proof_abstractions::verifier::verify;
    use crate::tests::shared_tokio_runtime;

    impl ConsensusProgramSpecification for NativeCurrency {
        fn source(&self) {
            // get in the current program's hash digest
            let self_digest: Digest = tasm::own_program_digest();

            // read standard input:
            //  - transaction kernel mast hash
            //  - input salted utxos digest
            //  - output salted utxos digest
            // (All type scripts take this triple as input.)
            let tx_kernel_digest: Digest = tasm::tasmlib_io_read_stdin___digest();
            let input_utxos_digest: Digest = tasm::tasmlib_io_read_stdin___digest();
            let output_utxos_digest: Digest = tasm::tasmlib_io_read_stdin___digest();

            // divine witness from memory
            let start_address: BFieldElement =
                FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
            let native_currency_witness_mem: NativeCurrencyWitnessMemory =
                tasm::decode_from_memory(start_address);
            let coinbase: Option<NativeCurrencyAmount> = native_currency_witness_mem.coinbase;
            let fee: NativeCurrencyAmount = native_currency_witness_mem.fee;
            let input_salted_utxos: SaltedUtxos = native_currency_witness_mem.salted_input_utxos;
            let output_salted_utxos: SaltedUtxos = native_currency_witness_mem.salted_output_utxos;
            let timestamp = native_currency_witness_mem.timestamp;

            // authenticate coinbase against kernel mast hash
            let coinbase_leaf_index: u32 = TransactionKernelField::Coinbase as u32;
            let coinbase_leaf: Digest = Tip5::hash(&coinbase);
            let kernel_tree_height: u32 = u32::try_from(TransactionKernel::MAST_HEIGHT).unwrap();
            tasm::tasmlib_hashing_merkle_verify(
                tx_kernel_digest,
                coinbase_leaf_index,
                coinbase_leaf,
                kernel_tree_height,
            );

            // unpack coinbase
            let some_coinbase: NativeCurrencyAmount = match coinbase {
                Some(coins) => coins,
                None => NativeCurrencyAmount::coins(0),
            };
            assert!(!some_coinbase.is_negative());

            // authenticate fee against kernel mast hash
            let fee_leaf_index: u32 = TransactionKernelField::Fee as u32;
            let fee_leaf: Digest = Tip5::hash(&fee);
            tasm::tasmlib_hashing_merkle_verify(
                tx_kernel_digest,
                fee_leaf_index,
                fee_leaf,
                kernel_tree_height,
            );

            assert!(coinbase.is_none() || !fee.is_negative());

            let timestamp_leaf_index = TransactionKernelField::Timestamp as u32;
            let timestamp_leaf = Tip5::hash(&timestamp);
            tasm::tasmlib_hashing_merkle_verify(
                tx_kernel_digest,
                timestamp_leaf_index,
                timestamp_leaf,
                kernel_tree_height,
            );

            // authenticate inputs against salted commitment
            assert_eq!(input_utxos_digest, Tip5::hash(&input_salted_utxos));

            // authenticate outputs against salted commitment
            assert_eq!(output_utxos_digest, Tip5::hash(&output_salted_utxos));

            // get total input amount from inputs
            let mut total_input = NativeCurrencyAmount::coins(0);
            let mut i: u32 = 0;
            let num_inputs: u32 = input_salted_utxos.utxos.len() as u32;
            while i < num_inputs {
                let utxo_i = &input_salted_utxos.utxos[i as usize];
                let num_coins: u32 = utxo_i.coins().len() as u32;
                let mut j = 0;
                while j < num_coins {
                    if utxo_i.coins()[j as usize].type_script_hash == self_digest {
                        // decode state to get amount
                        let amount: NativeCurrencyAmount =
                            *NativeCurrencyAmount::decode(&utxo_i.coins()[j as usize].state)
                                .unwrap();

                        // make sure amount is positive (or zero)
                        assert!(!amount.is_negative());

                        // safely add to total
                        total_input = total_input.checked_add(&amount).unwrap();
                    }
                    j += 1;
                }
                i += 1;
            }

            // get total output amount from outputs
            let mut total_output = NativeCurrencyAmount::coins(0);
            let mut timelocked_output = NativeCurrencyAmount::coins(0);

            i = 0;
            let num_outputs: u32 = output_salted_utxos.utxos.len() as u32;
            while i < num_outputs {
                let utxo_i = output_salted_utxos.utxos[i as usize].clone();
                let num_coins: u32 = utxo_i.coins().len() as u32;
                let mut total_amount_for_utxo = NativeCurrencyAmount::coins(0);
                let mut time_locked = false;
                let mut j = 0;
                while j < num_coins {
                    let coin_j = utxo_i.coins()[j as usize].clone();
                    if coin_j.type_script_hash == self_digest {
                        // decode state to get amount
                        let amount: NativeCurrencyAmount =
                            *NativeCurrencyAmount::decode(&coin_j.state).unwrap();

                        // make sure amount is positive (or zero)
                        assert!(!amount.is_negative());

                        // safely add to total
                        total_amount_for_utxo = total_amount_for_utxo.checked_add(&amount).unwrap();
                    } else if coin_j.type_script_hash == TimeLock.hash() {
                        // decode state to get release date
                        let release_date = *Timestamp::decode(&coin_j.state).unwrap();
                        if release_date >= timestamp + MINING_REWARD_TIME_LOCK_PERIOD {
                            time_locked = true;
                        }
                    }
                    j += 1;
                }
                total_output = total_output.checked_add(&total_amount_for_utxo).unwrap();
                if time_locked {
                    timelocked_output = timelocked_output
                        .checked_add(&total_amount_for_utxo)
                        .unwrap();
                }
                i += 1;
            }

            assert!(
                fee >= NativeCurrencyAmount::min(),
                "fee exceeds amount lower bound"
            );
            assert!(
                fee <= NativeCurrencyAmount::max(),
                "fee exceeds amount upper bound"
            );

            // if coinbase is set, verify that half of total output is
            // time-locked.
            if some_coinbase.is_positive() {
                let mut required_timelocked = total_output;
                required_timelocked.div_two();
                assert!(timelocked_output >= required_timelocked);
            }

            // test no-inflation equation
            let total_input_plus_coinbase: NativeCurrencyAmount =
                total_input.checked_add(&some_coinbase).unwrap();
            let total_output_plus_fee: NativeCurrencyAmount =
                total_output.checked_add_negative(&fee).unwrap();
            assert_eq!(total_input_plus_coinbase, total_output_plus_fee);
        }
    }

    fn assert_both_rust_and_tasm_halt_gracefully(
        native_currency_witness: NativeCurrencyWitness,
    ) -> Result<(), TestCaseError> {
        let rust_result = NativeCurrency
            .run_rust(
                &native_currency_witness.standard_input(),
                native_currency_witness.nondeterminism(),
            )
            .expect("rust run should pass");
        prop_assert!(rust_result.is_empty());

        let tasm_result = match NativeCurrency.run_tasm(
            &native_currency_witness.standard_input(),
            native_currency_witness.nondeterminism(),
        ) {
            Ok(r) => r,
            Err(e) => match e {
                ConsensusError::RustShadowPanic(rsp) => {
                    panic!("Tasm run failed due to rust shadow panic (?): {rsp}");
                }
                ConsensusError::TritonVMPanic(err, instruction_error) => {
                    panic!("Tasm run failed due to VM panic: {instruction_error}:\n{err}");
                }
            },
        };

        prop_assert!(tasm_result.is_empty());

        Ok(())
    }

    fn assert_both_rust_and_tasm_fail(
        native_currency_witness: NativeCurrencyWitness,
        expected_error_ids: &[i128],
    ) {
        let stdin = native_currency_witness.standard_input();
        let nd = native_currency_witness.nondeterminism();
        let test_result = NativeCurrency.test_assertion_failure(stdin, nd, expected_error_ids);
        test_result.unwrap();
    }

    #[test]
    fn native_currency_derived_witness_generates_accepting_tasm_program_empty_tx() {
        // Generate a tx with no inputs, no outputs and zero fee, commonly
        // referred to as a "nop" transaction. This must pass.
        let mut test_runner = TestRunner::deterministic();
        let nop = PrimitiveWitness::arbitrary_with_size_numbers(Some(0), 0, 0)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let native_currency_witness = NativeCurrencyWitness::from(nop);
        assert_both_rust_and_tasm_halt_gracefully(native_currency_witness).unwrap();
    }

    #[test]
    fn native_currency_derived_witness_generates_accepting_tasm_program_unittest() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 2)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness);
        assert_both_rust_and_tasm_halt_gracefully(native_currency_witness).unwrap();
    }

    fn prop_inflation_violation_when_fee_too_big(mut primitive_witness: PrimitiveWitness) {
        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness.clone());
        assert_both_rust_and_tasm_halt_gracefully(native_currency_witness).unwrap();

        // Increase fee by 1 nau and verify inflation violation
        primitive_witness.kernel = TransactionKernelModifier::default()
            .fee(primitive_witness.kernel.fee + NativeCurrencyAmount::from_nau(1))
            .modify(primitive_witness.kernel);
        assert_both_rust_and_tasm_fail(
            NativeCurrencyWitness::from(primitive_witness.clone()),
            &[NativeCurrency::NO_INFLATION_VIOLATION],
        );

        // Increase fee by 2^{32} nau and verify inflation violation
        primitive_witness.kernel = TransactionKernelModifier::default()
            .fee(primitive_witness.kernel.fee + NativeCurrencyAmount::from_nau(1 << 32))
            .modify(primitive_witness.kernel);
        assert_both_rust_and_tasm_fail(
            NativeCurrencyWitness::from(primitive_witness.clone()),
            &[NativeCurrency::NO_INFLATION_VIOLATION],
        );
    }

    #[test]
    fn balanced_transaction_valid_unbalanced_invalid_no_coinbase() {
        for num_inputs in 0..=2 {
            for num_outputs in 0..=2 {
                let mut test_runner = TestRunner::deterministic();
                let no_coinbase_pw =
                    PrimitiveWitness::arbitrary_with_size_numbers(Some(num_inputs), num_outputs, 2)
                        .new_tree(&mut test_runner)
                        .unwrap()
                        .current();
                prop_inflation_violation_when_fee_too_big(no_coinbase_pw)
            }
        }
    }

    #[test]
    fn balanced_transaction_valid_unbalanced_invalid_with_coinbase() {
        for num_outputs in 0..=3 {
            let mut test_runner = TestRunner::deterministic();
            let coinbase_pw = PrimitiveWitness::arbitrary_with_size_numbers(None, num_outputs, 1)
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
            prop_inflation_violation_when_fee_too_big(coinbase_pw)
        }
    }

    #[test]
    fn very_negative_fee_allowed() {
        // Since the block validity rules require that the fee is non-negative,
        // it's OK that it's posssible to inflate supply internally to a
        // transaction as long as you end up with a transaction with a negative
        // fee. Since:
        //   a) mining this transaction directly is not possible
        //   b) merging this transaction with another must result in a
        //      transaction with a non-negative fee. So a negative fee in one
        //      transaction must be cancelled by a equally-sized positive fee
        //      in the other transaction, and this positive fee must be paid for
        //      by offsetting the inflation created in this transaction.
        let input =
            Utxo::new_native_currency(Digest::default(), NativeCurrencyAmount::from_nau(1_000));
        let output = Utxo::new_native_currency(
            Digest::default(),
            NativeCurrencyAmount::from_nau(167_999_999_999_999_999_999_999_999_999_999_999_999i128),
        );
        let fee = NativeCurrencyAmount::from_nau(
            -167_999_999_999_999_999_999_999_999_999_999_998_999i128,
        );

        // Ensure kernel has no coinbase and correct fee.
        let mut test_runner = TestRunner::deterministic();
        let kernel = arb::<TransactionKernel>()
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let kernel = TransactionKernelModifier::default()
            .fee(fee)
            .coinbase(None)
            .clone_modify(&kernel);

        let very_negative_fee = NativeCurrencyWitness {
            salted_input_utxos: SaltedUtxos {
                utxos: vec![input],
                salt: Default::default(),
            },
            salted_output_utxos: SaltedUtxos {
                utxos: vec![output],
                salt: Default::default(),
            },
            kernel,
        };

        assert_both_rust_and_tasm_halt_gracefully(very_negative_fee).unwrap();
    }

    #[proptest(cases = 30)]
    fn balanced_transaction_is_valid(
        #[strategy(0usize..=6)] _num_inputs: usize,
        #[strategy(0usize..=6)] _num_outputs: usize,
        #[strategy(0usize..=1)] _num_announcements: usize,
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(Some(#_num_inputs), #_num_outputs, #_num_announcements))]
        primitive_witness: PrimitiveWitness,
    ) {
        // PrimitiveWitness::arbitrary_with already ensures the transaction is balanced
        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness);
        assert_both_rust_and_tasm_halt_gracefully(native_currency_witness)?;
    }

    #[proptest(cases = 50)]
    fn native_currency_is_valid_for_primitive_witness_with_timelock(
        #[strategy(1usize..=3)] _num_inputs: usize,
        #[strategy(0usize..=3)] _num_outputs: usize,
        #[strategy(0usize..=1)] _num_announcements: usize,
        #[strategy(arb::<Timestamp>())] _now: Timestamp,
        #[strategy(arbitrary_primitive_witness_with_active_timelocks(
            #_num_inputs,
            #_num_outputs,
            #_num_announcements,
            #_now,
        ))]
        primitive_witness: PrimitiveWitness,
    ) {
        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness);

        // there are inputs so there can be no coinbase and we are testing a
        // regular transaction
        assert_both_rust_and_tasm_halt_gracefully(native_currency_witness)?;
    }

    #[test]
    fn native_currency_is_valid_for_primitive_witness_with_timelock_deterministic() {
        let mut test_runner = TestRunner::deterministic();
        let now = arb::<Timestamp>()
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let primitive_witness = arbitrary_primitive_witness_with_active_timelocks(2, 2, 3, now)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness);

        assert_both_rust_and_tasm_halt_gracefully(native_currency_witness).unwrap();
    }

    #[proptest(cases = 50)]
    fn unbalanced_transaction_without_coinbase_is_invalid_prop(
        #[strategy(1usize..=3)] _num_inputs: usize,
        #[strategy(1usize..=3)] _num_outputs: usize,
        #[strategy(0usize..=3)] _num_announcements: usize,
        #[strategy(vec(arb::<Utxo>(), #_num_inputs))] _input_utxos: Vec<Utxo>,
        #[strategy(vec(arb::<LockScriptAndWitness>(), #_num_inputs))]
        _input_lock_scripts_and_witnesses: Vec<LockScriptAndWitness>,
        #[strategy(vec(arb::<Utxo>(), #_num_outputs))] _output_utxos: Vec<Utxo>,
        #[strategy(vec(arb(), #_num_announcements))] _announcements: Vec<Announcement>,
        #[strategy(arb())] _fee: NativeCurrencyAmount,
        #[strategy(PrimitiveWitness::arbitrary_primitive_witness_with(
            &#_input_utxos,
            &#_input_lock_scripts_and_witnesses,
            &#_output_utxos,
            &#_announcements,
            #_fee,
            None,
        ))]
        primitive_witness: PrimitiveWitness,
    ) {
        // with high probability the amounts (which are random) do not add up
        let witness = NativeCurrencyWitness::from(primitive_witness);

        NativeCurrency.test_assertion_failure(
            witness.standard_input(),
            witness.nondeterminism(),
            &[NativeCurrency::NO_INFLATION_VIOLATION],
        )?;
    }

    #[proptest(cases = 50)]
    fn unbalanced_transaction_with_coinbase_is_invalid(
        #[strategy(1usize..=3)] _num_inputs: usize,
        #[strategy(1usize..=3)] _num_outputs: usize,
        #[strategy(1usize..=3)] _num_announcements: usize,
        #[strategy(NativeCurrencyAmount::arbitrary_non_negative())] _coinbase: NativeCurrencyAmount,
        #[strategy(vec(arb::<Utxo>(), #_num_inputs))] _input_utxos: Vec<Utxo>,
        #[strategy(vec(arb::<LockScriptAndWitness>(), #_num_inputs))]
        _input_lock_scripts_and_witnesses: Vec<LockScriptAndWitness>,
        #[strategy(vec(arb::<Utxo>(), #_num_outputs))] _output_utxos: Vec<Utxo>,
        #[strategy(vec(arb(), #_num_announcements))] _announcements: Vec<Announcement>,
        #[strategy(NativeCurrencyAmount::arbitrary_non_negative())] _fee: NativeCurrencyAmount,
        #[strategy(PrimitiveWitness::arbitrary_primitive_witness_with(
            &#_input_utxos,
            &#_input_lock_scripts_and_witnesses,
            &#_output_utxos,
            &#_announcements,
            #_fee,
            Some(#_coinbase),
        ))]
        primitive_witness: PrimitiveWitness,
    ) {
        // with high probability the amounts (which are random) do not add up
        // and since the coinbase is set, the coinbase-timelock test might fail
        // before the no-inflation test.
        let witness = NativeCurrencyWitness::from(primitive_witness);
        assert!(witness.kernel.coinbase.is_some(), "coinbase is none");
        NativeCurrency.test_assertion_failure(
            witness.standard_input(),
            witness.nondeterminism(),
            &[
                NativeCurrency::NO_INFLATION_VIOLATION,
                NativeCurrency::COINBASE_TIMELOCK_INSUFFICIENT,
            ],
        )?;
    }

    #[test]
    fn tx_with_negative_coinbase_is_invalid_deterministic() {
        let mut test_runner = TestRunner::deterministic();
        let fee = NativeCurrencyAmount::zero();
        let witness = PrimitiveWitness::arbitrary_primitive_witness_with(
            &[],
            &[],
            &[],
            &[],
            fee,
            Some(-NativeCurrencyAmount::coins(1)),
        )
        .new_tree(&mut test_runner)
        .unwrap()
        .current();
        let witness = NativeCurrencyWitness::from(witness);
        NativeCurrency
            .test_assertion_failure(
                witness.standard_input(),
                witness.nondeterminism(),
                &[CoinbaseAmount::ILLEGAL_COINBASE_AMOUNT_ERROR],
            )
            .unwrap();
    }

    #[proptest(cases = 50)]
    fn tx_with_negative_coinbase_is_invalid(
        #[strategy(1usize..=3)] _num_inputs: usize,
        #[strategy(1usize..=3)] _num_outputs: usize,
        #[strategy(1usize..=3)] _num_announcements: usize,
        #[strategy(NativeCurrencyAmount::arbitrary_non_negative())]
        _minus_coinbase: NativeCurrencyAmount,
        #[strategy(vec(arb::<Utxo>(), #_num_inputs))] _input_utxos: Vec<Utxo>,
        #[strategy(vec(arb::<LockScriptAndWitness>(), #_num_inputs))]
        _input_lock_scripts_and_witnesses: Vec<LockScriptAndWitness>,
        #[strategy(vec(arb::<Utxo>(), #_num_outputs))] _output_utxos: Vec<Utxo>,
        #[strategy(vec(arb(), #_num_announcements))] _announcements: Vec<Announcement>,
        #[strategy(NativeCurrencyAmount::arbitrary_non_negative())] _fee: NativeCurrencyAmount,
        #[strategy(PrimitiveWitness::arbitrary_primitive_witness_with(
            &#_input_utxos,
            &#_input_lock_scripts_and_witnesses,
            &#_output_utxos,
            &#_announcements,
            #_fee,
            Some(-#_minus_coinbase),
        ))]
        primitive_witness: PrimitiveWitness,
    ) {
        // with high probability the amounts (which are random) do not add up
        // and since the coinbase is set, the coinbase-timelock test might fail
        // before the no-inflation test.
        let witness = NativeCurrencyWitness::from(primitive_witness);
        assert!(witness.kernel.coinbase.is_some(), "coinbase is none");
        NativeCurrency.test_assertion_failure(
            witness.standard_input(),
            witness.nondeterminism(),
            &[CoinbaseAmount::ILLEGAL_COINBASE_AMOUNT_ERROR],
        )?;
    }

    #[apply(shared_tokio_runtime)]
    async fn native_currency_proof_happy_path() {
        let network = Network::Main;
        let mut test_runner = TestRunner::deterministic();

        let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 2)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let txk_mast_hash = primitive_witness.kernel.mast_hash();
        let salted_input_utxos_hash = Tip5::hash(&primitive_witness.input_utxos);
        let salted_output_utxos_hash = Tip5::hash(&primitive_witness.output_utxos);

        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness);
        let type_script_and_witness = TypeScriptAndWitness::new_with_nondeterminism(
            NativeCurrency.program(),
            native_currency_witness.nondeterminism(),
        );
        let tasm_halts = type_script_and_witness.halts_gracefully(
            txk_mast_hash,
            salted_input_utxos_hash,
            salted_output_utxos_hash,
        );

        assert!(tasm_halts);

        let claim = Claim::new(NativeCurrency.program().hash())
            .with_input(native_currency_witness.standard_input().individual_tokens);
        let proof = type_script_and_witness
            .prove(
                txk_mast_hash,
                salted_input_utxos_hash,
                salted_output_utxos_hash,
                TritonVmJobQueue::get_instance(),
                TritonVmJobPriority::default().into(),
            )
            .await
            .unwrap();
        assert!(verify(claim, proof, network).await, "proof fails");
    }

    #[test]
    fn tx_with_negative_fee_with_coinbase_is_invalid_deterministic() {
        let mut test_runner = TestRunner::deterministic();
        let mut primitive_witness =
            PrimitiveWitness::arbitrary_with_fee(-NativeCurrencyAmount::coins(1))
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
        let good_native_currency_witness = NativeCurrencyWitness::from(primitive_witness.clone());
        assert_both_rust_and_tasm_halt_gracefully(good_native_currency_witness).unwrap();

        let kernel_modifier =
            TransactionKernelModifier::default().coinbase(Some(NativeCurrencyAmount::coins(1)));
        primitive_witness.kernel = kernel_modifier.modify(primitive_witness.kernel);
        let bad_native_currency_witness = NativeCurrencyWitness::from(primitive_witness.clone());
        NativeCurrency
            .test_assertion_failure(
                bad_native_currency_witness.standard_input(),
                bad_native_currency_witness.nondeterminism(),
                &[NativeCurrency::COINBASE_IS_SET_AND_FEE_IS_NEGATIVE],
            )
            .unwrap();
    }

    #[proptest]
    fn tx_with_negative_fee_with_coinbase_is_invalid_prop(
        #[strategy(NativeCurrencyAmount::arbitrary_non_negative())] _fee: NativeCurrencyAmount,
        #[strategy(PrimitiveWitness::arbitrary_with_fee(-#_fee))]
        mut primitive_witness: PrimitiveWitness,
        #[strategy(NativeCurrencyAmount::arbitrary_non_negative())]
        coinbase_amount: NativeCurrencyAmount,
    ) {
        let good_native_currency_witness = NativeCurrencyWitness::from(primitive_witness.clone());
        assert_both_rust_and_tasm_halt_gracefully(good_native_currency_witness).unwrap();

        let kernel_modifier = TransactionKernelModifier::default().coinbase(Some(coinbase_amount));
        primitive_witness.kernel = kernel_modifier.modify(primitive_witness.kernel);
        let bad_native_currency_witness = NativeCurrencyWitness::from(primitive_witness.clone());
        NativeCurrency
            .test_assertion_failure(
                bad_native_currency_witness.standard_input(),
                bad_native_currency_witness.nondeterminism(),
                &[NativeCurrency::COINBASE_IS_SET_AND_FEE_IS_NEGATIVE],
            )
            .unwrap();
    }

    #[proptest]
    fn transaction_with_timelocked_coinbase_is_valid_prop(
        #[strategy(1usize..=10)] _num_outputs: usize,
        #[strategy(0usize..=10)] _num_public_announcements: usize,
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(None, #_num_outputs, #_num_public_announcements))]
        #[filter(!#primitive_witness.kernel.fee.is_negative())]
        primitive_witness: PrimitiveWitness,
    ) {
        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness);
        assert_both_rust_and_tasm_halt_gracefully(native_currency_witness).unwrap();
    }

    #[test]
    fn transaction_with_timelocked_coinbase_is_valid_deterministic_small() {
        let mut test_runner = TestRunner::deterministic();
        let mut primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(None, 1, 0)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        while primitive_witness.kernel.fee.is_negative() {
            primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(None, 1, 0)
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
        }
        println!("primitive_witness:\n{primitive_witness}\n\n");

        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness);

        assert!(assert_both_rust_and_tasm_halt_gracefully(native_currency_witness).is_ok());
    }

    #[test]
    fn transaction_with_timelocked_coinbase_is_valid_deterministic_medium() {
        let mut test_runner = TestRunner::deterministic();
        let mut primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(None, 2, 2)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        while primitive_witness.kernel.fee.is_negative() {
            primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(None, 2, 2)
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
        }
        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness);
        let mut fee = native_currency_witness.kernel.fee;
        fee.div_two();

        assert!(assert_both_rust_and_tasm_halt_gracefully(native_currency_witness).is_ok());
    }

    #[test]
    fn unbalanced_transaction_without_coinbase_is_invalid_deterministic() {
        fn sample<T: Clone, S: Strategy<Value = T>>(
            strategy: S,
            test_runner: &mut TestRunner,
        ) -> T {
            strategy.new_tree(test_runner).unwrap().current().clone()
        }

        let mut tr = TestRunner::deterministic();

        for _ in 0..10 {
            let input_utxos = sample(vec(arb::<Utxo>(), 3), &mut tr);
            let input_lock_scripts_and_witnesses =
                sample(vec(arb::<LockScriptAndWitness>(), 3), &mut tr);
            let output_utxos = sample(vec(arb::<Utxo>(), 3), &mut tr);
            let announcements = sample(vec(arb(), 3), &mut tr);
            let fee = sample(NativeCurrencyAmount::arbitrary_non_negative(), &mut tr);
            let primitive_witness = PrimitiveWitness::arbitrary_primitive_witness_with(
                &input_utxos,
                &input_lock_scripts_and_witnesses,
                &output_utxos,
                &announcements,
                fee,
                None,
            )
            .new_tree(&mut tr)
            .unwrap()
            .current()
            .clone();

            // with high probability the amounts (which are random) do not add up
            let witness = NativeCurrencyWitness::from(primitive_witness);
            let result = NativeCurrency.test_assertion_failure(
                witness.standard_input(),
                witness.nondeterminism(),
                &[NativeCurrency::NO_INFLATION_VIOLATION],
            );
            assert!(result.is_ok());
        }
    }

    #[proptest]
    fn unbalanced_coinbase_transaction_is_invalid_changed_coinbase_prop(
        #[strategy(1usize..=5)] _num_outputs: usize,
        #[strategy(1usize..=5)] _num_announcements: usize,
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(
            None,
            #_num_outputs,
            #_num_announcements,
        ))]
        mut primitive_witness: PrimitiveWitness,
        #[strategy(arb())] delta: NativeCurrencyAmount,
    ) {
        assert_both_rust_and_tasm_halt_gracefully(NativeCurrencyWitness::from(
            primitive_witness.clone(),
        ))?;

        // Modify the kernel so as to change the coinbase but not the fee. The
        // resulting transaction is imbalanced. The amount timelocked is
        // correct, since required timelocked amount is calculated by dividing
        // total output with 2. So this run must fail on the no inflation
        // violation. The no inflation check disallows *any* imbalance, so total
        // output amount can neither be too big, nor too small.

        // Another test handles negative coinbase amounts.
        let coinbase = primitive_witness.kernel.coinbase.unwrap();
        let new_coinbase = coinbase + delta;
        prop_assume!(!new_coinbase.is_negative());

        let kernel_modifier = TransactionKernelModifier::default().coinbase(Some(new_coinbase));
        primitive_witness.kernel = kernel_modifier.modify(primitive_witness.kernel);
        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness);
        assert_both_rust_and_tasm_fail(
            native_currency_witness,
            &[NativeCurrency::NO_INFLATION_VIOLATION],
        );
    }

    #[proptest]
    fn unbalanced_coinbase_transaction_is_invalid_changed_fee_prop(
        #[strategy(1usize..=5)] _num_outputs: usize,
        #[strategy(1usize..=5)] _num_announcements: usize,
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(
            None,
            #_num_outputs,
            #_num_announcements,
        ))]
        mut primitive_witness: PrimitiveWitness,
        #[strategy(arb())] delta: NativeCurrencyAmount,
    ) {
        // Another test handles negative fee amounts when coinbase is set.
        let fee = primitive_witness.kernel.fee;
        let new_fee = fee + delta;
        prop_assume!(!new_fee.is_negative());

        let kernel_modifier = TransactionKernelModifier::default().fee(new_fee);
        primitive_witness.kernel = kernel_modifier.modify(primitive_witness.kernel);
        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness);

        assert_both_rust_and_tasm_fail(
            native_currency_witness,
            &[NativeCurrency::NO_INFLATION_VIOLATION],
        );
    }

    #[proptest]
    fn unbalanced_input_transaction_is_invalid_changed_fee_prop(
        #[strategy(1usize..=5)] _num_inputs: usize,
        #[strategy(1usize..=5)] _num_outputs: usize,
        #[strategy(0usize..=5)] _num_public_announcements: usize,
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(
            Some(#_num_inputs),
            #_num_outputs,
            #_num_public_announcements,
        ))]
        mut primitive_witness: PrimitiveWitness,
        #[strategy(arb())] delta: NativeCurrencyAmount,
    ) {
        let fee = primitive_witness.kernel.fee;
        let kernel_modifier = TransactionKernelModifier::default().fee(fee + delta);
        primitive_witness.kernel = kernel_modifier.modify(primitive_witness.kernel);
        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness);
        assert_both_rust_and_tasm_fail(
            native_currency_witness,
            &[NativeCurrency::NO_INFLATION_VIOLATION],
        );
    }

    #[proptest]
    fn coinbase_transaction_with_too_early_release_is_invalid_fixed_delta(
        #[strategy(1usize..=3)] _num_outputs: usize,
        #[strategy(1usize..=3)] _num_announcements: usize,
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(
            None,
            #_num_outputs,
            #_num_announcements,
        ))]
        mut primitive_witness: PrimitiveWitness,
    ) {
        // Modify the kernel's timestamp to push it later in time. As a result,
        // the time-locks embedded in the coinbase UTXOs are less than the
        // coinbase time-lock time.
        let delta = Timestamp::days(1);
        let kernel_modifier = TransactionKernelModifier::default()
            .timestamp(primitive_witness.kernel.timestamp + delta);
        primitive_witness.kernel = kernel_modifier.modify(primitive_witness.kernel);
        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness);
        assert_both_rust_and_tasm_fail(
            native_currency_witness,
            &[NativeCurrency::COINBASE_TIMELOCK_INSUFFICIENT],
        );
    }

    #[proptest(cases = 50)]
    fn coinbase_transaction_with_too_early_release_is_invalid_prop_delta(
        #[strategy(1usize..=3)] _num_outputs: usize,
        #[strategy(1usize..=3)] _num_announcements: usize,
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(
            None,
            #_num_outputs,
            #_num_announcements,
        ))]
        mut primitive_witness: PrimitiveWitness,
        #[strategy(arb())]
        #[filter(Timestamp::zero() < #delta)]
        delta: Timestamp,
    ) {
        // Modify the kernel's timestamp to push it later in time. As a result,
        // the time-locks embedded in the coinbase UTXOs are less than the
        // coinbase time-lock time.
        // Skip test-cases that wrap around on the timestamp value, as this
        // represents an earlier timestamp.
        prop_assume!(
            primitive_witness.kernel.timestamp + delta >= primitive_witness.kernel.timestamp
        );
        let kernel_modifier = TransactionKernelModifier::default()
            .timestamp(primitive_witness.kernel.timestamp + delta);
        primitive_witness.kernel = kernel_modifier.modify(primitive_witness.kernel);
        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness);
        assert_both_rust_and_tasm_fail(
            native_currency_witness,
            &[NativeCurrency::COINBASE_TIMELOCK_INSUFFICIENT],
        );
    }

    #[proptest(cases = 1)]
    fn assertion_failure_is_caught_gracefully() {
        // This test is supposed to catch wrong compilation flags causing
        // causing asserts not to be caught by catch_unwind.
        let result = panic::catch_unwind(|| {
            let f = false;
            assert!(f, "This assertion will fail");
        });
        prop_assert!(result.is_err());
    }

    #[test]
    fn fee_can_be_positive_deterministic() {
        let mut test_runner = TestRunner::deterministic();
        for _ in 0..10 {
            let fee = NativeCurrencyAmount::arbitrary_non_negative()
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
            let pw = PrimitiveWitness::arbitrary_with_fee(fee)
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
            assert_both_rust_and_tasm_halt_gracefully(NativeCurrencyWitness::from(pw)).unwrap();
        }
    }

    #[proptest]
    fn fee_can_be_positive(
        #[strategy(NativeCurrencyAmount::arbitrary_non_negative())] _fee: NativeCurrencyAmount,
        #[strategy(PrimitiveWitness::arbitrary_with_fee(#_fee))]
        primitive_witness: PrimitiveWitness,
    ) {
        assert_both_rust_and_tasm_halt_gracefully(NativeCurrencyWitness::from(primitive_witness))?;
    }

    #[test]
    fn fee_can_be_negative_deterministic() {
        let mut test_runner = TestRunner::deterministic();
        let fee = NativeCurrencyAmount::arbitrary_non_negative()
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let pw = PrimitiveWitness::arbitrary_with_fee(-fee)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        assert_both_rust_and_tasm_halt_gracefully(NativeCurrencyWitness::from(pw)).unwrap();
    }

    #[proptest]
    fn fee_can_be_negative(
        #[strategy(NativeCurrencyAmount::arbitrary_non_negative())] _fee: NativeCurrencyAmount,
        #[strategy(PrimitiveWitness::arbitrary_with_fee(-#_fee))]
        primitive_witness: PrimitiveWitness,
    ) {
        assert_both_rust_and_tasm_halt_gracefully(NativeCurrencyWitness::from(primitive_witness))?;
    }

    #[proptest]
    fn positive_fee_cannot_exceed_max_nau(
        #[strategy(invalid_positive_amount())] _fee: NativeCurrencyAmount,
        #[strategy(PrimitiveWitness::arbitrary_with_fee(#_fee))]
        primitive_witness: PrimitiveWitness,
    ) {
        // Why INVALID_COIN_AMOUNT and not FEE_EXCEEDS_MAX?
        // It's because an invalid fee needs to come from invalid inputs; so
        // the INVALID_COIN_AMOUNT assert is triggered when computing the sum
        // of all inputs.
        assert_both_rust_and_tasm_fail(
            NativeCurrencyWitness::from(primitive_witness),
            &[NativeCurrency::INVALID_COIN_AMOUNT],
        );
    }

    #[ignore]
    #[proptest]
    fn negative_fee_cannot_exceed_min_nau(
        #[strategy(invalid_positive_amount())] _fee: NativeCurrencyAmount,
        #[strategy(PrimitiveWitness::arbitrary_with_fee(-#_fee))]
        primitive_witness: PrimitiveWitness,
    ) {
        assert_both_rust_and_tasm_fail(
            NativeCurrencyWitness::from(primitive_witness),
            &[NativeCurrency::FEE_EXCEEDS_MIN],
        );

        // It is actually impossible to trigger this assert error id -- or is it?
        // I'm not convinced.
    }

    test_program_snapshot!(
        NativeCurrency,
        "35ab20eaca74e39c97b1b1c6eeb337853babec0d1b4152b6218f12ab673618df11bb3a534af30f64"
    );
}
