use std::collections::HashMap;
use std::sync::OnceLock;

use get_size2::GetSize;
use itertools::Itertools;
use num_traits::CheckedAdd;
use num_traits::Zero;
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
use tasm_lib::structure::tasm_object::DEFAULT_MAX_DYN_FIELD_SIZE;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;

use super::neptune_coins::NeptuneCoins;
use super::TypeScriptWitness;
use crate::models::blockchain::block::MINING_REWARD_TIME_LOCK_PERIOD;
use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::primitive_witness::SaltedUtxos;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelField;
use crate::models::blockchain::transaction::utxo::Coin;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::validity::tasm::coinbase_amount::CoinbaseAmount;
use crate::models::blockchain::type_scripts::BFieldCodec;
use crate::models::blockchain::type_scripts::TypeScriptAndWitness;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::builtins as tasm;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::proof_abstractions::SecretWitness;

const BAD_COINBASE_SIZE_ERROR: i128 = 1_000_030;
const BAD_SALTED_UTXOS_ERROR: i128 = 1_000_031;
const NO_INFLATION_VIOLATION: i128 = 1_000_032;
const BAD_STATE_SIZE_ERROR: i128 = 1_000_033;
const COINBASE_TIMELOCK_INSUFFICIENT: i128 = 1_000_034;
const UTXO_SIZE_TOO_LARGE_ERROR: i128 = 1_000_035;
const TOO_BIG_COIN_FIELD_SIZE_ERROR: i128 = 1_000_036;
const STATE_LENGTH_FOR_TIME_LOCK_NOT_ONE_ERROR: i128 = 1_000_037;
const FEE_EXCEEDS_MAX: i128 = 1_000_038;
const FEE_EXCEEDS_MIN: i128 = 1_000_039;
const SUM_OF_OUTPUTS_EXCEEDS_MAX: i128 = 1_000_040;
const SUM_OF_OUTPUTS_IS_NEGATIVE: i128 = 1_000_041;
const COINBASE_IS_SET_AND_FEE_IS_NEGATIVE: i128 = 1_000_042;

/// `NativeCurrency` is the type script that governs Neptune's native currency,
/// Neptune coins.
///
/// The arithmetic for amounts is defined by the struct `NeptuneCoins`.
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
#[derive(Debug, Clone, Serialize, Deserialize, BFieldCodec, GetSize, PartialEq, Eq)]
pub struct NativeCurrency;

impl NativeCurrency {
    // const TIME_LOCK_HASH: Digest = Digest([
    //     BFieldElement::new(1099415371751974362_u64),
    //     BFieldElement::new(274457847644817458_u64),
    //     BFieldElement::new(5749046657545930452_u64),
    //     BFieldElement::new(4873191867236712662_u64),
    //     BFieldElement::new(6955338650254959680_u64),
    // ]);
    const TIME_LOCK_HASH: Digest = Digest([
        BFieldElement::new(7207785320433617162_u64),
        BFieldElement::new(890210137924970311_u64),
        BFieldElement::new(7901065193700473067_u64),
        BFieldElement::new(7504530257290336718_u64),
        BFieldElement::new(9848604556451651092_u64),
    ]);
}

impl ConsensusProgram for NativeCurrency {
    #[allow(clippy::needless_return)]
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
        let start_address: BFieldElement = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
        let native_currency_witness_mem: NativeCurrencyWitnessMemory =
            tasm::decode_from_memory(start_address);
        let coinbase: Option<NeptuneCoins> = native_currency_witness_mem.coinbase;
        let fee: NeptuneCoins = native_currency_witness_mem.fee;
        let input_salted_utxos: SaltedUtxos = native_currency_witness_mem.salted_input_utxos;
        let output_salted_utxos: SaltedUtxos = native_currency_witness_mem.salted_output_utxos;
        let timestamp = native_currency_witness_mem.timestamp;

        // authenticate coinbase against kernel mast hash
        let coinbase_leaf_index: u32 = 4;
        let coinbase_leaf: Digest = Hash::hash(&coinbase);
        let kernel_tree_height: u32 = 3;
        tasm::tasmlib_hashing_merkle_verify(
            tx_kernel_digest,
            coinbase_leaf_index,
            coinbase_leaf,
            kernel_tree_height,
        );

        // unpack coinbase
        let some_coinbase: NeptuneCoins = match coinbase {
            Some(coins) => coins,
            None => NeptuneCoins::new(0),
        };
        assert!(!some_coinbase.is_negative());

        // authenticate fee against kernel mast hash
        let fee_leaf_index: u32 = 3;
        let fee_leaf: Digest = Hash::hash(&fee);
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
        assert_eq!(input_utxos_digest, Hash::hash(&input_salted_utxos));

        // authenticate outputs against salted commitment
        assert_eq!(output_utxos_digest, Hash::hash(&output_salted_utxos));

        // get total input amount from inputs
        let mut total_input = NeptuneCoins::new(0);
        let mut i: u32 = 0;
        let num_inputs: u32 = input_salted_utxos.utxos.len() as u32;
        while i < num_inputs {
            let utxo_i = &input_salted_utxos.utxos[i as usize];
            let num_coins: u32 = utxo_i.coins().len() as u32;
            let mut j = 0;
            while j < num_coins {
                if utxo_i.coins()[j as usize].type_script_hash == self_digest {
                    // decode state to get amount
                    let amount: NeptuneCoins =
                        *NeptuneCoins::decode(&utxo_i.coins()[j as usize].state).unwrap();

                    // safely add to total
                    total_input = total_input.checked_add(&amount).unwrap();
                }
                j += 1;
            }
            i += 1;
        }

        // get total output amount from outputs
        let mut total_output = NeptuneCoins::new(0);
        let mut total_timelocked_output = NeptuneCoins::new(0);

        i = 0;
        let num_outputs: u32 = output_salted_utxos.utxos.len() as u32;
        while i < num_outputs {
            let utxo_i = output_salted_utxos.utxos[i as usize].clone();
            let num_coins: u32 = utxo_i.coins().len() as u32;
            let mut total_amount_for_utxo = NeptuneCoins::new(0);
            let mut time_locked = false;
            let mut j = 0;
            while j < num_coins {
                let coin_j = utxo_i.coins()[j as usize].clone();
                if coin_j.type_script_hash == self_digest {
                    // decode state to get amount
                    let amount: NeptuneCoins = *NeptuneCoins::decode(&coin_j.state).unwrap();

                    // make sure amount is positive (or zero)
                    assert!(!amount.is_negative());

                    // safely add to total
                    total_amount_for_utxo = total_amount_for_utxo.checked_add(&amount).unwrap();
                } else if coin_j.type_script_hash == Self::TIME_LOCK_HASH {
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
                total_timelocked_output = total_timelocked_output
                    .checked_add(&total_amount_for_utxo)
                    .unwrap();
            }
            i += 1;
        }

        assert!(fee >= NeptuneCoins::min(), "fee exceeds amount lower bound");
        assert!(fee <= NeptuneCoins::max(), "fee exceeds amount upper bound");

        // if coinbase is set, verify that half of it is time-locked
        let mut half_of_coinbase = some_coinbase;
        half_of_coinbase.div_two();
        let mut half_of_fee = fee;
        half_of_fee.div_two();
        assert!(some_coinbase.is_zero() || half_of_coinbase <= total_timelocked_output + half_of_fee,
            "not enough funds timelocked -- half of coinbase == {} > total_timelocked_output + half_of_fee == {} whereas total output == {}",
            half_of_coinbase,
            total_timelocked_output + half_of_fee,
            total_output,);

        // test no-inflation equation
        let total_input_plus_coinbase: NeptuneCoins =
            total_input.checked_add(&some_coinbase).unwrap();
        let total_output_plus_fee: NeptuneCoins = total_output.checked_add_negative(&fee).unwrap();
        assert_eq!(total_input_plus_coinbase, total_output_plus_fee);
    }

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
        let field_coins = field!(Utxo::coins);
        let field_type_script_hash = field!(Coin::type_script_hash);
        let field_state = field!(Coin::state);

        let hash_varlen = library.import(Box::new(HashVarlen));
        let merkle_verify =
            library.import(Box::new(tasm_lib::hashing::merkle_verify::MerkleVerify));
        let coin_size = NeptuneCoins::static_length().unwrap();
        let hash_fee = library.import(Box::new(HashStaticSize { size: coin_size }));
        let compare_coin_amount = DataType::compare_elem_of_stack_size(coin_size);
        let timestamp_size = 1;
        let hash_timestamp = library.import(Box::new(HashStaticSize {
            size: timestamp_size,
        }));
        let u128_safe_add = library.import(Box::new(tasm_lib::arithmetic::u128::safe_add::SafeAdd));
        let u128_overflowing_add = library.import(Box::new(
            tasm_lib::arithmetic::u128::overflowing_add::OverflowingAdd,
        ));
        let i128_shr = library.import(Box::new(
            tasm_lib::arithmetic::i128::shift_right::ShiftRight,
        ));
        let u128_lt = library.import(Box::new(tasm_lib::arithmetic::u128::lt::Lt));
        let i128_lt = library.import(Box::new(tasm_lib::arithmetic::i128::lt::Lt));
        let u64_lt = library.import(Box::new(tasm_lib::arithmetic::u64::lt::Lt));
        let coinbase_pointer_to_amount = library.import(Box::new(CoinbaseAmount));
        let audit_preloaded_data = library.import(Box::new(VerifyNdSiIntegrity::<
            NativeCurrencyWitnessMemory,
        >::default()));

        let own_program_digest_alloc = library.kmalloc(Digest::LEN as u32);
        let coinbase_release_date_alloc = library.kmalloc(1);

        let loop_utxos_add_amounts =
            "neptune_consensus_transaction_type_script_loop_utxos_add_amounts".to_string();
        let loop_coins_add_amounts_and_check_timelock =
            "neptune_consensus_transaction_type_script_loop_coins_add_amounts_and_check_timelock"
                .to_string();
        let read_and_add_amount =
            "neptune_consensus_transaction_type_script_read_and_add_amount".to_string();
        let add_timelocked_amount =
            "neptune_consensus_transaction_type_script_add_timelocked_amount".to_string();
        let test_time_lock_and_maybe_mark =
            "neptune_consensus_transaction_type_script_test_time_lock_and_maybe_mark".to_string();

        let store_own_program_digest = triton_asm!(
            // _

            dup 15 dup 15 dup 15 dup 15 dup 15
            // _ [own_program_digest]

            push {own_program_digest_alloc.write_address()}
            write_mem {Digest::LEN}
            pop 1
            // _
        );

        let load_own_program_digest = triton_asm! {
            // _

            push {own_program_digest_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
            // _ [own_program_digest]
        };

        let store_coinbase_release_date = triton_asm!(
            // _ release_date
            push {coinbase_release_date_alloc.write_address()}
            write_mem 1
            pop 1
            // _
        );
        let load_coinbase_release_date = triton_asm!(
            // _
            push {coinbase_release_date_alloc.read_address()}
            read_mem 1
            pop 1
            // _ release_date
        );

        let push_timelock_digest = Self::TIME_LOCK_HASH
            .values()
            .into_iter()
            .rev()
            .map(|v| triton_instr!(push v))
            .collect_vec();

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
            assert error_id {BAD_COINBASE_SIZE_ERROR}
            // _ coinbase_size
        );

        let push_max_amount = NeptuneCoins::max().push_to_stack();
        let push_min_amount = NeptuneCoins::min().push_to_stack();

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
            assert error_id {BAD_SALTED_UTXOS_ERROR}
            // _ *salted_utxos
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

            dup 1 addi {coin_size-1} read_mem {coin_size} pop 1
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant [fee]

            push 127 call {i128_shr}
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant [fee >> 127]
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant signs signs signs signs

            place 3 pop 3
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant signs

            push 2 place 1 div_mod
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant quotient sign

            place 1 pop 1
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant sign

            add
            // _ [txkmh] *ncw *coinbase *fee (coinbase_discriminant + sign)

            push 2 eq
            // _ [txkmh] *ncw *coinbase *fee (coinbase_discriminant && sign)

            push 0 eq
            // _ [txkmh] *ncw *coinbase *fee (!coinbase_discriminant || !sign)

            assert error_id {COINBASE_IS_SET_AND_FEE_IS_NEGATIVE}


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

            call {loop_utxos_add_amounts}
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

            call {loop_utxos_add_amounts}
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

            assert error_id {SUM_OF_OUTPUTS_EXCEEDS_MAX}

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

            assert error_id {SUM_OF_OUTPUTS_IS_NEGATIVE}

            // add half of fee to timelocked amount
            dup 14
            push {coin_size-1} add
            read_mem {coin_size}
            pop 1
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N N *output_utxos[N]_si * * * [total_output] [timelocked_amount] [fee]

            push 1
            call {i128_shr}
            call {u128_overflowing_add}
            pop 1
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N N *output_utxos[N]_si * * * [total_output] [total_timelocked]

            hint total_timelocked : u128 = stack[0..4]

            pick 8 pop 1
            pick 8 pop 1
            pick 8 pop 1
            pick 8 pop 1
            pick 8 pop 1
            pick 8 pop 1
            pick 8 pop 1
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] [total_output] [total_timelocked]

            pick 12 pop 1
            pick 12 pop 1
            pick 12 pop 1
            pick 12 pop 1
            pick 12 pop 1
            pick 12 pop 1
            pick 12 pop 1
            // _ [txkmh] *ncw *coinbase *fee [total_input] [total_output] [total_timelocked]

            pick 13
            call {coinbase_pointer_to_amount}
            // _ [txkmh] *ncw *fee [total_input] [total_output] [total_timelocked] [coinbase]
            hint coinbase = stack[0..4]

            push 1
            call {i128_shr}
            // _ [txkmh] *ncw *fee [total_input] [total_output] [total_timelocked] [coinbase/2]

            pick 7
            pick 7
            pick 7
            pick 7
            call {u128_lt}
            // _ [txkmh] *ncw *fee [total_input] [total_output] (total_timelocked < coinbase/2)

            push 0 eq
            // _ [txkmh] *ncw *fee [total_input] [total_output] (total_timelocked >= coinbase/2)

            assert error_id {COINBASE_TIMELOCK_INSUFFICIENT}
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

            assert error_id {FEE_EXCEEDS_MAX}
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

            assert error_id {FEE_EXCEEDS_MIN}
            // _ [txkmh] *ncw [total_input] [total_output] [fee]

            call {u128_overflowing_add}
            pop 1
            // _ [txkmh] *ncw [total_input] [total_output']

            {&compare_coin_amount}
            // _ [txkmh] *ncw (total_input == total_output')

            assert error_id {NO_INFLATION_VIOLATION}
            // _ [txkmh] *ncw

            pop 1
            pop 5
            // _

            halt
        };

        let subroutines = triton_asm! {

            // INVARIANT: _ N i *utxos[i]_si * * * [amount] [timelocked_amount]
            {loop_utxos_add_amounts}:

                dup 13 dup 13 eq
                // _ N i *utxos[i]_si * * * [amount] [timelocked_amount] (N == i)

                skiz return
                // _ N i *utxos[i]_si * * * [amount] [timelocked_amount]

                dup 11 push 1 add
                // _ N i *utxos[i]_si * * * [amount] [timelocked_amount] *utxos[i]

                {&field_coins}
                // _ N i *utxos[i]_si * * * [amount] [timelocked_amount] *coins

                read_mem 1 push 2 add
                // _ N i *utxos[i]_si * * * [amount] [timelocked_amount] M *coins[0]_si

                swap 10 pop 1
                // _ N i *utxos[i]_si * * *coins[0]_si [amount] [timelocked_amount] M

                swap 11 pop 1
                // _ N i *utxos[i]_si M * *coins[0]_si [amount] [timelocked_amount]

                push 0 swap 10 pop 1
                // _ N i *utxos[i]_si M 0 *coins[0]_si [amount] [timelocked_amount]

                hint coins_j_si = stack[8]
                hint j = stack[9]
                hint emm = stack[10]

                push 0 push 0 push 0 push 0
                push 0
                // _ N i *utxos[i]_si M 0 *coins[0]_si [amount] [timelocked_amount] [utxo_amount] false
                hint utxo_is_timelocked = stack[0]

                call {loop_coins_add_amounts_and_check_timelock}
                // _ N i *utxos[i]_si M M *coins[M]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked

                skiz call {add_timelocked_amount}
                // _ N i *utxos[i]_si M M *coins[M]_si [amount] [timelocked_amount'] [utxo_amount]

                pick 11 pick 11 pick 11 pick 11
                call {u128_safe_add}
                pick 7 pick 7 pick 7 pick 7
                // _ N i *utxos[i]_si M M *coins[M]_si [amount'] [timelocked_amount']

                // prepare next iteration
                dup 12 addi 1
                // _ N i *utxos[i]_si M M *coins[M]_si [amount'] [timelocked_amount'] (i+1)

                swap 13 pop 1
                // _ N (i+1) *utxos[i]_si M M *coins[M]_si [amount'] [timelocked_amount']

                dup 11 read_mem 1 push 2 add
                // _ N (i+1) *utxos[i]_si M M *coins[M]_si [amount'] [timelocked_amount'] size(utxos[i]) *utxos[i]

                push  {DEFAULT_MAX_DYN_FIELD_SIZE}
                dup 2
                lt
                assert error_id {UTXO_SIZE_TOO_LARGE_ERROR}

                add swap 12 pop 1
                // _ N (i+1) *utxos[i+1]_si M M *coins[M]_si [amount'] [timelocked_amount']

                recurse

            // BEFORE: _ [timelocked_amount] [utxo_amount]
            // AFTER: _ [timelocked_amount'] [utxo_amount]
            {add_timelocked_amount}:
                pick 7 pick 7 pick 7 pick 7
                // _ [utxo_amount] [timelocked_amount]

                dup 7 dup 7 dup 7 dup 7
                // _ [utxo_amount] [timelocked_amount] [utxo_amount]

                call {u128_safe_add}
                // _ [utxo_amount] [timelocked_amount']

                pick 7 pick 7 pick 7 pick 7
                // _ [timelocked_amount'] [utxo_amount]
                return

            // INVARIANT: _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked
            {loop_coins_add_amounts_and_check_timelock}:
                hint utxo_amount = stack[1..5]

                // evaluate termination criterion and return if necessary
                dup 15 dup 15 eq
                // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked (M == j)

                skiz return
                // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked


                // if coin is native currency, add amount
                dup 13 push 1 add
                hint coins_j = stack[0]
                // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked *coins[j]

                {&field_type_script_hash}
                hint type_script_hash_ptr = stack[0]
                // _ M j *coins[j]_si [amount] [timelocked_amount]  [utxo_amount] utxo_is_timelocked *type_script_hash

                push {Digest::LEN-1} add read_mem {Digest::LEN} pop 1
                hint type_script_hash : Digest = stack[0..5]
                // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked [type_script_hash]

                {&load_own_program_digest}
                hint own_program_digest = stack[0..5]
                // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked [type_script_hash] [own_program_digest]

                {&digest_eq}
                hint digests_are_equal = stack[0]
                // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked (type_script_hash == own_program_digest)

                skiz call {read_and_add_amount}
                // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked


                // if coin is timelock, test and mark if necessary
                dup 13 push 1 add
                hint coins_j = stack[0]
                // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked *coins[j]

                {&field_type_script_hash}
                hint type_script_hash_ptr = stack[0]
                // _ M j *coins[j]_si [amount] [timelocked_amount]  [utxo_amount'] utxo_is_timelocked *type_script_hash

                push {Digest::LEN-1} add read_mem {Digest::LEN} pop 1
                hint type_script_hash : Digest = stack[0..5]
                // _ M j *coins[j]_si [amount] [timelocked_amount]  [utxo_amount'] utxo_is_timelocked [type_script_hash]

                {&push_timelock_digest}
                // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked [type_script_hash] [timelock_digest]

                {&digest_eq}
                // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked (type_script_hash == timelock_digest)

                skiz call {test_time_lock_and_maybe_mark}
                // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked


                // prepare for next iteration
                dup 14 push 1 add swap 15 pop 1
                // _ M (j+1) *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked

                dup 13 read_mem 1 push 2 add
                // _ M (j+1) *coins[j]_si [amount] [timelocked_amount]  [utxo_amount] utxo_is_timelocked size(coins[j]) *coins[j]

                /* Range-check on size */
                push {DEFAULT_MAX_DYN_FIELD_SIZE}
                dup 2
                lt
                assert error_id {TOO_BIG_COIN_FIELD_SIZE_ERROR}
                // _ M (j+1) *coins[j]_si [amount] [timelocked_amount]  [utxo_amount] utxo_is_timelocked size(coins[j]) *coins[j]

                add
                // _ M (j+1) *coins[j]_si [amount] [timelocked_amount]  [utxo_amount] utxo_is_timelocked *coins[j+1]_si

                swap 14 pop 1
                // _ M (j+1) *coins[j+1]_si [amount] [timelocked_amount]  [utxo_amount] utxo_is_timelocked

                recurse


                // The coin is a time lock. Test the state, which encodes a
                // release date, against the timestamp of the transaction kernel
                // plus the coinbase timelock period.
                // INVARIANT: _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked
                {test_time_lock_and_maybe_mark}:
                    dup 13 push 1 add
                    hint coins_j = stack[0]
                    // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked *coin[j]

                    {&field_state}
                    // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked *coin[j].state

                    addi 1 read_mem 2 pop 1
                    // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked state[0] state.len()

                    // time lock states must encode exactly one element
                    assert error_id {STATE_LENGTH_FOR_TIME_LOCK_NOT_ONE_ERROR}
                    // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked utxo_release_date

                    split
                    // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked utxo_release_date_hi utxo_release_date_lo

                    {&load_coinbase_release_date}
                    // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked utxo_release_date_hi utxo_release_date_lo coinbase_release_date

                    split
                    // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked utxo_release_date_hi utxo_release_date_lo coinbase_release_date_hi coinbase_release_date_lo

                    pick 3 pick 3
                    // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked coinbase_release_date_hi coinbase_release_date_lo utxo_release_date_hi utxo_release_date_lo

                    call {u64_lt}
                    // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked (utxo_release_date < coinbase_release_date)

                    push 0 eq
                    // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked (coinbase_release_date <= utxo_release_date)

                    add push 0 lt
                    // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] ((utxo_is_timelocked + (coinbase_release_date <= utxo_release_date)) > 0)
                    // _ M j *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked'

                    return


                // BEFORE: _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked
                // AFTER:  _ *coins[j]_si [amount'] [timelocked_amount] [utxo_amount] utxo_is_timelocked
                {read_and_add_amount}:
                    hint utxo_is_timelocked = stack[0]
                    hint utxo_amount = stack[1..5]
                    hint timelocked_amount = stack[5..9]

                    dup 13 addi 1
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked *coins[j]

                    {&field_state}
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked *state
                    hint state_ptr = stack[0]

                    read_mem 1
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked state_size (*state+1)

                    addi {coin_size+1}
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked state_size *state[last]
                    hint state_last_ptr = stack[0]

                    swap 1 push {coin_size} eq
                    assert error_id {BAD_STATE_SIZE_ERROR}
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked *state[last]

                    read_mem {coin_size} pop 1
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked [coin_amount]

                    pick 8 pick 8 pick 8 pick 8
                    // _ *coins[j]_si [amount] [timelocked_amount] utxo_is_timelocked [coin_amount] [utxo_amount]

                    call {u128_safe_add}
                    // _ *coins[j]_si [amount] [timelocked_amount] utxo_is_timelocked [utxo_amount']

                    pick 4
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked

                    return
        };

        let imports = library.all_imports();

        let code = triton_asm!(
            {&main_code}
            {&subroutines}
            {&imports}
        );

        (library, code)
    }

    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }
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
    coinbase: Option<NeptuneCoins>,
    fee: NeptuneCoins,
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
pub mod test {
    use std::panic;

    use num_traits::Zero;
    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::triton_vm;
    use tasm_lib::triton_vm::proof::Claim;
    use tasm_lib::triton_vm::stark::Stark;
    use test_strategy::proptest;

    use super::*;
    use crate::job_queue::triton_vm::TritonVmJobPriority;
    use crate::job_queue::triton_vm::TritonVmJobQueue;
    use crate::models::blockchain::transaction::lock_script::LockScriptAndWitness;
    use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
    use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::models::blockchain::transaction::utxo::Utxo;
    use crate::models::blockchain::transaction::PublicAnnouncement;
    use crate::models::blockchain::type_scripts::neptune_coins::test::invalid_positive_amount;
    use crate::models::blockchain::type_scripts::time_lock::arbitrary_primitive_witness_with_active_timelocks;
    use crate::models::blockchain::type_scripts::time_lock::TimeLock;
    use crate::models::proof_abstractions::tasm::program::test::consensus_program_negative_test;
    use crate::models::proof_abstractions::tasm::program::ConsensusError;
    use crate::models::proof_abstractions::timestamp::Timestamp;

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
        consensus_program_negative_test(NativeCurrency, &stdin, nd, expected_error_ids);
    }

    #[test]
    fn native_currency_derived_witness_generates_accepting_tasm_program_empty_tx() {
        // Generate a tx with coinbase input, no outputs, fee-size is the same
        // as the coinbase, so tx is valid.
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(0), 0, 0)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness);
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

    #[proptest(cases = 50)]
    fn balanced_transaction_is_valid(
        #[strategy(0usize..=3)] _num_inputs: usize,
        #[strategy(0usize..=3)] _num_outputs: usize,
        #[strategy(0usize..=1)] _num_public_announcements: usize,
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(Some(#_num_inputs), #_num_outputs, #_num_public_announcements))]
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
        #[strategy(0usize..=1)] _num_public_announcements: usize,
        #[strategy(arb::<Timestamp>())] _now: Timestamp,
        #[strategy(arbitrary_primitive_witness_with_active_timelocks(
            #_num_inputs,
            #_num_outputs,
            #_num_public_announcements,
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
        #[strategy(0usize..=3)] _num_public_announcements: usize,
        #[strategy(vec(arb::<Utxo>(), #_num_inputs))] _input_utxos: Vec<Utxo>,
        #[strategy(vec(arb::<LockScriptAndWitness>(), #_num_inputs))]
        _input_lock_scripts_and_witnesses: Vec<LockScriptAndWitness>,
        #[strategy(vec(arb::<Utxo>(), #_num_outputs))] _output_utxos: Vec<Utxo>,
        #[strategy(vec(arb(), #_num_public_announcements))] _public_announcements: Vec<
            PublicAnnouncement,
        >,
        #[strategy(arb())] _fee: NeptuneCoins,
        #[strategy(PrimitiveWitness::arbitrary_primitive_witness_with(
            &#_input_utxos,
            &#_input_lock_scripts_and_witnesses,
            &#_output_utxos,
            &#_public_announcements,
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
            &[NO_INFLATION_VIOLATION],
        )?;
    }

    #[proptest(cases = 50)]
    fn unbalanced_transaction_with_coinbase_is_invalid(
        #[strategy(1usize..=3)] _num_inputs: usize,
        #[strategy(1usize..=3)] _num_outputs: usize,
        #[strategy(1usize..=3)] _num_public_announcements: usize,
        #[strategy(NeptuneCoins::arbitrary_non_negative())] _coinbase: NeptuneCoins,
        #[strategy(vec(arb::<Utxo>(), #_num_inputs))] _input_utxos: Vec<Utxo>,
        #[strategy(vec(arb::<LockScriptAndWitness>(), #_num_inputs))]
        _input_lock_scripts_and_witnesses: Vec<LockScriptAndWitness>,
        #[strategy(vec(arb::<Utxo>(), #_num_outputs))] _output_utxos: Vec<Utxo>,
        #[strategy(vec(arb(), #_num_public_announcements))] _public_announcements: Vec<
            PublicAnnouncement,
        >,
        #[strategy(arb())] _fee: NeptuneCoins,
        #[strategy(PrimitiveWitness::arbitrary_primitive_witness_with(
            &#_input_utxos,
            &#_input_lock_scripts_and_witnesses,
            &#_output_utxos,
            &#_public_announcements,
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
                NO_INFLATION_VIOLATION,
                COINBASE_TIMELOCK_INSUFFICIENT,
                COINBASE_IS_SET_AND_FEE_IS_NEGATIVE,
            ],
        )?;
    }

    #[tokio::test]
    async fn tx_with_negative_fee_has_coinbase_deterministic() {
        let mut test_runner = TestRunner::deterministic();
        let mut primitive_witness = PrimitiveWitness::arbitrary_with_fee(-NeptuneCoins::new(1))
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let good_native_currency_witness = NativeCurrencyWitness::from(primitive_witness.clone());
        assert_both_rust_and_tasm_halt_gracefully(good_native_currency_witness).unwrap();

        let kernel_modifier =
            TransactionKernelModifier::default().coinbase(Some(NeptuneCoins::new(1)));
        primitive_witness.kernel = kernel_modifier.modify(primitive_witness.kernel);
        let bad_native_currency_witness = NativeCurrencyWitness::from(primitive_witness.clone());
        NativeCurrency
            .test_assertion_failure(
                bad_native_currency_witness.standard_input(),
                bad_native_currency_witness.nondeterminism(),
                &[COINBASE_IS_SET_AND_FEE_IS_NEGATIVE],
            )
            .unwrap();
    }

    #[tokio::test]
    async fn native_currency_failing_proof() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 2)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let txk_mast_hash = primitive_witness.kernel.mast_hash();
        let salted_input_utxos_hash = Hash::hash(&primitive_witness.input_utxos);
        let salted_output_utxos_hash = Hash::hash(&primitive_witness.output_utxos);

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
                &TritonVmJobQueue::dummy(),
                TritonVmJobPriority::default().into(),
            )
            .await
            .unwrap();
        assert!(
            triton_vm::verify(Stark::default(), &claim, &proof),
            "proof fails"
        );
    }

    #[proptest]
    fn transaction_with_timelocked_coinbase_is_valid(
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(None, 2, 2))]
        #[filter(!#primitive_witness.kernel.fee.is_negative())]
        primitive_witness: PrimitiveWitness,
    ) {
        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness);
        assert_both_rust_and_tasm_halt_gracefully(native_currency_witness).unwrap();
    }

    #[test]
    fn transaction_with_timelocked_coinbase_is_valid_deterministic() {
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
            let public_announcements = sample(vec(arb(), 3), &mut tr);
            let fee = sample(NeptuneCoins::arbitrary_non_negative(), &mut tr);
            let primitive_witness = PrimitiveWitness::arbitrary_primitive_witness_with(
                &input_utxos,
                &input_lock_scripts_and_witnesses,
                &output_utxos,
                &public_announcements,
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
                &[NO_INFLATION_VIOLATION],
            );
            assert!(result.is_ok());
        }
    }

    #[proptest]
    fn coinbase_transaction_with_not_enough_funds_timelocked_is_invalid(
        #[strategy(1usize..=3)] _num_outputs: usize,
        #[strategy(1usize..=3)] _num_public_announcements: usize,
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(
            None,
            #_num_outputs,
            #_num_public_announcements
        ))]
        mut primitive_witness: PrimitiveWitness,
        #[strategy(arb())]
        #[filter(NeptuneCoins::zero() < #delta)]
        delta: NeptuneCoins,
    ) {
        // Modify the kernel so as to increase the coinbase but not the fee. The
        // resulting transaction is imbalanced but since the timelocked coinbase
        // amount is checked prior to the input/output balancing check, we know
        // which assert will be hit.
        let coinbase = primitive_witness.kernel.coinbase.unwrap();
        let kernel_modifier = TransactionKernelModifier::default().coinbase(Some(coinbase + delta));
        primitive_witness.kernel = kernel_modifier.modify(primitive_witness.kernel);
        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness);
        assert_both_rust_and_tasm_fail(native_currency_witness, &[COINBASE_TIMELOCK_INSUFFICIENT]);
    }

    #[proptest]
    fn coinbase_transaction_with_too_early_release_is_invalid_fixed_delta(
        #[strategy(1usize..=3)] _num_outputs: usize,
        #[strategy(1usize..=3)] _num_public_announcements: usize,
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(
            None,
            #_num_outputs,
            #_num_public_announcements
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
        assert_both_rust_and_tasm_fail(native_currency_witness, &[COINBASE_TIMELOCK_INSUFFICIENT]);
    }

    #[proptest(cases = 50)]
    fn coinbase_transaction_with_too_early_release_is_invalid_prop_delta(
        #[strategy(1usize..=3)] _num_outputs: usize,
        #[strategy(1usize..=3)] _num_public_announcements: usize,
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(
            None,
            #_num_outputs,
            #_num_public_announcements
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
        assert_both_rust_and_tasm_fail(native_currency_witness, &[COINBASE_TIMELOCK_INSUFFICIENT]);
    }

    #[test]
    fn hardcoded_time_lock_hash_matches_hash_of_time_lock_program() {
        let calculated = TimeLock.hash();
        assert_eq!(
            NativeCurrency::TIME_LOCK_HASH,
            calculated,
            "Timelock.hash():\n{}",
            calculated
        );
    }

    #[proptest]
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
            let fee = NeptuneCoins::arbitrary_non_negative()
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
        #[strategy(NeptuneCoins::arbitrary_non_negative())] _fee: NeptuneCoins,
        #[strategy(PrimitiveWitness::arbitrary_with_fee(#_fee))]
        primitive_witness: PrimitiveWitness,
    ) {
        assert_both_rust_and_tasm_halt_gracefully(NativeCurrencyWitness::from(primitive_witness))?;
    }

    #[proptest]
    fn fee_can_be_negative(
        #[strategy(NeptuneCoins::arbitrary_non_negative())] _fee: NeptuneCoins,
        #[strategy(PrimitiveWitness::arbitrary_with_fee(-#_fee))]
        primitive_witness: PrimitiveWitness,
    ) {
        assert_both_rust_and_tasm_halt_gracefully(NativeCurrencyWitness::from(primitive_witness))?;
    }

    #[proptest]
    fn positive_fee_cannot_exceed_max_nau(
        #[strategy(invalid_positive_amount())] _fee: NeptuneCoins,
        #[strategy(PrimitiveWitness::arbitrary_with_fee(#_fee))]
        primitive_witness: PrimitiveWitness,
    ) {
        assert_both_rust_and_tasm_fail(
            NativeCurrencyWitness::from(primitive_witness),
            &[FEE_EXCEEDS_MAX],
        );
    }

    #[ignore]
    #[proptest]
    fn negative_fee_cannot_exceed_min_nau(
        #[strategy(invalid_positive_amount())] _fee: NeptuneCoins,
        #[strategy(PrimitiveWitness::arbitrary_with_fee(-#_fee))]
        primitive_witness: PrimitiveWitness,
    ) {
        assert_both_rust_and_tasm_fail(
            NativeCurrencyWitness::from(primitive_witness),
            &[FEE_EXCEEDS_MIN],
        );

        // It is actually impossible to trigger this assert error id -- or is it?
        // I'm not convinced.
    }
}
