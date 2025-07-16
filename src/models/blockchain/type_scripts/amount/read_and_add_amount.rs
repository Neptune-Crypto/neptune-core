use tasm_lib::field;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::isa::triton_asm;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::prelude::LabelledInstruction;

use crate::api::export::NativeCurrencyAmount;
use crate::models::blockchain::transaction::utxo::Coin;
use crate::models::blockchain::type_scripts::amount::BAD_STATE_SIZE_ERROR;
use crate::models::blockchain::type_scripts::native_currency::NativeCurrency;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ReadAndAddAmount;

impl BasicSnippet for ReadAndAddAmount {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*coin_si".to_string()),
            (DataType::U128, "amount".to_string()),
            (DataType::U128, "timelocked_amount".to_string()),
            (DataType::U128, "utxo_amount".to_string()),
            (DataType::Bool, "utxo_is_timelocked".to_string()),
        ]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*coin_si".to_string()),
            (DataType::U128, "amount".to_string()),
            (DataType::U128, "timelocked_amount".to_string()),
            (DataType::U128, "utxo_amount'".to_string()),
            (DataType::Bool, "utxo_is_timelocked".to_string()),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_type_script_amount_read_and_add_amount".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let field_state = field!(Coin::state);

        let u128_safe_add = library.import(Box::new(tasm_lib::arithmetic::u128::safe_add::SafeAdd));
        let u128_lt = library.import(Box::new(tasm_lib::arithmetic::u128::lt::Lt));

        let coin_size = NativeCurrencyAmount::static_length().unwrap();
        let push_max_amount = NativeCurrencyAmount::max().push_to_stack();

        triton_asm! {
                // BEFORE: _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked
                // AFTER:  _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked
                {self.entrypoint()}:
                    hint utxo_is_timelocked = stack[0]
                    hint utxo_amount = stack[1..5]
                    hint timelocked_amount = stack[5..9]

                    dup 13 addi 1
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked *coins[j]

                    {&field_state}
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked *state
                    hint state_ptr = stack[0]

                    read_mem 1
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked state_size (*state-1)

                    addi {coin_size+1}
                    hint state_last_ptr = stack[0]
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked state_size *state[last]

                    swap 1 push {coin_size} eq
                    assert error_id {BAD_STATE_SIZE_ERROR}
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked *state[last]

                    read_mem {coin_size} pop 1
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked [coin_amount]

                    /* assert 0 <= coin_amount <= max */
                    dup 3
                    dup 3
                    dup 3
                    dup 3
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked [coin_amount] [coin_amount]

                    {&push_max_amount}
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked [coin_amount] [coin_amount] [max_amount]

                    call {u128_lt}
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked [coin_amount] (max_amount < coin_amount)

                    push 0 eq
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked [coin_amount] (max_amount >= coin_amount)

                    assert error_id {NativeCurrency::INVALID_COIN_AMOUNT}
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked [coin_amount]

                    pick 8 pick 8 pick 8 pick 8
                    // _ *coins[j]_si [amount] [timelocked_amount] utxo_is_timelocked [coin_amount] [utxo_amount]

                    call {u128_safe_add}
                    // _ *coins[j]_si [amount] [timelocked_amount] utxo_is_timelocked [utxo_amount']

                    pick 4
                    // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked

                    return
        }
    }
}
