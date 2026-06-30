use tasm_lib::library::StaticAllocation;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::prelude::TasmStruct;
use tasm_lib::triton_vm::isa::triton_asm;
use tasm_lib::triton_vm::prelude::LabelledInstruction;

use crate::protocol::consensus::transaction::utxo::Coin;
use crate::protocol::consensus::type_scripts::amount::STATE_LENGTH_FOR_TIME_LOCK_NOT_ONE_ERROR;

#[derive(Debug, Clone, Copy)]
pub(crate) struct TestTimeLockAndMaybeMark {
    /// Must be of [size](StaticAllocation::num_words) 1, else this snippet
    /// will cause a rust-runtime, tasm-compiletime panic.
    pub(crate) release_date: StaticAllocation,
}

impl BasicSnippet for TestTimeLockAndMaybeMark {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*coin".to_string()),
            (DataType::U128, "amount".to_string()),
            (DataType::U128, "timelocked_amount".to_string()),
            (DataType::U128, "utxo_amount".to_string()),
            (DataType::Bool, "utxo_is_timelocked".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*coin".to_string()),
            (DataType::U128, "amount".to_string()),
            (DataType::U128, "timelocked_amount".to_string()),
            (DataType::U128, "utxo_amount".to_string()),
            (DataType::Bool, "utxo_is_timelocked'".to_string()),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_type_script_total_amount_test_time_lock_and_maybe_mark".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        assert_eq!(1, self.release_date.num_words());

        let u64_lt = library.import(Box::new(tasm_lib::arithmetic::u64::lt::Lt));

        triton_asm! {
            // BEFORE: _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked
            // AFTER:  _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked'
            {self.entrypoint()}:
                dup 13 push 1 add
                hint coins_j = stack[0]
                // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked *coin[j]

                {&Coin::get_field("state")}
                // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked *coin[j].state

                addi 1 read_mem 2 pop 1
                // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked state[0] state.len()

                // time lock states must encode exactly one element
                assert error_id {STATE_LENGTH_FOR_TIME_LOCK_NOT_ONE_ERROR}
                // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked utxo_release_date

                split
                // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked utxo_release_date_hi utxo_release_date_lo

                push {self.release_date.read_address()}
                read_mem 1
                pop 1
                // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked utxo_release_date_hi utxo_release_date_lo coinbase_release_date

                split
                // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked utxo_release_date_hi utxo_release_date_lo coinbase_release_date_hi coinbase_release_date_lo

                pick 3 pick 3
                // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked coinbase_release_date_hi coinbase_release_date_lo utxo_release_date_hi utxo_release_date_lo

                call {u64_lt}
                // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked (utxo_release_date < coinbase_release_date)

                push 0 eq
                // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked (coinbase_release_date <= utxo_release_date)

                add push 0 lt
                // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] ((utxo_is_timelocked + (coinbase_release_date <= utxo_release_date)) > 0)
                // _ *coins[j]_si [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked'

                return
        }
    }
}
