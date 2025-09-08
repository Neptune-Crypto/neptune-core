use tasm_lib::field;
use tasm_lib::library::StaticAllocation;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Library;
use tasm_lib::structure::tasm_object::DEFAULT_MAX_DYN_FIELD_SIZE;
use tasm_lib::triton_vm::isa::triton_asm;
use tasm_lib::triton_vm::prelude::LabelledInstruction;

use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::protocol::consensus::type_scripts::amount::add_all_amounts_and_check_time_lock::AddAllAmountsAndCheckTimeLock;
use crate::protocol::consensus::type_scripts::amount::add_time_locked_amount::AddTimelockedAmount;
use crate::protocol::consensus::type_scripts::amount::UTXO_SIZE_TOO_LARGE_ERROR;

#[derive(Debug, Clone, Copy)]
pub enum DigestSource {
    StaticMemory(StaticAllocation),
    Hardcode(Digest),
}

#[derive(Debug, Clone, Copy)]
pub struct TotalAmountMainLoop {
    pub digest_source: DigestSource,
    pub release_date: StaticAllocation,
}

impl BasicSnippet for TotalAmountMainLoop {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::U32, "num_utxos".to_string()),
            (DataType::U32, "utxo_index".to_string()),
            (DataType::VoidPointer, "*input_utxos[i]_si".to_string()),
            (DataType::U32, "padding_for_M".to_string()),
            (DataType::U32, "padding_for_j".to_string()),
            (
                DataType::VoidPointer,
                "padding_for_*coins[j]_si".to_string(),
            ),
            (DataType::U128, "initial_total_amount".to_string()),
            (DataType::U128, "initial_timelocked_amount".to_string()),
        ]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::U32, "num_utxos".to_string()),
            (DataType::U32, "num_utxos".to_string()),
            (DataType::VoidPointer, "*input_utxos[N]_si".to_string()),
            (DataType::U32, "garbage_M".to_string()),
            (DataType::U32, "garbage_j".to_string()),
            (DataType::VoidPointer, "garbage_*coins[j]_si".to_string()),
            (DataType::U128, "final_total_amount".to_string()),
            (DataType::U128, "final_timelocked_amount".to_string()),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_type_script_total_amount_main_loop".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let add_timelocked_amount_label = library.import(Box::new(AddTimelockedAmount));
        let add_all_amounts_and_check_time_lock_label =
            library.import(Box::new(AddAllAmountsAndCheckTimeLock {
                digest_source: self.digest_source,
                release_date: self.release_date,
            }));

        let field_coins = field!(Utxo::coins);

        let u128_safe_add = library.import(Box::new(tasm_lib::arithmetic::u128::safe_add::SafeAdd));

        triton_asm! {

            // INVARIANT: _ N i *utxos[i]_si * * * [amount] [timelocked_amount]
            {self.entrypoint()}:

                dup 13 dup 13 eq
                // _ N i *utxos[i]_si * * * [amount] [timelocked_amount] (N == i)

                skiz return
                // _ N i *utxos[i]_si * * * [amount] [timelocked_amount]

                dup 11 addi 1
                // _ N i *utxos[i]_si * * * [amount] [timelocked_amount] *utxos[i]

                {&field_coins}
                // _ N i *utxos[i]_si * * * [amount] [timelocked_amount] *coins

                read_mem 1 addi 2
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

                call {add_all_amounts_and_check_time_lock_label}
                // _ N i *utxos[i]_si M M *coins[M]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked

                skiz call {add_timelocked_amount_label}
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

                dup 11 read_mem 1 addi 2
                // _ N (i+1) *utxos[i]_si M M *coins[M]_si [amount'] [timelocked_amount'] size(utxos[i]) *utxos[i]

                push  {DEFAULT_MAX_DYN_FIELD_SIZE}
                dup 2
                lt
                assert error_id {UTXO_SIZE_TOO_LARGE_ERROR}

                add swap 12 pop 1
                // _ N (i+1) *utxos[i+1]_si M M *coins[M]_si [amount'] [timelocked_amount']

                recurse
        }
    }
}
