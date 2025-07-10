use tasm_lib::field;
use tasm_lib::library::StaticAllocation;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Library;
use tasm_lib::structure::tasm_object::DEFAULT_MAX_DYN_FIELD_SIZE;
use tasm_lib::triton_vm::isa::triton_asm;
use tasm_lib::triton_vm::prelude::LabelledInstruction;

use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::type_scripts::amount::add_all_amounts_and_check_time_lock::AddAllAmountsAndCheckTimeLock;
use crate::models::blockchain::type_scripts::amount::add_time_locked_amount::AddTimelockedAmount;
use crate::models::blockchain::type_scripts::amount::read_and_add_amount::ReadAndAddAmount;
use crate::models::blockchain::type_scripts::amount::test_time_lock_and_maybe_mark::TestTimeLockAndMaybeMark;
use crate::models::blockchain::type_scripts::amount::UTXO_SIZE_TOO_LARGE_ERROR;

#[derive(Debug, Clone, Copy)]
pub enum DigestSource {
    StaticMemory(StaticAllocation),
    Hardcode(Digest),
}

/// Compute the total amount and total timelocked amount from a list of UTXOs.
///
/// This snippet covers the inner body of the loop; the correct setup is the
/// responsibility of the caller.
//
// This snippet was previously inlined in `NativeCurrency` and there it was
// called `loop_utxos_add_amount` (ignoring the prefix).

#[derive(Debug, Clone, Copy)]
pub struct TotalAmountMainLoop {
    pub digest_source: DigestSource,
    pub release_date: StaticAllocation,
}

impl TotalAmountMainLoop {
    /// Produce the snippet's source code, along with non-imported dependencies,
    /// in a format that
    /// [`NativeCurrency`](super::super::native_currency::NativeCurrency)
    /// expects.
    ///
    /// Note: this is a backwards-compatibility layer. Under normal
    /// circumstances it would be preferable to use `Library::import` and let
    /// the [`Library`] handle the dependencies.
    pub fn view_for_native_currency(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let add_timelocked_amount = AddTimelockedAmount;
        let add_timelocked_amount_code = add_timelocked_amount.code(library);
        let add_timelocked_amount_label = add_timelocked_amount.entrypoint();

        let test_time_lock_and_maybe_mark = TestTimeLockAndMaybeMark {
            release_date: self.release_date,
        };
        let test_time_lock_and_maybe_mark_code = test_time_lock_and_maybe_mark.code(library);
        let test_time_lock_and_maybe_mark_label = test_time_lock_and_maybe_mark.entrypoint();

        let read_and_add_amount = ReadAndAddAmount;
        let read_and_add_amount_code = read_and_add_amount.code(library);
        let read_and_add_amount_label = read_and_add_amount.entrypoint();

        let add_all_amounts_and_check_time_lock = AddAllAmountsAndCheckTimeLock {
            digest_source: self.digest_source,
            release_date: self.release_date,
        };
        let add_all_amounts_and_check_time_lock_code = add_all_amounts_and_check_time_lock
            .view_for_main_loop(
                test_time_lock_and_maybe_mark_label,
                read_and_add_amount_label,
            );
        let add_all_amounts_and_check_time_lock_label =
            add_all_amounts_and_check_time_lock.entrypoint();

        triton_asm! {
            {&self.main_loop(library, add_all_amounts_and_check_time_lock_label, add_timelocked_amount_label)}
            {&add_timelocked_amount_code}
            {&add_all_amounts_and_check_time_lock_code}
            {&test_time_lock_and_maybe_mark_code}
            {&read_and_add_amount_code}
        }
    }

    fn main_loop(
        &self,
        library: &mut Library,
        loop_coins_add_amounts_and_check_timelock: String,
        add_timelocked_amount: String,
    ) -> Vec<LabelledInstruction> {
        let field_coins = field!(Utxo::coins);

        let u128_safe_add = library.import(Box::new(tasm_lib::arithmetic::u128::safe_add::SafeAdd));

        triton_asm! {

            // INVARIANT: _ N i *utxos[i]_si * * * [amount] [timelocked_amount]
            {self.entrypoint()}:

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
        }
    }
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
        self.view_for_native_currency(library)
    }
}
