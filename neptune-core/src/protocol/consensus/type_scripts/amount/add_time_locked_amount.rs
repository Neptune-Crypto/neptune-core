use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::isa::triton_asm;
use tasm_lib::triton_vm::prelude::LabelledInstruction;

/// Replace the amount on stack elements 4..8 with the sum of the
/// amount living on 0..4 and 4..8.

#[derive(Debug, Clone, Copy)]
pub(crate) struct AddTimelockedAmount;

impl BasicSnippet for AddTimelockedAmount {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::U128, "timelocked_amount".to_string()),
            (DataType::U128, "utxo_amount".to_string()),
        ]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::U128, "sum".to_string()),
            (DataType::U128, "utxo_amount".to_string()),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_type_script_total_amount__add_timelocked_amount".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let u128_safe_add = library.import(Box::new(tasm_lib::arithmetic::u128::safe_add::SafeAdd));

        triton_asm! {
            // BEFORE: _ [timelocked_amount] [utxo_amount]
            // AFTER: _ [timelocked_amount'] [utxo_amount]
            {self.entrypoint()}:
                pick 7 pick 7 pick 7 pick 7
                // _ [utxo_amount] [timelocked_amount]

                dup 7 dup 7 dup 7 dup 7
                // _ [utxo_amount] [timelocked_amount] [utxo_amount]

                call {u128_safe_add}
                // _ [utxo_amount] [timelocked_amount']

                pick 7 pick 7 pick 7 pick 7
                // _ [timelocked_amount'] [utxo_amount]
                return
        }
    }
}
