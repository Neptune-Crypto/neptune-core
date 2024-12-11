use tasm_lib::prelude::Digest;

use super::native_currency::NativeCurrency;
use super::native_currency::NativeCurrencyWitness;
use super::time_lock::TimeLock;
use super::time_lock::TimeLockWitness;
use super::TypeScriptAndWitness;
use super::TypeScriptWitness;
use crate::models::blockchain::transaction::primitive_witness::SaltedUtxos;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;

pub(crate) fn match_type_script_and_generate_witness(
    type_script_hash: Digest,
    transaction_kernel: TransactionKernel,
    salted_input_utxos: SaltedUtxos,
    salted_output_utxos: SaltedUtxos,
) -> Option<TypeScriptAndWitness> {
    let type_script_and_witness = if type_script_hash == NativeCurrency.hash() {
        NativeCurrencyWitness::new(transaction_kernel, salted_input_utxos, salted_output_utxos)
            .type_script_and_witness()
    } else if type_script_hash == TimeLock.hash() {
        TimeLockWitness::new(transaction_kernel, salted_input_utxos, salted_output_utxos)
            .type_script_and_witness()
    } else {
        return None;
    };
    Some(type_script_and_witness)
}
