use crate::models::{
    blockchain::transaction::primitive_witness::SaltedUtxos,
    consensus::tasm::program::ConsensusProgram,
};

use crate::models::blockchain::type_scripts::BFieldCodec;
use crate::models::consensus::tasm::builtins as tasm;
use get_size::GetSize;
use serde::{Deserialize, Serialize};

use tasm_lib::{triton_vm, twenty_first::shared_math::b_field_element::BFieldElement, Digest};
use triton_vm::{program::Program, triton_asm};

use super::neptune_coins::NeptuneCoins;

#[derive(Debug, Clone, Serialize, Deserialize, BFieldCodec, GetSize, PartialEq, Eq)]
pub struct NativeCurrency {}

impl ConsensusProgram for NativeCurrency {
    #[allow(clippy::needless_return)]
    fn source() {
        // get in the current program's hash digest
        let _self_digest: Digest = tasm::own_program_digest();

        // read standard input:
        //  - transaction kernel mast hash
        //  - input salted utxos digest
        //  - output salted utxos digest
        // (All type scripts take this triple as input.)
        let _tx_kernel_digest: Digest = tasm::tasm_io_read_stdin___digest();
        let _input_utxos_digest: Digest = tasm::tasm_io_read_stdin___digest();
        let _output_utxos_digest: Digest = tasm::tasm_io_read_stdin___digest();
        // public input is kernel mast hash

        // get coinbase, fee, inputs, and outputs
        // these objects live in nondeterministically-initialized memory,
        // so divine pointers and decode
        let coinbase_pointer: BFieldElement = tasm::tasm_io_read_secin___bfe();
        let _coinbase: Option<NeptuneCoins> = tasm::decode_from_memory(coinbase_pointer);
        let fee_pointer: BFieldElement = tasm::tasm_io_read_secin___bfe();
        let _fee: NeptuneCoins = tasm::decode_from_memory(fee_pointer);
        let input_salted_utxos_pointer: BFieldElement = tasm::tasm_io_read_secin___bfe();
        let _input_salted_utxos: SaltedUtxos = tasm::decode_from_memory(input_salted_utxos_pointer);
        let output_salted_utxos_pointer: BFieldElement = tasm::tasm_io_read_secin___bfe();
        let _output_salted_utxos: SaltedUtxos =
            tasm::decode_from_memory(output_salted_utxos_pointer);

        // todo
    }

    fn code() -> Vec<triton_vm::prelude::LabelledInstruction> {
        todo!()
    }
}

pub const NATIVE_CURRENCY_TYPE_SCRIPT_DIGEST: Digest = Digest::new([
    BFieldElement::new(4843866011885844809),
    BFieldElement::new(16618866032559590857),
    BFieldElement::new(18247689143239181392),
    BFieldElement::new(7637465675240023996),
    BFieldElement::new(9104890367162237026),
]);

pub fn native_currency_program() -> Program {
    // todo: insert inflation check logic here
    Program::new(&triton_asm!(halt))
}

#[cfg(test)]
mod tests_native_coin {
    use super::*;
    use crate::Hash;

    #[test]
    fn hash_is_really_hash() {
        let calculated_digest = native_currency_program().hash::<Hash>();
        assert_eq!(
            calculated_digest, NATIVE_CURRENCY_TYPE_SCRIPT_DIGEST,
            "\ncalculated: ({calculated_digest})\nhardcoded: ({NATIVE_CURRENCY_TYPE_SCRIPT_DIGEST})"
        );
    }
}
