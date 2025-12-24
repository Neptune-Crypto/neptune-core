use tasm_lib::prelude::Digest;

use crate::protocol::proof_abstractions::tasm::{self, builtins};

impl crate::protocol::proof_abstractions::tasm::program::tests::ConsensusProgramSpecification for super::The {
    fn source(&self) {
        // get in the current program's hash digest
        let self_digest: Digest = tasm::builtins::own_program_digest();

        // read standard input
        let publicinput_releasedate = tasm::builtins::tasmlib_io_read_stdin___bfe();
        let publicinput_receiverdigest: Digest = tasm::builtins::tasmlib_io_read_stdin___digest();

        // divine witness from memory
        // let start_address: BFieldElement = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
        let ram: super::WitnessMemory = tasm::builtins::decode_from_memory(
            tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS
        );
        // let coinbase: Option<NativeCurrencyAmount> = native_currency_witness_mem.coinbase;
        // let fee: NativeCurrencyAmount = native_currency_witness_mem.fee;
        // let input_salted_utxos: SaltedUtxos = native_currency_witness_mem.salted_input_utxos;
        // let output_salted_utxos: SaltedUtxos = native_currency_witness_mem.salted_output_utxos;
        // let timestamp = native_currency_witness_mem.timestamp;
    }
}