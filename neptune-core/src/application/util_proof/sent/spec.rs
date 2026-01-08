use tasm_lib::{
    prelude::{Digest, Tip5},
    triton_vm::prelude::BFieldCodec,
    twenty_first::prelude::Mmr,
};

use crate::{
    api::export::NativeCurrencyAmount,
    protocol::{
        consensus::type_scripts::native_currency::NativeCurrency,
        proof_abstractions::{
            tasm::{
                self,
                builtins::{
                    self, tasmlib_io_write_to_stdout___digest,
                    tasmlib_io_write_to_stdout___encoding, tasmlib_io_write_to_stdout___u128,
                },
                program::ConsensusProgram,
            },
            timestamp::Timestamp,
        },
    },
};

impl crate::protocol::proof_abstractions::tasm::program::tests::ConsensusProgramSpecification
    for super::The
{
    fn source(&self) {
        // get in the current program's hash digest
        // let self_digest: Digest = tasm::builtins::own_program_digest();

        // read standard input
        let publicinput_releasedate = tasm::builtins::tasmlib_io_read_stdin___bfe();
        let publicinput_receiverdigest: Digest = tasm::builtins::tasmlib_io_read_stdin___digest();

        // divine witness from memory
        let ram: super::WitnessMemory = tasm::builtins::decode_from_memory(
            tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
        );

        // receiver: expose the address lock script part
        tasmlib_io_write_to_stdout___digest(ram.utxo.lock_script_hash());

        // fill `Claim::output` with `sender_randomness_digest`
        tasmlib_io_write_to_stdout___digest(ram.sender_randomness.hash());

        let utxo_digest = Tip5::hash_varlen(ram.utxo.encode().as_slice());

        // constraint consistency for two parts of the witness
        // assert_eq!(ram.utxo_digest, utxo_digest);

        // constraint the UTXO addition record is in the AOCL
        assert!(
            tasm::builtins::mmr_verify_from_secret_in_leaf_index_on_stack(
                ram.aocl.peaks().as_slice(),
                ram.aocl.num_leafs(),
                ram.aocl_leaf_index,
                crate::util_types::mutator_set::commit(
                    utxo_digest,
                    ram.sender_randomness,
                    publicinput_receiverdigest
                )
                .canonical_commitment
            )
        );

        // output the AOCL digest used for the proof
        tasmlib_io_write_to_stdout___digest(ram.aocl.bag_peaks());

        // adapted from this trait implementation for `NativeCurrency`
        let mut total_amount_for_utxo = NativeCurrencyAmount::coins(0);
        let mut _time_locked = false;
        let mut j = 0;
        while j < ram.utxo.coins().len() {
            let coin_j = ram.utxo.coins()[j].clone();
            if coin_j.type_script_hash == ConsensusProgram::hash(&NativeCurrency) {
                // decode state to get amount
                let amount = *NativeCurrencyAmount::decode(&coin_j.state).unwrap();

                // make sure amount is positive (or zero)
                assert!(!amount.is_negative());

                // safely add to total
                total_amount_for_utxo =
                    num_traits::CheckedAdd::checked_add(&total_amount_for_utxo, &amount).unwrap();
            } else if coin_j.type_script_hash
                == ConsensusProgram::hash(
                    &crate::protocol::consensus::type_scripts::time_lock::TimeLock,
                )
            {
                // decode state to get release date
                if *Timestamp::decode(&coin_j.state).unwrap()
                    >= *Timestamp::decode(&[publicinput_releasedate]).unwrap()
                        + crate::protocol::consensus::block::MINING_REWARD_TIME_LOCK_PERIOD
                {
                    _time_locked = true;
                }
            }
            j += 1;
        }
        /* end of the adaptation
        ______________ */

        tasmlib_io_write_to_stdout___encoding(total_amount_for_utxo);
    }
}
