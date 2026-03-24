//! https://github.com/Neptune-Crypto/neptune-core/pull/799#issuecomment-3881252534
//! > ... I guess it won't make it without tasm_lib::mmr::verify_from_memory::MmrVerifyFromMemory shadow; I remember searching it pretty hard, so it will be a nice surprise to me if someone could point out it to me.
//! >
//! > I thought it both easier and beneficiary to try to implement the trait with a nearest thing (tasm::builtins::mmr_verify_from_secret_in_leaf_index_on_stack); little hope there was, at least the outline waiting for the right shadow is here.

use tasm_lib::prelude::{Digest, Tip5};
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::twenty_first::prelude::Mmr;

use crate::api::export::NativeCurrencyAmount;
use crate::protocol::consensus::type_scripts::native_currency::NativeCurrency;
use crate::protocol::proof_abstractions::tasm;
use crate::protocol::proof_abstractions::tasm::builtins::tasmlib_io_write_to_stdout___digest;
use crate::protocol::proof_abstractions::tasm::builtins::tasmlib_io_write_to_stdout___encoding;
use crate::protocol::proof_abstractions::tasm::program::TritonProgram;
use crate::protocol::proof_abstractions::timestamp::Timestamp;

impl crate::protocol::proof_abstractions::tasm::program::tests::TritonProgramSpecification
    for super::ProofOfTransfer
{
    /* TODO
    https://github.com/Neptune-Crypto/neptune-core/pull/799#pullrequestreview-3778560914
    > There is a discrepancy between the spec and the tasm code. The first thing the spec reads is the release date. The first thing the tasm code reads is the receiver digest. */
    fn source(&self) {
        // get in the current program's hash digest
        // let self_digest: Digest = tasm::builtins::own_program_digest();

        // read standard input
        let publicinput_releasedate = tasm::builtins::tasmlib_io_read_stdin___bfe();
        let publicinput_receiverdigest: Digest = tasm::builtins::tasmlib_io_read_stdin___digest();

        // divine witness from memory
        let proof_of_transfer_witness: super::ProofOfTransferWitness =
            tasm::builtins::decode_from_memory(
                tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            );

        // receiver: expose the address lock script part
        tasmlib_io_write_to_stdout___digest(proof_of_transfer_witness.utxo.lock_script_hash());

        // fill `Claim::output` with `sender_randomness_digest`
        tasmlib_io_write_to_stdout___digest(proof_of_transfer_witness.sender_randomness.hash());

        let utxo_digest = Tip5::hash_varlen(proof_of_transfer_witness.utxo.encode().as_slice());

        // constraint consistency for two parts of the witness
        // assert_eq!(ram.utxo_digest, utxo_digest);

        // constraint the UTXO addition record is in the AOCL
        assert!(
            tasm::builtins::mmr_verify_from_secret_in_leaf_index_on_stack(
                proof_of_transfer_witness.aocl.peaks().as_slice(),
                proof_of_transfer_witness.aocl.num_leafs(),
                proof_of_transfer_witness.aocl_leaf_index,
                crate::util_types::mutator_set::commit(
                    utxo_digest,
                    proof_of_transfer_witness.sender_randomness,
                    publicinput_receiverdigest
                )
                .canonical_commitment
            )
        );

        // output the bagged peaks of the AOCL used for the proof
        tasmlib_io_write_to_stdout___digest(proof_of_transfer_witness.aocl.bag_peaks());

        // adapted from this trait implementation for `NativeCurrency`
        let mut total_amount_for_utxo = NativeCurrencyAmount::coins(0);
        let mut _time_locked = false;
        let mut j = 0;
        while j < proof_of_transfer_witness.utxo.coins().len() {
            let coin_j = proof_of_transfer_witness.utxo.coins()[j].clone();
            if coin_j.type_script_hash == TritonProgram::hash(&NativeCurrency) {
                // decode state to get amount
                let amount = *NativeCurrencyAmount::decode(&coin_j.state).unwrap();

                // make sure amount is positive (or zero)
                assert!(!amount.is_negative());

                // safely add to total
                total_amount_for_utxo =
                    num_traits::CheckedAdd::checked_add(&total_amount_for_utxo, &amount).unwrap();
            } else if coin_j.type_script_hash
                == TritonProgram::hash(
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
