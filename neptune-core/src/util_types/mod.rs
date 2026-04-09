pub mod archival_mmr;
pub mod mutator_set;
pub mod rusty_archival_block_mmr;
pub mod sent;

use tasm_lib::prelude::*;

#[derive(TasmObject, triton_vm::prelude::BFieldCodec, Debug)]
struct ProofOfTransferWitness {
    /// AOCL accumulator of the block
    aocl: twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator,
    aocl_membership_proof: twenty_first::prelude::MmrMembershipProof,
    sender_randomness: Digest,
    aocl_leaf_index: u64,
    utxo: crate::api::export::Utxo,
}

#[derive(Debug)]
pub(crate) struct ProofOfTransfer(ProofOfTransferWitness, triton_vm::proof::Claim);


#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod test_shared;
