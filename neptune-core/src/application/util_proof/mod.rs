use tasm_lib::prelude::*;

pub mod sent;

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
