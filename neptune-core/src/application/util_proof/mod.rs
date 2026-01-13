use tasm_lib::prelude::TasmObject;

pub mod reserves;
pub mod sent;

#[derive(TasmObject, tasm_lib::triton_vm::prelude::BFieldCodec, Debug)]
struct ProofOfTransferWitness {
    /// AOCL accumulator of the block
    aocl: tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator,
    membership_proof: tasm_lib::twenty_first::prelude::MmrMembershipProof,
    sender_randomness: tasm_lib::prelude::Digest,
    aocl_leaf_index: u64,
    utxo: crate::api::export::Utxo,
    // utxo_digest: Digest,
}

#[derive(Debug)]
pub(crate) struct ProofOfTransfer(ProofOfTransferWitness, tasm_lib::triton_vm::proof::Claim);