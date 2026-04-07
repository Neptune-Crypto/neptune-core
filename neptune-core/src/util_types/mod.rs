pub mod archival_mmr;
pub mod mutator_set;
pub mod proof_of_transfer;
pub mod rusty_archival_block_mmr;

#[derive(Debug)]
pub(crate) struct ProofOfTransfer(
    proof_of_transfer::ProofOfTransferWitness,
    tasm_lib::triton_vm::proof::Claim,
);

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod test_shared;
