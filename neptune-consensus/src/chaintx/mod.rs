//! Transaction chaining.
//!
//! Data structures and consensus programs for the transaction-chaining
//! (`LinkTx`) pipeline that runs parallel to the single-proof `Transaction` pipeline.

pub mod advance;
pub(crate) mod authenticate_link_kernel_field;
pub mod cast;
pub mod chain;
pub mod forge;
pub(crate) mod generate_link_proof_claim;
pub mod link_kernel;
pub mod link_primitive_witness;
pub mod link_proof;
pub mod link_proof_witness;
pub mod link_tx;
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers;

/// A stand-in for the `SingleProof` program digest `D` that a `LinkProof` claim
/// carries.
///
/// Tests need to name a `D`, and a second one distinct from it, without caring
/// what it is: no branch that exists yet reads the value, and reaching for the
/// real `SingleProof::hash()` would put back the very Rust edge that promoting
/// `D` to a claim parameter removes.
#[cfg(test)]
pub(crate) fn mock_single_proof_digest(seed: u64) -> tasm_lib::prelude::Digest {
    use tasm_lib::prelude::Tip5;
    use tasm_lib::triton_vm::prelude::BFieldElement;

    Tip5::hash(&BFieldElement::new(seed))
}
