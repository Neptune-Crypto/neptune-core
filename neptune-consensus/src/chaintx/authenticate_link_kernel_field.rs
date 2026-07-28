use neptune_primitives::mast_hash::HasDiscriminant;
use neptune_primitives::mast_hash::MastHash;
use tasm_lib::data_type::DataType;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use super::link_kernel::LinkKernel;
use super::link_kernel::LinkKernelField;

/// Authenticate one variable-length [`LinkKernel`] MAST leaf against a
/// [`LinkKernel`] MAST hash.
///
/// Crashes the VM if the field does not hash to the leaf the root commits to at
/// that index.
///
/// The [`LinkKernel`] analog of
/// [`AuthenticateTxkField`](crate::transaction::validity::tasm::authenticate_txk_field::AuthenticateTxkField),
/// and a copy of it but for the tree height and the leaf enum. Deliberately
/// *not* a shared, height-parameterized snippet: the legacy one is baked into
/// the consensus-pinned `SingleProof` hash, so widening it could only ever risk
/// that hash, for no gain here. (Contrast
/// [`AuthenticateMsaAgainstTxk`](crate::transaction::validity::tasm::leaf_authentication::authenticate_msa_against_txk::AuthenticateMsaAgainstTxk),
/// which *was* worth parameterizing: its body is substantial, and its one
/// legacy caller could absorb the change.)
///
/// Only for leafs whose field is read out of memory. A leaf whose value is fixed
/// by consensus -- [`no_coinbase_leaf`](super::link_proof::no_coinbase_leaf),
/// [`merge_bit_false_leaf`](super::link_proof::merge_bit_false_leaf) -- is
/// authenticated by pushing the constant digest straight into `merkle_verify`,
/// which asserts the field's *value* at the same time and so is strictly
/// stronger.
#[derive(Debug, Clone, Copy)]
pub(super) struct AuthenticateLinkKernelField(pub(super) LinkKernelField);

impl BasicSnippet for AuthenticateLinkKernelField {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "link_kernel_mast_hash".to_owned()),
            (DataType::VoidPointer, "field".to_owned()),
            (DataType::U32, "field_size".to_owned()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![]
    }

    fn entrypoint(&self) -> String {
        format!(
            "neptune_consensus_chaintx_authenticate_field_{}_against_link_kernel_mast_hash",
            self.0
        )
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let hash_varlen = library.import(Box::new(HashVarlen));
        let merkle_verify = library.import(Box::new(MerkleVerify));

        triton_asm!(
            {self.entrypoint()}:
                // _ [root] *field field_size

                push {self.0.discriminant() as u32}
                swap 1
                // _ [root] *field leaf_index field_size

                push {LinkKernel::MAST_HEIGHT}
                swap 3
                swap 1
                // _ [root] height leaf_index *field field_size

                call {hash_varlen}
                // _ [root] height leaf_index [field_hash]

                call {merkle_verify}
                // _

                return
        )
    }
}
