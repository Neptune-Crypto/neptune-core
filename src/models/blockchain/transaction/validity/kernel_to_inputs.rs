use get_size::GetSize;
use serde::{Deserialize, Serialize};
use twenty_first::{
    shared_math::bfield_codec::BFieldCodec, util_types::algebraic_hasher::AlgebraicHasher,
};

use crate::models::blockchain::shared::Hash;

use super::{ClaimSupport, SupportedClaim, TxValidationLogic};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub struct KernelToInputs {
    supported_claim: SupportedClaim,
}

impl KernelToInputs {
    // TODO: Remove after implementing this struct
    pub fn dummy() -> Self {
        Self {
            supported_claim: SupportedClaim::dummy_supported_claim(),
        }
    }
}

impl TxValidationLogic for KernelToInputs {
    fn new_from_witness(
        primitive_witness: &crate::models::blockchain::transaction::PrimitiveWitness,
        tx_kernel: &crate::models::blockchain::transaction::transaction_kernel::TransactionKernel,
    ) -> Self {
        let program = triton_vm::program::Program::default(); // TODO: implement!
        let program_digest = Hash::hash_varlen(&program.encode());
        let empty_string = vec![];
        let input = tx_kernel.mast_hash();
        let output = primitive_witness.input_utxos.encode();
        Self {
            supported_claim: SupportedClaim {
                claim: triton_vm::Claim {
                    program_digest,
                    input: input.values().to_vec(),
                    output,
                },
                support: ClaimSupport::SecretWitness(empty_string, program),
            },
        }
    }

    fn prove(&mut self) -> anyhow::Result<()> {
        todo!()
    }

    fn verify(
        &self,
        _tx_kernel: &crate::models::blockchain::transaction::transaction_kernel::TransactionKernel,
    ) -> bool {
        todo!()
    }
}
