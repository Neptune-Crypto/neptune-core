use get_size::GetSize;
use serde::{Deserialize, Serialize};
use twenty_first::shared_math::bfield_codec::BFieldCodec;

use super::{SupportedClaim, ValidationLogic};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct TypeScriptsHalt {
    pub supported_claims: Vec<SupportedClaim>,
}

impl TypeScriptsHalt {
    // TODO: Remove after implementing this struct
    pub fn dummy() -> Self {
        Self {
            supported_claims: vec![SupportedClaim::dummy()],
        }
    }
}

impl ValidationLogic for TypeScriptsHalt {
    fn new_from_witness(
        _primitive_witness: &crate::models::blockchain::transaction::PrimitiveWitness,
        _tx_kernel: &crate::models::blockchain::transaction::transaction_kernel::TransactionKernel,
    ) -> Self {
        todo!()
    }

    fn prove(&mut self) -> anyhow::Result<()> {
        todo!()
    }

    fn verify(&self) -> bool {
        todo!()
    }
}
