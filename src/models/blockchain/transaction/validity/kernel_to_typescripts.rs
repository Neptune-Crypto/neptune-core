use get_size::GetSize;
use serde::{Deserialize, Serialize};

use super::{SupportedClaim, TxValidationLogic};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub struct KernelToTypeScripts {
    supported_claim: SupportedClaim,
}

impl KernelToTypeScripts {
    // TODO: Remove after implementing this struct
    pub fn dummy() -> Self {
        Self {
            supported_claim: SupportedClaim::dummy_supported_claim(),
        }
    }
}

impl TxValidationLogic for KernelToTypeScripts {
    fn unproven_from_primitive_witness(
        _primitive_witness: &crate::models::blockchain::transaction::PrimitiveWitness,
        _tx_kernel: &crate::models::blockchain::transaction::transaction_kernel::TransactionKernel,
    ) -> Self {
        todo!()
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
