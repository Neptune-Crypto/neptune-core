use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;

use crate::api::export::NativeCurrencyAmount;
use crate::api::export::Transaction;
use crate::api::export::TransactionKernelId;
use crate::api::export::TransactionProof;
use crate::api::export::TransactionProofType;

#[derive(Clone, Debug, Copy, Serialize, Deserialize)]
pub struct MempoolTransactionInfo {
    pub id: TransactionKernelId,
    pub proof_type: TransactionProofType,
    pub num_inputs: usize,
    pub num_outputs: usize,
    pub positive_balance_effect: NativeCurrencyAmount,
    pub negative_balance_effect: NativeCurrencyAmount,
    pub fee: NativeCurrencyAmount,
    pub synced: bool,
}

impl From<&Transaction> for MempoolTransactionInfo {
    fn from(mptx: &Transaction) -> Self {
        MempoolTransactionInfo {
            id: mptx.kernel.txid(),
            proof_type: match mptx.proof {
                TransactionProof::Witness(_) => TransactionProofType::PrimitiveWitness,
                TransactionProof::SingleProof(_) => TransactionProofType::SingleProof,
                TransactionProof::ProofCollection(_) => TransactionProofType::ProofCollection,
            },
            num_inputs: mptx.kernel.inputs.len(),
            num_outputs: mptx.kernel.outputs.len(),
            positive_balance_effect: NativeCurrencyAmount::zero(),
            negative_balance_effect: NativeCurrencyAmount::zero(),
            fee: mptx.kernel.fee,
            synced: false,
        }
    }
}

impl MempoolTransactionInfo {
    pub(crate) fn with_positive_effect_on_balance(
        mut self,
        positive_balance_effect: NativeCurrencyAmount,
    ) -> Self {
        self.positive_balance_effect = positive_balance_effect;
        self
    }

    pub(crate) fn with_negative_effect_on_balance(
        mut self,
        negative_balance_effect: NativeCurrencyAmount,
    ) -> Self {
        self.negative_balance_effect = negative_balance_effect;
        self
    }

    pub fn synced(mut self) -> Self {
        self.synced = true;
        self
    }
}

#[cfg(feature = "mock-rpc")]
impl rand::distr::Distribution<MempoolTransactionInfo> for rand::distr::StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> MempoolTransactionInfo {
        MempoolTransactionInfo {
            id: rng.random(),
            proof_type: rng.random(),
            num_inputs: rng.random_range(0..10),
            num_outputs: rng.random_range(0..10),
            positive_balance_effect: rng
                .random::<NativeCurrencyAmount>()
                .lossy_f64_fraction_mul(0.0001),
            negative_balance_effect: rng
                .random::<NativeCurrencyAmount>()
                .lossy_f64_fraction_mul(0.0001),
            fee: rng
                .random::<NativeCurrencyAmount>()
                .lossy_f64_fraction_mul(0.0001),
            synced: rng.random(),
        }
    }
}
