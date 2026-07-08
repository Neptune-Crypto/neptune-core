use neptune_consensus::transaction::transaction_proof::TransactionProofType;
use neptune_consensus::transaction::Transaction;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_mempool::transaction_kernel_id::TransactionKernelId;
use neptune_mempool::transaction_kernel_id::Txid;
use serde::Deserialize;
use serde::Serialize;

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

impl MempoolTransactionInfo {
    pub(crate) fn new(
        tx: &Transaction,
        is_synced: bool,
        pos_balance_effect: NativeCurrencyAmount,
        neg_balance_effect: NativeCurrencyAmount,
    ) -> Self {
        Self {
            id: tx.kernel.txid(),
            proof_type: (&tx.proof).into(),
            num_inputs: tx.kernel.inputs.len(),
            num_outputs: tx.kernel.outputs.len(),
            positive_balance_effect: pos_balance_effect,
            negative_balance_effect: neg_balance_effect,
            fee: tx.kernel.fee,
            synced: is_synced,
        }
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
