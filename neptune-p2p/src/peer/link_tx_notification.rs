use anyhow::Result;
use anyhow::bail;
use neptune_consensus::chaintx::link_tx::LinkTx;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_mempool::transaction_kernel_id::TransactionKernelId;
use neptune_mempool::transaction_kernel_id::Txid;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

/// Data structure for communicating knowledge of link transactions.
///
/// The chain-pipeline analog of
/// [`TransactionNotification`](super::transaction_notification::TransactionNotification).
/// It carries no proof quality: only proof-backed link transactions are ever
/// shared, so there is exactly one shareable quality.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkTxNotification {
    /// A unique identifier of the link transaction.
    pub txid: TransactionKernelId,

    /// The hash of the mutator set under which this link transaction is valid.
    pub mutator_set_hash: Digest,

    /// How much fee is the link transaction paying?
    pub fee: NativeCurrencyAmount,

    /// How many confirmed inputs does the link transaction have?
    pub num_inputs: u64,

    /// How many outputs does the link transaction have?
    pub num_outputs: u64,

    /// How many thruputs, unconfirmed inputs, does the link transaction have?
    pub num_thruputs: u64,
}

impl TryFrom<&LinkTx> for LinkTxNotification {
    type Error = anyhow::Error;

    fn try_from(link_tx: &LinkTx) -> Result<Self> {
        if link_tx.proof.is_witness() {
            bail!("Cannot share witness-backed link transaction, as this would leak secret keys");
        }

        let kernel = &link_tx.kernel.kernel;
        Ok(Self {
            txid: link_tx.txid(),
            mutator_set_hash: kernel.mutator_set_hash,
            fee: kernel.fee,
            num_inputs: kernel.inputs.len().try_into().unwrap(),
            num_outputs: kernel.outputs.len().try_into().unwrap(),
            num_thruputs: link_tx.kernel.thruputs.len().try_into().unwrap(),
        })
    }
}
