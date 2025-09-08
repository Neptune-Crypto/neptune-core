use anyhow::bail;
use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;

use super::transfer_transaction::TransactionProofQuality;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::consensus::transaction::TransactionProof;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::state::transaction::transaction_kernel_id::TransactionKernelId;
use crate::tasm_lib::prelude::Digest;

/// Data structure for communicating knowledge of transactions.
///
/// A sender broadcasts to all peers a `TransactionNotification` when it has
/// received a transaction with the given `TransactionId`.  It is implied
/// that interested peers can request the full transaction object from this
/// sender.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct TransactionNotification {
    /// A unique identifier of the transaction. Matches keys in the [mempool]
    /// data structure.
    ///
    /// [mempool]: crate::state::mempool::Mempool
    pub(crate) txid: TransactionKernelId,

    /// The hash of the mutator set under which this transaction is valid.
    /// The receiver can use this to check if it matches their tip. If not, they
    /// can choose to ignore the transaction.
    pub(crate) mutator_set_hash: Digest,

    /// The quality of the proof. Denotes how much effort it takes to get the
    /// transaction included in a block. Higher quality means less effort.
    pub(crate) proof_quality: TransactionProofQuality,

    /// How much fee is the transaction paying?
    pub(crate) fee: NativeCurrencyAmount,

    /// How many inputs does the transaction have?
    pub(crate) num_inputs: u64,

    /// How many outputs does the transaction have?
    pub(crate) num_outputs: u64,
}

impl TryFrom<&Transaction> for TransactionNotification {
    type Error = anyhow::Error;

    fn try_from(transaction: &Transaction) -> Result<Self> {
        let proof_quality = match &transaction.proof {
            TransactionProof::Witness(_) => bail!(
                "Cannot share primitive witness-backed transaction, as this would leak secret keys"
            ),
            TransactionProof::SingleProof(_) => TransactionProofQuality::SingleProof,
            TransactionProof::ProofCollection(_) => TransactionProofQuality::ProofCollection,
        };
        Ok(Self {
            txid: transaction.kernel.txid(),
            mutator_set_hash: transaction.kernel.mutator_set_hash,
            proof_quality,
            fee: transaction.kernel.fee,
            num_inputs: transaction.kernel.inputs.len().try_into().unwrap(),
            num_outputs: transaction.kernel.outputs.len().try_into().unwrap(),
        })
    }
}
