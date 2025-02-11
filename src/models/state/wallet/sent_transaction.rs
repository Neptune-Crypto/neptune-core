use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::transaction_details::TransactionDetails;
use crate::models::state::wallet::transaction_output::TxOutputList;

type AoclLeafIndex = u64;

/// represents a user-level tx that has been sent by this wallet.
///
/// this type is intended for storing in the wallet-db in order to
/// group together inputs and outputs as a single payment for purposes
/// of wallet history display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentTransaction {
    pub tx_inputs: Vec<(AoclLeafIndex, Utxo)>,
    pub tx_outputs: TxOutputList,
    pub fee: NativeCurrencyAmount,
    pub timestamp: Timestamp,
    pub tip_when_sent: Digest, // tip block when sent.  (not when confirmed)
}

impl From<(TransactionDetails, Digest)> for SentTransaction {
    fn from(data: (TransactionDetails, Digest)) -> Self {
        let (td, tip_when_sent) = data;
        Self::new(td, tip_when_sent)
    }
}

impl SentTransaction {
    pub(crate) fn new(td: TransactionDetails, tip_when_sent: Digest) -> Self {
        Self {
            tx_inputs: td
                .tx_inputs
                .into_iter()
                .map(|u| (u.mutator_set_mp().aocl_leaf_index, u.utxo))
                .collect(),
            tx_outputs: td.tx_outputs,
            fee: td.fee,
            timestamp: td.timestamp,
            tip_when_sent,
        }
    }
}
