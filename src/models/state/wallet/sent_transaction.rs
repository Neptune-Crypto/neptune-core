use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use super::unlocked_utxo::UnlockedUtxo;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::transaction_details::TransactionDetails;
use crate::models::state::wallet::transaction_output::TxOutputList;

/// represents a user-level tx that has been sent by this wallet.
///
/// this type is intended for storing in the wallet-db in order to
/// group together inputs and outputs as a single payment for purposes
/// of wallet history display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentTransaction {
    pub tx_inputs: Vec<UnlockedUtxo>,
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
            tx_inputs: td.tx_inputs,
            tx_outputs: td.tx_outputs,
            fee: td.fee,
            timestamp: td.timestamp,
            tip_when_sent,
        }
    }
}
