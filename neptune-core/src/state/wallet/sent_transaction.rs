use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::state::transaction::transaction_details::TransactionDetails;
use crate::state::wallet::transaction_output::TxOutputList;

pub(crate) type AoclLeafIndex = u64;

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

impl SentTransaction {
    pub(crate) fn new(td: &TransactionDetails, tip_when_sent: Digest) -> Self {
        Self {
            tx_inputs: td
                .tx_inputs
                .iter()
                .map(|u| (u.mutator_set_mp().aocl_leaf_index, u.utxo.clone()))
                .collect(),
            tx_outputs: td.tx_outputs.clone(),
            fee: td.fee,
            timestamp: td.timestamp,
            tip_when_sent,
        }
    }
}
