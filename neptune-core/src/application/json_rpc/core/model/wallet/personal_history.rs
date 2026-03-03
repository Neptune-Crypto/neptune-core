use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use crate::api::export::Timestamp;
use crate::application::json_rpc::core::model::block::header::RpcBlockHeight;
use crate::application::json_rpc::core::model::block::transaction_kernel::RpcAbsoluteIndexSet;
use crate::application::json_rpc::core::model::block::transaction_kernel::RpcAdditionRecord;
use crate::application::json_rpc::core::model::common::RpcNativeCurrencyAmount;
use crate::application::json_rpc::core::model::wallet::transaction::RpcUtxo;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct ReceivedTransactionOutput {
    pub aocl_leaf_index: u64,
    pub addition_record: RpcAdditionRecord,
    pub utxo: RpcUtxo,
    pub receiver_preimage: Digest,
    pub sender_randomness: Digest,
    pub confirmed_timestamp: Timestamp,
    pub confirmed_block: Digest,
    pub confirmed_height: RpcBlockHeight,
    pub receiving_address: Option<String>,
    pub canonical: bool,

    /// If transaction was mined in a canonical block, this value shows the
    /// position of the output in the mined block. Always set to `None` if the
    /// block is not canonical.
    pub output_index: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InitiatedTransactionInput {
    pub utxo: RpcUtxo,
    pub aocl_leaf_index: u64,

    /// The absolute index set of the input to the transaction, if known.
    pub absolute_index_set: Option<RpcAbsoluteIndexSet>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InitiatedTransactionOutput {
    pub utxo: RpcUtxo,
    pub sender_randomness: Digest,
    pub receiver_digest: Digest,

    /// Enum of "on-chain" or "off-chain"
    pub notification_medium: String,

    /// Did we wallet know the spending key for the UTXO when the transaction
    /// was initiated?
    pub owned: bool,
    pub is_change: bool,
    pub to_address: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InitiatedTransaction {
    pub inputs: Vec<InitiatedTransactionInput>,
    pub outputs: Vec<InitiatedTransactionOutput>,
    pub fee: RpcNativeCurrencyAmount,
    pub timestamp: Timestamp,
    pub tip_when_sent: Digest,
}
