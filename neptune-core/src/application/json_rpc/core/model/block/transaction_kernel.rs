use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tasm_lib::prelude::Digest;

use crate::{
    api::export::Timestamp,
    application::json_rpc::core::model::common::{RpcBFieldElements, RpcNativeCurrencyAmount},
    protocol::consensus::transaction::transaction_kernel::TransactionKernel,
    util_types::mutator_set::removal_record::{
        absolute_index_set::AbsoluteIndexSet, chunk_dictionary::ChunkDictionary, RemovalRecord,
    },
};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct RpcChunkDictionary(pub BTreeMap<u64, (Vec<Digest>, Vec<u32>)>);

impl From<ChunkDictionary> for RpcChunkDictionary {
    fn from(value: ChunkDictionary) -> Self {
        Self(
            value
                .dictionary
                .into_iter()
                .map(|(index, (proof, chunk))| {
                    (index, (proof.authentication_path, chunk.relative_indices))
                })
                .collect(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcRemovalRecord {
    pub absolute_indices: AbsoluteIndexSet,
    pub target_chunks: RpcChunkDictionary,
}

impl From<RemovalRecord> for RpcRemovalRecord {
    fn from(record: RemovalRecord) -> Self {
        Self {
            absolute_indices: record.absolute_indices,
            target_chunks: record.target_chunks.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcTransactionKernel {
    pub inputs: Vec<RpcRemovalRecord>,
    pub outputs: Vec<Digest>,
    pub announcements: Vec<RpcBFieldElements>,
    pub fee: RpcNativeCurrencyAmount,
    pub coinbase: Option<RpcNativeCurrencyAmount>,
    pub timestamp: Timestamp,
    pub mutator_set_hash: Digest,
    pub merge_bit: bool,
}

impl From<&TransactionKernel> for RpcTransactionKernel {
    fn from(kernel: &TransactionKernel) -> Self {
        Self {
            inputs: kernel.inputs.clone().into_iter().map(Into::into).collect(),
            outputs: kernel
                .outputs
                .iter()
                .map(|r| r.canonical_commitment)
                .collect(),
            announcements: kernel
                .announcements
                .iter()
                .map(|a| a.message.clone().into())
                .collect(),
            fee: kernel.fee.into(),
            coinbase: kernel.coinbase.map(|c| c.into()),
            timestamp: kernel.timestamp,
            mutator_set_hash: kernel.mutator_set_hash,
            merge_bit: kernel.merge_bit,
        }
    }
}
