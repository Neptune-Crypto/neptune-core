use std::collections::BTreeMap;

use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use crate::api::export::AdditionRecord;
use crate::api::export::Timestamp;
use crate::application::json_rpc::core::model::common::RpcBFieldElements;
use crate::application::json_rpc::core::model::common::RpcNativeCurrencyAmount;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use crate::util_types::mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
use crate::util_types::mutator_set::removal_record::RemovalRecord;

pub type RpcAbsoluteIndexSet = AbsoluteIndexSet;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RpcRemovalRecord {
    pub absolute_indices: RpcAbsoluteIndexSet,
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

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RpcAdditionRecord(pub Digest);

impl From<AdditionRecord> for RpcAdditionRecord {
    fn from(record: AdditionRecord) -> Self {
        Self(record.canonical_commitment)
    }
}

impl From<RpcAdditionRecord> for AdditionRecord {
    fn from(record: RpcAdditionRecord) -> Self {
        Self {
            canonical_commitment: record.0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcTransactionKernel {
    pub inputs: Vec<RpcRemovalRecord>,
    pub outputs: Vec<RpcAdditionRecord>,
    pub announcements: Vec<RpcBFieldElements>,
    pub fee: RpcNativeCurrencyAmount,
    pub coinbase: Option<RpcNativeCurrencyAmount>,
    pub timestamp: Timestamp,
    pub mutator_set_hash: Digest,
    pub merge_bit: bool,
}

impl PartialEq for RpcTransactionKernel {
    fn eq(&self, o: &Self) -> bool {
        self.inputs == o.inputs
            && self.outputs == o.outputs
            && self.announcements == o.announcements
            && self.fee == o.fee
            && self.coinbase == o.coinbase
            && self.timestamp == o.timestamp
            && self.mutator_set_hash == o.mutator_set_hash
            && self.merge_bit == o.merge_bit
    }
}

impl From<&TransactionKernel> for RpcTransactionKernel {
    fn from(kernel: &TransactionKernel) -> Self {
        Self {
            inputs: kernel.inputs.clone().into_iter().map(Into::into).collect(),
            outputs: kernel.outputs.iter().copied().map(Into::into).collect(),
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
