use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use crate::api::export::NeptuneProof;
use crate::api::export::Transaction;
use crate::api::export::TransactionProof;
use crate::application::json_rpc::core::model::block::transaction_kernel::RpcTransactionKernel;
use crate::application::json_rpc::core::model::common::RpcBFieldElements;
use crate::protocol::consensus::transaction::validity::proof_collection::ProofCollection;

// TODO: Cleanup funky types and From impl
pub type RpcNeptuneProof = NeptuneProof;

impl From<RpcBFieldElements> for RpcNeptuneProof {
    fn from(bfes: RpcBFieldElements) -> Self {
        bfes.0.into()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RpcProofCollection {
    pub removal_records_integrity: RpcBFieldElements,
    pub collect_lock_scripts: RpcBFieldElements,
    pub lock_scripts_halt: Vec<RpcBFieldElements>,
    pub kernel_to_outputs: RpcBFieldElements,
    pub collect_type_scripts: RpcBFieldElements,
    pub type_scripts_halt: Vec<RpcBFieldElements>,
    pub lock_script_hashes: Vec<Digest>,
    pub type_script_hashes: Vec<Digest>,
    pub kernel_mast_hash: Digest,
    pub salted_inputs_hash: Digest,
    pub salted_outputs_hash: Digest,
    pub merge_bit_mast_path: Vec<Digest>,
}

impl From<RpcProofCollection> for ProofCollection {
    fn from(pc: RpcProofCollection) -> Self {
        Self {
            removal_records_integrity: pc.removal_records_integrity.into(),
            collect_lock_scripts: pc.collect_lock_scripts.into(),
            lock_scripts_halt: pc.lock_scripts_halt.into_iter().map(Into::into).collect(),
            kernel_to_outputs: pc.kernel_to_outputs.into(),
            collect_type_scripts: pc.collect_type_scripts.into(),
            type_scripts_halt: pc.type_scripts_halt.into_iter().map(Into::into).collect(),
            lock_script_hashes: pc.lock_script_hashes,
            type_script_hashes: pc.type_script_hashes,
            kernel_mast_hash: pc.kernel_mast_hash,
            salted_inputs_hash: pc.salted_inputs_hash,
            salted_outputs_hash: pc.salted_outputs_hash,
            merge_bit_mast_path: pc.merge_bit_mast_path,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum RpcTransactionProof {
    ProofCollection(Box<RpcProofCollection>),
    SingleProof(RpcBFieldElements),
}

impl From<RpcTransactionProof> for TransactionProof {
    fn from(proof: RpcTransactionProof) -> TransactionProof {
        match proof {
            RpcTransactionProof::ProofCollection(pc) => {
                TransactionProof::ProofCollection((*pc).into())
            }
            RpcTransactionProof::SingleProof(sp) => TransactionProof::SingleProof(sp.into()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcTransaction {
    pub kernel: RpcTransactionKernel,
    pub proof: RpcTransactionProof,
}

impl From<RpcTransaction> for Transaction {
    fn from(tx: RpcTransaction) -> Self {
        Transaction {
            kernel: tx.kernel.into(),
            proof: tx.proof.into(),
        }
    }
}
