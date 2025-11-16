use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use crate::application::json_rpc::core::model::block::transaction_kernel::RpcTransactionKernel;
use crate::application::json_rpc::core::model::common::RpcBFieldElements;
use crate::protocol::consensus::transaction::validity::proof_collection::ProofCollection;

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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum RpcTransactionProof {
    ProofCollection(Box<ProofCollection>),
    SingleProof(RpcBFieldElements),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcTransaction {
    pub kernel: RpcTransactionKernel,
    pub proof: RpcTransactionProof,
}
