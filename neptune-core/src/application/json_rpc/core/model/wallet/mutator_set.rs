use std::collections::BTreeMap;

use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldElement;

use crate::application::json_rpc::core::model::block::body::RpcMutatorSetAccumulator;
use crate::application::json_rpc::core::model::block::transaction_kernel::RpcChunkDictionary;
use crate::util_types::mutator_set::archival_mutator_set::IndexedAoclAuthPath;
use crate::util_types::mutator_set::archival_mutator_set::MsMembershipProofPrivacyPreserving;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RpcIndexedAoclAuthPaths(pub BTreeMap<u64, Vec<Digest>>);

impl From<Vec<IndexedAoclAuthPath>> for RpcIndexedAoclAuthPaths {
    fn from(value: Vec<IndexedAoclAuthPath>) -> Self {
        RpcIndexedAoclAuthPaths(
            value
                .into_iter()
                .map(|indexed| (indexed.leaf_index, indexed.auth_path.authentication_path)) // TODO: RpcMmrMembershipProof
                .collect(),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MsMembershipProof {
    pub aocl_auth_paths: RpcIndexedAoclAuthPaths,
    pub target_chunks: RpcChunkDictionary,
}

impl From<MsMembershipProofPrivacyPreserving> for MsMembershipProof {
    fn from(value: MsMembershipProofPrivacyPreserving) -> Self {
        MsMembershipProof {
            aocl_auth_paths: value.aocl_auth_paths.into(),
            target_chunks: value.target_chunks.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcMsMembershipSnapshot {
    pub synced_height: BFieldElement,
    pub synced_hash: Digest,
    pub synced_mutator_set: RpcMutatorSetAccumulator,
    pub membership_proofs: Vec<MsMembershipProof>,
}
