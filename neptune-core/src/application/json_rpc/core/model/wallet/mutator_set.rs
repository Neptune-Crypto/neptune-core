use std::collections::BTreeMap;

use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::twenty_first::prelude::MmrMembershipProof;

use crate::application::json_rpc::core::model::block::body::RpcMutatorSetAccumulator;
use crate::application::json_rpc::core::model::block::transaction_kernel::RpcChunkDictionary;
use crate::util_types::mutator_set::archival_mutator_set::IndexedAoclAuthPath;
use crate::util_types::mutator_set::archival_mutator_set::MsMembershipProofPrivacyPreserving;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RpcMmrMembershipProof(Vec<Digest>);

impl From<MmrMembershipProof> for RpcMmrMembershipProof {
    fn from(value: MmrMembershipProof) -> Self {
        Self(value.authentication_path)
    }
}

impl From<RpcMmrMembershipProof> for MmrMembershipProof {
    fn from(value: RpcMmrMembershipProof) -> Self {
        MmrMembershipProof::new(value.0)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RpcIndexedAoclAuthPaths(pub BTreeMap<u64, RpcMmrMembershipProof>);

impl From<Vec<IndexedAoclAuthPath>> for RpcIndexedAoclAuthPaths {
    fn from(value: Vec<IndexedAoclAuthPath>) -> Self {
        Self(
            value
                .into_iter()
                .map(|indexed| (indexed.leaf_index, indexed.auth_path.into()))
                .collect(),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcMsMembershipProofPrivacyPreserving {
    pub aocl_auth_paths: RpcIndexedAoclAuthPaths,
    pub target_chunks: RpcChunkDictionary,
}

impl RpcMsMembershipProofPrivacyPreserving {
    /// Extracts the correct mutator‑set membership proof from the privacy‑preserving
    /// recovery data by selecting the appropriate AOCL MMR authentication path.
    pub fn extract_ms_membership_proof(
        self,
        aocl_leaf_index: u64,
        sender_randomness: Digest,
        receiver_preimage: Digest,
    ) -> Option<MsMembershipProof> {
        let aocl_mmr = self.aocl_auth_paths.0.get(&aocl_leaf_index).cloned()?;

        Some(MsMembershipProof {
            sender_randomness,
            receiver_preimage,
            auth_path_aocl: aocl_mmr.into(),
            aocl_leaf_index,
            target_chunks: self.target_chunks.into(),
        })
    }
}

impl From<MsMembershipProofPrivacyPreserving> for RpcMsMembershipProofPrivacyPreserving {
    fn from(value: MsMembershipProofPrivacyPreserving) -> Self {
        Self {
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
    pub membership_proofs: Vec<RpcMsMembershipProofPrivacyPreserving>,
}
