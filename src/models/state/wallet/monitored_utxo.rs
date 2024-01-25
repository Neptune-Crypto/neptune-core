use crate::prelude::twenty_first;

use std::{collections::VecDeque, time::Duration};

use crate::{
    models::{
        blockchain::block::{block_header::BlockHeader, block_height::BlockHeight},
        state::archival_state::ArchivalState,
    },
    util_types::mutator_set::ms_membership_proof::MsMembershipProof,
    Hash,
};
use serde::{Deserialize, Serialize};
use twenty_first::shared_math::tip5::Digest;

use crate::models::blockchain::transaction::utxo::Utxo;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredUtxo {
    pub utxo: Utxo,

    // Mapping from block digest to membership proof
    pub blockhash_to_membership_proof: VecDeque<(Digest, MsMembershipProof<Hash>)>,

    pub number_of_mps_per_utxo: usize,

    // hash of the block, if any, in which this UTXO was spent
    pub spent_in_block: Option<(Digest, Duration, BlockHeight)>,

    // hash of the block, if any, in which this UTXO was confirmed
    pub confirmed_in_block: Option<(Digest, Duration, BlockHeight)>,

    /// Indicator used to mark the UTXO as belonging to an abandoned fork
    /// Indicates what was the block tip when UTXO was marked as abandoned
    pub abandoned_at: Option<(Digest, Duration, BlockHeight)>,
}

impl MonitoredUtxo {
    pub fn new(utxo: Utxo, max_number_of_mps_stored: usize) -> Self {
        Self {
            utxo,
            blockhash_to_membership_proof: VecDeque::default(),
            number_of_mps_per_utxo: max_number_of_mps_stored,
            spent_in_block: None,
            confirmed_in_block: None,
            abandoned_at: None,
        }
    }

    // determine whether the attached membership proof is synced to the given block
    pub fn is_synced_to(&self, block_hash: Digest) -> bool {
        self.get_membership_proof_for_block(block_hash).is_some()
    }

    pub fn add_membership_proof_for_tip(
        &mut self,
        block_digest: Digest,
        updated_membership_proof: MsMembershipProof<Hash>,
    ) {
        while self.blockhash_to_membership_proof.len() >= self.number_of_mps_per_utxo {
            self.blockhash_to_membership_proof.pop_back();
        }

        self.blockhash_to_membership_proof
            .push_front((block_digest, updated_membership_proof));
    }

    pub fn get_membership_proof_for_block(
        &self,
        block_digest: Digest,
    ) -> Option<MsMembershipProof<Hash>> {
        self.blockhash_to_membership_proof
            .iter()
            .find(|x| x.0 == block_digest)
            .map(|x| x.1.clone())
    }

    pub fn get_latest_membership_proof_entry(&self) -> Option<(Digest, MsMembershipProof<Hash>)> {
        self.blockhash_to_membership_proof.iter().next().cloned()
    }

    /// Returns true if the MUTXO was abandoned
    pub async fn was_abandoned(
        &self,
        tip_header: &BlockHeader,
        archival_state: &ArchivalState,
    ) -> bool {
        match self.confirmed_in_block {
            Some((confirm_block, _, _)) => {
                let confirm_block_header = archival_state
                    .get_block_header(confirm_block)
                    .await
                    .unwrap();
                !archival_state
                    .block_belongs_to_canonical_chain(&confirm_block_header, tip_header)
                    .await
            }
            None => false,
        }
    }
}
