use crate::{models::consensus::timestamp::Timestamp, prelude::twenty_first};

use std::collections::VecDeque;

use crate::{
    models::{blockchain::block::block_height::BlockHeight, state::archival_state::ArchivalState},
    util_types::mutator_set::ms_membership_proof::MsMembershipProof,
};
use serde::{Deserialize, Serialize};
use twenty_first::math::tip5::Digest;

use crate::models::blockchain::transaction::utxo::Utxo;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredUtxo {
    pub utxo: Utxo,

    // Mapping from block digest to membership proof
    pub blockhash_to_membership_proof: VecDeque<(Digest, MsMembershipProof)>,

    pub number_of_mps_per_utxo: usize,

    // hash of the block, if any, in which this UTXO was spent
    pub spent_in_block: Option<(Digest, Timestamp, BlockHeight)>,

    // hash of the block, if any, in which this UTXO was confirmed
    pub confirmed_in_block: Option<(Digest, Timestamp, BlockHeight)>,

    /// Indicator used to mark the UTXO as belonging to an abandoned fork
    /// Indicates what was the block tip when UTXO was marked as abandoned
    pub abandoned_at: Option<(Digest, Timestamp, BlockHeight)>,
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
        updated_membership_proof: MsMembershipProof,
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
    ) -> Option<MsMembershipProof> {
        self.blockhash_to_membership_proof
            .iter()
            .find(|x| x.0 == block_digest)
            .map(|x| x.1.clone())
    }

    /// Get the most recent (block hash, membership proof) entry in the database,
    /// if any.
    pub fn get_latest_membership_proof_entry(&self) -> Option<(Digest, MsMembershipProof)> {
        self.blockhash_to_membership_proof.iter().next().cloned()
    }

    /// Returns true if the MUTXO was abandoned
    pub async fn was_abandoned(&self, tip_digest: Digest, archival_state: &ArchivalState) -> bool {
        match self.confirmed_in_block {
            Some((confirm_block_digest, _, _)) => {
                !archival_state
                    .block_belongs_to_canonical_chain(confirm_block_digest, tip_digest)
                    .await
            }
            None => false,
        }
    }
}
