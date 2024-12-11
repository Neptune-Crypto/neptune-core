use std::collections::VecDeque;

use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::Tip5;

use twenty_first::math::tip5::Digest;

use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::archival_state::ArchivalState;
use crate::prelude::twenty_first;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::commit;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;

/// Represents a UTXO sent to this wallet. The UTXO must, at one point, have
/// been mined, although the block in which it was mined might have been
/// abandoned.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MonitoredUtxo {
    pub utxo: Utxo,

    /// Mapping from block digest to membership proof. The struct is assumed
    /// to have at least one membership proof, and all its AOCL indices are
    /// assumed to be the same.
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
    pub(crate) fn new(utxo: Utxo, max_number_of_mps_stored: usize) -> Self {
        Self {
            utxo,
            blockhash_to_membership_proof: VecDeque::default(),
            number_of_mps_per_utxo: max_number_of_mps_stored,
            spent_in_block: None,
            confirmed_in_block: None,
            abandoned_at: None,
        }
    }

    /// Return the addition record associated with this UTXO.
    pub(crate) fn addition_record(&self) -> AdditionRecord {
        let item = Tip5::hash(&self.utxo);
        let (_block, msmp) = self
        .get_latest_membership_proof_entry()
        .unwrap_or_else(|| panic!("All monitored UTXOs must have at least one membership proof. Couldn't find one for {self:?}"));

        commit(item, msmp.sender_randomness, msmp.receiver_preimage.hash())
    }

    /// Return the AOCL index in which this UTXO was added
    pub(crate) fn aocl_index(&self) -> u64 {
        let (_block, msmp) = self
            .get_latest_membership_proof_entry()
            .unwrap_or_else(|| panic!("All monitored UTXOs must have at least one membership proof. Couldn't find one for {self:?}"));

        msmp.aocl_leaf_index
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

    pub(crate) fn mark_as_spent(&mut self, spending_block: &Block) {
        self.spent_in_block = Some((
            spending_block.hash(),
            spending_block.kernel.header.timestamp,
            spending_block.kernel.header.height,
        ));
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
