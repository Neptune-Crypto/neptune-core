use std::collections::VecDeque;
use std::fmt::Display;

use itertools::Itertools;
use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::Tip5;
use tasm_lib::twenty_first::tip5::digest::Digest;

use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::state::archival_state::ArchivalState;
use crate::state::wallet::wallet_db_tables::StrongUtxoKey;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::commit;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;

/// Enumerates the possible spent spend-statuses of a monitored UTXO.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MonitoredUtxoSpentStatus {
    /// No spend of this UTXO was ever recorded.
    Unspent,

    /// UTXO is spent but the node does not know in which block it was spent.
    /// To correctly handle reorganizations of the block in which the UTXO was
    /// spent, a check against the archival mutator set must be performed each
    /// time its status is queried.
    SpentInUnknownBlock,

    /// UTXO is spent and the block in which it was spent is known.
    SpentIn {
        block_hash: Digest,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
    },
}

/// A mined [`Utxo`] managed by this wallet.
///
/// The UTXO must, at one point, have  been mined, although the block in which
/// it was mined might have been abandoned.
///
/// See also: [`IncomingUtxo`](super::incoming_utxo::IncomingUtxo),
/// [`ExpectedUtxo`](super::expected_utxo::ExpectedUtxo),
/// [`MonitoredUtxo`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MonitoredUtxo {
    pub utxo: Utxo,

    /// The AOCL leaf index that the monitored UTXO pertains to. This is the
    /// MMR leaf index in the AOCL that contains all historical transaction
    /// outputs.
    pub aocl_leaf_index: u64,

    /// The sender's randomness.
    pub sender_randomness: Digest,

    /// The preimage of the receiver digest.
    pub receiver_preimage: Digest,

    /// Mapping from block digest to membership proof. Only non-archival nodes
    /// should maintain membership proofs, as archival nodes can simply generate
    /// them on-demand when needed.
    pub blockhash_to_membership_proof: VecDeque<(Digest, MsMembershipProof)>,

    /// The number of membership proofs maintained per monitored UTXO. Should be
    /// 0 for all archival nodes.
    pub number_of_mps_per_utxo: usize,

    /// Hash and other metadata of the block, if any, in which this UTXO was
    /// spent.
    pub spent: MonitoredUtxoSpentStatus,

    /// Hash and other metadata of the block in which this UTXO was confirmed.
    pub confirmed_in_block: (Digest, Timestamp, BlockHeight),

    /// Indicator used to mark the UTXO as belonging to an abandoned fork
    /// Indicates what was the block tip when UTXO was marked as abandoned
    pub abandoned_at: Option<(Digest, Timestamp, BlockHeight)>,
}

impl Display for MonitoredUtxo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let aocl_leaf_index = match self.get_latest_membership_proof_entry() {
            Some(msmp) => msmp.1.aocl_leaf_index.to_string(),
            None => "not mined".to_owned(),
        };
        let spent = match self.spent {
            MonitoredUtxoSpentStatus::Unspent => "not spent".to_owned(),
            MonitoredUtxoSpentStatus::SpentInUnknownBlock => "spent in unknown block".to_owned(),
            MonitoredUtxoSpentStatus::SpentIn {
                block_hash,
                block_timestamp,
                block_height,
            } => format!(
                "spent in {block_hash:x}, at {block_timestamp}, block height {block_height}."
            ),
        };
        let confirmed = {
            let (block_hash, timestamp, height) = self.confirmed_in_block;
            format!("received in {block_hash:x}, at {timestamp}, block height {height}.")
        };
        let msmp_for_blocks = format!(
            "tracekd MSMPs for blocks\n{}\n",
            self.blockhash_to_membership_proof
                .iter()
                .map(|(digest, _)| digest.to_hex())
                .join("\n")
        );

        write!(
            f,
            "AOCL-leaf index: {aocl_leaf_index}\n\
            {spent}\n\
            {confirmed}\n\
            {msmp_for_blocks}\n
            "
        )
    }
}

impl MonitoredUtxo {
    pub(crate) fn new(
        utxo: Utxo,
        max_number_of_mps_stored: usize,
        aocl_leaf_index: u64,
        sender_randomness: Digest,
        receiver_preimage: Digest,
        confirmed_in: &Block,
    ) -> Self {
        Self {
            utxo,
            aocl_leaf_index,
            sender_randomness,
            receiver_preimage,
            blockhash_to_membership_proof: VecDeque::default(),
            number_of_mps_per_utxo: max_number_of_mps_stored,
            spent: MonitoredUtxoSpentStatus::Unspent,
            confirmed_in_block: (
                confirmed_in.hash(),
                confirmed_in.header().timestamp,
                confirmed_in.header().height,
            ),
            abandoned_at: None,
        }
    }

    pub(crate) fn new_from_block_info(
        utxo: Utxo,
        max_number_of_mps_stored: usize,
        aocl_leaf_index: u64,
        sender_randomness: Digest,
        receiver_preimage: Digest,
        confirmed_in_block: (Digest, Timestamp, BlockHeight),
    ) -> Self {
        Self {
            utxo,
            aocl_leaf_index,
            sender_randomness,
            receiver_preimage,
            blockhash_to_membership_proof: VecDeque::default(),
            number_of_mps_per_utxo: max_number_of_mps_stored,
            spent: MonitoredUtxoSpentStatus::Unspent,
            confirmed_in_block,
            abandoned_at: None,
        }
    }

    /// Return the addition record associated with this UTXO.
    pub(crate) fn addition_record(&self) -> AdditionRecord {
        let item = Tip5::hash(&self.utxo);
        commit(item, self.sender_randomness, self.receiver_preimage.hash())
    }

    /// Return the absolute index set associated with this mined UTXO.
    pub(crate) fn absolute_indices(&self) -> AbsoluteIndexSet {
        let item = Tip5::hash(&self.utxo);

        AbsoluteIndexSet::compute(
            item,
            self.sender_randomness,
            self.receiver_preimage,
            self.aocl_leaf_index,
        )
    }

    pub(crate) fn strong_utxo_key(&self) -> StrongUtxoKey {
        StrongUtxoKey::new(self.addition_record(), self.aocl_leaf_index)
    }

    /// Determine whether the attached membership proof is synced to the given
    /// block.
    ///
    /// Is only relevant for non-archival nodes as archival nodes can get their
    /// membership proofs from the archival mutator set.
    pub fn is_synced_to(&self, block_hash: Digest) -> bool {
        self.get_membership_proof_for_block(block_hash).is_some()
    }

    pub fn add_membership_proof_for_tip(
        &mut self,
        block_digest: Digest,
        updated_membership_proof: MsMembershipProof,
    ) {
        // Don't add MSMP for this block if it's already there.
        if self
            .blockhash_to_membership_proof
            .iter()
            .any(|(block_hash, _)| *block_hash == block_digest)
        {
            return;
        }

        while self.blockhash_to_membership_proof.len() >= self.number_of_mps_per_utxo
            && !self.blockhash_to_membership_proof.is_empty()
        {
            self.blockhash_to_membership_proof.pop_back();
        }

        // Ensure *no* MSMP is stored if max length is zero
        if self.number_of_mps_per_utxo.is_zero() {
            return;
        }

        self.blockhash_to_membership_proof
            .push_front((block_digest, updated_membership_proof));
    }

    pub fn membership_proof_ref_for_block(
        &self,
        block_digest: Digest,
    ) -> Option<&MsMembershipProof> {
        self.blockhash_to_membership_proof
            .iter()
            .find(|x| x.0 == block_digest)
            .map(|x| &x.1)
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

    /// Mark the monitored UTXO as spent, with the given block info, if
    /// available. If the block info is not available, the UTXO is still marked
    /// as spent, but without information about the block in which it was spent.
    pub(crate) fn mark_as_spent(&mut self, block_info: Option<(Digest, Timestamp, BlockHeight)>) {
        let spent = match block_info {
            Some((block_hash, block_timestamp, block_height)) => {
                MonitoredUtxoSpentStatus::SpentIn {
                    block_hash,
                    block_timestamp,
                    block_height,
                }
            }
            None => MonitoredUtxoSpentStatus::SpentInUnknownBlock,
        };
        self.spent = spent;
    }

    /// Get the most recent (block hash, membership proof) entry in the database,
    /// if any.
    pub fn get_latest_membership_proof_entry(&self) -> Option<(Digest, MsMembershipProof)> {
        self.blockhash_to_membership_proof.iter().next().cloned()
    }

    /// Returns true if the MUTXO was abandoned
    pub(crate) async fn was_abandoned(&self, archival_state: &ArchivalState) -> bool {
        !archival_state
            .block_belongs_to_canonical_chain(self.confirmed_in_block.0)
            .await
    }
}
