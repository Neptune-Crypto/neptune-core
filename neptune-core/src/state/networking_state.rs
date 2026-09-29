use std::time::SystemTime;

use neptune_p2p::peer::InstanceId;
use neptune_primitives::block_height::BlockHeight;
use neptune_primitives::difficulty_control::ProofOfWork;
use rand::rng;
use rand::Rng;
use tasm_lib::prelude::Digest;
use tasm_lib::twenty_first::prelude::Mmr;
use tasm_lib::twenty_first::prelude::MmrMembershipProof;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

use crate::application::loops::sync_loop::sync_progress::SyncProgress;
use crate::state::sync_status::SyncStatus;

/// Information about a foreign tip towards which the client is syncing.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SyncAnchor {
    /// Cumulative proof-of-work number of the target fork that we are syncing
    /// towards. This number is immutable for each `SyncAnchor`.
    pub(crate) cumulative_proof_of_work: ProofOfWork,

    /// The block MMR accumulator *after* appending the claimed tip digest. This
    /// value is immutable for each `SyncAnchor`.
    pub(crate) block_mmr: MmrAccumulator,

    /// Indicates the block that we have currently synced to under this anchor.
    pub(crate) champion: (BlockHeight, Digest),

    /// Authentication path of the node's tip, relative to `block_mmr`, if that
    /// block arrived with one. Processed blocks are deleted from the sync
    /// store, so this retained path is what allows membership proofs to be
    /// extended to anchor-relative ones when serving other syncing peers.
    pub(crate) tip_auth_path: Option<(BlockHeight, MmrMembershipProof)>,

    /// The last time this anchor was either created or updated.
    pub(crate) updated: SystemTime,

    /// How much progress have we made so far?
    pub(crate) status: SyncProgress,
}

impl SyncAnchor {
    /// # Panics
    ///
    /// If the claimed block MMR accumulator does not match the claimed height.
    ///
    /// The block defining this anchor must have its digest added to the MMR.
    pub(crate) fn new(
        claimed_cumulative_pow: ProofOfWork,
        claimed_block_mmra: MmrAccumulator,
        claimed_height: BlockHeight,
        claimed_block_digest: Digest,
    ) -> Self {
        assert_eq!(
            claimed_height.next().value(),
            claimed_block_mmra.num_leafs(),
            "Claimed block MMR accumulator must have one leaf per block up to \
             and including the claimed tip of height {claimed_height}."
        );

        let status = SyncProgress::new(claimed_block_mmra.num_leafs());
        Self {
            cumulative_proof_of_work: claimed_cumulative_pow,
            block_mmr: claimed_block_mmra,
            champion: (claimed_height, claimed_block_digest),
            tip_auth_path: None,
            updated: SystemTime::now(),
            status,
        }
    }

    /// Determine if the incoming block is the new champion.
    ///
    /// This is true if the champion is not set yet, or if its height is smaller
    /// than that of the incoming block.
    pub(crate) fn incoming_block_is_new_champion(
        &self,
        incoming_block_height: BlockHeight,
    ) -> bool {
        self.champion.0 < incoming_block_height
    }

    /// Modify the sync anchor to point to the new incoming block, if its height
    /// is larger.
    pub(crate) fn catch_up(&mut self, height: BlockHeight, block_hash: Digest) {
        let new_champion = (height, block_hash);
        let now = SystemTime::now();

        if self.champion.0 <= new_champion.0 {
            self.champion = new_champion;
            self.updated = now;
        }
    }
}

/// `NetworkingState` contains in-memory data related to the node's networking
/// state: Whether it is so far behind that it must catch up through syncing,
/// and other data.
#[derive(Debug, Clone)]
pub struct NetworkingState {
    /// This value is only Some if the instance is running an archival node
    /// that is currently in sync mode (downloading blocks in batches).
    /// Only the main task may update this flag.
    pub(crate) sync_anchor: Option<SyncAnchor>,

    /// Tracks status of sync process: whether it is active, or how far it has
    /// progressed. This value may be updated by the main task or by peers.
    pub sync_status: SyncStatus,

    /// Read-only value set at random during startup.
    pub instance_id: InstanceId,

    /// If set to `true`, no blocks, block proposals, or transactions will be
    /// sent from this client, or accepted from peers.
    /// Only the RPC server may update this flag.
    pub freeze: bool,
}

impl NetworkingState {
    pub(crate) fn new() -> Self {
        Self {
            sync_anchor: None,
            sync_status: SyncStatus::Unknown,
            instance_id: rng().random(),
            freeze: false,
        }
    }
}

#[cfg(any(test, feature = "test-helpers"))]
mod test_helpers {
    use super::*;

    /// Views into sync-internal state, for integration tests.
    impl NetworkingState {
        /// Whether a running sync process has retained an authentication path
        /// for the current tip.
        pub fn sync_tip_auth_path_is_retained(&self) -> bool {
            self.sync_anchor
                .as_ref()
                .is_some_and(|sync_anchor| sync_anchor.tip_auth_path.is_some())
        }

        /// Whether a running sync process has downloaded every block in its
        /// span, processed or not.
        pub fn sync_download_is_complete(&self) -> bool {
            matches!(&self.sync_status, SyncStatus::Syncing(progress) if progress.download_is_complete())
        }
    }
}
