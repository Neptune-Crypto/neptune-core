use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;

use crate::state::archival_state::ArchivalState;
use crate::state::wallet::monitored_utxo::MonitoredUtxo;
use crate::state::wallet::monitored_utxo::MonitoredUtxoSpentStatus;
use crate::state::wallet::monitored_utxo_state::MonitoredUtxoState;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

/// Enumerates the ways in which UTXO validity (spent status and AOCL inclusion
/// status) can be verified relative to a mutator set.
pub(crate) enum UtxoValidator<'a> {
    /// The node does not maintain an archival state and must thus maintain
    /// membership proofs for all the wallet's UTXOs.
    Light {
        tip: Digest,
        tip_msa: MutatorSetAccumulator,
    },

    /// The node maintains an archival state, so it can get all required
    /// membership proofs on-demand at the time when they are needed from the
    /// archival mutator set.
    Archival(&'a ArchivalState),
}

impl<'a> UtxoValidator<'a> {
    #[inline]
    pub(crate) async fn mutxo_state(&self, monitored_utxo: &MonitoredUtxo) -> MonitoredUtxoState {
        match self {
            UtxoValidator::Light {
                tip: tip_digest,
                tip_msa: mutator_set_accumulator,
            } => {
                if let Some(mp) = monitored_utxo.get_membership_proof_for_block(*tip_digest) {
                    let spent =
                        !mutator_set_accumulator.verify(Tip5::hash(&monitored_utxo.utxo), &mp);
                    if spent {
                        MonitoredUtxoState::Spent
                    } else {
                        MonitoredUtxoState::SyncedAndUnspent
                    }
                } else {
                    MonitoredUtxoState::Unsynced
                }
            }
            UtxoValidator::Archival(archival_state) => {
                let synced = {
                    let (block_hash, _, block_height) = monitored_utxo.confirmed_in_block;
                    archival_state
                        .is_canonical_block(block_hash, block_height)
                        .await
                };

                if !synced {
                    return MonitoredUtxoState::Unsynced;
                }

                match monitored_utxo.spent {
                    MonitoredUtxoSpentStatus::Unspent => {
                        return MonitoredUtxoState::SyncedAndUnspent;
                    }
                    MonitoredUtxoSpentStatus::SpentIn {
                        block_hash,
                        block_height,
                        ..
                    } => {
                        if archival_state
                            .is_canonical_block(block_hash, block_height)
                            .await
                        {
                            return MonitoredUtxoState::Spent;
                        }
                    }
                    MonitoredUtxoSpentStatus::SpentInUnknownBlock => (),
                };

                // UTXO is marked as spent but we don't know in which block it
                // was spent *or* the block in which an expenditure was seen
                // is not canonical.
                // If we don't know when the UTXO was spent, the spending block
                // could have been reorganized away. And even if we know
                // that the block in which the UTXO was spent was reorganized
                // away, it could could have been reorganized away to a chain
                // where the spend also occurred. So we have to check the
                // mutator set to see if the UTXO was actually spent or not.
                // The reason we don't do this for all UTXOs, is that it's too
                // slow compared to inspecting the fields on the monitored UTXO
                // directly.
                let absolute_index_set = monitored_utxo.absolute_indices();
                let is_spent = archival_state
                    .archival_mutator_set
                    .ams()
                    .absolute_index_set_was_applied(absolute_index_set)
                    .await;

                if is_spent {
                    MonitoredUtxoState::Spent
                } else {
                    MonitoredUtxoState::SyncedAndUnspent
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;

    impl<'a> UtxoValidator<'a> {
        pub(crate) async fn fetch_ms_membership_proof(
            &self,
            monitored_utxo: &MonitoredUtxo,
        ) -> Option<MsMembershipProof> {
            match self {
                UtxoValidator::Light {
                    tip: tip_digest, ..
                } => monitored_utxo.get_membership_proof_for_block(*tip_digest),
                UtxoValidator::Archival(archival_state) => {
                    let item = Tip5::hash(&monitored_utxo.utxo);
                    archival_state
                        .archival_mutator_set
                        .ams()
                        .restore_membership_proof(
                            item,
                            monitored_utxo.sender_randomness,
                            monitored_utxo.receiver_preimage,
                            monitored_utxo.aocl_leaf_index,
                        )
                        .await
                        .ok()
                }
            }
        }
    }
}
