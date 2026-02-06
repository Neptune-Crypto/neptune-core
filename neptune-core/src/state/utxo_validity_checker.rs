use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;

use crate::state::archival_state::ArchivalState;
use crate::state::wallet::monitored_utxo::MonitoredUtxo;
use crate::state::wallet::monitored_utxo_state::MonitoredUtxoState;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

/// Enumerates the ways in which UTXO validity (spent status and AOCL inclusion
/// status) can be verified relative to a mutator set.
pub(crate) enum UtxoValidityChecker<'a> {
    Light {
        tip: Digest,
        tip_msa: MutatorSetAccumulator,
    },
    Archival(&'a ArchivalState),
}

impl<'a> UtxoValidityChecker<'a> {
    async fn fetch_ms_membership_proof(
        &self,
        monitored_utxo: &MonitoredUtxo,
    ) -> Option<MsMembershipProof> {
        match self {
            UtxoValidityChecker::Light {
                tip: tip_digest, ..
            } => monitored_utxo.get_membership_proof_for_block(*tip_digest),
            UtxoValidityChecker::Archival(archival_state) => {
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

    #[inline]
    pub(crate) async fn mutxo_state(&self, monitored_utxo: &MonitoredUtxo) -> MonitoredUtxoState {
        match self {
            UtxoValidityChecker::Light {
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
            UtxoValidityChecker::Archival(archival_state) => {
                let synced = {
                    let (block_hash, _, block_height) = monitored_utxo.confirmed_in_block;
                    archival_state
                        .is_canonical_block(block_hash, block_height)
                        .await
                };

                if !synced {
                    return MonitoredUtxoState::Unsynced;
                }

                let Some((spending_hash, _, spending_height)) = monitored_utxo.spent_in_block
                else {
                    return MonitoredUtxoState::SyncedAndUnspent;
                };

                // If MUTXO was ever observed as spent, we need to check
                // the archival mutator set to see if the spend was
                // reorganized away. If a spend was never observed, then
                // it is assumed that the monitored UTXO was never
                // spent.
                let spend_is_canonical = archival_state
                    .is_canonical_block(spending_hash, spending_height)
                    .await;

                if spend_is_canonical {
                    MonitoredUtxoState::Spent
                } else {
                    // Corner case: Even *if* latest spend is not
                    // canonical, this spending block could have been
                    // reorganized away to a chain where the spend also
                    // occurred. So we have to check the mutator set to
                    // see if the UTXO was spent or not.
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
}
