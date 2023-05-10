use anyhow::{bail, Result};
use bytesize::ByteSize;
use get_size::GetSize;
use itertools::Itertools;
use mutator_set_tf::util_types::mutator_set::{
    addition_record::AdditionRecord, mutator_set_trait::commit,
};
use num_traits::Zero;
use priority_queue::DoublePriorityQueue;
use std::{collections::HashMap, time::SystemTime};
use tracing::{error, info, warn};
use twenty_first::{shared_math::tip5::Digest, util_types::algebraic_hasher::AlgebraicHasher};

use crate::models::{
    blockchain::{
        shared::Hash,
        transaction::{utxo::Utxo, Transaction},
    },
    peer::InstanceId,
};

pub type Credibility = i32;

#[derive(Clone, Debug, PartialEq, Eq, Hash, GetSize)]
pub struct ExpectedUtxo {
    pub utxo: Utxo,
    pub addition_record: AdditionRecord,
    pub sender_randomness: Digest,
    pub receiver_preimage: Digest,
    pub received_from: UtxoNotifier,
    pub notification_received: SystemTime,
    pub mined_in_block: Option<Digest>,
}

impl ExpectedUtxo {
    pub fn new(
        utxo: Utxo,
        sender_randomness: Digest,
        receiver_preimage: Digest,
        received_from: UtxoNotifier,
    ) -> Self {
        Self {
            addition_record: commit::<Hash>(
                &Hash::hash(&utxo),
                &sender_randomness,
                &receiver_preimage.vmhash::<Hash>(),
            ),
            utxo,
            sender_randomness,
            receiver_preimage,
            received_from,
            notification_received: SystemTime::now(),
            mined_in_block: None,
        }
    }
}

#[derive(Clone, Debug, GetSize)]
pub struct UtxoNotificationPool {
    max_total_size: usize,
    max_unconfirmed_notification_count_per_peer: usize,
    notifications: HashMap<AdditionRecord, ExpectedUtxo>,

    peer_id_to_expected_utxos: HashMap<InstanceId, Vec<AdditionRecord>>,

    #[get_size(ignore)] // This is relatively small compared to `notifications`
    queue: DoublePriorityQueue<AdditionRecord, Credibility>,
}

impl UtxoNotificationPool {
    fn pop_min(&mut self) -> Option<(ExpectedUtxo, Credibility)> {
        if let Some((utxo_digest, credibility)) = self.queue.pop_min() {
            let expected_utxo = self.notifications.remove(&utxo_digest).unwrap();
            if let UtxoNotifier::PeerUnsigned((peer_id, _socket), _credibility) =
                &expected_utxo.received_from
            {
                self.peer_id_to_expected_utxos
                    .entry(*peer_id)
                    .and_modify(|e| e.retain(|ar| *ar != expected_utxo.addition_record));
                if self.peer_id_to_expected_utxos[peer_id].is_empty() {
                    self.peer_id_to_expected_utxos.remove(peer_id);
                }
            }
            debug_assert_eq!(self.notifications.len(), self.queue.len());
            Some((expected_utxo, credibility))
        } else {
            None
        }
    }

    fn _shrink_to_fit(&mut self) {
        self.queue.shrink_to_fit();
        self.notifications.shrink_to_fit()
    }

    fn shrink_to_max_size(&mut self) {
        while self.get_size() > self.max_total_size && self.pop_min().is_some() {
            continue;
        }

        // TODO: A call to this function might reallocate. Expensive! Is this a good idea?
        // self._shrink_to_fit()
    }

    pub fn new(max_total_size: ByteSize, max_notification_count_per_peer: usize) -> Self {
        Self {
            max_total_size: max_total_size.0.try_into().unwrap(),
            max_unconfirmed_notification_count_per_peer: max_notification_count_per_peer,
            notifications: Default::default(),
            queue: Default::default(),
            peer_id_to_expected_utxos: Default::default(),
        }
    }

    pub fn len(&self) -> usize {
        debug_assert_eq!(
            self.notifications.len(),
            self.queue.len(),
            "Lengths of queue and hash map must match"
        );
        self.notifications.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len().is_zero()
    }

    /// Scans the transaction for outputs that match with list of expected
    /// incoming UTXOs, and returns expected UTXOs that are present in the
    /// transaction.
    /// Returns a list of (addition record, UTXO, sender randomness, receiver_preimage)
    pub fn scan_for_expected_utxos(
        &self,
        transaction: &Transaction,
    ) -> Vec<(AdditionRecord, Utxo, Digest, Digest)> {
        let mut received_expected_utxos = vec![];
        for tx_output in transaction.kernel.outputs.iter() {
            if let Some(expected_utxo) = self.notifications.get(tx_output) {
                received_expected_utxos.push((
                    tx_output.to_owned(),
                    expected_utxo.utxo.to_owned(),
                    expected_utxo.sender_randomness,
                    expected_utxo.receiver_preimage,
                ));
            }
        }
        received_expected_utxos
    }

    /// Return all expected UTXOs
    pub fn get_all_expected_utxos(&self) -> Vec<ExpectedUtxo> {
        self.notifications.values().cloned().collect_vec()
    }

    pub fn add_expected_utxo(
        &mut self,
        utxo: Utxo,
        sender_randomness: Digest,
        receiver_preimage: Digest,
        received_from: UtxoNotifier,
    ) -> Result<()> {
        // Check if UTXO notification exceeds peer's max number of allowed notifications
        if let UtxoNotifier::PeerUnsigned((peer_id, peer_socket), _cred) = &received_from {
            if let Some(expected_utxos_for_peer) = self.peer_id_to_expected_utxos.get(&peer_id) {
                if expected_utxos_for_peer.len() >= self.max_unconfirmed_notification_count_per_peer
                {
                    warn!("Stored {} expected UTXOs for peer {peer_id}, exceeds capacity. Checking if any are confirmed...", self.max_unconfirmed_notification_count_per_peer);
                    // Check if the expected UTXOs have not been mined yet. If they haven't, then
                    // this insertion is not allowed.

                    let number_of_unconfirmed_utxo_notifications = expected_utxos_for_peer
                        .iter()
                        .filter(|x| self.notifications.get(x).unwrap().mined_in_block.is_none())
                        .count();
                    if number_of_unconfirmed_utxo_notifications
                        >= self.max_unconfirmed_notification_count_per_peer
                    {
                        let error_msg = format!("Received too many UTXO notifications from peer with instance ID {} and socket {}", peer_id, peer_socket);
                        error!(error_msg);
                        bail!(error_msg)
                    }

                    info!("Some were confirmed. Accepting notification.");
                }
            }
        }
        // TODO: Add check that we can actually unlock the UTXO's lock script.
        // Also check that receiver preimage belongs to us etc.
        // Or should this be the caller's responsibility?
        let addition_record = commit::<Hash>(
            &Hash::hash(&utxo),
            &sender_randomness,
            &receiver_preimage.vmhash::<Hash>(),
        );

        // Check that addition record is not already contained in notification set.
        // If it is, do not allow its timestamp to be updated. Return early.
        if self.notifications.contains_key(&addition_record) {
            warn!("Received repeated addition record. Ignoring");
            return Ok(());
        }

        let expected_utxo = ExpectedUtxo {
            addition_record,
            utxo,
            sender_randomness,
            receiver_preimage,
            received_from: received_from.clone(),
            notification_received: SystemTime::now(),
            mined_in_block: None,
        };
        let ret = self.notifications.insert(addition_record, expected_utxo);

        // Sanity check
        assert!(
            ret.is_none(),
            "Addition record was already present in expected UTXO set"
        );

        self.queue
            .push(addition_record, received_from.credibility());

        debug_assert_eq!(
            self.notifications.len(),
            self.queue.len(),
            "hashmap and queue length must agree for expected UTXO pool after add"
        );

        // Add addition record to list for peer
        if let UtxoNotifier::PeerUnsigned((peer_id, _socket), _cred) = &received_from {
            self.peer_id_to_expected_utxos
                .entry(*peer_id)
                .and_modify(|e| e.push(addition_record))
                .or_insert(vec![addition_record]);
        }

        self.shrink_to_max_size();

        Ok(())
    }

    pub fn mark_as_received(
        &mut self,
        addition_record: AdditionRecord,
        block_digest: Digest,
    ) -> Result<()> {
        if let Some(entry) = self.notifications.get_mut(&addition_record) {
            entry.mined_in_block = Some(block_digest);
            Ok(())
        } else {
            let error_msg = "Requested to mark unknown UTXO notification as received";
            error!(error_msg);
            bail!(error_msg);
        }
    }

    pub fn drop_expected_utxo(
        &mut self,
        utxo: Utxo,
        sender_randomness: Digest,
        receiver_preimage: Digest,
    ) {
        let addition_record = commit::<Hash>(
            &Hash::hash(&utxo),
            &sender_randomness,
            &receiver_preimage.vmhash::<Hash>(),
        );
        let maybe_removed = self.notifications.remove(&addition_record);

        if let Some(removed_exp_utxo) = maybe_removed {
            self.queue.remove(&addition_record);
            if let UtxoNotifier::PeerUnsigned((peer_id, _socket), _cred) =
                removed_exp_utxo.received_from
            {
                self.peer_id_to_expected_utxos
                    .entry(peer_id)
                    .and_modify(|e| e.retain(|ar| *ar != addition_record));
                if self.peer_id_to_expected_utxos[&peer_id].is_empty() {
                    self.peer_id_to_expected_utxos.remove(&peer_id);
                }
            }
        }

        debug_assert_eq!(
            self.notifications.len(),
            self.queue.len(),
            "hashmap and queue length must agree for expected UTXO pool after drop"
        );
        debug_assert!(
            self.peer_id_to_expected_utxos.values().map(|x| x.len()).sum::<usize>() <= self.notifications.len(),
            "Total number of UTXO notifications from peers may not exceed total number of expected UTXOs");
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, GetSize)]
pub enum UtxoNotifier {
    OwnMiner,
    Cli,
    // ((instanceId, stringified SocketAddr), peer credibility)
    PeerUnsigned((InstanceId, String), Credibility),
    Premine,
}

const OWN_MINER_SUPPRESSION: Credibility = 1;
const CLI_SUPPRESSION: Credibility = 2;
const UNSIGNED_PEER_SUPPRESSION: Credibility = 4;

impl UtxoNotifier {
    pub fn credibility(&self) -> Credibility {
        match self {
            UtxoNotifier::Premine => Credibility::MAX,
            UtxoNotifier::OwnMiner => Credibility::MAX - OWN_MINER_SUPPRESSION,
            UtxoNotifier::Cli => Credibility::MAX - CLI_SUPPRESSION,
            UtxoNotifier::PeerUnsigned(_, credibility) => {
                // Ensure that peer notifications always have lower priority
                // than those reported other ways, and prevent overflow in this calculation
                credibility.saturating_sub(UNSIGNED_PEER_SUPPRESSION)
            }
        }
    }
}

#[cfg(test)]
mod wallet_state_tests {
    use rand::random;
    use tracing_test::traced_test;

    use super::*;
    use crate::{
        models::blockchain::transaction::{amount::Amount, utxo::LockScript},
        tests::shared::make_mock_transaction,
    };

    #[traced_test]
    #[tokio::test]
    async fn utxo_notification_insert_remove_scan() {
        let mut notification_pool = UtxoNotificationPool::new(ByteSize::kb(1), 100);
        assert!(notification_pool.is_empty());
        assert!(notification_pool.len().is_zero());
        let mock_utxo = Utxo {
            lock_script: LockScript(vec![]),
            coins: Into::<Amount>::into(10).to_native_coins(),
        };
        let sender_randomness: Digest = random();
        let receiver_preimage: Digest = random();
        let peer_instance_id: InstanceId = random();
        let expected_addition_record = commit::<Hash>(
            &Hash::hash(&mock_utxo),
            &sender_randomness,
            &receiver_preimage.vmhash::<Hash>(),
        );
        notification_pool
            .add_expected_utxo(
                mock_utxo.clone(),
                sender_randomness,
                receiver_preimage,
                UtxoNotifier::PeerUnsigned((peer_instance_id, String::default()), 100),
            )
            .unwrap();
        assert!(!notification_pool.is_empty());
        assert_eq!(1, notification_pool.len());
        assert_eq!(
            1,
            notification_pool.peer_id_to_expected_utxos[&peer_instance_id].len()
        );

        let mock_tx_containing_expected_utxo =
            make_mock_transaction(vec![], vec![expected_addition_record]);

        let ret_with_tx_containing_utxo =
            notification_pool.scan_for_expected_utxos(&mock_tx_containing_expected_utxo);
        assert_eq!(1, ret_with_tx_containing_utxo.len());

        // Call scan but with another input. Verify that it returns the empty list
        let another_addition_record = commit::<Hash>(
            &Hash::hash(&mock_utxo),
            &random(),
            &receiver_preimage.vmhash::<Hash>(),
        );
        let tx_without_utxo = make_mock_transaction(vec![], vec![another_addition_record]);
        let ret_with_tx_without_utxo = notification_pool.scan_for_expected_utxos(&tx_without_utxo);
        assert!(ret_with_tx_without_utxo.is_empty());

        // Verify that we can remove the expected UTXO again
        notification_pool.drop_expected_utxo(mock_utxo, sender_randomness, receiver_preimage);
        assert!(notification_pool.is_empty());
        assert!(
            !notification_pool
                .peer_id_to_expected_utxos
                .contains_key(&peer_instance_id),
            "Key for peer must be deleted after removal of expected UTXO"
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn utxo_notification_peer_spam_test() {
        let max_number_of_stored_utxos_per_peer = 100;
        let mut notification_pool =
            UtxoNotificationPool::new(ByteSize::mb(1), max_number_of_stored_utxos_per_peer);

        let spamming_peer: InstanceId = random();
        let mock_utxo = Utxo {
            lock_script: LockScript(vec![]),
            coins: Into::<Amount>::into(14).to_native_coins(),
        };
        let receiver_preimage: Digest = random();
        let first_sender_randomness: Digest = random();
        let spamming_peer_credibility = 10;

        // Add 1 expected UTXO from spamming peer
        notification_pool
            .add_expected_utxo(
                mock_utxo.clone(),
                first_sender_randomness,
                receiver_preimage,
                UtxoNotifier::PeerUnsigned(
                    (spamming_peer, String::default()),
                    spamming_peer_credibility,
                ),
            )
            .unwrap();

        // Add another N, until capacity from spamming peer
        for _ in 1..max_number_of_stored_utxos_per_peer {
            notification_pool
                .add_expected_utxo(
                    mock_utxo.clone(),
                    random(),
                    receiver_preimage,
                    UtxoNotifier::PeerUnsigned(
                        (spamming_peer, String::default()),
                        spamming_peer_credibility,
                    ),
                )
                .unwrap();
        }

        // The next insertion must fail
        assert!(notification_pool
            .add_expected_utxo(
                mock_utxo.clone(),
                random(),
                receiver_preimage,
                UtxoNotifier::PeerUnsigned(
                    (spamming_peer, String::default()),
                    spamming_peer_credibility
                ),
            )
            .is_err());

        // An insertion from another peer must be allowed
        let non_spamming_peer_credibility = 100;
        let non_spamming_peer: InstanceId = random();
        notification_pool
            .add_expected_utxo(
                mock_utxo.clone(),
                random(),
                random(),
                UtxoNotifier::PeerUnsigned(
                    (non_spamming_peer, String::default()),
                    non_spamming_peer_credibility,
                ),
            )
            .unwrap();

        // Once one of the spamming peer's UTXOs are marked as received, another UTXO
        // notification can be stored.
        notification_pool
            .mark_as_received(
                commit::<Hash>(
                    &Hash::hash(&mock_utxo),
                    &first_sender_randomness,
                    &receiver_preimage.vmhash::<Hash>(),
                ),
                Digest::default(),
            )
            .unwrap();
        notification_pool
            .add_expected_utxo(
                mock_utxo.clone(),
                random(),
                random(),
                UtxoNotifier::PeerUnsigned(
                    (spamming_peer, String::default()),
                    spamming_peer_credibility,
                ),
            )
            .unwrap();
        assert_eq!(
            101,
            notification_pool.peer_id_to_expected_utxos[&spamming_peer].len()
        );
        assert_eq!(
            1,
            notification_pool.peer_id_to_expected_utxos[&non_spamming_peer].len()
        );

        // Verify that `pop_min` returns the UTXO notification with lowest credibility
        let (lowest_priority_notif, infimum_cred) = notification_pool.pop_min().unwrap();
        assert_eq!(
            spamming_peer_credibility - UNSIGNED_PEER_SUPPRESSION,
            infimum_cred
        );
        assert_eq!(
            UtxoNotifier::PeerUnsigned(
                (spamming_peer, String::default()),
                spamming_peer_credibility
            ),
            lowest_priority_notif.received_from
        );
    }
}
