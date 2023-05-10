use std::{collections::HashMap, time::SystemTime};

use bytesize::ByteSize;
use get_size::GetSize;
use itertools::Itertools;
use mutator_set_tf::util_types::mutator_set::{
    addition_record::AdditionRecord, mutator_set_trait::commit,
};
use num_traits::Zero;
use priority_queue::DoublePriorityQueue;
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
    notifications: HashMap<AdditionRecord, ExpectedUtxo>,

    #[get_size(ignore)] // This is relatively small compared to `notifications`
    queue: DoublePriorityQueue<AdditionRecord, Credibility>,
}

impl UtxoNotificationPool {
    fn pop_min(&mut self) -> Option<(ExpectedUtxo, Credibility)> {
        if let Some((utxo_digest, credibility)) = self.queue.pop_min() {
            let utxo = self.notifications.remove(&utxo_digest).unwrap();
            debug_assert_eq!(self.notifications.len(), self.queue.len());
            Some((utxo, credibility))
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

    pub fn new(max_total_size: ByteSize) -> Self {
        Self {
            max_total_size: max_total_size.0.try_into().unwrap(),
            notifications: Default::default(),
            queue: Default::default(),
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
    ) {
        // TODO: Add check that we can actually unlock the UTXO's lock script.
        // Also check that receiver preimage belongs to us etc.
        // Or should this be the caller's responsibility?
        let addition_record = commit::<Hash>(
            &Hash::hash(&utxo),
            &sender_randomness,
            &receiver_preimage.vmhash::<Hash>(),
        );

        let expected_utxo = ExpectedUtxo {
            utxo,
            sender_randomness,
            receiver_preimage,
            received_from: received_from.clone(),
            notification_received: SystemTime::now(),
            mined_in_block: None,
        };
        self.notifications.insert(addition_record, expected_utxo);
        self.queue
            .push(addition_record, received_from.credibility());

        debug_assert_eq!(
            self.notifications.len(),
            self.queue.len(),
            "hashmap and queue length must agree for expected UTXO pool after add"
        );

        self.shrink_to_max_size();
    }

    pub fn mark_as_received(&mut self, addition_record: AdditionRecord, block_digest: Digest) {
        self.notifications
            .entry(addition_record)
            .and_modify(|x| x.mined_in_block = Some(block_digest));
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
        maybe_removed.map(|_x| self.queue.remove(&addition_record));

        debug_assert_eq!(
            self.notifications.len(),
            self.queue.len(),
            "hashmap and queue length must agree for expected UTXO pool after drop"
        );
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, GetSize)]
pub enum UtxoNotifier {
    OwnMiner,
    Cli,
    // ((instanceId, stringified SocketAddr), peer credibility)
    Peer((InstanceId, String), Credibility),
    Premine,
}

impl UtxoNotifier {
    pub fn credibility(&self) -> Credibility {
        match self {
            UtxoNotifier::Premine => Credibility::MAX,
            UtxoNotifier::OwnMiner => Credibility::MAX - 1,
            UtxoNotifier::Cli => Credibility::MAX - 2,
            UtxoNotifier::Peer(_, credibility) => {
                // Ensure that peer notifications always have lower priority
                // than those reported other ways, and prevent overflow in this calculation
                credibility.saturating_sub(3)
            }
        }
    }
}

#[cfg(test)]
mod wallet_state_tests {
    use rand::random;

    use super::*;
    use crate::{
        models::blockchain::transaction::{amount::Amount, utxo::LockScript},
        tests::shared::make_mock_transaction,
    };

    #[tokio::test]
    async fn utxo_notification_insert_remove_scan() {
        let mut notification_pool = UtxoNotificationPool::new(ByteSize::kb(1));
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
        notification_pool.add_expected_utxo(
            mock_utxo.clone(),
            sender_randomness,
            receiver_preimage,
            UtxoNotifier::Peer((peer_instance_id, String::default()), 100),
        );
        assert!(!notification_pool.is_empty());
        assert_eq!(1, notification_pool.len());

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
    }
}
