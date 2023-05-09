use std::{collections::HashMap, time::SystemTime};

use bytesize::ByteSize;
use get_size::GetSize;
use itertools::Itertools;
use mutator_set_tf::util_types::mutator_set::{
    addition_record::AdditionRecord, mutator_set_trait::commit,
};
use priority_queue::DoublePriorityQueue;
use twenty_first::{shared_math::tip5::Digest, util_types::algebraic_hasher::AlgebraicHasher};

use crate::models::{
    blockchain::{
        shared::Hash,
        transaction::{utxo::Utxo, Transaction},
    },
    peer::InstanceId,
};

pub type Credibility = u32;

#[derive(Clone, Debug, PartialEq, Eq, Hash, GetSize)]
pub struct ExpectedUtxo {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
    pub receiver_preimage: Digest,
    pub received_from: UtxoNotifier,
    pub notification_received: SystemTime,
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
        // self.shrink_to_fit()
    }

    pub fn new(max_total_size: ByteSize) -> Self {
        Self {
            max_total_size: max_total_size.0.try_into().unwrap(),
            notifications: Default::default(),
            queue: Default::default(),
        }
    }

    /// Scans the transaction for outputs that match with list of expected
    /// incomign UTXOs, and returns expected UTXOs that are present in the
    /// transaction.
    pub fn scan_for_expected_utxos(
        &self,
        transaction: &Transaction,
    ) -> Vec<(AdditionRecord, Utxo, Digest, Digest)> {
        let mut received_expected_utxos = vec![];
        for (utxo, sender_randomness, receiver_preimage) in self.get_expected_utxos() {
            let receiver_digest = receiver_preimage.vmhash::<Hash>();
            let ar = commit::<Hash>(&Hash::hash(&utxo), &sender_randomness, &receiver_digest);
            if transaction
                .kernel
                .outputs
                .iter()
                .any(|output| *output == ar)
            {
                received_expected_utxos.push((ar, utxo, sender_randomness, receiver_preimage));
            }
        }
        received_expected_utxos
    }

    fn get_expected_utxos(&self) -> Vec<(Utxo, Digest, Digest)> {
        println!("self.notifications.len() = {}", self.notifications.len());
        self.notifications
            .iter()
            .map(|(_, expected_utxo)| {
                (
                    expected_utxo.utxo.clone(),
                    expected_utxo.sender_randomness,
                    expected_utxo.receiver_preimage,
                )
            })
            .collect_vec()
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
                // Prevent ensure that peer notifications  always have lower priority
                // than those reported other ways, and prevent overflow in this calculation
                if *credibility >= 3 {
                    credibility - 3
                } else {
                    0
                }
            }
        }
    }
}
