use crate::models::blockchain::{shared::Hash, transaction::utxo::Utxo};
use crate::{
    models::consensus::timestamp::Timestamp,
    prelude::twenty_first,
    util_types::mutator_set::{addition_record::AdditionRecord, commit},
};
use get_size::GetSize;
use serde::{Deserialize, Serialize};
use twenty_first::{math::tip5::Digest, util_types::algebraic_hasher::AlgebraicHasher};

// 28 days in secs
pub const UNRECEIVED_UTXO_NOTIFICATION_THRESHOLD_AGE_IN_SECS: u64 = 28 * 24 * 60 * 60;
pub const RECEIVED_UTXO_NOTIFICATION_THRESHOLD_AGE_IN_SECS: u64 = 3 * 24 * 60 * 60;

/// represents utxo and secrets necessary for recipient to claim it.
///
/// [ExpectedUtxo] is intended for offchain temporary storage of utxos that a
/// wallet sends to itself, eg change outputs.
///
/// The `ExpectedUtxo` will exist in the local [UtxoNotificationPool] from the
/// time the transaction is sent until it is mined in a block and claimed by the
/// wallet.
///
/// note that when using `ExpectedUtxo` there is a risk of losing funds because
/// the wallet stores this state on disk and if the associated file(s) are lost
/// then the funds cannot be claimed.
///
/// an alternative is to use onchain symmetric keys instead, which uses some
/// blockchain space and may leak some privacy if a key is ever used more than
/// once.
///
/// ### about `receiver_preimage`
///
/// The `receiver_preimage` field in expected_utxo is not strictly necessary.
/// It is an optimization and a compromise.
///
/// #### optimization
///
/// An `ExpectedUtxo` really only needs `utxo`, `sender_randomness` and
/// `receiver_identifier`.  These match the fields used in `PublicAnnouncement`.
///
/// However it then becomes necessary to scan all known wallet keys (of all key
/// types) in order to find the matching key, in order to obtain the preimage.
///
/// improvement: To avoid scanning a map of \[`receiver_identifier`\] -->
/// `derivation_index` could be stored in local wallet state for all known keys.
///
/// However no such map presently exists, and so the most efficient and easy
/// thing is to include the preimage in [ExpectedUtxo] instead of a
/// `receiver_identifier`.  This buys us an equivalent optimization for little
/// effort.
///
/// #### compromise
///
/// Because the preimage is necessary to create an [ExpectedUtxo]
/// `create_transaction()` must accept a `change_key: SpendingKey` parameter
/// rather than `change_address: ReceivingAddress`.  One would normally expect
/// an output to require only an address.
///
/// Further if [ExpectedUtxo] and `PublicAnnouncement` use the same fields then
/// they can share much of the same codepath when claiming.  At present, we have
/// separate codepaths that perform largely the same function.
///
/// We may revisit this area in the future, as it seems ripe for improvement.
/// In particular wallet receiver_identifier map idea indicates it is possible
/// to do this efficiently.  As such it may be best to implement at least the
/// scanning based approach before mainnet.
///
/// A branch with an implementation of the scanning approach exists:
/// danda/symmetric_keys_and_expected_utxos_without_receiver_preimage
///
/// At time of writing many tests are not passing and need updating with the new
/// field.
///
/// see [UtxoNotificationPool], [AnnouncedUtxo], [UtxoNotification](crate::models::blockchain::transaction::UtxoNotification)
#[derive(Clone, Debug, PartialEq, Eq, Hash, GetSize, Serialize, Deserialize)]
pub struct ExpectedUtxo {
    pub utxo: Utxo,
    pub addition_record: AdditionRecord,
    pub sender_randomness: Digest,
    pub receiver_preimage: Digest,
    pub received_from: UtxoNotifier,
    pub notification_received: Timestamp,
    pub mined_in_block: Option<(Digest, Timestamp)>,
}

impl ExpectedUtxo {
    pub fn new(
        utxo: Utxo,
        sender_randomness: Digest,
        receiver_preimage: Digest,
        received_from: UtxoNotifier,
    ) -> Self {
        Self {
            addition_record: commit(
                Hash::hash(&utxo),
                sender_randomness,
                receiver_preimage.hash::<Hash>(),
            ),
            utxo,
            sender_randomness,
            receiver_preimage,
            received_from,
            notification_received: Timestamp::now(),
            mined_in_block: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, GetSize, Serialize, Deserialize)]
pub enum UtxoNotifier {
    OwnMiner,
    Cli,
    Myself,
    Premine,
}
