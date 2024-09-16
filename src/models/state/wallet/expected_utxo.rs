use crate::models::blockchain::{shared::Hash, transaction::utxo::Utxo};
use crate::{
    models::consensus::timestamp::Timestamp,
    prelude::twenty_first,
    util_types::mutator_set::{addition_record::AdditionRecord, commit},
};
use get_size::GetSize;
use serde::{Deserialize, Serialize};
use twenty_first::{math::tip5::Digest, util_types::algebraic_hasher::AlgebraicHasher};

/// represents utxo and secrets necessary for recipient to claim it.
///
/// [ExpectedUtxo] is intended for offchain temporary storage of utxos that a
/// wallet sends to itself, eg change outputs.
///
/// The `ExpectedUtxo` will exist in the local
/// [RustyWalletDatabase](super::rusty_wallet_database::RustyWalletDatabase)
/// from the time the transaction is sent until it is mined in a block and
/// claimed by the wallet.
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
/// See issue #176.
/// <https://github.com/Neptune-Crypto/neptune-core/issues/176>
///
/// see [AnnouncedUtxo](crate::models::blockchain::transaction::AnnouncedUtxo), [UtxoNotification](crate::models::blockchain::transaction::UtxoNotification)
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
    Claim,
}
