use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use twenty_first::math::tip5::Digest;


use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::prelude::twenty_first;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::commit;

/// represents utxo and secrets necessary for recipient to claim it.
///
/// [ExpectedUtxo] is intended to inform the wallet of UTXOs that were confirmed
/// or are about to be confirmed, that it can claim. For example:
///  - change outputs,
///  - coinbase UTXOs (produced by the miner)
///  - incoming off-chain transaction notifications.
///
/// The on-chain notifications follow a completely different code path and never
/// touch [ExpectedUtxo]s.
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
/// Objects of this type are not intended to be transmitted; they only ever live
/// locally in the client's memory or disk. The main use of this thing
///
/// ### about `receiver_preimage`
///
/// See issue #176.
/// <https://github.com/Neptune-Crypto/neptune-core/issues/176>
///
/// see [AnnouncedUtxo](crate::models::blockchain::transaction::AnnouncedUtxo), [UtxoNotification](crate::models::blockchain::transaction::UtxoNotification)
#[derive(Clone, Debug, Hash, GetSize, Serialize, Deserialize)]
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
    pub(crate) fn new(
        utxo: Utxo,
        sender_randomness: Digest,
        receiver_preimage: Digest,
        received_from: UtxoNotifier,
    ) -> Self {
        Self {
            addition_record: commit(
                Hash::hash(&utxo),
                sender_randomness,
                receiver_preimage.hash(),
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

#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Hash, GetSize, Serialize, Deserialize, strum_macros::Display,
)]
pub enum UtxoNotifier {
    OwnMinerComposeBlock,
    OwnMinerGuessNonce,
    Cli,
    Myself,
    Premine,
}
