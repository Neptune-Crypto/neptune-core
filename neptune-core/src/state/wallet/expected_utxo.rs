#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::twenty_first::tip5::digest::Digest;

use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::protocol::consensus::transaction::utxo_triple::UtxoTriple;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::util_types::mutator_set::addition_record::AdditionRecord;

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
/// see [IncomingUtxo](crate::state::wallet::incoming_utxo::IncomingUtxo),
/// [UtxoNotificationPayLoad](crate::state::wallet::utxo_notification::UtxoNotificationPayload)
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
            addition_record: UtxoTriple {
                utxo: utxo.clone(),
                sender_randomness,
                receiver_digest: receiver_preimage.hash(),
            }
            .addition_record(),
            utxo,
            sender_randomness,
            receiver_preimage,
            received_from,
            notification_received: Timestamp::now(),
            mined_in_block: None,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, GetSize, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(Arbitrary))]
pub enum UtxoNotifier {
    OwnMinerComposeBlock,
    OwnMinerGuessNonce,
    Cli,
    Myself,
    Premine,
    FeeGobbler,
}
