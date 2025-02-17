#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use tasm_lib::prelude::Digest;

use super::expected_utxo::UtxoNotifier;
use super::utxo_notification::UtxoNotificationPayload;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::state::ExpectedUtxo;
use crate::models::state::Tip5;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::commit;

/// A [`Utxo`] along with associated data necessary for a recipient to claim it.
///
/// This struct does not store:
///  - Membership proofs -- the recipient must produce them on their own,
///    possibly by running an archival node.
///  - Unlock keys -- cryptographic data necessary for unlocking the UTXO.
///    (There is one exception to this rule: for guesser fee UTXOs, the unlock
///    key coincides with the receiver preimage.)
///
/// See [crate::models::state::wallet::utxo_notification::UtxoNotificationPayload], [ExpectedUtxo]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(Arbitrary))]
pub(crate) struct IncomingUtxo {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
    pub receiver_preimage: Digest,
}

impl From<&ExpectedUtxo> for IncomingUtxo {
    fn from(eu: &ExpectedUtxo) -> Self {
        Self {
            utxo: eu.utxo.clone(),
            sender_randomness: eu.sender_randomness,
            receiver_preimage: eu.receiver_preimage,
        }
    }
}

impl IncomingUtxo {
    pub(crate) fn addition_record(&self) -> AdditionRecord {
        commit(
            Tip5::hash(&self.utxo),
            self.sender_randomness,
            self.receiver_preimage.hash(),
        )
    }

    /// Returns true iff this UTXO is a guesser reward.
    pub(crate) fn is_guesser_fee(&self) -> bool {
        self.utxo
            .is_lockscript_with_preimage(self.receiver_preimage)
    }

    pub(crate) fn from_utxo_notification_payload(
        payload: UtxoNotificationPayload,
        receiver_preimage: Digest,
    ) -> Self {
        Self {
            utxo: payload.utxo,
            sender_randomness: payload.sender_randomness,
            receiver_preimage,
        }
    }

    pub(crate) fn into_expected_utxo(self, received_from: UtxoNotifier) -> ExpectedUtxo {
        ExpectedUtxo::new(
            self.utxo.to_owned(),
            self.sender_randomness,
            self.receiver_preimage,
            received_from,
        )
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;

    #[proptest]
    fn consistent_conversion(
        #[strategy(arb())] incoming_utxo: IncomingUtxo,
        #[strategy(arb())] notifier: UtxoNotifier,
    ) {
        let as_expected_utxo = incoming_utxo.clone().into_expected_utxo(notifier);
        prop_assert_eq!(
            incoming_utxo.addition_record(),
            as_expected_utxo.addition_record
        );

        let back_again: IncomingUtxo = (&as_expected_utxo).into();
        prop_assert_eq!(incoming_utxo, back_again);
    }
}
