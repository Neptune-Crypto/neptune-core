use std::hash::Hash;

#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use tasm_lib::prelude::Digest;

use super::expected_utxo::UtxoNotifier;
use super::utxo_notification::UtxoNotificationPayload;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::protocol::consensus::transaction::utxo_triple::UtxoTriple;
use crate::state::ExpectedUtxo;
use crate::util_types::mutator_set::addition_record::AdditionRecord;

/// A [`Utxo`] along with associated data necessary for a recipient to claim it.
///
/// This struct does not store:
///  - Membership proofs -- the recipient must produce them on their own,
///    possibly by running an archival node.
///  - Unlock keys -- cryptographic data necessary for unlocking the UTXO.
///    (There is one exception to this rule: for guesser fee UTXOs, the unlock
///    key coincides with the receiver preimage.)
///
/// See [UtxoNotificationPayload], [ExpectedUtxo]
#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(Arbitrary))]
pub(crate) struct IncomingUtxo {
    pub(crate) utxo: Utxo,
    pub(crate) sender_randomness: Digest,
    pub(crate) receiver_preimage: Digest,

    /// Whether the UTXO is a guesser fee or not. Only to be used for log
    /// messages and wallet info. Does not affect how the ability to claim the
    /// UTXO.
    pub(crate) is_guesser_fee: bool,
}

impl PartialEq for IncomingUtxo {
    fn eq(&self, other: &Self) -> bool {
        // Exclude `is_guesser_fee` in equality as the other fields are
        // sufficient to claim the UTXO.
        self.utxo == other.utxo
            && self.sender_randomness == other.sender_randomness
            && self.receiver_preimage == other.receiver_preimage
    }
}

impl Eq for IncomingUtxo {}

impl Hash for IncomingUtxo {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Exclude `is_guesser_fee` because the equality implementation does.
        std::hash::Hash::hash(&self.utxo, state);
        std::hash::Hash::hash(&self.sender_randomness, state);
        std::hash::Hash::hash(&self.receiver_preimage, state);
    }
}

impl From<&ExpectedUtxo> for IncomingUtxo {
    fn from(eu: &ExpectedUtxo) -> Self {
        Self {
            utxo: eu.utxo.clone(),
            sender_randomness: eu.sender_randomness,
            receiver_preimage: eu.receiver_preimage,

            // An expected UTXO is always assumed to refer to something we're
            // receiving, not to a successful PoW guess.
            is_guesser_fee: false,
        }
    }
}

impl IncomingUtxo {
    pub(crate) fn utxo_triple(&self) -> UtxoTriple {
        UtxoTriple {
            utxo: self.utxo.clone(),
            sender_randomness: self.sender_randomness,
            receiver_digest: self.receiver_preimage.hash(),
        }
    }
    pub(crate) fn addition_record(&self) -> AdditionRecord {
        self.utxo_triple().addition_record()
    }

    pub(crate) fn from_utxo_notification_payload(
        payload: UtxoNotificationPayload,
        receiver_preimage: Digest,
    ) -> Self {
        Self {
            utxo: payload.utxo,
            sender_randomness: payload.sender_randomness,
            receiver_preimage,
            is_guesser_fee: false,
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
#[cfg_attr(coverage_nightly, coverage(off))]
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
