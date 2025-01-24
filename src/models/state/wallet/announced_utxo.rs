use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::state::ExpectedUtxo;
use crate::models::state::Tip5;
use crate::models::state::UtxoNotifier;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::commit;

use tasm_lib::prelude::Digest;

/// A [`Utxo`] along with associated data necessary for a recipient to claim it.
///
/// This struct does not store:
///  - Membership proofs -- the recipient must produce them on their own,
///    possibly by running and archival node.
///
/// `AnnouncedUtxo`s are built from one of:
///   onchain symmetric-key public announcements
///   onchain asymmetric-key public announcements
///   offchain expected-utxos
///
/// See also [`PublicAnnouncement`], [`ExpectedUtxo`],
/// [`OwnUtxo`](super::own_utxo::OwnUtxo).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AnnouncedUtxo {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
    pub receiver_preimage: Digest,
    pub hash_lock_key: Option<Digest>,
}

impl AnnouncedUtxo {
    pub(crate) fn addition_record(&self) -> AdditionRecord {
        commit(
            Tip5::hash(&self.utxo),
            self.sender_randomness,
            self.receiver_preimage.hash(),
        )
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
