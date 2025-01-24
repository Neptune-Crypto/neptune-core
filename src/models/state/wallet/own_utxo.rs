use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::state::ExpectedUtxo;
use crate::models::state::Tip5;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::commit;

use tasm_lib::prelude::Digest;

use super::announced_utxo::AnnouncedUtxo;

/// A [`Utxo`] along with associated data necessary for a recipient to claim it.
///
/// This struct does not store:
///  - Membership proofs -- the recipient must produce them on their own,
///    possibly by running and archival node.
///  - Unlock keys -- cryptographic data necessary for unlocking the UTXO.
///    (There is one exception to this rule: for guesser fee UTXOs, the unlock
///    key coincides with the receiver preimage.)
///
/// See [PublicAnnouncement], [ExpectedUtxo], [AnnouncedUtxo]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OwnUtxo {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
    pub receiver_preimage: Digest,
}

impl From<&ExpectedUtxo> for OwnUtxo {
    fn from(eu: &ExpectedUtxo) -> Self {
        Self {
            utxo: eu.utxo.clone(),
            sender_randomness: eu.sender_randomness,
            receiver_preimage: eu.receiver_preimage,
        }
    }
}

impl From<AnnouncedUtxo> for OwnUtxo {
    fn from(value: AnnouncedUtxo) -> Self {
        Self {
            utxo: value.utxo,
            sender_randomness: value.sender_randomness,
            receiver_preimage: value.receiver_preimage,
        }
    }
}

impl OwnUtxo {
    pub(crate) fn addition_record(&self) -> AdditionRecord {
        commit(
            Tip5::hash(&self.utxo),
            self.sender_randomness,
            self.receiver_preimage.hash(),
        )
    }
}
