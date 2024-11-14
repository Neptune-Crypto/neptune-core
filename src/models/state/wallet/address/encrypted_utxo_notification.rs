use get_size::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::BFieldElement;

/// an encrypted wrapper for UTXO notifications.
///
/// This type is intended to be serialized and actually transferred between
/// parties.
///
/// note: bech32m encoding of this type is considered standard and is
/// recommended over serde serialization.
///
/// the receiver_identifier enables the receiver to find the matching
/// `SpendingKey` in their wallet.
#[derive(Clone, Debug, PartialEq, Eq, Hash, GetSize, Serialize, Deserialize)]
pub(crate) struct EncryptedNotification {
    /// Encrypted UTXO notification.
    pub ciphertext: Vec<BFieldElement>,

    /// enables the receiver to find the matching `SpendingKey` in their wallet.
    pub receiver_identifier: BFieldElement,
}
