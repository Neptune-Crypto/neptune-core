use anyhow::anyhow;
use anyhow::ensure;
use anyhow::Result;
use bech32::FromBase32;
use bech32::ToBase32;
use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::prelude::BFieldElement;

use crate::api::export::SpendingKey;
use crate::application::config::network::Network;
use crate::protocol::consensus::transaction::announcement::Announcement;
use crate::state::wallet::address::common::network_hrp_char;
use crate::state::wallet::utxo_notification::UtxoNotificationPayload;

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
#[derive(Clone, Debug, PartialEq, Eq, Hash, GetSize, Serialize, Deserialize, BFieldCodec)]
pub(crate) struct EncryptedUtxoNotification {
    /// Describes the type of encoding used here
    pub(crate) flag: BFieldElement,

    /// enables the receiver to find the matching `SpendingKey` in their wallet.
    pub(crate) receiver_identifier: BFieldElement,

    /// Encrypted UTXO notification payload.
    pub(crate) ciphertext: Vec<BFieldElement>,
}

#[derive(Debug, Copy, Clone, strum::Display)]
pub(crate) enum ConversionFromMessageError {
    // length must be at least 2
    MessageTooShort(usize),
}

impl EncryptedUtxoNotification {
    fn into_message(self) -> Vec<BFieldElement> {
        [vec![self.flag, self.receiver_identifier], self.ciphertext].concat()
    }

    fn from_message(message: Vec<BFieldElement>) -> Result<Self, ConversionFromMessageError> {
        if message.len() < 2 {
            Err(ConversionFromMessageError::MessageTooShort(message.len()))
        } else {
            Ok(Self {
                flag: message[0],
                receiver_identifier: message[1],
                ciphertext: message[2..].to_vec(),
            })
        }
    }

    /// Convert an encrypted UTXO notification to a announcement. Leaks
    /// privacy in the form of `receiver_identifier` is addresses are reused.
    /// Never leaks actual UTXO info such as amount transferred.
    pub(crate) fn into_announcement(self) -> Announcement {
        // We could use `BfieldCodec` encode here. But it might be a bit faster
        // to filter out irrelevant announcement if we don't have to
        // attempt a decoding to a specific data type first but can instead just
        // read out b-field elements and skip items based on that.
        Announcement::new(self.into_message())
    }

    pub(crate) fn into_bech32m(self, network: Network) -> String {
        let hrp = Self::get_hrp(network);
        let message = self.into_message();
        let payload = bincode::serialize(&message).unwrap_or_else(|e| {
            panic!("Serialization shouldn't fail. Message was: {message:?}\nerror: {e}")
        });
        let payload_base_32 = payload.to_base32();
        let variant = bech32::Variant::Bech32m;
        bech32::encode(&hrp, payload_base_32, variant).unwrap_or_else(|e| panic!(
            "bech32 encoding shouldn't fail. Arguments were:\n\n{hrp}\n\n{payload:?}\n\n{variant:?}\n\nerror: {e}"
        ))
    }

    /// decodes from a bech32m string and verifies it matches `network`
    pub(crate) fn from_bech32m(encoded: &str, network: Network) -> Result<Self> {
        let (hrp, data, variant) = bech32::decode(encoded)?;

        ensure!(
            variant == bech32::Variant::Bech32m,
            "Can only decode bech32m addresses."
        );
        ensure!(
            hrp == *Self::get_hrp(network),
            "Could not decode bech32m address because of invalid prefix",
        );

        let payload = Vec::<u8>::from_base32(&data)?;
        let message = bincode::deserialize(&payload)
            .map_err(|e| anyhow!("Could not decode bech32m because of error: {e}"))?;
        let encrypted_utxo_notification = Self::from_message(message)
            .map_err(|e| anyhow!("conversion from bech32m failed: {e}"))?;

        Ok(encrypted_utxo_notification)
    }

    /// returns human readable prefix (hrp) of a utxo-transfer-encrypted, specific to `network`
    pub(crate) fn get_hrp(network: Network) -> String {
        format!("utxo{}", network_hrp_char(network))
    }

    pub fn decrypt_with_spending_key(
        &self,
        spending_key: &SpendingKey,
    ) -> Result<UtxoNotificationPayload> {
        spending_key
            .decrypt(&self.ciphertext)
            .map(|(utxo, sender_randomness)| UtxoNotificationPayload::new(utxo, sender_randomness))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use arbitrary::Arbitrary;
    use arbitrary::Unstructured;
    use bech32::FromBase32;
    use bech32::ToBase32;
    use proptest::collection::vec;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::triton_vm::prelude::BFieldElement;
    use tasm_lib::twenty_first::bfe;
    use test_strategy::proptest;

    use super::EncryptedUtxoNotification;
    use crate::application::config::network::Network;

    impl<'a> Arbitrary<'a> for EncryptedUtxoNotification {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            let object = Self {
                flag: BFieldElement::arbitrary(u)?,
                receiver_identifier: BFieldElement::arbitrary(u)?,
                ciphertext: Vec::<BFieldElement>::arbitrary(u)?,
            };
            Ok(object)
        }
    }

    #[proptest]
    fn base32_encoding(#[strategy(vec(arb::<u8>(), 0..1000))] bytes: Vec<u8>) {
        let base32 = bytes.to_base32();
        let bytes_again = Vec::<u8>::from_base32(&base32).unwrap();
        prop_assert_eq!(bytes, bytes_again);
    }

    #[proptest]
    fn encrypted_utxo_notification_to_and_fro_bech32m(
        #[strategy(arb())] encrypted_utxo_notification: EncryptedUtxoNotification,
    ) {
        prop_assert!(bech32m_conversion_succeeds(encrypted_utxo_notification));
    }

    #[test]
    fn empty_encutxo_encoding() {
        let object = EncryptedUtxoNotification {
            flag: bfe!(0),
            receiver_identifier: bfe!(0),
            ciphertext: vec![],
        };
        assert!(bech32m_conversion_succeeds(object));
    }

    /// tests bech32m serialize, deserialize for [`EncryptedUtxoNotification`]
    pub fn bech32m_conversion_succeeds(
        encrypted_utxo_notification: EncryptedUtxoNotification,
    ) -> bool {
        let encoded = encrypted_utxo_notification
            .clone()
            .into_bech32m(Network::Testnet(0));

        let encrypted_utxo_notification_again =
            EncryptedUtxoNotification::from_bech32m(&encoded, Network::Testnet(0)).unwrap();

        encrypted_utxo_notification == encrypted_utxo_notification_again
    }
}
