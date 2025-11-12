//! implements wallet keys and addresses.
//!
//! naming: it would make more sense for this module to be named 'key' or 'keys'
//! and it will probably be renamed in a future commit.
//!
//! (especially since we now have a key type with no corresponding address)
mod addressable_key;
mod common;
pub mod encrypted_utxo_notification;
pub mod generation_address;
mod receiving_address;
pub mod symmetric_key;

pub use addressable_key::KeyType;
pub use addressable_key::SpendingKey;
pub use receiving_address::ReceivingAddress;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use generation_address::GenerationReceivingAddress;
    use generation_address::GenerationSpendingKey;
    use proptest_arbitrary_interop::arb;
    use rand::random;
    use rand::Rng;
    use symmetric_key::SymmetricKey;
    use test_strategy::proptest;

    use super::*;
    use crate::application::config::network::Network;
    use crate::protocol::consensus::transaction::utxo::Utxo;
    use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use crate::state::wallet::utxo_notification::UtxoNotificationPayload;
    use crate::state::Digest;
    use crate::tests::shared::mock_tx::make_mock_transaction;

    /// tests scanning for announced utxos with a symmetric key
    #[proptest]
    fn scan_for_announced_utxos_symmetric(#[strategy(arb())] seed: Digest) {
        worker::scan_for_announced_utxos(SymmetricKey::from_seed(seed).into())
    }

    /// tests scanning for announced utxos with an asymmetric (generation) key
    #[proptest]
    fn scan_for_announced_utxos_generation(#[strategy(arb())] seed: Digest) {
        worker::scan_for_announced_utxos(GenerationSpendingKey::derive_from_seed(seed).into())
    }

    /// tests encrypting and decrypting with a symmetric key
    #[proptest]
    fn test_encrypt_decrypt_symmetric(#[strategy(arb())] seed: Digest) {
        worker::test_encrypt_decrypt(SymmetricKey::from_seed(seed).into())
    }

    /// tests encrypting and decrypting with an asymmetric (generation) key
    #[proptest]
    fn test_encrypt_decrypt_generation(#[strategy(arb())] seed: Digest) {
        worker::test_encrypt_decrypt(GenerationSpendingKey::derive_from_seed(seed).into())
    }

    /// tests keygen, sign, and verify with a symmetric key
    #[proptest]
    fn test_keygen_sign_verify_symmetric(#[strategy(arb())] seed: Digest) {
        worker::test_keypair_validity(
            SymmetricKey::from_seed(seed).into(),
            SymmetricKey::from_seed(seed).into(),
        );
    }

    /// tests keygen, sign, and verify with an asymmetric (generation) key
    #[proptest]
    fn test_keygen_sign_verify_generation(#[strategy(arb())] seed: Digest) {
        worker::test_keypair_validity(
            GenerationSpendingKey::derive_from_seed(seed).into(),
            GenerationReceivingAddress::derive_from_seed(seed).into(),
        );
    }

    /// tests bech32m serialize, deserialize with a symmetric key
    #[proptest]
    fn test_bech32m_conversion_symmetric(#[strategy(arb())] seed: Digest) {
        worker::test_bech32m_conversion(SymmetricKey::from_seed(seed).into());
    }

    /// tests bech32m serialize, deserialize with an asymmetric (generation) key
    #[proptest]
    fn test_bech32m_conversion_generation(#[strategy(arb())] seed: Digest) {
        worker::test_bech32m_conversion(GenerationReceivingAddress::derive_from_seed(seed).into());
    }

    mod worker {
        use super::*;
        use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
        use crate::protocol::consensus::transaction::utxo_triple::UtxoTriple;

        /// this tests the generate_announcement() and
        /// scan_for_announced_utxos() methods with a [SpendingKey]
        ///
        /// a Announcement is created with generate_announcement() and
        /// added to a Tx.  It is then found by scanning for announced_utoxs.  Then
        /// we verify that the data matches the original/expected values.
        pub fn scan_for_announced_utxos(key: SpendingKey) {
            // 1. generate a utxo with amount = 10
            let utxo = Utxo::new_native_currency(
                key.to_address().lock_script_hash(),
                NativeCurrencyAmount::coins(10),
            );

            // 2. generate sender randomness
            let sender_randomness: Digest = random();

            // 3. create an addition record to verify against later.
            let utxo_triple = UtxoTriple {
                utxo: utxo.clone(),
                sender_randomness,
                receiver_digest: key.to_address().privacy_digest(),
            };
            let expected_addition_record = utxo_triple.addition_record();

            // 4. create a mock tx with no inputs or outputs
            let mut mock_tx = make_mock_transaction(vec![], vec![]);

            // 5. verify that no announced utxos exist for this key
            assert!(key.scan_for_announced_utxos(&mock_tx.kernel).is_empty());

            // 6. generate a announcement for this address
            let utxo_notification_payload =
                UtxoNotificationPayload::new(utxo.clone(), sender_randomness);
            let announcement = key
                .to_address()
                .generate_announcement(utxo_notification_payload);

            // 7. verify that the announcement is marked as our key type.
            assert!(key.matches_announcement_key_type(&announcement));

            // 8. add the announcement to the mock tx.
            let mut new_announcements = mock_tx.kernel.announcements.clone();
            new_announcements.push(announcement);

            mock_tx.kernel = TransactionKernelModifier::default()
                .announcements(new_announcements)
                .modify(mock_tx.kernel);

            // 9. scan tx announcements for announced utxos
            let announced_utxos = key.scan_for_announced_utxos(&mock_tx.kernel);

            // 10. verify there is exactly 1 announced_utxo and obtain it.
            assert_eq!(1, announced_utxos.len());
            let announced_utxo = announced_utxos.into_iter().next().unwrap();

            // 11. verify each field of the announced_utxo matches original values.
            assert_eq!(utxo, announced_utxo.utxo);
            assert_eq!(expected_addition_record, announced_utxo.addition_record());
            assert_eq!(sender_randomness, announced_utxo.sender_randomness);
            assert_eq!(key.privacy_preimage(), announced_utxo.receiver_preimage);
        }

        /// This tests encrypting and decrypting with a [SpendingKey]
        pub fn test_encrypt_decrypt(key: SpendingKey) {
            let mut rng = rand::rng();

            // 1. create utxo with random amount
            let amount = NativeCurrencyAmount::coins(rng.random_range(0..42000000));
            let utxo = Utxo::new_native_currency(key.to_address().lock_script_hash(), amount);

            // 2. generate sender randomness
            let sender_randomness: Digest = random();

            // 3. encrypt secrets (utxo, sender_randomness)
            let notification_payload =
                UtxoNotificationPayload::new(utxo.clone(), sender_randomness);
            let ciphertext = key.to_address().encrypt(&notification_payload);
            println!("ciphertext.get_size() = {}", ciphertext.len() * 8);

            // 4. decrypt secrets
            let (utxo_again, sender_randomness_again) = key.decrypt(&ciphertext).unwrap();

            // 5. verify that decrypted secrets match original secrets
            assert_eq!(utxo, utxo_again);
            assert_eq!(sender_randomness, sender_randomness_again);
        }

        /// tests key generation, signing, and decrypting with a [SpendingKey]
        ///
        /// note: key generation is performed by the caller. Both the
        /// spending_key and receiving_address must be independently derived from
        /// the same seed.
        pub fn test_keypair_validity(
            spending_key: SpendingKey,
            receiving_address: ReceivingAddress,
        ) {
            // 1. prepare a (random) message and witness data.
            let msg: Digest = random();
            let l_and_s = spending_key.lock_script_and_witness();

            // 2. perform proof verification
            assert!(l_and_s.halts_gracefully(msg.values().to_vec().into()));

            // 3. convert spending key to an address.
            let receiving_address_again = spending_key.to_address();

            // 4. verify that both address match.
            assert_eq!(receiving_address, receiving_address_again);
        }

        /// tests bech32m serialize, deserialize for [ReceivingAddress]
        pub fn test_bech32m_conversion(receiving_address: ReceivingAddress) {
            // 1. serialize address to bech32m
            let encoded = receiving_address.to_bech32m(Network::Testnet(0)).unwrap();

            // 2. deserialize bech32m back into an address
            let receiving_address_again =
                ReceivingAddress::from_bech32m(&encoded, Network::Testnet(0)).unwrap();

            // 3. verify both addresses match
            assert_eq!(receiving_address, receiving_address_again);
        }
    }
}
