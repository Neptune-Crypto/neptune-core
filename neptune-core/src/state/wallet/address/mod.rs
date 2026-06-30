//! implements wallet keys and addresses.
//!
//! naming: it would make more sense for this module to be named 'key' or 'keys'
//! and it will probably be renamed in a future commit.
//!
//! (especially since we now have a key type with no corresponding address)
mod addressable_key;
pub mod announcement_flag;
mod common;
pub mod elliptic_curve_hybrid;
pub mod encrypted_utxo_notification;
pub mod generation_address;
mod receiving_address;
pub mod symmetric_key;
pub mod viewing_address;

pub use addressable_key::KeyType;
pub use addressable_key::SpendingKey;
pub use receiving_address::ReceivingAddress;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use proptest_arbitrary_interop::arb;
    use rand::random;
    use rand::Rng;
    use strum::IntoEnumIterator;
    use test_strategy::proptest;
    use tracing_test::traced_test;

    use super::*;
    use crate::protocol::consensus::network::Network;
    use crate::protocol::consensus::transaction::test_helpers::make_mock_transaction;
    use crate::protocol::consensus::transaction::utxo::Utxo;
    use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use crate::state::wallet::utxo_notification::UtxoNotificationPayload;
    use crate::state::Digest;

    #[proptest]
    fn scan_for_announceed_utxos(#[strategy(arb())] seed: Digest) {
        for key_type in KeyType::iter() {
            let key = SpendingKey::from_seed(seed, key_type);
            worker::scan_for_announced_utxos(key)
        }
    }

    /// tests encrypting and decrypting with all key types.
    #[proptest(cases = 10)]
    fn test_encrypt_decrypt(#[strategy(arb())] seed: Digest) {
        for key_type in KeyType::iter() {
            let key = SpendingKey::from_seed(seed, key_type);
            worker::test_encrypt_decrypt(key);
        }
    }

    /// tests keygen, sign, and verify with a symmetric key
    #[proptest(cases = 10)]
    fn test_keygen_sign_verify(#[strategy(arb())] seed: Digest) {
        for key_type in KeyType::iter() {
            let key = SpendingKey::from_seed(seed, key_type);
            worker::test_keypair_validity(key.clone(), key.to_address());
        }
    }

    #[proptest(cases = 10)]
    fn test_bech32m_conversion(#[strategy(arb())] seed: Digest) {
        for key_type in KeyType::iter() {
            let key = SpendingKey::from_seed(seed, key_type);
            worker::test_bech32m_conversion(key.to_address());
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn can_spend_from_address_type() {
        for key_type in KeyType::iter() {
            worker::can_spend_from_address_type(key_type).await;
        }
    }

    mod worker {
        use num_traits::CheckedSub;

        use super::*;
        use crate::api::export::ChangePolicy;
        use crate::api::export::InputSelectionPriority;
        use crate::api::export::OutputFormat;
        use crate::api::export::Timestamp;
        use crate::api::export::TxProvingCapability;
        use crate::api::export::WalletEntropy;
        use crate::api::tx_initiation::builder::input_selector::InputSelectionPolicy;
        use crate::api::tx_initiation::builder::input_selector::SortOrder;
        use crate::application::config::cli_args;
        use crate::protocol::consensus::block::Block;
        use crate::protocol::consensus::block::INITIAL_BLOCK_SUBSIDY;
        use crate::protocol::consensus::consensus_rule_set::tests::tx_with_n_outputs;
        use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
        use crate::protocol::consensus::transaction::utxo_triple::UtxoTriple;
        use crate::state::mempool::upgrade_priority::UpgradePriority;
        use crate::state::wallet::address::elliptic_curve_hybrid::EcHybridAddress;
        use crate::tests::shared::blocks::next_block;
        use crate::tests::shared::globalstate::mock_genesis_global_state;

        pub(super) async fn can_spend_from_address_type(key_type: KeyType) {
            let network = Network::Main;
            let cli = cli_args::Args {
                network,
                tx_proving_capability: Some(TxProvingCapability::SingleProof),
                ..Default::default()
            };

            let wallet = WalletEntropy::devnet_wallet();
            let genesis = Block::genesis(network);
            let mut state = mock_genesis_global_state(2, wallet, cli).await;

            let recipient_address = {
                let mut state = state.global_state_lock.lock_guard_mut().await;
                let recipient_key = state.wallet_state.next_unused_spending_key(key_type).await;
                recipient_key.to_address()
            };

            let timestamp = genesis.header().timestamp + Timestamp::months(9);
            let oldest_first = InputSelectionPolicy::default()
                .prioritize(InputSelectionPriority::ByAge(SortOrder::Descending));
            let tx = tx_with_n_outputs(
                state.clone(),
                2,
                timestamp,
                Some(oldest_first),
                Some(recipient_address),
                Some(NativeCurrencyAmount::coins(8)),
            )
            .await
            .unwrap();

            assert!(
                2 <= tx
                    .transaction
                    .kernel
                    .announcements
                    .iter()
                    .filter(|ann| KeyType::try_from(*ann).is_ok_and(|kt| kt == key_type))
                    .count(),
                "At least two of the announcements must be for key type {key_type}."
            );

            state
                .lock_guard_mut()
                .await
                .mempool_insert(tx.transaction().to_owned(), UpgradePriority::Critical)
                .await;

            let block1 = next_block(state.clone(), genesis.clone(), Some(timestamp)).await;
            let now = block1.header().timestamp;
            assert!(block1.is_valid(&genesis, now, network).await);

            let height1 = block1.header().height;
            state.set_new_tip(block1).await.unwrap();

            // Verify that balance is set correctly
            let new_liquid = state
                .lock_guard()
                .await
                .get_wallet_status_for_tip()
                .await
                .confirmed_available_balance(height1, now);
            println!("key_type: {key_type}");
            println!("new_liquid: {new_liquid}");
            let expected_liquid = NativeCurrencyAmount::coins(20)
                + INITIAL_BLOCK_SUBSIDY
                    .half()
                    .checked_sub(&tx.transaction().kernel.fee.half())
                    .unwrap();
            println!("expected_liquid: {expected_liquid}");
            assert_eq!(expected_liquid, new_liquid);

            // Verify that received funds can be spent, from the address type.
            // Make a big enough transaction that UTXOs received on this
            // address type must be used.
            let third_party_address = EcHybridAddress::from_seed(Digest::default());
            let to_third_party = vec![OutputFormat::AddressAndAmount(
                third_party_address.into(),
                NativeCurrencyAmount::coins(82),
            )];

            let fee = NativeCurrencyAmount::coins(1);
            let tx_from_address = state
                .api_mut()
                .tx_sender_mut()
                .send(to_third_party, ChangePolicy::Burn, fee, timestamp, false)
                .await
                .unwrap();

            assert!(
                tx_from_address
                    .is_valid(network, state.lock_guard().await.consensus_rule_set())
                    .await
            );
        }

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
            for network in [Network::Main, Network::Testnet(0)] {
                let encoded = receiving_address.to_bech32m(network).unwrap();

                let receiving_address_again =
                    ReceivingAddress::from_bech32m(&encoded, network).unwrap();

                assert_eq!(receiving_address, receiving_address_again);
            }
        }
    }
}
