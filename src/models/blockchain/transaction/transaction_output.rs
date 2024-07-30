//! provides an interface to transaction outputs and associated types

use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::PublicAnnouncement;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::state::wallet::address::ReceivingAddress;
use crate::models::state::wallet::address::SpendingKey;
use crate::models::state::wallet::utxo_notification_pool::ExpectedUtxo;
use crate::models::state::wallet::utxo_notification_pool::UtxoNotifier;
use crate::models::state::wallet::wallet_state::WalletState;
use crate::prelude::twenty_first::math::digest::Digest;
use crate::prelude::twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::commit;
use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;
use std::ops::Deref;
use std::ops::DerefMut;

/// enumerates how utxos should be transferred.
///
/// see also: [UtxoNotification]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum UtxoNotifyMethod {
    /// the utxo notification should be transferred to recipient encrypted on the blockchain
    OnChain,

    /// the utxo notification should be transferred to recipient off the blockchain
    OffChain,
}

/// enumerates utxo transfer methods with payloads
///
/// [PublicAnnouncement] is essentially opaque however one can determine the key
/// type via [`KeyType::try_from::<PublicAnnouncement>()`](crate::models::state::wallet::address::KeyType::try_from::<PublicAnnouncement>())
///
/// see also: [UtxoNotifyMethod], [KeyType](crate::models::state::wallet::address::KeyType)
///
/// future work:
///
/// we should consider adding this variant that would facilitate passing
/// utxo from sender to receiver off-chain for lower-fee transfers between
/// trusted parties or eg wallets owned by the same person/org.
///
/// OffChainSerialized(PublicAnnouncement)
///
/// also, perhaps PublicAnnouncement should be used for `OffChain`
/// and replace ExpectedUtxo.  to consolidate code/logic.
///
/// see comment for: [TxOutput::auto()]
///
#[derive(Debug, Clone)]
pub enum UtxoNotification {
    /// the utxo notification should be transferred to recipient on the blockchain as a [PublicAnnouncement]
    OnChain(PublicAnnouncement),

    /// the utxo notification should be transferred to recipient off the blockchain as an [ExpectedUtxo]
    OffChain(Box<ExpectedUtxo>),
}

/// represents a transaction output, as accepted by
/// [GlobalState::create_transaction()](crate::models::state::GlobalState::create_transaction())
///
/// Contains data that a UTXO recipient requires in order to be notified about
/// and claim a given UTXO
#[derive(Debug, Clone)]
pub struct TxOutput {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
    pub receiver_privacy_digest: Digest,
    pub utxo_notification: UtxoNotification,
}

impl From<ExpectedUtxo> for TxOutput {
    fn from(expected_utxo: ExpectedUtxo) -> Self {
        Self {
            utxo: expected_utxo.utxo.clone(),
            sender_randomness: expected_utxo.sender_randomness,
            receiver_privacy_digest: expected_utxo.receiver_preimage.hash::<Hash>(),
            utxo_notification: UtxoNotification::OffChain(Box::new(expected_utxo)),
        }
    }
}

impl From<&TxOutput> for AdditionRecord {
    /// retrieves public announcements from possible sub-set of the list
    fn from(ur: &TxOutput) -> Self {
        commit(
            Hash::hash(&ur.utxo),
            ur.sender_randomness,
            ur.receiver_privacy_digest,
        )
    }
}

impl TxOutput {
    /// automatically generates [TxOutput] using some heuristics
    ///
    /// If the [Utxo] cannot be claimed by our wallet then `OnChain` transfer
    /// will be used. A [PublicAnnouncement] will be created using whichever
    /// address type is provided.
    ///
    /// If the [Utxo] can be claimed by our wallet, then
    /// `owned_utxo_notify_method` dictates the behavior:
    ///
    /// * `OffChain` results in local state transfer via whichever address type is provided.
    /// * `OnChain` results in blockchain transfer via whichever address type is provided.
    ///
    /// design decision: we do not return any error if a pub-key is used for
    /// onchain notification of an owned utxo.
    ///
    /// rationale: this is not an intended use case, however:
    ///  1. this keeps the logic simple and straight-forward. most important.
    ///  2. we can't truly stop it, people could always modify the software.
    ///  3. neptune-core wallet(s) will not generate that condition.
    ///  4. users are incentivized not to do this as it uses more blockchain space
    ///     and thus they will have a higher fee.
    ///
    /// design decision: we do not return any error if a symmetric-key is used
    /// for sending outside this wallet.
    ///
    /// rationale: this is not an intended use case, however:
    ///  1. this keeps the logic simple and straight-forward. most important.
    ///  2. we can't truly stop it, people could always modify the software.
    ///  3. neptune-core wallet(s) will not generate that condition.
    ///  4. valid use-cases exist like sending between two wallets that
    ///     are owned by the same owner or family members. In this case
    ///     the user knows more than the software about what is "safe".
    ///  5. why make an API that limits power users?
    ///
    /// future work:
    ///
    /// accept param `unowned_utxo_notify_method` that would specify `OnChain`
    /// or `OffChain` behavior for un-owned utxos.  This would facilitate
    /// off-chain notifications and lower tx fees between wallets controlled by
    /// the same person/org, or even untrusted 3rd parties when receiver uses an
    /// optional resend-to-self feature when claiming.
    ///
    pub fn auto(
        wallet_state: &WalletState,
        address: &ReceivingAddress,
        amount: NeptuneCoins,
        sender_randomness: Digest,
        owned_utxo_notify_method: UtxoNotifyMethod,
    ) -> Result<Self> {
        let onchain = || -> Result<TxOutput> {
            let utxo = Utxo::new_native_coin(address.lock_script(), amount);
            let pub_ann = address.generate_public_announcement(&utxo, sender_randomness)?;
            Ok(Self::onchain(
                utxo,
                sender_randomness,
                address.privacy_digest(),
                pub_ann,
            ))
        };

        let offchain = |key: SpendingKey| {
            let utxo = Utxo::new_native_coin(address.lock_script(), amount);
            Self::offchain(utxo, sender_randomness, key.privacy_preimage())
        };

        let utxo = Utxo::new_native_coin(address.lock_script(), amount);
        let utxo_wallet_key = wallet_state.find_spending_key_for_utxo(&utxo);

        let tx_output = match utxo_wallet_key {
            None => onchain()?,
            Some(key) => match owned_utxo_notify_method {
                UtxoNotifyMethod::OnChain => onchain()?,
                UtxoNotifyMethod::OffChain => offchain(key),
            },
        };

        Ok(tx_output)
    }

    /// instantiates `TxOutput` using `OnChain` transfer method.
    ///
    /// For normal situations, auto() should be used instead.
    pub fn onchain(
        utxo: Utxo,
        sender_randomness: Digest,
        receiver_privacy_digest: Digest,
        public_announcement: PublicAnnouncement,
    ) -> Self {
        Self {
            utxo,
            sender_randomness,
            receiver_privacy_digest,
            utxo_notification: UtxoNotification::OnChain(public_announcement),
        }
    }

    /// instantiates `TxOutput` using `OffChain` transfer method.
    ///
    /// For normal situations, auto() should be used instead.
    pub fn offchain(
        utxo: Utxo,
        sender_randomness: Digest,
        receiver_privacy_preimage: Digest,
    ) -> Self {
        ExpectedUtxo::new(
            utxo,
            sender_randomness,
            receiver_privacy_preimage,
            UtxoNotifier::Myself,
        )
        .into()
    }

    // only for legacy tests
    #[cfg(test)]
    pub fn fake_address(
        utxo: Utxo,
        sender_randomness: Digest,
        receiver_privacy_digest: Digest,
    ) -> Self {
        use crate::models::state::wallet::address::generation_address::GenerationReceivingAddress;

        let address: ReceivingAddress =
            GenerationReceivingAddress::derive_from_seed(rand::random()).into();
        let announcement = address
            .generate_public_announcement(&utxo, sender_randomness)
            .unwrap();

        Self {
            utxo,
            sender_randomness,
            receiver_privacy_digest,
            utxo_notification: UtxoNotification::OnChain(announcement),
        }
    }

    // only for legacy tests
    #[cfg(test)]
    pub fn random(utxo: Utxo) -> Self {
        Self::fake_address(utxo, rand::random(), rand::random())
    }
}

/// Represents a list of [TxOutput]
#[derive(Debug, Clone, Default)]
pub struct TxOutputList(Vec<TxOutput>);

impl Deref for TxOutputList {
    type Target = Vec<TxOutput>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TxOutputList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<TxOutput>> for TxOutputList {
    fn from(v: Vec<TxOutput>) -> Self {
        Self(v)
    }
}

impl From<&TxOutputList> for Vec<AdditionRecord> {
    fn from(list: &TxOutputList) -> Self {
        list.addition_records_iter().into_iter().collect()
    }
}

impl From<&TxOutputList> for Vec<Utxo> {
    fn from(list: &TxOutputList) -> Self {
        list.utxos_iter().into_iter().collect()
    }
}

impl From<&TxOutputList> for Vec<ExpectedUtxo> {
    fn from(list: &TxOutputList) -> Self {
        list.expected_utxos_iter().into_iter().collect()
    }
}

impl From<&TxOutputList> for Vec<PublicAnnouncement> {
    fn from(list: &TxOutputList) -> Self {
        list.public_announcements_iter().into_iter().collect()
    }
}

impl TxOutputList {
    /// calculates total amount in native currency
    pub fn total_native_coins(&self) -> NeptuneCoins {
        self.0
            .iter()
            .map(|u| u.utxo.get_native_currency_amount())
            .sum()
    }

    /// retrieves utxos
    pub fn utxos_iter(&self) -> impl IntoIterator<Item = Utxo> + '_ {
        self.0.iter().map(|u| u.utxo.clone())
    }

    /// retrieves utxos
    pub fn utxos(&self) -> Vec<Utxo> {
        self.utxos_iter().into_iter().collect()
    }

    /// retrieves addition_records
    pub fn addition_records_iter(&self) -> impl IntoIterator<Item = AdditionRecord> + '_ {
        self.0.iter().map(|u| u.into())
    }

    /// retrieves addition_records
    pub fn addition_records(&self) -> Vec<AdditionRecord> {
        self.addition_records_iter().into_iter().collect()
    }

    /// retrieves public announcements from possible sub-set of the list
    pub fn public_announcements_iter(&self) -> impl IntoIterator<Item = PublicAnnouncement> + '_ {
        self.0.iter().filter_map(|u| match &u.utxo_notification {
            UtxoNotification::OnChain(pa) => Some(pa.clone()),
            _ => None,
        })
    }

    /// retrieves public announcements from possible sub-set of the list
    pub fn public_announcements(&self) -> Vec<PublicAnnouncement> {
        self.public_announcements_iter().into_iter().collect()
    }

    /// retrieves expected_utxos from possible sub-set of the list
    pub fn expected_utxos_iter(&self) -> impl IntoIterator<Item = ExpectedUtxo> + '_ {
        self.0.iter().filter_map(|u| match &u.utxo_notification {
            UtxoNotification::OffChain(eu) => Some(*eu.clone()),
            _ => None,
        })
    }

    /// indicates if any offchain notifications (ExpectedUtxo) exist
    pub fn has_offchain(&self) -> bool {
        self.0
            .iter()
            .any(|u| matches!(&u.utxo_notification, UtxoNotification::OffChain(_)))
    }

    /// retrieves expected_utxos from possible sub-set of the list
    pub fn expected_utxos(&self) -> Vec<ExpectedUtxo> {
        self.expected_utxos_iter().into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_models::network::Network;
    use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
    use crate::models::state::wallet::address::generation_address::GenerationReceivingAddress;
    use crate::models::state::wallet::address::KeyType;
    use crate::models::state::wallet::WalletSecret;
    use crate::tests::shared::mock_genesis_global_state;
    use rand::Rng;

    #[tokio::test]
    async fn test_utxoreceiver_auto_not_owned_output() -> Result<()> {
        let global_state_lock =
            mock_genesis_global_state(Network::RegTest, 2, WalletSecret::devnet_wallet()).await;

        let state = global_state_lock.lock_guard().await;
        let block_height = state.chain.light_state().header().height;

        // generate a new receiving address that is not from our wallet.
        let mut rng = rand::thread_rng();
        let seed: Digest = rng.gen();
        let address = GenerationReceivingAddress::derive_from_seed(seed);

        let amount = NeptuneCoins::one();
        let utxo = Utxo::new_native_coin(address.lock_script(), amount);

        let sender_randomness = state
            .wallet_state
            .wallet_secret
            .generate_sender_randomness(block_height, address.privacy_digest);

        for utxo_notify_method in [UtxoNotifyMethod::OffChain, UtxoNotifyMethod::OnChain] {
            let utxo_receiver = TxOutput::auto(
                &state.wallet_state,
                &address.into(),
                amount,
                sender_randomness,
                utxo_notify_method, // how to notify of owned utxos.
            )?;

            // we should have OnChain transfer regardless of owned_transfer_method setting
            // because it only applies to owned outputs.
            assert!(matches!(
                utxo_receiver.utxo_notification,
                UtxoNotification::OnChain(_)
            ));
            assert_eq!(utxo_receiver.sender_randomness, sender_randomness);
            assert_eq!(
                utxo_receiver.receiver_privacy_digest,
                address.privacy_digest
            );
            assert_eq!(utxo_receiver.utxo, utxo);
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_utxoreceiver_auto_owned_output() -> Result<()> {
        let global_state_lock =
            mock_genesis_global_state(Network::RegTest, 2, WalletSecret::devnet_wallet()).await;

        // obtain next unused receiving address from our wallet.
        let spending_key_gen = global_state_lock
            .lock_guard_mut()
            .await
            .wallet_state
            .next_unused_spending_key(KeyType::Generation);
        let address_gen = spending_key_gen.to_address();

        // obtain next unused symmetric address from our wallet.
        let spending_key_sym = global_state_lock
            .lock_guard_mut()
            .await
            .wallet_state
            .next_unused_spending_key(KeyType::Symmetric);
        let address_sym = spending_key_sym.to_address();

        let state = global_state_lock.lock_guard().await;
        let block_height = state.chain.light_state().header().height;

        let amount = NeptuneCoins::one();

        for (transfer_method, address) in [
            (UtxoNotifyMethod::OffChain, address_gen.clone()),
            (UtxoNotifyMethod::OnChain, address_sym.clone()),
        ] {
            let utxo = Utxo::new_native_coin(address.lock_script(), amount);
            let sender_randomness = state
                .wallet_state
                .wallet_secret
                .generate_sender_randomness(block_height, address.privacy_digest());

            let utxo_receiver = TxOutput::auto(
                &state.wallet_state,
                &address,
                amount,
                sender_randomness,
                transfer_method, // how to notify of owned utxos.
            )?;

            let transfer_is_correct = match utxo_receiver.utxo_notification {
                UtxoNotification::OffChain(_) => {
                    matches!(transfer_method, UtxoNotifyMethod::OffChain)
                }
                UtxoNotification::OnChain(ref pa) => match transfer_method {
                    UtxoNotifyMethod::OnChain => address.matches_public_announcement_key_type(pa),
                    _ => false,
                },
            };

            println!("owned_transfer_method: {:#?}", transfer_method);
            println!("utxo_transfer: {:#?}", utxo_receiver.utxo_notification);

            assert!(transfer_is_correct);
            assert_eq!(utxo_receiver.sender_randomness, sender_randomness);
            assert_eq!(
                utxo_receiver.receiver_privacy_digest,
                address.privacy_digest()
            );
            assert_eq!(utxo_receiver.utxo, utxo);
        }

        Ok(())
    }
}
