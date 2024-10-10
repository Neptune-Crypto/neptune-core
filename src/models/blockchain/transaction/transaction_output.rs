//! provides an interface to transaction outputs and associated types

use std::ops::Deref;
use std::ops::DerefMut;

use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;

use super::PublicAnnouncement;
use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::state::wallet::address::ReceivingAddress;
use crate::models::state::wallet::wallet_state::WalletState;
use crate::prelude::twenty_first::math::digest::Digest;
use crate::prelude::twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::commit;

/// enumerates how utxos and spending information is communicated.
///
/// see also: [UtxoNotification]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum UtxoNotifyMethod {
    /// the utxo notification should be transferred to recipient encrypted on the blockchain
    OnChain,

    /// the utxo notification should be transferred to recipient off the blockchain
    OffChain,
}

/// The payload of a UTXO notification, containing all information necessary
/// to claim it, provided access to the associated spending key.
///
/// future work:
/// we should consider adding functionality that would facilitate passing
/// these payloads from sender to receiver off-chain for lower-fee transfers
/// between trusted parties or eg wallets owned by the same person/org.
#[derive(Debug, Clone)]
pub struct UtxoNotificationPayload {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
}

/// represents a transaction output, as accepted by
/// [GlobalState::create_transaction()](crate::models::state::GlobalState::create_transaction())
///
/// Contains data that a UTXO recipient requires in order to be notified about
/// and claim a given UTXO
#[derive(Debug, Clone)]
pub struct TxOutput {
    pub notification_payload: UtxoNotificationPayload,
    pub notification_method: UtxoNotifyMethod,
    pub receiving_address: ReceivingAddress,
}

impl From<&TxOutput> for AdditionRecord {
    /// retrieves public announcements from possible sub-set of the list
    fn from(txo: &TxOutput) -> Self {
        commit(
            Hash::hash(&txo.notification_payload.utxo),
            txo.notification_payload.sender_randomness,
            txo.receiving_address.privacy_digest(),
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
    /// If the [Utxo] can be claimed by our wallet, then parameter
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
        let onchain = || -> TxOutput {
            let utxo = Utxo::new_native_currency(address.lock_script(), amount);
            Self::onchain(utxo, sender_randomness, address.to_owned())
        };

        let offchain = || {
            let utxo = Utxo::new_native_currency(address.lock_script(), amount);
            Self::offchain(utxo, sender_randomness, address.to_owned())
        };

        let utxo = Utxo::new_native_currency(address.lock_script(), amount);
        let has_matching_spending_key = wallet_state.can_unlock(&utxo);

        let tx_output = if has_matching_spending_key {
            match owned_utxo_notify_method {
                UtxoNotifyMethod::OnChain => onchain(),
                UtxoNotifyMethod::OffChain => offchain(),
            }
        } else {
            onchain()
        };

        Ok(tx_output)
    }

    /// instantiates `TxOutput` using `OnChain` transfer method.
    ///
    /// For normal situations, auto() should be used instead.
    pub fn onchain(
        utxo: Utxo,
        sender_randomness: Digest,
        receiving_address: ReceivingAddress,
    ) -> Self {
        let payload = UtxoNotificationPayload {
            utxo,
            sender_randomness,
        };
        Self {
            notification_payload: payload,
            notification_method: UtxoNotifyMethod::OnChain,
            receiving_address,
        }
    }

    /// instantiates `TxOutput` using `OffChain` transfer method.
    ///
    /// For normal situations, auto() should be used instead.
    pub fn offchain(
        utxo: Utxo,
        sender_randomness: Digest,
        receiving_address: ReceivingAddress,
    ) -> Self {
        let payload = UtxoNotificationPayload {
            utxo,
            sender_randomness,
        };
        Self {
            notification_payload: payload,
            notification_method: UtxoNotifyMethod::OffChain,
            receiving_address,
        }
    }

    pub(crate) fn onchain_native_currency(
        amount: NeptuneCoins,
        sender_randomness: Digest,
        receiving_address: ReceivingAddress,
    ) -> Self {
        let utxo = Utxo::new_native_currency(receiving_address.lock_script(), amount);
        Self::onchain(utxo, sender_randomness, receiving_address)
    }

    pub(crate) fn offchain_native_currency(
        amount: NeptuneCoins,
        sender_randomness: Digest,
        receiving_address: ReceivingAddress,
    ) -> Self {
        let utxo = Utxo::new_native_currency(receiving_address.lock_script(), amount);
        Self::offchain(utxo, sender_randomness, receiving_address)
    }

    pub(crate) fn is_offchain(&self) -> bool {
        matches!(self.notification_method, UtxoNotifyMethod::OffChain)
    }

    pub(crate) fn utxo(&self) -> Utxo {
        self.notification_payload.utxo.clone()
    }

    pub(crate) fn sender_randomness(&self) -> Digest {
        self.notification_payload.sender_randomness
    }

    pub(crate) fn receiver_digest(&self) -> Digest {
        self.receiving_address.privacy_digest()
    }

    pub(crate) fn public_announcement(&self) -> Option<PublicAnnouncement> {
        match self.notification_method {
            UtxoNotifyMethod::OffChain => None,
            UtxoNotifyMethod::OnChain => Some(
                self.receiving_address
                    .generate_public_announcement(self.notification_payload.clone()),
            ),
        }
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

// Killed because: this mapping requires wallet info!
// impl From<&TxOutputList> for Vec<ExpectedUtxo> {
//     fn from(list: &TxOutputList) -> Self {
//         list.expected_utxos_iter().collect()
//     }
// }

// Killed because: this mapping requires recipient info!
// impl From<&TxOutputList> for Vec<PublicAnnouncement> {
//     fn from(list: &TxOutputList) -> Self {
//         list.public_announcements_iter().into_iter().collect()
//     }
// }

impl TxOutputList {
    /// calculates total amount in native currency
    pub fn total_native_coins(&self) -> NeptuneCoins {
        self.0
            .iter()
            .map(|u| u.notification_payload.utxo.get_native_currency_amount())
            .sum()
    }

    /// retrieves utxos
    pub fn utxos_iter(&self) -> impl IntoIterator<Item = Utxo> + '_ {
        self.0.iter().map(|u| u.notification_payload.utxo.clone())
    }

    /// retrieves utxos
    pub fn utxos(&self) -> Vec<Utxo> {
        self.utxos_iter().into_iter().collect()
    }

    pub(crate) fn sender_randomnesses(&self) -> Vec<Digest> {
        self.iter().map(|x| x.sender_randomness()).collect()
    }

    pub(crate) fn receiver_digests(&self) -> Vec<Digest> {
        self.iter().map(|x| x.receiver_digest()).collect()
    }

    /// retrieves addition_records
    pub fn addition_records_iter(&self) -> impl IntoIterator<Item = AdditionRecord> + '_ {
        self.0.iter().map(|u| u.into())
    }

    /// retrieves addition_records
    pub fn addition_records(&self) -> Vec<AdditionRecord> {
        self.addition_records_iter().into_iter().collect()
    }

    /// Returns all public announcement for this TxOutputList
    pub(crate) fn public_announcements(&self) -> Vec<PublicAnnouncement> {
        let mut public_announcements = vec![];
        for tx_output in self.0.iter() {
            if let Some(pa) = tx_output.public_announcement() {
                public_announcements.push(pa);
            }
        }

        public_announcements
    }

    /// retrieves expected_utxos from possible sub-set of the list
    // Killed because: going from `TxOutput` to `ExpectedUtxo` requires wallet
    // info.
    // pub fn expected_utxos_iter(&self) -> impl Iterator<Item = ExpectedUtxo> + '_ {
    //     self.0.iter().filter_map(|u| match &u.utxo_notification {
    //         UtxoNotification::OffChain(eu) => Some(*eu.clone()),
    //         _ => None,
    //     })
    // }

    /// retrieves expected_utxos from possible sub-set of the list
    // Killed because: see `expected_utxos_iter`
    // pub fn expected_utxos(&self) -> Vec<ExpectedUtxo> {
    //     self.expected_utxos_iter().collect()
    // }

    /// indicates if any offchain notifications exist
    pub fn has_offchain(&self) -> bool {
        self.0.iter().any(|u| u.is_offchain())
    }

    pub(crate) fn push(&mut self, tx_output: TxOutput) {
        self.0.push(tx_output);
    }

    pub(crate) fn concat_with<T>(mut self, maybe_tx_output: T) -> Self
    where
        T: IntoIterator<Item = TxOutput>,
    {
        self.0.extend(maybe_tx_output);
        self
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::*;
    use crate::config_models::network::Network;
    use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
    use crate::models::state::wallet::address::generation_address::GenerationReceivingAddress;
    use crate::models::state::wallet::address::KeyType;
    use crate::models::state::wallet::WalletSecret;
    use crate::tests::shared::mock_genesis_global_state;

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
        let utxo = Utxo::new_native_currency(address.lock_script(), amount);

        let sender_randomness = state
            .wallet_state
            .wallet_secret
            .generate_sender_randomness(block_height, address.privacy_digest);

        for utxo_notify_method in [UtxoNotifyMethod::OffChain, UtxoNotifyMethod::OnChain] {
            let tx_output = TxOutput::auto(
                &state.wallet_state,
                &address.into(),
                amount,
                sender_randomness,
                utxo_notify_method, // how to notify of owned utxos.
            )?;

            // we should have OnChain transfer regardless of owned_transfer_method setting
            // because it only applies to owned outputs.
            // assert!(matches!(
            //     tx_output.utxo_notification,
            //     ::OnChain(_)
            // ));
            assert_eq!(utxo_notify_method, tx_output.notification_method);
            assert_eq!(tx_output.sender_randomness(), sender_randomness);
            assert_eq!(tx_output.receiver_digest(), address.privacy_digest);
            assert_eq!(tx_output.utxo(), utxo);
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_utxoreceiver_auto_owned_output() -> Result<()> {
        let mut global_state_lock =
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
            let utxo = Utxo::new_native_currency(address.lock_script(), amount);
            let sender_randomness = state
                .wallet_state
                .wallet_secret
                .generate_sender_randomness(block_height, address.privacy_digest());

            let tx_output = TxOutput::auto(
                &state.wallet_state,
                &address,
                amount,
                sender_randomness,
                transfer_method, // how to notify of utxos sent to myself
            )?;

            assert_eq!(transfer_method, tx_output.notification_method);
            assert_eq!(
                sender_randomness,
                tx_output.notification_payload.sender_randomness
            );
            assert_eq!(
                address.lock_script().hash(),
                tx_output.utxo().lock_script_hash
            );

            println!("owned_transfer_method: {:#?}", transfer_method);
            println!("utxo_transfer: {:#?}", tx_output.notification_payload);

            assert_eq!(tx_output.sender_randomness(), sender_randomness);
            assert_eq!(tx_output.receiver_digest(), address.privacy_digest());
            assert_eq!(tx_output.utxo(), utxo);
        }

        Ok(())
    }
}
