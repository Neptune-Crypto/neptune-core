//! provides an interface to transaction outputs and associated types

use std::ops::Deref;
use std::ops::DerefMut;

use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;

use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::PublicAnnouncement;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::state::wallet::address::ReceivingAddress;
use crate::models::state::wallet::wallet_state::WalletState;
use crate::prelude::twenty_first::math::digest::Digest;
use crate::prelude::twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::commit;

/// Enumerates the medium of exchange for UTXO-notifications.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum UtxoNotificationMedium {
    /// The UTXO notification should be sent on-chain
    OnChain,

    /// The UTXO notification should be sent off-chain
    OffChain,
}

/// enumerates how utxos and spending information is communicated, including how
/// to encrypt this information.
///
/// see also: [UtxoNotification]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum UtxoNotifyMethod {
    /// the utxo notification should be transferred to recipient encrypted on the blockchain
    OnChain(ReceivingAddress),

    /// the utxo notification should be transferred to recipient off the blockchain
    OffChain(ReceivingAddress),

    /// No UTXO notification is intended
    None,
}

/// The payload of a UTXO notification, containing all information necessary
/// to claim it, provided access to the associated spending key.
///
/// future work:
/// we should consider adding functionality that would facilitate passing
/// these payloads from sender to receiver off-chain for lower-fee transfers
/// between trusted parties or eg wallets owned by the same person/org.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct UtxoNotificationPayload {
    pub(crate) utxo: Utxo,
    pub(crate) sender_randomness: Digest,
}

impl UtxoNotificationPayload {
    // TODO: Remove test flag when used in main code.
    #[cfg(test)]
    pub(crate) fn new(utxo: Utxo, sender_randomness: Digest) -> Self {
        Self {
            utxo,
            sender_randomness,
        }
    }
}

/// represents a transaction output, as accepted by
/// [GlobalState::create_transaction()](crate::models::state::GlobalState::create_transaction())
///
/// Contains data that a UTXO recipient requires in order to be notified about
/// and claim a given UTXO.
#[derive(Debug, Clone)]
pub struct TxOutput {
    utxo: Utxo,
    sender_randomness: Digest,
    receiver_digest: Digest,
    notification_method: UtxoNotifyMethod,
}

impl From<&TxOutput> for AdditionRecord {
    /// retrieves public announcements from possible sub-set of the list
    fn from(txo: &TxOutput) -> Self {
        commit(
            Hash::hash(&txo.utxo),
            txo.sender_randomness,
            txo.receiver_digest,
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
        address: ReceivingAddress,
        amount: NeptuneCoins,
        sender_randomness: Digest,
        owned_utxo_notify_medium: UtxoNotificationMedium,
    ) -> Self {
        let utxo = Utxo::new_native_currency(address.lock_script(), amount);

        let has_matching_spending_key = wallet_state.can_unlock(&utxo);

        let receiver_digest = address.privacy_digest();
        let notification_method = if has_matching_spending_key {
            match owned_utxo_notify_medium {
                UtxoNotificationMedium::OnChain => UtxoNotifyMethod::OnChain(address),
                UtxoNotificationMedium::OffChain => UtxoNotifyMethod::OffChain(address),
            }
        } else {
            UtxoNotifyMethod::OnChain(address)
        };

        Self {
            utxo,
            sender_randomness,
            receiver_digest,
            notification_method,
        }
    }

    /// Instantiaties [TxOutput] without any associated notification-info.
    ///
    /// Warning: If care is not taken, this is an easy way to lose funds.
    /// Don't use this constructor unless you have a good reason to.
    #[cfg(test)]
    pub(crate) fn no_notification(
        utxo: Utxo,
        sender_randomness: Digest,
        privacy_digest: Digest,
    ) -> Self {
        Self {
            utxo,
            sender_randomness,
            receiver_digest: privacy_digest,
            notification_method: UtxoNotifyMethod::None,
        }
    }

    /// Instantiate a [TxOutput] for native currency intended fro on-chain UTXO
    /// notification.
    pub(crate) fn onchain_native_currency(
        amount: NeptuneCoins,
        sender_randomness: Digest,
        receiving_address: ReceivingAddress,
    ) -> Self {
        let utxo = Utxo::new_native_currency(receiving_address.lock_script(), amount);
        Self {
            utxo,
            sender_randomness,
            receiver_digest: receiving_address.privacy_digest(),
            notification_method: UtxoNotifyMethod::OnChain(receiving_address),
        }
    }

    /// Instantiate a [TxOutput] for native currency intended for off-chain UTXO
    /// notification.
    pub(crate) fn offchain_native_currency(
        amount: NeptuneCoins,
        sender_randomness: Digest,
        receiving_address: ReceivingAddress,
    ) -> Self {
        let utxo = Utxo::new_native_currency(receiving_address.lock_script(), amount);
        Self {
            utxo,
            sender_randomness,
            receiver_digest: receiving_address.privacy_digest(),
            notification_method: UtxoNotifyMethod::OffChain(receiving_address),
        }
    }

    pub(crate) fn is_offchain(&self) -> bool {
        matches!(self.notification_method, UtxoNotifyMethod::OffChain(_))
    }

    pub(crate) fn utxo(&self) -> Utxo {
        self.utxo.clone()
    }

    pub(crate) fn sender_randomness(&self) -> Digest {
        self.sender_randomness
    }

    pub(crate) fn receiver_digest(&self) -> Digest {
        self.receiver_digest
    }

    pub(crate) fn public_announcement(&self) -> Option<PublicAnnouncement> {
        match &self.notification_method {
            UtxoNotifyMethod::None => None,
            UtxoNotifyMethod::OffChain(_) => None,
            UtxoNotifyMethod::OnChain(receiving_address) => {
                let notification_payload = UtxoNotificationPayload {
                    utxo: self.utxo(),
                    sender_randomness: self.sender_randomness(),
                };
                Some(receiving_address.generate_public_announcement(notification_payload))
            }
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

impl IntoIterator for TxOutputList {
    type Item = TxOutput;

    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
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

impl From<Option<TxOutput>> for TxOutputList {
    fn from(value: Option<TxOutput>) -> Self {
        value.into_iter().collect_vec().into()
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
    use crate::config_models::cli_args;
    use crate::config_models::network::Network;
    use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
    use crate::models::state::wallet::address::generation_address::GenerationReceivingAddress;
    use crate::models::state::wallet::address::KeyType;
    use crate::models::state::wallet::WalletSecret;
    use crate::tests::shared::mock_genesis_global_state;

    #[tokio::test]
    async fn test_utxoreceiver_auto_not_owned_output() {
        let global_state_lock = mock_genesis_global_state(
            Network::RegTest,
            2,
            WalletSecret::devnet_wallet(),
            cli_args::Args::default(),
        )
        .await;

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

        for owned_utxo_notification_medium in [
            UtxoNotificationMedium::OffChain,
            UtxoNotificationMedium::OnChain,
        ] {
            let tx_output = TxOutput::auto(
                &state.wallet_state,
                address.into(),
                amount,
                sender_randomness,
                owned_utxo_notification_medium, // how to notify utxos sent to myself.
            );

            assert!(
                matches!(tx_output.notification_method, UtxoNotifyMethod::OnChain(_)),
                "Not owned UTXOs are, currently, always transmitted on-chain"
            );
            assert_eq!(tx_output.sender_randomness(), sender_randomness);
            assert_eq!(tx_output.receiver_digest(), address.privacy_digest);
            assert_eq!(tx_output.utxo(), utxo);
        }
    }

    #[tokio::test]
    async fn test_utxoreceiver_auto_owned_output() {
        let mut global_state_lock = mock_genesis_global_state(
            Network::RegTest,
            2,
            WalletSecret::devnet_wallet(),
            cli_args::Args::default(),
        )
        .await;

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

        for (owned_utxo_notification_medium, address) in [
            (UtxoNotificationMedium::OffChain, address_gen.clone()),
            (UtxoNotificationMedium::OnChain, address_sym.clone()),
        ] {
            let utxo = Utxo::new_native_currency(address.lock_script(), amount);
            let sender_randomness = state
                .wallet_state
                .wallet_secret
                .generate_sender_randomness(block_height, address.privacy_digest());

            let tx_output = TxOutput::auto(
                &state.wallet_state,
                address.clone(),
                amount,
                sender_randomness,
                owned_utxo_notification_medium, // how to notify of utxos sent to myself
            );

            match owned_utxo_notification_medium {
                UtxoNotificationMedium::OnChain => assert!(matches!(
                    tx_output.notification_method,
                    UtxoNotifyMethod::OnChain(_)
                )),
                UtxoNotificationMedium::OffChain => assert!(matches!(
                    tx_output.notification_method,
                    UtxoNotifyMethod::OffChain(_)
                )),
            };

            assert_eq!(sender_randomness, tx_output.sender_randomness());
            assert_eq!(
                address.lock_script().hash(),
                tx_output.utxo().lock_script_hash
            );

            assert_eq!(tx_output.sender_randomness(), sender_randomness);
            assert_eq!(tx_output.receiver_digest(), address.privacy_digest());
            assert_eq!(tx_output.utxo(), utxo);
        }
    }
}
