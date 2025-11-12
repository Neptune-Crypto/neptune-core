//! provides a builder and related type(s) for generating [TxOutputList], ie a list of
//! transaction outputs ([TxOutput]).
//!
//! outputs may be specified in several ways via the [OutputFormat] enum.
//!
//! see [builder](super) for examples of using the builders together.
use serde::Deserialize;
use serde::Serialize;

use crate::api::export::Timestamp;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::state::wallet::address::ReceivingAddress;
use crate::state::wallet::transaction_output::TxOutput;
use crate::state::wallet::transaction_output::TxOutputList;
use crate::state::wallet::utxo_notification::UtxoNotificationMedium;
use crate::state::StateLock;
use crate::WalletState;

// ##multicoin## :
//  1. The *AndUtxo variants enable basic multi-coin support.
//  2. maybe there should be some variant like AddressAndCoinAndAmount(ReceivingAddress, Coin, CoinAmount)
//     but this requires a new amount type.

/// enumerates various ways to specify a transaction output as a simple tuple.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    /// specify receiving address and amount
    AddressAndAmount(ReceivingAddress, NativeCurrencyAmount),

    /// specify receiving address, amount, and a utxo-notification-medium
    AddressAndAmountAndMedium(
        ReceivingAddress,
        NativeCurrencyAmount,
        UtxoNotificationMedium,
    ),

    /// specify a receiving address, amount, and a release date for time-locking
    /// the output
    AddressAndAmountAndReleaseDate(ReceivingAddress, NativeCurrencyAmount, Timestamp),

    /// specify utxo and receiving address
    AddressAndUtxo(ReceivingAddress, Utxo),

    /// specify utxo, receiving address, and a utxo-notification-medium
    AddressAndUtxoAndMedium(ReceivingAddress, Utxo, UtxoNotificationMedium),
}

impl OutputFormat {
    /// returns the native currency amount
    pub fn native_currency_amount(&self) -> NativeCurrencyAmount {
        match self {
            Self::AddressAndAmount(_, amt) => *amt,
            Self::AddressAndAmountAndMedium(_, amt, _) => *amt,
            Self::AddressAndAmountAndReleaseDate(_, amt, _) => *amt,
            Self::AddressAndUtxo(_, u) => u.get_native_currency_amount(),
            Self::AddressAndUtxoAndMedium(_, u, _) => u.get_native_currency_amount(),
        }
    }

    // ##multicoin## : maybe something like
    // pub fn amount(&self, coint: Coin) -> CoinAmount;

    pub fn address(&self) -> &ReceivingAddress {
        match self {
            OutputFormat::AddressAndAmount(ra, _) => ra,
            OutputFormat::AddressAndAmountAndMedium(ra, _, _) => ra,
            OutputFormat::AddressAndAmountAndReleaseDate(ra, _, _) => ra,
            OutputFormat::AddressAndUtxo(ra, _) => ra,
            OutputFormat::AddressAndUtxoAndMedium(ra, _, _) => ra,
        }
    }
}

impl From<(ReceivingAddress, NativeCurrencyAmount)> for OutputFormat {
    fn from(v: (ReceivingAddress, NativeCurrencyAmount)) -> Self {
        Self::AddressAndAmount(v.0, v.1)
    }
}

impl
    From<(
        ReceivingAddress,
        NativeCurrencyAmount,
        UtxoNotificationMedium,
    )> for OutputFormat
{
    fn from(
        v: (
            ReceivingAddress,
            NativeCurrencyAmount,
            UtxoNotificationMedium,
        ),
    ) -> Self {
        Self::AddressAndAmountAndMedium(v.0, v.1, v.2)
    }
}

impl From<(ReceivingAddress, Utxo)> for OutputFormat {
    fn from(v: (ReceivingAddress, Utxo)) -> Self {
        Self::AddressAndUtxo(v.0, v.1)
    }
}

impl From<(ReceivingAddress, Utxo, UtxoNotificationMedium)> for OutputFormat {
    fn from(v: (ReceivingAddress, Utxo, UtxoNotificationMedium)) -> Self {
        Self::AddressAndUtxoAndMedium(v.0, v.1, v.2)
    }
}

/// a builder for generating a list of transaction outputs.
#[derive(Debug)]
pub struct TxOutputListBuilder {
    // note: all fields intentionally private
    outputs: Vec<OutputFormat>,
    owned_utxo_notification_medium: UtxoNotificationMedium,
    unowned_utxo_notification_medium: UtxoNotificationMedium,
}

impl Default for TxOutputListBuilder {
    fn default() -> Self {
        Self {
            outputs: vec![],
            owned_utxo_notification_medium: UtxoNotificationMedium::OffChain,
            unowned_utxo_notification_medium: UtxoNotificationMedium::OnChain,
        }
    }
}

impl TxOutputListBuilder {
    /// instantiate builder
    pub fn new() -> Self {
        Default::default()
    }

    /// set a default utxo-notification-medium for owned utxos. (spending key exists in wallet)
    ///
    /// this is applied for [OutputFormat] variants that do not specify a medium.
    ///
    /// if not set, it defaults to [UtxoNotificationMedium::OffChain]
    pub fn owned_utxo_notification_medium(mut self, medium: UtxoNotificationMedium) -> Self {
        self.owned_utxo_notification_medium = medium;
        self
    }

    /// set a default utxo-notification-medium for unowned utxos (spending key not in wallet).
    ///
    /// this is applied for [OutputFormat] variants that do not specify a medium.
    ///
    /// if not set, it defaults to [UtxoNotificationMedium::OnChain]
    pub fn unowned_utxo_notification_medium(mut self, medium: UtxoNotificationMedium) -> Self {
        self.unowned_utxo_notification_medium = medium;
        self
    }

    /// add an output
    pub fn output(mut self, output: impl Into<OutputFormat>) -> Self {
        self.outputs.push(output.into());
        self
    }

    /// add a list of outputs
    pub fn outputs(mut self, outputs: impl IntoIterator<Item = impl Into<OutputFormat>>) -> Self {
        for output in outputs {
            self.outputs.push(output.into())
        }
        self
    }

    /// add an output, as receiving address and amount
    pub fn address_and_amount(
        mut self,
        address: ReceivingAddress,
        amount: NativeCurrencyAmount,
    ) -> Self {
        self.outputs
            .push(OutputFormat::AddressAndAmount(address, amount));
        self
    }

    /// add an output, as receiving address and amount and notification medium
    pub fn address_and_amount_and_medium(
        mut self,
        address: ReceivingAddress,
        amount: NativeCurrencyAmount,
        medium: UtxoNotificationMedium,
    ) -> Self {
        self.outputs.push(OutputFormat::AddressAndAmountAndMedium(
            address, amount, medium,
        ));
        self
    }

    /// add an output, as receiving address and utxo
    pub fn address_and_utxo(mut self, address: ReceivingAddress, utxo: Utxo) -> Self {
        self.outputs
            .push(OutputFormat::AddressAndUtxo(address, utxo));
        self
    }

    /// add an output, as receiving address and utxo and notification medium
    pub fn address_and_utxo_and_medium(
        mut self,
        address: ReceivingAddress,
        utxo: Utxo,
        medium: UtxoNotificationMedium,
    ) -> Self {
        self.outputs
            .push(OutputFormat::AddressAndUtxoAndMedium(address, utxo, medium));
        self
    }

    /// build the list of [TxOutput], with [StateLock]
    ///
    /// note: if you already acquired a read-lock or write-lock over
    /// [GlobalState](crate::state::GlobalState) you should provide a
    /// ReadGuard or WriteGuard.  The builder will use the already-acquired
    /// lock, which can still be used afterwards.
    pub async fn build(self, state_lock: &StateLock<'_>) -> TxOutputList {
        match state_lock {
            StateLock::Lock(gsl) => {
                let gs = gsl.lock_guard().await;
                self.build_worker(&gs.wallet_state, gs.chain.light_state().header().height)
            }
            StateLock::ReadGuard(gs) => {
                self.build_worker(&gs.wallet_state, gs.chain.light_state().header().height)
            }
            StateLock::WriteGuard(gs) => {
                self.build_worker(&gs.wallet_state, gs.chain.light_state().header().height)
            }
        }
    }

    /// build the list of [TxOutput]
    fn build_worker(self, wallet_state: &WalletState, block_height: BlockHeight) -> TxOutputList {
        let wallet_entropy = &wallet_state.wallet_entropy;

        // Convert outputs.  [address:amount] --> TxOutputList
        let outputs = self.outputs.into_iter().map(|output_type| {
            let sender_randomness = wallet_entropy
                .generate_sender_randomness(block_height, output_type.address().privacy_digest());

            match output_type {
                OutputFormat::AddressAndAmount(address, amt) => {
                    // The UtxoNotifyMethod (Onchain or Offchain) is auto-detected
                    // based on whether the address belongs to our wallet or not
                    TxOutput::auto(
                        wallet_state,
                        address,
                        amt,
                        sender_randomness,
                        self.owned_utxo_notification_medium,
                        self.unowned_utxo_notification_medium,
                    )
                }

                OutputFormat::AddressAndAmountAndReleaseDate(address, amt, release_date) => {
                    // The UtxoNotifyMethod (Onchain or Offchain) is auto-detected
                    // based on whether the address belongs to our wallet or not
                    TxOutput::auto(
                        wallet_state,
                        address,
                        amt,
                        sender_randomness,
                        self.owned_utxo_notification_medium,
                        self.unowned_utxo_notification_medium,
                    )
                    .with_time_lock(release_date)
                }

                OutputFormat::AddressAndAmountAndMedium(address, amt, medium) => {
                    let utxo = Utxo::new_native_currency(address.lock_script_hash(), amt);
                    let owned = wallet_state.can_unlock(&utxo);

                    TxOutput::native_currency(amt, sender_randomness, address, medium, owned)
                }

                OutputFormat::AddressAndUtxo(address, utxo) => {
                    // The UtxoNotifyMethod (Onchain or Offchain) is auto-detected
                    // based on whether the address belongs to our wallet or not
                    TxOutput::auto_utxo(
                        wallet_state,
                        utxo,
                        address,
                        sender_randomness,
                        self.owned_utxo_notification_medium,
                        self.unowned_utxo_notification_medium,
                    )
                }

                OutputFormat::AddressAndUtxoAndMedium(address, utxo, medium) => {
                    let owned = wallet_state.can_unlock(&utxo);

                    match medium {
                        UtxoNotificationMedium::OnChain => {
                            TxOutput::onchain_utxo(utxo, sender_randomness, address, owned)
                        }
                        UtxoNotificationMedium::OffChain => {
                            TxOutput::offchain_utxo(utxo, sender_randomness, address, owned)
                        }
                    }
                }
            }
        });

        outputs.into()
    }
}
