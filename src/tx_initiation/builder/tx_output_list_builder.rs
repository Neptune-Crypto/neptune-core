//! provides a builder and related type(s) for generating [TxOutputList], ie a list of
//! transaction outputs ([TxOutput]).
//!
//! outputs may be specified in several ways via the [OutputFormat] enum.
use serde::Deserialize;
use serde::Serialize;

use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::state::wallet::address::ReceivingAddress;
use crate::models::state::wallet::transaction_output::TxOutput;
use crate::models::state::wallet::transaction_output::TxOutputList;
use crate::models::state::wallet::utxo_notification::UtxoNotificationMedium;
use crate::WalletState;

/// enumerates various ways to specify a transaction output.
#[derive(Debug, Serialize, Deserialize)]
pub enum OutputFormat {
    /// specify receiving address and amount
    AddressAndAmount(ReceivingAddress, NativeCurrencyAmount),

    /// specify receiving address, amount, and a utxo-notification-medium
    AddressAndAmountAndMedium(
        ReceivingAddress,
        NativeCurrencyAmount,
        UtxoNotificationMedium,
    ),

    /// specify utxo and receiving address
    AddressAndUtxo(ReceivingAddress, Utxo),

    /// specify utxo, receiving address, and a utxo-notification-medium
    AddressAndUtxoAndMedium(ReceivingAddress, Utxo, UtxoNotificationMedium),

    /// specify a [TxOutput]
    TxOutput(TxOutput),
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
    /// if not set, it defaults to [UtxoNotificationMedium::default()]
    pub fn owned_utxo_notification_medium(mut self, medium: UtxoNotificationMedium) -> Self {
        self.owned_utxo_notification_medium = medium;
        self
    }

    /// set a default utxo-notification-medium for unowned utxos (spending key not in wallet).
    ///
    /// this is applied for [OutputFormat] variants that do not specify a medium.
    ///
    /// if not set, it defaults to [UtxoNotificationMedium::default()]
    pub fn unowned_utxo_notification_medium(mut self, medium: UtxoNotificationMedium) -> Self {
        self.unowned_utxo_notification_medium = medium;
        self
    }

    /// add an output
    pub fn output_format(mut self, output_format: OutputFormat) -> Self {
        self.outputs.push(output_format);
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

    /// add an output, as [TxOutput]
    pub fn tx_output(mut self, tx_output: TxOutput) -> Self {
        self.outputs.push(OutputFormat::TxOutput(tx_output));
        self
    }

    /// build the list of [TxOutput]
    pub fn build(self, wallet_state: &WalletState, block_height: BlockHeight) -> TxOutputList {
        let wallet_entropy = &wallet_state.wallet_entropy;

        // Convert outputs.  [address:amount] --> TxOutputList
        let outputs = self.outputs.into_iter().map(|output_type| {
            match output_type {
                OutputFormat::TxOutput(o) => o,

                OutputFormat::AddressAndAmount(address, amt) => {
                    let sender_randomness = wallet_entropy
                        .generate_sender_randomness(block_height, address.privacy_digest());

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

                OutputFormat::AddressAndAmountAndMedium(address, amt, medium) => {
                    let sender_randomness = wallet_entropy
                        .generate_sender_randomness(block_height, address.privacy_digest());
                    let utxo = Utxo::new_native_currency(address.lock_script(), amt);
                    let owned = wallet_state.can_unlock(&utxo);

                    match medium {
                        UtxoNotificationMedium::OnChain => TxOutput::onchain_native_currency(
                            amt,
                            sender_randomness,
                            address,
                            owned,
                        ),
                        UtxoNotificationMedium::OffChain => TxOutput::offchain_native_currency(
                            amt,
                            sender_randomness,
                            address,
                            owned,
                        ),
                    }
                }

                OutputFormat::AddressAndUtxo(address, utxo) => {
                    let sender_randomness = wallet_entropy
                        .generate_sender_randomness(block_height, address.privacy_digest());

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
                    let sender_randomness = wallet_entropy
                        .generate_sender_randomness(block_height, address.privacy_digest());
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
