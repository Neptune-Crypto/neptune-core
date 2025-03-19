use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::state::wallet::address::ReceivingAddress;
use crate::models::state::wallet::transaction_output::TxOutput;
use crate::models::state::wallet::transaction_output::TxOutputList;
use crate::models::state::wallet::utxo_notification::UtxoNotificationMedium;
use crate::WalletState;

#[derive(Debug)]
enum OutputType {
    AddressAndAmount(ReceivingAddress, NativeCurrencyAmount),
    AddressAndAmountAndMedium(
        ReceivingAddress,
        NativeCurrencyAmount,
        UtxoNotificationMedium,
    ),
    AddressAndUtxo(ReceivingAddress, Utxo),
    AddressAndUtxoAndMedium(ReceivingAddress, Utxo, UtxoNotificationMedium),
    TxOutput(TxOutput),
}

// note: all fields intentionally private
#[derive(Debug)]
pub struct TxOutputListBuilder {
    outputs: Vec<OutputType>,
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
    pub fn new() -> Self {
        Default::default()
    }

    pub fn owned_utxo_notification_medium(mut self, medium: UtxoNotificationMedium) -> Self {
        self.owned_utxo_notification_medium = medium;
        self
    }

    pub fn unowned_utxo_notification_medium(mut self, medium: UtxoNotificationMedium) -> Self {
        self.unowned_utxo_notification_medium = medium;
        self
    }

    pub fn address_and_amount(
        mut self,
        address: ReceivingAddress,
        amount: NativeCurrencyAmount,
    ) -> Self {
        self.outputs
            .push(OutputType::AddressAndAmount(address, amount));
        self
    }

    pub fn address_and_amount_and_medium(
        mut self,
        address: ReceivingAddress,
        amount: NativeCurrencyAmount,
        medium: UtxoNotificationMedium,
    ) -> Self {
        self.outputs.push(OutputType::AddressAndAmountAndMedium(
            address, amount, medium,
        ));
        self
    }

    pub fn address_and_utxo(mut self, address: ReceivingAddress, utxo: Utxo) -> Self {
        self.outputs.push(OutputType::AddressAndUtxo(address, utxo));
        self
    }

    pub fn address_and_utxo_and_medium(
        mut self,
        address: ReceivingAddress,
        utxo: Utxo,
        medium: UtxoNotificationMedium,
    ) -> Self {
        self.outputs
            .push(OutputType::AddressAndUtxoAndMedium(address, utxo, medium));
        self
    }

    pub fn tx_output(mut self, tx_output: TxOutput) -> Self {
        self.outputs.push(OutputType::TxOutput(tx_output));
        self
    }

    pub fn build(self, wallet_state: &WalletState, block_height: BlockHeight) -> TxOutputList {
        let wallet_entropy = &wallet_state.wallet_entropy;

        // Convert outputs.  [address:amount] --> TxOutputList
        let outputs = self.outputs.into_iter().map(|output_type| {
            match output_type {
                OutputType::TxOutput(o) => o,

                OutputType::AddressAndAmount(address, amt) => {
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

                OutputType::AddressAndAmountAndMedium(address, amt, medium) => {
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

                OutputType::AddressAndUtxo(address, utxo) => {
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

                OutputType::AddressAndUtxoAndMedium(address, utxo, medium) => {
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
