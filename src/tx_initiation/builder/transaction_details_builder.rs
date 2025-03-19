use num_traits::CheckedAdd;
use num_traits::CheckedSub;
use tasm_lib::prelude::Digest;

use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::transaction::lock_script::LockScript;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::transaction_details::TransactionDetails;
use crate::models::state::tx_creation_config::ChangePolicy;
use crate::models::state::wallet::address::SpendingKey;
use crate::models::state::wallet::transaction_input::TxInput;
use crate::models::state::wallet::transaction_input::TxInputList;
use crate::models::state::wallet::transaction_output::TxOutput;
use crate::models::state::wallet::transaction_output::TxOutputList;
use crate::models::state::wallet::utxo_notification::UtxoNotificationMedium;
use crate::Block;
use crate::WalletState;

// note: all fields intentionally private
#[derive(Debug, Default)]
pub struct TransactionDetailsBuilder {
    tx_inputs: TxInputList,
    tx_outputs: TxOutputList,
    fee: NativeCurrencyAmount,
    coinbase: Option<NativeCurrencyAmount>,
    change_policy: ChangePolicy,
    timestamp: Timestamp,
}

impl TransactionDetailsBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn input(mut self, tx_input: TxInput) -> Self {
        self.tx_inputs.push(tx_input);
        self
    }

    pub fn inputs(mut self, mut tx_input_list: TxInputList) -> Self {
        self.tx_inputs.append(&mut tx_input_list);
        self
    }

    pub fn output(mut self, tx_output: TxOutput) -> Self {
        self.tx_outputs.push(tx_output);
        self
    }

    pub fn outputs(mut self, mut tx_output_list: TxOutputList) -> Self {
        self.tx_outputs.append(&mut tx_output_list);
        self
    }

    // maybe?
    // pub fn output_address_and_amount(mut self, ReceivingAddress, amount: NativeCurrencyAmount) -> Self;

    pub fn fee(mut self, amount: NativeCurrencyAmount) -> Self {
        self.fee = amount;
        self
    }

    pub fn coinbase(mut self, amount: NativeCurrencyAmount) -> Self {
        self.coinbase = Some(amount);
        self
    }

    pub fn change_policy(mut self, change_policy: ChangePolicy) -> Self {
        self.change_policy = change_policy;
        self
    }

    // build impl could look something like:
    // pub fn build(mut self) -> Result<TransactionDetails, TransactionDetailsBuildError> {
    pub fn build(
        self,
        wallet_state: &WalletState,
        tip: &Block,
    ) -> anyhow::Result<TransactionDetails> {
        let mutator_set_accumulator = tip.mutator_set_accumulator_after();

        let TransactionDetailsBuilder {
            tx_inputs,
            mut tx_outputs,
            fee,
            coinbase,
            timestamp,
            change_policy,
            ..
        } = self;

        let total_outbound_amount = tx_outputs
            .total_native_coins()
            .checked_add(&fee)
            .ok_or(anyhow::anyhow!("total spend amount is too large"))?;
        let total_unlocked_amount = tx_inputs.total_native_coins();

        let change_amount = total_unlocked_amount
            .checked_sub(&total_outbound_amount)
            .ok_or(anyhow::anyhow!("insufficient funds"))?;

        // Add change output, if required to balance transaction
        if change_amount > 0.into() {
            let change_output = match change_policy {
                ChangePolicy::ExactChange => {
                    anyhow::bail!("ChangePolicy = ExactChange, but inputs exceed outputs.")
                }

                ChangePolicy::Recover { key, medium } => Self::create_change_output(
                    wallet_state,
                    tip.header().height,
                    change_amount,
                    *key,
                    medium,
                )?,

                ChangePolicy::Burn => TxOutput::no_notification(
                    Utxo::new_native_currency(LockScript::burn(), change_amount),
                    Digest::default(),
                    Digest::default(),
                    false,
                ),
            };
            tx_outputs.push(change_output);
        }

        TransactionDetails::new(
            tx_inputs.into(),
            tx_outputs,
            fee,
            coinbase,
            timestamp,
            mutator_set_accumulator,
        )
    }

    /// Generate a change UTXO to ensure that the difference in input amount
    /// and output amount goes back to us. Return the UTXO in a format compatible
    /// with claiming it later on.
    //
    // "Later on" meaning: as an [ExpectedUtxo].
    fn create_change_output(
        wallet_state: &WalletState,
        tip_height: BlockHeight,
        change_amount: NativeCurrencyAmount,
        change_key: SpendingKey,
        change_utxo_notify_method: UtxoNotificationMedium,
    ) -> anyhow::Result<TxOutput> {
        let Some(own_receiving_address) = change_key.to_address() else {
            anyhow::bail!("Cannot create change output when supplied spending key has no corresponding address.");
        };

        let receiver_digest = own_receiving_address.privacy_digest();
        let change_sender_randomness = wallet_state
            .wallet_entropy
            .generate_sender_randomness(tip_height, receiver_digest);

        let owned = true;
        let change_output = match change_utxo_notify_method {
            UtxoNotificationMedium::OnChain => TxOutput::onchain_native_currency(
                change_amount,
                change_sender_randomness,
                own_receiving_address,
                owned,
            ),
            UtxoNotificationMedium::OffChain => TxOutput::offchain_native_currency(
                change_amount,
                change_sender_randomness,
                own_receiving_address,
                owned,
            ),
        };

        Ok(change_output)
    }
}
