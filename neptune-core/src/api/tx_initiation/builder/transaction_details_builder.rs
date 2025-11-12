//! This module provides a builder for generating [TransactionDetails].
//!
//! The builder will modify state only if one or more new keys must be added to
//! the wallet for change output(s).  see [TransactionDetailsBuilder::build()]
//! for details.
//!
//! The resulting `TransactionDetails` contains all data needed for a [Transaction](crate::protocol::consensus::transaction::Transaction)
//! except for a [TransactionProof](crate::protocol::consensus::transaction::TransactionProof).
//!
//! see [builder](super) for examples of using the builders together.
use std::sync::Arc;

use num_traits::CheckedAdd;
use num_traits::CheckedSub;
use tasm_lib::prelude::Digest;

use crate::api::export::TransparentInput;
use crate::api::export::TransparentTransactionInfo;
use crate::api::tx_initiation::error::CreateTxError;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::transaction::announcement::Announcement;
use crate::protocol::consensus::transaction::lock_script::LockScript;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::state::transaction::transaction_details::TransactionDetails;
use crate::state::wallet::address::KeyType;
use crate::state::wallet::address::SpendingKey;
use crate::state::wallet::change_policy::ChangePolicy;
use crate::state::wallet::transaction_input::TxInput;
use crate::state::wallet::transaction_input::TxInputList;
use crate::state::wallet::transaction_output::TxOutput;
use crate::state::wallet::transaction_output::TxOutputList;
use crate::state::wallet::utxo_notification::UtxoNotificationMedium;
use crate::state::GlobalState;
use crate::state::StateLock;
use crate::Block;
use crate::WalletState;

/// a builder to generate [TransactionDetails].
// note: all fields intentionally private
#[derive(Debug, Default)]
pub struct TransactionDetailsBuilder {
    tx_inputs: TxInputList,
    tx_outputs: TxOutputList,
    custom_announcements: Vec<Announcement>,
    fee: NativeCurrencyAmount,
    coinbase: Option<NativeCurrencyAmount>,
    change_policy: ChangePolicy,
    timestamp: Option<Timestamp>,
    transparent: bool,
}

impl TransactionDetailsBuilder {
    /// instantiate builder
    pub fn new() -> Self {
        Default::default()
    }

    /// add a timestamp.  defaults to Timestamp::now()
    pub fn timestamp(mut self, timestamp: Timestamp) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// adds an input.
    pub fn input(mut self, tx_input: TxInput) -> Self {
        self.tx_inputs.push(tx_input);
        self
    }

    /// adds a list of inputs.  See [TxInputListBuilder](super::tx_input_list_builder::TxInputListBuilder)
    pub fn inputs(mut self, mut tx_input_list: TxInputList) -> Self {
        self.tx_inputs.append(&mut tx_input_list);
        self
    }

    /// adds an output
    pub fn output(mut self, tx_output: TxOutput) -> Self {
        self.tx_outputs.push(tx_output);
        self
    }

    /// adds a list of outputs.  See [TxOutputListBuilder](super::tx_output_list_builder::TxOutputListBuilder)
    pub fn outputs(mut self, mut tx_output_list: TxOutputList) -> Self {
        self.tx_outputs.append(&mut tx_output_list);
        self
    }

    /// Add many custom announcements.
    ///
    /// Use this method for announcements that are *not* any of the following:
    ///  - encrypted UTXO notifications;
    ///  - transparent transaction data.
    ///
    /// Announcements that do satisfy any of these descriptions are generated on
    /// the fly at a later stage.
    pub fn custom_announcements(mut self, mut announcements: Vec<Announcement>) -> Self {
        self.custom_announcements.append(&mut announcements);
        self
    }

    /// adds a fee amount
    pub fn fee(mut self, amount: NativeCurrencyAmount) -> Self {
        self.fee = amount;
        self
    }

    /// adds a coinbase amount
    pub fn coinbase(mut self, amount: NativeCurrencyAmount) -> Self {
        self.coinbase = Some(amount);
        self
    }

    /// adds a change policy.   defaults to [ChangePolicy::default()]
    pub fn change_policy(mut self, change_policy: ChangePolicy) -> Self {
        self.change_policy = change_policy;
        self
    }

    /// Set the transparency flag.
    ///
    /// Transactions that are transparent include an announcements which
    /// contains the raw UTXOs and commitment data for all inputs and outputs,
    /// in plaintext. By default, transactions are *not* transparent.
    pub fn transparent(mut self, transparent: bool) -> Self {
        self.transparent = transparent;
        self
    }

    // ##multicoin## : we must consider change for non-native Coin.
    //   1. how to obtain the coin amount for these? need some kind of CoinAmount type.
    //   2. if inputs and outputs have more than one Coin type, how do we
    //      sum(inputs) and sum(outputs) to determine if inputs exceed outputs?
    //      (perhaps in a loop for each Coin type present?)

    /// Build [TransactionDetails] and possibly mutate wallet state, acquiring
    /// write-lock if necessary.
    ///
    /// Some basic validation of inputs is performed however the result could
    /// still represent an invalid transaction.  One can call
    /// [TransactionDetails::validate()] on the result.  Otherwise, the
    /// transaction will be fully validated by the triton VM before it is
    /// recorded and and broadcast.
    ///
    /// important: this method will generate a new wallet-key for change if
    /// necessary. This occurs if change_policy is
    /// ChangePolicy::RecoverToNextUnusedKey and change is needed.
    ///
    /// important: this method accepts a StateLock mutable reference.
    ///
    /// If a new change key must be generated then:
    /// * StateLock::Lock       --> a write-lock will be acquired (once).
    /// * StateLock::WriteGuard --> existing write-lock will be used.
    /// * StateLock::ReadGuard  --> return error CreateTxError::CantGenChangeKeyForImmutableWallet
    ///
    /// else:
    /// * StateLock::Lock       --> a read-lock will be acquired (once).
    /// * StateLock::WriteGuard --> existing write-lock will be used.
    /// * StateLock::ReadGuard  --> existing read-lock will be used.
    pub async fn build(
        self,
        state_lock: &mut StateLock<'_>,
    ) -> Result<TransactionDetails, CreateTxError> {
        let TransactionDetailsBuilder {
            tx_inputs,
            mut tx_outputs,
            fee,
            coinbase,
            timestamp,
            change_policy,
            ..
        } = self;

        // default to present time if unspecified
        let timestamp = timestamp.unwrap_or_else(Timestamp::now);

        // ##multicoin## : do we need a total amount for each Coin?
        let total_outbound_amount = tx_outputs
            .total_native_coins()
            .checked_add(&fee)
            .ok_or(CreateTxError::TotalSpendTooLarge)?;
        let total_unlocked_amount = tx_inputs.total_native_coins();

        // ##multicoin## : do we need a change amount for each Coin?
        let change_amount = total_unlocked_amount
            .checked_sub(&total_outbound_amount)
            .ok_or_else(|| {
                tracing::error!("Attempt to build transaction failed due to insufficient funds. requested: {}, versus available: {}", total_outbound_amount, total_unlocked_amount);
                CreateTxError::InsufficientFunds {
                    requested: total_outbound_amount,
                    available: total_unlocked_amount,
                }
            })?;

        // ##multicoin## : do we need a change output for each Coin?
        let has_change_output = change_amount.is_positive();

        // Add change output, if required to balance transaction
        let tip_block = if has_change_output {
            let (change_output, tip) = match change_policy {
                ChangePolicy::ExactChange => {
                    return Err(CreateTxError::NotExactChange);
                }

                ChangePolicy::RecoverToNextUnusedKey { key_type, medium } => {
                    async fn create_change(
                        gsm: &mut GlobalState,
                        key_type: KeyType,
                        change_amount: NativeCurrencyAmount,
                        medium: UtxoNotificationMedium,
                    ) -> Result<(TxOutput, Arc<Block>), CreateTxError> {
                        let tip = gsm.chain.light_state_clone();
                        let key = gsm.wallet_state.next_unused_spending_key(key_type).await;

                        Ok((
                            TransactionDetailsBuilder::create_change_output(
                                &gsm.wallet_state,
                                tip.header().height,
                                change_amount,
                                key,
                                medium,
                            ),
                            tip,
                        ))
                    }

                    match state_lock {
                        StateLock::Lock(ref mut global_state_lock) => {
                            create_change(
                                &mut *global_state_lock.lock_guard_mut().await,
                                key_type,
                                change_amount,
                                medium,
                            )
                            .await?
                        }
                        StateLock::WriteGuard(ref mut gsm) => {
                            create_change(&mut *gsm, key_type, change_amount, medium).await?
                        }
                        StateLock::ReadGuard(_) => {
                            return Err(CreateTxError::CantGenChangeKeyForImmutableWallet)
                        }
                    }
                }

                ChangePolicy::RecoverToProvidedKey { key, medium } => {
                    let create_change = |gs: &GlobalState| -> Result<_, CreateTxError> {
                        let tip = gs.chain.light_state_clone();
                        Ok((
                            Self::create_change_output(
                                &gs.wallet_state,
                                tip.header().height,
                                change_amount,
                                *key,
                                medium,
                            ),
                            tip,
                        ))
                    };

                    match state_lock {
                        StateLock::Lock(global_state_lock) => {
                            create_change(&*global_state_lock.lock_guard().await)?
                        }
                        StateLock::WriteGuard(gsm) => create_change(&*gsm)?,
                        StateLock::ReadGuard(gs) => create_change(&*gs)?,
                    }
                }

                ChangePolicy::Burn => (
                    TxOutput::no_notification_as_change(
                        Utxo::new_native_currency(LockScript::burn().hash(), change_amount),
                        Digest::default(),
                        Digest::default(),
                    ),
                    state_lock.tip().await,
                ),
            };
            tx_outputs.push(change_output);
            tip
        } else {
            state_lock.tip().await
        };

        let mut custom_announcements = self.custom_announcements;

        // if transaction is supposed to be transparent, serialize critical data
        // and include it as an announcement
        if self.transparent {
            let transparent_inputs = tx_inputs
                .iter()
                .cloned()
                .map(TransparentInput::from)
                .collect::<Vec<_>>();
            let transparent_outputs = tx_outputs
                .iter()
                .map(|x| x.utxo_triple())
                .collect::<Vec<_>>();
            let transparent_transaction_details =
                TransparentTransactionInfo::new(transparent_inputs, transparent_outputs);
            custom_announcements.push(transparent_transaction_details.to_announcement());
        }

        let transaction_details = TransactionDetails::new(
            tx_inputs,
            tx_outputs,
            fee,
            coinbase,
            timestamp,
            tip_block
                .mutator_set_accumulator_after()
                .map_err(|_| CreateTxError::NoMutatorSetAccumulatorAfter)?,
            state_lock.cli().network,
        )
        .with_announcements(custom_announcements);

        Ok(transaction_details)
    }

    // ##multicoin## : should probably accept a Coin and CoinAmount arg?

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
    ) -> TxOutput {
        let own_receiving_address = change_key.to_address();

        let receiver_digest = own_receiving_address.privacy_digest();
        let change_sender_randomness = wallet_state
            .wallet_entropy
            .generate_sender_randomness(tip_height, receiver_digest);

        match change_utxo_notify_method {
            UtxoNotificationMedium::OnChain => TxOutput::onchain_native_currency_as_change(
                change_amount,
                change_sender_randomness,
                own_receiving_address,
            ),
            UtxoNotificationMedium::OffChain => TxOutput::offchain_native_currency_as_change(
                change_amount,
                change_sender_randomness,
                own_receiving_address,
            ),
        }
    }
}
