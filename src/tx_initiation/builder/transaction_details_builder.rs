use std::sync::Arc;

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
use crate::models::state::wallet::address::KeyType;
use crate::models::state::wallet::address::SpendingKey;
use crate::models::state::wallet::transaction_input::TxInput;
use crate::models::state::wallet::transaction_input::TxInputList;
use crate::models::state::wallet::transaction_output::TxOutput;
use crate::models::state::wallet::transaction_output::TxOutputList;
use crate::models::state::wallet::utxo_notification::UtxoNotificationMedium;
use crate::models::state::GlobalState;
use crate::models::state::StateLock;
use crate::tx_initiation::error::CreateTxError;
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

    /// build [TransactionDetails] and possibly mutate wallet state, acquiring write-lock if necessary.
    ///
    /// important: this method will generate a new wallet-key for change if
    /// necessary. This occurs if change_policy is
    /// ChangePolicy::RecoverToNextUnusedKey and change is needed.
    ///
    /// important: this method accepts a StateLock mutable reference.
    ///
    /// If a new change key must be generated then:
    ///   StateLock::Lock       --> a write-lock will be acquired (once).
    ///   StateLock::WriteGuard --> existing write-lock will be used.
    ///   StateLock::ReadGuard  --> return error CreateTxError::CantGenChangeKeyForImmutableWallet
    ///
    /// else:
    ///   StateLock::Lock       --> a read-lock will be acquired (once).
    ///   StateLock::WriteGuard --> existing write-lock will be used.
    ///   StateLock::ReadGuard  --> existing read-lock will be used.
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

        let total_outbound_amount = tx_outputs
            .total_native_coins()
            .checked_add(&fee)
            .ok_or(CreateTxError::TotalSpendTooLarge)?;
        let total_unlocked_amount = tx_inputs.total_native_coins();

        let change_amount = total_unlocked_amount
            .checked_sub(&total_outbound_amount)
            .ok_or(CreateTxError::InsufficientFunds {
                requested: total_outbound_amount,
                available: total_unlocked_amount,
            })?;

        let has_change_output = change_amount > 0.into();

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

                        let Some(key) = gsm.wallet_state.next_unused_spending_key(key_type).await
                        else {
                            // it is gross there is now a key-type that can't be
                            // used for change, so the call can fail, and we must
                            // have this error variant.
                            return Err(CreateTxError::InvalidKeyForChange);
                        };

                        Ok((
                            TransactionDetailsBuilder::create_change_output(
                                &gsm.wallet_state,
                                tip.header().height,
                                change_amount,
                                key,
                                medium,
                            )?,
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
                            )?,
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
                        Utxo::new_native_currency(LockScript::burn(), change_amount),
                        Digest::default(),
                        Digest::default(),
                        false, // owned
                    ),
                    state_lock.tip().await,
                ),
            };
            tx_outputs.push(change_output);
            tip
        } else {
            state_lock.tip().await
        };

        Ok(TransactionDetails::new(
            tx_inputs,
            tx_outputs,
            fee,
            coinbase,
            timestamp,
            tip_block.mutator_set_accumulator_after(),
        )?)
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
    ) -> Result<TxOutput, CreateTxError> {
        let Some(own_receiving_address) = change_key.to_address() else {
            // it's gross that there is now a key-type without any corresponding
            // address, so to_address() can now fail, and we must have this
            // error variant and return Result instead of being correct by construction.
            return Err(CreateTxError::InvalidKeyForChange);
        };

        let receiver_digest = own_receiving_address.privacy_digest();
        let change_sender_randomness = wallet_state
            .wallet_entropy
            .generate_sender_randomness(tip_height, receiver_digest);

        let owned = true;
        let change_output = match change_utxo_notify_method {
            UtxoNotificationMedium::OnChain => TxOutput::onchain_native_currency_as_change(
                change_amount,
                change_sender_randomness,
                own_receiving_address,
                owned,
            ),
            UtxoNotificationMedium::OffChain => TxOutput::offchain_native_currency_as_change(
                change_amount,
                change_sender_randomness,
                own_receiving_address,
                owned,
            ),
        };

        Ok(change_output)
    }
}

// enum WalletStateRef<'a> {
//     Mutable(&'a mut WalletState),
//     Immutable(&'a WalletState),
//     Lock(GlobalStateLock),
// }

// impl<'a> WalletStateRef<'a> {
//     fn immutable(&'a self) -> &'a WalletState {
//         match self {
//             Self::Mutable(ws) => ws,
//             Self::Immutable(ws) => ws,
//         }
//     }
// }
