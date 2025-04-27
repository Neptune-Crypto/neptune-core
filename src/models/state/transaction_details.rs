use std::fmt::Display;

use anyhow::bail;
use anyhow::Result;
use itertools::Itertools;
use num_traits::CheckedSub;
use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tracing::error;

use super::wallet::transaction_output::TxOutput;
use super::wallet::utxo_notification::UtxoNotifyMethod;
use crate::api::tx_initiation::error::CreateTxError;
use crate::config_models::network::Network;
use crate::models::blockchain::block::MINING_REWARD_TIME_LOCK_PERIOD;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::wallet::transaction_input::TxInputList;
use crate::models::state::wallet::transaction_output::TxOutputList;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

/// contains the unblinded data that a [Transaction](crate::models::blockchain::transaction::Transaction) is generated from,
/// minus the [TransactionProof](crate::models::blockchain::transaction::TransactionProof).
///
/// conceptually, `TransactionDetails` + `TransactionProof` --> `Transaction`.
///
/// or in more detail:
///
/// ```text
/// TransactionDetails -> (TransactionKernel, PrimitiveWitness)
/// (TransactionKernel, PrimitiveWitness) -> (TransactionKernel, ProofCollection)
/// (TransactionKernel, ProofCollection) -> (TransactionKernel, SingleProof)
/// (TransactionKernel, SingleProof) -> (TransactionKernel, SingleProof)
/// TransactionProof = PrimitiveWitness | ProofCollection | SingleProof
/// Transaction = TransactionKernel + TransactionProof
/// ```
///
/// security: This type contains secrets (keys) and should never be shared.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionDetails {
    pub tx_inputs: TxInputList,
    pub tx_outputs: TxOutputList,
    pub fee: NativeCurrencyAmount,
    pub coinbase: Option<NativeCurrencyAmount>,
    pub timestamp: Timestamp,
    pub mutator_set_accumulator: MutatorSetAccumulator,
    pub network: Network,
}

// so we can emit a detailed log msg when sending a transaction.
impl Display for TransactionDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"TransactionDetails:
    timestamp: {},
    spend_amount: {},
    inputs_amount: {},
    outputs_amount: {},
    fee: {},
    coinbase: {},
    inputs: {},
    outputs: {},
    change_outputs: {},
    owned_outputs: {},
    network: {},
"#,
            self.timestamp.standard_format(),
            self.spend_amount(),
            self.tx_inputs.total_native_coins(),
            self.tx_outputs.total_native_coins(),
            self.fee,
            self.coinbase.unwrap_or_else(|| 0.into()),
            self.tx_inputs
                .iter()
                .map(|o| o.native_currency_amount())
                .join(", "),
            self.tx_outputs
                .iter()
                .map(|o| o.native_currency_amount())
                .join(", "),
            self.tx_outputs
                .change_iter()
                .map(|o| o.native_currency_amount())
                .join(", "),
            self.tx_outputs
                .owned_iter()
                .map(|o| o.native_currency_amount())
                .join(", "),
            self.network,
        )
    }
}

impl TransactionDetails {
    /// Create (`TransactionDetails` for) a nop-transaction, with no inputs and
    /// no outputs. Can be used if a merge bit needs to be flipped.
    pub(crate) fn nop(
        mutator_set_accumulator: MutatorSetAccumulator,
        now: Timestamp,
        network: Network,
    ) -> Self {
        Self::fee_gobbler(
            NativeCurrencyAmount::zero(),
            Digest::default(),
            mutator_set_accumulator,
            now,
            UtxoNotifyMethod::None,
            network,
        )
    }

    /// Create (`TransactionDetails` for) a new fee-gobbler transaction.
    ///
    /// The produced transaction has no inputs, sets a negative fee, and
    /// distributes it over two UTXOs (one time-locked and one liquid
    /// immediately) of which both are locked to the given lock script hash.
    /// The produced transaction is supported by a [`PrimitiveWitness`], so
    /// the caller still needs a follow-up proving operation.
    pub(crate) fn fee_gobbler(
        gobbled_fee: NativeCurrencyAmount,
        sender_randomness: Digest,
        mutator_set_accumulator: MutatorSetAccumulator,
        now: Timestamp,
        notification_method: UtxoNotifyMethod,
        network: Network,
    ) -> Self {
        let gobbling_utxos = if gobbled_fee.is_zero() {
            vec![]
        } else {
            let mut amount_liquid = gobbled_fee;
            amount_liquid.div_two();
            let amount_timelocked = gobbled_fee.checked_sub(&amount_liquid).unwrap();
            match notification_method {
                UtxoNotifyMethod::OnChain(receiving_address) => vec![
                    TxOutput::onchain_native_currency(
                        amount_liquid,
                        sender_randomness,
                        receiving_address.clone(),
                        true, // owned
                    ),
                    TxOutput::onchain_native_currency(
                        amount_timelocked,
                        sender_randomness,
                        receiving_address,
                        true, // owned
                    )
                    .with_time_lock(now + MINING_REWARD_TIME_LOCK_PERIOD),
                ],
                UtxoNotifyMethod::OffChain(receiving_address) => vec![
                    TxOutput::offchain_native_currency(
                        amount_liquid,
                        sender_randomness,
                        receiving_address.clone(),
                        true, // owned
                    ),
                    TxOutput::offchain_native_currency(
                        amount_timelocked,
                        sender_randomness,
                        receiving_address,
                        true, // owned
                    )
                    .with_time_lock(now + MINING_REWARD_TIME_LOCK_PERIOD),
                ],
                UtxoNotifyMethod::None => {
                    panic!("Cannot produce fee gobbler transaction without UTXO notification")
                }
            }
        };

        TransactionDetails::new_without_coinbase(
            TxInputList::empty(),
            gobbling_utxos,
            -gobbled_fee,
            now,
            mutator_set_accumulator,
            network,
        )
        .expect("new_without_coinbase should succeed when total output amount is zero and no inputs are provided")
    }

    /// Construct a [`TransactionDetails`] instance with coinbase from state
    /// information.
    ///
    /// Does sanity checks on:
    /// - amounts, must be balanced
    /// - mutator set membership proofs, must be valid wrt. supplied mutator set
    ///
    /// See also: [Self::new_without_coinbase].
    pub(crate) fn new_with_coinbase(
        tx_inputs: impl Into<TxInputList>,
        tx_outputs: impl Into<TxOutputList>,
        coinbase: NativeCurrencyAmount,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
        mutator_set_accumulator: MutatorSetAccumulator,
        network: Network,
    ) -> Result<TransactionDetails> {
        Self::new(
            tx_inputs,
            tx_outputs,
            fee,
            Some(coinbase),
            timestamp,
            mutator_set_accumulator,
            network,
        )
    }

    /// Construct a [`TransactionDetails`] instance without coinbase from state
    /// information.
    ///
    /// Does sanity checks on:
    /// - amounts, must be balanced
    /// - mutator set membership proofs, must be valid wrt. supplied mutator set
    ///
    /// See also: [Self::new_with_coinbase].
    pub(crate) fn new_without_coinbase(
        tx_inputs: impl Into<TxInputList>,
        tx_outputs: impl Into<TxOutputList>,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
        mutator_set_accumulator: MutatorSetAccumulator,
        network: Network,
    ) -> Result<TransactionDetails> {
        Self::new(
            tx_inputs,
            tx_outputs,
            fee,
            None,
            timestamp,
            mutator_set_accumulator,
            network,
        )
    }

    /// Constructor for TransactionDetails with some sanity checks.
    ///
    /// # Error
    ///
    /// Returns an error if (any of)
    ///  - the transaction is not balanced
    ///  - some mutator set membership proof is invalid.
    pub(crate) fn new(
        tx_inputs: impl Into<TxInputList>,
        tx_outputs: impl Into<TxOutputList>,
        fee: NativeCurrencyAmount,
        coinbase: Option<NativeCurrencyAmount>,
        timestamp: Timestamp,
        mutator_set_accumulator: MutatorSetAccumulator,
        network: Network,
    ) -> Result<TransactionDetails> {
        let tx_inputs: TxInputList = tx_inputs.into();
        let tx_outputs: TxOutputList = tx_outputs.into();

        // total amount to be spent -- determines how many and which UTXOs to use
        let total_spend = tx_outputs.total_native_coins() + fee;
        let total_input: NativeCurrencyAmount = tx_inputs
            .iter()
            .map(|x| x.utxo.get_native_currency_amount())
            .sum();
        let coinbase_amount = coinbase.unwrap_or(NativeCurrencyAmount::zero());
        let total_spendable = total_input + coinbase_amount;

        // sanity check: do we even have enough funds?
        if total_spend > total_spendable {
            error!("Insufficient funds.\n\n total_spend: {total_spend}\
            \ntotal_spendable: {total_spendable}\ntotal_input: {total_input}\ncoinbase amount: {coinbase_amount}");
            bail!("Not enough available funds.");
        }
        if total_spend < total_spendable {
            let diff = total_spend - total_spendable;
            bail!("Missing change output in the amount of {}", diff);
        }
        if tx_inputs
            .iter()
            .any(|x| !mutator_set_accumulator.verify(x.mutator_set_item(), x.mutator_set_mp()))
        {
            bail!("Invalid mutator set membership proof/mutator set pair provided.");
        }

        Ok(TransactionDetails {
            tx_inputs,
            tx_outputs,
            fee,
            coinbase,
            timestamp,
            mutator_set_accumulator,
            network,
        })
    }

    /// amount spent (excludes change and fee)
    ///
    /// ie: sum(inputs) - (change + fee)
    pub fn spend_amount(&self) -> NativeCurrencyAmount {
        let not_spend = self.tx_outputs.change_amount() + self.fee;

        // sum(inputs) - (change + fee)
        self.tx_inputs
            .total_native_coins()
            .checked_sub(&not_spend)
            .unwrap_or_else(|| 0.into())
    }

    /// verifies the transaction details are valid.
    ///
    /// specifically, a [PrimitiveWitness] is built from these
    /// details and validated in the triton VM.
    pub async fn validate(&self) -> Result<(), CreateTxError> {
        // note: we map the WitnessValidationError into CreateTxError as this
        // method is called during Tx creation, and for consistency in that
        // process.
        Ok(PrimitiveWitness::from_transaction_details(self)
            .validate()
            .await?)
    }

    pub fn primitive_witness(&self) -> PrimitiveWitness {
        self.into()
    }
}

#[cfg(test)]
mod tests {
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;

    #[proptest]
    fn test_fee_gobbler_properties(
        #[strategy(NativeCurrencyAmount::arbitrary_non_negative())]
        gobbled_fee: NativeCurrencyAmount,
        #[strategy(arb())] sender_randomness: Digest,
        #[strategy(arb())] mutator_set_accumulator: MutatorSetAccumulator,
        #[strategy(arb())] now: Timestamp,
        #[filter(#notification_method != UtxoNotifyMethod::None)]
        #[strategy(arb())]
        notification_method: UtxoNotifyMethod,
    ) {
        let fee_gobbler = TransactionDetails::fee_gobbler(
            gobbled_fee,
            sender_randomness,
            mutator_set_accumulator,
            now,
            notification_method,
            Network::Main,
        );

        assert!(
            fee_gobbler.tx_inputs.is_empty(),
            "fee gobbler must have no inputs"
        );

        assert_eq!(
            NativeCurrencyAmount::zero(),
            fee_gobbler
                .tx_outputs
                .iter()
                .map(|txo| txo.utxo().get_native_currency_amount())
                .sum::<NativeCurrencyAmount>()
                + fee_gobbler.fee,
            "total transaction amount must be zero for fee gobbler"
        );

        assert!(
            fee_gobbler.fee.is_negative() || fee_gobbler.fee.is_zero(),
            "fee must be negative or zero; got {}",
            fee_gobbler.fee
        );

        let mut half_of_fee = fee_gobbler.fee;
        half_of_fee.div_two();

        let time_locked_amount = fee_gobbler
            .tx_outputs
            .iter()
            .map(|txo| txo.utxo())
            .filter(|utxo| match utxo.release_date() {
                Some(date) => date >= fee_gobbler.timestamp + MINING_REWARD_TIME_LOCK_PERIOD,
                None => false,
            })
            .map(|utxo| utxo.get_native_currency_amount())
            .sum::<NativeCurrencyAmount>();
        assert!(
            -half_of_fee
                <= time_locked_amount,
            "at least half of negative-fee must be time-locked\nhalf of negative fee: {}\ntime-locked amount: {}",
            -half_of_fee,
            time_locked_amount,
        );
    }
}
