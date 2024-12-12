use anyhow::bail;
use anyhow::Result;
use num_traits::CheckedSub;
use num_traits::Zero;
use tasm_lib::prelude::Digest;
use tracing::error;

use super::wallet::transaction_output::TxOutput;
use super::wallet::unlocked_utxo::UnlockedUtxo;
use super::wallet::utxo_notification::UtxoNotifyMethod;
use crate::models::blockchain::block::MINING_REWARD_TIME_LOCK_PERIOD;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::wallet::transaction_output::TxOutputList;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

/// Information, fetched from the state of the node, required to generate a
/// transaction.
#[derive(Debug, Clone)]
pub(crate) struct TransactionDetails {
    pub tx_inputs: Vec<UnlockedUtxo>,
    pub tx_outputs: TxOutputList,
    pub fee: NeptuneCoins,
    pub coinbase: Option<NeptuneCoins>,
    pub timestamp: Timestamp,
    pub mutator_set_accumulator: MutatorSetAccumulator,
}

impl TransactionDetails {
    /// Create (`TransactionDetails` for) a new fee-gobbler transaction.
    ///
    /// The produced transaction has no inputs, sets a negative fee, and
    /// distributes it over two UTXOs (one time-locked and one liquid
    /// immediately) of which both are locked to the given lock script hash.
    /// The produced transaction is supported by a [`PrimitiveWitness`], so
    /// the caller still needs a follow-up proving operation.
    pub(crate) fn fee_gobbler(
        gobbled_fee: NeptuneCoins,
        sender_randomness: Digest,
        mutator_set_accumulator: MutatorSetAccumulator,
        now: Timestamp,
        notification_method: UtxoNotifyMethod,
    ) -> Self {
        let mut amount_liquid = gobbled_fee;
        amount_liquid.div_two();
        let amount_timelocked = gobbled_fee.checked_sub(&amount_liquid).unwrap();

        let (time_locked_txo, liquid_txo) = match notification_method {
            UtxoNotifyMethod::OnChain(receiving_address) => (
                TxOutput::onchain_native_currency(
                    amount_timelocked,
                    sender_randomness,
                    receiving_address.clone(),
                    true,
                ),
                TxOutput::onchain_native_currency(
                    amount_liquid,
                    sender_randomness,
                    receiving_address,
                    true,
                )
                .with_time_lock(now + MINING_REWARD_TIME_LOCK_PERIOD),
            ),
            UtxoNotifyMethod::OffChain(receiving_address) => (
                TxOutput::offchain_native_currency(
                    amount_timelocked,
                    sender_randomness,
                    receiving_address.clone(),
                    true,
                ),
                TxOutput::offchain_native_currency(
                    amount_liquid,
                    sender_randomness,
                    receiving_address,
                    true,
                )
                .with_time_lock(now + MINING_REWARD_TIME_LOCK_PERIOD),
            ),
            UtxoNotifyMethod::None => {
                panic!("Cannot produce fee gobbler transaction without UTXO notification")
            }
        };

        TransactionDetails::new_without_coinbase(
            vec![],
            vec![time_locked_txo, liquid_txo].into(),
            -gobbled_fee,
            now,
            mutator_set_accumulator,
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
        tx_inputs: Vec<UnlockedUtxo>,
        tx_outputs: TxOutputList,
        coinbase: NeptuneCoins,
        fee: NeptuneCoins,
        timestamp: Timestamp,
        mutator_set_accumulator: MutatorSetAccumulator,
    ) -> Result<TransactionDetails> {
        Self::new(
            tx_inputs,
            tx_outputs,
            fee,
            Some(coinbase),
            timestamp,
            mutator_set_accumulator,
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
        tx_inputs: Vec<UnlockedUtxo>,
        tx_outputs: TxOutputList,
        fee: NeptuneCoins,
        timestamp: Timestamp,
        mutator_set_accumulator: MutatorSetAccumulator,
    ) -> Result<TransactionDetails> {
        Self::new(
            tx_inputs,
            tx_outputs,
            fee,
            None,
            timestamp,
            mutator_set_accumulator,
        )
    }

    /// Constructor for TransactionDetails with some sanity checks.
    ///
    /// # Error
    ///
    /// Returns an error if (any of)
    ///  - the transaction is not balanced
    ///  - some mutator set membership proof is invalid.
    fn new(
        tx_inputs: Vec<UnlockedUtxo>,
        tx_outputs: TxOutputList,
        fee: NeptuneCoins,
        coinbase: Option<NeptuneCoins>,
        timestamp: Timestamp,
        mutator_set_accumulator: MutatorSetAccumulator,
    ) -> Result<TransactionDetails> {
        // total amount to be spent -- determines how many and which UTXOs to use
        let total_spend = tx_outputs.total_native_coins() + fee;
        let total_input: NeptuneCoins = tx_inputs
            .iter()
            .map(|x| x.utxo.get_native_currency_amount())
            .sum();
        let coinbase_amount = coinbase.unwrap_or(NeptuneCoins::zero());
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
        })
    }
}

#[cfg(test)]
mod test {
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;

    #[proptest]
    fn test_fee_gobbler_properties(
        #[strategy(NeptuneCoins::arbitrary_non_negative())] gobbled_fee: NeptuneCoins,
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
        );

        assert!(
            fee_gobbler.tx_inputs.is_empty(),
            "fee gobbler must have no inputs"
        );

        assert_eq!(
            NeptuneCoins::zero(),
            fee_gobbler
                .tx_outputs
                .iter()
                .map(|txo| txo.utxo().get_native_currency_amount())
                .sum::<NeptuneCoins>()
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
            .sum::<NeptuneCoins>();
        assert!(
            -half_of_fee
                <= time_locked_amount,
            "at least half of negative-fee must be time-locked\nhalf of negative fee: {}\ntime-locked amount: {}",
            -half_of_fee,
            time_locked_amount,
        );
    }
}
