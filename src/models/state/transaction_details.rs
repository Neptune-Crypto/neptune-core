use anyhow::bail;
use anyhow::Result;
use num_traits::Zero;
use tracing::debug;

use super::wallet::unlocked_utxo::UnlockedUtxo;
use crate::models::blockchain::transaction::transaction_output::TxOutputList;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::proof_abstractions::timestamp::Timestamp;
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
        fee: NeptuneCoins,
        coinbase: NeptuneCoins,
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

    fn new(
        tx_inputs: Vec<UnlockedUtxo>,
        tx_outputs: TxOutputList,
        fee: NeptuneCoins,
        coinbase: Option<NeptuneCoins>,
        timestamp: Timestamp,
        mutator_set_accumulator: MutatorSetAccumulator,
    ) -> Result<TransactionDetails> {
        // total amount to be spent -- determines how many and which UTXOs to use
        let total_spent = tx_outputs.total_native_coins() + fee;
        let total_input: NeptuneCoins = tx_inputs
            .iter()
            .map(|x| x.utxo.get_native_currency_amount())
            .sum();
        let total_spendable = total_input + coinbase.unwrap_or(NeptuneCoins::zero());

        // sanity check: do we even have enough funds?
        if total_spent > total_spendable {
            debug!("Insufficient funds. total_spend: {total_spent}, total_spendable: {total_spendable}");
            bail!("Not enough available funds.");
        }
        if total_spent < total_spendable {
            let diff = total_spent - total_spendable;
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
