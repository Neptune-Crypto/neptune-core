use std::fmt::Display;

use anyhow::Result;
use itertools::Itertools;
use num_traits::CheckedSub;
use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use super::wallet::transaction_output::TxOutput;
use super::wallet::utxo_notification::UtxoNotifyMethod;
use crate::config_models::network::Network;
use crate::models::blockchain::block::MINING_REWARD_TIME_LOCK_PERIOD;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::primitive_witness::WitnessValidationError;
use crate::models::blockchain::transaction::public_announcement::PublicAnnouncement;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelProxy;
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

    /// Public announcements *excluding* encrypted UTXO notifications.
    public_announcements: Vec<PublicAnnouncement>,
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
    public announcements (excluding encrypted UTXO notifications):\n[{}],
"#,
            self.timestamp.standard_format(),
            self.spend_amount(),
            self.tx_inputs.total_native_coins(),
            self.tx_outputs.total_native_coins(),
            self.fee,
            // render Some(0) and None differently
            self.coinbase
                .map(|nca| format!("{nca}"))
                .unwrap_or("-".to_string()),
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
            self.public_announcements
                .iter()
                .map(|pa| format!("{pa}"))
                .join(",\n"),
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
    ) -> Self {
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
    ) -> Self {
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
    /// This fn does not perform any validation.  use validate() instead.
    pub(crate) fn new(
        tx_inputs: impl Into<TxInputList>,
        tx_outputs: impl Into<TxOutputList>,
        fee: NativeCurrencyAmount,
        coinbase: Option<NativeCurrencyAmount>,
        timestamp: Timestamp,
        mutator_set_accumulator: MutatorSetAccumulator,
        network: Network,
    ) -> Self {
        Self {
            tx_inputs: tx_inputs.into(),
            tx_outputs: tx_outputs.into(),
            public_announcements: vec![],
            fee,
            coinbase,
            timestamp,
            mutator_set_accumulator,
            network,
        }
    }

    /// Extend the [`TransactionDetails`] object with public announcements.
    ///
    /// Use this method for public announcements that are *not* encrypted UTXO
    /// notifications.
    ///
    /// Public announcements are not part of the main constructor [`Self::new`]
    /// because in the common case they are not necessary. If there are
    /// encrypted UTXO notifications, these are computed on the fly from the
    /// transaction outputs. This function should only be used for public
    /// announcements that are not encrypted UTXO notifications, which is an
    /// exceptional case.
    pub(crate) fn with_public_announcements<Iter: IntoIterator<Item = PublicAnnouncement>>(
        mut self,
        public_announcements: Iter,
    ) -> Self {
        let public_announcements = self
            .public_announcements
            .into_iter()
            .chain(public_announcements)
            .collect_vec();
        self.public_announcements = public_announcements;
        self
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
            .unwrap_or_else(NativeCurrencyAmount::zero)
    }

    /// verifies the transaction details are valid.
    ///
    /// specifically, a [PrimitiveWitness] is built from these
    /// details and validated.
    pub async fn validate(&self) -> Result<(), WitnessValidationError> {
        PrimitiveWitness::from_transaction_details(self)
            .validate()
            .await
    }

    /// Produce the list of public announcements, including the UTXO
    /// notifications.
    pub fn public_announcements(&self) -> Vec<PublicAnnouncement> {
        [
            self.public_announcements.clone(),
            self.tx_outputs.public_announcements(),
        ]
        .concat()
    }

    pub fn primitive_witness(&self) -> PrimitiveWitness {
        self.into()
    }

    /// Assemble the transaction kernel corresponding to this
    /// [`TransactionDetails`] object.
    pub fn transaction_kernel(&self) -> TransactionKernel {
        let removal_records = self
            .tx_inputs
            .iter()
            .map(|txi| txi.removal_record(&self.mutator_set_accumulator))
            .collect_vec();
        TransactionKernelProxy {
            inputs: removal_records,
            outputs: self.tx_outputs.addition_records(),
            public_announcements: self.public_announcements(),
            fee: self.fee,
            coinbase: self.coinbase,
            timestamp: self.timestamp,
            mutator_set_hash: self.mutator_set_accumulator.hash(),
            merge_bit: false,
        }
        .into_kernel()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
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
