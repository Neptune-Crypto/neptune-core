use std::fmt::Display;

use anyhow::Result;
use itertools::Itertools;
use num_traits::CheckedSub;
use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use super::super::wallet::transaction_output::TxOutput;
use super::super::wallet::utxo_notification::UtxoNotificationMethod;
use crate::application::config::network::Network;
use crate::protocol::consensus::transaction::announcement::Announcement;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::primitive_witness::WitnessValidationError;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelProxy;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::state::wallet::transaction_input::TxInputList;
use crate::state::wallet::transaction_output::TxOutputList;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

/// contains the unblinded data that a
/// [Transaction](crate::protocol::consensus::transaction::Transaction) is
/// generated from, minus the
/// [TransactionProof](crate::protocol::consensus::transaction::TransactionProof).
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

    /// announcements *excluding* encrypted UTXO notifications.
    extra_announcements: Vec<Announcement>,
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
    extra announcements:\n[{}],
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
            self.extra_announcements
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
            UtxoNotificationMethod::None,
            network,
        )
    }

    /// Create (`TransactionDetails` for) a new fee-gobbler transaction.
    ///
    /// The produced transaction has no inputs, sets a negative fee, and
    /// distributes it over one UTXO which is locked to the given lock script
    /// hash.
    ///
    /// # Panics
    ///
    /// - If the supplied fee is negative.
    /// - If UtxoNotifyMethod is set to none
    pub(crate) fn fee_gobbler(
        gobbled_fee: NativeCurrencyAmount,
        sender_randomness: Digest,
        mutator_set_accumulator: MutatorSetAccumulator,
        now: Timestamp,
        notification_method: UtxoNotificationMethod,
        network: Network,
    ) -> Self {
        assert!(
            !gobbled_fee.is_negative(),
            "Gobbled fee may not be negative"
        );
        let gobbling_utxos = if gobbled_fee.is_zero() {
            vec![]
        } else {
            match notification_method {
                UtxoNotificationMethod::OnChain(receiving_address) => {
                    vec![TxOutput::onchain_native_currency(
                        gobbled_fee,
                        sender_randomness,
                        receiving_address.clone(),
                        true, // owned
                    )]
                }
                UtxoNotificationMethod::OffChain(receiving_address) => {
                    vec![TxOutput::offchain_native_currency(
                        gobbled_fee,
                        sender_randomness,
                        receiving_address.clone(),
                        true, // owned
                    )]
                }
                UtxoNotificationMethod::None => {
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
            extra_announcements: vec![],
            fee,
            coinbase,
            timestamp,
            mutator_set_accumulator,
            network,
        }
    }

    /// Extend the [`TransactionDetails`] object with announcements.
    ///
    /// Use this method for announcements that are *not* encrypted UTXO
    /// notifications.
    ///
    /// Announcements are not part of the main constructor [`Self::new`]
    /// because in the common case they are not necessary. If there are
    /// encrypted UTXO notifications, these are computed on the fly from the
    /// transaction outputs. This function should only be used for
    /// announcements that are not encrypted UTXO notifications, which is an
    /// exceptional case.
    pub(crate) fn with_announcements<Iter: IntoIterator<Item = Announcement>>(
        mut self,
        announcements: Iter,
    ) -> Self {
        self.extra_announcements = self
            .extra_announcements
            .into_iter()
            .chain(announcements)
            .collect_vec();
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

    /// Produce the list of announcements, including the UTXO
    /// notifications.
    pub fn announcements(&self) -> Vec<Announcement> {
        [
            self.extra_announcements.clone(),
            self.tx_outputs.announcements(),
        ]
        .concat()
    }

    pub fn primitive_witness(&self) -> PrimitiveWitness {
        PrimitiveWitness::from_transaction_details(self)
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
            announcements: self.announcements(),
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

    use super::*;

    #[test_strategy::proptest(async = "tokio", cases = 30)]
    async fn test_fee_gobbler_properties(
        #[strategy(NativeCurrencyAmount::arbitrary_non_negative())]
        gobbled_fee: NativeCurrencyAmount,
        #[strategy(arb())] sender_randomness: Digest,
        #[strategy(arb())] mutator_set_accumulator: MutatorSetAccumulator,
        #[strategy(arb())] now: Timestamp,
        #[filter(#notification_method != UtxoNotificationMethod::None)]
        #[strategy(arb())]
        notification_method: UtxoNotificationMethod,
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

        assert!(
            fee_gobbler
                .tx_outputs
                .iter()
                .all(|x| !x.utxo().is_timelocked()),
            "Gobbler fees should not be timelocked"
        );

        assert!(fee_gobbler.primitive_witness().validate().await.is_ok());
    }
}
