use std::collections::HashSet;

use itertools::Itertools;
use tasm_lib::triton_vm::prelude::BFieldCodec;

use crate::api::export::Announcement;
use crate::api::tx_initiation::transparent_input::TransparentInput;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::utxo_triple::UtxoTriple;

/// A struct containing the UTXOs and all information needed to reproduce the
/// [`RemovalRecord`]s (or at least, the [`AbsoluteIndexSet`]s) and the
/// [`AdditionRecord`]s for the transaction in which they are consumed and
/// produced.
#[derive(Debug, Clone, BFieldCodec)]
pub struct TransparentTransactionDetails {
    pub inputs: Vec<TransparentInput>,
    pub outputs: Vec<UtxoTriple>,
}

impl TransparentTransactionDetails {
    /// Construct a new [`TransparentTransactionDetails`] object from the given
    /// inputs and outputs.
    pub fn new(inputs: Vec<TransparentInput>, outputs: Vec<UtxoTriple>) -> Self {
        Self { inputs, outputs }
    }

    /// Convert the [`TransparentTransactionDetails`] object into an
    /// [`Announcement`].
    pub fn to_announcement(&self) -> Announcement {
        Announcement {
            message: self.encode(),
        }
    }

    /// Try and interpret the [`Announcement`] as a
    /// [`TransparentTransactionDetails`].
    pub fn try_from_announcement(
        announcement: &Announcement,
    ) -> Result<Self, <Self as BFieldCodec>::Error> {
        Ok(*Self::decode(&announcement.message)?)
    }

    /// Validate the [`TransparentTransactionDetails`] relative to a given
    /// [`TransactionKernel`].
    ///
    /// Specifically, verify that all the associated [`AdditionRecord`]s and
    /// [`AbsoluteIndexSet`]s induced by the [`TransparentTransactionDetails`]
    /// are present in the [`TransactionKernel`].
    pub fn validate(&self, transaction_kernel: &TransactionKernel) -> bool {
        let addition_records_from_self = self
            .outputs
            .iter()
            .map(|utxo_triple| utxo_triple.addition_record())
            .collect_vec();
        let absolute_index_sets_from_self = self
            .inputs
            .iter()
            .map(|transparent_input| transparent_input.absolute_index_set())
            .collect_vec();

        let all_addition_records_are_present = addition_records_from_self
            .iter()
            .all(|ar| transaction_kernel.outputs.contains(ar));
        let absolute_index_sets_in_transaction = transaction_kernel
            .inputs
            .iter()
            .map(|removal_record| removal_record.absolute_indices)
            .collect::<HashSet<_>>();
        let all_absolute_index_sets_are_present = absolute_index_sets_from_self
            .iter()
            .all(|ais| absolute_index_sets_in_transaction.contains(ais));

        all_addition_records_are_present && all_absolute_index_sets_are_present
    }
}
