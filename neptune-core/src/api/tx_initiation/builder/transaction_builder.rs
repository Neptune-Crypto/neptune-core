//! a builder for [Transaction].
//!
//! see [builder](super) for examples of using the builders together.

use neptune_consensus::transaction::transaction_kernel::TransactionKernel;
use neptune_consensus::transaction::Transaction;
use neptune_consensus::transaction::TransactionProof;
use neptune_wallet::transaction_details::TransactionDetails;

use crate::api::tx_initiation::error::CreateTxError;

/// a builder for [Transaction]
///
/// see module docs for example usage.
#[derive(Debug, Default)]
pub struct TransactionBuilder<'a> {
    transaction_details: Option<&'a TransactionDetails>,
    kernel: Option<TransactionKernel>,
    transaction_proof: Option<TransactionProof>,
}

impl<'a> TransactionBuilder<'a> {
    /// instantiate
    pub fn new() -> Self {
        Default::default()
    }

    /// set transaction details
    pub fn transaction_details(mut self, transaction_details: &'a TransactionDetails) -> Self {
        self.transaction_details = Some(transaction_details);
        self
    }

    /// set transaction details option
    pub fn transaction_details_option(
        mut self,
        transaction_details: Option<&'a TransactionDetails>,
    ) -> Self {
        self.transaction_details = transaction_details;
        self
    }

    /// set transaction kernel (most efficient)
    pub fn transaction_kernel(mut self, kernel: TransactionKernel) -> Self {
        self.kernel = Some(kernel);
        self
    }

    /// set transaction kernel option
    pub fn transaction_kernel_option(mut self, kernel: Option<TransactionKernel>) -> Self {
        self.kernel = kernel;
        self
    }

    /// set transaction proof (required)
    pub fn transaction_proof(mut self, transaction_proof: TransactionProof) -> Self {
        self.transaction_proof = Some(transaction_proof);
        self
    }

    /// set transaction proof option
    pub fn transaction_proof_option(mut self, transaction_proof: Option<TransactionProof>) -> Self {
        self.transaction_proof = transaction_proof;
        self
    }

    /// build a `Transaction`
    ///
    /// Either a `TransactionKernel` or `TransactionDetails` is required.
    ///
    /// Provide a kernel if available.  Note that it can be obtained from a
    /// [PrimitiveWitness](neptune_consensus::transaction::primitive_witness::PrimitiveWitness)
    /// and that `TransactionDetails` provides a `primitive_witness()` method.
    ///
    /// note: the builder does not validate the resulting artifacts.
    /// That can be done with [Transaction::is_valid()]
    pub fn build(self) -> Result<Transaction, CreateTxError> {
        // prefer kernel, else tx_details.
        let Some(kernel) = self.kernel.or_else(|| {
            self.transaction_details
                .map(|d| d.primitive_witness().kernel)
        }) else {
            return Err(CreateTxError::MissingRequirement);
        };

        let Some(proof) = self.transaction_proof else {
            return Err(CreateTxError::MissingRequirement);
        };

        Ok(Transaction { kernel, proof })
    }
}
