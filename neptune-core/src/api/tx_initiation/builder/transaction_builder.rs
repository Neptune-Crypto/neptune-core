//! a builder for [Transaction].
//!
//! see [builder](super) for examples of using the builders together.

use crate::api::tx_initiation::error::CreateTxError;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::consensus::transaction::TransactionProof;
use crate::state::transaction::transaction_details::TransactionDetails;

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
    /// [PrimitiveWitness] and that `TransactionDetails` provides a
    /// `primitive_witness()` method.
    ///
    /// If both are provided, the details are ignored as using them requires the
    /// builder to generate a new [PrimitiveWitness], which is comparatively
    /// expensive.
    ///
    /// note: the builder does not validate the resulting artifacts.
    /// That can be done with [Transaction::is_valid()]
    pub fn build(self) -> Result<Transaction, CreateTxError> {
        // prefer kernel, else tx_details.
        let Some(kernel) = self.kernel.or_else(|| {
            self.transaction_details
                .map(|d| PrimitiveWitness::from_transaction_details(d).kernel)
        }) else {
            return Err(CreateTxError::MissingRequirement);
        };

        let Some(proof) = self.transaction_proof else {
            return Err(CreateTxError::MissingRequirement);
        };

        Ok(Transaction { kernel, proof })
    }
}
