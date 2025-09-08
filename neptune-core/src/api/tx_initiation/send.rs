//! provides an easy-to-use `TransactionSender` with single send() method.
//!
//! This is highest-level and easiest to use API for sending a transaction.
//!
//! It should be preferred to lower-level APIs unless there is a need for
//! greater flexibility than this provides.
//!
//! see [tx_initiation](super) for other available API.
//!
//! Example:
//!
//! ```
//! use neptune_cash::{api, api::export, api::tx_initiation::{self, send}};
//! use export::ChangePolicy;
//! use export::GlobalStateLock;
//! use export::NativeCurrencyAmount;
//! use export::ReceivingAddress;
//! use export::Timestamp;
//! use export::TxCreationArtifacts;
//!
//! async fn my_send_transaction(gsl: GlobalStateLock, recipient: ReceivingAddress, amount: NativeCurrencyAmount, change_policy: ChangePolicy, fee: NativeCurrencyAmount) -> Result<TxCreationArtifacts, tx_initiation::error::SendError> {
//!     let outputs = vec![(recipient, amount)];
//!
//!     send::TransactionSender::from(gsl)
//!         .send(
//!             outputs,
//!             change_policy,
//!             fee,
//!             Timestamp::now()
//!         ).await
//! }
//! ```

use super::error;
use crate::api::tx_initiation::builder::tx_output_list_builder::OutputFormat;
use crate::api::tx_initiation::initiator::TransactionInitiator;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::state::transaction::tx_creation_artifacts::TxCreationArtifacts;
use crate::state::wallet::change_policy::ChangePolicy;
use crate::GlobalStateLock;

/// provides a send() method to send a neptune transaction in one call.
#[derive(Debug)]
pub struct TransactionSender {
    global_state_lock: GlobalStateLock,
}

impl From<GlobalStateLock> for TransactionSender {
    fn from(global_state_lock: GlobalStateLock) -> Self {
        Self { global_state_lock }
    }
}

impl TransactionSender {
    // You should call offchain-notifications() on the returned value
    // to retrieve (and store) offchain notifications, if any.
    pub async fn send(
        &mut self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
    ) -> Result<TxCreationArtifacts, error::SendError> {
        TransactionInitiator {
            global_state_lock: self.global_state_lock.clone(),
        }
        .send(outputs, change_policy, fee, timestamp)
        .await
    }
}
