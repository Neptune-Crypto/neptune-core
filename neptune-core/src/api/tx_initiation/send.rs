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
//! use neptune_wallet::change_policy::ChangePolicy;
//! use export::GlobalStateLock;
//! use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
//! use neptune_wallet::address::ReceivingAddress;
//! use neptune_primitives::timestamp::Timestamp;
//! use export::TxCreationArtifacts;
//!
//! async fn my_send_transaction(gsl: GlobalStateLock, recipient: ReceivingAddress, amount: NativeCurrencyAmount, change_policy: ChangePolicy, fee: NativeCurrencyAmount) -> Result<TxCreationArtifacts, tx_initiation::error::SendError> {
//!     let outputs = vec![(recipient, amount)];
//!     let accept_lustrations = false;
//!
//!     send::TransactionSender::from(gsl)
//!         .send(
//!             outputs,
//!             change_policy,
//!             fee,
//!             Timestamp::now(),
//!             accept_lustrations,
//!         ).await
//! }
//! ```

use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_primitives::timestamp::Timestamp;
use neptune_wallet::change_policy::ChangePolicy;

use super::error;
use crate::api::tx_initiation::builder::tx_output_list_builder::OutputFormat;
use crate::api::tx_initiation::initiator::TransactionInitiator;
use crate::state::transaction::chained_tx_artifacts::ChainedTxArtifacts;
use crate::state::transaction::link_tx_artifacts::LinkTxArtifacts;
use crate::state::transaction::tx_creation_artifacts::TxCreationArtifacts;
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
        accept_lustrations: bool,
    ) -> Result<TxCreationArtifacts, error::SendError> {
        TransactionInitiator {
            global_state_lock: self.global_state_lock.clone(),
        }
        .send(outputs, change_policy, fee, timestamp, accept_lustrations)
        .await
    }

    /// Send a chained transaction, paying with unconfirmed funds. See
    /// [`TransactionInitiator::send_chained`].
    pub async fn send_chained(
        &mut self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
    ) -> Result<ChainedTxArtifacts, error::SendError> {
        TransactionInitiator {
            global_state_lock: self.global_state_lock.clone(),
        }
        .send_chained(outputs, change_policy, fee, timestamp)
        .await
    }

    /// Send a chained transaction that stays a link transaction. See
    /// [`TransactionInitiator::send_chained_link`].
    pub async fn send_chained_link(
        &mut self,
        outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
        change_policy: ChangePolicy,
        fee: NativeCurrencyAmount,
        timestamp: Timestamp,
    ) -> Result<LinkTxArtifacts, error::SendError> {
        TransactionInitiator {
            global_state_lock: self.global_state_lock.clone(),
        }
        .send_chained_link(outputs, change_policy, fee, timestamp)
        .await
    }
}
