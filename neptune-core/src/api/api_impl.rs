// private module.  no need for module docs.

use crate::api;
use crate::GlobalStateLock;

/// central interface for accessing api types.
///
/// This type is provided for convenience only. All type can be instantiated
/// manually instead.
///
/// In turn, this type can be instantiated via [GlobalStateLock::api()]
/// or [GlobalStateLock::api_mut()].
///
/// A recommended (concise) usage pattern is:
///
/// ```
/// # use neptune_cash::api::export::GlobalStateLock;
/// # use neptune_cash::api::export::WalletBalances;
/// # use neptune_cash::api::export::Timestamp;
///
/// # async fn get_balances(global_state_lock: GlobalStateLock) -> WalletBalances {
/// global_state_lock
///     .api()
///     .wallet()
///     .balances(Timestamp::now()).await
/// # }
/// ```
#[derive(Debug)]
pub struct Api {
    global_state_lock: GlobalStateLock,
}

impl From<GlobalStateLock> for Api {
    fn from(global_state_lock: GlobalStateLock) -> Self {
        Self { global_state_lock }
    }
}

impl Api {
    /// retrieve a transaction initiator in a mutable context.
    pub fn tx_initiator_mut(&mut self) -> api::tx_initiation::initiator::TransactionInitiator {
        self.global_state_lock.clone().into()
    }

    /// retrieve a transaction initiator in immutable context.
    pub fn tx_initiator(&self) -> api::tx_initiation::initiator::TransactionInitiator {
        self.global_state_lock.clone().into()
    }

    /// retrieve a transaction sender in mutable context.
    pub fn tx_sender_mut(&mut self) -> api::tx_initiation::send::TransactionSender {
        self.global_state_lock.clone().into()
    }

    /// retrieve a transaction sender in mutable context.
    pub fn regtest_mut(&mut self) -> api::regtest::RegTest {
        self.global_state_lock.clone().into()
    }

    /// retrieve a transaction recipient in mutable context.
    pub fn wallet_mut(&mut self) -> api::wallet::Wallet<'_> {
        self.global_state_lock.clone().into()
    }

    /// retrieve a transaction recipient in immutable context.
    pub fn wallet(&self) -> api::wallet::Wallet<'_> {
        self.global_state_lock.clone().into()
    }
}

#[cfg(test)]
impl Api {
    /// retrieve a crate-internal transaction initiator
    ///
    /// for calling "traditional" create_transaction()
    pub(crate) fn tx_initiator_internal(
        &self,
    ) -> api::tx_initiation::test_util::TransactionInitiatorInternal {
        self.global_state_lock.clone().into()
    }
}
