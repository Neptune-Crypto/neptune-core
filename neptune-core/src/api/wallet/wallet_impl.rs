use super::error::WalletError;
use super::wallet_balances::WalletBalances;
use crate::macros::state_lock_call_async;
use crate::macros::state_lock_call_mut_async;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::state::wallet::address::KeyType;
use crate::state::wallet::address::ReceivingAddress;
use crate::state::wallet::address::SpendingKey;
use crate::state::wallet::transaction_input::TxInputList;
use crate::state::wallet::transaction_output::TxOutput;
use crate::state::GlobalState;
use crate::state::StateLock;
use crate::GlobalStateLock;

/// Provides an API for interacting with the `neptune-core` wallet.
///
/// This type is built from a [StateLock] which means it can
/// use a [GlobalStateLock] or an already-acquired lock guard.
///
/// ### case: lock guard provided
///
/// If provided with a lock-guard then each method will simply use the guard.
/// Be careful though: if a mutable method is called on a read-guard a panic
/// will result.
///
/// If multiple Wallet method calls are made, the series of calls will see (or mutate)
/// a consistent, atomic view of global-state.
///
/// When `Wallet` is dropped, the guard will also be dropped and the lock
/// released.
///
/// If one wishes to continue using the guard then `StateLock::from(wallet)`
/// or `Wallet::into_inner()` may be used to regain ownership.
///
/// ### case: global-state-lock provided
///
/// If not provided with a lock guard then each method call will acquire the
/// lock in read-or write mode as necessary.
///
/// If multiple wallet methods are invoked they will be independent and any
/// changes will not be atomic across the series.
#[derive(Debug)]
pub struct Wallet<'a> {
    state_lock: StateLock<'a>,
}

impl<'a> From<StateLock<'a>> for Wallet<'a> {
    fn from(state_lock: StateLock<'a>) -> Self {
        Self { state_lock }
    }
}

impl From<GlobalStateLock> for Wallet<'_> {
    fn from(gsl: GlobalStateLock) -> Self {
        Self {
            state_lock: gsl.into(),
        }
    }
}

impl<'a> From<Wallet<'a>> for StateLock<'a> {
    fn from(w: Wallet<'a>) -> Self {
        w.state_lock
    }
}

// These methods just call a worker method, so the public API
// is easy to read and digest.
impl<'a> Wallet<'a> {
    /// convert into inner `StateLock`
    ///
    /// This is useful if the `StateLock` holds a lock guard and one wishes to
    /// continue using the guard.
    ///
    /// Note: this is a convienence `fn` as `into()` also exists.
    pub fn into_inner(self) -> StateLock<'a> {
        self.state_lock
    }

    /// generate a new spending key of the specified type
    ///
    /// Note: for receiving payments use [Wallet::next_receiving_address()].
    ///
    /// # important! read or risk losing funds!!!
    ///
    /// for most transactions, use [KeyType::Generation].
    ///
    /// [KeyType::Symmetric] must *only* be used if the payer and
    /// payee are the same party, ie the payer is sending to a wallet
    /// under their control.
    ///
    /// This is because when `KeyType::Symmetric` is specified the returned
    /// "address" is also the spending key.  Anyone who received this "address"
    /// can spend the funds.  So never give it out!
    ///
    /// `KeyType::Symmetric` is provided as an option for self-owned payments
    /// because it requires much less space on the blockchain, which can also
    /// potentially lessen fees.
    ///
    /// Note that by default `KeyType::Symmetric` is used for change outputs
    /// and (composer) block rewards.
    ///
    /// Be aware also that these considerations apply to each output `Utxo` of a
    /// transaction individually not the transaction as a whole.
    ///
    /// If in any doubt, just use [KeyType::Generation].
    pub async fn next_unused_spending_key(
        &mut self,
        key_type: KeyType,
    ) -> Result<SpendingKey, WalletError> {
        state_lock_call_mut_async!(
            &mut self.state_lock,
            worker::next_unused_spending_key,
            key_type
        )
        .await
    }

    /// generate a new receiving address of the specified type
    ///
    /// a payment recipient (payee) should call this method to obtain an address
    /// which can be provided to the payment sender (payer).
    ///
    /// # important! read or risk losing funds!!!
    ///
    /// for most transactions, use [KeyType::Generation].
    ///
    /// [KeyType::Symmetric] must *only* be used if the payer and
    /// payee are the same party, ie the payer is sending to a wallet
    /// under their control.
    ///
    /// This is because when `KeyType::Symmetric` is specified the returned
    /// "address" is also the spending key.  Anyone who received this "address"
    /// can spend the funds.  So never give it out!
    ///
    /// `KeyType::Symmetric` is provided as an option for self-owned payments
    /// because it requires much less space on the blockchain, which can also
    /// potentially lessen fees.
    ///
    /// Note that by default `KeyType::Symmetric` is used for change outputs
    /// and (composer) block rewards.
    ///
    /// Be aware also that these considerations apply to each output `Utxo` of a
    /// transaction individually not the transaction as a whole.
    ///
    /// If in any doubt, just use [KeyType::Generation].
    pub async fn next_receiving_address(
        &mut self,
        key_type: KeyType,
    ) -> Result<ReceivingAddress, WalletError> {
        Ok(self.next_unused_spending_key(key_type).await?.to_address())
    }

    /// get wallet balances as of timestamp
    ///
    /// Timestamp can be a date in the future in order to see what the balances
    /// would be at that time, with respect to time-locked utxos.
    ///
    /// If timestamp is in the past the result will be the same as if the
    /// present.
    pub async fn balances(&self, timestamp: Timestamp) -> WalletBalances {
        state_lock_call_async!(&self.state_lock, worker::balances, timestamp).await
    }

    /// Returns all spendable inputs in the wallet at provided time.
    ///
    /// Timestamp can be a date in the future in order to see what spendable
    /// inputs would be at that time, with respect to time-locked utxos.
    ///
    /// If timestamp is in the past the result will be the same as if the
    /// present.
    ///
    /// The order of returned inputs is undefined.
    pub async fn spendable_inputs(&self, timestamp: Timestamp) -> TxInputList {
        state_lock_call_async!(&self.state_lock, worker::spendable_inputs, timestamp).await
    }

    /// Gets the output of a sent transaction by its indices in the wallet.
    ///
    /// # Panics.
    /// The implementation detail is when `tx_ix` is out of its bound it crashes the node until
    /// <https://github.com/Neptune-Crypto/neptune-core/issues/816> is done.
    pub async fn sentoutput_by_indicies(
        &self,
        tx_ix: u64,
        utxo_ix: usize,
    ) -> Result<TxOutput, WalletError> {
        state_lock_call_async!(
            &self.state_lock,
            worker::sentoutput_by_indicies,
            tx_ix,
            utxo_ix
        )
        .await
    }
}

mod worker {
    use super::*;

    pub async fn next_unused_spending_key(
        gsm: &mut GlobalState,
        key_type: KeyType,
    ) -> Result<SpendingKey, WalletError> {
        let address = gsm.wallet_state.next_unused_spending_key(key_type).await;

        // persist wallet state to disk
        gsm.persist_wallet().await?;

        Ok(address)
    }

    pub async fn balances(gs: &GlobalState, timestamp: Timestamp) -> WalletBalances {
        WalletBalances::from_global_state(gs, timestamp).await
    }

    pub async fn spendable_inputs(gs: &GlobalState, timestamp: Timestamp) -> TxInputList {
        // Sadly we have to collect here because we can't hold `ref` after lock guard is dropped.
        gs.wallet_spendable_inputs(timestamp)
            .await
            .into_iter()
            .into()
    }

    /// returns result just in hope that some day failure in the indecies would be distinguished
    pub async fn sentoutput_by_indicies(
        gs: &GlobalState,
        tx_ix: u64,
        utxo_ix: usize,
        // block: Digest,
    ) -> Result<TxOutput, WalletError> {
        let tx_sent =
            crate::application::database::storage::storage_vec::traits::StorageVecBase::get(
                gs.wallet_state.wallet_db.sent_transactions(),
                tx_ix,
            )
            .await;
        tx_sent
            .tx_outputs
            .get(utxo_ix)
            .ok_or_else(|| WalletError::Failed("sent tx output index is out of bounds".to_string()))
            .cloned()
    }
}
