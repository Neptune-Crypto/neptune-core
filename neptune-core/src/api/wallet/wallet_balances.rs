// private module.  no need for module docs.

use serde::Deserialize;
use serde::Serialize;

use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::state::GlobalState;

/// represents the 4 native-currency wallet balances that neptune-core tracks.
///
/// naming: available vs total:
///
/// `available` includes utxos that are not time-locked for spending in the future.
/// `total` includes available utxos plus time-locked utxos.
///
/// naming: confirmed vs unconfirmed:
///
/// `confirmed` includes only utxos that have been recorded in the blockchain.
/// `unconfirmed` includes confirmed utxos plus utxos in the mempool.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct WalletBalances {
    /// balance of confirmed, available utxos
    pub confirmed_available: NativeCurrencyAmount,

    /// balance of all confirmed utxos.  (available and time-locked)
    pub confirmed_total: NativeCurrencyAmount,

    /// balance of unconfirmed, available utxos
    pub unconfirmed_available: NativeCurrencyAmount,

    /// balance of all unconfirmed utxos. (available and time-locked)
    pub unconfirmed_total: NativeCurrencyAmount,
}

impl std::fmt::Display for WalletBalances {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "\
            confirmed    -- total: {}, available: {}\n\
            unconfirmed  -- total: {}, available: {}\n",
            self.confirmed_total,
            self.confirmed_available,
            self.unconfirmed_total,
            self.unconfirmed_available,
        )
    }
}

impl WalletBalances {
    pub(super) async fn from_global_state(gs: &GlobalState, timestamp: Timestamp) -> Self {
        let wallet_status = gs.get_wallet_status_for_tip().await;
        let wallet_state = &gs.wallet_state;

        Self {
            confirmed_available: wallet_status.available_confirmed(timestamp),
            confirmed_total: wallet_status.total_confirmed(),
            unconfirmed_available: wallet_state
                .unconfirmed_available_balance(&wallet_status, timestamp),
            unconfirmed_total: wallet_state.unconfirmed_total_balance(&wallet_status),
        }
    }
}
