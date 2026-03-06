//! provides an interface for working with transaction inputs

use std::ops::Deref;

use serde::Deserialize;
use serde::Serialize;

use crate::api::export::BlockHeight;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::state::wallet::wallet_status::SyncedUtxo;

/// Represents a potential transaction input UTXO.
///
/// Besides the UTXO, it contains
///  - index data for fetching membership proof and witness data;
///  - metadata for applying filtering and prioritization policies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputCandidate {
    pub synced_utxo: SyncedUtxo,
    pub number_of_confirmations: usize,
}

impl InputCandidate {
    pub(crate) fn from_synced_utxo(
        synced_utxo: SyncedUtxo,
        current_block_height: BlockHeight,
    ) -> Self {
        let next_block_height = current_block_height.next();
        let number_of_confirmations =
            usize::try_from(next_block_height - synced_utxo.confirmed_in_block).unwrap_or(0);
        Self {
            synced_utxo,
            number_of_confirmations,
        }
    }
}

impl Deref for InputCandidate {
    type Target = SyncedUtxo;

    fn deref(&self) -> &Self::Target {
        &self.synced_utxo
    }
}

impl InputCandidate {
    pub fn aocl_leaf_index(&self) -> u64 {
        self.synced_utxo.aocl_leaf_index
    }

    /// retrieve native currency amount
    pub fn native_currency_amount(&self) -> NativeCurrencyAmount {
        self.utxo.get_native_currency_amount()
    }
}
