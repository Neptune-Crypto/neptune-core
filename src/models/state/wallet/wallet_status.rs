use std::fmt::Display;

use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;

use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletStatusElement {
    pub aocl_leaf_index: u64,
    pub utxo: Utxo,
}

impl WalletStatusElement {
    pub fn new(aocl_leaf_index: u64, utxo: Utxo) -> Self {
        Self {
            aocl_leaf_index,
            utxo,
        }
    }
}

impl Display for WalletStatusElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string: String = format!("({}, {:?})", self.aocl_leaf_index, self.utxo);
        write!(f, "{}", string)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletStatus {
    /// UTXOs that have a synced and valid membership proof
    pub synced_unspent: Vec<(WalletStatusElement, MsMembershipProof)>,

    /// UTXOs that do not have a synced membership proof
    pub unsynced: Vec<WalletStatusElement>,

    /// UTXOs that have a synced membership proof but it is invalid (probably
    /// because it was spent)
    pub synced_spent: Vec<WalletStatusElement>,
}

impl WalletStatus {
    pub fn synced_unspent_liquid_amount(&self, timestamp: Timestamp) -> NativeCurrencyAmount {
        self.synced_unspent
            .iter()
            .map(|(wse, _msmp)| &wse.utxo)
            .filter(|utxo| utxo.can_spend_at(timestamp))
            .map(|utxo| utxo.get_native_currency_amount())
            .sum::<NativeCurrencyAmount>()
    }
    pub fn synced_unspent_timelocked_amount(&self, timestamp: Timestamp) -> NativeCurrencyAmount {
        self.synced_unspent
            .iter()
            .map(|(wse, _msmp)| &wse.utxo)
            .filter(|utxo| utxo.is_timelocked_but_otherwise_spendable_at(timestamp))
            .map(|utxo| utxo.get_native_currency_amount())
            .sum::<NativeCurrencyAmount>()
    }

    /// Sum of value of monitored unsynced UTXOs.
    ///
    /// Does not check for spendability, as that can only be determined once the
    /// monitored UTXO is synced.
    pub fn unsynced_amount(&self) -> NativeCurrencyAmount {
        self.unsynced
            .iter()
            .map(|wse| wse.utxo.get_native_currency_amount())
            .sum::<NativeCurrencyAmount>()
    }

    pub fn synced_spent_amount(&self) -> NativeCurrencyAmount {
        self.synced_spent
            .iter()
            .map(|wse| wse.utxo.get_native_currency_amount())
            .sum::<NativeCurrencyAmount>()
    }
}

impl Display for WalletStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let now = Timestamp::now();
        let synced_unspent_available_count: usize = self
            .synced_unspent
            .iter()
            .filter(|(wse, _mnmp)| wse.utxo.can_spend_at(now))
            .count();
        let synced_unspent_available: String = format!(
            "synced, unspent available UTXOS: count: {}, amount: {:?}\n[{}]",
            synced_unspent_available_count,
            self.synced_unspent_liquid_amount(now),
            self.synced_unspent
                .iter()
                .filter(|(wse, _mnmp)| wse.utxo.can_spend_at(now))
                .map(|x| x.0.to_string())
                .join(",")
        );
        let synced_unspent_timelocked_count: usize = self
            .synced_unspent
            .iter()
            .filter(|(wse, _mnmp)| wse.utxo.is_timelocked_but_otherwise_spendable_at(now))
            .count();
        let synced_unspent_timelocked: String = format!(
            "synced, unspent timelocked UTXOS: count: {}, amount: {:?}\n[{}]",
            synced_unspent_timelocked_count,
            self.synced_unspent_timelocked_amount(now),
            self.synced_unspent
                .iter()
                .filter(|(wse, _mnmp)| wse.utxo.is_timelocked_but_otherwise_spendable_at(now))
                .map(|x| x.0.to_string())
                .join(",")
        );
        let unsynced_count: usize = self.unsynced.len();
        let unsynced: String = format!(
            "unsynced UTXOS: count: {}, amount: {:?}\n[{}]",
            unsynced_count,
            self.unsynced_amount(),
            self.unsynced.iter().map(|x| x.to_string()).join(",")
        );
        let synced_spent_count: usize = self.synced_spent.len();
        let synced_spent: String = format!(
            "synced, spent UTXOS: count: {}, amount: {:?}\n[{}]",
            synced_spent_count,
            self.synced_spent_amount(),
            self.synced_spent.iter().map(|x| x.to_string()).join(",")
        );
        write!(
            f,
            "{}\n\n{}\n\n{}\n\n{}",
            synced_unspent_available, synced_unspent_timelocked, unsynced, synced_spent,
        )
    }
}
