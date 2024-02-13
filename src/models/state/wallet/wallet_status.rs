use std::fmt::Display;

use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::models::blockchain::transaction::{neptune_coins::NeptuneCoins, utxo::Utxo};
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletStatusElement(pub u64, pub Utxo);

impl Display for WalletStatusElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string: String = format!("({}, {:?})", self.0, self.1);
        write!(f, "{}", string)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletStatus {
    pub synced_unspent_amount: NeptuneCoins,
    pub synced_unspent: Vec<(WalletStatusElement, MsMembershipProof)>,
    pub unsynced_unspent_amount: NeptuneCoins,
    pub unsynced_unspent: Vec<WalletStatusElement>,
    pub synced_spent_amount: NeptuneCoins,
    pub synced_spent: Vec<WalletStatusElement>,
    pub unsynced_spent_amount: NeptuneCoins,
    pub unsynced_spent: Vec<WalletStatusElement>,
}

impl Display for WalletStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let synced_unspent_count: usize = self.synced_unspent.len();
        let synced_unspent: String = format!(
            "synced, unspent UTXOS: count: {}, amount: {:?}\n[{}]",
            synced_unspent_count,
            self.synced_unspent_amount,
            self.synced_unspent
                .iter()
                .map(|x| x.0.to_string())
                .join(",")
        );
        let unsynced_unspent_count: usize = self.unsynced_unspent.len();
        let unsynced_unspent: String = format!(
            "unsynced, unspent UTXOS: count: {}, amount: {:?}\n[{}]",
            unsynced_unspent_count,
            self.unsynced_unspent_amount,
            self.unsynced_unspent
                .iter()
                .map(|x| x.to_string())
                .join(",")
        );
        let synced_spent_count: usize = self.synced_spent.len();
        let synced_spent: String = format!(
            "synced, spent UTXOS: count: {}, amount: {:?}\n[{}]",
            synced_spent_count,
            self.synced_spent_amount,
            self.synced_spent.iter().map(|x| x.to_string()).join(",")
        );
        let unsynced_spent_count: usize = self.unsynced_spent.len();
        let unsynced_spent: String = format!(
            "unsynced, spent UTXOS: count: {}, amount: {:?}\n[{}]",
            unsynced_spent_count,
            self.unsynced_spent_amount,
            self.unsynced_spent.iter().map(|x| x.to_string()).join(",")
        );
        write!(
            f,
            "{}\n\n{}\n\n{}\n\n{}",
            synced_unspent, unsynced_unspent, synced_spent, unsynced_spent
        )
    }
}
