use std::fmt::Display;

use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;

use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::consensus::timestamp::Timestamp;
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
    pub synced_unspent: Vec<(WalletStatusElement, MsMembershipProof)>,
    pub unsynced_unspent: Vec<WalletStatusElement>,
    pub synced_spent: Vec<WalletStatusElement>,
    pub unsynced_spent: Vec<WalletStatusElement>,
    pub mempool_spent: Vec<Utxo>,
    pub mempool_unspent: Vec<(Utxo, MsMembershipProof)>,
}

// action         synced_unspent   synced_spent         mempool_unspent      mempool_spent

// coinbase       100
// send 5         100                                   95                   100
// send 10        100                                   85                   100,95
// coinbase       100,85           100,95

// synced_unspent - intersection(synced_unspent, mempool_spent) + mempool_unspent

impl WalletStatus {
    pub fn synced_unspent_available_amount(&self, timestamp: Timestamp) -> NeptuneCoins {
        self.synced_unspent
            .iter()
            .map(|(wse, _msmp)| &wse.utxo)
            .filter(|utxo| utxo.can_spend_at(timestamp))
            .map(|utxo| utxo.get_native_currency_amount())
            .sum::<NeptuneCoins>()
    }
    pub fn synced_unspent_timelocked_amount(&self, timestamp: Timestamp) -> NeptuneCoins {
        self.synced_unspent
            .iter()
            .map(|(wse, _msmp)| &wse.utxo)
            .filter(|utxo| utxo.is_timelocked_but_otherwise_spendable_at(timestamp))
            .map(|utxo| utxo.get_native_currency_amount())
            .sum::<NeptuneCoins>()
    }
    pub fn unsynced_unspent_amount(&self) -> NeptuneCoins {
        self.unsynced_unspent
            .iter()
            .map(|wse| wse.utxo.get_native_currency_amount())
            .sum::<NeptuneCoins>()
    }
    pub fn synced_spent_amount(&self) -> NeptuneCoins {
        self.synced_spent
            .iter()
            .map(|wse| wse.utxo.get_native_currency_amount())
            .sum::<NeptuneCoins>()
    }
    pub fn unsynced_spent_amount(&self) -> NeptuneCoins {
        self.unsynced_spent
            .iter()
            .map(|wse| wse.utxo.get_native_currency_amount())
            .sum::<NeptuneCoins>()
    }

    pub fn unconfirmed_unspent_utxos_iter(
        &self,
    ) -> impl Iterator<Item = (&Utxo, &MsMembershipProof)> {
        self.synced_unspent
            .iter()
            .map(|(wse, msmp)| (&wse.utxo, msmp))
            .chain(self.mempool_unspent.iter().map(|(a, b)| (a, b)))
            .filter(|(utxo, _)| !self.mempool_spent.contains(utxo))
    }
    pub fn unconfirmed_unspent_available_utxos_iter(
        &self,
        timestamp: Timestamp,
    ) -> impl Iterator<Item = (&Utxo, &MsMembershipProof)> {
        self.unconfirmed_unspent_utxos_iter()
            .filter(move |(utxo, _)| utxo.can_spend_at(timestamp))
    }
    pub fn unconfirmed_unspent_available_amount(&self, timestamp: Timestamp) -> NeptuneCoins {
        self.unconfirmed_unspent_available_utxos_iter(timestamp)
            .map(|(utxo, _)| utxo.get_native_currency_amount())
            .sum::<NeptuneCoins>()
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
            self.synced_unspent_available_amount(now),
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
        let unsynced_unspent_count: usize = self.unsynced_unspent.len();
        let unsynced_unspent: String = format!(
            "unsynced, unspent UTXOS: count: {}, amount: {:?}\n[{}]",
            unsynced_unspent_count,
            self.unsynced_unspent_amount(),
            self.unsynced_unspent
                .iter()
                .map(|x| x.to_string())
                .join(",")
        );
        let synced_spent_count: usize = self.synced_spent.len();
        let synced_spent: String = format!(
            "synced, spent UTXOS: count: {}, amount: {:?}\n[{}]",
            synced_spent_count,
            self.synced_spent_amount(),
            self.synced_spent.iter().map(|x| x.to_string()).join(",")
        );
        let unsynced_spent_count: usize = self.unsynced_spent.len();
        let unsynced_spent: String = format!(
            "unsynced, spent UTXOS: count: {}, amount: {:?}\n[{}]",
            unsynced_spent_count,
            self.unsynced_spent_amount(),
            self.unsynced_spent.iter().map(|x| x.to_string()).join(",")
        );
        write!(
            f,
            "{}\n\n{}\n\n{}\n\n{}\n\n{}",
            synced_unspent_available,
            synced_unspent_timelocked,
            unsynced_unspent,
            synced_spent,
            unsynced_spent
        )
    }
}
