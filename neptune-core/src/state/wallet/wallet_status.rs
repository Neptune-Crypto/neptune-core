use std::collections::HashSet;

use itertools::Itertools;
use num_traits::CheckedSub;
use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumIter;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;

use crate::api::export::AdditionRecord;
use crate::api::export::BlockHeight;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::state::wallet::wallet_db_tables::StrongUtxoKey;
use crate::util_types::mutator_set::commit;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct IncomingMempoolUtxo {
    pub(crate) utxo: Utxo,
    pub(crate) sender_randomness: Digest,
    pub(crate) receiver_preimage: Digest,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct OutgoingMempoolUtxo {
    pub(crate) utxo: Utxo,
    pub(crate) aocl_leaf_index: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
enum MempoolUtxo {
    Incoming(IncomingMempoolUtxo),
    Outgoing(OutgoingMempoolUtxo),
}

impl From<IncomingMempoolUtxo> for MempoolUtxo {
    fn from(value: IncomingMempoolUtxo) -> Self {
        Self::Incoming(value)
    }
}

impl From<OutgoingMempoolUtxo> for MempoolUtxo {
    fn from(value: OutgoingMempoolUtxo) -> Self {
        Self::Outgoing(value)
    }
}

impl MempoolUtxo {
    fn is_incoming(&self) -> bool {
        matches!(self, Self::Incoming(_))
    }

    fn is_outgoing(&self) -> bool {
        matches!(self, Self::Outgoing(_))
    }

    fn utxo(&self) -> &Utxo {
        match self {
            MempoolUtxo::Incoming(imu) => &imu.utxo,
            MempoolUtxo::Outgoing(omu) => &omu.utxo,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct UnsyncedUtxo {
    pub(crate) utxo: Utxo,
    pub(crate) sender_randomness: Digest,
    pub(crate) receiver_preimage: Digest,
    pub(crate) aocl_leaf_index: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SyncedUtxo {
    pub(crate) utxo: Utxo,
    pub(crate) sender_randomness: Digest,
    pub(crate) receiver_preimage: Digest,
    pub(crate) aocl_leaf_index: u64,
    pub(crate) confirmed_in_block: BlockHeight,

    /// If set, the UTXO was spent.
    ///
    /// If the node does not have access to a full historical view, for
    /// instance, because of wallet rescans and/or recovery, the correct block
    /// height might not be known. In this case, this option will be set anyway
    /// and the wrapped value will be equal to that of `confirmed_in_block`.
    ///
    /// Any discrepancy (of the wrong spending block height) does not affect
    /// currently spendable UTXOs. It may affect historical balances. (And if it
    /// does affect historical balances, this convention errs on the safe side
    /// by reporting the smaller balance.)
    spent_in_block: Option<BlockHeight>,
}

impl SyncedUtxo {
    pub(crate) fn new_unspent(
        utxo: Utxo,
        aocl_leaf_index: u64,
        sender_randomness: Digest,
        receiver_preimage: Digest,
        confirmed_in_block: BlockHeight,
    ) -> Self {
        Self {
            aocl_leaf_index,
            utxo,
            sender_randomness,
            receiver_preimage,
            confirmed_in_block,
            spent_in_block: None,
        }
    }

    pub(crate) fn new_spent(
        utxo: Utxo,
        aocl_leaf_index: u64,
        sender_randomness: Digest,
        receiver_preimage: Digest,
        confirmed_in_block: BlockHeight,
        spent_in_block: BlockHeight,
    ) -> Self {
        Self {
            aocl_leaf_index,
            utxo,
            sender_randomness,
            receiver_preimage,
            confirmed_in_block,
            spent_in_block: Some(spent_in_block),
        }
    }

    fn addition_record(&self) -> AdditionRecord {
        let item = Tip5::hash(&self.utxo);
        commit(item, self.sender_randomness, self.receiver_preimage.hash())
    }

    pub(crate) fn strong_utxo_key(&self) -> StrongUtxoKey {
        StrongUtxoKey::new(self.addition_record(), self.aocl_leaf_index)
    }
}

/// Represents a snapshot of
/// [`MonitoredUtxo`](super::monitored_utxo::MonitoredUtxo)s in the wallet at a
/// given point in time, as well as mempool-UTXOs that affect the wallet balance
/// to capture impending changes.
///
/// The UTXOs are divided into two primary groups:
///
///  1. **Synced** UTXOs are those which have a mutator set membership proof for
///     the current tip, *regardless of the snapshot time*.
///
///  2. **Mempool** UTXOs are inputs or outputs to transactions that live in the
///     mempool and might be confirmed at any moment.
///
///  3. **Unsynced** UTXOs are those which have no mutator set membership proof
///     or one for a block that is different from the current tip. (This group
///     is presently only used by unit tests and is a candidate for removal.)
///
/// Synced UTXOs are further divided into:
///
///  a) **Unspent** describes UTXOs that have not (yet) been used as an input in
///     a confirmed block.
///
///  b) **Spent** describes UTXOs that been used as an input in a confirmed
///     block.
///
/// Furthermore, UTXOs are classified based on their effect on the wallet
/// balance(s):
///
///  a) **Incoming** describes outputs of transactions that increase the
///     wallet balance(s).
///
///  b) **Outgoing** describes inputs of transactions that decrease the
///     wallet balance(s).
///
/// Mempool UTXOs can be incoming or outgoing. Unspent synced UTXOs are always
/// incoming. However, *spent* synced UTXOs are neither incoming nor outgoing
/// (and this lack of category is not a problem because spent synced UTXOs are
/// filtered out before it becomes relevant).
///
/// For synced-unspent UTXOs and for incoming-mempool UTXOs, a further
/// distinction is made:
///
///  i:  **Available* are UTXOs that are spendable now. In other words, they
///      have no time-lock or they do and the time-lock has already expired
///      (release date is in the past).
///
///  ii: **Time-locked** UTXOs are those which are not spendable until a certain
///      time, because they have a time-lock and the release date is in the
///      future.
///
/// This struct serves two purposes. One is to aid in the rapid calculation of a
/// node's various balances, which counter-intuitively denote multiple numbers
/// depending on
///  - whether to count mempool transactions;
///  - after how many blocks to count transactions as "confirmed";
///  - whether to count time-locked coins.
///
/// The other purpose is to enable input-selection when initiating transactions.
///
/// [`WalletStatus`] is *not* responsible for managing mutator set membership
/// proofs or other witness information needed to unlock and spend UTXOs. It
/// carries only data necessary to determine whether to include a UTXO as an
/// input in a transaction and, correspondingly, whether to count its
/// contribution to the wallet balance.
///
/// Note: [`WalletStatus`] is generated by
/// [`super::wallet_state::WalletState::get_wallet_status`].
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct WalletStatus {
    synced: Vec<SyncedUtxo>,
    unsynced: Vec<UnsyncedUtxo>,
    mempool: Vec<MempoolUtxo>,
}

impl WalletStatus {
    /// Create a new [`WalletStatus`] object with synced and unsynced UTXOs from
    /// the wallet database.
    ///
    /// To populate the [`WalletStatus`] with mempool UTXOs, call
    /// [`WalletStatus::with_mempool`].
    pub(crate) fn new(synced: Vec<SyncedUtxo>, unsynced: Vec<UnsyncedUtxo>) -> Self {
        Self {
            synced,
            unsynced,
            mempool: vec![],
        }
    }

    /// Set the list of balance-affecting UTXOs in the mempool, or overwrite it
    /// if already set.
    pub(crate) fn with_mempool(
        mut self,
        incoming: Vec<IncomingMempoolUtxo>,
        outgoing: Vec<OutgoingMempoolUtxo>,
    ) -> Self {
        self.mempool = incoming
            .into_iter()
            .map(MempoolUtxo::from)
            .chain(outgoing.into_iter().map(MempoolUtxo::from))
            .collect_vec();
        self
    }

    /// Return an iterator over all synced UTXOs that were not spent before the
    /// given threshold block height.
    ///
    /// If the threshold is unset, all blocks count. Meaning that the UTXO is
    /// considered spent if it was spent in the most recent block.
    pub(crate) fn synced_unspent(
        &self,
        maybe_threshold: Option<BlockHeight>,
    ) -> impl Iterator<Item = &SyncedUtxo> {
        self.synced
            .iter()
            .filter(move |su| match (su.spent_in_block, maybe_threshold) {
                (Some(_), None) =>
                // The UTXO was spent somewhere and we are not discounting any
                // blocks. So it is spent in our view.
                {
                    false
                }
                (None, _) =>
                // The UTXO was never spent in any view, with or without
                // truncation.
                {
                    true
                }
                (Some(spending_block), Some(threshold)) =>
                // The UTXO was spent, but was it spent before the cutoff point?
                {
                    spending_block > threshold
                }
            })
    }

    /// Return an iterator over all synced UTXOs that were spent before the
    /// given threshold block height.
    pub(crate) fn synced_spent(
        &self,
        maybe_threshold: Option<BlockHeight>,
    ) -> impl Iterator<Item = &SyncedUtxo> {
        self.synced
            .iter()
            .filter(move |su| match (su.spent_in_block, maybe_threshold) {
                (Some(_), None) =>
                // The UTXO was spent somewhere and we are not discounting any
                // blocks. So it is spent in our view.
                {
                    true
                }
                (None, _) =>
                // The UTXO was never spent in any view, with or without
                // truncation.
                {
                    false
                }
                (Some(spending_block), Some(threshold)) =>
                // The UTXO was spent, but was it spent before the cutoff point?
                {
                    spending_block <= threshold
                }
            })
    }

    /// Return an iterator over all synced UTXOs that were confirmed and not
    /// spent before the given threshold block height.
    fn confirmed_unspent_utxos(&self, threshold: BlockHeight) -> impl Iterator<Item = &Utxo> {
        self.synced_unspent(Some(threshold))
            .filter(move |su| su.confirmed_in_block <= threshold)
            .map(|su| &su.utxo)
    }

    /// Compute the total balance (liquid or time-locked with any release date)
    /// of coins with confirming block height below or equal to the given
    /// threshold block height.
    pub fn confirmed_total_balance(
        &self,
        threshold_block_height: BlockHeight,
    ) -> NativeCurrencyAmount {
        self.confirmed_unspent_utxos(threshold_block_height)
            .map(|utxo| utxo.get_native_currency_amount())
            .sum::<NativeCurrencyAmount>()
    }

    /// Compute the balance of spendable coins (liquid or time-locked with
    /// already-expired release date) with confirming block height below or
    /// equal to the given block height.
    pub fn confirmed_available_balance(
        &self,
        threshold_block_height: BlockHeight,
        timestamp: Timestamp,
    ) -> NativeCurrencyAmount {
        self.confirmed_unspent_utxos(threshold_block_height)
            .filter(|utxo| utxo.can_spend_at(timestamp))
            .map(|utxo| utxo.get_native_currency_amount())
            .sum::<NativeCurrencyAmount>()
    }

    /// Return an iterator over all incoming UTXOs, whether confirmed in some
    /// block or still in the mempool, but do filter out UTXOs that have already
    /// been spent somewhere.
    ///
    /// Note that there is no counterpart `all_outgoing_utxos` because
    /// downstream, synced spent UTXOs are treated differently from outgoing
    /// mempool UTXOs.
    fn all_incoming_utxos(&self) -> impl Iterator<Item = &Utxo> {
        self.synced_unspent(None).map(|su| &su.utxo).chain(
            self.mempool
                .iter()
                .filter(|mu| mu.is_incoming())
                .map(|mu| mu.utxo()),
        )
    }

    /// Return an iterator over all outgoing UTXOs in the mempool.
    ///
    /// Note that spent synced UTXOs are never counted as outgoing; instead,
    /// they are filtered out prior to counting the balance or to the set of
    /// spendable UTXOs.
    fn outgoing_mempool_utxos(&self) -> impl Iterator<Item = &Utxo> {
        self.mempool
            .iter()
            .filter(|mu| mu.is_outgoing())
            .map(|mu| mu.utxo())
    }

    /// Compute the total balance (liquid or time-locked with any release date)
    /// of coins with any number of confirmations (including zero).
    pub(crate) fn unconfirmed_total_balance(&self) -> NativeCurrencyAmount {
        let incoming = self
            .all_incoming_utxos()
            .map(|utxo| utxo.get_native_currency_amount())
            .sum::<NativeCurrencyAmount>();
        let outgoing = self
            .outgoing_mempool_utxos()
            .map(|utxo| utxo.get_native_currency_amount())
            .sum::<NativeCurrencyAmount>();
        incoming
            .checked_sub(&outgoing)
            // **Can be negative**: if two transactions spending the same UTXO
            // live in the mempool.
            .unwrap_or(NativeCurrencyAmount::zero())
    }

    /// Compute the balance of spendable coins (liquid or time-locked with
    /// already-expired release date) of coins with any number of confirmations
    /// (including zero).
    pub(crate) fn unconfirmed_available_balance(
        &self,
        timestamp: Timestamp,
    ) -> NativeCurrencyAmount {
        let incoming = self
            .all_incoming_utxos()
            .filter(|utxo| utxo.can_spend_at(timestamp))
            .map(|utxo| utxo.get_native_currency_amount())
            .sum::<NativeCurrencyAmount>();
        let outgoing = self
            .outgoing_mempool_utxos()
            .map(|utxo| utxo.get_native_currency_amount())
            .sum::<NativeCurrencyAmount>();
        incoming
            .checked_sub(&outgoing)
            // **Can be negative**: if two transactions spending the same UTXO
            // live in the mempool.
            .unwrap_or(NativeCurrencyAmount::zero())
    }

    /// Return a list of spendable inputs.
    ///
    /// A UTXO is spendable if it is (all of)
    ///  - synced (= confirmed by at least one block),
    ///  - spendable now (no time-locked present or present-but-expired),
    ///  - not spent by any blocks,
    ///  - not spent in the mempool either.
    ///
    /// We do not support chaining transactions yet but when we do we may
    /// consider relaxing the "synced" requirement and allowing inputs that are
    /// generated by a transaction in the mempool.
    pub(crate) fn spendable_inputs(&self, timestamp: Timestamp) -> Vec<SyncedUtxo> {
        let confirmed_unspent = self
            .synced_unspent(None)
            .filter(|su| su.utxo.can_spend_at(timestamp));
        let mempool_spent_aocl_leaf_indices = self
            .mempool
            .iter()
            .filter_map(|mu| match mu {
                MempoolUtxo::Incoming(_) => None,
                MempoolUtxo::Outgoing(omu) => Some(omu.aocl_leaf_index),
            })
            .collect::<HashSet<_>>();
        confirmed_unspent
            .filter(|su| !mempool_spent_aocl_leaf_indices.contains(&su.aocl_leaf_index))
            .cloned()
            .collect_vec()
    }
}

#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, Default, EnumIter, strum::Display,
)]
#[strum(serialize_all = "lowercase")]
pub enum WalletStatusExportFormat {
    #[default]
    Json,
    Table,
}

impl WalletStatusExportFormat {
    pub fn export(&self, wallet_status: &WalletStatus) -> String {
        match self {
            Self::Json => match serde_json::to_string_pretty(&wallet_status) {
                Ok(pretty_string) => pretty_string,
                Err(e) => format!("JSON format error: {e:?}"),
            },
            Self::Table => {
                fn unsynced_row(wse: &UnsyncedUtxo) -> String {
                    let utxo = &wse.utxo;
                    let native_currency_amount = if utxo.has_native_currency() {
                        utxo.get_native_currency_amount().display_lossless()
                    } else {
                        "-".to_string()
                    };
                    let release_date = utxo
                        .release_date()
                        .map_or("-".to_string(), |t| t.standard_format());
                    format!(
                        "| {:>7} | {:>44} | {:^29} |",
                        wse.aocl_leaf_index, native_currency_amount, release_date
                    )
                }
                fn synced_row(wse: &SyncedUtxo) -> String {
                    let utxo = &wse.utxo;
                    let native_currency_amount = if utxo.has_native_currency() {
                        utxo.get_native_currency_amount().display_lossless()
                    } else {
                        "-".to_string()
                    };
                    let release_date = utxo
                        .release_date()
                        .map_or("-".to_string(), |t| t.standard_format());
                    format!(
                        "| {:>7} | {:>44} | {:^29} |",
                        wse.aocl_leaf_index, native_currency_amount, release_date
                    )
                }
                fn mempool_row(mu: &MempoolUtxo) -> String {
                    let utxo = mu.utxo();
                    let native_currency_amount = if utxo.has_native_currency() {
                        utxo.get_native_currency_amount().display_lossless()
                    } else {
                        "-".to_string()
                    };
                    let release_date = utxo
                        .release_date()
                        .map_or("-".to_string(), |t| t.standard_format());
                    format!(
                        "| {:>7} | {:>44} | {:^29} |",
                        " ", native_currency_amount, release_date
                    )
                }

                let header = format!(
                    "\
                    | aocl li | {:^44} | {:^29} |\n\
                    |:-------:|-{}:|:{}-|",
                    "native currency amount (coins)",
                    "release date",
                    (0..44).map(|_| "-").join(""),
                    (0..29).map(|_| "-").join("")
                );

                format!(
                    "\n\
                    **Synced Unspent**\n\
                    \n\
                    {header}\n\
                    {}\n\n\
                    Total:      {:>44} \n\
                    \n\
                    **Synced Spent**\n\
                    \n\
                    {header}\n\
                    {}\n\n\
                    Total:      {:>44} \n\
                    \n\
                    **Mempool IN**\n\
                    \n\
                    {header}\n\
                    {}\n\n\
                    Total:      {:>44} \n\
                    \n\
                    **Mempool OUT**\n\
                    \n\
                    {header}\n\
                    {}\n\n\
                    Total:      {:>44} \n\
                    \n\
                    **Unsynced**\n\
                    \n\
                    {header}\n\
                    {}\n\n\
                    Total:      {:>44} \n",
                    wallet_status
                        .synced_unspent(None)
                        .map(synced_row)
                        .join("\n"),
                    wallet_status
                        .synced_unspent(None)
                        .map(|su| su.utxo.get_native_currency_amount())
                        .sum::<NativeCurrencyAmount>()
                        .display_lossless(),
                    wallet_status.synced_spent(None).map(synced_row).join("\n"),
                    wallet_status
                        .synced_spent(None)
                        .map(|su| su.utxo.get_native_currency_amount())
                        .sum::<NativeCurrencyAmount>()
                        .display_lossless(),
                    wallet_status
                        .mempool
                        .iter()
                        .filter(|mu| mu.is_incoming())
                        .map(mempool_row)
                        .join("\n"),
                    wallet_status
                        .mempool
                        .iter()
                        .filter(|mu| mu.is_incoming())
                        .map(|mu| mu.utxo())
                        .map(|utxo| utxo.get_native_currency_amount())
                        .sum::<NativeCurrencyAmount>(),
                    wallet_status
                        .mempool
                        .iter()
                        .filter(|mu| mu.is_outgoing())
                        .map(mempool_row)
                        .join("\n"),
                    wallet_status
                        .mempool
                        .iter()
                        .filter(|mu| mu.is_outgoing())
                        .map(|mu| mu.utxo())
                        .map(|utxo| utxo.get_native_currency_amount())
                        .sum::<NativeCurrencyAmount>(),
                    wallet_status.unsynced.iter().map(unsynced_row).join("\n"),
                    wallet_status
                        .unsynced
                        .iter()
                        .map(|uu| uu.utxo.get_native_currency_amount())
                        .sum::<NativeCurrencyAmount>()
                        .display_lossless(),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl WalletStatus {
        pub(crate) fn num_elements(&self) -> usize {
            self.mempool.len() + self.synced.len() + self.unsynced.len()
        }

        pub(crate) fn num_unsynced(&self) -> usize {
            self.unsynced.len()
        }
    }
}
