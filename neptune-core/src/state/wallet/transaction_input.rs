//! provides an interface for working with transaction inputs

use std::ops::Deref;
use std::ops::DerefMut;

use serde::Deserialize;
use serde::Serialize;

use super::unlocked_utxo::UnlockedUtxo;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::removal_record::RemovalRecord;

/// represents a transaction input
///
/// this is a newtype wrapper around UnlockedUtxo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInput(UnlockedUtxo);

impl From<UnlockedUtxo> for TxInput {
    fn from(unlocked_utxo: UnlockedUtxo) -> Self {
        Self(unlocked_utxo)
    }
}

impl From<TxInput> for UnlockedUtxo {
    fn from(tx_input: TxInput) -> Self {
        tx_input.0
    }
}

impl Deref for TxInput {
    type Target = UnlockedUtxo;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TxInput {
    /// retrieve native currency amount
    pub fn native_currency_amount(&self) -> NativeCurrencyAmount {
        self.utxo.get_native_currency_amount()
    }
}

/// Represents a list of [TxInput]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TxInputList(Vec<TxInput>);

impl Deref for TxInputList {
    type Target = Vec<TxInput>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TxInputList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<TxInput> for TxInputList {
    fn from(t: TxInput) -> Self {
        Self(vec![t])
    }
}

impl<I: Into<TxInput>, T: IntoIterator<Item = I>> From<T> for TxInputList {
    fn from(v: T) -> Self {
        Self(v.into_iter().map(|i| i.into()).collect())
    }
}

impl From<TxInputList> for Vec<TxInput> {
    fn from(list: TxInputList) -> Self {
        list.0
    }
}

impl From<&TxInputList> for Vec<MsMembershipProof> {
    fn from(list: &TxInputList) -> Self {
        list.ms_membership_proofs_iter().into_iter().collect()
    }
}

impl From<TxInputList> for Vec<UnlockedUtxo> {
    fn from(list: TxInputList) -> Self {
        list.0.into_iter().map(|v| v.into()).collect()
    }
}

impl TxInputList {
    pub fn empty() -> Self {
        Self(vec![])
    }

    /// retrieves native currency sum(inputs)
    pub fn total_native_coins(&self) -> NativeCurrencyAmount {
        self.0
            .iter()
            .map(|u| u.utxo.get_native_currency_amount())
            .sum()
    }

    /// provides an iterator over input Utxo
    pub fn utxos_iter(&self) -> impl IntoIterator<Item = Utxo> + '_ {
        self.0.iter().map(|u| &u.utxo).cloned()
    }

    /// retrieves all Utxo
    pub fn utxos(&self) -> Vec<Utxo> {
        self.utxos_iter().into_iter().collect()
    }

    /// provides iterator over removal records
    pub fn removal_records_iter<'a>(
        &'a self,
        msa: &'a MutatorSetAccumulator,
    ) -> impl IntoIterator<Item = RemovalRecord> + 'a {
        self.0.iter().map(|u| u.removal_record(msa))
    }

    /// retrieves removal records
    pub fn removal_records<'a>(&'a self, msa: &'a MutatorSetAccumulator) -> Vec<RemovalRecord> {
        self.removal_records_iter(msa).into_iter().collect()
    }

    /// provides mutator-set membership proof iterator
    pub fn ms_membership_proofs_iter(&self) -> impl IntoIterator<Item = MsMembershipProof> + '_ {
        self.0.iter().map(|u| u.mutator_set_mp()).cloned()
    }

    /// retrieves mutator-set membership proofs
    pub fn ms_membership_proofs(&self) -> Vec<MsMembershipProof> {
        self.ms_membership_proofs_iter().into_iter().collect()
    }
}
