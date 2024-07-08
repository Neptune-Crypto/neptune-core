use super::utxo::LockScript;
use super::utxo::Utxo;
use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::state::wallet::address::SpendingKeyType;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::removal_record::RemovalRecord;
use std::ops::Deref;
use std::ops::DerefMut;
use tasm_lib::twenty_first::prelude::AlgebraicHasher;

/// represents a transaction input, as accepted by
/// `GlobalState::create_transaction()`
#[derive(Debug, Clone)]
pub struct TxInput {
    pub spending_key: SpendingKeyType,
    pub utxo: Utxo,
    pub lock_script: LockScript,
    pub ms_membership_proof: MsMembershipProof,
}

/// Represents a list of [TxInput]
#[derive(Debug, Clone, Default)]
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

impl From<Vec<TxInput>> for TxInputList {
    fn from(v: Vec<TxInput>) -> Self {
        Self(v)
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

impl TxInputList {
    pub fn total_native_coins(&self) -> NeptuneCoins {
        self.0
            .iter()
            .map(|u| u.utxo.get_native_currency_amount())
            .sum()
    }

    /// retrieves utxos
    pub fn utxos_iter(&self) -> impl IntoIterator<Item = Utxo> + '_ {
        self.0.iter().map(|u| &u.utxo).cloned()
    }

    pub fn utxos(&self) -> Vec<Utxo> {
        self.utxos_iter().into_iter().collect()
    }

    /// retrieves removal records
    pub fn removal_records_iter<'a>(
        &'a self,
        msa: &'a MutatorSetAccumulator,
    ) -> impl IntoIterator<Item = RemovalRecord> + '_ {
        self.0
            .iter()
            .map(|u| msa.drop(Hash::hash(&u.utxo), &u.ms_membership_proof))
    }

    /// retrieves removal records
    pub fn removal_records<'a>(&'a self, msa: &'a MutatorSetAccumulator) -> Vec<RemovalRecord> {
        self.removal_records_iter(msa).into_iter().collect()
    }

    /// retrieves lock scripts
    pub fn lock_scripts_iter(&self) -> impl IntoIterator<Item = LockScript> + '_ {
        self.0.iter().map(|u| &u.lock_script).cloned()
    }

    /// retrieves lock scripts
    pub fn lock_scripts(&self) -> Vec<LockScript> {
        self.lock_scripts_iter().into_iter().collect()
    }

    /// retrieves spending keys
    pub fn spending_keys_iter(&self) -> impl IntoIterator<Item = SpendingKeyType> + '_ {
        self.0.iter().map(|u| u.spending_key)
    }

    /// retrieves spending keys
    pub fn spending_keys(&self) -> Vec<SpendingKeyType> {
        self.spending_keys_iter().into_iter().collect()
    }

    /// retrieves membership proofs
    pub fn ms_membership_proofs_iter(&self) -> impl IntoIterator<Item = MsMembershipProof> + '_ {
        self.0.iter().map(|u| &u.ms_membership_proof).cloned()
    }

    /// retrieves membership proofs
    pub fn ms_membership_proofs(&self) -> Vec<MsMembershipProof> {
        self.ms_membership_proofs_iter().into_iter().collect()
    }
}
