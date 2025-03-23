//! provides an interface to transaction inputs

use std::ops::Deref;
use std::ops::DerefMut;

use serde::Deserialize;
use serde::Serialize;

use super::unlocked_utxo::UnlockedUtxo;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
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
    pub fn native_currency_amount(&self) -> NativeCurrencyAmount {
        self.utxo.get_native_currency_amount()
    }

    #[cfg(test)]
    pub fn new_random(amount: NativeCurrencyAmount) -> Self {
        use crate::models::blockchain::transaction::lock_script::LockScript;
        use crate::models::state::wallet::address::generation_address::GenerationSpendingKey;
        use crate::util_types::mutator_set::ms_membership_proof::pseudorandom_mutator_set_membership_proof;

        let lock_script = LockScript::anyone_can_spend();
        Self(UnlockedUtxo::unlock(
            Utxo::new_native_currency(lock_script.clone(), amount),
            GenerationSpendingKey::derive_from_seed(rand::random()).into(),
            pseudorandom_mutator_set_membership_proof(rand::random()),
        ))
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
    pub(crate) fn empty() -> Self {
        Self(vec![])
    }

    pub fn total_native_coins(&self) -> NativeCurrencyAmount {
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
    ) -> impl IntoIterator<Item = RemovalRecord> + 'a {
        self.0.iter().map(|u| u.removal_record(msa))
    }

    /// retrieves removal records
    pub fn removal_records<'a>(&'a self, msa: &'a MutatorSetAccumulator) -> Vec<RemovalRecord> {
        self.removal_records_iter(msa).into_iter().collect()
    }

    /*
        /// retrieves lock scripts
        pub fn lock_scripts_iter(&self) -> impl IntoIterator<Item = LockScript> + '_ {
            self.0.iter().map(|u| &u.lock_script).cloned()
        }

        /// retrieves lock scripts
        pub fn lock_scripts(&self) -> Vec<LockScript> {
            self.lock_scripts_iter().into_iter().collect()
        }

        /// retrieves unlock keys
        pub fn unlock_keys_iter(&self) -> impl Iterator<Item = Digest> + '_ {
            self.0.iter().map(|u| u.unlock_key)
        }

        /// retrieves unlock keys
        pub fn unlock_keys(&self) -> Vec<Digest> {
            self.unlock_keys_iter().collect()
        }

        /// retrieves unlock keys as lock script witnesses
        pub fn lock_script_witnesses(&self) -> Vec<Vec<BFieldElement>> {
            self.unlock_keys_iter().map(|uk| uk.encode()).collect()
        }
    */
    /// retrieves membership proofs
    pub fn ms_membership_proofs_iter(&self) -> impl IntoIterator<Item = MsMembershipProof> + '_ {
        self.0.iter().map(|u| u.mutator_set_mp()).cloned()
    }

    /// retrieves membership proofs
    pub fn ms_membership_proofs(&self) -> Vec<MsMembershipProof> {
        self.ms_membership_proofs_iter().into_iter().collect()
    }
}
