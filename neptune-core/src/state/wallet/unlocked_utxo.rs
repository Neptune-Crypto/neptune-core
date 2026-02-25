use std::ops::Deref;
use std::ops::DerefMut;

use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::Tip5;

use crate::api::export::NativeCurrencyAmount;
use crate::protocol::consensus::transaction::lock_script::LockScriptAndWitness;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::tasm_lib::prelude::Digest;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::commit;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::removal_record::RemovalRecord;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockedUtxo {
    pub utxo: Utxo,
    lock_script_and_witness: LockScriptAndWitness,
    membership_proof: MsMembershipProof,
}

impl UnlockedUtxo {
    pub fn unlock(
        utxo: Utxo,
        lock_script_and_witness: LockScriptAndWitness,
        membership_proof: MsMembershipProof,
    ) -> Self {
        Self {
            utxo,
            lock_script_and_witness,
            membership_proof,
        }
    }

    /// Return the `item` from the perspective of the mutator set
    pub fn mutator_set_item(&self) -> Digest {
        Tip5::hash(&self.utxo)
    }

    pub fn mutator_set_mp(&self) -> &MsMembershipProof {
        &self.membership_proof
    }

    pub fn lock_script_and_witness(&self) -> &LockScriptAndWitness {
        &self.lock_script_and_witness
    }

    pub(crate) fn removal_record(&self, mutator_set: &MutatorSetAccumulator) -> RemovalRecord {
        let item = self.mutator_set_item();
        let msmp = &self.membership_proof;
        mutator_set.drop(item, msmp)
    }

    pub(crate) fn addition_record(&self) -> AdditionRecord {
        commit(
            self.mutator_set_item(),
            self.membership_proof.sender_randomness,
            self.membership_proof.receiver_preimage.hash(),
        )
    }
}

impl Deref for UnlockedUtxo {
    type Target = Utxo;

    fn deref(&self) -> &Self::Target {
        &self.utxo
    }
}

/// Represents a list of [`UnlockedUtxo`] decorated with convenience functions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TxInputs(Vec<UnlockedUtxo>);

impl Deref for TxInputs {
    type Target = Vec<UnlockedUtxo>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TxInputs {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<UnlockedUtxo> for TxInputs {
    fn from(t: UnlockedUtxo) -> Self {
        Self(vec![t])
    }
}

impl<I: Into<UnlockedUtxo>, T: IntoIterator<Item = I>> From<T> for TxInputs {
    fn from(v: T) -> Self {
        Self(v.into_iter().map(|i| i.into()).collect())
    }
}

impl From<TxInputs> for Vec<UnlockedUtxo> {
    fn from(list: TxInputs) -> Self {
        list.0
    }
}

impl From<&TxInputs> for Vec<MsMembershipProof> {
    fn from(list: &TxInputs) -> Self {
        list.ms_membership_proofs_iter().into_iter().collect()
    }
}

impl TxInputs {
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
