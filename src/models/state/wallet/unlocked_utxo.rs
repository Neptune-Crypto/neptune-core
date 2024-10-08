use tasm_lib::triton_vm::prelude::Tip5;
use tasm_lib::twenty_first::prelude::AlgebraicHasher;

use super::address::SpendingKey;
use crate::models::blockchain::transaction::lock_script::LockScriptAndWitness;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::tasm_lib::Digest;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;

#[derive(Debug, Clone)]
pub(crate) struct UnlockedUtxo {
    pub utxo: Utxo,
    lock_script_and_witness: LockScriptAndWitness,
    membership_proof: MsMembershipProof,
}

impl UnlockedUtxo {
    pub fn unlock(
        utxo: Utxo,
        spending_key: SpendingKey,
        membership_proof: MsMembershipProof,
    ) -> Self {
        Self {
            utxo,
            lock_script_and_witness: spending_key.lock_script_and_witness(),
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
}
