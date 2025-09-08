use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::Tip5;

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
