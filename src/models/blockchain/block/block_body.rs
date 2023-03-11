use mutator_set_tf::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use mutator_set_tf::util_types::mutator_set::mutator_set_trait::MutatorSet;
use serde::{Deserialize, Serialize};
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::util_types::algebraic_hasher::{AlgebraicHasher, Hashable};

use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::Transaction;

use super::mutator_set_update::MutatorSetUpdate;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockBody {
    pub transaction: Transaction,
    pub next_mutator_set_accumulator: MutatorSetAccumulator<Hash>,
    pub previous_mutator_set_accumulator: MutatorSetAccumulator<Hash>,
    pub mutator_set_update: MutatorSetUpdate,
    pub stark_proof: Vec<BFieldElement>,
}

impl Hashable for BlockBody {
    // FIXME: This .to_sequence() currently creates three digests and serializes those,
    // rather than return the concatenated serialization of the three. For more predictable
    // hashing behavior, consider changing `mutator_set.get_commitment()` into Hashable?
    fn to_sequence(&self) -> Vec<BFieldElement> {
        let transaction_digest = Hash::hash(&self.transaction);

        // Append mutator set's commitment
        //
        // Mutable copy necessary here because `.get_commitment(&mut self)`.
        //
        // It's not necessary to hash `previous_mutator_set_accumulator` and `ms_update_digest` here,
        // as they are fully determined by `next_ms_acc_digest` assuming a good hash function.
        let mut block_body_copy: BlockBody = self.to_owned();
        let next_ms_acc_digest = block_body_copy.next_mutator_set_accumulator.hash();

        // Append digest of STARK proof
        let stark_proof_digest = Hash::hash_varlen(&self.stark_proof);

        [
            transaction_digest.to_sequence(),
            next_ms_acc_digest.to_sequence(),
            stark_proof_digest.to_sequence(),
        ]
        .concat()
    }
}
