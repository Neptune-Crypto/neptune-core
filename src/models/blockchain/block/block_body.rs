use mutator_set_tf::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use mutator_set_tf::util_types::mutator_set::mutator_set_trait::MutatorSet;
use serde::{Deserialize, Serialize};
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::util_types::simple_hasher::Hasher;

use crate::models::blockchain::digest::{Digest, Hashable2};
use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::Transaction;

use super::mutator_set_update::MutatorSetUpdate;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockBody {
    pub transaction: Transaction,
    pub next_mutator_set_accumulator: MutatorSetAccumulator<Hash>,
    pub previous_mutator_set_accumulator: MutatorSetAccumulator<Hash>,
    pub mutator_set_update: MutatorSetUpdate,
    pub stark_proof: Vec<BFieldElement>,
}

impl Hashable2 for BlockBody {
    fn neptune_hash(&self) -> Digest {
        let transaction_digest = self.transaction.neptune_hash().values();

        // Append mutator set's commitment
        //
        // Mutable copy necessary here because `.get_commitment(&mut self)`.
        //
        // It's not necessary to hash `previous_mutator_set_accumulator` and `ms_update_digest` here,
        // as they are fully determined by `next_ms_acc_digest` assuming a good hash function.
        let mut block_body_copy: BlockBody = self.to_owned();
        let next_ms_acc_digest = block_body_copy
            .next_mutator_set_accumulator
            .get_commitment();

        // Append digest of STARK proof
        let stark_proof_digest = Hash::new().hash_sequence(&self.stark_proof);

        Digest::new(Hash::new().hash_many(&[
            transaction_digest,
            next_ms_acc_digest,
            stark_proof_digest,
        ]))
    }
}
