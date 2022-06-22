use serde::{Deserialize, Serialize};
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use twenty_first::util_types::mutator_set::mutator_set_trait::MutatorSet;
use twenty_first::util_types::simple_hasher::Hasher;

use crate::models::blockchain::digest::{Digest, Hashable, RESCUE_PRIME_OUTPUT_SIZE_IN_BFES};
use crate::models::blockchain::mutator_set_update::MutatorSetUpdate;
use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::Transaction;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BlockBody {
    pub transactions: Vec<Transaction>,
    pub next_mutator_set_accumulator: MutatorSetAccumulator<Hash>,
    pub previous_mutator_set_accumulator: MutatorSetAccumulator<Hash>,
    pub mutator_set_update: MutatorSetUpdate,
    pub stark_proof: Vec<BFieldElement>,
}

impl Hashable for BlockBody {
    fn hash(&self) -> Digest {
        // It's not necessary to hash `previous_mutator_set_accumulator` and `ms_update_digest` here,
        // as they are fully determined by `next_ms_acc_digest` assuming a good hash function.
        let transactions_digests: Vec<Vec<BFieldElement>> = self
            .transactions
            .iter()
            .map(|tx| Into::<Vec<BFieldElement>>::into(tx.hash()))
            .collect();
        let mut next_ms_acc_digest: Vec<BFieldElement> =
            self.next_mutator_set_accumulator.get_commitment();
        let mut all_digests: Vec<BFieldElement> = transactions_digests.concat();
        all_digests.append(&mut next_ms_acc_digest);
        all_digests.append(&mut self.stark_proof.clone());

        let hasher = Hash::new();

        hasher
            .hash(&all_digests, RESCUE_PRIME_OUTPUT_SIZE_IN_BFES)
            .into()
    }
}
