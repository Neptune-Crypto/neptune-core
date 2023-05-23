use anyhow::bail;
use mutator_set_tf::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use serde::{Deserialize, Serialize};
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::shared_math::bfield_codec::{decode_field_length_prepended, BFieldCodec};

use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::Transaction;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockBody {
    pub transaction: Transaction,
    pub next_mutator_set_accumulator: MutatorSetAccumulator<Hash>,
    pub previous_mutator_set_accumulator: MutatorSetAccumulator<Hash>,
    pub stark_proof: Vec<BFieldElement>,
}

impl BFieldCodec for BlockBody {
    fn decode(sequence: &[BFieldElement]) -> anyhow::Result<Box<Self>> {
        let (transaction, sequence) = decode_field_length_prepended(sequence)?;
        let (next_mutator_set_accumulator, sequence) = decode_field_length_prepended(sequence)?;
        let (previous_mutator_set_accumulator, sequence) = decode_field_length_prepended(sequence)?;
        let (stark_proof, sequence) = decode_field_length_prepended(sequence)?;
        if !sequence.is_empty() {
            bail!("After decoding sequence of field elements as block body, sequence should be empty.");
        }
        Ok(Box::new(BlockBody {
            transaction,
            next_mutator_set_accumulator,
            previous_mutator_set_accumulator,
            stark_proof,
        }))
    }

    fn encode(&self) -> Vec<BFieldElement> {
        let transaction_encoded = self.transaction.encode();
        let next_mutator_set_accumulator_encoded = self.next_mutator_set_accumulator.encode();
        let previous_mutator_set_accumulator_encoded =
            self.previous_mutator_set_accumulator.encode();
        let stark_proof_encoded = self.stark_proof.encode();

        let transaction_len = BFieldElement::new(transaction_encoded.len() as u64);
        let next_mutator_set_accumulator_len =
            BFieldElement::new(next_mutator_set_accumulator_encoded.len() as u64);
        let previous_mutator_set_accumulator_len =
            BFieldElement::new(previous_mutator_set_accumulator_encoded.len() as u64);
        let stark_proof_len = BFieldElement::new(stark_proof_encoded.len() as u64);

        [
            vec![transaction_len],
            transaction_encoded,
            vec![next_mutator_set_accumulator_len],
            next_mutator_set_accumulator_encoded,
            vec![previous_mutator_set_accumulator_len],
            previous_mutator_set_accumulator_encoded,
            vec![stark_proof_len],
            stark_proof_encoded,
        ]
        .concat()
    }
}
