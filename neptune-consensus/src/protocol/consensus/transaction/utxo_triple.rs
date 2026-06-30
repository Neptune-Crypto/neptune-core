use neptune_mutator_set::addition_record::AdditionRecord;
use neptune_mutator_set::commit;
use rand::distr::Distribution;
use rand::distr::StandardUniform;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::BFieldCodec;

use crate::protocol::consensus::transaction::utxo::Utxo;

/// Represents the preimage of a transaction output, so not just the UTXO but
/// also the randomnesses.
#[derive(Debug, Clone, BFieldCodec, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct UtxoTriple {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
    pub receiver_digest: Digest,
}

impl UtxoTriple {
    pub fn addition_record(&self) -> AdditionRecord {
        commit(
            Tip5::hash(&self.utxo),
            self.sender_randomness,
            self.receiver_digest,
        )
    }
}

impl Distribution<UtxoTriple> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> UtxoTriple {
        UtxoTriple {
            utxo: rng.random(),
            sender_randomness: rng.random(),
            receiver_digest: rng.random(),
        }
    }
}
