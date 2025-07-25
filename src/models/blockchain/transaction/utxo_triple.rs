use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::BFieldCodec;

use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::state::wallet::transaction_output::TxOutput;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::commit;

/// Represents the preimage of a transaction output, so not just the UTXO but
/// also the randomnesses.
#[derive(Debug, Clone, BFieldCodec)]
pub(crate) struct UtxoTriple {
    pub(crate) utxo: Utxo,
    pub(crate) sender_randomness: Digest,
    pub(crate) receiver_digest: Digest,
}

impl UtxoTriple {
    pub(crate) fn addition_record(&self) -> AdditionRecord {
        commit(
            Tip5::hash(&self.utxo),
            self.sender_randomness,
            self.receiver_digest,
        )
    }
}

impl From<TxOutput> for UtxoTriple {
    fn from(value: TxOutput) -> Self {
        Self {
            utxo: value.utxo(),
            sender_randomness: value.sender_randomness(),
            receiver_digest: value.receiver_digest(),
        }
    }
}
