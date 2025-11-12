use rand::distr::Distribution;
use rand::distr::StandardUniform;
use rand::Rng;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::BFieldCodec;

use crate::api::export::TxInput;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::commit;
use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;

/// The key data from a transaction input that enables a transparent audit.
///
/// Specifically, this struct contains enough data to re-derive the
/// `AbsoluteIndexSet` without the target chunks. This information uniquely
/// identifies the UTXO. Furthermore, it contains the UTXO in plaintext, which
/// in particular lays bare the amounts if native currency coins are involved.
///
/// See also:
///  - `UnlockedUtxo` -- also contains lock script and witness and mutator set
///    membership proof;
///  - [`TxInput`] -- newtype wrapper around `UnlockedUtxo`;
///  - `ExpectedUtxo` -- contains data for receiving and monitoring received
///    UTXOs;
///  - `IncomingUtxo` -- contains extra data and does not store the AOCL leaf
///    index;
///  - [`UtxoTriple`](crate::protocol::consensus::transaction::utxo_triple::UtxoTriple)
///    -- output counterpart to this struct, does not contain info needed to
///    re-derive the absolute index set because that information is not known by
///    the transaction initiator.
#[derive(Debug, Clone, BFieldCodec)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct TransparentInput {
    pub utxo: Utxo,
    pub aocl_leaf_index: u64,
    pub sender_randomness: Digest,
    pub receiver_preimage: Digest,
}

impl From<TxInput> for TransparentInput {
    fn from(tx_input: TxInput) -> Self {
        TransparentInput {
            utxo: tx_input.utxo.clone(),
            aocl_leaf_index: tx_input.mutator_set_mp().aocl_leaf_index,
            sender_randomness: tx_input.mutator_set_mp().sender_randomness,
            receiver_preimage: tx_input.mutator_set_mp().receiver_preimage,
        }
    }
}

impl TransparentInput {
    pub fn absolute_index_set(&self) -> AbsoluteIndexSet {
        let item = Tip5::hash(&self.utxo);
        AbsoluteIndexSet::compute(
            item,
            self.sender_randomness,
            self.receiver_preimage,
            self.aocl_leaf_index,
        )
    }

    pub fn addition_record(&self) -> AdditionRecord {
        commit(
            Tip5::hash(&self.utxo),
            self.sender_randomness,
            self.receiver_preimage.hash(),
        )
    }
}

impl Distribution<TransparentInput> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> TransparentInput {
        let utxo = rng.random::<Utxo>();
        let aocl_leaf_index = rng.random_range(0..(u64::MAX >> 1));
        let sender_randomness = rng.random();
        let receiver_preimage = rng.random();
        TransparentInput {
            utxo,
            aocl_leaf_index,
            sender_randomness,
            receiver_preimage,
        }
    }
}
