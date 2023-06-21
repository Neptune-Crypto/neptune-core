use get_size::GetSize;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use twenty_first::{
    shared_math::{b_field_element::BFieldElement, bfield_codec::BFieldCodec, tip5::Digest},
    util_types::{
        algebraic_hasher::AlgebraicHasher, merkle_tree::CpuParallel,
        merkle_tree_maker::MerkleTreeMaker,
    },
};

use super::Amount;
use crate::{
    util_types::mutator_set::{addition_record::AdditionRecord, removal_record::RemovalRecord},
    Hash,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct PubScriptHashAndInput {
    pub pubscript_hash: Digest,
    pub pubscript_input: Vec<BFieldElement>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct TransactionKernel {
    pub inputs: Vec<RemovalRecord<Hash>>,

    // `outputs` contains the commitments (addition records) that go into the AOCL
    pub outputs: Vec<AdditionRecord>,

    pub pubscript_hashes_and_inputs: Vec<PubScriptHashAndInput>,
    pub fee: Amount,
    pub coinbase: Option<Amount>,

    // number of milliseconds since unix epoch
    pub timestamp: BFieldElement,

    pub mutator_set_hash: Digest,
}

impl TransactionKernel {
    pub fn mast_sequences(&self) -> Vec<Vec<BFieldElement>> {
        let input_utxos_sequence = self.inputs.encode();

        let output_utxos_sequence = self.outputs.encode();

        let pubscript_sequence = self.pubscript_hashes_and_inputs.encode();

        let fee_sequence = self.fee.encode();

        let coinbase_sequence = self.coinbase.encode();

        let timestamp_sequence = self.timestamp.encode();

        let mutator_set_hash_sequence = self.mutator_set_hash.encode();

        vec![
            input_utxos_sequence,
            output_utxos_sequence,
            pubscript_sequence,
            fee_sequence,
            coinbase_sequence,
            timestamp_sequence,
            mutator_set_hash_sequence,
        ]
    }

    pub fn mast_hash(&self) -> Digest {
        // get a sequence of BFieldElements for each field
        let mut sequences = self.mast_sequences();

        // pad until power of two
        while sequences.len() & (sequences.len() - 1) != 0 {
            sequences.push(Digest::default().encode());
        }

        // compute Merkle tree and return hash
        <CpuParallel as MerkleTreeMaker<Hash>>::from_digests(
            &sequences
                .iter()
                .map(|seq| Hash::hash_varlen(seq))
                .collect_vec(),
        )
        .get_root()
    }
}

#[cfg(test)]
pub mod transaction_kernel_tests {

    use crate::tests::shared::{random_pubscript_struct, random_transaction_kernel};

    use super::*;

    #[test]
    pub fn decode_pubscripthash_and_input() {
        let pubscript = random_pubscript_struct();
        let encoded = pubscript.encode();
        let decoded = *PubScriptHashAndInput::decode(&encoded).unwrap();
        assert_eq!(pubscript, decoded);
    }

    #[test]
    pub fn decode_pubscripthashes_and_inputs() {
        let pubscripts = vec![random_pubscript_struct(), random_pubscript_struct()];
        let encoded = pubscripts.encode();
        let decoded = *Vec::<PubScriptHashAndInput>::decode(&encoded).unwrap();
        assert_eq!(pubscripts, decoded);
    }

    #[test]
    pub fn test_decode_transaction_kernel() {
        let kernel = random_transaction_kernel();
        let encoded = kernel.encode();
        let decoded = *TransactionKernel::decode(&encoded).unwrap();
        assert_eq!(kernel, decoded);
    }
}
