use anyhow::bail;
use get_size::GetSize;
use itertools::Itertools;
use mutator_set_tf::util_types::mutator_set::{
    addition_record::AdditionRecord, removal_record::RemovalRecord,
};
use serde::{Deserialize, Serialize};
use twenty_first::{
    shared_math::{
        b_field_element::BFieldElement,
        bfield_codec::{
            decode_field_length_prepended, decode_vec_length_prepended, encode_vec, BFieldCodec,
        },
        tip5::Digest,
    },
    util_types::{
        algebraic_hasher::AlgebraicHasher, merkle_tree::CpuParallel,
        merkle_tree_maker::MerkleTreeMaker,
    },
};

use super::Amount;
use crate::Hash;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub struct TransactionKernel {
    pub inputs: Vec<RemovalRecord<Hash>>,

    // `outputs` contains the commitments (addition records) that go into the AOCL
    pub outputs: Vec<AdditionRecord>,

    pub pubscript_hashes_and_inputs: Vec<(Digest, Vec<BFieldElement>)>,
    pub fee: Amount,
    pub coinbase: Option<Amount>,

    // number of milliseconds since unix epoch
    pub timestamp: BFieldElement,
}

impl BFieldCodec for TransactionKernel {
    fn encode(&self) -> Vec<BFieldElement> {
        let inputs = encode_vec(&self.inputs);
        let outputs = encode_vec(&self.outputs);
        let pubscripts = encode_vec(&self.pubscript_hashes_and_inputs);
        let fee = self.fee.encode();
        let coinbase = self.coinbase.encode();
        let timestamp = self.timestamp.encode();

        [
            vec![BFieldElement::new(inputs.len() as u64)],
            inputs,
            vec![BFieldElement::new(outputs.len() as u64)],
            outputs,
            vec![BFieldElement::new(pubscripts.len() as u64)],
            pubscripts,
            vec![BFieldElement::new(fee.len() as u64)],
            fee,
            vec![BFieldElement::new(coinbase.len() as u64)],
            coinbase,
            vec![BFieldElement::new(timestamp.len() as u64)],
            timestamp,
        ]
        .concat()
    }

    fn decode(sequence: &[BFieldElement]) -> anyhow::Result<Box<Self>> {
        let (inputs, sequence) = decode_vec_length_prepended(sequence)?;
        let (outputs, sequence) = decode_vec_length_prepended(&sequence)?;
        let (pubscript_hashes_and_inputs, sequence) = decode_vec_length_prepended(&sequence)?;
        let (fee, sequence) = decode_field_length_prepended(&sequence)?;
        let (coinbase, sequence) = decode_field_length_prepended(&sequence)?;
        let (timestamp, sequence) = decode_field_length_prepended(&sequence)?;

        if !sequence.is_empty() {
            bail!("Cannot decode sequence of BFieldElements as TransactionKernel: sequence should be empty afterwards.");
        }

        Ok(Box::new(TransactionKernel {
            inputs,
            outputs,
            pubscript_hashes_and_inputs,
            fee,
            coinbase,
            timestamp,
        }))
    }
}

impl TransactionKernel {
    pub fn mast_sequences(&self) -> Vec<Vec<BFieldElement>> {
        let input_utxos_sequence = encode_vec(&self.inputs);

        let output_utxos_sequence = encode_vec(&self.outputs);

        let pubscript_sequence = encode_vec(&self.pubscript_hashes_and_inputs);

        let fee_sequence = self.fee.encode();

        let coinbase_sequence = self.coinbase.encode();

        let timestamp_sequence = self.timestamp.encode();

        vec![
            input_utxos_sequence,
            output_utxos_sequence,
            pubscript_sequence,
            fee_sequence,
            coinbase_sequence,
            timestamp_sequence,
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
    use mutator_set_tf::test_shared::mutator_set::{self};
    use rand::{random, thread_rng, Rng, RngCore};
    use twenty_first::{amount::u32s::U32s, shared_math::other::random_elements};

    use super::*;

    pub fn random_addition_record() -> AdditionRecord {
        let ar: Digest = random();
        AdditionRecord {
            canonical_commitment: ar,
        }
    }

    pub fn random_pubscript_tuple() -> (Digest, Vec<BFieldElement>) {
        let mut rng = thread_rng();
        let digest: Digest = rng.gen();
        let len = 10 + (rng.next_u32() % 50) as usize;
        let input: Vec<BFieldElement> = random_elements(len);
        (digest, input)
    }

    pub fn random_amount() -> Amount {
        let number: [u32; 4] = random();
        Amount(U32s::new(number))
    }

    pub fn random_option<T>(thing: T) -> Option<T> {
        if thread_rng().next_u32() % 2 == 0 {
            None
        } else {
            Some(thing)
        }
    }

    pub fn random_transaction_kernel() -> TransactionKernel {
        let mut rng = thread_rng();
        let num_inputs = 1 + (rng.next_u32() % 5) as usize;
        let num_outputs = 1 + (rng.next_u32() % 6) as usize;
        let num_pubscripts = (rng.next_u32() % 5) as usize;

        let inputs = (0..num_inputs)
            .map(|_| mutator_set::random_removal_record())
            .collect_vec();
        let outputs = (0..num_outputs)
            .map(|_| random_addition_record())
            .collect_vec();
        let pubscripts = (0..num_pubscripts)
            .map(|_| random_pubscript_tuple())
            .collect_vec();
        let fee = random_amount();
        let coinbase = random_option(random_amount());
        let timestamp: BFieldElement = random();

        TransactionKernel {
            inputs,
            outputs,
            pubscript_hashes_and_inputs: pubscripts,
            fee,
            coinbase,
            timestamp,
        }
    }

    #[test]
    pub fn test_decode_transaction_kernel() {
        let kernel = random_transaction_kernel();
        let encoded = kernel.encode();
        let decoded = *TransactionKernel::decode(&encoded).unwrap();
        assert_eq!(kernel, decoded);
    }
}
