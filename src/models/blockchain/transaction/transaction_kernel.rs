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
        bfield_codec::{decode_vec, encode_vec, BFieldCodec},
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
        let inputs = encode_vec(self.inputs);
        let outputs = encode_vec(self.outputs);
        let pubscripts = encode_vec(self.pubscript_hashes_and_inputs);
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
        let mut read_index = 0;

        // read inputs
        if sequence.len() < read_index + 1 {
            bail!("Cannot decode empty sequence of BFieldElements to TransactionKernel.");
        }
        let inputs_length = sequence[0].value() as usize;
        read_index += 1;
        if sequence.len() < read_index + inputs_length {
            bail!("Cannot decode sequence of BFieldElements to TransactionKernel: input length mismatch");
        }
        let inputs: Vec<RemovalRecord> =
            *decode_vec(sequence[read_index..read_index + inputs_length])?;
        read_index += inputs_length;

        // read outputs
        if sequence.len() <= read_index {
            bail!("Cannot decode sequence of BFieldElements to TransactionKernel: cannot read length of outputs");
        }
        let outputs_length = sequence[0].value() as usize;
        read_index += 1;
        if sequence.len() < read_index + outputs_length {
            bail!("Cannot decode sequence of BFieldElements to TransactionKernel: output length mismatch");
        }
        let outputs: Vec<AdditionRecord> =
            *decode_vec(sequence[read_index..read_index + outputs_length])?;
        read_index += outputs_length;

        // read public scripts
        if sequence.len() < read_index + 1 {
            bail!("Cannot decode sequence of BFieldElements to TransactionKernel: cannot read public scripts length");
        }
        let pubscripts_length = sequence[0].value() as usize;
        read_index += 1;
        if sequence.len() < read_index + pubscripts_length {
            bail!("Cannot decode sequence of BFieldElements to TransactionKernel: pubscripts length mismatch");
        }
        let pubscripts: Vec<(Digest, Vec<BFieldElement>)> =
            *decode_vec(sequence[read_index..read_index + pubscripts_length])?;
        read_index += pubscripts_length;

        // read fee
        if sequence.len() < read_index + 1 {
            bail!("Cannot decode sequence of BFieldElements to TransactionKernel: cannot read fee length");
        }
        let fee_length = sequence[0].value() as usize;
        read_index += 1;
        if sequence.len() < read_index + fee_length {
            bail!("Cannot decode sequence of BFieldElements to TransactionKernel: fee length mismatch");
        }
        let fee = *Amount::decode(sequence[read_index..read_index + fee_length])?;
        read_index += fee_length;

        // read coinbase
        if sequence.len() < read_index + 1 {
            bail!("Cannot decode sequence of BFieldElements to TransactionKernel: cannot read coinbase length");
        }
        let coinbase_length = sequence[0].value() as usize;
        read_index += 1;
        if sequence.len() < read_index + coinbase_length {
            bail!("Cannot decode sequence of BFieldElements to TransactionKernel: coinbase length mismatch");
        }
        let coinbase =
            *Option::<Amount>::decode(sequence[read_index..read_index + coinbase_length])?;
        read_index += coinbase_length;

        // read timestamp
        if sequence.len() < read_index + 1 {
            bail!("Cannot decode sequence of BFieldElements to TransactionKernel: cannot read timestamp length");
        }
        let timestamp_length = sequence[0].value() as usize;
        read_index += 1;
        if sequence.len() < read_index + timestamp_length {
            bail!("Cannot decode sequence of BFieldElements to TransactionKernel: timestamp length mismatch");
        }
        let timestamp =
            *BFieldElement::decode(sequence[read_index..read_index + timestamp_length])?;
        read_index += timestamp_length;

        if read_index != sequence.len() {
            bail!(
                "Cannot decode sequence of BFieldElements to TransactionKernel: length mismatch."
            );
        }

        Ok(Box::new(TransactionKernel {
            inputs,
            outputs,
            pubscript_hashes_and_inputs: pubscripts,
            fee,
            coinbase,
            timestamp,
        }))
    }
}

impl TransactionKernel {
    pub fn mast_sequences(&self) -> Vec<Vec<BFieldElement>> {
        let mut input_utxos_sequence = vec![BFieldElement::new(self.inputs.len() as u64)];
        for input in self.inputs.iter() {
            let mut input_sequence = input.to_sequence();
            input_utxos_sequence.push(BFieldElement::new(input_sequence.len() as u64));
            input_utxos_sequence.append(&mut input_sequence);
        }

        let mut output_utxos_sequence = vec![BFieldElement::new(self.outputs.len() as u64)];
        for output in self.outputs.iter() {
            let mut output_sequence = output.to_sequence();
            output_utxos_sequence.push(BFieldElement::new(output_sequence.len() as u64));
            output_utxos_sequence.append(&mut output_sequence);
        }

        let mut pubscript_sequence = vec![BFieldElement::new(
            self.pubscript_hashes_and_inputs.len() as u64,
        )];
        for (pubscript_hash, pubscript_input) in self.pubscript_hashes_and_inputs.iter() {
            pubscript_sequence.append(&mut pubscript_hash.to_sequence());
            pubscript_sequence.push(BFieldElement::new(pubscript_input.len() as u64));
            pubscript_sequence.append(&mut pubscript_sequence.clone());
        }

        let mut fee_sequence = vec![BFieldElement::new(self.fee.to_sequence().len() as u64)];
        fee_sequence.append(&mut self.fee.to_sequence());

        let mut coinbase_as_bfes = match self.coinbase {
            Some(amount) => amount.to_sequence(),
            None => {
                vec![]
            }
        };
        let mut coinbase_sequence = vec![BFieldElement::new(coinbase_as_bfes.len() as u64)];
        coinbase_sequence.append(&mut coinbase_as_bfes);

        let timestamp_sequence = vec![BFieldElement::new(1u64), self.timestamp];

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
            sequences.push(Digest::default().to_sequence());
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
    use rand::{random, thread_rng, RngCore};
    use twenty_first::shared_math::other::random_elements;

    use super::*;

    pub fn random_addition_record() -> AdditionRecord {
        let ar: Digest = random();
        ar
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
        let amount = Amount(number.into());
        amount
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
            .map(|_| random_addition_record())
            .collect_vec();
        let outputs = (0..num_outputs)
            .map(|_| mutator_set::random_removal_record())
            .collect_vec();
        let pubscripts = (0..num_pubscripts).map(|_| random_pubscript_tuple());
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
        let decoded = *TransactionKernel::decode(encoded).unwrap();
        assert_eq!(kernel, decoded);
    }
}
