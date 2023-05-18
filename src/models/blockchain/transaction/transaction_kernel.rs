use get_size::GetSize;
use itertools::Itertools;
use mutator_set_tf::util_types::mutator_set::{
    addition_record::AdditionRecord, removal_record::RemovalRecord,
};
use serde::{Deserialize, Serialize};
use twenty_first::{
    shared_math::{b_field_element::BFieldElement, tip5::Digest},
    util_types::{
        algebraic_hasher::{AlgebraicHasher, Hashable},
        merkle_tree::CpuParallel,
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

impl Hashable for TransactionKernel {
    fn to_sequence(&self) -> Vec<BFieldElement> {
        let inputs_preimage = self
            .inputs
            .iter()
            .flat_map(|input_utxo| input_utxo.to_sequence());

        let outputs_preimage = self
            .outputs
            .iter()
            .flat_map(|output_utxo| output_utxo.to_sequence());

        let public_scripts_preimage = self
            .pubscript_hashes_and_inputs
            .iter()
            .flat_map(|(psh, psi)| [psh.to_sequence(), psi.to_vec()].concat());
        let fee_preimage = self.fee.to_sequence().into_iter();
        let timestamp_preimage = vec![self.timestamp].into_iter();

        inputs_preimage
            .chain(outputs_preimage)
            .chain(public_scripts_preimage)
            .chain(fee_preimage)
            .chain(timestamp_preimage)
            .collect_vec()
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
