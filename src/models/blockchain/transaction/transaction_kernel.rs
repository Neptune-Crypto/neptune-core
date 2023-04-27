use itertools::Itertools;
use mutator_set_tf::util_types::mutator_set::{
    addition_record::AdditionRecord, removal_record::RemovalRecord,
};
use serde::{Deserialize, Serialize};
use twenty_first::{
    shared_math::b_field_element::BFieldElement, util_types::algebraic_hasher::Hashable,
};

use super::{utxo::Utxo, Amount, PubScript};
use crate::Hash;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionKernel {
    pub inputs: Vec<RemovalRecord<Hash>>,

    // `outputs` contains the commitments that go into the AOCL
    pub outputs: Vec<AdditionRecord>,
    pub public_scripts: Vec<PubScript>,
    pub fee: Amount,

    // number of milliseconds since unix epoch
    pub timestamp: BFieldElement,
}

impl Hashable for TransactionKernel {
    fn to_sequence(&self) -> Vec<BFieldElement> {
        let inputs_preimage = self
            .input_utxos
            .iter()
            .flat_map(|input_utxo| input_utxo.to_sequence());

        let outputs_preimage = self
            .output_utxos
            .iter()
            .flat_map(|output_utxo| output_utxo.to_sequence());

        let public_scripts_preimage = self.public_scripts.concat().into_iter();
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
