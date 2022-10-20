use itertools::Itertools;
use twenty_first::{
    shared_math::b_field_element::BFieldElement, util_types::algebraic_hasher::Hashable,
};

use super::{utxo::Utxo, Amount};

pub struct TransactionKernel {
    pub input_utxos: Vec<Utxo>,
    pub output_utxos: Vec<Utxo>,
    pub public_scripts: Vec<Vec<BFieldElement>>,
    pub fee: Amount,
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
