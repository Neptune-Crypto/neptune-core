use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::util_types::simple_hasher::{Hashable, Hasher};

use crate::models::blockchain::digest::{Digest, Hashable2};
use crate::models::blockchain::shared::Hash;

use super::{utxo::Utxo, Amount};

pub struct TransactionKernel {
    pub input_utxos: Vec<Utxo>,
    pub output_utxos: Vec<Utxo>,
    pub public_scripts: Vec<Vec<BFieldElement>>,
    pub fee: Amount,
    pub timestamp: BFieldElement,
}

impl Hashable2 for TransactionKernel {
    fn neptune_hash(&self) -> Digest {
        // Hash all inputs
        let inputs_preimage: Vec<BFieldElement> = self
            .input_utxos
            .iter()
            .flat_map(|input_utxo| input_utxo.neptune_hash().values())
            .collect();

        // Hash all outputs
        let outputs_preimage: Vec<BFieldElement> = self
            .output_utxos
            .iter()
            .flat_map(|output_utxo| output_utxo.neptune_hash().values())
            .collect();

        // Hash all public scripts
        let public_scripts_preimage: Vec<BFieldElement> = self.public_scripts.concat();

        // Hash fee
        let fee_preimage: Vec<BFieldElement> = self.fee.to_sequence();

        // Hash timestamp
        let timestamp_preimage = vec![self.timestamp];

        let all_digests = vec![
            inputs_preimage,
            outputs_preimage,
            fee_preimage,
            timestamp_preimage,
            public_scripts_preimage,
        ]
        .concat();

        Digest::new(Hash::new().hash_sequence(&all_digests))
    }
}
