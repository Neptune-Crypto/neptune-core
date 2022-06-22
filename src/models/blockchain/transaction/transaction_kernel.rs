use twenty_first::{amount::u32s::U32s, shared_math::b_field_element::BFieldElement};

use crate::models::blockchain::digest::{Digest, Hashable};

use super::{utxo::Utxo, AMOUNT_SIZE_FOR_U32};

pub struct TransactionKernel {
    pub input_utxos: Vec<Utxo>,
    pub output_utxos: Vec<Utxo>,
    pub public_scripts: Vec<Vec<BFieldElement>>,
    pub fee: U32s<AMOUNT_SIZE_FOR_U32>,
    pub timestamp: BFieldElement,
}

impl Hashable for TransactionKernel {
    fn hash(&self) -> Digest {
        todo!()
        // let mut leafs: Vec<RescuePrimeDigest> = vec![];
        // leafs.push(MerkleTree::root_from_arbitrary_number_of_digests(
        //     self.input_utxos
        //         .iter()
        //         .map(|i| i.hash())
        //         .collect()
        //         .try_into()
        //         .unwrap(),
        // ));
        // leafs.push(MerkleTree::root_from_arbitrary_number_of_digests(
        //     self.output_utxos
        //         .iter()
        //         .map(|i| i.hash())
        //         .collect()
        //         .try_into()
        //         .unwrap(),
        // ));
        // leafs.push(MerkleTree::root_from_arbitrary_number_of_digests(
        //     self.public_scripts.iter().map(|i| i.hash()).collect(),
        // ));
        // leafs.push(fee.hash());
        // leafs.push(time.hash());

        // MerkleTree::root_from_arbitrary_number_of_digests(&leafs)
    }
}
