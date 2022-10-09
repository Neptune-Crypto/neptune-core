use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::shared_math::rescue_prime_regular::DIGEST_LENGTH;
use twenty_first::util_types::merkle_tree::MerkleTree;
use twenty_first::util_types::simple_hasher::Hasher;

use crate::models::blockchain::digest::{Digest, Hashable};
use crate::models::blockchain::shared::Hash;

use super::{utxo::Utxo, Amount, AMOUNT_SIZE_FOR_U32};

pub struct TransactionKernel {
    pub input_utxos: Vec<Utxo>,
    pub output_utxos: Vec<Utxo>,
    pub public_scripts: Vec<Vec<BFieldElement>>,
    pub fee: Amount,
    pub timestamp: BFieldElement,
}

impl Hashable for TransactionKernel {
    fn neptune_hash(&self) -> Digest {
        let mut leafs: Vec<Vec<BFieldElement>> = vec![];

        // Hash all inputs
        let input_digests: Vec<Vec<BFieldElement>> = self
            .input_utxos
            .iter()
            .map(|inp| inp.neptune_hash().into())
            .collect();
        leafs.push(MerkleTree::<Hash>::root_from_arbitrary_number_of_digests(
            &input_digests,
        ));

        // Hash all outputs
        let output_digests: Vec<Vec<BFieldElement>> = self
            .output_utxos
            .iter()
            .map(|inp| inp.neptune_hash().into())
            .collect();
        leafs.push(MerkleTree::<Hash>::root_from_arbitrary_number_of_digests(
            &output_digests,
        ));

        // Hash all public scripts
        let hasher = Hash::new();
        let public_script_digests: Vec<Vec<BFieldElement>> = self
            .public_scripts
            .iter()
            .map(|ps| hasher.hash(ps, DIGEST_LENGTH))
            .collect();
        leafs.push(MerkleTree::<Hash>::root_from_arbitrary_number_of_digests(
            &public_script_digests,
        ));

        // Hash fee
        let fee_bfes: [BFieldElement; AMOUNT_SIZE_FOR_U32] = self.fee.into();
        let fee_digest = hasher.hash(&fee_bfes, DIGEST_LENGTH);
        leafs.push(fee_digest);

        // Hash timestamp
        let timestamp_digest = hasher.hash(&[self.timestamp], DIGEST_LENGTH);
        leafs.push(timestamp_digest);

        MerkleTree::<Hash>::root_from_arbitrary_number_of_digests(&leafs).into()
    }
}
