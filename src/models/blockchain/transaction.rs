use serde::{Deserialize, Serialize};
use twenty_first::{
    amount::u32s::U32s,
    shared_math::b_field_element::BFieldElement,
    util_types::{
        mutator_set::{
            removal_record::RemovalRecord, transfer_ms_membership_proof::TransferMsMembershipProof,
        },
        simple_hasher::Hasher,
    },
};

use super::{
    digest::{RescuePrimeDigest, RESCUE_PRIME_OUTPUT_SIZE_IN_BFES},
    shared::Hash,
};

pub const AMOUNT_SIZE_FOR_U32: usize = 4;
pub const PUBLIC_KEY_LENGTH_IN_BYTES: usize = 33;
pub const PUBLIC_KEY_LENGTH_IN_BFES: usize = 5;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Utxo {
    amount: U32s<AMOUNT_SIZE_FOR_U32>,
    public_key: secp256k1::PublicKey,
}

impl Utxo {
    fn accumulate(&self) -> Vec<BFieldElement> {
        let amount_bfes: [BFieldElement; AMOUNT_SIZE_FOR_U32] = self.amount.into();
        let bytes: [u8; PUBLIC_KEY_LENGTH_IN_BYTES] = self.public_key.serialize();
        let pk_bfes: [BFieldElement; PUBLIC_KEY_LENGTH_IN_BFES] =
            BFieldElement::from_byte_array(bytes).try_into().unwrap();
        vec![amount_bfes.to_vec(), pk_bfes.to_vec()].concat()
    }

    pub fn hash(&self) -> RescuePrimeDigest {
        let hasher = Hash::new();
        RescuePrimeDigest::new(
            hasher
                .hash(&self.accumulate(), RESCUE_PRIME_OUTPUT_SIZE_IN_BFES)
                .try_into()
                .unwrap(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub inputs: Vec<(Utxo, TransferMsMembershipProof<Hash>, RemovalRecord<Hash>)>,
    pub outputs: Vec<Utxo>,
    pub public_scripts: Vec<Vec<u8>>,
    pub fee: U32s<AMOUNT_SIZE_FOR_U32>,
    pub timestamp: BFieldElement,
}
