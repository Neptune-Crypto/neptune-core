use serde::{Deserialize, Serialize};
use std::str::FromStr;
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::util_types::simple_hasher::Hasher;

use super::{Amount, AMOUNT_SIZE_FOR_U32};
use crate::models::blockchain::{
    digest::{Digest, Hashable, RESCUE_PRIME_OUTPUT_SIZE_IN_BFES},
    shared::Hash,
};

pub const PUBLIC_KEY_LENGTH_IN_BYTES: usize = 33;
pub const PUBLIC_KEY_LENGTH_IN_BFES: usize = 5;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Utxo {
    pub amount: Amount,
    pub public_key: secp256k1::PublicKey,
}

impl Utxo {
    pub fn new_from_hex(amount: Amount, public_key: &str) -> Self {
        Self::new(
            amount,
            secp256k1::PublicKey::from_str(public_key).expect("public key decoded from hex string"),
        )
    }

    pub fn new(amount: Amount, public_key: secp256k1::PublicKey) -> Self {
        Self { amount, public_key }
    }

    fn accumulate(&self) -> Vec<BFieldElement> {
        let amount_bfes: [BFieldElement; AMOUNT_SIZE_FOR_U32] = self.amount.into();
        let bytes: [u8; PUBLIC_KEY_LENGTH_IN_BYTES] = self.public_key.serialize();
        let pk_bfes: [BFieldElement; PUBLIC_KEY_LENGTH_IN_BFES] =
            BFieldElement::from_byte_array(bytes).try_into().unwrap();
        vec![amount_bfes.to_vec(), pk_bfes.to_vec()].concat()
    }
}

impl Hashable for Utxo {
    fn hash(&self) -> Digest {
        let hasher = Hash::new();
        Digest::new(
            hasher
                .hash(&self.accumulate(), RESCUE_PRIME_OUTPUT_SIZE_IN_BFES)
                .try_into()
                .unwrap(),
        )
    }
}
