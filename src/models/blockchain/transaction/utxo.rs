use serde::{Deserialize, Serialize};
use std::hash::{Hash as StdHash, Hasher as StdHasher};
use std::str::FromStr;

use crate::models::blockchain::shared::Hash;

use super::{Amount, AMOUNT_SIZE_FOR_U32};
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::util_types::algebraic_hasher::{AlgebraicHasher, Hashable};

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

    pub fn matches_pubkey(&self, public_key: secp256k1::PublicKey) -> bool {
        self.public_key == public_key
    }
}

impl Hashable for Utxo {
    fn to_sequence(&self) -> Vec<BFieldElement> {
        let amount_bfes: [BFieldElement; AMOUNT_SIZE_FOR_U32] = self.amount.into();
        let bytes: [u8; PUBLIC_KEY_LENGTH_IN_BYTES] = self.public_key.serialize();

        // FIXME: This is the only caller of `BFieldElement::from_byte_array`. All these
        // sizes are fixed, so there's no reason to convert this into Vec<_> and back, and
        // into Vec<_> again. ([u8] -> Vec<BFE> -> [BFE] -> Vec<BFE>)
        let pk_bfes: [BFieldElement; PUBLIC_KEY_LENGTH_IN_BFES] =
            BFieldElement::from_byte_array(bytes).try_into().unwrap();
        vec![amount_bfes.to_vec(), pk_bfes.to_vec()].concat()
    }
}

/// Make `Utxo` hashable with `StdHash` for using it in `HashMap`.
///
/// The Clippy warning is safe to suppress, because we do not violate the invariant: k1 == k2 => hash(k1) == hash(k2).
#[allow(clippy::derive_hash_xor_eq)]
impl StdHash for Utxo {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        let neptune_hash = Hash::hash(self);
        StdHash::hash(&neptune_hash, state);
    }
}
