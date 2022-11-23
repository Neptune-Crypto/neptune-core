use serde::{Deserialize, Serialize};
use std::hash::{Hash as StdHash, Hasher as StdHasher};
use std::str::FromStr;

use crate::models::blockchain::shared::Hash;

use super::Amount;
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
        let amount_bfes: Vec<BFieldElement> = self
            .amount
            .as_ref()
            .iter()
            .copied()
            .map(BFieldElement::from)
            .collect();

        let mut pk_bfes = Vec::with_capacity(PUBLIC_KEY_LENGTH_IN_BFES);
        let pk_bfe_bytes: [u8; PUBLIC_KEY_LENGTH_IN_BYTES] = self.public_key.serialize();
        pk_bfes.push(convert::<7>(&pk_bfe_bytes[0..7]));
        pk_bfes.push(convert::<7>(&pk_bfe_bytes[7..14]));
        pk_bfes.push(convert::<7>(&pk_bfe_bytes[14..21]));
        pk_bfes.push(convert::<7>(&pk_bfe_bytes[21..28]));
        pk_bfes.push(convert::<5>(&pk_bfe_bytes[28..33]));

        vec![amount_bfes, pk_bfes].concat()
    }
}

fn convert<const N: usize>(bytes: &[u8]) -> BFieldElement {
    let mut u64_input: [u8; 8] = [0; 8];
    u64_input[..N].copy_from_slice(bytes);
    BFieldElement::new(u64::from_le_bytes(u64_input))
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

#[cfg(test)]
mod utxo_tests {
    use twenty_first::util_types::emojihash_trait::Emojihash;

    use crate::tests::shared::new_random_wallet;

    use super::*;

    #[test]
    fn hash_utxo_test() {
        let wallet = new_random_wallet();
        let amount = Amount::from(42);
        let public_key = wallet.get_public_key();
        let output = Utxo { amount, public_key };
        let digest = Hash::hash(&output);

        println!("{}", digest.emojihash());
    }
}
