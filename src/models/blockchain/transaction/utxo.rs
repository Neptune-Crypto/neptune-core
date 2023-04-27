use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::hash::{Hash as StdHash, Hasher as StdHasher};
use twenty_first::shared_math::tip5::Digest;

use crate::models::blockchain::shared::Hash;

use super::{native_coin, Amount};
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::util_types::algebraic_hasher::{AlgebraicHasher, Hashable};

pub const PUBLIC_KEY_LENGTH_IN_BYTES: usize = 33;
pub const PUBLIC_KEY_LENGTH_IN_BFES: usize = 5;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Utxo {
    pub lock_script: LockScript,
    pub coins: Vec<(Digest, Vec<BFieldElement>)>,
}

impl Utxo {
    pub fn new(lock_script: LockScript, coins: Vec<(Digest, Vec<BFieldElement>)>) -> Self {
        Self { lock_script, coins }
    }

    pub fn new_native_coin(lock_script: LockScript, amount: Amount) -> Self {
        Self::new(
            lock_script,
            vec![(
                native_coin::NATIVE_COIN_TYPESCRIPT_DIGEST,
                amount.to_sequence(),
            )],
        )
    }
}

impl Hashable for Utxo {
    fn to_sequence(&self) -> Vec<BFieldElement> {
        let lock_script_bfes: Vec<BFieldElement> = self.lock_script.to_sequence();

        let coins_bfes = self
            .coins
            .iter()
            .flat_map(|(d, s)| {
                [
                    vec![BFieldElement::new(d.to_sequence().len() as u64)],
                    d.to_sequence(),
                    vec![BFieldElement::new(s.len() as u64)],
                    s.clone(),
                ]
                .concat()
            })
            .collect_vec();

        [
            vec![BFieldElement::new(lock_script_bfes.len() as u64)],
            lock_script_bfes,
            vec![BFieldElement::new(coins_bfes.len() as u64)],
            coins_bfes,
        ]
        .concat()
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
#[allow(clippy::derived_hash_with_manual_eq)]
impl StdHash for Utxo {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        let neptune_hash = Hash::hash(self);
        StdHash::hash(&neptune_hash, state);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockScript(pub Vec<BFieldElement>);

impl Hashable for LockScript {
    fn to_sequence(&self) -> Vec<BFieldElement> {
        self.0.clone()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TypeScript(pub Vec<BFieldElement>);

impl Hashable for TypeScript {
    fn to_sequence(&self) -> Vec<BFieldElement> {
        self.0.clone()
    }
}

#[cfg(test)]
mod utxo_tests {

    use rand::{thread_rng, Rng};
    use tracing_test::traced_test;
    use twenty_first::shared_math::other::random_elements;

    use super::*;

    fn make_random_utxo() -> Utxo {
        let mut rng = thread_rng();
        let lock_script = LockScript(random_elements(rng.gen_range(1..20)));
        let num_coins = rng.gen_range(0..10);
        let mut coins = vec![];
        for i in 0..num_coins {
            let type_script = TypeScript(random_elements(rng.gen_range(10..100)));
            let state: Vec<BFieldElement> = random_elements(rng.gen_range(0..10));
            coins.push((Hash::hash(&type_script), state));
        }

        Utxo { lock_script, coins }
    }

    #[test]
    fn hash_utxo_test() {
        let output = make_random_utxo();
        let _digest = Hash::hash(&output);
    }

    #[traced_test]
    #[test]
    fn serialization_test() {
        let utxo = make_random_utxo();
        let serialized: String = serde_json::to_string(&utxo).unwrap();
        let utxo_again: Utxo = serde_json::from_str(&serialized).unwrap();
        assert_eq!(utxo, utxo_again);
    }
}
