use std::fmt::Display;
use std::hash::Hash as StdHash;
use std::hash::Hasher as StdHasher;

use arbitrary::Arbitrary;
use get_size::GetSize;
use itertools::Itertools;
use num_traits::Zero;
use rand::rngs::StdRng;
use rand::Rng;
use rand::RngCore;
use rand::SeedableRng;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::structure::tasm_object::TasmObject;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::math::bfield_codec::BFieldCodec;
use twenty_first::math::tip5::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::lock_script::LockScript;
use crate::models::blockchain::type_scripts::native_currency::NativeCurrency;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::blockchain::type_scripts::time_lock::TimeLock;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::prelude::twenty_first;

#[derive(
    Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec, TasmObject, Arbitrary,
)]

pub struct Coin {
    pub type_script_hash: Digest,
    pub state: Vec<BFieldElement>,
}

impl Display for Coin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let output = if self.type_script_hash == NativeCurrency.hash() {
            let amount = match NeptuneCoins::decode(&self.state) {
                Ok(boxed_amount) => boxed_amount.to_string(),
                Err(_) => "Error: Unable to decode amount".to_owned(),
            };
            format!("Native currency: {amount}")
        } else if self.type_script_hash == TimeLock.hash() {
            let release_date = self.release_date().unwrap();
            format!("Timelock until: {release_date}")
        } else {
            "Unknown type script hash".to_owned()
        };

        write!(f, "{}", output)
    }
}

impl Coin {
    pub fn release_date(&self) -> Option<Timestamp> {
        if self.type_script_hash == TimeLock.hash() {
            Some(Timestamp(BFieldElement::new(self.state[0].value())))
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec, TasmObject)]
pub struct Utxo {
    pub lock_script_hash: Digest,
    pub coins: Vec<Coin>,
}

impl Display for Utxo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.coins
                .iter()
                .enumerate()
                .map(|(i, coin)| format!("coin {i}: {coin}"))
                .join("; ")
        )
    }
}

impl GetSize for Utxo {
    fn get_stack_size() -> usize {
        std::mem::size_of::<Self>()
    }

    fn get_heap_size(&self) -> usize {
        // self.lock_script.get_heap_size() + self.coins.len() * (std::mem::size_of::<Digest>())
        let mut total = self.lock_script_hash.get_heap_size();
        for v in self.coins.iter() {
            total += std::mem::size_of::<Digest>();
            total += v.state.len() * std::mem::size_of::<BFieldElement>();
        }

        total
    }

    fn get_size(&self) -> usize {
        Self::get_stack_size() + GetSize::get_heap_size(self)
    }
}

impl Utxo {
    pub fn new(lock_script: LockScript, coins: Vec<Coin>) -> Self {
        Self {
            lock_script_hash: lock_script.hash(),
            coins,
        }
    }

    pub fn new_native_coin(lock_script: LockScript, amount: NeptuneCoins) -> Self {
        Self::new(
            lock_script,
            vec![Coin {
                type_script_hash: NativeCurrency.hash(),
                state: amount.encode(),
            }],
        )
    }

    /// Get the amount of Neptune coins that are encapsulated in this UTXO,
    /// regardless of which other coins are present. (Even if that makes the
    /// Neptune coins unspendable.)
    pub fn get_native_currency_amount(&self) -> NeptuneCoins {
        self.coins
            .iter()
            .filter(|coin| coin.type_script_hash == NativeCurrency.hash())
            .map(|coin| match NeptuneCoins::decode(&coin.state) {
                Ok(boxed_amount) => *boxed_amount,
                Err(_) => NeptuneCoins::zero(),
            })
            .sum()
    }

    /// If the UTXO has a timelock, find out what the release date is.
    pub fn release_date(&self) -> Option<Timestamp> {
        self.coins
            .iter()
            .find(|coin| coin.type_script_hash == TimeLock.hash())
            .map(|coin| coin.state[0].value())
            .map(BFieldElement::new)
            .map(Timestamp)
    }

    /// Determine whether the UTXO has coins that contain only known type
    /// scripts. If other type scripts are included, then we cannot spend
    /// this UTXO.
    pub fn has_known_type_scripts(&self) -> bool {
        let known_type_script_hashes = [NativeCurrency.hash(), TimeLock.hash()];
        self.coins
            .iter()
            .all(|c| known_type_script_hashes.contains(&c.type_script_hash))
    }

    /// Determine if the UTXO can be spent at a given date in the future,
    /// assuming it can be unlocked. Currently, this boils down to checking
    /// whether it has a time lock and if it does, verifying that the release
    /// date is in the past.
    pub fn can_spend_at(&self, timestamp: Timestamp) -> bool {
        // unknown type script
        if !self.has_known_type_scripts() {
            return false;
        }

        // decode and test release date(s) (if any)
        for state in self
            .coins
            .iter()
            .filter(|c| c.type_script_hash == TimeLock.hash())
            .map(|c| c.state.clone())
        {
            match Timestamp::decode(&state) {
                Ok(release_date) => {
                    if timestamp <= *release_date {
                        return false;
                    }
                }
                Err(_) => {
                    return false;
                }
            };
        }

        true
    }

    /// Determine whether the only thing preventing the UTXO from being spendable
    /// is the timelock whose according release date is in the future.
    pub fn is_timelocked_but_otherwise_spendable_at(&self, timestamp: Timestamp) -> bool {
        if !self.has_known_type_scripts() {
            return false;
        }

        // decode and test release date(s) (if any)
        let mut have_future_release_date = false;
        for state in self
            .coins
            .iter()
            .filter(|c| c.type_script_hash == TimeLock.hash())
            .map(|c| c.state.clone())
        {
            match Timestamp::decode(&state) {
                Ok(release_date) => {
                    if timestamp <= *release_date {
                        have_future_release_date = true;
                    }
                }
                Err(_) => {
                    return false;
                }
            };
        }

        have_future_release_date
    }
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

/// Generate a UTXO pseudorandomly, for testing purposes
pub fn pseudorandom_utxo(seed: [u8; 32]) -> Utxo {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    Utxo {
        lock_script_hash: rng.gen(),
        coins: NeptuneCoins::new(rng.next_u32() % 42000000).to_native_coins(),
    }
}

impl<'a> Arbitrary<'a> for Utxo {
    /// Produce a strategy for "arbitrary" UTXOs where "arbitrary" means:
    ///  - lock script corresponding to an arbitrary generation address
    ///  - one coin of type NativeCurrency and arbitrary amount.
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let lock_script_hash: Digest = Digest::arbitrary(u)?;
        let type_script_hash = NativeCurrency.hash();
        let amount = NeptuneCoins::arbitrary(u)?;
        let coins = vec![Coin {
            type_script_hash,
            state: amount.encode(),
        }];
        Ok(Utxo {
            lock_script_hash,
            coins,
        })
    }
}
#[cfg(test)]
mod utxo_tests {
    use rand::thread_rng;
    use tracing_test::traced_test;
    use twenty_first::math::other::random_elements;

    use super::*;
    use crate::models::blockchain::type_scripts::TypeScript;
    use crate::triton_vm::prelude::*;

    fn make_random_utxo() -> Utxo {
        let mut rng = thread_rng();
        let lock_script = LockScript::anyone_can_spend();
        let lock_script_hash = lock_script.hash();
        let num_coins = rng.gen_range(0..10);
        let mut coins = vec![];
        for _i in 0..num_coins {
            let type_script = TypeScript::native_currency();
            let state: Vec<BFieldElement> = random_elements(rng.gen_range(0..10));
            coins.push(Coin {
                type_script_hash: type_script.hash(),
                state,
            });
        }

        Utxo {
            lock_script_hash,
            coins,
        }
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

    #[test]
    fn utxo_timelock_test() {
        let mut rng = thread_rng();
        let release_date = Timestamp(BFieldElement::new(rng.next_u64() >> 2));
        let mut delta = release_date + Timestamp::seconds(1);
        while delta > release_date {
            delta = Timestamp(BFieldElement::new(rng.next_u64() >> 2));
        }
        let mut utxo = Utxo::new(
            LockScript {
                program: Program::new(&[]),
            },
            NeptuneCoins::new(1).to_native_coins(),
        );
        utxo.coins.push(TimeLock::until(release_date));
        assert!(!utxo.can_spend_at(release_date - delta));
        assert!(utxo.is_timelocked_but_otherwise_spendable_at(release_date - delta));
        assert!(utxo.can_spend_at(release_date + delta));
        assert!(!utxo.is_timelocked_but_otherwise_spendable_at(release_date + delta));
    }
}
