use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::blockchain::type_scripts::time_lock::TimeLock;
use crate::models::consensus::tasm::program::ConsensusProgram;
use crate::prelude::{triton_vm, twenty_first};

use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::type_scripts::native_currency::NativeCurrency;
use arbitrary::Arbitrary;
use get_size::GetSize;
use num_traits::Zero;
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::hash::{Hash as StdHash, Hasher as StdHasher};
use triton_vm::instruction::LabelledInstruction;
use triton_vm::program::Program;
use triton_vm::triton_asm;
use twenty_first::shared_math::bfield_codec::BFieldCodec;
use twenty_first::shared_math::tip5::Digest;

use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec, Arbitrary)]

pub struct Coin {
    pub type_script_hash: Digest,
    pub state: Vec<BFieldElement>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec)]
pub struct Utxo {
    pub lock_script_hash: Digest,
    pub coins: Vec<Coin>,
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

    /// Determine whether the UTXO has coins that contain only known type
    /// scripts. If other type scripts are included, then we cannot spend
    /// this UTXO.
    pub fn has_known_type_scripts(&self) -> bool {
        let known_type_script_hashes = [NativeCurrency.hash(), TimeLock.hash()];
        if !self
            .coins
            .iter()
            .all(|c| known_type_script_hashes.contains(&c.type_script_hash))
        {
            return false;
        }
        true
    }

    /// Determine if the UTXO can be spent at a given date in the future,
    /// assuming it can be unlocked. Currently, this boils down to checking
    /// whether it has a time lock and if it does, verifying that the release
    /// date is in the past.
    pub fn can_spend_at(&self, timestamp: u64) -> bool {
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
            match BFieldElement::decode(&state) {
                Ok(release_date) => {
                    if timestamp <= release_date.value() {
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
    pub fn is_timelocked_but_otherwise_spendable_at(&self, timestamp: u64) -> bool {
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
            match BFieldElement::decode(&state) {
                Ok(release_date) => {
                    if timestamp <= release_date.value() {
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct LockScript {
    pub program: Program,
}

impl From<Vec<LabelledInstruction>> for LockScript {
    fn from(instrs: Vec<LabelledInstruction>) -> Self {
        Self {
            program: Program::new(&instrs),
        }
    }
}

impl From<&[LabelledInstruction]> for LockScript {
    fn from(instrs: &[LabelledInstruction]) -> Self {
        Self {
            program: Program::new(instrs),
        }
    }
}

impl LockScript {
    pub fn new(program: Program) -> Self {
        Self { program }
    }

    pub fn anyone_can_spend() -> Self {
        Self {
            program: Program::new(&triton_asm!(
                read_io 5
                halt
            )),
        }
    }

    pub fn hash(&self) -> Digest {
        self.program.hash::<Hash>()
    }
}

impl<'a> Arbitrary<'a> for LockScript {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let program = Program::arbitrary(u)?;
        Ok(LockScript { program })
    }
}

#[cfg(test)]
mod utxo_tests {
    use crate::models::blockchain::type_scripts::TypeScript;

    use super::*;
    use rand::{thread_rng, Rng};
    use tracing_test::traced_test;
    use twenty_first::shared_math::other::random_elements;

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
        let release_date = rng.next_u64() >> 1;
        let mut delta = release_date + 1;
        while delta > release_date {
            delta = rng.next_u64() >> 1;
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
