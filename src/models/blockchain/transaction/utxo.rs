use crate::prelude::{triton_vm, twenty_first};

use crate::models::blockchain::shared::Hash;
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

use super::native_coin::{native_coin_program, NATIVE_COIN_TYPESCRIPT_DIGEST};
use super::{native_coin, Amount};
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec)]

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

    pub fn new_native_coin(lock_script: LockScript, amount: Amount) -> Self {
        Self::new(
            lock_script,
            vec![Coin {
                type_script_hash: native_coin::NATIVE_COIN_TYPESCRIPT_DIGEST,
                state: amount.encode(),
            }],
        )
    }

    pub fn get_native_coin_amount(&self) -> Amount {
        self.coins
            .iter()
            .filter(|coin| coin.type_script_hash == NATIVE_COIN_TYPESCRIPT_DIGEST)
            .map(|coin| match Amount::decode(&coin.state) {
                Ok(boxed_amount) => *boxed_amount,
                Err(_) => Amount::zero(),
            })
            .sum()
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
        coins: Amount::from(rng.next_u32()).to_native_coins(),
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct TypeScript {
    pub program: Program,
}

// Standard hash needed for filtering out duplicates.
impl std::hash::Hash for TypeScript {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        self.program.instructions.hash(state);
    }
}

impl From<Vec<LabelledInstruction>> for TypeScript {
    fn from(instrs: Vec<LabelledInstruction>) -> Self {
        Self {
            program: Program::new(&instrs),
        }
    }
}

impl From<&[LabelledInstruction]> for TypeScript {
    fn from(instrs: &[LabelledInstruction]) -> Self {
        Self {
            program: Program::new(instrs),
        }
    }
}

impl TypeScript {
    pub fn new(program: Program) -> Self {
        Self { program }
    }

    pub fn hash(&self) -> Digest {
        self.program.hash::<Hash>()
    }

    pub fn native_coin() -> Self {
        Self {
            program: native_coin_program(),
        }
    }
}

#[cfg(test)]
mod utxo_tests {
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
            let type_script = TypeScript::native_coin();
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
}
